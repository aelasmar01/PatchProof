"""One revision execution: exactly one target and one verifier (PROJECT_SPEC.md 10; verdict spec 4, 5.3).

**Sequence:**
1. **Image identity.** Inspect both approved images. The ID, platform, environment and
   target health check must match the approved run-image records.
2. **Inputs.** Re-hash the pack snapshot and this side's source snapshot, and confirm the
   snapshot was materialized with exactly the profile's source scope.
3. **Create and gate, before anything starts.** Create the target (`--network=none`, source
   at `/app/source`, read-only), inspect it, and gate it. Then create the verifier (joined
   to that exact target ID, pack at `/pack`, read-only), inspect it, and gate it. A failure
   here is pre-execution: nothing has started (D5).
4. **Start and readiness.** Start the target, then poll `docker inspect` for the image's
   health state until `healthy`, a stopped target (`STARTUP_FAILED`), or the readiness
   deadline (`READINESS_TIMEOUT`). The verifier is never started for a target that is not
   ready.
5. **Verifier.** Start it attached. Its standard output, the only event channel, is read
   bounded at `result_cap_bytes + 1` and within the remaining revision deadline. A verifier
   still running after that is stopped.
6. **Observe.** Inspect exit code, OOM state and whether the target exited during the tests.
7. **Target logs.** Read them bounded, labeled untrusted, and never parsed.
8. **Cleanup.** Remove both containers by exact ID after re-checking ownership (PP-003
   `cleanup.remove_owned`). Nothing else is touched.

A `session_end` event never makes an execution trusted. Trust comes from the host-observed
facts recorded here (verdict specification 4.2).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Final, Literal, Protocol

from ..core.records import validate_record
from ..core.records.run import Execution
from .cleanup import CleanupResult, OwnershipRegistry, remove_owned
from .collector import CollectedStream, collect_stream
from .docker_cli import ContainerRef, Executor, ImageInspect, Inspect, Logs, Start, Stop
from .inputs import InputIntegrityError, verify_pack_snapshot, verify_source_snapshot
from .inspect_gate import parse_single_inspect
from .policy import ContainerId, PolicyViolation
from .run_gate import check_run_container
from .run_plan import ApprovedRunImage, RunPlan, check_source_scope
from .run_policy import (
    RunContainerSpec,
    RunCreate,
    RunRole,
    StartAttached,
    build_run_spec,
    target_command,
    verifier_command,
)

TARGET_LOG_CAP: Final = 5 * 1024 * 1024
READINESS_POLL_SECONDS: Final = 0.5


class Clock(Protocol):
    def monotonic(self) -> float: ...

    def sleep(self, seconds: float) -> None: ...


@dataclass
class _Facts:
    started: bool = False
    readiness: str = "NOT_STARTED"
    target_oom: bool = False
    target_exited: bool = False
    termination: str = "NOT_STARTED"
    exit_code: int | None = None
    signal: int | None = None
    verifier_oom: bool = False
    deadline_exceeded: bool = False
    canceled: bool = False
    runtime_errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RevisionResult:
    pair: int
    side: Literal["baseline", "candidate"]
    execution: Execution
    stream: CollectedStream
    raw_stream: bytes
    target_log: bytes
    target_log_truncated: bool
    cleanup: tuple[CleanupResult, ...]
    precondition_failure: tuple[str, str] | None
    notes: tuple[str, ...]


def _image_problems(stdout: bytes, approved: ApprovedRunImage) -> list[str]:
    try:
        data = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ["image inspect output is not JSON"]
    if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
        return ["image inspect must return exactly one object"]
    obj = data[0]
    raw_config = obj.get("Config")
    config: dict[str, Any] = raw_config if isinstance(raw_config, dict) else {}
    problems = []
    if obj.get("Id") != approved.image.value:
        problems.append("image ID differs from the approved run image")
    if (obj.get("Os"), obj.get("Architecture")) != ("linux", "amd64"):
        problems.append("image platform is not linux/amd64")
    if config.get("Env") != list(approved.env):
        problems.append("image environment differs from the approved record")
    if config.get("Healthcheck") != approved.healthcheck:
        problems.append("image health check differs from the approved record")
    return problems


def _state(obj: dict[str, Any]) -> dict[str, Any]:
    state = obj.get("State")
    return state if isinstance(state, dict) else {}


def execute_revision(executor: Executor, plan: RunPlan, pair: int, side: Literal["baseline", "candidate"],
                     registry: OwnershipRegistry, *, clock: Clock,
                     cancel: Callable[[], bool] = lambda: False) -> RevisionResult:
    facts = _Facts()
    notes: list[str] = []
    created: list[ContainerId] = []
    out: dict[str, Any] = {"raw": b"", "log": b"", "log_truncated": False, "failure": None}
    cap = plan.profile.result_cap_bytes
    target_limits, verifier_limits = plan.limits(RunRole.TARGET), plan.limits(RunRole.VERIFIER)
    deadline = clock.monotonic() + target_limits.deadline_seconds

    def inspect(cid: ContainerId) -> dict[str, Any] | None:
        result = executor.run(Inspect(ContainerRef(cid.value)))
        if not result.ok:
            return None
        try:
            return parse_single_inspect(result.stdout, cid)
        except ValueError:
            return None

    def create_and_gate(spec: RunContainerSpec, approved: ApprovedRunImage) -> ContainerId | None:
        registry.plan(spec.name, spec.role.probe_role)
        op = RunCreate(spec)
        result = executor.run(op)
        try:
            cid = ContainerId(result.stdout.decode("ascii").strip()) if result.ok else None
        except (UnicodeDecodeError, PolicyViolation):
            cid = None
        if cid is None:
            facts.runtime_errors.append("CONTAINER_CREATE_FAILED")
            notes.append(f"{spec.role.value}: create failed")
            return None
        registry.record_created(spec.name, cid)
        created.insert(0, cid)
        obj = inspect(cid)
        if obj is None:
            facts.runtime_errors.append("INSPECT_FAILED")
            out["failure"] = ("environment_identity", "RUNTIME_POLICY_FAILED")
            return None
        gate = check_run_container(obj, spec, cid, approved.env, create_argv=op.argv_tail())
        if not gate.passed:
            out["failure"] = ("environment_identity", "RUNTIME_POLICY_FAILED")
            notes.append(f"{spec.role.value}: policy gate failed: {gate.summary()}")
            return None
        return cid

    def body() -> None:
        for approved in (plan.target_image, plan.verifier_image):
            result = executor.run(ImageInspect(approved.image))
            problems = ["image inspect failed"] if not result.ok else _image_problems(result.stdout, approved)
            if problems:
                out["failure"] = ("environment_identity", "ENVIRONMENT_NONCOMPARABLE")
                notes.extend(f"{approved.role.value} image: {p}" for p in problems)
                return
        try:
            verify_pack_snapshot(plan.pack)
        except InputIntegrityError as exc:
            out["failure"] = ("pack_integrity", "PACK_INTEGRITY_FAILED")
            notes.append(f"pack snapshot: {exc}")
            return
        source = plan.source(side)
        try:
            check_source_scope(plan.profile, verify_source_snapshot(source))
        except InputIntegrityError as exc:
            out["failure"] = ("source_identity", "SOURCE_IDENTITY_MISMATCH")
            notes.append(f"{side} source snapshot: {exc}")
            return

        target_spec = build_run_spec(ownership=plan.ownership, pair=pair, side=side, role=RunRole.TARGET,
                                     image=plan.target_image.image, limits=target_limits,
                                     input_dir=source.source_dir, command=target_command(plan.profile.asgi_app))
        target_id = create_and_gate(target_spec, plan.target_image)
        if target_id is None:
            return
        verifier_spec = build_run_spec(
            ownership=plan.ownership, pair=pair, side=side, role=RunRole.VERIFIER, image=plan.verifier_image.image,
            limits=verifier_limits, input_dir=plan.pack.root, join_target=target_id,
            command=verifier_command(run_id=plan.ownership.run_id, pair=pair, side=side, test_paths=plan.test_paths,
                                     connect_timeout=plan.profile.timeouts.request_connect_seconds,
                                     read_timeout=plan.profile.timeouts.request_read_seconds))
        verifier_id = create_and_gate(verifier_spec, plan.verifier_image)
        if verifier_id is None:
            return
        if cancel():
            facts.canceled = True
            return

        if not executor.run(Start(target_id)).ok:
            facts.runtime_errors.append("CONTAINER_START_FAILED")
            notes.append("target: start failed")
            return
        facts.started = True
        facts.readiness = "READINESS_TIMEOUT"
        ready_by = min(deadline, clock.monotonic() + plan.profile.timeouts.readiness_seconds)
        while clock.monotonic() < ready_by:
            if cancel():
                facts.canceled = True
                break
            obj = inspect(target_id)
            if obj is None:
                facts.runtime_errors.append("INSPECT_FAILED")
                break
            state = _state(obj)
            if not state.get("Running"):
                facts.readiness = "STARTUP_FAILED"
                facts.target_oom = state.get("OOMKilled") is True
                break
            health = state.get("Health")
            status = health.get("Status") if isinstance(health, dict) else None
            if status == "healthy":
                facts.readiness = "READY"
                break
            if status == "unhealthy":
                facts.readiness = "STARTUP_FAILED"
                break
            clock.sleep(READINESS_POLL_SECONDS)

        if facts.readiness == "READY" and not facts.canceled:
            remaining = deadline - clock.monotonic()
            if remaining <= 0:
                facts.deadline_exceeded = True
            else:
                attached = executor.run(StartAttached(verifier_id, timeout_seconds=remaining, stdout_cap=cap + 1))
                out["raw"] = attached.stdout
                facts.deadline_exceeded = attached.timed_out
                if attached.stdout_truncated:
                    notes.append("verifier output reached the result cap; reading stopped")
                obj = inspect(verifier_id)
                if obj is not None and _state(obj).get("Running"):
                    executor.run(Stop(verifier_id))
                    obj = inspect(verifier_id)
                _record_verifier(facts, obj, stopped_by_host=attached.timed_out or attached.stdout_truncated)
            target_obj = inspect(target_id)
            if target_obj is None:
                facts.runtime_errors.append("INSPECT_FAILED")
            else:
                facts.target_oom = facts.target_oom or _state(target_obj).get("OOMKilled") is True
                facts.target_exited = not _state(target_obj).get("Running")
        logs = executor.run(Logs(target_id, stdout_cap=TARGET_LOG_CAP))
        out["log"], out["log_truncated"] = logs.stdout, logs.stdout_truncated

    cleanup: list[CleanupResult] = []
    try:
        body()
    finally:
        for cid in created:
            cleanup.append(remove_owned(executor, registry, cid))

    raw: bytes = out["raw"] if facts.termination != "NOT_STARTED" else b""
    stream = collect_stream(raw, plan.stream_identity(pair, side), result_cap_bytes=cap)
    errors = list(dict.fromkeys(facts.runtime_errors))
    execution = validate_record(Execution, {
        "schema_version": "1.0", "run_id": plan.ownership.run_id, "pair": pair, "side": side,
        "started": facts.started,
        "target": {"readiness": facts.readiness, "oom_killed": facts.target_oom,
                   "exited_during_tests": facts.target_exited},
        "verifier": {"termination": facts.termination, "exit_code": facts.exit_code, "signal": facts.signal,
                     "oom_killed": facts.verifier_oom},
        "deadline_exceeded": facts.deadline_exceeded, "canceled": facts.canceled, "runtime_errors": errors,
        "stream": {"status": stream.status, "session_end_received": stream.session_end_received,
                   "events_received": stream.events_received, "bytes_received": stream.bytes_received,
                   "failed_reports": stream.failed_reports},
    }, "execution")
    return RevisionResult(pair=pair, side=side, execution=execution, stream=stream, raw_stream=raw,
                          target_log=out["log"], target_log_truncated=out["log_truncated"],
                          cleanup=tuple(cleanup), precondition_failure=out["failure"], notes=tuple(notes))


def _record_verifier(facts: _Facts, obj: dict[str, Any] | None, *, stopped_by_host: bool) -> None:
    if obj is None:
        facts.termination = "NOT_OBSERVED"
        facts.runtime_errors.append("INSPECT_FAILED")
        return
    state = _state(obj)
    facts.verifier_oom = state.get("OOMKilled") is True
    started_at = state.get("StartedAt")
    if isinstance(started_at, str) and started_at.startswith("0001-"):
        facts.termination = "NOT_STARTED"
        facts.runtime_errors.append("ATTACH_FAILED")
        return
    code = state.get("ExitCode")
    if state.get("Running") or not isinstance(code, int) or isinstance(code, bool) or not 0 <= code <= 255:
        facts.termination = "NOT_OBSERVED"
    elif code > 128 and (stopped_by_host or facts.verifier_oom) and code - 128 <= 64:
        facts.termination, facts.signal = "SIGNALED", code - 128
    else:
        facts.termination, facts.exit_code = "EXITED", code
