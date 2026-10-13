"""One standalone verifier container: collection or synthetic self-test (PP-008 gate C).

**What it is:** the verifier image with `--network=none` and no target. The approved pack
snapshot is mounted read-only at `/pack`, and the fixed launcher runs in `collect` or `run`
mode. Every policy setting other than the network topology is the verifier's.

**Sequence (verdict specification 5.3):**
1. image identity;
2. pack re-verification;
3. create and inspect-gate; a gate failure removes the container **unstarted**;
4. attached start, bounded by deadline and output cap;
5. exit inspection, stopping the container if it is still running;
6. exact-ID, ownership-checked cleanup;
7. pack re-verification.

The result records host-observed facts only. Standard output and standard error are kept
as raw bytes; their meaning is decided by the caller's collector.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .cleanup import CleanupResult, OwnershipRegistry, remove_owned
from .docker_cli import ContainerRef, Executor, ImageInspect, Inspect, Stop
from .inputs import InputIntegrityError, PackSnapshot, verify_pack_snapshot
from .inspect_gate import GateResult, parse_single_inspect
from .policy import ContainerId, Ownership, PolicyViolation, ResourceLimits
from .revision import _Facts, _image_problems, _record_verifier
from .run_gate import check_run_container
from .run_plan import ApprovedRunImage
from .run_policy import RunCreate, RunRole, StartAttached, build_run_spec


@dataclass(frozen=True)
class StandalonePlan:
    ownership: Ownership
    image: ApprovedRunImage
    pack: PackSnapshot
    command: tuple[str, ...]
    limits: ResourceLimits
    output_cap_bytes: int

    def __post_init__(self) -> None:
        if self.image.role is not RunRole.VERIFIER:
            raise PolicyViolation("a standalone container runs the approved verifier image only")


@dataclass
class StandaloneResult:
    container_id: str | None = None
    create_argv: tuple[str, ...] = ()
    gate: GateResult | None = None
    started: bool = False
    timed_out: bool = False
    stdout: bytes = b""
    stdout_truncated: bool = False
    stderr: bytes = b""
    termination: str = "NOT_STARTED"
    exit_code: int | None = None
    signal: int | None = None
    oom_killed: bool = False
    pack_verified_before: bool = False
    pack_verified_after: bool = False
    cleanup: list[CleanupResult] = field(default_factory=list)
    failure: str | None = None
    operations: list[str] = field(default_factory=list)


def run_standalone(executor: Executor, plan: StandalonePlan, registry: OwnershipRegistry) -> StandaloneResult:
    result = StandaloneResult()
    created: list[ContainerId] = []

    def run(op: Any) -> Any:
        result.operations.append(op.op_name)
        return executor.run(op)

    def inspect(cid: ContainerId) -> dict[str, Any] | None:
        res = run(Inspect(ContainerRef(cid.value)))
        if not res.ok:
            return None
        try:
            return parse_single_inspect(res.stdout, cid)
        except ValueError:
            return None

    def body() -> None:
        image = run(ImageInspect(plan.image.image))
        problems = ["image inspect failed"] if not image.ok else _image_problems(image.stdout, plan.image)
        if problems:
            result.failure = "image identity: " + "; ".join(problems)
            return
        try:
            verify_pack_snapshot(plan.pack)
            result.pack_verified_before = True
        except InputIntegrityError as exc:
            result.failure = f"pack integrity before start: {exc}"
            return
        spec = build_run_spec(ownership=plan.ownership, pair=1, side="baseline", role=RunRole.STANDALONE,
                              image=plan.image.image, limits=plan.limits, input_dir=plan.pack.root,
                              command=plan.command)
        registry.plan(spec.name, spec.role.probe_role)
        op = RunCreate(spec)
        result.create_argv = tuple(op.argv_tail())
        created_res = run(op)
        try:
            cid = ContainerId(created_res.stdout.decode("ascii").strip()) if created_res.ok else None
        except (UnicodeDecodeError, PolicyViolation):
            cid = None
        if cid is None:
            result.failure = "container create failed"
            return
        registry.record_created(spec.name, cid)
        created.append(cid)
        result.container_id = cid.value
        obj = inspect(cid)
        if obj is None:
            result.failure = "pre-start inspect failed"
            return
        result.gate = check_run_container(obj, spec, cid, plan.image.env, create_argv=list(result.create_argv))
        if not result.gate.passed:
            result.failure = "pre-start policy gate failed: " + result.gate.summary()
            return
        attached = run(StartAttached(cid, timeout_seconds=float(plan.limits.deadline_seconds),
                                     stdout_cap=plan.output_cap_bytes + 1))
        result.started = True
        result.stdout, result.stderr = attached.stdout, attached.stderr
        result.timed_out, result.stdout_truncated = attached.timed_out, attached.stdout_truncated
        obj = inspect(cid)
        if obj is not None and isinstance(obj.get("State"), dict) and obj["State"].get("Running"):
            run(Stop(cid))
            obj = inspect(cid)
        facts = _Facts()
        _record_verifier(facts, obj, stopped_by_host=attached.timed_out or attached.stdout_truncated)
        result.termination, result.exit_code, result.signal = facts.termination, facts.exit_code, facts.signal
        result.oom_killed = facts.verifier_oom
        if facts.termination == "NOT_STARTED":
            result.started = False
            result.failure = "the container did not start"
        elif attached.timed_out:
            result.failure = "deadline exceeded"
        elif attached.stdout_truncated:
            result.failure = "output exceeded the cap"

    try:
        body()
    finally:
        for cid in created:
            result.cleanup.append(remove_owned(executor, registry, cid))
            result.operations.append("cleanup")
        try:
            verify_pack_snapshot(plan.pack)
            result.pack_verified_after = True
        except InputIntegrityError as exc:
            result.failure = result.failure or f"pack integrity after the run: {exc}"
    return result
