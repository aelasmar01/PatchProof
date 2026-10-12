"""Probe-suite orchestration over the typed runner (A4 execution path).

The orchestrator never builds a Docker argument itself. It asks `policy.build_spec` for a
validated spec, hands typed operations to an `Executor`, passes every created container
through the inspect gate before starting it, and removes containers only through
`cleanup`. Unit tests drive it with a synthetic executor; a real run needs the A2/A3/A4
gates, which `check_execution_gates` enforces in code. Those gates are procedural
controls owned by the operator, not an OS sandbox.
"""

from __future__ import annotations

import copy
import dataclasses
import json
from functools import partial
import secrets
import signal
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from types import FrameType
from typing import Any, Final

from ..runner import cleanup as cl
from ..runner.docker_cli import (
    ALLOWED_OP_TYPES,
    FORBIDDEN_TOKENS,
    SNAPSHOT_KINDS,
    CommandResult,
    ContainerRef,
    ContextInspect,
    Create,
    Executor,
    ImageInspect,
    Inspect,
    Logs,
    SnapshotList,
    Start,
    Stop,
    Version,
    Wait,
    create_argv_tail,
    docker_options_of,
)
from ..runner.inspect_gate import check_create_argv, check_created_container, parse_single_inspect
from ..runner.policy import (
    APPROVED_PROBE_IMAGE_ID,
    CEILINGS,
    GIB,
    LimitClass,
    ContainerId,
    ContainerSpec,
    ImageId,
    Ownership,
    PolicyViolation,
    ResourceLimits,
    Role,
    build_spec,
    check_profile_document,
    script_sha256,
)
from . import evidence as ev
from .interpret import (
    CleanupFacts,
    ContainerFacts,
    LogFacts,
    Outcome,
    PolicyFact,
    RunFacts,
    SleeperFacts,
    interpret,
    parse_stream,
    suite_status,
)

TV_DEADLINE_SECONDS: Final = 150
STANDALONE_DEADLINE_SECONDS: Final = 90
SLEEPER_DEADLINE_SECONDS: Final = 10
LOGFLOOD_READ_CAP: Final = 12 * 1024 * 1024
COLLECTOR_TEST_CAP: Final = 1024 * 1024
STANDARD_LOG_CAP: Final = 1024 * 1024
REMOVED_STATUSES: Final = frozenset({cl.CleanupStatus.REMOVED, cl.CleanupStatus.FORCE_REMOVED})


GLOBAL_DEADLINE_SECONDS: Final = 20 * 60  # owner-approved 2026-10-11
CLEANUP_WINDOW_SECONDS: Final = 2 * 60
MIN_OP_TIMEOUT_SECONDS: Final = 0.5


class SuiteInterrupted(Exception):
    """Raised from the SIGTERM handler so the finally-block cleanup runs."""


class SuiteDeadlineExceeded(Exception):
    """The 20-minute active-execution budget is spent; no further probe operation may start."""


class CleanupWindowExpired(Exception):
    """The separate 2-minute cleanup window is spent; remaining containers are CLEANUP_FAILED."""


class ExecutionBudget:
    """Monotonic budgets: one for active probing, then a separate one for cleanup."""

    def __init__(self, clock: Callable[[], float], active_seconds: float, cleanup_seconds: float) -> None:
        self.clock = clock
        self.active_seconds = active_seconds
        self.cleanup_seconds = cleanup_seconds
        self.started: float | None = None
        self.cleanup_started: float | None = None

    def begin(self) -> None:
        self.started = self.clock()

    def start_cleanup(self) -> None:
        if self.cleanup_started is None:
            self.cleanup_started = self.clock()

    @property
    def in_cleanup(self) -> bool:
        return self.cleanup_started is not None

    def remaining(self) -> float:
        if self.cleanup_started is not None:
            return self.cleanup_seconds - (self.clock() - self.cleanup_started)
        if self.started is None:
            return self.active_seconds
        return self.active_seconds - (self.clock() - self.started)

    def elapsed(self) -> float:
        return 0.0 if self.started is None else self.clock() - self.started


# --- Execution gates (A2, A3, A4) --------------------------------------------------------


def check_execution_gates(
    image: ImageId, evidence_root: Path, *, operator_confirmed: bool,
    approved_image_id: str | None = APPROVED_PROBE_IMAGE_ID,
) -> None:
    if approved_image_id is None:
        raise PolicyViolation("A2 not satisfied: no approved probe image identity is recorded in policy code")
    if image.value != approved_image_id:
        raise PolicyViolation("A2 not satisfied: requested image ID differs from the approved identity")
    ev.verify_evidence_root(evidence_root)
    if not operator_confirmed:
        raise PolicyViolation("A4 not satisfied: the operator has not confirmed this execution")


# --- Policy refusal checks (POL-*): no Docker call is permitted ------------------------


def _profile_example() -> dict[str, Any]:
    return {
        "schema_version": "1.1", "profile_id": "probe-policy-check", "profile_version": "0.1.0",
        "adapter": "python-asgi-http-v1", "target_image_id": "sha256:" + "a" * 64,
        "verifier_image_id": "sha256:" + "b" * 64, "asgi_app": "papertrail.app:app",
        "fixture_contract": "synthetic-documents-v1", "network_policy": "none-shared-loopback-v1",
        "source_scope": {"include": ["papertrail"]},
        "resources": {
            "target": {"cpus": 1, "memory_bytes": GIB, "pids": 128, "scratch_tmpfs_bytes": 268435456,
                       "tmp_tmpfs_bytes": 67108864},
            "verifier": {"cpus": 1, "memory_bytes": 536870912, "pids": 128, "scratch_tmpfs_bytes": 117440512,
                         "tmp_tmpfs_bytes": 16777216},
        },
        "timeouts": {"readiness_seconds": 30, "request_connect_seconds": 5, "request_read_seconds": 5,
                     "revision_deadline_seconds": 180, "cancellation_grace_seconds": 5},
        "logging": {"max_file_bytes": 5242880, "max_files": 2},
        "result_cap_bytes": 10485760,
    }


def _refused(fn: Callable[[], object]) -> tuple[bool, str]:
    try:
        fn()
    except PolicyViolation as exc:
        return True, str(exc)[:200]
    return False, "accepted"


def run_policy_refusals(executor_calls: Callable[[], int], ownership: Ownership, image: ImageId,
                        script: str) -> dict[str, PolicyFact]:
    """Exercise POL-P1 and POL-01..04 and count Docker invocations made meanwhile (must be 0)."""
    before = executor_calls()
    cases: dict[str, list[tuple[str, bool, str]]] = {k: [] for k in ("POL-P1", "POL-01", "POL-02", "POL-03", "POL-04")}

    def with_field(key: str, value: object) -> dict[str, Any]:
        doc = _profile_example()
        doc[key] = value
        return doc

    target = build_spec(ownership=ownership, role=Role.TARGET, image=image, script=script, args=("target", "0" * 32))
    for label, fn in (
        ("profile example", lambda: check_profile_document(_profile_example())),
        ("target spec", lambda: target),
        ("verifier spec", lambda: build_spec(ownership=ownership, role=Role.VERIFIER, image=image, script=script,
                                             args=("verifier", "0" * 32), join_target=ContainerId("c" * 64))),
    ):
        cases["POL-P1"].append((label, *_refused(fn)))
    for label, doc in (("privileged true", with_field("privileged", True)),
                       ("cap_add", with_field("cap_add", ["SYS_ADMIN"])),
                       ("security_opt unconfined", with_field("security_opt", ["seccomp=unconfined"]))):
        cases["POL-01"].append((label, *_refused(partial(check_profile_document, doc))))
    for label, doc in (("docker socket mount", with_field("mounts", ["/var/run/docker.sock:/var/run/docker.sock"])),
                       ("home bind", with_field("volumes", ["/Users:/host"])),
                       ("bridge network", with_field("network_policy", "bridge")),
                       ("host network", with_field("network_mode", "host")),
                       ("raw docker args", with_field("docker_args", ["--privileged"])),
                       ("environment", with_field("environment", {"AWS_SECRET_ACCESS_KEY": "x"}))):
        cases["POL-02"].append((label, *_refused(partial(check_profile_document, doc))))
    cases["POL-02"].append(("verifier without exact target join", *_refused(lambda: build_spec(
        ownership=ownership, role=Role.VERIFIER, image=image, script=script, args=("verifier", "0" * 32)))))
    cases["POL-02"].append(("target joining another namespace", *_refused(lambda: build_spec(
        ownership=ownership, role=Role.TARGET, image=image, script=script, args=("target", "0" * 32),
        join_target=ContainerId("d" * 64)))))
    for ref in ("python:latest", "python:3.13-slim", "python@sha256:" + "e" * 64, "sha256:abc123", "e" * 64,
                "docker.io/library/python:3.13"):
        cases["POL-03"].append((ref, *_refused(partial(ImageId, ref))))
        cases["POL-03"].append((f"profile {ref}", *_refused(
            partial(check_profile_document, with_field("target_image_id", ref)))))
    ceiling = CEILINGS[LimitClass.TARGET]
    for label, limits in (
        ("memory above ceiling", ResourceLimits(ceiling.nano_cpus, ceiling.memory_bytes * 2, ceiling.pids,
                                                ceiling.scratch_bytes, ceiling.tmp_bytes, ceiling.deadline_seconds)),
        ("cpus above ceiling", ResourceLimits(ceiling.nano_cpus * 2, ceiling.memory_bytes, ceiling.pids,
                                              ceiling.scratch_bytes, ceiling.tmp_bytes, ceiling.deadline_seconds)),
        ("pids above ceiling", ResourceLimits(ceiling.nano_cpus, ceiling.memory_bytes, 4096,
                                              ceiling.scratch_bytes, ceiling.tmp_bytes, ceiling.deadline_seconds)),
        ("scratch above ceiling", ResourceLimits(ceiling.nano_cpus, ceiling.memory_bytes, ceiling.pids,
                                                 ceiling.scratch_bytes * 4, ceiling.tmp_bytes,
                                                 ceiling.deadline_seconds)),
        ("zero memory (unlimited)", ResourceLimits(ceiling.nano_cpus, 0, ceiling.pids,
                                                   ceiling.scratch_bytes, ceiling.tmp_bytes, ceiling.deadline_seconds)),
    ):
        cases["POL-04"].append((label, *_refused(partial(
            build_spec, ownership=ownership, role=Role.TARGET, image=image, script=script,
            args=("target", "0" * 32), limits=limits))))
    doc = _profile_example()
    doc["resources"]["verifier"]["memory_bytes"] = 2 * GIB
    cases["POL-04"].append(("profile verifier memory 2 GiB", *_refused(lambda: check_profile_document(doc))))
    calls = executor_calls() - before
    return {k: PolicyFact(cases=v, docker_calls=calls) for k, v in cases.items()}


GATE_MUTATIONS: Final[tuple[tuple[str, Callable[[dict[str, Any]], None]], ...]] = (
    ("privileged", lambda o: o["HostConfig"].__setitem__("Privileged", True)),
    ("cap-add SYS_ADMIN", lambda o: o["HostConfig"].__setitem__("CapAdd", ["SYS_ADMIN"])),
    ("docker socket bind", lambda o: o["HostConfig"].__setitem__(
        "Binds", ["/var/run/docker.sock:/var/run/docker.sock"])),
    ("bridge network", lambda o: o["HostConfig"].__setitem__("NetworkMode", "bridge")),
    ("seccomp unconfined", lambda o: o["HostConfig"].__setitem__("SecurityOpt",
                                                                  ["no-new-privileges=true", "seccomp=unconfined"])),
    ("unlimited memory", lambda o: o["HostConfig"].__setitem__("Memory", 0)),
    ("host pid namespace", lambda o: o["HostConfig"].__setitem__("PidMode", "host")),
    ("published port", lambda o: o["HostConfig"].__setitem__("PortBindings", {"8080/tcp": [{"HostPort": "8080"}]})),
    ("root user", lambda o: o["Config"].__setitem__("User", "0:0")),
    ("writable rootfs", lambda o: o["HostConfig"].__setitem__("ReadonlyRootfs", False)),
    ("missing CapDrop", lambda o: o["HostConfig"].pop("CapDrop", None)),
)


ARGV_MUTATIONS: Final[tuple[tuple[str, Callable[[list[str]], list[str]]], ...]] = (
    ("create without --pull=never", lambda a: [t for t in a if t != "--pull=never"]),
    ("create with --pull=always", lambda a: ["--pull=always" if t == "--pull=never" else t for t in a]),
    ("create without --platform", lambda a: [t for i, t in enumerate(a)
                                             if t != "--platform" and (i == 0 or a[i - 1] != "--platform")]),
    ("create for linux/arm64", lambda a: ["linux/arm64" if t == "linux/amd64" else t for t in a]),
    ("create by tag", lambda a: ["python:3.13-slim" if t.startswith("sha256:") and len(t) == 71 else t for t in a]),
)


def gate_mutation_results(inspect: Mapping[str, Any], spec: ContainerSpec, cid: ContainerId,
                          image_env: tuple[str, ...], argv: list[str]) -> list[tuple[str, bool]]:
    def rejected(obj: Mapping[str, Any], tail: list[str]) -> bool:
        return not check_created_container(obj, spec, cid, image_env, create_argv=tail).passed

    results = [("", rejected(inspect, argv))]
    for name, mutate in GATE_MUTATIONS:
        mutated = copy.deepcopy(dict(inspect))
        mutate(mutated)
        results.append((name, rejected(mutated, argv)))
    for name, mutate_argv in ARGV_MUTATIONS:
        results.append((name, rejected(inspect, mutate_argv(list(argv)))))
    return results


# --- Preservation snapshots (CLN-06) -----------------------------------------------------

_SNAPSHOT_KEYS: Final[Mapping[str, tuple[str, ...]]] = {
    "images": ("ID", "Repository", "Tag", "Digest"),
    "containers": ("ID", "Names", "Image", "State"),
    "volumes": ("Name", "Driver"),
    "networks": ("ID", "Name", "Driver"),
    "system-df": ("Type", "TotalCount"),
}


def normalize_snapshot(kind: str, stdout: bytes) -> list[str]:
    """Stable identity fields only; relative-time fields such as Status are dropped."""
    keys = _SNAPSHOT_KEYS[kind]
    rows = []
    for raw in stdout.decode("utf-8").splitlines():
        if not raw.strip():
            continue
        obj = json.loads(raw)
        if not isinstance(obj, dict) or any(k not in obj for k in keys):
            raise ValueError(f"{kind} snapshot row lacks identity fields")
        rows.append(json.dumps([str(obj[k]) for k in keys]))
    return sorted(rows)


def compare_snapshots(before: Mapping[str, list[str]], after: Mapping[str, list[str]]) -> list[str]:
    differences = []
    for kind in SNAPSHOT_KINDS:
        b, a = set(before.get(kind, [])), set(after.get(kind, []))
        differences += [f"{kind}: missing after run: {row}" for row in sorted(b - a)]
        differences += [f"{kind}: new after run: {row}" for row in sorted(a - b)]
    return differences


# --- Command-log audit (CLN-05) -----------------------------------------------------------


def audit_command_log(results: list[CommandResult]) -> tuple[Outcome, str]:
    allowed = {"context-inspect", "version", "image-inspect", "create", "inspect", "start", "wait", "logs",
               "stop", "remove", "force-remove", "snapshot"}
    problems = []
    forced = 0
    for index, res in enumerate(results):
        if res.op_name not in allowed:
            problems.append(f"non-allowlisted op {res.op_name}")
        if res.op_name == "force-remove":
            forced += 1
            cid = res.argv[-1]
            if list(res.argv[-5:]) != ["container", "rm", "--force", "--", cid] or len(cid) != 64:
                problems.append("force-remove argv deviates from its fixed shape")
            last_write = max((i for i in range(index) if results[i].op_name in ("stop", "remove")
                              and results[i].argv[-1] == cid), default=-1)
            reinspected = any(results[i].op_name == "inspect" and results[i].argv[-1] == cid
                              for i in range(last_write + 1, index))
            if last_write < 0 or not reinspected:
                problems.append("force-remove without a failed stop/remove and a fresh ownership re-inspect")
            continue
        tokens = docker_options_of(res.argv) if res.op_name == "create" else list(res.argv[:-1])
        bad = [t for t in tokens if t in FORBIDDEN_TOKENS or "unconfined" in t]
        if bad:
            problems.append(f"{res.op_name}: forbidden tokens {bad}")
    if not results:
        return Outcome.NOT_RUN, "no Docker commands executed"
    if problems:
        return Outcome.FAIL, "; ".join(problems[:6])
    suffix = f"; {forced} verified force-removal(s)" if forced else ""
    return Outcome.PASS, f"{len(results)} commands, all allowlisted operations{suffix}"


# --- The suite ---------------------------------------------------------------------------


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class ContainerRun:
    spec: ContainerSpec
    facts: ContainerFacts
    cid: ContainerId | None = None
    create_argv: list[str] = field(default_factory=list)
    mismatches: list[dict[str, str]] = field(default_factory=list)
    cleanup: cl.CleanupResult | None = None


class CountingExecutor:
    """Wraps an executor: allowlist, budget check before every operation, timeout bounded
    by the remaining budget, and the command log for audit."""

    def __init__(self, inner: Executor, budget: ExecutionBudget | None = None) -> None:
        self.inner = inner
        self.budget = budget
        self.log: list[CommandResult] = []

    def run(self, op: Any) -> CommandResult:
        if not isinstance(op, ALLOWED_OP_TYPES):
            raise PolicyViolation(f"operation {type(op).__name__} is not allowlisted")
        if self.budget is not None:
            remaining = self.budget.remaining()
            if remaining <= 0:
                raise CleanupWindowExpired() if self.budget.in_cleanup else SuiteDeadlineExceeded()
            if op.timeout_seconds > remaining:
                op = dataclasses.replace(op, timeout_seconds=max(remaining, MIN_OP_TIMEOUT_SECONDS))
        result = self.inner.run(op)
        self.log.append(result)
        return result

    @property
    def calls(self) -> int:
        return len(self.log)


class ProbeSuite:
    def __init__(self, executor: Executor, ownership: Ownership, image: ImageId, script: str, *, home: str,
                 run_dir: Path | None = None, nonce: str | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 deadline_seconds: float = GLOBAL_DEADLINE_SECONDS,
                 cleanup_seconds: float = CLEANUP_WINDOW_SECONDS) -> None:
        if not 0 <= deadline_seconds <= GLOBAL_DEADLINE_SECONDS or not 0 <= cleanup_seconds <= CLEANUP_WINDOW_SECONDS:
            raise PolicyViolation("execution budgets may only be at or below the approved 20 min / 2 min")
        self.budget = ExecutionBudget(clock, deadline_seconds, cleanup_seconds)
        self.exec = CountingExecutor(executor, self.budget)
        self.phase = "not-started"
        self.deadline_expired = False
        self.expired_during: str | None = None
        self.interrupted = False
        self.cleanup_window_expired = False
        self.ownership = ownership
        self.image = image
        self.script = script
        self.home = home
        self.run_dir = run_dir
        self.nonce = nonce or secrets.token_hex(16)
        self.registry = cl.OwnershipRegistry(
            ownership=ownership, journal_path=(run_dir / "journal.jsonl") if run_dir else None)
        self.facts = RunFacts(nonce=self.nonce)
        self.runs: dict[Role, ContainerRun] = {}
        self.server_version: str | None = None
        self.image_record: dict[str, Any] | None = None
        self.preservation: dict[str, Any] = {"outcome": "NOT_RUN", "differences": []}
        self.extra_limitations: list[str] = []
        self.inspect_dumps: dict[str, Any] = {}

    # -- helpers ------------------------------------------------------------------

    def _spec(self, role: Role, mode: str, join: ContainerId | None = None) -> ContainerSpec:
        return build_spec(ownership=self.ownership, role=role, image=self.image, script=self.script,
                          args=(mode, self.nonce), join_target=join)

    def _inspect(self, cid: ContainerId) -> dict[str, Any] | None:
        res = self.exec.run(Inspect(ContainerRef(cid.value)))
        if not res.ok:
            return None
        try:
            return parse_single_inspect(res.stdout, cid)
        except ValueError:
            return None

    def create_and_gate(self, spec: ContainerSpec) -> ContainerRun:
        run = ContainerRun(spec=spec, facts=ContainerFacts(role=spec.role))
        self.runs[spec.role] = run
        self.registry.plan(spec.name, spec.role)
        res = self.exec.run(Create(spec))
        run.create_argv = list(res.argv[3:])  # drop "<docker> --context desktop-linux"
        text = res.stdout.decode("utf-8", "replace").strip()
        try:
            cid = ContainerId(text)
        except PolicyViolation:
            run.facts.error = f"create failed or returned no ID (rc={res.returncode})"
            return run
        self.registry.record_created(spec.name, cid)
        run.cid, run.facts.created = cid, True
        inspected = self._inspect(cid)
        if inspected is None:
            run.facts.gate_passed, run.facts.error = False, "inspect after create failed"
            return run
        self.inspect_dumps[f"{spec.role.value}-created"] = inspected
        gate = check_created_container(inspected, spec, cid, self.facts.image_env, create_argv=run.create_argv)
        run.facts.gate_passed = gate.passed
        run.facts.gate_summary = gate.summary()
        run.facts.inspect = inspected
        run.mismatches = [{"field": m.field, "expected": m.expected, "observed": m.observed}
                          for m in gate.mismatches]
        return run

    def start(self, run: ContainerRun) -> bool:
        if run.cid is None or run.facts.gate_passed is not True:
            return False
        res = self.exec.run(Start(run.cid))
        run.facts.started = res.ok
        if not res.ok:
            run.facts.error = "start failed"
        return res.ok

    def wait_and_collect(self, run: ContainerRun, deadline: float,
                         log_cap: int = STANDARD_LOG_CAP) -> CommandResult | None:
        if run.cid is None or not run.facts.started:
            return None
        res = self.exec.run(Wait(run.cid, timeout_seconds=deadline))
        if res.timed_out:
            run.facts.wait_timed_out = True
            self.exec.run(Stop(run.cid))
        after = self._inspect(run.cid)
        if after is not None:
            self.inspect_dumps[f"{run.spec.role.value}-exited"] = after
            state = _mapping(after.get("State"))
            exit_code = state.get("ExitCode")
            run.facts.exit_code = exit_code if type(exit_code) is int else None
            run.facts.oom_killed = state.get("OOMKilled") if isinstance(state.get("OOMKilled"), bool) else None
        logs = self.exec.run(Logs(run.cid, stdout_cap=log_cap))
        if logs.returncode == 0 or logs.stdout_truncated:
            run.facts.stream = parse_stream(logs.stdout, run.spec.role, self.nonce, truncated=logs.stdout_truncated)
        else:
            run.facts.error = "log collection failed"
        if self.run_dir:
            ev.write_private(self.run_dir, f"stdout-{run.spec.role.value}.log", logs.stdout)
        return logs

    def remove(self, run: ContainerRun) -> None:
        if run.cid is None or run.cleanup is not None:
            return
        remover = cl.remove_decoy if run.spec.role.is_decoy else cl.remove_owned
        try:
            run.cleanup = remover(self.exec, self.registry, run.cid)
        except CleanupWindowExpired:
            # One attempt per container in the window; no retry, nothing broader.
            self.cleanup_window_expired = True
            run.cleanup = cl.CleanupResult(
                run.spec.name, run.cid.value, cl.CleanupStatus.FAILED,
                f"CLEANUP_FAILED: the {self.budget.cleanup_seconds:g} s cleanup window expired before removal "
                "was confirmed")
            self.registry.record_outcome(run.cleanup)

    # -- phases -------------------------------------------------------------------

    def preflight(self) -> bool:
        res = self.exec.run(ContextInspect())
        expected = f"unix://{self.home}/.docker/run/docker.sock"
        try:
            ctx = json.loads(res.stdout.decode("utf-8")) if res.ok else None
            host = ctx[0]["Endpoints"]["docker"]["Host"] if isinstance(ctx, list) and len(ctx) == 1 else None
        except (ValueError, KeyError, TypeError, IndexError):
            host = None
        if host != expected:
            self.facts.host["PRE-01"] = (Outcome.BLOCKED, "context endpoint is not the expected Docker Desktop socket")
            return False
        self.facts.host["PRE-01"] = (Outcome.PASS, "desktop-linux context on the Docker Desktop user socket")
        ver = self.exec.run(Version())
        try:
            self.server_version = str(json.loads(ver.stdout.decode("utf-8"))["Server"]["Version"])[:32]
        except (ValueError, KeyError, TypeError):
            self.server_version = None
        img = self.exec.run(ImageInspect(self.image))
        try:
            data = json.loads(img.stdout.decode("utf-8")) if img.ok else None
            obj = data[0] if isinstance(data, list) and len(data) == 1 else None
        except ValueError:
            obj = None
        if not isinstance(obj, dict):
            self.facts.host["PRE-02"] = (Outcome.BLOCKED, "approved image not present locally; no pull attempted")
            return False
        config = _mapping(obj.get("Config"))
        env = config.get("Env")
        problems = []
        if obj.get("Id") != self.image.value:
            problems.append("Id differs")
        if obj.get("Os") != "linux" or obj.get("Architecture") != "amd64":
            problems.append(f"platform {obj.get('Os')}/{obj.get('Architecture')}")
        if config.get("Volumes"):
            problems.append("image declares volumes (anonymous volumes would be created)")
        if not isinstance(env, list) or not all(isinstance(e, str) for e in env):
            problems.append("image Env unreadable")
        if problems:
            self.facts.host["PRE-02"] = (Outcome.BLOCKED, "; ".join(problems))
            return False
        self.facts.image_env = tuple(env)  # type: ignore[arg-type]
        raw_digests = obj.get("RepoDigests")
        digests: list[Any] = raw_digests if isinstance(raw_digests, list) else []
        self.image_record = {"image_id": self.image.value, "repo_digests": [str(d)[:200] for d in digests][:8],
                             "os": "linux", "architecture": "amd64"}
        self.facts.host["PRE-02"] = (Outcome.PASS, "approved image present; linux/amd64; no declared volumes")
        return True

    def snapshot(self) -> dict[str, list[str]] | None:
        out: dict[str, list[str]] = {}
        for kind in SNAPSHOT_KINDS:
            res = self.exec.run(SnapshotList(kind))
            if not res.ok or res.stdout_truncated:
                return None
            try:
                out[kind] = normalize_snapshot(kind, res.stdout)
            except ValueError:
                return None
        return out

    def phase_policy(self) -> None:
        self.facts.policy = run_policy_refusals(lambda: self.exec.calls, self.ownership, self.image, self.script)
        specs = [self._spec(r, m) for r, m in ((Role.TARGET, "target"), (Role.MEMORY, "memory"))]
        ok = all(not check_create_argv(create_argv_tail(s), s) for s in specs)
        self.facts.host["PRE-03"] = (
            (Outcome.PASS, "--platform linux/amd64, --pull=never and the full image ID in every create")
            if ok else (Outcome.FAIL, "create argv lacks --platform, --pull=never, or the image ID"))

    def phase_target_verifier(self) -> None:
        t = self.create_and_gate(self._spec(Role.TARGET, "target"))
        if t.cid is not None and t.facts.inspect is not None:
            self.facts.gate_mutations = gate_mutation_results(t.facts.inspect, t.spec, t.cid, self.facts.image_env,
                                                              t.create_argv)
        if not self.start(t) or t.cid is None:
            return
        v = self.create_and_gate(self._spec(Role.VERIFIER, "verifier", join=t.cid))
        if self.start(v):
            self.wait_and_collect(v, TV_DEADLINE_SECONDS)
        self.wait_and_collect(t, TV_DEADLINE_SECONDS if not v.facts.started else 30)
        self.remove(v)
        self.remove(t)

    def phase_standalone(self, role: Role, mode: str) -> ContainerRun:
        run = self.create_and_gate(self._spec(role, mode))
        if self.start(run):
            self.wait_and_collect(run, STANDALONE_DEADLINE_SECONDS)
        self.remove(run)
        return run

    def phase_logflood(self) -> None:
        run = self.create_and_gate(self._spec(Role.LOGFLOOD, "logflood"))
        if self.start(run):
            full = self.wait_and_collect(run, STANDALONE_DEADLINE_SECONDS, log_cap=LOGFLOOD_READ_CAP)
            if full is not None and run.cid is not None and run.facts.stream is not None:
                capped = self.exec.run(Logs(run.cid, stdout_cap=COLLECTOR_TEST_CAP))
                end = run.facts.stream.marker("flood-end")
                reported = end.get("bytes") if end else None
                self.facts.log = LogFacts(
                    uncapped_bytes=len(full.stdout), uncapped_truncated=full.stdout_truncated,
                    flood_start_present=run.facts.stream.marker("flood-start") is not None,
                    flood_end_present=end is not None,
                    flood_end_reported_bytes=reported if type(reported) is int else None,
                    capped_bytes=len(capped.stdout), capped_truncated=capped.stdout_truncated,
                    cap_bytes=COLLECTOR_TEST_CAP)
        self.remove(run)

    def phase_sleeper(self) -> None:
        run = self.create_and_gate(self._spec(Role.SLEEPER, "sleeper"))
        if not self.start(run) or run.cid is None:
            self.remove(run)
            return
        waited = self.exec.run(Wait(run.cid, timeout_seconds=SLEEPER_DEADLINE_SECONDS))
        started = time.monotonic()
        stop = self.exec.run(Stop(run.cid)) if waited.timed_out else None
        stop_seconds = round(time.monotonic() - started, 3)
        after = self._inspect(run.cid)
        state = _mapping(after.get("State")) if after else None
        logs = self.exec.run(Logs(run.cid))
        run.facts.stream = parse_stream(logs.stdout, Role.SLEEPER, self.nonce, truncated=logs.stdout_truncated)
        run.facts.wait_timed_out = waited.timed_out
        self.remove(run)
        self.facts.sleeper = SleeperFacts(
            sleeping_marker=run.facts.stream.marker("sleeping") is not None,
            deadline_expired=waited.timed_out,
            stop_ok=bool(stop and stop.ok),
            stop_seconds=stop_seconds,
            running_after_stop=(state.get("Running") if state and isinstance(state.get("Running"), bool) else None),
            removed=run.cleanup is not None and run.cleanup.status in REMOVED_STATUSES,
        )

    def phase_decoys(self) -> tuple[bool | None, bool | None, bool | None, bool | None]:
        """Create never-started decoys, check refusal, then tear them down separately."""
        other = self.create_and_gate(self._spec(Role.DECOY_OTHER_RUN, "sleeper"))
        foreign = self.create_and_gate(self._spec(Role.DECOY_FOREIGN, "sleeper"))
        results: list[bool | None] = []
        for decoy in (other, foreign):
            if decoy.cid is None:
                results += [None, None]
                continue
            # Ask the owned-container cleanup routine to remove the decoy: it must refuse.
            entry = self.registry.entries[decoy.spec.name]
            attempt = self._remove_owned_bypassing_role(decoy.cid, entry)
            still_there = self._inspect(decoy.cid) is not None
            results += [attempt.status is cl.CleanupStatus.REFUSED, still_there]
        for decoy in (other, foreign):
            self.remove(decoy)
        return results[0], results[1], results[2], results[3]

    def _remove_owned_bypassing_role(self, cid: ContainerId, entry: cl.RegistryEntry) -> cl.CleanupResult:
        """CLN-02/03: present the decoy to remove_owned as if it were an owned entry.

        The registry role marks it as a decoy, which remove_owned would refuse on its own.
        To test the label check rather than the role check, a temporary registry presents
        the decoy as an owned container; the label check must still refuse it.
        """
        probe_registry = cl.OwnershipRegistry(ownership=self.ownership)
        probe_registry.entries[entry.name] = cl.RegistryEntry(entry.name, Role.TARGET, cid)
        return cl.remove_owned(self.exec, probe_registry, cid)

    # -- driver -------------------------------------------------------------------

    def run(self, authorization: Mapping[str, bool]) -> dict[str, Any]:
        started_at = utc_now()
        previous = signal.getsignal(signal.SIGTERM)

        def on_term(signum: int, frame: FrameType | None) -> None:
            raise SuiteInterrupted()

        signal.signal(signal.SIGTERM, on_term)
        decoy_facts: tuple[bool | None, ...] = (None, None, None, None)
        before: dict[str, list[str]] | None = None
        self.budget.begin()
        try:
            self.phase = "preflight"
            if self.preflight():
                self.phase = "snapshot-before"
                before = self.snapshot()
                if before is None:
                    self.facts.host["CLN-06"] = (Outcome.BLOCKED, "before-snapshot failed; no container created")
                else:
                    self.phase = "policy-refusal"
                    self.phase_policy()
                    self.phase = "target-verifier"
                    self.phase_target_verifier()
                    for role, mode in ((Role.MEMORY, "memory"), (Role.PIDS, "pids"), (Role.CPU, "cpu"),
                                       (Role.STORAGE, "storage")):
                        self.phase = mode
                        self.phase_standalone(role, mode)
                    self.phase = "logflood"
                    self.phase_logflood()
                    self.phase = "sleeper"
                    self.phase_sleeper()
                    self.phase = "decoys"
                    decoy_facts = self.phase_decoys()
                    self.phase = "complete"
        except SuiteDeadlineExceeded:
            self.deadline_expired, self.expired_during = True, self.phase
            self.extra_limitations.append(
                f"Global execution deadline ({self.budget.active_seconds:g} s) expired during phase '{self.phase}'. "
                "Probes not yet run are NOT_RUN or INCONCLUSIVE; completed observations are kept.")
        except (SuiteInterrupted, KeyboardInterrupt):
            self.interrupted = True
            self.extra_limitations.append("Run interrupted; remaining owned containers cleaned up by exact ID.")
        finally:
            self.budget.start_cleanup()
            self._final_cleanup()
            if before is not None:
                self._check_preservation(before)
            signal.signal(signal.SIGTERM, previous)
        return self._finish(started_at, authorization, decoy_facts)

    def _check_preservation(self, before: dict[str, list[str]]) -> None:
        """Read-only after-snapshot, inside the cleanup window, after every removal attempt."""
        try:
            after = self.snapshot()
        except CleanupWindowExpired:
            self.facts.host["CLN-06"] = (Outcome.NOT_RUN, "cleanup window expired before the after-snapshot")
            return
        if after is None:
            self.facts.host["CLN-06"] = (Outcome.ERROR, "after-snapshot failed")
            return
        diffs = compare_snapshots(before, after)
        self.preservation = {"outcome": "FAIL" if diffs else "PASS", "differences": diffs[:64]}
        self.facts.host["CLN-06"] = ((Outcome.FAIL, "; ".join(diffs[:4])) if diffs
                                     else (Outcome.PASS, "snapshots identical"))
        if self.run_dir:
            ev.write_private(self.run_dir, "snapshot-before.json", json.dumps(before).encode())
            ev.write_private(self.run_dir, "snapshot-after.json", json.dumps(after).encode())

    def execution_summary(self) -> dict[str, Any]:
        tracked = [r for r in self.runs.values() if r.cid is not None]
        removed = {cl.CleanupStatus.REMOVED, cl.CleanupStatus.FORCE_REMOVED, cl.CleanupStatus.ALREADY_ABSENT}
        failed = [r for r in tracked if r.cleanup is None or r.cleanup.status not in removed]
        return {
            "global_deadline_seconds": self.budget.active_seconds,
            "cleanup_window_seconds": self.budget.cleanup_seconds,
            "active_elapsed_seconds": round(min(self.budget.elapsed(), 10**6), 3),
            "deadline_expired": self.deadline_expired,
            "expired_during_phase": self.expired_during,
            "interrupted": self.interrupted,
            "cleanup_window_expired": self.cleanup_window_expired,
            "cleanup_status": "NOT_NEEDED" if not tracked else ("CLEANUP_FAILED" if failed else "COMPLETE"),
        }

    def _final_cleanup(self) -> None:
        for run in self.runs.values():
            self.remove(run)

    def _finish(self, started_at: str, authorization: Mapping[str, bool],
                decoy_facts: tuple[bool | None, ...]) -> dict[str, Any]:
        self.facts.containers = {role: run.facts for role, run in self.runs.items()}
        owned = [r for r in self.runs.values() if not r.spec.role.is_decoy and r.cid is not None]
        decoys = [r for r in self.runs.values() if r.spec.role.is_decoy and r.cid is not None]
        if self.runs:
            self.facts.cleanup = CleanupFacts(
                owned_total=len(owned),
                owned_removed=sum(1 for r in owned if r.cleanup and r.cleanup.status in REMOVED_STATUSES),
                owned_forced=sum(1 for r in owned if r.cleanup and r.cleanup.status is cl.CleanupStatus.FORCE_REMOVED),
                owned_details=[f"{r.spec.name}: {r.cleanup.status.value if r.cleanup else 'none'}" for r in owned],
                other_run_refused=decoy_facts[0], other_run_present_after=decoy_facts[1],
                foreign_refused=decoy_facts[2], foreign_present_after=decoy_facts[3],
                decoys_removed=sum(1 for r in decoys if r.cleanup and r.cleanup.status in REMOVED_STATUSES),
                decoys_total=len(decoys))
        self.facts.host["CLN-05"] = audit_command_log(self.exec.log)
        if self.deadline_expired:
            self.facts.host["RES-15"] = (Outcome.INCONCLUSIVE, f"global deadline expired during phase "
                                         f"'{self.expired_during}'; unfinished checks were not run")
        elif self.interrupted:
            self.facts.host["RES-15"] = (Outcome.INCONCLUSIVE, "run interrupted before completion")
        elif self.phase == "complete":
            self.facts.host["RES-15"] = (Outcome.PASS, f"completed in {self.budget.elapsed():.1f} s of "
                                         f"{self.budget.active_seconds:g} s")
        outcomes = interpret(self.facts)
        status = suite_status(outcomes)
        records = [
            ev.ContainerRecord(
                facts=run.facts, name=run.spec.name, container_id=run.cid.value if run.cid else None,
                policy_digest=ev.requested_policy_digest(run.spec), gate_mismatches=run.mismatches,
                cleanup_status=run.cleanup.status.value if run.cleanup else "NOT_CREATED",
                cleanup_detail=run.cleanup.detail if run.cleanup else "")
            for run in self.runs.values()
        ]
        record = ev.build_record(
            ownership=self.ownership, started_at=started_at, finished_at=utc_now(),
            server_version=self.server_version, image=self.image_record,
            script_digest=script_sha256(self.script), authorization=authorization, containers=records,
            outcomes=outcomes, status=status, preservation=self.preservation,
            execution=self.execution_summary(), extra_limitations=self.extra_limitations)
        if self.run_dir:
            ev.write_private(self.run_dir, "inspect.json", json.dumps(self.inspect_dumps, default=str).encode())
            log = [{"op": r.op_name, "argv": [script_sha256(self.script) if a == self.script else a for a in r.argv],
                    "returncode": r.returncode, "timed_out": r.timed_out, "seconds": r.duration_seconds}
                   for r in self.exec.log]
            ev.write_private(self.run_dir, "commands.json", json.dumps(log).encode())
            ev.write_private(self.run_dir, "run-record.json", json.dumps(record, indent=2).encode())
        return record
