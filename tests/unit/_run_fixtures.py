"""PP-008 test fixtures: a scripted fake Docker executor and synthetic run plans.

Nothing here contacts Docker. Synthetic identities only:
- image IDs `sha256:aaaa…` (target) and `sha256:bbbb…` (verifier);
- run and installation IDs made of fixed hex;
- an approval made by a "Synthetic Reviewer", in a temporary directory.

None of these is an approval of the PaperTrail pack.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from patchproof.core.approvals import ReviewDecision, confirmation_phrase, create_approval
from patchproof.core.records import load_record
from patchproof.core.records.pack import ApprovalRecord, CollectedTest, ExecutionProfileV11
from patchproof.git.command import resolve_git_binary
from patchproof.git.paths import SourceScope
from patchproof.git.repository import register_repository
from patchproof.git.snapshot import create_snapshot
from patchproof.packs.validation import validate_pack
from patchproof.reference.papertrail import generate_reference_repository
from patchproof.runner.docker_cli import CommandResult, DockerOp, ImageInspect, Inspect, Logs, SnapshotList, Start, Stop
from patchproof.runner.inputs import SourceSnapshot, materialize_pack
from patchproof.runner.policy import ImageId, Ownership
from patchproof.runner.run_plan import ApprovedRunImage, RunPlan
from patchproof.runner.run_policy import TARGET_HEALTHCHECK, RunContainerSpec, RunCreate, RunRole, StartAttached

ROOT = Path(__file__).resolve().parents[2]
PACK_DIR = ROOT / "examples" / "packs" / "papertrail-document-access"
GROUND_TRUTH = json.loads((ROOT / "examples" / "papertrail" / "reference-fixture.json").read_text())
TARGET_IMAGE = "sha256:" + "a" * 64
VERIFIER_IMAGE = "sha256:" + "b" * 64
TARGET_ENV = ("PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "PYTHONDONTWRITEBYTECODE=1")
VERIFIER_ENV = ("PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "PYTHONDONTWRITEBYTECODE=1",
                "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1", "PYTHONHASHSEED=0", "HOME=/nonexistent", "LC_ALL=C.UTF-8")
OWNERSHIP = Ownership(installation_id="inst-" + "1" * 32, run_id="run-" + "2" * 32)
NOW = datetime(2026, 10, 12, 12, 0, tzinfo=UTC)

TARGET_RECORD = ApprovedRunImage(RunRole.TARGET, ImageId(TARGET_IMAGE), TARGET_ENV, TARGET_HEALTHCHECK)
VERIFIER_RECORD = ApprovedRunImage(RunRole.VERIFIER, ImageId(VERIFIER_IMAGE), VERIFIER_ENV, None)
APPROVED_IMAGES = (TARGET_RECORD, VERIFIER_RECORD)


def private(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return Path(os.path.realpath(path))


@dataclass
class Environment:
    plan: RunPlan
    approvals: list[ApprovalRecord]
    store: Path
    snapshots: dict[str, SourceSnapshot]


def build_environment(tmp: Path, *, baseline_tag: str = "refs/tags/authz-r1-vulnerable",
                      candidate_tag: str = "refs/tags/authz-r3-correct") -> Environment:
    work = private(tmp / "work")
    generated = generate_reference_repository(work / "repo")
    repo = register_repository(generated.root, resolve_git_binary())
    snaps_dir = private(work / "snapshots")
    scope = SourceScope.of(GROUND_TRUTH["target"]["source_scope"]["include"])
    snapshots = {}
    for side, tag in (("baseline", baseline_tag), ("candidate", candidate_tag)):
        result = create_snapshot(repo, tag, scope, snaps_dir)
        snapshots[side] = SourceSnapshot(Path(os.path.realpath(result.snapshot_dir)), result.manifest_sha256)
    pack = validate_pack(PACK_DIR)
    store = private(work / "packs")
    snapshot = materialize_pack(pack, store)
    profile_doc = json.loads((ROOT / "schemas/examples/valid/execution-profile.v1.1--papertrail-reference.json")
                             .read_text())
    profile = load_record(ExecutionProfileV11, json.dumps(profile_doc).encode())
    collection = tuple(CollectedTest(id=t.id, nodeid=t.nodeid) for t in pack.manifest.tests)
    draft = RunPlan(ownership=OWNERSHIP, profile=profile, manifest=pack.manifest, pack=snapshot,
                    approval_id="apr-" + "0" * 32, collection=collection, baseline=snapshots["baseline"],
                    candidate=snapshots["candidate"], pairs=1, target_image=TARGET_RECORD,
                    verifier_image=VERIFIER_RECORD)
    bindings = draft.binding_inputs().bindings()
    approval = create_approval(bindings, ReviewDecision("Synthetic Reviewer", "Synthetic unit-test approval.",
                                                        "Unit tests only.", confirmation_phrase(bindings)),
                               supersedes=None, now=NOW)
    plan = RunPlan(**{**draft.__dict__, "approval_id": approval.approval_id})
    return Environment(plan=plan, approvals=[approval], store=store, snapshots=snapshots)


# ------------------------------------------------------------------ synthetic event streams


def event(plan: RunPlan, pair: int, side: str, seq: int, kind: str, payload: dict[str, Any]) -> bytes:
    return (json.dumps({"schema_version": "1.0", "run_id": plan.ownership.run_id, "pair": pair, "side": side,
                        "seq": seq, "type": kind, "payload": payload}, separators=(",", ":")) + "\n").encode()


def stream(plan: RunPlan, pair: int, side: str, outcomes: dict[str, str]) -> bytes:
    """A complete, grammar-valid stream. outcomes: test ID -> VIOLATION_CONFIRMED|SECURE|PASS|FAIL."""
    seq = 0
    out = bytearray()

    def emit(kind: str, payload: dict[str, Any]) -> None:
        nonlocal seq
        out.extend(event(plan, pair, side, seq, kind, payload))
        seq += 1

    emit("session_start", {"verifier_plugin_version": "0.1.0", "pack_tree_sha256": plan.pack.pack_tree_sha256})
    emit("collected", {"tests": [c.model_dump() for c in plan.collection]})
    observations = 0
    for test in plan.collection:
        outcome = outcomes[test.id]
        emit("test_report", {"test_id": test.id, "phase": "setup", "outcome": "passed", "failure_class": "none",
                             "xfail": False})
        if outcome in ("VIOLATION_CONFIRMED", "SECURE"):
            observations += 1
            emit("observation", {"test_id": test.id, "outcome": outcome, "summary": "synthetic", "evidence_refs": []})
        failed = outcome in ("VIOLATION_CONFIRMED", "FAIL")
        emit("test_report", {"test_id": test.id, "phase": "call", "outcome": "failed" if failed else "passed",
                             "failure_class": {"VIOLATION_CONFIRMED": "security_terminal", "FAIL": "assertion"}.get(
                                 outcome, "none"), "xfail": False})
        emit("test_report", {"test_id": test.id, "phase": "teardown", "outcome": "passed", "failure_class": "none",
                             "xfail": False})
    emit("session_end", {"tests_reported": len(plan.collection), "observations_emitted": observations})
    return bytes(out)


def declared_outcomes(revision: str) -> dict[str, str]:
    """The PP-006 declared outcome per check for a revision (synthetic: not an observation)."""
    return {c["id"]: c["expected"][revision]["semantic"] for c in GROUND_TRUTH["checks"]}


# ------------------------------------------------------------------ scripted fake Docker


def ok(op: DockerOp, stdout: bytes = b"", **extra: Any) -> CommandResult:
    return CommandResult(op_name=op.op_name, argv=tuple(op.argv_tail()), returncode=extra.pop("returncode", 0),
                         stdout=stdout, stderr=extra.pop("stderr", b""),
                         stdout_truncated=extra.pop("stdout_truncated", False),
                         stderr_truncated=extra.pop("stderr_truncated", False),
                         timed_out=extra.pop("timed_out", False), duration_seconds=0.0)


def fail(op: DockerOp, stderr: bytes = b"error") -> CommandResult:
    return CommandResult(op_name=op.op_name, argv=tuple(op.argv_tail()), returncode=1, stdout=b"", stderr=stderr,
                         stdout_truncated=False, stderr_truncated=False, timed_out=False, duration_seconds=0.0)


def container_inspect(spec: RunContainerSpec, cid: str, env: tuple[str, ...], *, status: str = "created",
                      running: bool = False, health: str | None = None, exit_code: int = 0, oom: bool = False,
                      started_at: str = "2026-10-12T12:00:01Z") -> dict[str, Any]:
    state: dict[str, Any] = {"Status": status, "Running": running, "ExitCode": exit_code, "OOMKilled": oom,
                             "StartedAt": started_at}
    if health is not None:
        state["Health"] = {"Status": health}
    config: dict[str, Any] = {
        "Image": spec.image.value, "User": "10001:10001", "Entrypoint": ["/usr/local/bin/python3"],
        "Cmd": list(spec.command), "Labels": spec.label_map, "Env": list(env), "WorkingDir": "/scratch",
        "Tty": False, "OpenStdin": False, "AttachStdin": False, "ExposedPorts": None, "Volumes": None,
    }
    if spec.role is RunRole.TARGET:
        config["Healthcheck"] = TARGET_HEALTHCHECK
    limits = spec.limits
    return {
        "Id": cid, "Name": "/" + spec.name, "Image": spec.image.value, "Platform": "linux", "State": state,
        "Config": config,
        "HostConfig": {
            "Privileged": False, "CapDrop": ["ALL"], "CapAdd": None, "ReadonlyRootfs": True,
            "SecurityOpt": ["no-new-privileges=true"], "NetworkMode": spec.network.mode, "PortBindings": {},
            "PublishAllPorts": False, "Binds": None, "VolumesFrom": None, "Links": None, "Devices": [],
            "DeviceRequests": None, "DeviceCgroupRules": None, "ExtraHosts": [], "GroupAdd": None, "Sysctls": None,
            "CgroupParent": "", "Tmpfs": spec.tmpfs(), "Memory": limits.memory_bytes,
            "MemorySwap": limits.memory_bytes, "NanoCpus": limits.nano_cpus, "PidsLimit": limits.pids,
            "OomKillDisable": False, "Init": None, "PidMode": "", "IpcMode": "private", "ShmSize": 16777216,
            "UTSMode": "", "UsernsMode": "", "CgroupnsMode": "private", "Runtime": "runc", "AutoRemove": False,
            "LogConfig": {"Type": "local", "Config": {"max-size": "5m", "max-file": "2", "compress": "false"}},
            "MaskedPaths": ["/proc/kcore"], "ReadonlyPaths": ["/proc/sys"], "RestartPolicy": {"Name": "no"},
            "Mounts": [{"Type": "bind", "Source": str(spec.input.source), "Target": spec.input.destination,
                        "ReadOnly": True}],
        },
        "Mounts": [{"Type": "bind", "Source": str(spec.input.source), "Destination": spec.input.destination,
                    "Mode": "", "RW": False, "Propagation": "rprivate"}],
        "NetworkSettings": {"Ports": {}},
    }


def image_inspect(record: ApprovedRunImage) -> bytes:
    config: dict[str, Any] = {"Env": list(record.env)}
    if record.healthcheck is not None:
        config["Healthcheck"] = record.healthcheck
    return json.dumps([{"Id": record.image.value, "Os": "linux", "Architecture": "amd64", "Config": config}]).encode()


def default_listings() -> dict[str, list[dict[str, Any]]]:
    """A plausible unrelated inventory: one foreign container, the built-in networks, a volume."""
    return {
        "images": [{"ID": "sha256:" + "4e" * 32, "Repository": "example/unrelated", "Tag": "1", "Digest": "<none>"}],
        "containers": [{"ID": "f0" * 32, "Names": "someone-elses-container", "Image": "example/unrelated:1",
                        "State": "running", "Labels": "com.example.owner=someone-else"}],
        "networks": [{"ID": "1b" * 32, "Name": "bridge", "Driver": "bridge", "Scope": "local"},
                     {"ID": "2c" * 32, "Name": "host", "Driver": "host", "Scope": "local"},
                     {"ID": "3d" * 32, "Name": "none", "Driver": "null", "Scope": "local"},
                     {"ID": "5f" * 32, "Name": "unrelated-net", "Driver": "bridge", "Scope": "local"}],
        "volumes": [{"Name": "unrelated-volume", "Driver": "local"}],
    }


@dataclass
class FakeDocker:
    """Scripted Docker: tracks two containers by role and answers every allowed operation.

    Behavior knobs describe the scenario: target health sequence, verifier stdout, exit
    code, OOM, timeouts and so on. `log` records every operation, so tests can assert that
    nothing outside the run's own containers was touched.
    """

    target_health: list[str] = field(default_factory=lambda: ["starting", "healthy"])
    streams: dict[str, bytes] = field(default_factory=dict)
    target_dies: bool = False
    target_oom: bool = False
    target_exits_during_tests: bool = False
    verifier_stdout: bytes = b""
    verifier_exit: int | None = None  # None: like pytest, 1 if any report failed, else 0
    verifier_oom: bool = False
    verifier_timeout: bool = False
    verifier_truncated: bool = False
    verifier_never_started: bool = False
    create_fails: str | None = None
    gate_tamper: Callable[[dict[str, Any]], None] | None = None
    image_tamper: Callable[[dict[str, Any]], None] | None = None
    foreign_labels_on_cleanup: bool = False
    on_attach: Callable[[str], None] | None = None
    records: tuple[ApprovedRunImage, ApprovedRunImage] = (TARGET_RECORD, VERIFIER_RECORD)
    create_fails_side: str | None = None  # "baseline" or "candidate": that side's target create fails
    listings: dict[str, list[dict[str, Any]]] = field(default_factory=lambda: default_listings())
    listing_fails: set[str] = field(default_factory=set)
    down: bool = False  # the daemon is unreachable: every operation fails, nothing is "not found"
    log: list[DockerOp] = field(default_factory=list)
    specs: dict[str, RunContainerSpec] = field(default_factory=dict)
    health: dict[str, list[str]] = field(default_factory=dict)
    created: list[str] = field(default_factory=list)
    roles: dict[str, RunRole] = field(default_factory=dict)
    removed: list[str] = field(default_factory=list)
    stopped: set[str] = field(default_factory=set)
    started: set[str] = field(default_factory=set)
    target_logs: bytes = b"INFO started\n{\"type\":\"session_end\"}\n"
    target_stderr: bytes = b"INFO:     Uvicorn running on http://127.0.0.1:8080\n"
    verifier_console: bytes = b"PASSED tests/test_x.py::test_a\n"
    logs_fail: bool = False

    def _cid(self, role: RunRole) -> str:
        return ("c" if role is RunRole.TARGET else "d") + format(len(self.created) + 1, "063x")

    def run(self, op: DockerOp) -> CommandResult:
        self.log.append(op)
        if self.down:
            return fail(op, b"Cannot connect to the Docker daemon. Is the docker daemon running?")
        if isinstance(op, SnapshotList):
            if op.kind in self.listing_fails:
                return fail(op)
            rows = list(self.listings.get(op.kind, []))
            if op.kind == "containers":  # this fake's own live containers are listed too
                rows += [{"ID": c, "Names": self.specs[c].name, "Image": self.specs[c].image.value,
                          "State": "exited", "Labels": ""} for c in self.created if c not in self.removed]
            return ok(op, b"".join(json.dumps(r).encode() + b"\n" for r in rows))
        if isinstance(op, ImageInspect):
            matching = [r for r in self.records if r.image.value == op.image.value]
            if not matching:
                return fail(op, b"Error: No such image")
            data = json.loads(image_inspect(matching[0]))
            if self.image_tamper is not None:
                self.image_tamper(data[0])
            return ok(op, json.dumps(data).encode())
        if isinstance(op, RunCreate):
            if self.create_fails == op.spec.role.value or (
                    self.create_fails_side == op.spec.side and op.spec.role is RunRole.TARGET):
                return fail(op)
            cid = self._cid(op.spec.role)
            self.created.append(cid)
            self.specs[cid], self.roles[cid] = op.spec, op.spec.role
            self.health[cid] = list(self.target_health)
            return ok(op, (cid + "\n").encode())
        if isinstance(op, Inspect):
            cid = op.ref.value
            if cid in self.removed or cid not in self.specs:
                return fail(op, b"Error: No such container: " + cid.encode())
            return ok(op, json.dumps([self._inspect(cid)]).encode())
        if isinstance(op, Start):
            self.started.add(op.container.value)
            return ok(op)
        if isinstance(op, StartAttached):
            if self.verifier_never_started:
                return fail(op)
            self.started.add(op.container.value)
            if self.on_attach is not None:
                self.on_attach(self.specs[op.container.value].side)
            out = self.streams.get(self.specs[op.container.value].side, self.verifier_stdout)
            return ok(op, out, stderr=self.verifier_console,
                      returncode=None if self.verifier_timeout else self._exit(op.container.value),
                      timed_out=self.verifier_timeout, stdout_truncated=self.verifier_truncated)
        if isinstance(op, Stop):
            self.stopped.add(op.container.value)
            return ok(op)
        if isinstance(op, Logs):
            if self.logs_fail:
                return fail(op, b"Error response from daemon: synthetic log read failure")
            return ok(op, self.target_logs, stderr=self.target_stderr)
        if op.op_name in ("remove", "force-remove"):
            self.removed.append(op.argv_tail()[-1])
            return ok(op)
        raise AssertionError(f"unexpected operation {op.op_name}")

    def _inspect(self, cid: str) -> dict[str, Any]:
        spec = self.specs[cid]
        env = self.records[0].env if spec.role is RunRole.TARGET else self.records[1].env
        removed_or_stopped = cid in self.stopped
        if spec.role is RunRole.TARGET:
            if cid not in self.started:
                obj = container_inspect(spec, cid, env)
                if self.gate_tamper is not None:
                    self.gate_tamper(obj)
            else:
                sequence = self.health[cid]
                health = sequence.pop(0) if len(sequence) > 1 else sequence[0]
                running = not (self.target_dies or removed_or_stopped or (
                    self.target_exits_during_tests and any(self.roles[c] is RunRole.VERIFIER for c in self.started)))
                obj = container_inspect(spec, cid, env, status="running" if running else "exited", running=running,
                                        health=health, oom=self.target_oom, exit_code=0 if running else 1)
        else:
            if cid not in self.started:
                obj = container_inspect(spec, cid, env, started_at="0001-01-01T00:00:00Z")
            elif self.verifier_timeout and cid not in self.stopped:
                obj = container_inspect(spec, cid, env, status="running", running=True)
            elif self.verifier_timeout or self.verifier_truncated:
                obj = container_inspect(spec, cid, env, status="exited", exit_code=137)
            else:
                obj = container_inspect(spec, cid, env, status="exited", exit_code=self._exit(cid),
                                        oom=self.verifier_oom)
        if self.foreign_labels_on_cleanup and spec.role is RunRole.TARGET and cid in self.started:
            obj["Config"]["Labels"] = {"com.example.owner": "someone-else"}
        return obj

    def _exit(self, cid: str) -> int:
        if self.verifier_exit is not None:
            return self.verifier_exit
        out = self.streams.get(self.specs[cid].side, self.verifier_stdout)
        return 1 if b'"outcome":"failed"' in out else 0

    def touched_ids(self) -> set[str]:
        ids: set[str] = set()
        for op in self.log:
            tail = op.argv_tail()
            if op.op_name in ("inspect", "start", "start-attached", "stop", "remove", "force-remove", "logs"):
                ids.add(tail[-1])
        return ids
