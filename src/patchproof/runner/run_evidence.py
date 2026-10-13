"""Private run evidence, the Docker operation journal, and inventory reconciliation (PP-008).

**Evidence directory.** `<user data>/evidence/runs/<run-id>/`, created exclusively (an
existing directory refuses the run), mode 0700. Every file is:
- written to a temporary name with `O_EXCL`, fsynced, then hard-linked to its final name,
  so a file either exists completely or not at all, and a final name is never overwritten;
- owner-only (0600).

Journals (`docker-ops.jsonl`, the ownership journal) are append-only and fsynced per line,
so a crash keeps everything up to the last completed operation. The run is finalized by
`manifest.json`, written last, listing the SHA-256 and size of every file. **No manifest
means the evidence is incomplete**: a crash leaves the partial files and no manifest. A
handled failure writes `manifest.json` with `status: INCOMPLETE` and the reason.

**Trusted and untrusted bytes stay apart.** The verifier's attached standard output, the
only event channel, is stored as `verifier-stream-<side>.bin`. Target logs are stored as
`untrusted-target-log-<side>.log` and never parsed. The operation journal records only
the length and hash of both, never their content.

**Container budget.** `RecordingExecutor` refuses a fifth container creation before it
reaches Docker. Exactly four are planned.

**Inventory reconciliation by identity.** Images, containers, networks and volumes are
listed before and after the run and compared by ID (volumes by name), never by count.
- **Explained, daemon-managed:** a built-in network (`bridge`, `host`, `none`) present
  under the same name and driver but a new ID. Docker Desktop recreates them when its VM or
  daemon restarts. This is recorded, with both IDs, and marks a suspected daemon restart:
  continuity during the run is not established.
- **Unexplained, needs attention:** every other addition, removal or identity change, and
  any container this run created that still exists. Nothing is dismissed automatically and
  nothing outside this run's own containers is ever touched.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Literal

from ..core.verdict_input import parse_verdict_input
from ..core.verdicts import evaluate
from .docker_cli import CommandResult, DockerOp, Executor, SnapshotList
from .policy import PolicyViolation

MAX_CONTAINER_CREATIONS: Final = 4
# Largest single evidence file: above the schema's maximum result cap (50 MiB) and the
# bounded target log, so nothing legitimate is refused; anything larger is an error.
MAX_EVIDENCE_FILE_BYTES: Final = 64 * 1024 * 1024
MAX_JOURNAL_LINE_BYTES: Final = 1024 * 1024
MAX_DOCKER_OPERATIONS: Final = 200
_NAME_RE: Final = re.compile(r"[a-z0-9][a-z0-9.-]{0,100}")
_RUN_RE: Final = re.compile(r"run-[0-9a-f]{32}")
_RECOVERY_RE: Final = re.compile(r"rec-[0-9a-f]{32}")
# Operation outputs kept inline in the journal: configuration evidence. Verifier output
# (`start-attached`) and target logs (`logs`) are stored separately, by the caller.
_INLINE_OUTPUT: Final = frozenset({"run-create", "inspect", "image-inspect", "snapshot", "stop", "remove",
                                   "force-remove", "start"})
INVENTORY_KINDS: Final = ("images", "containers", "networks", "volumes")
BUILTIN_NETWORKS: Final = ("bridge", "host", "none")


class EvidenceError(RuntimeError):
    """Evidence could not be written as specified."""


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _private_dir(path: Path) -> None:
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077:
        raise EvidenceError(f"{path} must be a private (0700) directory owned by you")


def _private_root(root: Path) -> None:
    """An absolute canonical directory, created 0700 if missing, under a private parent."""
    raw = str(root)
    if not os.path.isabs(raw) or os.path.realpath(raw) != raw:
        raise EvidenceError("evidence root must be an absolute canonical path")
    _private_dir(root.parent)
    try:
        os.mkdir(root, 0o700)
    except FileExistsError:
        pass
    _private_dir(root)


class RunEvidence:
    def __init__(self, directory: Path, identity: tuple[int, int]) -> None:
        self.directory = directory
        self._identity = identity

    @classmethod
    def claim(cls, root: Path, run_id: str) -> RunEvidence:
        """Create the run's evidence directory exclusively. An existing one refuses the run."""
        if not _RUN_RE.fullmatch(run_id):
            raise EvidenceError("invalid run ID")
        _private_root(root)
        directory = root / run_id
        try:
            os.mkdir(directory, 0o700)
        except FileExistsError:
            raise EvidenceError(f"evidence for {run_id} already exists; a run is never repeated") from None
        st = os.lstat(directory)
        _private_dir(directory)
        return cls(directory, (st.st_dev, st.st_ino))

    @classmethod
    def claim_recovery(cls, root: Path, run_id: str, recovery_id: str) -> RunEvidence:
        """A new recovery directory `<root>/<run-id>/<recovery-id>`, created exclusively.

        `root` is `<user data>/evidence/recoveries`, a sibling of the runs root: recovery
        never writes into a run's own evidence directory.
        """
        if not _RUN_RE.fullmatch(run_id) or not _RECOVERY_RE.fullmatch(recovery_id):
            raise EvidenceError("invalid run or recovery ID")
        _private_root(root)
        _private_root(root / run_id)
        directory = root / run_id / recovery_id
        try:
            os.mkdir(directory, 0o700)
        except FileExistsError:
            raise EvidenceError(f"recovery {recovery_id} already exists") from None
        st = os.lstat(directory)
        _private_dir(directory)
        return cls(directory, (st.st_dev, st.st_ino))

    def _check(self) -> None:
        st = os.lstat(self.directory)
        if (st.st_dev, st.st_ino) != self._identity:
            raise EvidenceError("the evidence directory was replaced")
        _private_dir(self.directory)

    def path(self, name: str) -> Path:
        if not _NAME_RE.fullmatch(name):
            raise EvidenceError(f"invalid evidence file name {name!r}")
        return self.directory / name

    def write(self, name: str, data: bytes) -> str:
        """Write one complete file, once. Returns its SHA-256."""
        final = self.path(name)
        if len(data) > MAX_EVIDENCE_FILE_BYTES:
            raise EvidenceError(f"{name} exceeds the evidence file bound ({len(data)} bytes)")
        self._check()
        temporary = self.directory / f".tmp-{secrets.token_hex(8)}-{name}"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temporary, final, follow_symlinks=False)
            except FileExistsError:
                raise EvidenceError(f"{name} already exists; evidence is never overwritten") from None
        finally:
            os.unlink(temporary)
        self._fsync_dir()
        return _sha256(data)

    def write_json(self, name: str, value: Any) -> str:
        return self.write(name, json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n")

    def append_line(self, name: str, value: Mapping[str, Any]) -> None:
        line = json.dumps(value, sort_keys=True).encode("utf-8") + b"\n"
        if len(line) > MAX_JOURNAL_LINE_BYTES:
            raise EvidenceError(f"a {name} line exceeds the journal line bound")
        self._check()
        fd = os.open(self.path(name), os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)

    def _fsync_dir(self) -> None:
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def files(self) -> dict[str, dict[str, Any]]:
        """Every evidence file and its hash, re-read now. Temporary leftovers are listed as such."""
        self._check()
        found: dict[str, dict[str, Any]] = {}
        for name in sorted(os.listdir(self.directory)):
            if name == "manifest.json":
                continue
            full = self.directory / name
            st = os.lstat(full)
            if not stat.S_ISREG(st.st_mode):
                raise EvidenceError(f"{name} is not a regular file")
            data = full.read_bytes()
            found[name] = {"sha256": _sha256(data), "bytes": len(data), "mode": oct(stat.S_IMODE(st.st_mode)),
                           "partial": name.startswith(".tmp-")}
        return found

    def finalize(self, *, status: Literal["FINALIZED", "INCOMPLETE"], summary: Mapping[str, Any]) -> str:
        """Write manifest.json last. Its presence marks the end of evidence collection."""
        manifest = {"schema": "patchproof-run-evidence-manifest-v1", "status": status, "summary": dict(summary),
                    "files": self.files()}
        return self.write("manifest.json", json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8") + b"\n")


def verify_evidence(directory: Path) -> dict[str, Any]:
    """Re-check a run's evidence directory against its manifest. Read-only.

    Detects missing, added, changed and partial files relative to `manifest.json`, and
    recomputes the verdict from `verdict-input.json` with the accepted engine. As
    PROJECT_SPEC.md 12.2 says, this detects inconsistent or corrupted evidence, not a local
    adversary who rewrites both the manifest and the files.
    """
    problems: list[str] = []
    manifest_path = directory / "manifest.json"
    if not manifest_path.is_file():
        return {"state": "NO_MANIFEST", "status": None, "problems": ["no manifest: the run did not finalize "
                                                                     "(hard kill, crash or power loss)"]}
    try:
        manifest = json.loads(manifest_path.read_bytes())
        listed: dict[str, Any] = manifest["files"]
        status = manifest["status"]
    except (ValueError, KeyError, TypeError) as exc:
        return {"state": "MANIFEST_UNREADABLE", "status": None, "problems": [f"manifest: {exc}"]}
    present = sorted(n for n in os.listdir(directory) if n != "manifest.json")
    for name in sorted(set(listed) | set(present)):
        if name not in present:
            problems.append(f"{name}: listed in the manifest but missing")
            continue
        data = (directory / name).read_bytes()
        if name not in listed:
            problems.append(f"{name}: present but not in the manifest")
        elif listed[name].get("sha256") != _sha256(data) or listed[name].get("bytes") != len(data):
            problems.append(f"{name}: content differs from the manifest")
        if name.startswith(".tmp-"):
            problems.append(f"{name}: a partial write was left behind")
    if (directory / "verdict-input.json").is_file() and (directory / "verdict.json").is_file():
        try:
            recorded = json.loads((directory / "verdict.json").read_bytes())
            recomputed = evaluate(parse_verdict_input(json.loads((directory / "verdict-input.json").read_bytes())),
                                  recorded["evaluated_at"])
            if recomputed != recorded:
                problems.append("verdict.json differs from the engine's evaluation of verdict-input.json")
        except Exception as exc:  # noqa: BLE001 - any failure to recompute is reported, never trusted
            problems.append(f"verdict could not be recomputed: {type(exc).__name__}: {exc}")
    return {"state": "CONSISTENT" if not problems else "INCONSISTENT", "status": status, "problems": problems}


# ------------------------------------------------------------------ Docker operation journal


@dataclass
class RecordingExecutor:
    """Wraps the real executor: journals every operation and enforces the container budget."""

    inner: Executor
    evidence: RunEvidence
    journal: str = "docker-ops.jsonl"
    creations: int = 0
    operations: int = 0
    results: list[CommandResult] = field(default_factory=list)

    def run(self, op: DockerOp) -> CommandResult:
        if self.operations >= MAX_DOCKER_OPERATIONS:
            raise PolicyViolation("the run exceeded its Docker operation bound")
        if op.op_name in ("run-create", "create"):
            if self.creations >= MAX_CONTAINER_CREATIONS:
                raise PolicyViolation("the authorized run may create at most four containers")
            self.creations += 1
        self.operations += 1
        entry: dict[str, Any] = {"seq": self.operations, "op": op.op_name, "argv_tail": op.argv_tail()}
        self.evidence.append_line(self.journal, {**entry, "phase": "requested"})
        result = self.inner.run(op)
        entry.update({"phase": "completed", "returncode": result.returncode, "timed_out": result.timed_out,
                      "stdout_truncated": result.stdout_truncated, "duration_seconds": result.duration_seconds,
                      "stdout_bytes": len(result.stdout), "stdout_sha256": _sha256(result.stdout),
                      "stderr": result.stderr[:4096].decode("utf-8", "replace")})
        if op.op_name in _INLINE_OUTPUT:
            entry["stdout"] = result.stdout.decode("utf-8", "replace")
        self.evidence.append_line(self.journal, entry)
        self.results.append(result)
        return result


# ------------------------------------------------------------------ inventory


_FIELDS: Final[Mapping[str, tuple[str, tuple[str, ...]]]] = {
    "images": ("ID", ("Repository", "Tag", "Digest")),
    "containers": ("ID", ("Names", "Image", "State", "Labels")),
    "networks": ("ID", ("Name", "Driver", "Scope")),
    "volumes": ("Name", ("Driver",)),
}


@dataclass(frozen=True)
class Inventory:
    complete: bool
    problems: tuple[str, ...]
    resources: Mapping[str, Mapping[str, Mapping[str, Any]]]
    raw_sha256: Mapping[str, str]

    def document(self) -> dict[str, Any]:
        return {"complete": self.complete, "problems": list(self.problems), "raw_sha256": dict(self.raw_sha256),
                "resources": {k: {i: dict(v) for i, v in sorted(r.items())} for k, r in self.resources.items()}}

    def builtin_networks(self) -> dict[str, str]:
        return {v["Name"]: i for i, v in self.resources.get("networks", {}).items()
                if v.get("Name") in BUILTIN_NETWORKS}


def parse_listing(kind: str, stdout: bytes) -> dict[str, dict[str, Any]]:
    key, fields = _FIELDS[kind]
    found: dict[str, dict[str, Any]] = {}
    for line in stdout.decode("utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        if not isinstance(obj, dict) or not isinstance(obj.get(key), str) or not obj[key]:
            raise ValueError(f"{kind} listing line has no {key}")
        ident = obj[key]
        record = {f: obj.get(f) for f in fields}
        if kind == "images":  # one image ID can be listed once per tag
            previous = found.get(ident, {"refs": []})
            record = {"refs": sorted({*previous["refs"], f"{obj.get('Repository')}:{obj.get('Tag')}"}),
                      "Digest": obj.get("Digest")}
        elif ident in found:
            raise ValueError(f"{kind} listing repeats {ident}")
        found[ident] = record
    return found


def capture_inventory(executor: Executor, kinds: Iterable[str] = INVENTORY_KINDS) -> Inventory:
    resources: dict[str, dict[str, dict[str, Any]]] = {}
    hashes: dict[str, str] = {}
    problems: list[str] = []
    for kind in kinds:
        result = executor.run(SnapshotList(kind))
        hashes[kind] = _sha256(result.stdout)
        if not result.ok or result.stdout_truncated:
            problems.append(f"{kind}: listing failed or was truncated")
            continue
        try:
            resources[kind] = parse_listing(kind, result.stdout)
        except (ValueError, UnicodeDecodeError) as exc:
            problems.append(f"{kind}: unparseable listing ({exc})")
    return Inventory(complete=not problems, problems=tuple(problems), resources=resources, raw_sha256=hashes)


ReconciliationStatus = Literal["CONSISTENT", "EXPLAINED_DAEMON_MANAGED", "ATTENTION", "INCOMPLETE"]


def reconcile(before: Inventory, after: Inventory, owned_container_ids: Iterable[str]) -> dict[str, Any]:
    """Compare two inventories by identity. Pure; touches nothing."""
    owned = set(owned_container_ids)
    findings: list[dict[str, Any]] = []
    if not (before.complete and after.complete):
        return {"status": "INCOMPLETE", "daemon_restart_suspected": None, "findings": [],
                "problems": [*before.problems, *after.problems]}
    explained_networks: set[str] = set()
    before_builtin, after_builtin = before.builtin_networks(), after.builtin_networks()
    for name in BUILTIN_NETWORKS:
        old, new = before_builtin.get(name), after_builtin.get(name)
        if old and new and old != new and (before.resources["networks"][old].get("Driver")
                                           == after.resources["networks"][new].get("Driver")):
            explained_networks |= {old, new}
            findings.append({"kind": "networks", "name": name, "before_id": old, "after_id": new,
                             "classification": "DAEMON_MANAGED_BUILTIN_RECREATED",
                             "detail": "a built-in network has a new ID under the same name and driver; Docker "
                                       "recreates these when its daemon or VM restarts. Not a PatchProof operation."})
    for kind in INVENTORY_KINDS:
        old_ids, new_ids = set(before.resources[kind]), set(after.resources[kind])
        for ident in sorted(new_ids - old_ids):
            if kind == "networks" and ident in explained_networks:
                continue
            classification = "OWNED_CONTAINER_REMAINS" if ident in owned else "UNEXPLAINED_ADDED"
            findings.append({"kind": kind, "id": ident, "classification": classification,
                             "after": after.resources[kind][ident]})
        for ident in sorted(old_ids - new_ids):
            if kind == "networks" and ident in explained_networks:
                continue
            findings.append({"kind": kind, "id": ident, "classification": "UNEXPLAINED_REMOVED",
                             "before": before.resources[kind][ident]})
        for ident in sorted(old_ids & new_ids):
            if ident in owned:
                findings.append({"kind": kind, "id": ident, "classification": "OWNED_CONTAINER_REMAINS"})
            elif kind != "containers" and before.resources[kind][ident] != after.resources[kind][ident]:
                findings.append({"kind": kind, "id": ident, "classification": "UNEXPLAINED_CHANGED",
                                 "before": before.resources[kind][ident], "after": after.resources[kind][ident]})
    unexplained = [f for f in findings if f["classification"] != "DAEMON_MANAGED_BUILTIN_RECREATED"]
    restarted = bool(explained_networks)
    status: ReconciliationStatus = ("ATTENTION" if unexplained else
                                    "EXPLAINED_DAEMON_MANAGED" if restarted else "CONSISTENT")
    return {"status": status, "daemon_restart_suspected": restarted, "findings": findings, "problems": []}
