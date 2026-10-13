"""Status and owner-confirmed cleanup for ONE consumed run authorization (PP-008, limited).

This is not the general PP-014 crash-recovery framework. It exists because a hard kill
(SIGKILL, host shutdown, crash) of `patchproof.run_papertrail_once` cannot run cleanup, so the
containers of the revision in progress can remain. It never resumes, retries or re-executes
anything: it has no path to create or start a container.

**Assessment (read-only: `inspect` and the container listing only).** For each of the four
container names that the run's authorization fixes, the run's own ownership journal (planned
names and created IDs, read strictly) is compared with what Docker reports. Names are
resolved through `docker container ls --all`; containers are inspected only by exact full
ID. Each container is:
- `ABSENT`: no container under that ID or name;
- `OWNED`: one container, the journal's ID (if one was recorded) and name agree, the journal
  planned it, and its labels name this owner, installation and run;
- `FOREIGN`: labels or identity do not prove ownership: never touched;
- `AMBIGUOUS`: ID and name disagree, or the journal never planned it: never touched;
- `UNKNOWN`: Docker could not answer.
Any listed container that carries this run's label or name prefix but is not one of those
four is also ambiguous. **Any FOREIGN, AMBIGUOUS, UNKNOWN or unreadable journal refuses
cleanup for the whole run.**

**Cleanup (only after a typed confirmation, by the caller).** The assessment is repeated and
must name the same container IDs. Each `OWNED` container is then removed with the accepted
`cleanup.remove_owned`: a fresh inspect re-verifies ID, name and labels, then graceful stop,
exact-ID removal, and `--force` only for a still-running owned container. Docker operations
pass through an allowlist (`inspect`, listing, `stop`, `remove`, `force-remove`).

**Evidence.** Everything is written to a new `evidence/recoveries/<run-id>/rec-<id>/`
directory; the run's own evidence directory is only read.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Final, Literal

from ..core.run_authorizations import container_names
from .cleanup import (
    CleanupResult,
    JournalState,
    OwnershipRegistry,
    RegistryEntry,
    is_not_found,
    ownership_problems,
    read_journal,
    remove_owned,
)
from .docker_cli import CommandResult, ContainerRef, DockerOp, Executor, Inspect, SnapshotList
from .inspect_gate import parse_single_inspect
from .policy import LABEL_RUN, ContainerId, Ownership, PolicyViolation
from .run_evidence import parse_listing
from .run_policy import RunRole

READ_ONLY_OPS: Final = frozenset({"inspect", "snapshot"})
CLEANUP_OPS: Final = READ_ONLY_OPS | {"stop", "remove", "force-remove"}

FindingState = Literal["ABSENT", "OWNED", "FOREIGN", "AMBIGUOUS", "UNKNOWN"]


@dataclass
class AllowlistExecutor:
    """Refuses every Docker operation outside `allowed`, before it reaches Docker."""

    inner: Executor
    allowed: frozenset[str]

    def run(self, op: DockerOp) -> CommandResult:
        if op.op_name not in self.allowed:
            raise PolicyViolation(f"recovery never performs {op.op_name!r}")
        return self.inner.run(op)


@dataclass(frozen=True)
class ContainerFinding:
    name: str
    side: str
    role: str
    journal: str  # not-planned, planned, created or settled
    journal_id: str | None
    state: FindingState
    container_id: str | None
    detail: str
    running: bool | None = None


@dataclass(frozen=True)
class Assessment:
    run_id: str
    findings: tuple[ContainerFinding, ...]
    unlisted: tuple[Mapping[str, Any], ...]
    problems: tuple[str, ...]

    @property
    def removable(self) -> list[ContainerFinding]:
        return [f for f in self.findings if f.state == "OWNED"]

    @property
    def cleanup_permitted(self) -> bool:
        return not self.problems and all(f.state in ("ABSENT", "OWNED") for f in self.findings)

    def document(self) -> dict[str, Any]:
        return {"run_id": self.run_id, "cleanup_permitted": self.cleanup_permitted,
                "findings": [asdict(f) for f in self.findings], "unlisted": [dict(u) for u in self.unlisted],
                "problems": list(self.problems)}


def _running(obj: Mapping[str, Any]) -> bool:
    state = obj.get("State")
    if not isinstance(state, Mapping):
        return True  # unknown is never assumed stopped
    return bool(state.get("Running") or state.get("Restarting") or state.get("Paused"))


def assess(executor: Executor, ownership: Ownership, journal_path: Path | None) -> Assessment:
    """Read-only. `journal_path` is the run's ownership journal, or None if the run never wrote one.

    Names are resolved through the container listing (`docker container ls --all`); every
    container is then inspected by its exact full ID only.
    """
    run_id = ownership.run_id
    problems: list[str] = []
    journal = JournalState(planned={}, created={}, settled=set())
    if journal_path is not None:
        try:
            journal = read_journal(journal_path, ownership)
        except (PolicyViolation, OSError, ValueError) as exc:
            problems.append(f"the run's ownership journal is unreadable or inconsistent: {exc}")
    expected = container_names(run_id)
    unexpected = sorted(set(journal.planned) - {n for _, _, n in expected})
    if unexpected:
        problems.append(f"the journal plans names this run never authorized: {unexpected}")

    rows: dict[str, dict[str, Any]] | None = None
    listing = executor.run(SnapshotList("containers"))
    if not listing.ok or listing.stdout_truncated:
        problems.append("the container listing failed or was truncated; names and leftovers cannot be resolved")
    else:
        try:
            rows = parse_listing("containers", listing.stdout)
        except (ValueError, UnicodeDecodeError) as exc:
            problems.append(f"the container listing is unreadable: {exc}")

    def names_of(row: Mapping[str, Any]) -> list[str]:
        return [n.strip().lstrip("/") for n in str(row.get("Names") or "").split(",") if n.strip()]

    findings: list[ContainerFinding] = []
    for side, role, name in expected:
        journal_id = journal.created[name].value if name in journal.created else None
        stage = ("settled" if name in journal.settled else "created" if journal_id
                 else "planned" if name in journal.planned else "not-planned")
        base = (name, side, role, stage, journal_id)
        if rows is None:
            findings.append(ContainerFinding(*base, "UNKNOWN", journal_id, "the container listing is unavailable"))
            continue
        by_name = sorted(i for i, row in rows.items() if name in names_of(row))
        if len(by_name) > 1 or (journal_id and by_name and by_name != [journal_id]):
            findings.append(ContainerFinding(*base, "AMBIGUOUS", journal_id,
                                             f"the name resolves to {by_name}, not only the recorded ID"))
            continue
        if journal_id and journal_id in rows and name not in names_of(rows[journal_id]):
            findings.append(ContainerFinding(*base, "AMBIGUOUS", journal_id,
                                             "the recorded ID exists under a different name"))
            continue
        ref = journal_id or (by_name[0] if by_name else None)
        if ref is None:
            findings.append(ContainerFinding(*base, "ABSENT", None, "no container under this name"))
            continue
        try:
            cid = ContainerId(ref)
        except PolicyViolation:
            findings.append(ContainerFinding(*base, "AMBIGUOUS", journal_id, "not a valid full container ID"))
            continue
        result = executor.run(Inspect(ContainerRef(cid.value)))
        if is_not_found(result):
            if journal_id and journal_id in rows:
                findings.append(ContainerFinding(*base, "AMBIGUOUS", cid.value,
                                                 "listed, but inspect reports it does not exist"))
            else:
                findings.append(ContainerFinding(*base, "ABSENT", cid.value, "inspect reports it does not exist"))
            continue
        if not result.ok:
            findings.append(ContainerFinding(*base, "UNKNOWN", cid.value, "inspect failed: " + result.stderr.decode(
                "utf-8", "replace").strip()[:160]))
            continue
        try:
            obj = parse_single_inspect(result.stdout, cid)
        except ValueError as exc:
            findings.append(ContainerFinding(*base, "UNKNOWN", cid.value, f"inspect unreadable: {exc}"))
            continue
        not_ours = ownership_problems(obj, cid, name, ownership)
        if not_ours:
            findings.append(ContainerFinding(*base, "FOREIGN", cid.value, "; ".join(not_ours), _running(obj)))
            continue
        if stage == "not-planned":
            findings.append(ContainerFinding(*base, "AMBIGUOUS", cid.value,
                                             "it carries this run's labels, but the run's journal never planned it",
                                             _running(obj)))
            continue
        findings.append(ContainerFinding(*base, "OWNED", cid.value, "ID, name and ownership labels verified",
                                         _running(obj)))

    unlisted: list[Mapping[str, Any]] = []
    if rows is not None:
        known = {f.container_id for f in findings if f.container_id}
        prefix = f"pp-run-{run_id[4:16]}-"
        for ident, row in sorted(rows.items()):
            mine = f"{LABEL_RUN}={run_id}" in str(row.get("Labels") or "").split(",") or any(
                n.startswith(prefix) for n in names_of(row))
            if mine and ident not in known:
                unlisted.append({"id": ident, **row})
        if unlisted:
            problems.append(f"{len(unlisted)} other container(s) carry this run's label or name prefix")
    for f in findings:
        if f.state in ("FOREIGN", "AMBIGUOUS", "UNKNOWN"):
            problems.append(f"{f.name}: {f.state}: {f.detail}")
    return Assessment(run_id=run_id, findings=tuple(findings), unlisted=tuple(unlisted), problems=tuple(problems))


def remove_verified(executor: Executor, assessment: Assessment, ownership: Ownership,
                    journal_path: Path) -> list[CleanupResult]:
    """Remove the assessment's OWNED containers by exact ID, each re-verified by `remove_owned`.

    `journal_path` is the recovery's own journal, never the run's.
    """
    if not assessment.cleanup_permitted:
        raise PolicyViolation("cleanup is refused: ownership is ambiguous or could not be established")
    registry = OwnershipRegistry(ownership=ownership, journal_path=journal_path)
    for f in assessment.removable:
        assert f.container_id is not None
        registry.entries[f.name] = RegistryEntry(name=f.name, role=RunRole(f.role).probe_role,
                                                 container_id=ContainerId(f.container_id))
    return [remove_owned(executor, registry, ContainerId(f.container_id or "")) for f in assessment.removable]


def describe(assessment: Assessment) -> str:
    lines = [f"  {f.name:<44} {f.state:<9} {f.container_id or '-'}"
             + (" running" if f.running else "") + f"\n      journal: {f.journal}; {f.detail}"
             for f in assessment.findings]
    lines += [f"  other: {json.dumps(dict(u), sort_keys=True)}" for u in assessment.unlisted]
    lines += [f"  PROBLEM: {p}" for p in assessment.problems]
    return "\n".join(lines) + "\n"
