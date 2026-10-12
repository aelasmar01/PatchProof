"""Exact-ID, ownership-checked cleanup (PROJECT_SPEC.md 5.4, 10.6).

Removal authority is deliberately narrow:

- only an ID this process registered when it created the container;
- only after a fresh inspect shows the same ID, the registered name, and labels for
  this installation *and* this run;
- stop with the fixed grace, then `docker container rm <id>` without --force;
- a container that does not satisfy every check is refused and left in place.

There is no bulk, prune, or filter-driven path. A write-ahead journal records each
planned name before `create`, so an interrupted run can be reconciled later by exact
name and ID, again only after the same ownership checks.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Final

from .docker_cli import CommandResult, ContainerRef, Executor, ForceRemove, Inspect, Remove, Stop
from .inspect_gate import parse_single_inspect
from .policy import (
    LABEL_DECOY_OF,
    LABEL_INSTALLATION,
    LABEL_OWNER,
    LABEL_RUN,
    OWNER_VALUE,
    ContainerId,
    Ownership,
    PolicyViolation,
    Role,
)

MAX_JOURNAL_BYTES: Final = 256 * 1024


class CleanupStatus(str, Enum):
    REMOVED = "REMOVED"
    FORCE_REMOVED = "FORCE_REMOVED"
    ALREADY_ABSENT = "ALREADY_ABSENT"
    REFUSED = "REFUSED"
    FAILED = "FAILED"
    NOT_CREATED = "NOT_CREATED"


@dataclass(frozen=True)
class CleanupResult:
    name: str
    container_id: str | None
    status: CleanupStatus
    detail: str


@dataclass
class RegistryEntry:
    name: str
    role: Role
    container_id: ContainerId | None = None


@dataclass
class OwnershipRegistry:
    """Containers this process created in this run. The sole source of removal authority."""

    ownership: Ownership
    entries: dict[str, RegistryEntry] = field(default_factory=dict)
    journal_path: Path | None = None

    def plan(self, name: str, role: Role) -> None:
        if name in self.entries:
            raise PolicyViolation(f"container name {name} already planned in this run")
        self.entries[name] = RegistryEntry(name=name, role=role)
        self._journal({"event": "planned", "name": name, "role": role.value})

    def record_created(self, name: str, container_id: ContainerId) -> None:
        entry = self.entries.get(name)
        if entry is None or entry.container_id is not None:
            raise PolicyViolation("created container does not match a planned, unrecorded entry")
        if any(e.container_id == container_id for e in self.entries.values()):
            raise PolicyViolation("container ID already registered")
        entry.container_id = container_id
        self._journal({"event": "created", "name": name, "id": container_id.value})

    def record_outcome(self, result: CleanupResult) -> None:
        self._journal({"event": "cleanup", "name": result.name, "status": result.status.value})

    def find(self, container_id: ContainerId) -> RegistryEntry | None:
        for entry in self.entries.values():
            if entry.container_id == container_id:
                return entry
        return None

    def _journal(self, record: Mapping[str, str]) -> None:
        if self.journal_path is None:
            return
        line = json.dumps({"run_id": self.ownership.run_id, **record}, sort_keys=True) + "\n"
        fd = os.open(self.journal_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)


# --- Pure ownership checks -------------------------------------------------------------


def ownership_problems(
    inspect: Mapping[str, Any], container_id: ContainerId, expected_name: str, ownership: Ownership
) -> list[str]:
    """Reasons this inspected container is NOT ours to remove. Empty means owned."""
    problems: list[str] = []
    if inspect.get("Id") != container_id.value:
        problems.append("inspected ID differs from the registered ID")
    if inspect.get("Name") != "/" + expected_name:
        problems.append("container name differs from the registered name")
    config = inspect.get("Config")
    labels = config.get("Labels") if isinstance(config, Mapping) else None
    if not isinstance(labels, Mapping):
        problems.append("container has no labels")
        return problems
    if labels.get(LABEL_OWNER) != OWNER_VALUE:
        problems.append("owner label missing or not patchproof")
    if labels.get(LABEL_INSTALLATION) != ownership.installation_id:
        problems.append("installation label does not match this installation")
    if labels.get(LABEL_RUN) != ownership.run_id:
        problems.append("run label does not match this run")
    return problems


def decoy_problems(
    inspect: Mapping[str, Any], container_id: ContainerId, expected_name: str, ownership: Ownership
) -> list[str]:
    """Reasons an inspected container is NOT this run's decoy. Decoys are never owned."""
    problems: list[str] = []
    if inspect.get("Id") != container_id.value:
        problems.append("inspected ID differs from the registered decoy ID")
    if inspect.get("Name") != "/" + expected_name:
        problems.append("decoy name differs from the registered name")
    state = inspect.get("State")
    if not isinstance(state, Mapping) or state.get("Status") != "created":
        problems.append("decoy is not in the never-started 'created' state")
    config = inspect.get("Config")
    labels = config.get("Labels") if isinstance(config, Mapping) else None
    if not isinstance(labels, Mapping) or labels.get(LABEL_DECOY_OF) != ownership.run_id:
        problems.append("decoy marker label does not name this run")
    elif labels.get(LABEL_RUN) == ownership.run_id:
        problems.append("decoy unexpectedly carries this run's ownership label")
    return problems


def is_not_found(result: CommandResult) -> bool:
    """`docker container inspect` on an absent container: exit 1, empty list, 'no such'."""
    return (
        result.returncode == 1
        and not result.timed_out
        and result.stdout.strip() in (b"", b"[]")
        and b"no such" in result.stderr.lower()
    )


# --- Removal ---------------------------------------------------------------------------


def _confirm_absent(executor: Executor, cid: ContainerId) -> bool:
    return is_not_found(executor.run(Inspect(ContainerRef(cid.value))))


def _still_running(obj: Mapping[str, Any]) -> bool:
    state = obj.get("State")
    if not isinstance(state, Mapping):
        return True  # unknown state is treated as running: never assume it stopped
    return bool(state.get("Running") or state.get("Restarting") or state.get("Paused"))


def _stderr(result: CommandResult) -> str:
    return result.stderr.decode("utf-8", "replace").strip()[:160]


def _stop_and_remove(
    executor: Executor,
    cid: ContainerId,
    running: bool,
    *,
    expected_name: str,
    ownership: Ownership,
    allow_force: bool,
) -> tuple[CleanupStatus, str]:
    """Owner-approved sequence (2026-10-11): graceful stop (5 s grace, daemon escalates to
    SIGKILL), ordinary exact-ID removal, and only if the container is *still running*
    after a fresh inspect that re-confirms this run's ownership, `rm --force` of that ID.
    """
    steps: list[str] = []
    stop_ok = True
    if running:
        stop = executor.run(Stop(cid))
        stop_ok = stop.ok
        steps.append("stop ok" if stop.ok else f"stop failed or timed out ({_stderr(stop) or 'no detail'})")
    removal_attempted = False
    if stop_ok:
        rm = executor.run(Remove(cid))
        removal_attempted = True
        if rm.ok:
            if _confirm_absent(executor, cid):
                return CleanupStatus.REMOVED, "removed by exact ID and confirmed absent"
            return CleanupStatus.FAILED, "CLEANUP_FAILED: container still present after remove"
        steps.append(f"remove failed ({_stderr(rm) or 'no detail'})")
    if not allow_force:
        return CleanupStatus.FAILED, "CLEANUP_FAILED: " + "; ".join(steps)

    # Step 5: inspect identity and ownership again before any escalation.
    again = executor.run(Inspect(ContainerRef(cid.value)))
    if is_not_found(again):
        return CleanupStatus.ALREADY_ABSENT, "; ".join(steps + ["container gone on re-inspect"])
    if not again.ok:
        return CleanupStatus.FAILED, "CLEANUP_FAILED: re-inspect failed; ownership not reconfirmed; " + "; ".join(steps)
    try:
        obj = parse_single_inspect(again.stdout, cid)
    except ValueError as exc:
        return CleanupStatus.FAILED, f"CLEANUP_FAILED: re-inspect unreadable ({exc}); " + "; ".join(steps)
    problems = ownership_problems(obj, cid, expected_name, ownership)
    if problems:
        return CleanupStatus.FAILED, "CLEANUP_FAILED: ownership not reconfirmed: " + "; ".join(problems)
    if not _still_running(obj):
        if removal_attempted:
            # Stopped, yet ordinary removal failed for another reason: force is not permitted.
            return CleanupStatus.FAILED, "CLEANUP_FAILED: not running, ordinary removal failed; " + "; ".join(steps)
        rm = executor.run(Remove(cid))
        if rm.ok and _confirm_absent(executor, cid):
            return CleanupStatus.REMOVED, "; ".join(steps + ["stopped on re-inspect; removed by exact ID"])
        return CleanupStatus.FAILED, "CLEANUP_FAILED: " + "; ".join(steps + [f"remove failed ({_stderr(rm)})"])
    # Step 6: exact, verified, owned, still running.
    forced = executor.run(ForceRemove(cid))
    if not forced.ok:
        return CleanupStatus.FAILED, "CLEANUP_FAILED: " + "; ".join(
            steps + [f"force-remove failed ({_stderr(forced)})"])
    if not _confirm_absent(executor, cid):
        return CleanupStatus.FAILED, "CLEANUP_FAILED: container still present after force-remove"
    return CleanupStatus.FORCE_REMOVED, "; ".join(steps + [
        "still running after graceful stop; ownership reconfirmed; force-removed by exact ID; confirmed absent"])


def remove_owned(executor: Executor, registry: OwnershipRegistry, container_id: ContainerId) -> CleanupResult:
    """Remove one container this run created, after re-verifying ownership."""
    entry = registry.find(container_id)
    if entry is None or entry.role.is_decoy:
        result = CleanupResult("<unregistered>" if entry is None else entry.name, container_id.value,
                               CleanupStatus.REFUSED, "ID is not a registered owned container of this run")
        registry.record_outcome(result)
        return result
    inspected = executor.run(Inspect(ContainerRef(container_id.value)))
    if is_not_found(inspected):
        result = CleanupResult(entry.name, container_id.value, CleanupStatus.ALREADY_ABSENT,
                               "inspect reports the container does not exist")
        registry.record_outcome(result)
        return result
    if not inspected.ok:
        result = CleanupResult(entry.name, container_id.value, CleanupStatus.FAILED,
                               "inspect failed; ownership could not be verified, nothing removed")
        registry.record_outcome(result)
        return result
    try:
        obj = parse_single_inspect(inspected.stdout, container_id)
    except ValueError as exc:
        result = CleanupResult(entry.name, container_id.value, CleanupStatus.REFUSED, str(exc))
        registry.record_outcome(result)
        return result
    problems = ownership_problems(obj, container_id, entry.name, registry.ownership)
    if problems:
        result = CleanupResult(entry.name, container_id.value, CleanupStatus.REFUSED, "; ".join(problems))
        registry.record_outcome(result)
        return result
    status, detail = _stop_and_remove(executor, container_id, _still_running(obj), expected_name=entry.name,
                                      ownership=registry.ownership, allow_force=True)
    result = CleanupResult(entry.name, container_id.value, status, detail)
    registry.record_outcome(result)
    return result


def remove_decoy(executor: Executor, registry: OwnershipRegistry, container_id: ContainerId) -> CleanupResult:
    """Separately logged teardown for a decoy this run created. Never used for owned containers."""
    entry = registry.find(container_id)
    if entry is None or not entry.role.is_decoy:
        result = CleanupResult("<unregistered>" if entry is None else entry.name, container_id.value,
                               CleanupStatus.REFUSED, "ID is not a registered decoy of this run")
        registry.record_outcome(result)
        return result
    inspected = executor.run(Inspect(ContainerRef(container_id.value)))
    if not inspected.ok:
        result = CleanupResult(entry.name, container_id.value, CleanupStatus.FAILED,
                               "decoy inspect failed; nothing removed")
        registry.record_outcome(result)
        return result
    try:
        obj = parse_single_inspect(inspected.stdout, container_id)
    except ValueError as exc:
        result = CleanupResult(entry.name, container_id.value, CleanupStatus.REFUSED, str(exc))
        registry.record_outcome(result)
        return result
    problems = decoy_problems(obj, container_id, entry.name, registry.ownership)
    if problems:
        result = CleanupResult(entry.name, container_id.value, CleanupStatus.REFUSED, "; ".join(problems))
        registry.record_outcome(result)
        return result
    # Decoys are never started; they never take the force path.
    status, detail = _stop_and_remove(executor, container_id, running=False, expected_name=entry.name,
                                      ownership=registry.ownership, allow_force=False)
    result = CleanupResult(entry.name, container_id.value, status, detail)
    registry.record_outcome(result)
    return result


def cleanup_all(executor: Executor, registry: OwnershipRegistry) -> list[CleanupResult]:
    """Remove every registered container of this run: owned ones, then decoys."""
    results: list[CleanupResult] = []
    for entry in list(registry.entries.values()):
        if entry.container_id is None:
            results.append(CleanupResult(entry.name, None, CleanupStatus.NOT_CREATED,
                                         "no container ID was recorded for this planned name"))
            continue
        remover = remove_decoy if entry.role.is_decoy else remove_owned
        results.append(remover(executor, registry, entry.container_id))
    return results


# --- Interrupted-run reconciliation ----------------------------------------------------


@dataclass(frozen=True)
class JournalState:
    planned: dict[str, Role]
    created: dict[str, ContainerId]
    settled: set[str]


def read_journal(path: Path, ownership: Ownership) -> JournalState:
    """Strictly parse a run journal. Any foreign or malformed line refuses recovery."""
    if path.stat().st_size > MAX_JOURNAL_BYTES:
        raise PolicyViolation("journal exceeds its size bound")
    planned: dict[str, Role] = {}
    created: dict[str, ContainerId] = {}
    settled: set[str] = set()
    for number, raw in enumerate(path.read_text("utf-8").splitlines(), start=1):
        try:
            record = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise PolicyViolation(f"journal line {number} is not JSON") from exc
        if not isinstance(record, dict) or record.get("run_id") != ownership.run_id:
            raise PolicyViolation(f"journal line {number} belongs to a different run")
        event, name = record.get("event"), record.get("name")
        if not isinstance(name, str):
            raise PolicyViolation(f"journal line {number} has no name")
        if event == "planned":
            planned[name] = Role(record.get("role"))
        elif event == "created" and name in planned:
            created[name] = ContainerId(str(record.get("id")))
        elif event == "cleanup" and record.get("status") in ("REMOVED", "FORCE_REMOVED", "ALREADY_ABSENT"):
            settled.add(name)
        elif event not in ("cleanup",):
            raise PolicyViolation(f"journal line {number} has an unexpected event")
    return JournalState(planned=planned, created=created, settled=settled)


def recover_interrupted(executor: Executor, journal_path: Path, ownership: Ownership) -> list[CleanupResult]:
    """Reconcile a run that ended without cleanup, using only its own journal.

    A planned name without a recorded ID is resolved by exact name; the inspected
    container must then pass the same ownership checks. Anything ambiguous is refused.
    """
    state = read_journal(journal_path, ownership)
    registry = OwnershipRegistry(ownership=ownership, journal_path=journal_path)
    results: list[CleanupResult] = []
    for name, role in state.planned.items():
        if name in state.settled:
            continue
        cid = state.created.get(name)
        if cid is None:
            looked_up = executor.run(Inspect(ContainerRef(name)))
            if is_not_found(looked_up):
                results.append(CleanupResult(name, None, CleanupStatus.NOT_CREATED,
                                             "planned but no container exists under that name"))
                continue
            try:
                obj = parse_single_inspect(looked_up.stdout)
                cid = ContainerId(str(obj.get("Id")))
            except (ValueError, PolicyViolation) as exc:
                results.append(CleanupResult(name, None, CleanupStatus.REFUSED, f"ambiguous lookup: {exc}"))
                continue
        registry.entries[name] = RegistryEntry(name=name, role=role, container_id=cid)
        remover = remove_decoy if role.is_decoy else remove_owned
        results.append(remover(executor, registry, cid))
    return results
