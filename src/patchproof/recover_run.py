"""Owner-operated status and cleanup for a consumed run authorization (PP-008, limited recovery).

Use it after `patchproof.run_papertrail_once` was hard-killed (SIGKILL, host shutdown,
crash) or reported a cleanup failure. Run it yourself, in your own terminal, from the
project directory, only with Docker approval (even the status check runs `docker inspect`
and `docker container ls`):

    uv run --locked --offline python -I -m patchproof.recover_run

It NEVER resumes, retries or re-executes a run, and it cannot create or start a container
(`runner.run_recovery.AllowlistExecutor`). In order:

1. Lists every claimed (consumed) run authorization with its evidence state (manifest
   re-hashed, verdict recomputed; no manifest means the run never finalized). You type the
   run ID to inspect.
2. **Read-only assessment** of that run's four fixed container names against its ownership
   journal, by exact ID and name; ambiguity or foreign ownership refuses cleanup.
3. If any verified owned container remains, it is listed with its exact ID and you type
   exactly `CLEANUP <run-id>`. The assessment is repeated and must name the same IDs; each
   container is then re-verified and removed by exact ID.

Everything is recorded in a new `evidence/recoveries/<run-id>/rec-<id>/` directory; the run's
own evidence is never modified. Exit codes: 0 nothing remains (or nothing was ever claimed);
5 needs attention (refused as ambiguous, changed before cleanup, or cleanup incomplete);
4 interrupted; 2 refused or not confirmed.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .core.run_authorizations import Claim, RunAuthorizationError, RunAuthorizationStore, StoredAuthorization
from .pack_approval import NotInteractive, Terminal, _ConsoleTerminal, require_interactive
from .runner.cleanup import CleanupStatus
from .runner.docker_cli import DockerCli, Executor, resolve_docker_binary
from .runner.interrupts import graceful_termination
from .runner.papertrail_plan import RunEnvironment, papertrail_environment
from .runner.policy import Ownership, PolicyViolation
from .runner.run_evidence import EvidenceError, RecordingExecutor, RunEvidence, verify_evidence
from .runner.run_recovery import CLEANUP_OPS, READ_ONLY_OPS, AllowlistExecutor, assess, describe, remove_verified

SETTLED = frozenset({CleanupStatus.REMOVED, CleanupStatus.FORCE_REMOVED, CleanupStatus.ALREADY_ABSENT})


def cleanup_phrase(run_id: str) -> str:
    return f"CLEANUP {run_id}"


def _run_evidence_state(env: RunEnvironment, run_id: str) -> dict[str, Any]:
    directory = env.evidence_root / run_id
    if not directory.is_dir():
        return {"state": "ABSENT", "status": None,
                "problems": ["no evidence directory: the run stopped before its first Docker operation"]}
    return verify_evidence(directory)


def recover(env: RunEnvironment, terminal: Terminal, executor_factory: Callable[[], Executor], *,
            new_recovery_id: Callable[[], str] = lambda: f"rec-{secrets.token_hex(16)}") -> int:
    try:
        records, claims = RunAuthorizationStore(env.authorization_store).scan()
    except (RunAuthorizationError, OSError) as exc:
        terminal.write(f"\nNOT RECOVERED: run-authorization store: {exc}. Nothing was inspected.\n")
        return 2
    consumed: dict[str, tuple[StoredAuthorization, Claim]] = {
        records[a].record.plan.run_id: (records[a], claims[a]) for a in sorted(claims) if a in records}
    if not consumed:
        terminal.write("\nNo run authorization has been claimed, so no run can have created a container. "
                       "Nothing to do.\n")
        return 0
    terminal.write("\nConsumed run authorizations:\n")
    for run_id, (stored, claim) in consumed.items():
        state = _run_evidence_state(env, run_id)
        terminal.write(f"  {run_id}  {stored.record.authorization_id}  claim {claim.state}  evidence "
                       f"{state['state']} {state['status'] or ''}\n")
    try:
        typed = terminal.read_line("Run to inspect (type its run ID): ")
    except (EOFError, KeyboardInterrupt):
        terminal.write("\nNOT RECOVERED: input ended. Nothing was inspected.\n")
        return 2
    if typed not in consumed:
        terminal.write("\nNOT RECOVERED: that is not a consumed run ID. Nothing was inspected.\n")
        return 2
    stored, claim = consumed[typed]
    plan = stored.record.plan
    ownership = Ownership(installation_id=plan.installation_id, run_id=plan.run_id)
    journal = env.evidence_root / plan.run_id / "ownership-journal.jsonl"
    try:
        executor = executor_factory()
        evidence = RunEvidence.claim_recovery(env.evidence_root.parent / "recoveries", plan.run_id, new_recovery_id())
    except (PolicyViolation, EvidenceError, OSError) as exc:
        terminal.write(f"\nNOT RECOVERED: {exc}. Nothing was inspected.\n")
        return 2

    def finish(result: str, extra: dict[str, Any] | None = None) -> None:
        summary = {"run_id": plan.run_id, "result": result, **(extra or {})}
        evidence.write_json("outcome.json", summary)
        evidence.finalize(status="FINALIZED", summary=summary)
        terminal.write(f"\nRECOVERY {result}. Evidence: {evidence.directory}\n")

    try:
        evidence.write_json("subject.json", {
            "run_id": plan.run_id, "authorization_id": stored.record.authorization_id, "claim_state": claim.state,
            "claim_sha256": "sha256:" + hashlib.sha256(claim.raw).hexdigest(),
            "run_evidence": _run_evidence_state(env, plan.run_id), "ownership_journal_present": journal.is_file(),
            "never": "this recovery never resumes, retries or re-executes the run"})
        reader = RecordingExecutor(AllowlistExecutor(executor, READ_ONLY_OPS), evidence)
        assessment = assess(reader, ownership, journal if os.path.lexists(journal) else None)
        evidence.write_json("assessment.json", assessment.document())
        terminal.write(f"\nRun {plan.run_id}, read-only assessment:\n{describe(assessment)}")
        if not assessment.cleanup_permitted:
            finish("REFUSED_AMBIGUOUS", {"problems": list(assessment.problems)})
            terminal.write("Nothing was removed. Resolve the listed problems manually; ambiguous or foreign "
                           "containers are never removed by PatchProof.\n")
            return 5
        removable = [(f.name, f.container_id) for f in assessment.removable]
        if not removable:
            finish("NOTHING_TO_REMOVE")
            return 0
        terminal.write("\n")
        typed = terminal.read_line(f"To stop and remove exactly these {len(removable)} container(s) by ID, type "
                                   f"exactly:  {cleanup_phrase(plan.run_id)}\nConfirmation: ")
        if typed != cleanup_phrase(plan.run_id):
            finish("NOT_CONFIRMED")
            return 2
        cleaner = RecordingExecutor(AllowlistExecutor(executor, CLEANUP_OPS), evidence,
                                    journal="docker-ops-cleanup.jsonl")
        again = assess(cleaner, ownership, journal if os.path.lexists(journal) else None)
        evidence.write_json("assessment-before-cleanup.json", again.document())
        if not again.cleanup_permitted or [(f.name, f.container_id) for f in again.removable] != removable:
            finish("CHANGED_BEFORE_CLEANUP", {"problems": list(again.problems)})
            return 5
        results = remove_verified(cleaner, again, ownership, evidence.path("cleanup-journal.jsonl"))
        evidence.write_json("cleanup.json", [{"name": r.name, "container_id": r.container_id,
                                              "status": r.status.value, "detail": r.detail} for r in results])
        final = assess(reader, ownership, journal if os.path.lexists(journal) else None)
        evidence.write_json("assessment-after.json", final.document())
        done = all(r.status in SETTLED for r in results) and final.cleanup_permitted and not final.removable
        terminal.write(describe(final))
        finish("CLEANED" if done else "CLEANUP_INCOMPLETE",
               {"cleanup": [f"{r.name} {r.container_id} {r.status.value}" for r in results]})
        return 0 if done else 5
    except KeyboardInterrupt:
        terminal.write(f"\nRECOVERY INTERRUPTED. Partial recovery evidence is in {evidence.directory}.\n")
        return 4
    except (EOFError, PolicyViolation, EvidenceError, OSError) as exc:
        terminal.write(f"\nRECOVERY STOPPED: {type(exc).__name__}: {exc}. Partial recovery evidence is in "
                       f"{evidence.directory}.\n")
        return 4


def main() -> int:
    try:
        require_interactive(sys.argv, os.environ)
    except NotInteractive as exc:
        sys.stderr.write(f"NOT RECOVERED: {exc}. Nothing was read or inspected.\n")
        return 2
    with graceful_termination():
        return recover(papertrail_environment(), _ConsoleTerminal(),
                       lambda: DockerCli(resolve_docker_binary(), str(Path.home())))


if __name__ == "__main__":
    raise SystemExit(main())
