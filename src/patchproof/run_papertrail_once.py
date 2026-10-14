"""Owner-operated execution of the one authorized PaperTrail comparison (PP-008 integration utility).

This is NOT a general Docker execution CLI and NOT the PP-009 workflow. It executes only the
single unused `papertrail-authz-r1-r3-one-pair-v1` run authorization, once. Run it yourself,
in your own terminal, from the project directory:

    uv run --locked --offline python -I -m patchproof.run_papertrail_once

**Refuses, with nothing consumed and no Docker operation, unless:**
- the process is an interactive foreground terminal with no arguments and no `PATCHPROOF*`
  variables;
- exactly one unused (unclaimed, unsuperseded) run authorization exists and is valid;
- the plan recomputed now from the current artifacts equals the frozen plan exactly: the
  current pack approval, pack copy, profile, runtime policy, both source snapshots, fixture
  hash and approved images;
- the run's evidence directory does not exist yet;
- the owner types exactly `EXECUTE <run-id>`.

**Then, in order:**
1. **Claim:** the authorization is consumed with an exclusive, fsynced claim file. From here
   on it can never run again, whatever happens. A crash leaves it consumed or indeterminate.
2. **Evidence:** the run's private evidence directory is created exclusively.
3. **Run:** before and after inventories, at most four containers, per-revision
   re-validation, the D2 baseline stop, exact-ID cleanup, and the accepted verdict engine
   (`runner.authorized_run`).

**Signals.** While it runs, SIGINT, SIGTERM and SIGHUP are delivered as one interrupt
(`runner.interrupts`): the revision in progress is cleaned up by exact ID, no further
revision starts, and the evidence is finalized as `INCOMPLETE`/`INTERRUPTED`. A repeated
signal is ignored so it cannot abort that cleanup. SIGKILL, a host shutdown or a crash
cannot run any of this: the claim (fsynced before any Docker operation) keeps the
authorization consumed, the journals keep every completed operation and every created
container ID, there is no manifest, and `patchproof.recover_run` handles what remains.

**Exit codes:** 0 evidence finalized, lifecycle `COMPLETE`, cleanup verified and the
inventory consistent; 5 finalized but needs attention (a stop, a cleanup failure, any
inventory change including a suspected daemon restart); 4 incomplete evidence after the
claim; 3 claimed but nothing executed; 2 refused, nothing consumed. The verdict, whatever
it is, is in the evidence and on screen; an exit code is never a verdict.

These are NOT the PROJECT_SPEC.md 13.2 codes (a finalized `NOT_FIXED` run exits 0 here).
`patchproof run <plan-id>` calls `execute_once` and applies 13.2 to the run's own record;
use it, not this utility's exit code, wherever a verdict-bearing exit code is needed.
"""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from .core.run_authorizations import RunAuthorizationError, RunAuthorizationStore, execution_phrase, is_superseded
from .pack_approval import ApprovalBlocked, NotInteractive, Terminal, _ConsoleTerminal, require_interactive
from .runner.authorized_run import RunOutcome, execute_authorized_run
from .runner.docker_cli import DockerCli, Executor, resolve_docker_binary
from .runner.interrupts import graceful_termination
from .runner.papertrail_plan import (
    PlanError,
    RunEnvironment,
    assemble_run,
    check_first_run_scope,
    papertrail_environment,
    plan_differences,
)
from .runner.policy import PolicyViolation
from .runner.revision import Clock
from .runner.run_evidence import EvidenceError, RunEvidence


class SystemClock:
    def monotonic(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


def _render(outcome: RunOutcome) -> str:
    if outcome.verdict is not None:
        verdict = f"{outcome.verdict} {outcome.reason_codes}"
    elif outcome.engine_verdict is not None:
        verdict = (f"NOT ESTABLISHED (evidence incomplete); the engine evaluated {outcome.engine_verdict} "
                   f"{outcome.reason_codes}, kept for review only")
    else:
        verdict = "not evaluated"
    return (f"\nRUN evidence {outcome.status}, lifecycle {outcome.lifecycle}\n"
            f"  verdict          {verdict}\n"
            f"  stop reason      {outcome.stop_reason or 'none'}\n"
            f"  cleanup verified {outcome.cleanup_complete}\n"
            f"  reconciliation   {outcome.reconciliation} (daemon continuity {outcome.daemon_continuity})\n"
            f"  evidence         {outcome.evidence_dir}\n")


@dataclass(frozen=True)
class OnceResult:
    """What `execute_once` did. `code` is this utility's own exit code (module docstring).

    `stage`: `REFUSED` (nothing claimed, no Docker operation), `CLAIMED_NOT_EXECUTED` (the
    authorization is consumed, no Docker operation), `INCOMPLETE` (execution started, no
    finalized evidence), `FINISHED` (`outcome` holds the finalized or incomplete record).
    """

    code: int
    stage: Literal["REFUSED", "CLAIMED_NOT_EXECUTED", "INCOMPLETE", "FINISHED"]
    outcome: RunOutcome | None = None


def run_once(env: RunEnvironment, terminal: Terminal, executor_factory: Callable[[], Executor], *, clock: Clock,
             now: Callable[[], datetime]) -> int:
    return execute_once(env, terminal, executor_factory, clock=clock, now=now).code


def execute_once(env: RunEnvironment, terminal: Terminal, executor_factory: Callable[[], Executor], *,
                 clock: Clock, now: Callable[[], datetime], expected_plan_sha256: str | None = None) -> OnceResult:
    """The execution flow. `expected_plan_sha256` (the `patchproof run <plan-id>` path) refuses,
    before anything is claimed, unless the single unused authorization binds exactly that plan."""
    try:
        try:
            store = RunAuthorizationStore(env.authorization_store)
            stored = store.executable()
        except RunAuthorizationError as exc:
            raise ApprovalBlocked(f"run-authorization store: {exc}") from None
        if stored is None:
            raise ApprovalBlocked("there is no unused run authorization")
        if expected_plan_sha256 is not None and stored.record.plan_sha256 != expected_plan_sha256:
            raise ApprovalBlocked("the unused run authorization binds a different plan; approve the selected plan "
                                  "first (a consumed authorization never runs again)")
        plan = stored.record.plan
        check_first_run_scope(plan)
        run = assemble_run(env, plan.run_id)
        if run.document != plan or run.sha256 != stored.record.plan_sha256:
            raise ApprovalBlocked(f"the current inputs differ from the authorized plan in "
                                  f"{plan_differences(plan, run.document)}; this authorization cannot execute")
        if os.path.lexists(env.evidence_root / plan.run_id):
            raise ApprovalBlocked("evidence for this run ID already exists")
        executor = executor_factory()
        terminal.write(f"Authorization {stored.record.authorization_id}\n  run  {plan.run_id}\n  plan "
                       f"{stored.record.plan_sha256}\n  baseline  {plan.sources.baseline.commit_id}\n  candidate "
                       f"{plan.sources.candidate.commit_id}\n  This creates at most 4 containers, sequentially, "
                       "and consumes the authorization even if the run fails.\n")
        typed = terminal.read_line(f"To execute, type exactly:  {execution_phrase(plan)}\nConfirmation: ")
        if typed != execution_phrase(plan):
            raise ApprovalBlocked("the confirmation does not match")
        if assemble_run(env, plan.run_id).document != plan or store.executable() != stored:
            raise ApprovalBlocked("an input or the authorization changed before the claim")
    except (ApprovalBlocked, PlanError, PolicyViolation, OSError) as exc:
        terminal.write(f"\nNOT EXECUTED: {exc}. Nothing was claimed and no Docker operation ran.\n")
        return OnceResult(2, "REFUSED")
    except (EOFError, KeyboardInterrupt):
        terminal.write("\nNOT EXECUTED: input ended. Nothing was claimed.\n")
        return OnceResult(2, "REFUSED")

    try:
        claim_raw = store.claim(stored.record.authorization_id, run_id=plan.run_id, now=now())
    except (RunAuthorizationError, OSError) as exc:
        terminal.write(f"\nNOT EXECUTED: {exc}. No Docker operation ran.\n")
        if isinstance(exc, RunAuthorizationError):
            return OnceResult(2, "REFUSED")
        return OnceResult(3, "CLAIMED_NOT_EXECUTED")
    except KeyboardInterrupt:
        terminal.write("\nNOT EXECUTED: interrupted during the claim. The authorization counts as consumed; "
                       "no Docker operation ran.\n")
        return OnceResult(3, "CLAIMED_NOT_EXECUTED")
    try:
        records, claims = store.scan()
        if is_superseded(records, stored.record.authorization_id) or claims[stored.record.authorization_id].raw \
                != claim_raw:
            raise ApprovalBlocked("the authorization was superseded or its claim differs")
        evidence = RunEvidence.claim(env.evidence_root, plan.run_id)
    except (ApprovalBlocked, RunAuthorizationError, EvidenceError, OSError, KeyError) as exc:
        terminal.write(f"\nNOT EXECUTED: {exc}. The authorization is consumed; no Docker operation ran.\n")
        return OnceResult(3, "CLAIMED_NOT_EXECUTED")
    except KeyboardInterrupt:
        terminal.write("\nNOT EXECUTED: interrupted after the claim. The authorization is consumed; no Docker "
                       "operation ran.\n")
        return OnceResult(3, "CLAIMED_NOT_EXECUTED")

    try:
        outcome = execute_authorized_run(env, stored.record, stored.raw, claim_raw, run, evidence, executor,
                                         clock=clock, now=now)
    except (EvidenceError, PolicyViolation, OSError, ValueError, KeyboardInterrupt) as exc:
        terminal.write(f"\nRUN INCOMPLETE: {type(exc).__name__}: {exc}. The authorization is consumed. Partial "
                       f"evidence is in {evidence.directory} (no manifest). Check for remaining containers with "
                       "`python -I -m patchproof.recover_run`.\n")
        return OnceResult(4, "INCOMPLETE")
    terminal.write(_render(outcome))
    if outcome.status != "FINALIZED":
        return OnceResult(4, "FINISHED", outcome)
    attention = (outcome.stop_reason is not None or not outcome.cleanup_complete or outcome.lifecycle != "COMPLETE"
                 or outcome.reconciliation != "CONSISTENT" or outcome.daemon_continuity != "NO_CHANGE_OBSERVED")
    return OnceResult(5 if attention else 0, "FINISHED", outcome)


def main() -> int:
    try:
        require_interactive(sys.argv, os.environ)
    except NotInteractive as exc:
        sys.stderr.write(f"NOT EXECUTED: {exc}. Nothing was read, claimed or executed.\n")
        return 2
    with graceful_termination():
        return run_once(papertrail_environment(), _ConsoleTerminal(),
                        lambda: DockerCli(resolve_docker_binary(), str(Path.home())), clock=SystemClock(),
                        now=lambda: datetime.now(UTC))


if __name__ == "__main__":
    raise SystemExit(main())
