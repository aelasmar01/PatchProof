"""The runner child of the interruption test (PP-008). Started ONLY by `patchproof.interruption_test`.

It is not an owner command and does nothing on its own: it executes an interruption-test
authorization only when the controller that claimed it is this process's parent. Its single
invocation form is fixed by the controller:

    python -I -m patchproof.interruption_child <run-id> <report-fd>

**Refuses, with no Docker operation and the report channel closed, unless:**
- the arguments are exactly a run ID and a file-descriptor number, and no `PATCHPROOF*`
  variable is set (there is no option, flag or environment switch);
- the interruption store holds exactly one authorization for that run ID, it is not
  superseded, and its claim is complete (`CLAIMED`), names that run, and names this process's
  parent as the claimant;
- the plan recomputed now equals the frozen plan exactly, and no evidence exists for the run;
- the report descriptor is an inherited pipe (`InterruptionPoint`).

Then it executes `runner.interruption_run.execute_interruption_test` once, under
`graceful_termination`, and exits with the run's PROJECT_SPEC.md 13.2 lifecycle exit code
(20 for the expected `INTERRUPTED` lifecycle). Exit 2 means refused before any Docker
operation. Nothing retries.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

from .core.interruption_authorizations import (
    InterruptionAuthorizationError,
    InterruptionAuthorizationStore,
    is_superseded,
)
from .run_papertrail_once import SystemClock
from .runner.docker_cli import DockerCli, Executor, resolve_docker_binary
from .runner.interrupts import graceful_termination
from .runner.interruption_plan import (
    assemble_interruption,
    check_interruption_scope,
    interruption_environment,
    interruption_plan_differences,
)
from .runner.interruption_point import InterruptionPoint
from .runner.interruption_run import execute_interruption_test
from .runner.papertrail_plan import PlanError, RunEnvironment
from .runner.policy import PolicyViolation
from .runner.revision import Clock
from .runner.run_evidence import EvidenceError, RunEvidence

REFUSED = 2
INTERRUPTED_EXIT = 20
_RUN_RE = re.compile(r"run-[0-9a-f]{32}")
_FD_RE = re.compile(r"[0-9]{1,4}")


class ChildRefused(Exception):
    """The child will not execute. Nothing was executed."""


def parse_arguments(argv: Sequence[str], environ: Mapping[str, str]) -> tuple[str, int]:
    if len(argv) != 3 or not _RUN_RE.fullmatch(argv[1]) or not _FD_RE.fullmatch(argv[2]):
        raise ChildRefused("the only accepted form is: <run-id> <report-fd>")
    if any(name.upper().startswith("PATCHPROOF") for name in environ):
        raise ChildRefused("PATCHPROOF* environment variables are not accepted")
    return argv[1], int(argv[2])


def run_child(env: RunEnvironment, run_id: str, report_fd: int, executor_factory: Callable[[], Executor], *,
              parent_pid: int, clock: Clock, now: Callable[[], datetime], log: Callable[[str], None]) -> int:
    point: InterruptionPoint | None = None
    try:
        try:
            records, claims = InterruptionAuthorizationStore(env.authorization_store).scan()
        except InterruptionAuthorizationError as exc:
            raise ChildRefused(f"interruption-authorization store: {exc}") from None
        matching = [r for r in records.values() if r.record.plan.run_id == run_id]
        if len(matching) != 1:
            raise ChildRefused("there is no interruption authorization for this run ID")
        stored = matching[0]
        claim = claims.get(stored.record.authorization_id)
        if claim is None or claim.state != "CLAIMED" or claim.run_id != run_id:
            raise ChildRefused("the authorization has no complete claim for this run")
        if claim.pid != parent_pid:
            raise ChildRefused("the authorization was not claimed by this process's parent")
        if is_superseded(records, stored.record.authorization_id):
            raise ChildRefused("the authorization was superseded")
        plan = stored.record.plan
        check_interruption_scope(plan)
        run = assemble_interruption(env, run_id)
        if run.document != plan or run.sha256 != stored.record.plan_sha256:
            raise ChildRefused(f"the current inputs differ from the authorized plan in "
                               f"{interruption_plan_differences(plan, run.document)}")
        if os.path.lexists(env.evidence_root / run_id):
            raise ChildRefused("evidence for this run ID already exists; a run is never repeated")
        point = InterruptionPoint(run_id, report_fd, plan.interruption.synchronization_wait_seconds)
        executor = executor_factory()
        evidence = RunEvidence.claim(env.evidence_root, run_id)
    except (ChildRefused, PlanError, PolicyViolation, EvidenceError, OSError, KeyboardInterrupt) as exc:
        if point is not None:
            point.close()
        else:
            try:
                os.close(report_fd)
            except OSError:
                pass
        log(f"INTERRUPTION CHILD REFUSED: {type(exc).__name__}: {exc}. No Docker operation ran.\n")
        return REFUSED
    try:
        outcome = execute_interruption_test(env, stored.record, stored.raw, claim.raw, run, evidence, executor, point,
                                            clock=clock, now=now)
    except (EvidenceError, PolicyViolation, OSError, ValueError, KeyboardInterrupt) as exc:
        point.close()
        log(f"INTERRUPTION CHILD STOPPED: {type(exc).__name__}: {exc}. Partial evidence (no manifest) is in "
            f"{evidence.directory}. Check for remaining containers with patchproof.recover_run.\n")
        return INTERRUPTED_EXIT
    log(f"INTERRUPTION CHILD FINISHED: lifecycle {outcome.lifecycle}, evidence {outcome.evidence_status}, "
        f"cleanup {outcome.cleanup_status}, verdict {outcome.verdict} ({outcome.decision_rule}), signal "
        f"{outcome.signal_observed}, lifecycle exit code {outcome.lifecycle_exit_code}.\n")
    return outcome.lifecycle_exit_code


def _log(text: str) -> None:
    sys.stderr.write(text)
    sys.stderr.flush()


def main(argv: Sequence[str] | None = None, environ: Mapping[str, str] | None = None) -> int:
    try:
        run_id, report_fd = parse_arguments(sys.argv if argv is None else argv,
                                            os.environ if environ is None else environ)
    except ChildRefused as exc:
        sys.stderr.write(f"INTERRUPTION CHILD REFUSED: {exc}. Nothing was read or executed.\n")
        return REFUSED
    with graceful_termination():
        return run_child(interruption_environment(), run_id, report_fd,
                         lambda: DockerCli(resolve_docker_binary(), str(Path.home())), parent_pid=os.getppid(),
                         clock=SystemClock(), now=lambda: datetime.now(UTC), log=_log)


if __name__ == "__main__":
    raise SystemExit(main())
