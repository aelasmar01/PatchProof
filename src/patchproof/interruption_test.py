"""Owner-operated controller of the deliberate interruption demonstration (PP-008 integration utility).

Test-only. It executes the single unused `papertrail-interruption-sigterm-baseline-v1`
authorization, once, and nothing else. Run it yourself, in your own terminal, from the project
directory, only with separate Docker approval:

    uv run --locked --offline python -I -m patchproof.interruption_test

**Refuses, with nothing consumed and no child started, unless:**
- the process is an interactive foreground terminal with no arguments and no `PATCHPROOF*`
  variables;
- exactly one unused interruption-test authorization exists and is valid;
- the plan recomputed now equals the frozen plan exactly;
- no evidence exists for the run (child or controller);
- the owner types exactly `INTERRUPT <run-id>`.

**Then, in order:**
1. **Claim:** the authorization is consumed with an exclusive, fsynced claim naming this
   controller's PID. From here on it can never run again, whatever happens.
2. **Child:** one runner child, `python -I -m patchproof.interruption_child <run-id> <fd>`,
   with one private pipe as its only extra descriptor. The child refuses unless the claim
   names this process as its parent.
3. **Checkpoint:** `interruption_point.deliver_at_checkpoint` waits at most the plan's report
   timeout for the child's report, checks it exactly (stage, run ID, the child's own PID,
   target `READY`, verifier created and inspected but not started), and sends exactly one
   SIGTERM through the child's process handle. Never another PID or a process group, never
   SIGKILL, never a retry. If the report is missing or wrong, nothing is sent and the child
   stops itself after its synchronization wait (fail closed).
4. **Wait:** at most the plan's cleanup timeout for the child to clean up and exit. A child
   still running then is reported, NOT killed: no further signal and no Docker operation
   (this controller has no Docker client). Its evidence is not read while it may still be
   written, cleanup is not confirmed, the controller record stays `INCOMPLETE`, and the
   output names the container IDs the controller knows and the `recover_run` step.
5. **Record:** the delivery, the child's PID and exit code, durations, and the comparison of
   the child's evidence with the expected outcome, in
   `<user data>/evidence/interruption-controller/<run-id>/`.

**Two different exit codes.** The child's exit code is the PatchProof lifecycle exit code of
the interrupted run (PROJECT_SPEC.md 13.2: 20 for `INTERRUPTED`); it is recorded, not reused.
This controller's own (harness) exit code is: 0 the expected outcome was observed exactly;
1 the test ran but deviated (or could not be confirmed); 3 claimed but no child ran;
2 refused, nothing consumed.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Protocol

from .core.interruption_authorizations import (
    InterruptionAuthorizationError,
    InterruptionAuthorizationStore,
    interruption_execution_phrase,
    is_superseded,
)
from .pack_approval import ApprovalBlocked, NotInteractive, Terminal, _ConsoleTerminal, require_interactive
from .runner.interrupts import graceful_termination
from .runner.interruption_plan import (
    assemble_interruption,
    check_interruption_scope,
    interruption_environment,
    interruption_plan_differences,
)
from .runner.interruption_point import ChildProcess, Delivery, deliver_at_checkpoint
from .runner.papertrail_plan import PlanError, RunEnvironment
from .runner.policy import PolicyViolation
from .runner.run_evidence import EvidenceError, RunEvidence, utc_stamp, verify_evidence

EXPECTED_OBSERVED = 0
DEVIATION = 1
REFUSED = 2
CLAIMED_NOT_RUN = 3


class ControlledChild(ChildProcess, Protocol):
    def wait(self, timeout: float | None = None) -> int: ...


Spawn = Callable[[str, int], ControlledChild]


CHILD_MODULE: Final = "patchproof.interruption_child"
CHILD_PATH: Final = "/usr/bin:/bin"
_RUN_RE: Final = re.compile(r"run-[0-9a-f]{32}")


def child_environment(home: str) -> dict[str, str]:
    """The child's complete environment: nothing is inherited from the controller's.

    `HOME` locates the same private data directory the controller uses; the child resolves the
    Docker client from its own allowlist, not from `PATH`, and passes Docker a sanitized
    environment of its own (`docker_cli.sanitized_env`).
    """
    if not os.path.isabs(home) or any(c in home for c in "\0\n\r"):
        raise PolicyViolation("the home directory must be an absolute path")
    return {"HOME": home, "PATH": CHILD_PATH, "LC_ALL": "C", "LANG": "C"}


def spawn_child(run_id: str, report_fd: int) -> ControlledChild:
    """The one child this controller starts: this interpreter, a fixed module, a validated run ID,
    one inherited pipe and an explicit environment. No shell; nothing else is configurable."""
    if not _RUN_RE.fullmatch(run_id) or isinstance(report_fd, bool) or not 3 <= report_fd <= 9999:
        raise PolicyViolation("invalid run ID or report descriptor")
    return subprocess.Popen([sys.executable, "-I", "-m", CHILD_MODULE, run_id, str(report_fd)],
                            pass_fds=(report_fd,), stdin=subprocess.DEVNULL, close_fds=True,
                            env=child_environment(os.path.expanduser("~")))


def controller_root(env: RunEnvironment) -> Path:
    return env.evidence_root.parent / "interruption-controller"


def _child_evidence(env: RunEnvironment, run_id: str) -> tuple[dict[str, Any], dict[str, Any] | None]:
    directory = env.evidence_root / run_id
    if not directory.is_dir():
        return {"state": "ABSENT", "status": None, "problems": ["no child evidence directory"]}, None
    check = verify_evidence(directory)
    try:
        outcome = json.loads((directory / "outcome.json").read_bytes())
    except (OSError, ValueError):
        outcome = None
    return check, outcome if isinstance(outcome, dict) else None


def harness_deviations(delivery: Delivery, child_exit: int | None, check: dict[str, Any],
                       outcome: dict[str, Any] | None, expected: dict[str, Any]) -> list[str]:
    """Everything that differs from the reviewed expectation. Empty: the expected outcome was observed."""
    problems = []
    if not delivery.delivered or delivery.signals_sent != 1:
        problems.append(f"signal not delivered: {delivery.reason}")
    if child_exit != expected["lifecycle_exit_code"]:
        problems.append(f"child lifecycle exit code {child_exit}, expected {expected['lifecycle_exit_code']}")
    if check["state"] != "CONSISTENT" or check["status"] != "INCOMPLETE":
        problems.append(f"child evidence {check['state']} {check['status']}: {check['problems']}")
    if outcome is None:
        problems.append("no child outcome.json")
        return problems
    for key in ("lifecycle", "evidence_status", "cleanup_status", "verdict", "decision_rule", "lifecycle_exit_code"):
        if outcome.get(key) != expected[key]:
            problems.append(f"{key}: expected {expected[key]}, observed {outcome.get(key)}")
    if outcome.get("signal_observed") != "SIGTERM" or not outcome.get("checkpoint_reached"):
        problems.append("the child did not observe SIGTERM at the checkpoint")
    if (outcome.get("candidate_executed") is not False or outcome.get("verifier_started") is not False
            or outcome.get("containers_created") != 2 or outcome.get("start_operations") != ["start"]):
        problems.append("the execution was not exactly: two creations, the target started, nothing else")
    if outcome.get("remaining_owned_container_ids") != [] or outcome.get("reconciliation") != "CONSISTENT":
        problems.append("containers remain or the inventory is not consistent")
    if outcome.get("verified") is not False or outcome.get("matches_expected") is not True:
        problems.append("the child's own comparison with the expected outcome failed")
    report = delivery.report or {}
    if report.get("pid") != delivery.pid:
        problems.append("the report PID is not the child's PID")
    return problems


def run_interruption_test(env: RunEnvironment, terminal: Terminal, spawn: Spawn, *,
                          now: Callable[[], datetime]) -> int:
    try:
        try:
            store = InterruptionAuthorizationStore(env.authorization_store)
            stored = store.executable()
        except InterruptionAuthorizationError as exc:
            raise ApprovalBlocked(f"interruption-authorization store: {exc}") from None
        if stored is None:
            raise ApprovalBlocked("there is no unused interruption-test authorization")
        plan = stored.record.plan
        check_interruption_scope(plan)
        run = assemble_interruption(env, plan.run_id)
        if run.document != plan or run.sha256 != stored.record.plan_sha256:
            raise ApprovalBlocked(f"the current inputs differ from the authorized plan in "
                                  f"{interruption_plan_differences(plan, run.document)}; it cannot execute")
        for directory in (env.evidence_root / plan.run_id, controller_root(env) / plan.run_id):
            if os.path.lexists(directory):
                raise ApprovalBlocked("evidence for this run ID already exists")
        i = plan.interruption
        terminal.write(
            f"Interruption-test authorization {stored.record.authorization_id}\n  run  {plan.run_id}\n  plan "
            f"{stored.record.plan_sha256}\n  baseline  {plan.sources.baseline.commit_id} (no candidate)\n"
            f"  At most 2 containers; only the target starts; the verifier is never started.\n"
            f"  One {i.signal} to the runner child at {i.stage}; never SIGKILL; no retry.\n"
            "  This run is deliberately interrupted and cannot produce a verified-fix result.\n"
            "  It consumes the authorization even if it fails.\n")
        phrase = interruption_execution_phrase(plan)
        typed = terminal.read_line(f"To execute, type exactly:  {phrase}\nConfirmation: ")
        if typed != phrase:
            raise ApprovalBlocked("the confirmation does not match")
        if assemble_interruption(env, plan.run_id).document != plan or store.executable() != stored:
            raise ApprovalBlocked("an input or the authorization changed before the claim")
    except (ApprovalBlocked, PlanError, PolicyViolation, OSError) as exc:
        terminal.write(f"\nNOT EXECUTED: {exc}. Nothing was claimed and no child was started.\n")
        return REFUSED
    except (EOFError, KeyboardInterrupt):
        terminal.write("\nNOT EXECUTED: input ended. Nothing was claimed.\n")
        return REFUSED

    try:
        claim_raw = store.claim(stored.record.authorization_id, run_id=plan.run_id, now=now())
    except InterruptionAuthorizationError as exc:
        terminal.write(f"\nNOT EXECUTED: {exc}. No child was started.\n")
        return REFUSED
    except (OSError, KeyboardInterrupt) as exc:
        terminal.write(f"\nNOT EXECUTED: the claim did not complete ({type(exc).__name__}). The authorization "
                       "counts as consumed; no child was started.\n")
        return CLAIMED_NOT_RUN
    try:
        records, claims = store.scan()
        if is_superseded(records, stored.record.authorization_id) or claims[stored.record.authorization_id].raw \
                != claim_raw:
            raise ApprovalBlocked("the authorization was superseded or its claim differs")
        record = RunEvidence.claim(controller_root(env), plan.run_id)
        record.write("claim.json", claim_raw)
    except (ApprovalBlocked, InterruptionAuthorizationError, EvidenceError, OSError, KeyError,
            KeyboardInterrupt) as exc:
        terminal.write(f"\nNOT EXECUTED: {exc}. The authorization is consumed; no child was started.\n")
        return CLAIMED_NOT_RUN

    report_read, report_write = os.pipe()
    started_at, started = utc_stamp(now()), time.monotonic()
    try:
        child = spawn(plan.run_id, report_write)
    except (OSError, PolicyViolation, KeyboardInterrupt) as exc:
        os.close(report_read)
        terminal.write(f"\nNOT EXECUTED: the child could not be started ({type(exc).__name__}). The authorization "
                       "is consumed.\n")
        _record(record, {"result": "CHILD_NOT_STARTED", "error": type(exc).__name__}, "INCOMPLETE")
        return CLAIMED_NOT_RUN
    finally:
        os.close(report_write)
    terminal.write(f"Runner child started: PID {child.pid}. Waiting for its checkpoint report "
                   f"(at most {i.checkpoint_report_timeout_seconds} s).\n")
    try:
        delivery = deliver_at_checkpoint(child, report_read, run_id=plan.run_id,
                                         report_timeout_seconds=i.checkpoint_report_timeout_seconds)
    except KeyboardInterrupt:  # the owner interrupted the controller: never signal the child for it
        delivery = Delivery(False, "CONTROLLER_INTERRUPTED", child.pid, None)
    except (PolicyViolation, OSError) as exc:
        delivery = Delivery(False, f"CHECKPOINT_NOT_READ ({type(exc).__name__})", child.pid, None)
    terminal.write(f"Checkpoint: {delivery.reason}.\n")
    wait = i.cleanup_timeout_seconds + (0 if delivery.delivered else i.synchronization_wait_seconds)
    child_exit: int | None
    try:
        child_exit = child.wait(timeout=wait)
    except subprocess.TimeoutExpired:
        child_exit = None
    except KeyboardInterrupt:
        child_exit = child.poll()
    finished = time.monotonic()
    exited = child_exit is not None
    # A child that has not exited may still be writing: its evidence is not read, so nothing
    # it might still change is reported as a result.
    check, outcome = _child_evidence(env, plan.run_id) if exited else (
        {"state": "NOT_READ", "status": None, "problems": ["the child had not exited"]}, None)
    deviations = harness_deviations(delivery, child_exit, check, outcome, plan.expected_outcome.model_dump())
    if not exited:
        deviations.append(f"the child (PID {child.pid}) had not exited after {wait} s; it was NOT killed and no "
                          "further signal or cleanup was attempted")
    cleanup_confirmed = bool(outcome and outcome.get("cleanup_status") == "COMPLETE"
                             and outcome.get("remaining_owned_container_ids") == [] and check["state"] == "CONSISTENT")
    reported_ids = [(delivery.report or {}).get(k) for k in ("target_id", "verifier_id")]
    possibly_remaining = sorted({*(i for i in reported_ids if isinstance(i, str)),
                                 *((outcome or {}).get("remaining_owned_container_ids") or [])}) \
        if not cleanup_confirmed else []
    summary = {
        "run_id": plan.run_id, "authorization_id": stored.record.authorization_id,
        "plan_sha256": stored.record.plan_sha256, "authorization_consumed": True,
        "result": "EXPECTED_OUTCOME_OBSERVED" if not deviations else "DEVIATION",
        "harness_exit_code": EXPECTED_OBSERVED if not deviations else DEVIATION,
        "child_pid": child.pid, "child_exited": exited, "child_lifecycle_exit_code": child_exit,
        "delivery": asdict(delivery), "signals_sent": delivery.signals_sent,
        "started_at": started_at, "finished_at": utc_stamp(now()),
        "duration_seconds": round(finished - started, 6),
        "child_evidence_check": check, "child_outcome": outcome,
        "cleanup_confirmed": cleanup_confirmed,
        "possibly_remaining_container_ids": possibly_remaining,
        "manual_recovery_may_be_required": not cleanup_confirmed,
        "expected_outcome": plan.expected_outcome.model_dump(), "deviations": deviations,
        "note": "The child's exit code is the PatchProof lifecycle exit code; the harness exit code is separate.",
    }
    # The controller's record is complete only once its child has exited.
    recorded = _record(record, summary, "FINALIZED" if exited else "INCOMPLETE")
    recovery = ("  Cleanup is confirmed by the child's evidence.\n" if cleanup_confirmed else
                "  CLEANUP NOT CONFIRMED: manual recovery may be required. "
                + (f"The child (PID {child.pid}) is still running; let it finish or stop it yourself, then " if not
                   exited else "")
                + f"run patchproof.recover_run for {plan.run_id} (with Docker approval). Container IDs known to "
                f"this controller: {possibly_remaining or 'none'}; the child's ownership journal is in "
                f"{env.evidence_root / plan.run_id}.\n")
    terminal.write(f"\nINTERRUPTION TEST {summary['result']}\n  child PID {child.pid}, lifecycle exit code "
                   f"{child_exit}\n  signal {delivery.reason}\n  child evidence {check['state']} {check['status']}\n"
                   + "".join(f"  deviation: {d}\n" for d in deviations)
                   + recovery
                   + f"  controller record {record.directory}{'' if recorded else ' (WRITE FAILED)'}\n")
    return EXPECTED_OBSERVED if not deviations and recorded else DEVIATION


def _record(evidence: RunEvidence, summary: dict[str, Any], status: str) -> bool:
    try:
        evidence.write_json("controller.json", summary)
        evidence.finalize(status="FINALIZED" if status == "FINALIZED" else "INCOMPLETE", summary=summary)
    except (EvidenceError, OSError):
        return False
    return True


def main() -> int:
    try:
        require_interactive(sys.argv, os.environ)
    except NotInteractive as exc:
        sys.stderr.write(f"NOT EXECUTED: {exc}. Nothing was read, claimed or executed.\n")
        return REFUSED
    with graceful_termination():
        return run_interruption_test(interruption_environment(), _ConsoleTerminal(), spawn_child,
                                     now=lambda: datetime.now(UTC))


if __name__ == "__main__":
    raise SystemExit(main())
