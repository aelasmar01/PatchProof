"""Deterministic synchronization point for the interruption test (PP-008).

**Reachability.** Only the dedicated interruption-test child (`patchproof.interruption_child`)
creates an `InterruptionPoint`, and only for a claimed `interruption-test-authorization` whose
claim names its parent. `run_papertrail_once` and `execute_authorized_run` have no parameter
that reaches it, and the ordinary run-authorization contract cannot express the test.

**What it does.** The runner process (the child) and the controller (the parent that started
it) share one anonymous pipe:

1. **Child, at the checkpoint.** `execute_revision` calls the point with the facts it has
   itself established (`revision.CheckpointState`). The point acts only if they are exactly:
   pair 1, baseline, the target started and `READY` (healthy), the verifier created and
   through its pre-start inspection gate but not started. Anything else aborts, and nothing
   is reported. It then writes one fixed JSON line, closes the pipe, and waits at most
   `wait_seconds` for the signal. The `graceful_termination` handler turns the signal into
   `RunTerminated`, which `execute_revision` records as the revision's interruption before
   the usual exact-ID cleanup. If no signal arrives, or the line cannot be written, the
   point raises `InterruptionTestAborted`: fail-closed, the same cleanup runs, the verifier
   is never started, and nothing retries. The report carries `send_by_monotonic` (system-wide
   monotonic clock): the wait's end minus a margin, after which the controller must not
   signal, so a stalled controller can never interrupt the cleanup that follows an abort.
2. **Controller.** `deliver_at_checkpoint` reads that line within a deadline and checks every
   key and value exactly: the stage, the run ID, the PID of the process the controller
   itself started and has not reaped, the target's readiness, the verifier's state, and that
   `send_by_monotonic` has not passed. Only then does it send SIGTERM, once, through that
   process handle (never `os.kill` on a number, never a process group, never SIGKILL).
   Anything else sends nothing.

The pipe carries no command, option, image or path: the only action it can cause is one
signal to one known child.
"""

from __future__ import annotations

import json
import os
import re
import select
import signal
import stat
import time
from dataclasses import dataclass, field
from typing import Any, Final, Literal, Protocol

from .policy import PolicyViolation
from .revision import CheckpointState, Clock

STAGE: Final = "baseline-target-ready"
VERIFIER_STATE: Final = "CREATED_INSPECTED_NOT_STARTED"
MAX_WAIT_SECONDS: Final = 60.0
MAX_REPORT_TIMEOUT_SECONDS: Final = 900.0
MAX_REPORT_BYTES: Final = 512
REPORT_KEYS: Final = frozenset({"checkpoint", "pid", "run_id", "target_id", "target_readiness", "verifier_id",
                                "verifier_state", "send_by_monotonic"})
MAX_SEND_MARGIN_SECONDS: Final = 5.0
_RUN_RE: Final = re.compile(r"run-[0-9a-f]{32}")
_CONTAINER_RE: Final = re.compile(r"[0-9a-f]{64}")
_POLL_SECONDS: Final = 0.05


class InterruptionTestAborted(PolicyViolation):
    """The interruption test could not synchronize; the revision stops and cleans up."""


def checkpoint_problems(state: CheckpointState) -> list[str]:
    """Why the runner's own facts are not the reviewed synchronization point (empty: they are)."""
    problems = []
    if (state.pair, state.side, state.stage) != (1, "baseline", "target-ready"):
        problems.append(f"not the reviewed stage (pair {state.pair}, {state.side}, {state.stage})")
    if not state.target_started or state.target_readiness != "READY":
        problems.append("the target has not started and passed readiness")
    if not state.verifier_gate_passed:
        problems.append("the verifier has not passed its pre-start inspection")
    if state.verifier_started:
        problems.append("the verifier has already started")
    if (not _CONTAINER_RE.fullmatch(state.target_id) or not _CONTAINER_RE.fullmatch(state.verifier_id)
            or state.target_id == state.verifier_id):
        problems.append("the container IDs are not two distinct full IDs")
    return problems


@dataclass
class InterruptionPoint:
    """The child's side: one report, then a bounded wait for the signal. Single use."""

    run_id: str
    report_fd: int
    wait_seconds: float
    stage: Literal["baseline-target-ready"] = STAGE
    used: bool = field(default=False, init=False)
    closed: bool = field(default=False, init=False)
    report: dict[str, Any] | None = field(default=None, init=False)
    reported_at_monotonic: float | None = field(default=None, init=False)
    observed: str | None = field(default=None, init=False)
    observed_at_monotonic: float | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        if not _RUN_RE.fullmatch(self.run_id):
            raise PolicyViolation("invalid run ID")
        if isinstance(self.wait_seconds, bool) or not 1 <= self.wait_seconds <= MAX_WAIT_SECONDS:
            raise PolicyViolation(f"the wait must be between 1 and {MAX_WAIT_SECONDS:g} seconds")
        if self.report_fd < 3 or not stat.S_ISFIFO(os.fstat(self.report_fd).st_mode):
            raise PolicyViolation("the report channel must be an inherited pipe, not a standard stream or file")

    def close(self) -> None:
        """Close the report channel if it is still open (idempotent). The controller then reads EOF."""
        if not self.closed:
            self.closed = True
            os.close(self.report_fd)

    def __call__(self, state: CheckpointState, clock: Clock) -> None:
        """Called by `execute_revision` at stage `target-ready`. Acts once, at the reviewed state only."""
        if self.used:
            raise InterruptionTestAborted("the interruption point was already used")
        self.used = True
        problems = checkpoint_problems(state)
        if problems:
            self.close()
            raise InterruptionTestAborted("the checkpoint was reached in the wrong state: " + "; ".join(problems))
        # The signal must arrive well before this child gives up waiting (time.monotonic is
        # system-wide, so the controller can compare it with its own reading).
        margin = min(MAX_SEND_MARGIN_SECONDS, self.wait_seconds / 2)
        report = {"checkpoint": self.stage, "pid": os.getpid(), "run_id": self.run_id,
                  "target_id": state.target_id, "target_readiness": state.target_readiness,
                  "verifier_id": state.verifier_id, "verifier_state": VERIFIER_STATE,
                  "send_by_monotonic": round(time.monotonic() + self.wait_seconds - margin, 6)}
        line = json.dumps(report, sort_keys=True).encode() + b"\n"
        try:
            written = os.write(self.report_fd, line)
        except OSError as exc:
            raise InterruptionTestAborted(f"the checkpoint could not be reported ({type(exc).__name__})") from None
        finally:
            self.close()
        if written != len(line):
            raise InterruptionTestAborted("the checkpoint report was cut short")
        self.report, self.reported_at_monotonic = report, time.monotonic()
        deadline = clock.monotonic() + self.wait_seconds
        try:
            while clock.monotonic() < deadline:  # the signal handler raises RunTerminated out of this sleep
                clock.sleep(_POLL_SECONDS)
        except KeyboardInterrupt as exc:
            self.observed = getattr(exc, "signal_name", "SIGINT")
            self.observed_at_monotonic = time.monotonic()
            raise
        raise InterruptionTestAborted(f"no signal within {self.wait_seconds:g} seconds; stopping without retry")


class ChildProcess(Protocol):
    """The controller's own child (`subprocess.Popen`): signalled only through this handle."""

    @property
    def pid(self) -> int: ...

    def poll(self) -> int | None: ...

    def send_signal(self, sig: int) -> None: ...


@dataclass(frozen=True)
class Delivery:
    delivered: bool
    reason: str
    pid: int
    report: dict[str, Any] | None
    signals_sent: int = 0
    reported_at_monotonic: float | None = None
    delivered_at_monotonic: float | None = None


def _read_report(fd: int, deadline: float) -> bytes:
    data = b""
    while b"\n" not in data and len(data) <= MAX_REPORT_BYTES:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        ready, _, _ = select.select([fd], [], [], remaining)
        if not ready:
            continue
        chunk = os.read(fd, MAX_REPORT_BYTES + 1 - len(data))
        if not chunk:
            break  # the child closed the pipe or exited
        data += chunk
    return data


def report_problems(report: dict[str, Any], *, run_id: str, child_pid: int) -> str | None:
    """The refusal reason for a parsed report, or None when every key and value is exact."""
    if set(report) != REPORT_KEYS:
        return "MALFORMED_REPORT"
    if report["checkpoint"] != STAGE or report["run_id"] != run_id:
        return "WRONG_STAGE_OR_RUN"
    if isinstance(report["pid"], bool) or report["pid"] != child_pid:
        return "REPORT_FROM_ANOTHER_PROCESS"
    if report["target_readiness"] != "READY":
        return "TARGET_NOT_READY"
    if report["verifier_state"] != VERIFIER_STATE:
        return "VERIFIER_NOT_IN_REVIEWED_STATE"
    ids = (report["target_id"], report["verifier_id"])
    if not all(isinstance(i, str) and _CONTAINER_RE.fullmatch(i) for i in ids) or ids[0] == ids[1]:
        return "MALFORMED_REPORT"
    send_by = report["send_by_monotonic"]
    if isinstance(send_by, bool) or not isinstance(send_by, (int, float)):
        return "MALFORMED_REPORT"
    return None


def deliver_at_checkpoint(child: ChildProcess, report_read_fd: int, *, run_id: str,
                          report_timeout_seconds: float) -> Delivery:
    """The controller's side: verify the child's report, then send SIGTERM to that child once.

    `child` must be a process this controller started and has not reaped, so its PID cannot
    have been reused. No retry, no other signal and no escalation: if the child does not
    stop, that is reported to the owner, not handled automatically.
    """
    if (not _RUN_RE.fullmatch(run_id) or isinstance(report_timeout_seconds, bool)
            or not 1 <= report_timeout_seconds <= MAX_REPORT_TIMEOUT_SECONDS):
        raise PolicyViolation("invalid run ID or report timeout")

    def refused(reason: str, report: dict[str, Any] | None = None) -> Delivery:
        return Delivery(False, reason, child.pid, report)

    try:
        raw = _read_report(report_read_fd, time.monotonic() + report_timeout_seconds)
    except TimeoutError:
        return refused("NO_CHECKPOINT_REPORT_IN_TIME")
    finally:
        os.close(report_read_fd)
    reported = time.monotonic()
    if not raw:
        return refused("NO_CHECKPOINT_REPORT")  # the child closed the channel without reaching the checkpoint
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1 or len(raw) > MAX_REPORT_BYTES:
        return refused("MALFORMED_REPORT")
    try:
        report = json.loads(raw, object_pairs_hook=_no_duplicates)
    except ValueError:
        return refused("MALFORMED_REPORT")
    if not isinstance(report, dict):
        return refused("MALFORMED_REPORT")
    problem = report_problems(report, run_id=run_id, child_pid=child.pid)
    if problem is not None:
        return refused(problem, report)
    if child.poll() is not None:
        return refused("CHILD_ALREADY_EXITED", report)
    if time.monotonic() > report["send_by_monotonic"]:  # the child may be cleaning up: never interrupt that
        return refused("REPORT_TOO_LATE", report)
    child.send_signal(signal.SIGTERM)  # Popen refuses to signal a reaped child
    return Delivery(True, "SIGTERM_SENT", child.pid, report, 1, reported, time.monotonic())


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key")
    return dict(pairs)
