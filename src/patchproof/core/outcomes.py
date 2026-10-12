"""Per-test outcome derivation (verdict specification sections 3.2 and 3.3).

The input is one test's block of events: its phase reports and terminal observations, in
stream order. The output is the observation cell's `lifecycle_outcome`,
`semantic_outcome` and `harness_errors`.

The rules are pure and applied in the specification's order. The PP-008 collector checks
the stream grammar (section 3.1) before calling this. A block that does not have one of the
two valid shapes is refused here as well, never interpreted.

Key consequences:
- a generic `AssertionError` in a security test is never a violation witness (L8);
- a crash or timeout is never a functional `FAIL`;
- a violation whose terminal exception was caught is flagged (`SUPPRESSED_TERMINAL_EXCEPTION`);
- missing or repeated observations are flagged.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from .records.run import HarnessError, LifecycleOutcome, ObservationPayload, SemanticOutcome, TestReportPayload


class BlockGrammarError(ValueError):
    """The block is not one of the two valid report sequences (stream MALFORMED)."""


@dataclass(frozen=True)
class DerivedOutcome:
    lifecycle_outcome: LifecycleOutcome
    semantic_outcome: SemanticOutcome
    harness_errors: tuple[HarnessError, ...]


def _shape(reports: Sequence[TestReportPayload], truncated: bool) -> None:
    phases = [r.phase for r in reports]
    complete = (["setup", "call", "teardown"] if reports and reports[0].outcome == "passed"
                else ["setup", "teardown"])
    expected = complete[:len(phases)] if truncated else complete
    if phases != expected or (truncated and len(phases) >= len(complete)):
        raise BlockGrammarError("phase reports do not form a valid block")


def derive_outcome(kind: Literal["security", "functional"], test_id: str,
                   events: Sequence[TestReportPayload | ObservationPayload], *,
                   truncated: bool = False) -> DerivedOutcome:
    if any(e.test_id != test_id for e in events):
        raise BlockGrammarError("an event belongs to a different test")
    reports = [e for e in events if isinstance(e, TestReportPayload)]
    observations = [e for e in events if isinstance(e, ObservationPayload)]
    _shape(reports, truncated)
    # Observations may only appear between the call's start (after setup) and its report.
    position = {id(e): i for i, e in enumerate(events)}
    setup_at = position[id(reports[0])] if reports else -1
    call = next((r for r in reports if r.phase == "call"), None)
    call_at = position[id(call)] if call else len(events)
    if any(not setup_at < position[id(o)] < call_at for o in observations):
        raise BlockGrammarError("an observation lies outside the call window")
    if observations and (not reports or reports[0].outcome != "passed"):
        raise BlockGrammarError("an observation without a passed setup")

    setup = reports[0] if reports else None
    teardown = next((r for r in reports if r.phase == "teardown"), None)
    errors: list[HarnessError] = []

    lifecycle: LifecycleOutcome
    if truncated:
        lifecycle = "INTERRUPTED"                                                     # L1
    elif any(r.xfail for r in reports):
        lifecycle = "XPASSED" if call and call.outcome in ("passed", "failed") else "XFAILED"   # L2, L3
    elif setup is not None and setup.outcome == "failed":
        lifecycle = "SETUP_ERROR"                                                     # L4
    elif (setup is not None and setup.outcome == "skipped") or (call and call.outcome == "skipped"):
        lifecycle = "SKIPPED"                                                         # L5
    elif call and call.outcome == "failed" and call.failure_class == "timeout":
        lifecycle = "TIMED_OUT"                                                       # L6
    elif call and call.outcome == "failed" and call.failure_class in ("exception", "helper_misuse"):
        lifecycle = "CALL_ERROR"                                                      # L7
    elif kind == "security" and call and call.outcome == "failed" and call.failure_class == "assertion":
        lifecycle = "CALL_ERROR"                                                      # L8
        errors.append("GENERIC_FAILURE_IN_SECURITY_TEST")
    elif kind == "functional" and call and call.outcome == "failed" and call.failure_class == "security_terminal":
        lifecycle = "CALL_ERROR"                                                      # L9
        errors.append("OBSERVATION_ON_FUNCTIONAL_TEST")
    elif teardown is not None and teardown.outcome == "failed":
        lifecycle = "TEARDOWN_ERROR"                                                  # L10
        if observations:
            errors.append("ERROR_AFTER_OBSERVATION")
    else:
        lifecycle = "COMPLETED"                                                       # L11

    semantic: SemanticOutcome = "NONE"
    if kind == "functional":
        if observations and "OBSERVATION_ON_FUNCTIONAL_TEST" not in errors:
            errors.append("OBSERVATION_ON_FUNCTIONAL_TEST")
        if lifecycle == "COMPLETED" and call is not None:
            if call.outcome == "passed":
                semantic = "PASS"
            elif call.failure_class == "assertion":
                semantic = "FAIL"
    else:
        if call is not None and not observations:
            errors.append("MISSING_TERMINAL_OBSERVATION")
        if len(observations) > 1:
            errors.append("MULTIPLE_TERMINAL_OBSERVATIONS")
        if len(observations) == 1 and lifecycle != "SETUP_ERROR":
            semantic = observations[0].outcome
        violation = len(observations) == 1 and observations[0].outcome == "VIOLATION_CONFIRMED"
        if violation and call is not None and call.outcome == "passed":
            errors.append("SUPPRESSED_TERMINAL_EXCEPTION")
        if call is not None and call.failure_class == "security_terminal" and not violation:
            errors.append("MALFORMED_EVIDENCE")
    return DerivedOutcome(lifecycle, semantic, tuple(errors))
