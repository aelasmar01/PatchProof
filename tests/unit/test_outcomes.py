"""PP-007: per-test lifecycle and semantic derivation (verdict specification sections 3.2-3.3).

Each case names the rule it exercises (L1-L11 and the harness-error table). These are the
integrity cases a pack cannot talk its way out of: a generic assertion is not a
violation, a crash is not a functional FAIL, a caught terminal exception is flagged, and
missing or repeated observations are flagged.
"""

from __future__ import annotations

from typing import Any

import pytest

from patchproof.core.outcomes import BlockGrammarError, derive_outcome
from patchproof.core.records.run import Observation, ObservationPayload, TestReportPayload

TID = "AUTH-001"


def rep(phase: str, outcome: str = "passed", failure: str = "none", xfail: bool = False) -> TestReportPayload:
    return TestReportPayload(test_id=TID, phase=phase, outcome=outcome, failure_class=failure,  # type: ignore[arg-type]
                             xfail=xfail)


def obs(outcome: str = "VIOLATION_CONFIRMED") -> ObservationPayload:
    return ObservationPayload(test_id=TID, outcome=outcome, summary="synthetic", evidence_refs=[])  # type: ignore[arg-type]


def derive(kind: str, *events: Any, truncated: bool = False) -> tuple[str, str, tuple[str, ...]]:
    d = derive_outcome(kind, TID, list(events), truncated=truncated)  # type: ignore[arg-type]
    return d.lifecycle_outcome, d.semantic_outcome, d.harness_errors


SECURITY_CASES = [
    ("L11 violation witnessed", [rep("setup"), obs(), rep("call", "failed", "security_terminal"), rep("teardown")],
     ("COMPLETED", "VIOLATION_CONFIRMED", ())),
    ("L11 secure", [rep("setup"), obs("SECURE"), rep("call"), rep("teardown")], ("COMPLETED", "SECURE", ())),
    ("L11 inconclusive", [rep("setup"), obs("INCONCLUSIVE"), rep("call"), rep("teardown")],
     ("COMPLETED", "INCONCLUSIVE", ())),
    ("L8 generic assertion is not a violation", [rep("setup"), rep("call", "failed", "assertion"), rep("teardown")],
     ("CALL_ERROR", "NONE", ("GENERIC_FAILURE_IN_SECURITY_TEST", "MISSING_TERMINAL_OBSERVATION"))),
    ("missing observation", [rep("setup"), rep("call"), rep("teardown")],
     ("COMPLETED", "NONE", ("MISSING_TERMINAL_OBSERVATION",))),
    ("multiple observations", [rep("setup"), obs("SECURE"), obs("SECURE"), rep("call"), rep("teardown")],
     ("COMPLETED", "NONE", ("MULTIPLE_TERMINAL_OBSERVATIONS",))),
    ("suppressed terminal exception", [rep("setup"), obs(), rep("call"), rep("teardown")],
     ("COMPLETED", "VIOLATION_CONFIRMED", ("SUPPRESSED_TERMINAL_EXCEPTION",))),
    ("terminal exception without a violation", [rep("setup"), obs("SECURE"),
                                                rep("call", "failed", "security_terminal"), rep("teardown")],
     ("COMPLETED", "SECURE", ("MALFORMED_EVIDENCE",))),
    ("L7 helper misuse", [rep("setup"), rep("call", "failed", "helper_misuse"), rep("teardown")],
     ("CALL_ERROR", "NONE", ("MISSING_TERMINAL_OBSERVATION",))),
    ("L7 exception (for example a connection error)", [rep("setup"), rep("call", "failed", "exception"),
                                                       rep("teardown")],
     ("CALL_ERROR", "NONE", ("MISSING_TERMINAL_OBSERVATION",))),
    ("L6 timeout", [rep("setup"), rep("call", "failed", "timeout"), rep("teardown")],
     ("TIMED_OUT", "NONE", ("MISSING_TERMINAL_OBSERVATION",))),
    ("L4 setup error", [rep("setup", "failed", "exception"), rep("teardown")], ("SETUP_ERROR", "NONE", ())),
    ("L5 skipped at setup", [rep("setup", "skipped"), rep("teardown")], ("SKIPPED", "NONE", ())),
    ("L5 skipped in call", [rep("setup"), rep("call", "skipped"), rep("teardown")],
     ("SKIPPED", "NONE", ("MISSING_TERMINAL_OBSERVATION",))),
    ("L3 xfailed", [rep("setup"), rep("call", "skipped", xfail=True), rep("teardown")],
     ("XFAILED", "NONE", ("MISSING_TERMINAL_OBSERVATION",))),
    ("L2 xpassed", [rep("setup"), obs("SECURE"), rep("call", xfail=True), rep("teardown")],
     ("XPASSED", "SECURE", ())),
    ("L10 teardown error after an observation", [rep("setup"), obs(), rep("call", "failed", "security_terminal"),
                                                 rep("teardown", "failed", "exception")],
     ("TEARDOWN_ERROR", "VIOLATION_CONFIRMED", ("ERROR_AFTER_OBSERVATION",))),
]


@pytest.mark.parametrize(("label", "events", "expected"), SECURITY_CASES, ids=[c[0] for c in SECURITY_CASES])
def test_security_derivation(label: str, events: list[Any], expected: tuple[str, str, tuple[str, ...]]) -> None:
    assert derive("security", *events) == expected


FUNCTIONAL_CASES = [
    ("pass", [rep("setup"), rep("call"), rep("teardown")], ("COMPLETED", "PASS", ())),
    ("assertion is a legitimate-behavior failure", [rep("setup"), rep("call", "failed", "assertion"), rep("teardown")],
     ("COMPLETED", "FAIL", ())),
    ("a crash is not a FAIL", [rep("setup"), rep("call", "failed", "exception"), rep("teardown")],
     ("CALL_ERROR", "NONE", ())),
    ("a timeout is not a FAIL", [rep("setup"), rep("call", "failed", "timeout"), rep("teardown")],
     ("TIMED_OUT", "NONE", ())),
    ("L9 security helper in a functional test", [rep("setup"), obs(), rep("call", "failed", "security_terminal"),
                                                 rep("teardown")],
     ("CALL_ERROR", "NONE", ("OBSERVATION_ON_FUNCTIONAL_TEST",))),
    ("observation on a passing functional test", [rep("setup"), obs("SECURE"), rep("call"), rep("teardown")],
     ("COMPLETED", "PASS", ("OBSERVATION_ON_FUNCTIONAL_TEST",))),
    ("teardown failure", [rep("setup"), rep("call"), rep("teardown", "failed", "exception")],
     ("TEARDOWN_ERROR", "NONE", ())),
    ("setup error", [rep("setup", "failed", "exception"), rep("teardown")], ("SETUP_ERROR", "NONE", ())),
]


@pytest.mark.parametrize(("label", "events", "expected"), FUNCTIONAL_CASES, ids=[c[0] for c in FUNCTIONAL_CASES])
def test_functional_derivation(label: str, events: list[Any], expected: tuple[str, str, tuple[str, ...]]) -> None:
    assert derive("functional", *events) == expected


def test_truncated_block_is_interrupted() -> None:
    assert derive("security", rep("setup"), obs(), truncated=True) == (
        "INTERRUPTED", "VIOLATION_CONFIRMED", ())
    assert derive("functional", rep("setup"), truncated=True)[0] == "INTERRUPTED"
    with pytest.raises(BlockGrammarError):
        derive("security", rep("setup"), rep("call"), rep("teardown"), truncated=True)


@pytest.mark.parametrize("events", [
    [],
    [rep("call"), rep("setup"), rep("teardown")],
    [rep("setup"), rep("teardown")],
    [rep("setup"), rep("call")],
    [rep("setup", "failed", "exception"), rep("call"), rep("teardown")],
    [obs(), rep("setup"), rep("call"), rep("teardown")],
    [rep("setup"), rep("call"), obs(), rep("teardown")],
    [rep("setup"), rep("call"), rep("call"), rep("teardown")],
])
def test_invalid_blocks_are_refused_not_interpreted(events: list[Any]) -> None:
    with pytest.raises(BlockGrammarError):
        derive("security", *events)


def test_event_for_another_test_is_refused() -> None:
    other = TestReportPayload(test_id="AUTH-002", phase="setup", outcome="passed", failure_class="none", xfail=False)
    with pytest.raises(BlockGrammarError):
        derive_outcome("security", TID, [other, rep("call"), rep("teardown")])


@pytest.mark.parametrize(("kind", "events"), [(k, [e for e in case[1]]) for k, cases in
                                              (("security", SECURITY_CASES), ("functional", FUNCTIONAL_CASES))
                                              for case in cases])
def test_every_derived_cell_is_a_schema_valid_observation(kind: str, events: list[Any]) -> None:
    lifecycle, semantic, errors = derive(kind, *events)
    Observation.model_validate({
        "schema_version": "1.0", "run_id": "run-" + "0" * 32, "pair": 1, "side": "candidate", "test_id": TID,
        "nodeid": "tests/test_documents.py::test_case", "kind": kind, "stream_status": "COMPLETE",
        "lifecycle_outcome": lifecycle, "semantic_outcome": semantic, "harness_errors": list(errors),
        "evidence_refs": [], "provenance": "verifier-event-stream"}, strict=True)


def _valid_reports(phase: str) -> list[TestReportPayload]:
    import itertools

    from pydantic import ValidationError

    found = []
    for outcome, failure, xfail in itertools.product(
            ("passed", "failed", "skipped"),
            ("none", "assertion", "security_terminal", "helper_misuse", "timeout", "exception"), (False, True)):
        try:
            found.append(TestReportPayload(test_id=TID, phase=phase, outcome=outcome,  # type: ignore[arg-type]
                                           failure_class=failure, xfail=xfail))  # type: ignore[arg-type]
        except ValidationError:
            pass
    return found


def test_functional_fail_is_reachable_only_through_an_assertion() -> None:
    """Exhaustive over every valid complete functional block, with and without observations.

    A functional cell is COMPLETED with a failed call only when the failure class is
    `assertion`, because L6, L7 and L9 route every other class first. That makes the
    explicit `failure_class == "assertion"` test before FAIL a redundant layer; mutation
    M26 is equivalent for that reason. And FAIL never arises from a crash, timeout,
    helper misuse or security exception.
    """
    completed_failed = 0
    for setup in _valid_reports("setup"):
        calls = _valid_reports("call") if setup.outcome == "passed" else [None]
        for call in calls:
            for teardown in _valid_reports("teardown"):
                for observations in ([], [obs("SECURE")]):
                    events: list[Any] = [setup, *(observations if call else []), *([call] if call else []), teardown]
                    lifecycle, semantic, _ = derive("functional", *events)
                    if semantic == "FAIL":
                        assert call is not None and call.failure_class == "assertion"
                    if lifecycle == "COMPLETED" and call is not None and call.outcome == "failed":
                        completed_failed += 1
                        assert call.failure_class == "assertion" and semantic == "FAIL"
    assert completed_failed > 0
