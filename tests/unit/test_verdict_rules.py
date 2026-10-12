"""PP-004: spec-derived rule tests, built by hand and independent of the scenario corpus.

Each test states the expected verdict from docs/architecture/verdict-specification.md
directly. Sections: decision table (6), decisions D1-D6 (11), validation M1-M7 / G1-G5
(5.2), execution trust E1-E4 (4.2), cell trust T1-T5 (4.3), flags (7), reasons and
details (8), counts (8).
"""

from __future__ import annotations

import copy
from typing import Any

import pytest
from _verdict_builder import (
    CAP,
    EVALUATED_AT,
    TESTS,
    details,
    execution,
    find_cell,
    find_execution,
    observation,
    resync,
    run,
    set_cell,
    set_stream,
    verified_input,
)

from patchproof.core import verdicts
from patchproof.core.verdict_input import parse_verdict_input
from patchproof.core.verdicts import EvaluationError, evaluate


def failed(phase: str, *codes: str) -> dict[str, Any]:
    return {"state": "FAILED", "detected_phase": phase, "reason_codes": list(codes)}


NOT_EVALUATED = {"state": "NOT_EVALUATED", "detected_phase": None, "reason_codes": []}


def not_started(data: dict[str, Any]) -> dict[str, Any]:
    data["executions"], data["observations"] = [], []
    return data


def verdict(result: dict[str, Any]) -> tuple[str, str]:
    return result["verdict"], result["decision_rule"]


# ------------------------------------------------------------------- decision table V-01..V-10


def test_v09_exact_agreement_is_verified() -> None:
    result = run(verified_input(pairs=2))
    assert verdict(result) == ("VERIFIED_FOR_CASES", "V-09")
    assert result["reason_codes"] == ["ALL_CONDITIONS_SATISFIED"] and result["details"] == []
    assert result["counts"]["trusted_cells"] == result["counts"]["required_cells"] == 16


@pytest.mark.parametrize("name", ["authorization", "pack_integrity", "source_identity", "environment_identity",
                                  "result_provenance"])
def test_v01_pre_execution_failure_blocks(name: str) -> None:
    data = not_started(verified_input())
    data["preconditions"][name] = failed("pre_execution", "APPROVAL_STALE")
    result = run(data)
    assert verdict(result) == ("BLOCKED", "V-01")
    assert result["execution_started"] is False and result["flags"]["incomplete_checks"] is True
    assert "APPROVAL_STALE" in result["reason_codes"]


def test_v01_unevaluated_precondition_before_start_blocks() -> None:
    data = not_started(verified_input())
    data["preconditions"]["source_identity"] = NOT_EVALUATED
    result = run(data)
    assert verdict(result) == ("BLOCKED", "V-01")
    assert "PRECONDITION_NOT_EVALUATED" in result["reason_codes"]


def test_v02_post_execution_failure_voids_all_evidence_including_violations() -> None:
    data = set_cell(verified_input(), 1, "candidate", "AUTH-001", semantic_outcome="VIOLATION_CONFIRMED")
    data["preconditions"]["environment_identity"] = failed("post_execution", "ENVIRONMENT_NONCOMPARABLE")
    result = run(data)
    assert verdict(result) == ("INCONCLUSIVE", "V-02")
    assert result["counts"]["trusted_cells"] == 0
    assert result["flags"]["candidate_violation"] is False and result["flags"]["harness_drift"] is True


def test_not_evaluated_code_survives_a_validation_failure() -> None:
    data = verified_input()
    data["preconditions"]["result_provenance"] = NOT_EVALUATED
    _dup(data)
    result = run(data, check_input_schema=False)
    assert verdict(result) == ("INCONCLUSIVE", "V-02")
    assert result["preconditions"]["result_provenance"] == "FAILED"
    assert "PRECONDITION_NOT_EVALUATED" in result["reason_codes"]


def test_v02_unevaluated_precondition_after_start() -> None:
    data = verified_input()
    data["preconditions"]["pack_integrity"] = NOT_EVALUATED
    result = run(data)
    assert verdict(result) == ("INCONCLUSIVE", "V-02")
    assert "PRECONDITION_NOT_EVALUATED" in result["reason_codes"]


def test_v02_validation_failure_without_execution_is_not_blocked() -> None:
    data = not_started(verified_input())
    rec = execution(1, "baseline")
    rec.update(started=False, run_id="run-" + "b" * 32)
    rec["target"]["readiness"] = "NOT_STARTED"
    rec["verifier"].update(termination="NOT_STARTED", exit_code=None)
    rec["stream"].update(status="ABSENT", session_end_received=False, events_received=0, bytes_received=0)
    data["executions"] = [rec]
    result = run(data)
    assert verdict(result) == ("INCONCLUSIVE", "V-02")
    assert result["preconditions"]["result_provenance"] == "FAILED"


def test_v03_trusted_candidate_violation_is_not_fixed() -> None:
    result = run(set_cell(verified_input(), 1, "candidate", "AUTH-001", semantic_outcome="VIOLATION_CONFIRMED"))
    assert verdict(result) == ("NOT_FIXED", "V-03")
    assert details(result, "CANDIDATE_VIOLATION_CONFIRMED") == [(1, "candidate", "AUTH-001")]
    assert details(result, "NEW_SECURITY_VIOLATION") == []  # baseline observed a violation, not SECURE


def test_new_security_violation_needs_a_trusted_same_pair_baseline_secure() -> None:
    result = run(set_cell(verified_input(), 1, "candidate", "AUTH-003", semantic_outcome="VIOLATION_CONFIRMED"))
    assert details(result, "NEW_SECURITY_VIOLATION") == [(1, "candidate", "AUTH-003")]
    data = set_cell(verified_input(), 1, "candidate", "AUTH-003", semantic_outcome="VIOLATION_CONFIRMED")
    set_cell(data, 1, "baseline", "AUTH-003", lifecycle_outcome="TIMED_OUT", semantic_outcome="NONE")
    result = run(data)
    assert verdict(result) == ("NOT_FIXED", "V-03")
    assert details(result, "NEW_SECURITY_VIOLATION") == []  # expectation alone is not comparative evidence


def test_v04_regression_needs_same_pair_trusted_baseline_pass() -> None:
    result = run(set_cell(verified_input(), 1, "candidate", "FUNC-001", semantic_outcome="FAIL"))
    assert verdict(result) == ("REGRESSION_DETECTED", "V-04")
    assert details(result, "FUNCTIONAL_REGRESSION") == [(1, "candidate", "FUNC-001")]


def test_v04_requires_the_same_pair() -> None:
    data = set_cell(verified_input(pairs=2), 2, "candidate", "FUNC-001", semantic_outcome="FAIL")
    set_cell(data, 2, "baseline", "FUNC-001", lifecycle_outcome="CALL_ERROR", semantic_outcome="NONE")
    result = run(data)  # pair 1 baseline PASS does not anchor pair 2
    assert result["flags"]["functional_regression"] is False
    assert verdict(result) == ("INCONCLUSIVE", "V-05")


def test_v05_missing_cell_is_inconclusive() -> None:
    data = verified_input()
    data["observations"] = [o for o in data["observations"]
                            if not (o["side"] == "candidate" and o["test_id"] == "AUTH-002")]
    set_stream(data, 1, "candidate", "TRUNCATED")
    result = run(data)
    assert verdict(result) == ("INCONCLUSIVE", "V-05")
    assert (1, "candidate", "AUTH-002") in details(result, "REQUIRED_CHECK_INCOMPLETE")


def test_v06_flakiness_precedes_control_and_reproduction_rules() -> None:
    data = set_cell(verified_input(pairs=2), 2, "baseline", "AUTH-001", semantic_outcome="SECURE")
    result = run(data)
    assert verdict(result) == ("INCONCLUSIVE", "V-06")
    assert result["flags"]["baseline_not_reproduced"] is True and result["flags"]["flaky_observations"] is True
    assert details(result, "INCONSISTENT_REPETITIONS") == [(None, "baseline", "AUTH-001")]


def test_v07_baseline_functional_control_failure() -> None:
    result = run(set_cell(verified_input(), 1, "baseline", "FUNC-001", semantic_outcome="FAIL"))
    assert verdict(result) == ("INCONCLUSIVE", "V-07")
    assert details(result, "BASELINE_CONTROL_FAILED") == [(1, "baseline", "FUNC-001")]


def test_v07_baseline_security_unexpected() -> None:
    result = run(set_cell(verified_input(), 1, "baseline", "AUTH-003", semantic_outcome="VIOLATION_CONFIRMED"))
    assert verdict(result) == ("INCONCLUSIVE", "V-07")
    assert details(result, "BASELINE_SECURITY_UNEXPECTED") == [(1, "baseline", "AUTH-003")]


def test_v08_baseline_not_reproduced() -> None:
    data = set_cell(verified_input(), 1, "baseline", "AUTH-001", semantic_outcome="SECURE")
    set_cell(data, 1, "baseline", "AUTH-002", semantic_outcome="SECURE")
    result = run(data)
    assert verdict(result) == ("NOT_REPRODUCED", "V-08")
    assert "BASELINE_NOT_REPRODUCED" in result["reason_codes"]
    assert details(result, "BASELINE_NOT_REPRODUCED") == [(None, "baseline", "AUTH-001"),
                                                          (None, "baseline", "AUTH-002")]


def test_v10_fallthrough_never_defaults_to_verified(monkeypatch: pytest.MonkeyPatch) -> None:
    # Unreachable by construction; force a stray reason on otherwise verified evidence.
    original = verdicts._execution_reasons
    monkeypatch.setattr(verdicts, "_execution_reasons", lambda e, cap: original(e, cap) | {"RUNTIME_ERROR"})
    result = evaluate(parse_verdict_input(verified_input()), EVALUATED_AT)
    assert verdict(result) == ("INCONCLUSIVE", "V-10")
    assert "UNCLASSIFIED_EVIDENCE" in result["reason_codes"]


# ------------------------------------------------------------------- owner decisions D1-D6


def test_d1_local_execution_failure_does_not_hide_violation_elsewhere() -> None:
    data = set_cell(verified_input(pairs=2), 1, "candidate", "AUTH-001", semantic_outcome="VIOLATION_CONFIRMED")
    find_execution(data, 2, "candidate")["deadline_exceeded"] = True
    result = run(resync(data))
    assert verdict(result) == ("NOT_FIXED", "V-03")
    assert result["flags"]["incomplete_checks"] is True
    assert details(result, "EXECUTION_TIMED_OUT") == [(2, "candidate", None)]


def test_d1_malformed_stream_is_global() -> None:
    data = set_cell(verified_input(pairs=2), 1, "candidate", "AUTH-001", semantic_outcome="VIOLATION_CONFIRMED")
    set_stream(data, 2, "candidate", "MALFORMED")
    result = run(data)
    assert verdict(result) == ("INCONCLUSIVE", "V-02")
    assert details(result, "EVENT_STREAM_MALFORMED") == [(2, "candidate", None)]
    assert result["counts"]["trusted_cells"] == 0


def test_d2_violation_in_one_pair_secure_in_another_is_not_fixed_and_flaky() -> None:
    data = set_cell(verified_input(pairs=2), 1, "candidate", "AUTH-001", semantic_outcome="VIOLATION_CONFIRMED")
    result = run(data)
    assert verdict(result) == ("NOT_FIXED", "V-03")
    assert result["flags"]["flaky_observations"] is True


def test_d3_truncated_stream_violation_is_not_evidence() -> None:
    data = set_cell(verified_input(), 1, "candidate", "AUTH-001", semantic_outcome="VIOLATION_CONFIRMED")
    set_stream(data, 1, "candidate", "TRUNCATED")
    result = run(data)
    assert verdict(result) == ("INCONCLUSIVE", "V-05")
    assert result["flags"]["candidate_violation"] is False
    assert details(result, "EVENT_STREAM_TRUNCATED") == [(1, "candidate", None)]


def test_d4_partial_reproduction_lists_only_unreproduced_tests() -> None:
    result = run(set_cell(verified_input(), 1, "baseline", "AUTH-002", semantic_outcome="SECURE"))
    assert verdict(result) == ("NOT_REPRODUCED", "V-08")
    assert details(result, "BASELINE_PARTIALLY_REPRODUCED") == [(None, "baseline", "AUTH-002")]
    assert "BASELINE_NOT_REPRODUCED" not in result["reason_codes"]


def test_d5_pre_execution_failure_while_started_is_inconsistent() -> None:
    data = verified_input()
    data["preconditions"]["authorization"] = failed("pre_execution", "APPROVAL_STALE")
    result = run(data)
    assert verdict(result) == ("INCONCLUSIVE", "V-02")
    assert "EXECUTION_EVIDENCE_INCONSISTENT" in result["reason_codes"]


def test_d5_post_execution_failure_claimed_without_execution_fails_closed() -> None:
    data = not_started(verified_input())
    data["preconditions"]["environment_identity"] = failed("post_execution", "ENVIRONMENT_NONCOMPARABLE")
    result = run(data)
    assert verdict(result) == ("INCONCLUSIVE", "V-02")
    assert "EXECUTION_EVIDENCE_INCONSISTENT" in result["reason_codes"]


@pytest.mark.parametrize("how", ["status", "bytes"])
def test_d6_over_cap_is_local_and_does_not_hide_other_violation(how: str) -> None:
    data = set_cell(verified_input(pairs=2), 1, "candidate", "AUTH-001", semantic_outcome="VIOLATION_CONFIRMED")
    if how == "status":
        set_stream(data, 2, "candidate", "OVER_CAP")
        find_execution(data, 2, "candidate")["stream"]["bytes_received"] = CAP + 1
    else:
        find_execution(data, 2, "candidate")["stream"]["bytes_received"] = CAP + 1
    result = run(data)
    assert verdict(result) == ("NOT_FIXED", "V-03")
    assert details(result, "RESULT_CAP_EXCEEDED") == [(2, "candidate", None)]
    assert result["counts"]["pairs_with_trusted_evidence"] == 1


def test_d6_over_cap_violation_alone_is_inconclusive_and_cap_boundary_is_inclusive() -> None:
    data = set_cell(verified_input(), 1, "candidate", "AUTH-001", semantic_outcome="VIOLATION_CONFIRMED")
    find_execution(data, 1, "candidate")["stream"]["bytes_received"] = CAP + 1
    result = run(data)
    assert verdict(result) == ("INCONCLUSIVE", "V-05") and result["flags"]["candidate_violation"] is False
    exact = verified_input()
    find_execution(exact, 1, "candidate")["stream"]["bytes_received"] = CAP
    assert verdict(run(exact)) == ("VERIFIED_FOR_CASES", "V-09")


# ------------------------------------------------------------------- input validation M1-M7, G1-G5


def _dup(data: dict[str, Any]) -> None:
    extra = copy.deepcopy(find_cell(data, 1, "baseline", "AUTH-001"))
    extra["evidence_refs"] = [{"artifact_id": "art-" + "c" * 32, "sha256": "sha256:" + "d" * 64}]
    data["observations"].append(extra)


VALIDATION_CASES: dict[str, tuple[Any, str]] = {
    "M1 foreign run id": (lambda d: find_cell(d, 1, "baseline", "AUTH-001").update(run_id="run-" + "e" * 32),
                          "OBSERVATION_MATRIX_INVALID"),
    "M2 unknown test": (lambda d: find_cell(d, 1, "baseline", "AUTH-001").update(test_id="AUTH-999"),
                        "OBSERVATION_MATRIX_INVALID"),
    "M2 kind mismatch": (lambda d: find_cell(d, 1, "baseline", "FUNC-001").update(kind="security",
                                                                                  semantic_outcome="SECURE"),
                         "OBSERVATION_MATRIX_INVALID"),
    "M2 nodeid mismatch": (lambda d: find_cell(d, 1, "baseline", "AUTH-001").update(nodeid="tests/test_x.py::test_x"),
                           "OBSERVATION_MATRIX_INVALID"),
    "M3 pair beyond plan": (lambda d: find_cell(d, 1, "candidate", "AUTH-001").update(pair=2),
                            "OBSERVATION_MATRIX_INVALID"),
    "M4 conflicting duplicate cell": (_dup, "OBSERVATION_MATRIX_INVALID"),
    "M5 duplicate execution": (lambda d: d["executions"].append(dict(copy.deepcopy(d["executions"][0]),
                                                                     runtime_errors=["INSPECT_FAILED"])),
                               "OBSERVATION_MATRIX_INVALID"),
    "M6 stream status differs": (lambda d: find_cell(d, 1, "candidate", "AUTH-001").update(stream_status="TRUNCATED",
                                                                                           lifecycle_outcome="COMPLETED"),
                                 "OBSERVATION_MATRIX_INVALID"),
    "M6 no owning execution": (lambda d: d["executions"].pop(), "OBSERVATION_MATRIX_INVALID"),
    "M7 complete stream missing a cell": (lambda d: d["observations"].remove(find_cell(d, 1, "candidate", "FUNC-001")),
                                          "OBSERVATION_MATRIX_INVALID"),
    "G2 events without verifier": (lambda d: find_execution(d, 1, "candidate")["verifier"].update(
        termination="NOT_STARTED", exit_code=None), "EXECUTION_EVIDENCE_INCONSISTENT"),
    "G3 exit code contradicts reports": (lambda d: find_execution(d, 1, "candidate")["verifier"].update(exit_code=1),
                                         "EXECUTION_EVIDENCE_INCONSISTENT"),
    "G4 fewer failed reports than failed cells": (lambda d: (find_execution(d, 1, "baseline")["stream"].update(
        failed_reports=1)), "EXECUTION_EVIDENCE_INCONSISTENT"),
}


@pytest.mark.parametrize("name", sorted(VALIDATION_CASES))
def test_validation_failures_are_global_and_fail_closed(name: str) -> None:
    mutate, code = VALIDATION_CASES[name]
    data = verified_input()
    mutate(data)
    result = run(data, check_input_schema=False)
    assert verdict(result) == ("INCONCLUSIVE", "V-02"), name
    assert code in result["reason_codes"] and result["preconditions"]["result_provenance"] == "FAILED"
    assert result["counts"]["trusted_cells"] == 0 and result["counts"]["pairs_with_trusted_evidence"] == 0


def test_g1_identity_mismatch_is_global() -> None:
    result = run(set_stream(verified_input(), 1, "baseline", "IDENTITY_MISMATCH"))
    assert verdict(result) == ("INCONCLUSIVE", "V-02")
    assert details(result, "EVENT_STREAM_IDENTITY_MISMATCH") == [(1, "baseline", None)]


def test_byte_identical_duplicate_bypassing_the_schema_is_still_rejected() -> None:
    data = verified_input()
    data["observations"].append(copy.deepcopy(data["observations"][0]))
    result = run(data, check_input_schema=False)
    assert verdict(result) == ("INCONCLUSIVE", "V-02") and "OBSERVATION_MATRIX_INVALID" in result["reason_codes"]


def test_duplicate_pack_test_ids_fail_closed_and_are_not_deduplicated() -> None:
    tests = copy.deepcopy(TESTS)
    tests[1] = dict(tests[1], id="AUTH-001", nodeid="tests/test_auth.py::test_other")
    result = run(verified_input(tests=tests), check_input_schema=False)
    assert verdict(result) == ("INCONCLUSIVE", "V-02")
    assert "OBSERVATION_MATRIX_INVALID" in result["reason_codes"]
    assert result["counts"]["security_tests"] == 3 and result["counts"]["required_cells"] == 8  # both entries kept


def test_duplicate_pack_node_ids_fail_closed() -> None:
    tests = copy.deepcopy(TESTS)
    tests[1] = dict(tests[1], nodeid=tests[0]["nodeid"])
    result = run(verified_input(tests=tests), check_input_schema=False)
    assert verdict(result) == ("INCONCLUSIVE", "V-02")


def test_global_failure_keeps_execution_count_but_no_trusted_evidence() -> None:
    data = verified_input()
    _dup(data)
    result = run(data, check_input_schema=False)
    assert result["counts"]["pairs_terminated_normally"] == 1
    assert result["counts"]["pairs_with_trusted_evidence"] == 0 and result["counts"]["trusted_cells"] == 0


# ------------------------------------------------------------------- execution trust E1-E4 and reasons


def _verifier(**kw: Any) -> Any:
    return lambda d: find_execution(d, 1, "candidate")["verifier"].update(**kw)


EXECUTION_FAILURES: dict[str, tuple[Any, list[str]]] = {
    "verifier exit 2": (_verifier(exit_code=2), ["VERIFIER_TERMINATED_ABNORMALLY"]),
    "verifier signaled": (_verifier(termination="SIGNALED", exit_code=None, signal=9),
                          ["VERIFIER_TERMINATED_ABNORMALLY"]),
    "verifier unobserved": (_verifier(termination="NOT_OBSERVED", exit_code=None), ["VERIFIER_TERMINATED_ABNORMALLY"]),
    "verifier OOM": (_verifier(oom_killed=True), ["EXECUTION_OOM_KILLED"]),
    "target OOM": (lambda d: find_execution(d, 1, "candidate")["target"].update(oom_killed=True),
                   ["EXECUTION_OOM_KILLED"]),
    "target exited": (lambda d: find_execution(d, 1, "candidate")["target"].update(exited_during_tests=True),
                      ["TARGET_EXITED_DURING_TESTS"]),
    "deadline": (lambda d: find_execution(d, 1, "candidate").update(deadline_exceeded=True), ["EXECUTION_TIMED_OUT"]),
    "canceled execution": (lambda d: find_execution(d, 1, "candidate").update(canceled=True), ["EXECUTION_CANCELED"]),
    "runtime error": (lambda d: find_execution(d, 1, "candidate").update(runtime_errors=["ATTACH_FAILED"]),
                      ["RUNTIME_ERROR"]),
    "truncated": (lambda d: set_stream(d, 1, "candidate", "TRUNCATED"), ["EVENT_STREAM_TRUNCATED"]),
}


@pytest.mark.parametrize("name", sorted(EXECUTION_FAILURES))
def test_untrusted_execution_is_local_and_never_verified(name: str) -> None:
    mutate, codes = EXECUTION_FAILURES[name]
    data = verified_input()
    mutate(data)
    result = run(data)
    assert verdict(result) == ("INCONCLUSIVE", "V-05"), name
    for code in codes:
        assert details(result, code) == [(1, "candidate", None)], (name, code)
    assert result["counts"]["pairs_terminated_normally"] == 0
    assert result["counts"]["trusted_cells"] == 4  # the baseline side is still trusted
    assert "REPETITION_INCOMPLETE" in result["reason_codes"]


@pytest.mark.parametrize("explanation", ["deadline_exceeded", "canceled", "oom", "over_cap"])
def test_abnormal_termination_code_is_suppressed_only_by_an_explaining_cause(explanation: str) -> None:
    data = verified_input()
    e = find_execution(data, 1, "candidate")
    e["verifier"].update(termination="SIGNALED", exit_code=None, signal=9)
    if explanation == "oom":
        e["verifier"]["oom_killed"] = True
    elif explanation == "over_cap":
        e["stream"]["bytes_received"] = CAP + 1
    else:
        e[explanation] = True
    result = run(data)
    assert "VERIFIER_TERMINATED_ABNORMALLY" not in result["reason_codes"]
    explaining = {"deadline_exceeded": "EXECUTION_TIMED_OUT", "canceled": "EXECUTION_CANCELED",
                  "oom": "EXECUTION_OOM_KILLED", "over_cap": "RESULT_CAP_EXCEEDED"}[explanation]
    assert details(result, explaining) == [(1, "candidate", None)]


def test_target_startup_failure() -> None:
    data = verified_input()
    data["observations"] = [o for o in data["observations"] if o["side"] != "baseline"]
    e = find_execution(data, 1, "baseline")
    e["target"]["readiness"] = "STARTUP_FAILED"
    e["verifier"].update(termination="NOT_STARTED", exit_code=None)
    e["stream"].update(status="ABSENT", session_end_received=False, events_received=0, bytes_received=0,
                       failed_reports=0)
    result = run(resync(data))
    assert verdict(result) == ("INCONCLUSIVE", "V-05")
    assert details(result, "TARGET_STARTUP_FAILED") == [(1, "baseline", None)]
    assert "VERIFIER_TERMINATED_ABNORMALLY" not in result["reason_codes"]


# ------------------------------------------------------------------- cell trust T3-T5 and generic failures


@pytest.mark.parametrize("lifecycle", ["SETUP_ERROR", "CALL_ERROR", "TEARDOWN_ERROR", "SKIPPED", "XFAILED", "XPASSED",
                                       "TIMED_OUT"])
def test_non_completed_lifecycle_is_never_evidence(lifecycle: str) -> None:
    semantic = "NONE" if lifecycle in ("SETUP_ERROR", "CALL_ERROR", "TIMED_OUT", "SKIPPED") else "VIOLATION_CONFIRMED"
    result = run(set_cell(verified_input(), 1, "candidate", "AUTH-001", lifecycle_outcome=lifecycle,
                          semantic_outcome=semantic))
    assert verdict(result) == ("INCONCLUSIVE", "V-05") and result["flags"]["candidate_violation"] is False


def test_generic_assertion_in_security_test_is_not_a_witness() -> None:
    result = run(set_cell(verified_input(), 1, "candidate", "AUTH-001", lifecycle_outcome="CALL_ERROR",
                          semantic_outcome="NONE", harness_errors=["GENERIC_FAILURE_IN_SECURITY_TEST"]))
    assert verdict(result) == ("INCONCLUSIVE", "V-05")
    assert result["flags"]["candidate_violation"] is False and result["flags"]["harness_drift"] is True


def test_harness_error_untrusts_an_apparent_violation() -> None:
    result = run(set_cell(verified_input(), 1, "candidate", "AUTH-001", semantic_outcome="VIOLATION_CONFIRMED",
                          harness_errors=["SUPPRESSED_TERMINAL_EXCEPTION"]))
    assert verdict(result) == ("INCONCLUSIVE", "V-05")
    assert details(result, "HARNESS_ERROR") == [(1, "candidate", "AUTH-001")]


def test_inconclusive_check_is_reported_and_untrusted() -> None:
    result = run(set_cell(verified_input(), 1, "candidate", "AUTH-002", semantic_outcome="INCONCLUSIVE"))
    assert verdict(result) == ("INCONCLUSIVE", "V-05")
    assert details(result, "CHECK_INCONCLUSIVE") == [(1, "candidate", "AUTH-002")]


# ------------------------------------------------------------------- run termination


@pytest.mark.parametrize("termination,code", [("canceled", "RUN_CANCELED"), ("interrupted", "RUN_INTERRUPTED")])
def test_abnormal_run_termination_is_never_verified(termination: str, code: str) -> None:
    data = verified_input()
    data["run_termination"] = termination
    result = run(data)
    assert verdict(result) == ("INCONCLUSIVE", "V-05") and code in result["reason_codes"]


def test_canceled_run_keeps_established_violation() -> None:
    data = set_cell(verified_input(), 1, "candidate", "AUTH-001", semantic_outcome="VIOLATION_CONFIRMED")
    data["run_termination"] = "canceled"
    assert verdict(run(data)) == ("NOT_FIXED", "V-03")


# ------------------------------------------------------------------- flags are independent of the rule


def test_flags_remain_visible_under_higher_rules() -> None:
    data = set_cell(verified_input(pairs=2), 1, "candidate", "AUTH-001", semantic_outcome="VIOLATION_CONFIRMED")
    set_cell(data, 2, "candidate", "FUNC-001", semantic_outcome="FAIL")
    set_cell(data, 2, "baseline", "AUTH-002", semantic_outcome="SECURE")
    result = run(data)
    assert verdict(result) == ("NOT_FIXED", "V-03")
    f = result["flags"]
    assert f["candidate_violation"] and f["functional_regression"] and f["baseline_not_reproduced"]
    assert f["flaky_observations"]


def test_untrusted_cells_never_set_evidence_flags() -> None:
    data = set_cell(verified_input(), 1, "candidate", "AUTH-001", semantic_outcome="VIOLATION_CONFIRMED")
    set_cell(data, 1, "candidate", "FUNC-001", semantic_outcome="FAIL")
    set_stream(data, 1, "candidate", "TRUNCATED")
    result = run(data)
    assert not result["flags"]["candidate_violation"] and not result["flags"]["functional_regression"]


# ------------------------------------------------------------------- details ordering and arguments


def test_details_follow_canonical_order() -> None:
    data = set_cell(verified_input(pairs=2), 2, "candidate", "AUTH-002", semantic_outcome="VIOLATION_CONFIRMED")
    set_cell(data, 1, "candidate", "AUTH-001", semantic_outcome="VIOLATION_CONFIRMED")
    find_execution(data, 2, "baseline")["deadline_exceeded"] = True
    result = run(resync(data))
    keys = [(d["reason_code"], d["pair"], d["side"], d["test_id"]) for d in result["details"]]
    rank = {c: i for i, c in enumerate(verdicts.REASON_CODES)}
    side_rank = {None: 0, "baseline": 1, "candidate": 2}
    assert keys == sorted(keys, key=lambda k: (rank[k[0]], k[1] or 0, side_rank[k[2]], k[3] or ""))
    assert result["reason_codes"] == sorted(result["reason_codes"], key=rank.__getitem__)


@pytest.mark.parametrize("bad", ["2026-10-12", "2026-10-12T00:00:00+00:00", "", "now"])
def test_evaluated_at_must_be_a_utc_timestamp(bad: str) -> None:
    with pytest.raises(EvaluationError):
        evaluate(parse_verdict_input(verified_input()), bad)


def test_observation_without_execution_counts_as_started() -> None:
    data = verified_input()
    data["executions"] = []
    result = run(data, check_input_schema=False)
    assert result["execution_started"] is True and verdict(result) == ("INCONCLUSIVE", "V-02")


def test_extra_observation_constructor_is_consistent() -> None:
    assert observation(1, "baseline", TESTS[0])["semantic_outcome"] == "VIOLATION_CONFIRMED"


# ------------------------------------------------------------------- owner-listed review situations


def test_functional_control_failing_on_both_revisions_is_a_control_failure_not_a_regression() -> None:
    data = set_cell(verified_input(), 1, "baseline", "FUNC-001", semantic_outcome="FAIL")
    set_cell(data, 1, "candidate", "FUNC-001", semantic_outcome="FAIL")
    result = run(data)
    # V-04 needs a trusted same-pair baseline PASS; a broken control on both sides is V-07.
    assert verdict(result) == ("INCONCLUSIVE", "V-07")
    assert result["flags"]["functional_regression"] is False and result["flags"]["baseline_control_failed"] is True


def test_secure_looking_candidate_with_untested_baseline_is_never_verified_or_not_reproduced() -> None:
    data = verified_input()
    data["observations"] = [o for o in data["observations"] if o["side"] != "baseline"]
    e = find_execution(data, 1, "baseline")
    e["target"]["readiness"] = "READINESS_TIMEOUT"
    e["verifier"].update(termination="NOT_STARTED", exit_code=None)
    e["stream"].update(status="ABSENT", session_end_received=False, events_received=0, bytes_received=0,
                       failed_reports=0)
    result = run(data)
    assert verdict(result) == ("INCONCLUSIVE", "V-05")
    assert result["counts"]["trusted_cells"] == 4  # the candidate's own cells, all SECURE/PASS
    assert not result["flags"]["baseline_not_reproduced"]


@pytest.mark.parametrize("code", sorted(verdicts.REASON_CODES))
@pytest.mark.parametrize("started", [False, True])
def test_every_failed_precondition_reason_is_refused_or_yields_a_schema_valid_record(code: str, started: bool) -> None:
    from patchproof.core.verdict_input import VerdictInputError

    data = verified_input() if started else not_started(verified_input())
    data["preconditions"]["source_identity"] = failed("post_execution" if started else "pre_execution", code)
    try:
        parsed = parse_verdict_input(data)
    except VerdictInputError:
        assert code == "ALL_CONDITIONS_SATISFIED"
        return
    result = evaluate(parsed, EVALUATED_AT)
    from _verdict_builder import OUTPUT_VALIDATOR

    assert not list(OUTPUT_VALIDATOR.iter_errors(result)), code
    assert result["verdict"] == ("INCONCLUSIVE" if started else "BLOCKED")
