"""Pure verdict engine (PP-004): `evaluate(VerdictInput, evaluated_at) -> verdict record`.

Implements docs/architecture/verdict-specification.md (accepted in PP-002) literally:
input validation M1-M7 / G1-G5 (section 5.2), execution trust E1-E4 (4.2), cell trust
T1-T5 (4.3), independent flags (7), reason codes / details / counts (8), and the
decision table V-01..V-10 (6), with owner decisions D1-D6.

The engine performs no I/O, reads no clock (the caller supplies `evaluated_at`), never
mutates its input, and has no input through which target output could reach it (INV-09).

Governing invariant: trustworthy evidence of a remaining vulnerability is preserved, and
missing, incomplete, inconsistent, or untrusted evidence never yields VERIFIED_FOR_CASES.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Final

from .verdict_input import (
    PRECONDITION_NAMES,
    REASON_CODES,
    SIDES,
    Execution,
    Observation,
    VerdictInput,
)

ENGINE_VERSION: Final = "0.0.0"
SCHEMA_VERSION: Final = "1.0"
TIMESTAMP_RE: Final = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z$")

DISPLAY_LABELS: Final = {
    "VERIFIED_FOR_CASES": "Verified for the selected cases",
    "NOT_FIXED": "Not fixed",
    "REGRESSION_DETECTED": "Regression detected",
    "NOT_REPRODUCED": "Not reproduced",
    "INCONCLUSIVE": "Inconclusive",
    "BLOCKED": "Blocked",
}
FLAG_NAMES: Final = ("incomplete_checks", "candidate_violation", "functional_regression", "harness_drift",
                     "flaky_observations", "baseline_not_reproduced", "baseline_control_failed")
_REASON_RANK: Final = {code: i for i, code in enumerate(REASON_CODES)}
_SIDE_RANK: Final = {None: 0, "baseline": 1, "candidate": 2}
GLOBAL_STREAM_REASONS: Final = {"MALFORMED": "EVENT_STREAM_MALFORMED",
                                 "IDENTITY_MISMATCH": "EVENT_STREAM_IDENTITY_MISMATCH"}
# Lifecycle outcomes whose report sequence contains a failed report (G4).
FAILED_REPORT_LIFECYCLES: Final = frozenset({"SETUP_ERROR", "CALL_ERROR", "TEARDOWN_ERROR", "TIMED_OUT"})
TRUSTED_SEMANTICS: Final = {"security": frozenset({"VIOLATION_CONFIRMED", "SECURE"}),
                            "functional": frozenset({"PASS", "FAIL"})}

Detail = tuple[str, int | None, str | None, str | None]  # (reason_code, pair, side, test_id)
CellKey = tuple[int, str, str]  # (pair, side, test_id)


class EvaluationError(ValueError):
    """The caller supplied an invalid evaluation argument (not an evidence problem)."""


@dataclass(frozen=True)
class _Validation:
    failed: bool
    reasons: frozenset[str]
    details: frozenset[Detail]


# --- section 5.2: input validation (fail closed, never normalize) -------------------------


def _validate(inp: VerdictInput, execution_started: bool) -> _Validation:
    reasons: set[str] = set()
    details: set[Detail] = set()
    pack = {t.id: t for t in inp.pack_tests}
    pack_ids = [t.id for t in inp.pack_tests]
    total_tests = len(inp.pack_tests)

    def matrix_invalid() -> None:
        reasons.add("OBSERVATION_MATRIX_INVALID")

    def inconsistent() -> None:
        reasons.add("EXECUTION_EVIDENCE_INCONSISTENT")

    # Owner-approved addition (2026-10-12): pack test IDs must be unique and are never
    # deduplicated. Node IDs are held to the same rule, since two IDs naming one pytest
    # test would make its evidence ambiguous.
    if len(set(pack_ids)) != len(pack_ids) or len({t.nodeid for t in inp.pack_tests}) != total_tests:
        matrix_invalid()
    # M1
    if any(e.run_id != inp.run_id for e in inp.executions) or any(o.run_id != inp.run_id for o in inp.observations):
        matrix_invalid()
    # M2
    for o in inp.observations:
        test = pack.get(o.test_id)
        if test is None or test.kind != o.kind or test.nodeid != o.nodeid:
            matrix_invalid()
    # M3
    if any(e.pair > inp.pairs_planned for e in inp.executions) or \
            any(o.pair > inp.pairs_planned for o in inp.observations):
        matrix_invalid()
    # M4 and M5: counted, never collapsed by dictionary assignment.
    observation_keys = Counter(o.key for o in inp.observations)
    execution_keys = Counter(e.key for e in inp.executions)
    if any(n > 1 for n in observation_keys.values()) or any(n > 1 for n in execution_keys.values()):
        matrix_invalid()
    executions_by_key: dict[tuple[int, str], list[Execution]] = {}
    for e in inp.executions:
        executions_by_key.setdefault(e.key, []).append(e)
    # M6
    for o in inp.observations:
        owners = executions_by_key.get((o.pair, o.side), [])
        if len(owners) != 1 or not owners[0].started or owners[0].stream.status != o.stream_status:
            matrix_invalid()
    # M7
    for e in inp.executions:
        if e.stream.status == "COMPLETE":
            for test_id in pack_ids:
                if observation_keys[(e.pair, e.side, test_id)] == 0:
                    matrix_invalid()
    for e in inp.executions:
        # G1: malformed or identity-mismatched streams are global provenance failures.
        if e.stream.status in GLOBAL_STREAM_REASONS:
            code = GLOBAL_STREAM_REASONS[e.stream.status]
            reasons.add(code)
            details.add((code, e.pair, e.side, None))
        # G2
        if e.stream.status != "ABSENT" and e.verifier.termination == "NOT_STARTED":
            inconsistent()
        if e.stream.status == "COMPLETE":
            # G3
            if e.verifier.termination == "EXITED" and e.verifier.exit_code in (0, 1):
                if (e.verifier.exit_code == 1) != (e.stream.failed_reports > 0):
                    inconsistent()
            # G4
            implied = sum(1 for o in inp.observations
                          if (o.pair, o.side) == e.key and _implies_failed_report(o))
            if not implied <= e.stream.failed_reports <= 2 * total_tests:
                inconsistent()
    # G5 (and its converse): detection phase must agree with whether execution started.
    for name in PRECONDITION_NAMES:
        precondition = inp.precondition(name)
        failed_phase = precondition.detected_phase if precondition.state == "FAILED" else None
        if failed_phase == "pre_execution" and execution_started:
            inconsistent()
        # Owner-approved addition (2026-10-12): a failure "detected after execution
        # began" in a run that never started is contradictory evidence.
        if failed_phase == "post_execution" and not execution_started:
            inconsistent()
    return _Validation(failed=bool(reasons), reasons=frozenset(reasons), details=frozenset(details))


def _implies_failed_report(o: Observation) -> bool:
    if o.lifecycle_outcome in FAILED_REPORT_LIFECYCLES:
        return True
    return o.lifecycle_outcome == "COMPLETED" and o.semantic_outcome in ("FAIL", "VIOLATION_CONFIRMED")


# --- section 4: trust ----------------------------------------------------------------------


def _over_cap(e: Execution, cap: int) -> bool:
    """D6: the engine enforces the cap from the host-observed byte count itself."""
    return e.stream.status == "OVER_CAP" or e.stream.bytes_received > cap


def _execution_trusted(e: Execution, cap: int) -> bool:
    e1 = e.started and e.target.readiness == "READY"
    e2 = e.verifier.termination == "EXITED" and e.verifier.exit_code in (0, 1)
    e3 = not (e.verifier.oom_killed or e.target.oom_killed or e.target.exited_during_tests
              or e.deadline_exceeded or e.canceled or e.runtime_errors)
    e4 = e.stream.status == "COMPLETE" and e.stream.bytes_received <= cap
    return e1 and e2 and e3 and e4


def _cell_semantic_if_trusted(o: Observation) -> str | None:
    """T3-T5 for one observation (T1/T2 are applied by the caller)."""
    if o.lifecycle_outcome != "COMPLETED" or o.harness_errors:
        return None
    return o.semantic_outcome if o.semantic_outcome in TRUSTED_SEMANTICS[o.kind] else None


# --- section 8: execution-scoped reasons -------------------------------------------------


def _execution_reasons(e: Execution, cap: int) -> set[str]:
    codes: set[str] = set()
    if e.target.readiness in ("STARTUP_FAILED", "READINESS_TIMEOUT"):
        codes.add("TARGET_STARTUP_FAILED")
    if e.deadline_exceeded:
        codes.add("EXECUTION_TIMED_OUT")
    oom = e.verifier.oom_killed or e.target.oom_killed
    if oom:
        codes.add("EXECUTION_OOM_KILLED")
    if e.target.exited_during_tests:
        codes.add("TARGET_EXITED_DURING_TESTS")
    if e.runtime_errors:
        codes.add("RUNTIME_ERROR")
    if e.canceled:
        codes.add("EXECUTION_CANCELED")
    over = _over_cap(e, cap)
    if over:
        codes.add("RESULT_CAP_EXCEEDED")
    abnormal = (e.verifier.termination in ("SIGNALED", "NOT_OBSERVED")
                or (e.verifier.termination == "EXITED" and e.verifier.exit_code not in (0, 1)))
    if abnormal and not (e.deadline_exceeded or oom or e.canceled or over):
        codes.add("VERIFIER_TERMINATED_ABNORMALLY")
    if e.target.readiness == "READY" and e.stream.status in ("TRUNCATED", "ABSENT"):
        codes.add("EVENT_STREAM_TRUNCATED")
    return codes


# --- evaluation ----------------------------------------------------------------------------


def evaluate(inp: VerdictInput, evaluated_at: str) -> dict[str, Any]:
    """Evaluate one run. Deterministic for a given input and timestamp; never mutates `inp`."""
    if not isinstance(evaluated_at, str) or not TIMESTAMP_RE.fullmatch(evaluated_at):
        raise EvaluationError("evaluated_at must be an RFC 3339 UTC timestamp ending in Z")
    cap = inp.result_cap_bytes
    pairs = range(1, inp.pairs_planned + 1)
    tests = inp.pack_tests
    pack = {t.id: t for t in tests}
    required: list[CellKey] = [(p, side, t.id) for p in pairs for side in SIDES for t in tests]

    execution_started = any(e.started for e in inp.executions) or bool(inp.observations)
    validation = _validate(inp, execution_started)

    # Effective preconditions: validation failure forces result_provenance FAILED (5.2).
    effective = {name: inp.precondition(name).state for name in PRECONDITION_NAMES}
    if validation.failed:
        effective["result_provenance"] = "FAILED"
    all_passed = all(state == "PASSED" for state in effective.values())

    # Execution trust (E1-E4) per unique (pair, side); duplicated keys are never trusted.
    execution_count = Counter(e.key for e in inp.executions)
    trusted_execution_keys = {e.key for e in inp.executions
                              if execution_count[e.key] == 1 and _execution_trusted(e, cap)}

    # Cell trust (T1-T5). T1 failing means no cell is trusted; when T1 holds, validation
    # passed, so every key occurs at most once and no record can be overwritten.
    trusted: dict[CellKey, str] = {}
    if all_passed:
        for o in inp.observations:
            if (o.pair, o.side) in trusted_execution_keys:
                semantic = _cell_semantic_if_trusted(o)
                if semantic is not None:
                    trusted[o.key] = semantic

    def cell(pair: int, side: str, test_id: str) -> str | None:
        return trusted.get((pair, side, test_id))

    # --- section 7: flags, each computed independently ---------------------------------
    security = [t for t in tests if t.kind == "security"]
    functional = [t for t in tests if t.kind == "functional"]
    expected_violation = [t for t in security if t.baseline_expected == "VIOLATION_CONFIRMED"]

    candidate_violations = [(p, t.id) for p in pairs for t in security
                            if cell(p, "candidate", t.id) == "VIOLATION_CONFIRMED"]
    regressions = [(p, t.id) for p in pairs for t in functional
                   if cell(p, "candidate", t.id) == "FAIL" and cell(p, "baseline", t.id) == "PASS"]
    flaky = sorted((side, t.id) for side in SIDES for t in tests
                   if len({cell(p, side, t.id) for p in pairs} - {None}) > 1)
    not_reproduced_cells = [(p, t.id) for p in pairs for t in expected_violation
                            if cell(p, "baseline", t.id) == "SECURE"]
    baseline_functional_failures = [(p, t.id) for p in pairs for t in functional if cell(p, "baseline", t.id) == "FAIL"]
    baseline_security_unexpected = [(p, t.id) for p in pairs for t in security
                                    if t.baseline_expected == "SECURE"
                                    and cell(p, "baseline", t.id) == "VIOLATION_CONFIRMED"]
    untrusted_required = [k for k in required if k not in trusted]
    post_execution_drift = any(
        inp.precondition(name).state == "FAILED" and inp.precondition(name).detected_phase == "post_execution"
        for name in ("environment_identity", "pack_integrity"))

    flags = {
        "incomplete_checks": bool(untrusted_required) or inp.run_termination != "normal",
        "candidate_violation": bool(candidate_violations),
        "functional_regression": bool(regressions),
        "harness_drift": post_execution_drift or any(o.harness_errors for o in inp.observations),
        "flaky_observations": bool(flaky),
        "baseline_not_reproduced": bool(not_reproduced_cells),
        "baseline_control_failed": bool(baseline_functional_failures or baseline_security_unexpected),
    }

    # --- section 8: counts ---------------------------------------------------------------
    pairs_terminated_normally = sum(1 for p in pairs if (p, "baseline") in trusted_execution_keys
                                    and (p, "candidate") in trusted_execution_keys)
    pairs_with_trusted_evidence = sum(1 for p in pairs
                                      if all((p, side, t.id) in trusted for side in SIDES for t in tests))

    # --- section 8: reason codes and details ---------------------------------------------
    reasons: set[str] = set(validation.reasons)
    details: set[Detail] = set(validation.details)

    def add(code: str, entries: Iterable[Detail] = ()) -> None:
        reasons.add(code)
        details.update(entries)

    for name in PRECONDITION_NAMES:
        precondition = inp.precondition(name)
        if precondition.state == "FAILED":
            reasons.update(precondition.reason_codes)
    # Section 5.4: an unevaluated precondition always adds this code, even when failed
    # input validation turned the effective result_provenance into FAILED (section 8).
    if any(state == "NOT_EVALUATED" for state in effective.values()) or any(
            inp.precondition(name).state == "NOT_EVALUATED" for name in PRECONDITION_NAMES):
        add("PRECONDITION_NOT_EVALUATED")
    if inp.run_termination == "canceled":
        add("RUN_CANCELED")
    if inp.run_termination == "interrupted":
        add("RUN_INTERRUPTED")
    if execution_started and pairs_terminated_normally < inp.pairs_planned:
        add("REPETITION_INCOMPLETE")
    for e in inp.executions:
        for code in _execution_reasons(e, cap):
            add(code, [(code, e.pair, e.side, None)])
    if execution_started and untrusted_required:
        add("REQUIRED_CHECK_INCOMPLETE", [("REQUIRED_CHECK_INCOMPLETE", *k) for k in untrusted_required])
    for o in inp.observations:
        if o.semantic_outcome == "INCONCLUSIVE":
            add("CHECK_INCONCLUSIVE", [("CHECK_INCONCLUSIVE", *o.key)])
        if o.harness_errors:
            add("HARNESS_ERROR", [("HARNESS_ERROR", *o.key)])
    for p, test_id in candidate_violations:
        add("CANDIDATE_VIOLATION_CONFIRMED", [("CANDIDATE_VIOLATION_CONFIRMED", p, "candidate", test_id)])
        if cell(p, "baseline", test_id) == "SECURE":
            add("NEW_SECURITY_VIOLATION", [("NEW_SECURITY_VIOLATION", p, "candidate", test_id)])
    for p, test_id in regressions:
        add("FUNCTIONAL_REGRESSION", [("FUNCTIONAL_REGRESSION", p, "candidate", test_id)])
    for side, test_id in flaky:
        add("INCONSISTENT_REPETITIONS", [("INCONSISTENT_REPETITIONS", None, side, test_id)])
    for p, test_id in baseline_functional_failures:
        add("BASELINE_CONTROL_FAILED", [("BASELINE_CONTROL_FAILED", p, "baseline", test_id)])
    for p, test_id in baseline_security_unexpected:
        add("BASELINE_SECURITY_UNEXPECTED", [("BASELINE_SECURITY_UNEXPECTED", p, "baseline", test_id)])
    # D4: classify each expected-violation test from its trusted baseline cells.
    not_reproduced_tests = sorted({test_id for _, test_id in not_reproduced_cells})
    reproduced_tests = [t.id for t in expected_violation if t.id not in not_reproduced_tests
                        and any(cell(p, "baseline", t.id) == "VIOLATION_CONFIRMED" for p in pairs)]
    if not_reproduced_tests:
        code = "BASELINE_PARTIALLY_REPRODUCED" if reproduced_tests else "BASELINE_NOT_REPRODUCED"
        add(code, [(code, None, "baseline", test_id) for test_id in not_reproduced_tests])

    # --- section 6: decision table (first match wins) ------------------------------------
    any_flag = any(flags.values())
    exact_agreement = len(trusted) == len(required) and all(
        trusted.get(k) == pack[k[2]].expected(k[1]) for k in required)
    if not execution_started and not validation.failed and not all_passed:
        verdict, rule = "BLOCKED", "V-01"
    elif not all_passed:
        verdict, rule = "INCONCLUSIVE", "V-02"
    elif flags["candidate_violation"]:
        verdict, rule = "NOT_FIXED", "V-03"
    elif flags["functional_regression"]:
        verdict, rule = "REGRESSION_DETECTED", "V-04"
    elif flags["incomplete_checks"]:
        verdict, rule = "INCONCLUSIVE", "V-05"
    elif flags["flaky_observations"]:
        verdict, rule = "INCONCLUSIVE", "V-06"
    elif flags["baseline_control_failed"]:
        verdict, rule = "INCONCLUSIVE", "V-07"
    elif flags["baseline_not_reproduced"]:
        verdict, rule = "NOT_REPRODUCED", "V-08"
    elif (execution_started and inp.run_termination == "normal"
          and pairs_terminated_normally == pairs_with_trusted_evidence == inp.pairs_planned
          and exact_agreement and not any_flag and not reasons):
        # The empty-reasons guard is implied by the conditions above; it is checked
        # explicitly so a verified record can never carry an unexplained reason.
        verdict, rule = "VERIFIED_FOR_CASES", "V-09"
        reasons = {"ALL_CONDITIONS_SATISFIED"}
    else:
        verdict, rule = "INCONCLUSIVE", "V-10"
        add("UNCLASSIFIED_EVIDENCE")

    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": inp.run_id,
        "engine_version": ENGINE_VERSION,
        "verdict": verdict,
        "display_label": DISPLAY_LABELS[verdict],
        "decision_rule": rule,
        "execution_started": execution_started,
        "run_termination": inp.run_termination,
        "reason_codes": sorted(reasons, key=_REASON_RANK.__getitem__),
        "details": [
            {"reason_code": code, "pair": pair, "side": side, "test_id": test_id}
            for code, pair, side, test_id in sorted(details, key=_detail_sort_key)
        ],
        "flags": {name: flags[name] for name in FLAG_NAMES},
        "preconditions": {name: effective[name] for name in PRECONDITION_NAMES},
        "counts": {
            "security_tests": len(security),
            "functional_tests": len(functional),
            "pairs_planned": inp.pairs_planned,
            "pairs_terminated_normally": pairs_terminated_normally,
            "pairs_with_trusted_evidence": pairs_with_trusted_evidence,
            "required_cells": len(required),
            "trusted_cells": len(trusted),
        },
        "evaluated_at": evaluated_at,
    }


def _detail_sort_key(d: Detail) -> tuple[int, int, int, str]:
    code, pair, side, test_id = d
    return (_REASON_RANK[code], 0 if pair is None else pair, _SIDE_RANK[side], test_id or "")
