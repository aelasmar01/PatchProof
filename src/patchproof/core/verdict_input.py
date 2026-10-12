"""Strictly typed verdict-engine input (schemas/verdict-input.schema.json 1.0).

`parse_verdict_input` converts already-loaded JSON data into frozen records and refuses
anything outside the contract's shape: unknown or missing fields, wrong types, values
outside an enumeration, or an inconsistent precondition. A shape error raises
`VerdictInputError`; the engine never evaluates malformed input.

Semantic matrix and consistency problems (verdict specification section 5.2: duplicates,
unknown tests, pair limits, contradictory execution facts) are deliberately NOT rejected
here. They are valid shapes that the engine must detect itself and turn into a V-02
`INCONCLUSIVE` verdict, so this parser preserves every record, including duplicates.

Full JSON Schema validation, the strict duplicate-key loader, and pack-level checks
belong to the caller (PP-007). Target output has no representable field (INV-09).
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

PRECONDITION_NAMES: Final = ("authorization", "pack_integrity", "source_identity", "environment_identity",
                             "result_provenance")
SIDES: Final = ("baseline", "candidate")
TERMINATIONS: Final = ("normal", "canceled", "interrupted")
PRECONDITION_STATES: Final = ("PASSED", "FAILED", "NOT_EVALUATED")
PHASES: Final = ("pre_execution", "post_execution")
TEST_KINDS: Final = ("security", "functional")
BASELINE_EXPECTATIONS: Final = ("VIOLATION_CONFIRMED", "SECURE", "PASS")
CANDIDATE_EXPECTATIONS: Final = ("SECURE", "PASS")
READINESS: Final = ("READY", "STARTUP_FAILED", "READINESS_TIMEOUT", "NOT_STARTED")
VERIFIER_TERMINATIONS: Final = ("EXITED", "SIGNALED", "NOT_STARTED", "NOT_OBSERVED")
RUNTIME_ERRORS: Final = ("CONTAINER_CREATE_FAILED", "CONTAINER_START_FAILED", "ATTACH_FAILED", "INSPECT_FAILED")
STREAM_STATUSES: Final = ("COMPLETE", "TRUNCATED", "MALFORMED", "IDENTITY_MISMATCH", "OVER_CAP", "ABSENT")
LIFECYCLE_OUTCOMES: Final = ("COMPLETED", "SETUP_ERROR", "CALL_ERROR", "TEARDOWN_ERROR", "SKIPPED", "XFAILED",
                             "XPASSED", "TIMED_OUT", "INTERRUPTED", "NOT_RUN", "NOT_COLLECTED")
SEMANTIC_OUTCOMES: Final = ("VIOLATION_CONFIRMED", "SECURE", "INCONCLUSIVE", "PASS", "FAIL", "NONE")
HARNESS_ERRORS: Final = ("MISSING_TERMINAL_OBSERVATION", "MULTIPLE_TERMINAL_OBSERVATIONS",
                         "SUPPRESSED_TERMINAL_EXCEPTION", "MALFORMED_EVIDENCE", "ERROR_AFTER_OBSERVATION",
                         "OBSERVATION_ON_FUNCTIONAL_TEST", "GENERIC_FAILURE_IN_SECURITY_TEST")

# Canonical reason order: common.schema.json $defs.reasonCode (verdict specification section 8).
REASON_CODES: Final = (
    "ALL_CONDITIONS_SATISFIED", "APPROVAL_MISSING", "APPROVAL_STALE", "PACK_INTEGRITY_FAILED",
    "PACK_INCOMPLETE_FOR_FIX_VERIFICATION", "PACK_COLLECTION_MISMATCH", "UNSUPPORTED_TARGET_PROFILE",
    "RUNTIME_POLICY_FAILED", "ENVIRONMENT_NONCOMPARABLE", "SOURCE_IDENTITY_MISMATCH", "EVENT_STREAM_MALFORMED",
    "EVENT_STREAM_IDENTITY_MISMATCH", "EVIDENCE_INCOMPLETE", "PRECONDITION_NOT_EVALUATED",
    "OBSERVATION_MATRIX_INVALID", "EXECUTION_EVIDENCE_INCONSISTENT", "RUN_CANCELED", "RUN_INTERRUPTED",
    "TARGET_STARTUP_FAILED", "EXECUTION_TIMED_OUT", "EXECUTION_OOM_KILLED", "TARGET_EXITED_DURING_TESTS",
    "VERIFIER_TERMINATED_ABNORMALLY", "RUNTIME_ERROR", "EXECUTION_CANCELED", "RESULT_CAP_EXCEEDED",
    "EVENT_STREAM_TRUNCATED", "REPETITION_INCOMPLETE", "REQUIRED_CHECK_INCOMPLETE", "CHECK_INCONCLUSIVE",
    "HARNESS_ERROR", "CANDIDATE_VIOLATION_CONFIRMED", "NEW_SECURITY_VIOLATION", "FUNCTIONAL_REGRESSION",
    "INCONSISTENT_REPETITIONS", "BASELINE_CONTROL_FAILED", "BASELINE_SECURITY_UNEXPECTED",
    "BASELINE_NOT_REPRODUCED", "BASELINE_PARTIALLY_REPRODUCED", "UNCLASSIFIED_EVIDENCE",
)

RUN_ID_RE: Final = re.compile(r"^run-[0-9a-f]{32}$")
TEST_ID_RE: Final = re.compile(r"^[A-Z][A-Z0-9]{1,15}-[0-9]{3}$")
SHA256_RE: Final = re.compile(r"^sha256:[0-9a-f]{64}$")
ARTIFACT_RE: Final = re.compile(r"^art-[0-9a-f]{32}$")
MAX_PAIRS: Final = 10


class VerdictInputError(ValueError):
    """The input does not have the verdict-input contract's shape. Nothing is evaluated."""


@dataclass(frozen=True)
class PackTest:
    id: str
    nodeid: str
    kind: str
    baseline_expected: str
    candidate_expected: str

    def expected(self, side: str) -> str:
        return self.baseline_expected if side == "baseline" else self.candidate_expected


@dataclass(frozen=True)
class Precondition:
    state: str
    detected_phase: str | None
    reason_codes: tuple[str, ...]


@dataclass(frozen=True)
class TargetFacts:
    readiness: str
    oom_killed: bool
    exited_during_tests: bool


@dataclass(frozen=True)
class VerifierFacts:
    termination: str
    exit_code: int | None
    signal: int | None
    oom_killed: bool


@dataclass(frozen=True)
class StreamFacts:
    status: str
    session_end_received: bool
    events_received: int
    bytes_received: int
    failed_reports: int


@dataclass(frozen=True)
class Execution:
    run_id: str
    pair: int
    side: str
    started: bool
    target: TargetFacts
    verifier: VerifierFacts
    deadline_exceeded: bool
    canceled: bool
    runtime_errors: tuple[str, ...]
    stream: StreamFacts

    @property
    def key(self) -> tuple[int, str]:
        return (self.pair, self.side)


@dataclass(frozen=True)
class Observation:
    run_id: str
    pair: int
    side: str
    test_id: str
    nodeid: str
    kind: str
    stream_status: str
    lifecycle_outcome: str
    semantic_outcome: str
    harness_errors: tuple[str, ...]
    evidence_refs: tuple[tuple[str, str], ...]

    @property
    def key(self) -> tuple[int, str, str]:
        return (self.pair, self.side, self.test_id)


@dataclass(frozen=True)
class VerdictInput:
    run_id: str
    pack_tests: tuple[PackTest, ...]
    pairs_planned: int
    result_cap_bytes: int
    preconditions: tuple[tuple[str, Precondition], ...]  # fixed PRECONDITION_NAMES order
    run_termination: str
    executions: tuple[Execution, ...]
    observations: tuple[Observation, ...]

    def precondition(self, name: str) -> Precondition:
        return dict(self.preconditions)[name]


# --- strict field helpers -----------------------------------------------------------------


def _object(value: Any, where: str, keys: Sequence[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise VerdictInputError(f"{where}: expected an object")
    missing = sorted(set(keys) - set(value))
    unknown = sorted(set(value) - set(keys))
    if missing or unknown:
        raise VerdictInputError(f"{where}: missing {missing}, unknown {unknown}")
    return value


def _enum(value: Any, allowed: Sequence[str | None], where: str) -> Any:
    if value not in allowed or isinstance(value, bool):
        raise VerdictInputError(f"{where}: {value!r} not in {list(allowed)}")
    return value


def _bool(value: Any, where: str) -> bool:
    if type(value) is not bool:
        raise VerdictInputError(f"{where}: expected a boolean")
    return value


def _int(value: Any, where: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise VerdictInputError(f"{where}: expected an integer in [{low}, {high}]")
    return value


def _str(value: Any, where: str, pattern: re.Pattern[str] | None = None, max_len: int = 255) -> str:
    if not isinstance(value, str) or not value or len(value) > max_len or (pattern and not pattern.fullmatch(value)):
        raise VerdictInputError(f"{where}: invalid string")
    return value


def _list(value: Any, where: str, max_items: int) -> list[Any]:
    if not isinstance(value, list) or len(value) > max_items:
        raise VerdictInputError(f"{where}: expected a list of at most {max_items} items")
    return value


def _schema_version(value: Any, where: str) -> None:
    if value != "1.0":
        raise VerdictInputError(f"{where}: unsupported schema_version {value!r}")


# --- record parsers ---------------------------------------------------------------------


def _pack_test(value: Any, where: str) -> PackTest:
    v = _object(value, where, ("id", "nodeid", "kind", "baseline_expected", "candidate_expected"))
    test = PackTest(
        id=_str(v["id"], f"{where}.id", TEST_ID_RE),
        nodeid=_str(v["nodeid"], f"{where}.nodeid"),
        kind=_enum(v["kind"], TEST_KINDS, f"{where}.kind"),
        baseline_expected=_enum(v["baseline_expected"], BASELINE_EXPECTATIONS, f"{where}.baseline_expected"),
        candidate_expected=_enum(v["candidate_expected"], CANDIDATE_EXPECTATIONS, f"{where}.candidate_expected"),
    )
    valid = (test.baseline_expected in ("VIOLATION_CONFIRMED", "SECURE") and test.candidate_expected == "SECURE"
             if test.kind == "security" else test.baseline_expected == test.candidate_expected == "PASS")
    if not valid:
        raise VerdictInputError(f"{where}: expectations are invalid for a {test.kind} test")
    return test


def _precondition(value: Any, where: str) -> Precondition:
    v = _object(value, where, ("state", "detected_phase", "reason_codes"))
    state = _enum(v["state"], PRECONDITION_STATES, f"{where}.state")
    phase = _enum(v["detected_phase"], (None, *PHASES), f"{where}.detected_phase")
    codes = _list(v["reason_codes"], f"{where}.reason_codes", 8)
    for code in codes:
        _enum(code, REASON_CODES, f"{where}.reason_codes")
    if len(set(codes)) != len(codes):
        raise VerdictInputError(f"{where}.reason_codes: duplicate code")
    if state == "FAILED" and (phase is None or not codes):
        raise VerdictInputError(f"{where}: a FAILED precondition needs detected_phase and reason codes")
    if state != "FAILED" and (phase is not None or codes):
        raise VerdictInputError(f"{where}: only a FAILED precondition carries a phase or reason codes")
    # Spec section 8: ALL_CONDITIONS_SATISFIED exists only on a V-09 verdict, as its only
    # code. A failed precondition claiming it is contradictory input, refused rather than
    # dropped (it would otherwise surface on a BLOCKED or INCONCLUSIVE record).
    if "ALL_CONDITIONS_SATISFIED" in codes:
        raise VerdictInputError(f"{where}: a failed precondition cannot report ALL_CONDITIONS_SATISFIED")
    return Precondition(state, phase, tuple(codes))


def _execution(value: Any, where: str) -> Execution:
    v = _object(value, where, ("schema_version", "run_id", "pair", "side", "started", "target", "verifier",
                               "deadline_exceeded", "canceled", "runtime_errors", "stream"))
    _schema_version(v["schema_version"], f"{where}.schema_version")
    t = _object(v["target"], f"{where}.target", ("readiness", "oom_killed", "exited_during_tests"))
    w = _object(v["verifier"], f"{where}.verifier", ("termination", "exit_code", "signal", "oom_killed"))
    s = _object(v["stream"], f"{where}.stream",
                ("status", "session_end_received", "events_received", "bytes_received", "failed_reports"))
    termination = _enum(w["termination"], VERIFIER_TERMINATIONS, f"{where}.verifier.termination")
    exit_code = None if w["exit_code"] is None else _int(w["exit_code"], f"{where}.verifier.exit_code", 0, 255)
    signal = None if w["signal"] is None else _int(w["signal"], f"{where}.verifier.signal", 1, 64)
    if (termination == "EXITED") != (exit_code is not None) or (termination == "SIGNALED") != (signal is not None):
        raise VerdictInputError(f"{where}.verifier: exit_code/signal inconsistent with termination")
    errors = _list(v["runtime_errors"], f"{where}.runtime_errors", 8)
    for error in errors:
        _enum(error, RUNTIME_ERRORS, f"{where}.runtime_errors")
    return Execution(
        run_id=_str(v["run_id"], f"{where}.run_id", RUN_ID_RE),
        pair=_int(v["pair"], f"{where}.pair", 1, MAX_PAIRS),
        side=_enum(v["side"], SIDES, f"{where}.side"),
        started=_bool(v["started"], f"{where}.started"),
        target=TargetFacts(
            readiness=_enum(t["readiness"], READINESS, f"{where}.target.readiness"),
            oom_killed=_bool(t["oom_killed"], f"{where}.target.oom_killed"),
            exited_during_tests=_bool(t["exited_during_tests"], f"{where}.target.exited_during_tests"),
        ),
        verifier=VerifierFacts(termination, exit_code, signal, _bool(w["oom_killed"], f"{where}.verifier.oom_killed")),
        deadline_exceeded=_bool(v["deadline_exceeded"], f"{where}.deadline_exceeded"),
        canceled=_bool(v["canceled"], f"{where}.canceled"),
        runtime_errors=tuple(errors),
        stream=StreamFacts(
            status=_enum(s["status"], STREAM_STATUSES, f"{where}.stream.status"),
            session_end_received=_bool(s["session_end_received"], f"{where}.stream.session_end_received"),
            events_received=_int(s["events_received"], f"{where}.stream.events_received", 0, 100001),
            bytes_received=_int(s["bytes_received"], f"{where}.stream.bytes_received", 0, 52428801),
            failed_reports=_int(s["failed_reports"], f"{where}.stream.failed_reports", 0, 400),
        ),
    )


def _observation(value: Any, where: str) -> Observation:
    v = _object(value, where, ("schema_version", "run_id", "pair", "side", "test_id", "nodeid", "kind",
                               "stream_status", "lifecycle_outcome", "semantic_outcome", "harness_errors",
                               "evidence_refs", "provenance"))
    _schema_version(v["schema_version"], f"{where}.schema_version")
    if v["provenance"] != "verifier-event-stream":
        raise VerdictInputError(f"{where}.provenance: only verifier-event-stream is a valid source (INV-09)")
    errors = _list(v["harness_errors"], f"{where}.harness_errors", 16)
    for error in errors:
        _enum(error, HARNESS_ERRORS, f"{where}.harness_errors")
    refs = []
    for i, ref in enumerate(_list(v["evidence_refs"], f"{where}.evidence_refs", 16)):
        r = _object(ref, f"{where}.evidence_refs[{i}]", ("artifact_id", "sha256"))
        refs.append((_str(r["artifact_id"], f"{where}.evidence_refs[{i}].artifact_id", ARTIFACT_RE),
                     _str(r["sha256"], f"{where}.evidence_refs[{i}].sha256", SHA256_RE)))
    return Observation(
        run_id=_str(v["run_id"], f"{where}.run_id", RUN_ID_RE),
        pair=_int(v["pair"], f"{where}.pair", 1, MAX_PAIRS),
        side=_enum(v["side"], SIDES, f"{where}.side"),
        test_id=_str(v["test_id"], f"{where}.test_id", TEST_ID_RE),
        nodeid=_str(v["nodeid"], f"{where}.nodeid"),
        kind=_enum(v["kind"], TEST_KINDS, f"{where}.kind"),
        stream_status=_enum(v["stream_status"], STREAM_STATUSES, f"{where}.stream_status"),
        lifecycle_outcome=_enum(v["lifecycle_outcome"], LIFECYCLE_OUTCOMES, f"{where}.lifecycle_outcome"),
        semantic_outcome=_enum(v["semantic_outcome"], SEMANTIC_OUTCOMES, f"{where}.semantic_outcome"),
        harness_errors=tuple(errors),
        evidence_refs=tuple(refs),
    )


def parse_verdict_input(data: Any) -> VerdictInput:
    """Parse loaded JSON into typed records. Raises VerdictInputError on any shape error."""
    v = _object(data, "verdict-input", ("schema_version", "run_id", "pack_tests", "pairs_planned",
                                        "result_cap_bytes", "preconditions", "run_termination", "executions",
                                        "observations"))
    _schema_version(v["schema_version"], "verdict-input.schema_version")
    pack = tuple(_pack_test(t, f"pack_tests[{i}]") for i, t in enumerate(_list(v["pack_tests"], "pack_tests", 200)))
    if len(pack) < 2:
        raise VerdictInputError("pack_tests: at least two required tests")
    pre = _object(v["preconditions"], "preconditions", PRECONDITION_NAMES)
    return VerdictInput(
        run_id=_str(v["run_id"], "run_id", RUN_ID_RE),
        pack_tests=pack,
        pairs_planned=_int(v["pairs_planned"], "pairs_planned", 1, MAX_PAIRS),
        result_cap_bytes=_int(v["result_cap_bytes"], "result_cap_bytes", 65536, 52428800),
        preconditions=tuple((name, _precondition(pre[name], f"preconditions.{name}")) for name in PRECONDITION_NAMES),
        run_termination=_enum(v["run_termination"], TERMINATIONS, "run_termination"),
        executions=tuple(_execution(e, f"executions[{i}]")
                         for i, e in enumerate(_list(v["executions"], "executions", 20))),
        observations=tuple(_observation(o, f"observations[{i}]")
                           for i, o in enumerate(_list(v["observations"], "observations", 4000))),
    )
