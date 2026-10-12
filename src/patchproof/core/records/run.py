"""Run records: verifier events, observations, executions, verdict input and verdict
(schemas verifier-event, observation, execution, verdict-input and verdict, all 1.0)."""

from __future__ import annotations

from typing import Annotated, ClassVar, Literal

from pydantic import AfterValidator, Field, model_validator

from .common import (
    EvidenceRef,
    LongText,
    PairIndex,
    PytestNodeId,
    ReasonCode,
    Record,
    RunId,
    RunTermination,
    SchemaVersion,
    Semver,
    Sha256,
    ShortText,
    Side,
    TestId,
    TestKind,
    Timestamp,
    unique_list,
)
from .pack import CollectedTest, RequiredTest

StreamStatus = Literal["COMPLETE", "TRUNCATED", "MALFORMED", "IDENTITY_MISMATCH", "OVER_CAP", "ABSENT"]
LifecycleOutcome = Literal["COMPLETED", "SETUP_ERROR", "CALL_ERROR", "TEARDOWN_ERROR", "SKIPPED", "XFAILED",
                           "XPASSED", "TIMED_OUT", "INTERRUPTED", "NOT_RUN", "NOT_COLLECTED"]
SemanticOutcome = Literal["VIOLATION_CONFIRMED", "SECURE", "INCONCLUSIVE", "PASS", "FAIL", "NONE"]
HarnessError = Literal["MISSING_TERMINAL_OBSERVATION", "MULTIPLE_TERMINAL_OBSERVATIONS",
                       "SUPPRESSED_TERMINAL_EXCEPTION", "MALFORMED_EVIDENCE", "ERROR_AFTER_OBSERVATION",
                       "OBSERVATION_ON_FUNCTIONAL_TEST", "GENERIC_FAILURE_IN_SECURITY_TEST"]
FailureClass = Literal["none", "assertion", "security_terminal", "helper_misuse", "timeout", "exception"]
EvidenceRefs = Annotated[list[EvidenceRef], Field(max_length=16)]

# ------------------------------------------------------------------ verifier events


class SessionStartPayload(Record):
    verifier_plugin_version: Semver
    pack_tree_sha256: Sha256


class CollectedPayload(Record):
    tests: Annotated[list[CollectedTest], Field(max_length=200)]


class TestReportPayload(Record):
    __test__: ClassVar[bool] = False  # not a pytest test class

    test_id: TestId
    phase: Literal["setup", "call", "teardown"]
    outcome: Literal["passed", "failed", "skipped"]
    failure_class: FailureClass
    xfail: bool

    @model_validator(mode="after")
    def _phase_rules(self) -> TestReportPayload:
        if (self.outcome == "failed") == (self.failure_class == "none"):
            raise ValueError("a failed report needs a failure class; any other outcome must have none")
        if self.phase != "call" and self.failure_class == "security_terminal":
            raise ValueError("the security helper's exception can only end the call phase")
        if self.phase == "teardown" and self.outcome == "skipped":
            raise ValueError("teardown is never skipped")
        return self


class ObservationPayload(Record):
    test_id: TestId
    outcome: Literal["VIOLATION_CONFIRMED", "SECURE", "INCONCLUSIVE"]
    summary: LongText
    evidence_refs: EvidenceRefs


class SessionEndPayload(Record):
    tests_reported: Annotated[int, Field(ge=0, le=200)]
    observations_emitted: Annotated[int, Field(ge=0, le=200)]


EventType = Literal["session_start", "collected", "test_report", "observation", "session_end"]
_PAYLOADS: dict[str, type[Record]] = {
    "session_start": SessionStartPayload, "collected": CollectedPayload, "test_report": TestReportPayload,
    "observation": ObservationPayload, "session_end": SessionEndPayload,
}


class VerifierEvent(Record):
    schema_version: SchemaVersion
    run_id: RunId
    pair: PairIndex
    side: Side
    seq: Annotated[int, Field(ge=0, le=100000)]
    type: EventType
    payload: SessionStartPayload | CollectedPayload | TestReportPayload | ObservationPayload | SessionEndPayload

    @model_validator(mode="before")
    @classmethod
    def _payload_for_type(cls, data: object) -> object:
        # Validate the payload against the model its event type names, never against whichever
        # union member happens to fit.
        if isinstance(data, dict) and isinstance(data.get("type"), str) and data["type"] in _PAYLOADS:
            payload = data.get("payload")
            if isinstance(payload, dict):
                return {**data, "payload": _PAYLOADS[data["type"]].model_validate(payload)}
        return data

    @model_validator(mode="after")
    def _payload_matches_type(self) -> VerifierEvent:
        if type(self.payload) is not _PAYLOADS[self.type]:
            raise ValueError("payload does not match the event type")
        return self


# ------------------------------------------------------------------ observations


class Observation(Record):
    schema_version: SchemaVersion
    run_id: RunId
    pair: PairIndex
    side: Side
    test_id: TestId
    nodeid: PytestNodeId
    kind: TestKind
    stream_status: StreamStatus
    lifecycle_outcome: LifecycleOutcome
    semantic_outcome: SemanticOutcome
    harness_errors: Annotated[list[HarnessError], Field(max_length=16), AfterValidator(unique_list("harness_errors"))]
    evidence_refs: EvidenceRefs
    provenance: Literal["verifier-event-stream"]

    @model_validator(mode="after")
    def _consistent(self) -> Observation:
        semantic, lifecycle = self.semantic_outcome, self.lifecycle_outcome
        if self.kind == "security" and semantic in ("PASS", "FAIL"):
            raise ValueError("a security check has no PASS/FAIL outcome")
        if self.kind == "functional":
            if semantic not in ("PASS", "FAIL", "NONE"):
                raise ValueError("a functional control has only PASS, FAIL or NONE")
            if lifecycle != "COMPLETED" and semantic != "NONE":
                raise ValueError("a functional result needs a completed lifecycle")
        if lifecycle in ("SETUP_ERROR", "NOT_RUN", "NOT_COLLECTED") and semantic != "NONE":
            raise ValueError("no call phase ran, so no result can exist")
        if self.stream_status == "COMPLETE" and lifecycle in ("INTERRUPTED", "NOT_RUN", "NOT_COLLECTED"):
            raise ValueError("a complete stream reports every collected test")
        if self.stream_status == "ABSENT" and (lifecycle != "NOT_RUN" or semantic != "NONE"):
            raise ValueError("an absent stream produced no reports")
        return self


# ------------------------------------------------------------------ executions


class TargetFacts(Record):
    readiness: Literal["READY", "STARTUP_FAILED", "READINESS_TIMEOUT", "NOT_STARTED"]
    oom_killed: bool
    exited_during_tests: bool


class VerifierFacts(Record):
    termination: Literal["EXITED", "SIGNALED", "NOT_STARTED", "NOT_OBSERVED"]
    exit_code: Annotated[int, Field(ge=0, le=255)] | None
    signal: Annotated[int, Field(ge=1, le=64)] | None
    oom_killed: bool

    @model_validator(mode="after")
    def _termination_facts(self) -> VerifierFacts:
        expected = {"EXITED": (True, False), "SIGNALED": (False, True)}.get(self.termination, (False, False))
        if ((self.exit_code is not None), (self.signal is not None)) != expected:
            raise ValueError("exit_code and signal do not match the termination")
        return self


class StreamFacts(Record):
    status: StreamStatus
    session_end_received: bool
    events_received: Annotated[int, Field(ge=0, le=100001)]
    bytes_received: Annotated[int, Field(ge=0, le=52428801)]
    failed_reports: Annotated[int, Field(ge=0, le=400)]

    @model_validator(mode="after")
    def _status_facts(self) -> StreamFacts:
        if self.status == "COMPLETE" and not self.session_end_received:
            raise ValueError("a complete stream ends with session_end")
        if self.status in ("TRUNCATED", "ABSENT") and self.session_end_received:
            raise ValueError("a truncated or absent stream has no session_end")
        if self.status == "ABSENT" and (self.events_received, self.bytes_received, self.failed_reports) != (0, 0, 0):
            raise ValueError("an absent stream received nothing")
        return self


class Execution(Record):
    schema_version: SchemaVersion
    run_id: RunId
    pair: PairIndex
    side: Side
    started: bool
    target: TargetFacts
    verifier: VerifierFacts
    deadline_exceeded: bool
    canceled: bool
    runtime_errors: Annotated[
        list[Literal["CONTAINER_CREATE_FAILED", "CONTAINER_START_FAILED", "ATTACH_FAILED", "INSPECT_FAILED"]],
        Field(max_length=8), AfterValidator(unique_list("runtime_errors"))]
    stream: StreamFacts

    @model_validator(mode="after")
    def _lifecycle_facts(self) -> Execution:
        if not self.started:
            if (self.target.readiness, self.target.oom_killed, self.target.exited_during_tests) != (
                    "NOT_STARTED", False, False):
                raise ValueError("an execution that never started has no target behavior")
            if self.verifier.termination != "NOT_STARTED" or self.verifier.oom_killed:
                raise ValueError("an execution that never started has no verifier behavior")
            if self.stream.status != "ABSENT":
                raise ValueError("an execution that never started has no stream")
        elif self.target.readiness == "NOT_STARTED":
            raise ValueError("a started execution has a target readiness result")
        if self.target.readiness != "READY" and (
                self.verifier.termination != "NOT_STARTED" or self.stream.status != "ABSENT"):
            raise ValueError("the verifier is not started unless the target became ready")
        return self


# ------------------------------------------------------------------ verdict input


class Precondition(Record):
    state: Literal["PASSED", "FAILED", "NOT_EVALUATED"]
    detected_phase: Literal["pre_execution", "post_execution"] | None
    reason_codes: Annotated[list[ReasonCode], Field(max_length=8), AfterValidator(unique_list("reason_codes"))]

    @model_validator(mode="after")
    def _state_rules(self) -> Precondition:
        if self.state == "FAILED":
            if self.detected_phase is None or not self.reason_codes:
                raise ValueError("a failed precondition records its phase and at least one reason")
        elif self.detected_phase is not None or self.reason_codes:
            raise ValueError("only a failed precondition has a phase and reasons")
        return self


class Preconditions(Record):
    authorization: Precondition
    pack_integrity: Precondition
    source_identity: Precondition
    environment_identity: Precondition
    result_provenance: Precondition


class VerdictInput(Record):
    schema_version: SchemaVersion
    run_id: RunId
    pack_tests: Annotated[list[RequiredTest], Field(min_length=2, max_length=200),
                          AfterValidator(unique_list("pack_tests"))]
    pairs_planned: Annotated[int, Field(ge=1, le=10)]
    result_cap_bytes: Annotated[int, Field(ge=65536, le=52428800)]
    preconditions: Preconditions
    run_termination: RunTermination
    executions: Annotated[list[Execution], Field(max_length=20), AfterValidator(unique_list("executions"))]
    observations: Annotated[list[Observation], Field(max_length=4000), AfterValidator(unique_list("observations"))]


# ------------------------------------------------------------------ verdict

Verdict = Literal["VERIFIED_FOR_CASES", "NOT_FIXED", "REGRESSION_DETECTED", "NOT_REPRODUCED", "INCONCLUSIVE",
                  "BLOCKED"]
CheckState = Literal["PASSED", "FAILED", "NOT_EVALUATED"]


class Detail(Record):
    reason_code: ReasonCode
    pair: PairIndex | None
    side: Side | None
    test_id: TestId | None


class Flags(Record):
    incomplete_checks: bool
    candidate_violation: bool
    functional_regression: bool
    harness_drift: bool
    flaky_observations: bool
    baseline_not_reproduced: bool
    baseline_control_failed: bool


class PreconditionStates(Record):
    authorization: CheckState
    pack_integrity: CheckState
    source_identity: CheckState
    environment_identity: CheckState
    result_provenance: CheckState

    def states(self) -> tuple[CheckState, ...]:
        return (self.authorization, self.pack_integrity, self.source_identity, self.environment_identity,
                self.result_provenance)


class Counts(Record):
    security_tests: Annotated[int, Field(ge=0, le=200)]
    functional_tests: Annotated[int, Field(ge=0, le=200)]
    pairs_planned: Annotated[int, Field(ge=0, le=10)]
    pairs_terminated_normally: Annotated[int, Field(ge=0, le=10)]
    pairs_with_trusted_evidence: Annotated[int, Field(ge=0, le=10)]
    required_cells: Annotated[int, Field(ge=0, le=4000)]
    trusted_cells: Annotated[int, Field(ge=0, le=4000)]


VERIFIED_LABEL = "Verified for the selected cases"
_LABELS = {"BLOCKED": "Blocked", "NOT_FIXED": "Not fixed", "REGRESSION_DETECTED": "Regression detected",
           "NOT_REPRODUCED": "Not reproduced", "INCONCLUSIVE": "Inconclusive"}
_RULES = {"VERIFIED_FOR_CASES": ("V-09",), "BLOCKED": ("V-01",), "NOT_FIXED": ("V-03",),
          "REGRESSION_DETECTED": ("V-04",), "NOT_REPRODUCED": ("V-08",),
          "INCONCLUSIVE": ("V-02", "V-05", "V-06", "V-07", "V-10")}


class VerdictRecord(Record):
    schema_version: SchemaVersion
    run_id: RunId
    engine_version: Semver
    verdict: Verdict
    display_label: ShortText
    decision_rule: Literal["V-01", "V-02", "V-03", "V-04", "V-05", "V-06", "V-07", "V-08", "V-09", "V-10"]
    execution_started: bool
    run_termination: RunTermination
    reason_codes: Annotated[list[ReasonCode], Field(min_length=1, max_length=40),
                            AfterValidator(unique_list("reason_codes"))]
    details: Annotated[list[Detail], Field(max_length=4096), AfterValidator(unique_list("details"))]
    flags: Flags
    preconditions: PreconditionStates
    counts: Counts
    evaluated_at: Timestamp

    @model_validator(mode="after")
    def _verdict_rules(self) -> VerdictRecord:
        v, f, reasons = self.verdict, self.flags, set(self.reason_codes)
        states = self.preconditions.states()
        all_passed = all(s == "PASSED" for s in states)
        if v == "VERIFIED_FOR_CASES":
            c = self.counts
            if (self.display_label != VERIFIED_LABEL or self.decision_rule != "V-09" or not self.execution_started
                    or self.run_termination != "normal" or self.reason_codes != ["ALL_CONDITIONS_SATISFIED"]
                    or self.details or any(f.model_dump().values()) or not all_passed
                    or min(c.security_tests, c.functional_tests, c.pairs_planned, c.pairs_terminated_normally,
                           c.pairs_with_trusted_evidence) < 1 or min(c.required_cells, c.trusted_cells) < 4):
                raise ValueError("VERIFIED_FOR_CASES requires every verification condition")
        else:
            if self.display_label == VERIFIED_LABEL or "ALL_CONDITIONS_SATISFIED" in reasons:
                raise ValueError("only VERIFIED_FOR_CASES carries the verified label or reason")
            if self.display_label != _LABELS[v] or self.decision_rule not in _RULES[v]:
                raise ValueError("display label or decision rule does not match the verdict")
        if v == "BLOCKED":
            if self.execution_started or all_passed:
                raise ValueError("BLOCKED is pre-execution and has a precondition that did not pass")
            if not f.incomplete_checks or any((f.candidate_violation, f.functional_regression, f.harness_drift,
                                               f.flaky_observations, f.baseline_not_reproduced,
                                               f.baseline_control_failed)):
                raise ValueError("BLOCKED sets only incomplete_checks")
        if v == "NOT_FIXED" and (not self.execution_started or not f.candidate_violation or not all_passed
                                 or "CANDIDATE_VIOLATION_CONFIRMED" not in reasons):
            raise ValueError("NOT_FIXED requires a trusted candidate violation")
        if v == "REGRESSION_DETECTED" and (not self.execution_started or f.candidate_violation
                                           or not f.functional_regression or not all_passed
                                           or "FUNCTIONAL_REGRESSION" not in reasons):
            raise ValueError("REGRESSION_DETECTED requires a regression and no candidate violation")
        if v == "NOT_REPRODUCED" and (
                not self.execution_started or self.run_termination != "normal" or not all_passed
                or f.model_dump() != {**{k: False for k in f.model_dump()}, "baseline_not_reproduced": True}
                or not reasons & {"BASELINE_NOT_REPRODUCED", "BASELINE_PARTIALLY_REPRODUCED"}):
            raise ValueError("NOT_REPRODUCED requires a complete run where only the baseline failed to reproduce")
        if v == "INCONCLUSIVE" and (f.candidate_violation or f.functional_regression):
            raise ValueError("INCONCLUSIVE cannot carry a candidate violation or regression")
        rule = self.decision_rule
        if rule == "V-02" and all_passed:
            raise ValueError("V-02 needs a precondition that did not pass")
        if rule in ("V-03", "V-04", "V-05", "V-06", "V-07", "V-08", "V-09") and not all_passed:
            raise ValueError("this decision rule requires every precondition to pass")
        if rule == "V-05" and not f.incomplete_checks:
            raise ValueError("V-05 requires incomplete checks")
        if rule == "V-06" and (not f.flaky_observations or "INCONSISTENT_REPETITIONS" not in reasons):
            raise ValueError("V-06 requires inconsistent repetitions")
        if rule == "V-07" and not f.baseline_control_failed:
            raise ValueError("V-07 requires a failed baseline control")
        if rule == "V-10" and "UNCLASSIFIED_EVIDENCE" not in reasons:
            raise ValueError("V-10 requires UNCLASSIFIED_EVIDENCE")
        for termination, code in (("canceled", "RUN_CANCELED"), ("interrupted", "RUN_INTERRUPTED")):
            if self.run_termination == termination and (code not in reasons or not f.incomplete_checks):
                raise ValueError(f"a {termination} run records {code} and incomplete checks")
        if "NOT_EVALUATED" in states and "PRECONDITION_NOT_EVALUATED" not in reasons:
            raise ValueError("an unevaluated precondition is reported")
        return self

