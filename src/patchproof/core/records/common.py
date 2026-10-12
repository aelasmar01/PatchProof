"""Shared bounded types: the Pydantic counterpart of schemas/common.schema.json (ADR-008).

These definitions are written independently of the JSON Schema files, not generated from
them, so the parity tests compare two implementations of one contract (ADR-002).

Every model is strict (no type coercion), closed (unknown fields rejected) and frozen.
Patterns are matched with `re.fullmatch` against the whole value, so a trailing newline
never satisfies a `$` anchor. Validation errors never echo the rejected input.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Sequence
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, hide_input_in_errors=True)


def matches(regex: str) -> AfterValidator:
    compiled = re.compile(regex)

    def check(value: str) -> str:
        if compiled.fullmatch(value) is None:
            raise ValueError("value does not match the required pattern")
        return value

    return AfterValidator(check)


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def require_unique(items: Sequence[Any], what: str) -> None:
    keys = [canonical(i.model_dump(mode="json") if isinstance(i, BaseModel) else i) for i in items]
    if len(set(keys)) != len(keys):
        raise ValueError(f"{what} must not contain duplicate items")


def unique_list[T](what: str) -> Callable[[list[T]], list[T]]:
    def check(items: list[T]) -> list[T]:
        require_unique(items, what)
        return items

    return check


def _is(expected: bool) -> AfterValidator:
    def check(value: bool) -> bool:
        if value is not expected:
            raise ValueError(f"value must be {str(expected).lower()}")
        return value

    return AfterValidator(check)


# Literal[False] / Literal[True] accept 0 and 1 even in strict mode, because 0 == False. A
# strict bool with an identity check accepts only the JSON booleans.
FalseOnly = Annotated[bool, _is(False)]
TrueOnly = Annotated[bool, _is(True)]


def one_of_ints(*allowed: int) -> AfterValidator:
    def check(value: int) -> int:
        if value not in allowed:
            raise ValueError("value is not permitted")
        return value

    return AfterValidator(check)


SchemaVersion = Literal["1.0"]
Identifier = Annotated[str, matches(r"^[a-z0-9][a-z0-9-]{0,62}$")]
Semver = Annotated[str, StringConstraints(max_length=32),
                   matches(r"^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$")]
Sha256 = Annotated[str, matches(r"^sha256:[0-9a-f]{64}$")]
ImageId = Annotated[str, matches(r"^sha256:[0-9a-f]{64}$")]
CommitId = Annotated[str, matches(r"^([0-9a-f]{40}|[0-9a-f]{64})$")]
RunId = Annotated[str, matches(r"^run-[0-9a-f]{32}$")]
ApprovalId = Annotated[str, matches(r"^apr-[0-9a-f]{32}$")]
ArtifactId = Annotated[str, matches(r"^art-[0-9a-f]{32}$")]
TestId = Annotated[str, matches(r"^[A-Z][A-Z0-9]{1,15}-[0-9]{3}$")]
PytestNodeId = Annotated[str, StringConstraints(max_length=255), matches(
    r"^tests/([A-Za-z0-9_][A-Za-z0-9_-]{0,63}/){0,4}test_[A-Za-z0-9_]{1,64}\.py::"
    r"([A-Z][A-Za-z0-9_]{0,63}::)?test_[A-Za-z0-9_]{1,64}(\[[A-Za-z0-9_.-]{1,64}\])?$")]
RelativePath = Annotated[str, StringConstraints(max_length=255),
                         matches(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}(/[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}){0,15}$")]
Timestamp = Annotated[str, StringConstraints(max_length=32),
                      matches(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z$")]
ShortText = Annotated[str, StringConstraints(min_length=1, max_length=200), matches(r"^[^\x00-\x1f\x7f]*$")]
LongText = Annotated[str, StringConstraints(min_length=1, max_length=4000),
                     matches(r"^[^\x00-\x08\x0b\x0c\x0e-\x1f\x7f]*$")]
PairIndex = Annotated[int, Field(ge=1, le=10)]
Side = Literal["baseline", "candidate"]
TestKind = Literal["security", "functional"]
PreconditionName = Literal["authorization", "pack_integrity", "source_identity", "environment_identity",
                           "result_provenance"]
RunTermination = Literal["normal", "canceled", "interrupted"]
ReasonCode = Literal[
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
]


class EvidenceRef(Record):
    artifact_id: ArtifactId
    sha256: Sha256


class ContainerLimitsV10(Record):
    cpus: Annotated[float, Field(gt=0, le=4)]
    memory_bytes: Annotated[int, Field(ge=67108864, le=4294967296)]
    pids: Annotated[int, Field(ge=16, le=1024)]
    scratch_tmpfs_bytes: Annotated[int, Field(ge=1048576, le=1073741824)]
