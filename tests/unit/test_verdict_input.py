"""PP-004: strict typed parsing of verdict-engine input.

Shape errors are refused before evaluation. Semantic problems (duplicates, unknown tests,
pair limits) are preserved for the engine, which must turn them into V-02 itself.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from _verdict_builder import verified_input

from patchproof.core.verdict_input import VerdictInputError, parse_verdict_input

ROOT = Path(__file__).resolve().parents[2]
Mutation = Callable[[dict[str, Any]], None]

SHAPE_ERRORS: dict[str, Mutation] = {
    "unknown top-level field": lambda d: d.__setitem__("target_stdout", "PASS"),
    "missing result cap": lambda d: d.pop("result_cap_bytes"),
    "unsupported schema version": lambda d: d.__setitem__("schema_version", "2.0"),
    "pairs out of range": lambda d: d.__setitem__("pairs_planned", 11),
    "boolean as integer": lambda d: d.__setitem__("pairs_planned", True),
    "bad termination": lambda d: d.__setitem__("run_termination", "finished"),
    "precondition missing": lambda d: d["preconditions"].pop("authorization"),
    "failed precondition without phase": lambda d: d["preconditions"].__setitem__(
        "authorization", {"state": "FAILED", "detected_phase": None, "reason_codes": ["APPROVAL_STALE"]}),
    "failed precondition without reason": lambda d: d["preconditions"].__setitem__(
        "authorization", {"state": "FAILED", "detected_phase": "pre_execution", "reason_codes": []}),
    "passed precondition with reason": lambda d: d["preconditions"].__setitem__(
        "authorization", {"state": "PASSED", "detected_phase": None, "reason_codes": ["APPROVAL_STALE"]}),
    "failed precondition claiming success": lambda d: d["preconditions"].__setitem__(
        "authorization", {"state": "FAILED", "detected_phase": "pre_execution",
                          "reason_codes": ["APPROVAL_STALE", "ALL_CONDITIONS_SATISFIED"]}),
    "unknown reason code": lambda d: d["preconditions"].__setitem__(
        "authorization", {"state": "FAILED", "detected_phase": "pre_execution", "reason_codes": ["IT_PASSED"]}),
    "security test expected to violate on candidate": lambda d: d["pack_tests"][0].__setitem__(
        "candidate_expected", "VIOLATION_CONFIRMED"),
    "functional test expecting SECURE": lambda d: d["pack_tests"][3].__setitem__("baseline_expected", "SECURE"),
    "single pack test": lambda d: d.__setitem__("pack_tests", d["pack_tests"][:1]),
    "observation from target stdout": lambda d: d["observations"][0].__setitem__("provenance", "target-stdout"),
    "observation extra field": lambda d: d["observations"][0].__setitem__("target_status", "PASS"),
    "bad lifecycle": lambda d: d["observations"][0].__setitem__("lifecycle_outcome", "PASSED"),
    "bad semantic": lambda d: d["observations"][0].__setitem__("semantic_outcome", "OK"),
    "bad harness error": lambda d: d["observations"][0].__setitem__("harness_errors", ["OOPS"]),
    "bad evidence ref": lambda d: d["observations"][0].__setitem__("evidence_refs", [{"artifact_id": "x",
                                                                                      "sha256": "y"}]),
    "execution missing stream": lambda d: d["executions"][0].pop("stream"),
    "exit code with signal": lambda d: d["executions"][0]["verifier"].update(signal=9),
    "signaled without signal": lambda d: d["executions"][0]["verifier"].update(termination="SIGNALED",
                                                                               exit_code=None),
    "bytes beyond bound": lambda d: d["executions"][0]["stream"].__setitem__("bytes_received", 52428802),
    "unknown runtime error": lambda d: d["executions"][0].__setitem__("runtime_errors", ["DOCKER_SOCKET_OPEN"]),
    "not an object": lambda d: d.__setitem__("executions", ["x"]),
}


@pytest.mark.parametrize("name", sorted(SHAPE_ERRORS))
def test_shape_errors_are_refused(name: str) -> None:
    data = verified_input()
    SHAPE_ERRORS[name](data)
    with pytest.raises(VerdictInputError):
        parse_verdict_input(data)


def test_valid_input_parses_into_frozen_records() -> None:
    parsed = parse_verdict_input(verified_input())
    with pytest.raises(AttributeError):
        parsed.observations[0].semantic_outcome = "SECURE"  # type: ignore[misc]
    assert len(parsed.observations) == 8 and parsed.precondition("authorization").state == "PASSED"


def test_duplicates_and_unknown_tests_are_preserved_for_the_engine() -> None:
    data = verified_input()
    data["observations"].append(copy.deepcopy(data["observations"][0]))
    data["observations"][1]["test_id"] = "ZZZ-999"
    parsed = parse_verdict_input(data)
    assert len(parsed.observations) == 9
    assert parsed.observations[0] == parsed.observations[-1]


@pytest.mark.parametrize("name,expect_refusal", [
    ("verdict-input--target-log-field.json", True),
    ("verdict-input--missing-result-cap.json", True),
    ("verdict-input--failed-precondition-without-reason.json", True),
    ("verdict-input--identical-duplicate-observation.json", False),  # a valid shape; the engine rejects it (M4)
])
def test_accepted_invalid_examples(name: str, expect_refusal: bool) -> None:
    data = json.loads((ROOT / "schemas" / "examples" / "invalid" / name).read_text())
    if expect_refusal:
        with pytest.raises(VerdictInputError):
            parse_verdict_input(data)
    else:
        from patchproof.core.verdicts import evaluate

        result = evaluate(parse_verdict_input(data), "2026-10-12T00:00:00Z")
        assert result["decision_rule"] == "V-02" and "OBSERVATION_MATRIX_INVALID" in result["reason_codes"]
