"""Hand-built verdict-engine inputs for spec-derived tests (independent of the scenario corpus).

`verified_input()` returns a schema-valid, fully trusted "verified fix" input. Tests then
mutate it; `resync()` restores the host-collector facts that must stay consistent with
the cells (failed_reports and the pytest exit code), so a test changes exactly the
property it intends to change.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from patchproof.core.verdict_input import parse_verdict_input
from patchproof.core.verdicts import evaluate

RUN_ID = "run-" + "a" * 31 + "1"
EVALUATED_AT = "2026-10-12T00:00:00Z"
CAP = 1048576
SCHEMAS = Path(__file__).resolve().parents[2] / "schemas"

TESTS: list[dict[str, str]] = [
    {"id": "AUTH-001", "nodeid": "tests/test_auth.py::test_cross_owner_read_denied", "kind": "security",
     "baseline_expected": "VIOLATION_CONFIRMED", "candidate_expected": "SECURE"},
    {"id": "AUTH-002", "nodeid": "tests/test_auth.py::test_cross_owner_update_denied", "kind": "security",
     "baseline_expected": "VIOLATION_CONFIRMED", "candidate_expected": "SECURE"},
    {"id": "AUTH-003", "nodeid": "tests/test_auth.py::test_admin_route_denied", "kind": "security",
     "baseline_expected": "SECURE", "candidate_expected": "SECURE"},
    {"id": "FUNC-001", "nodeid": "tests/test_func.py::test_owner_can_read", "kind": "functional",
     "baseline_expected": "PASS", "candidate_expected": "PASS"},
]


def _registry() -> Registry:
    docs = [json.loads(p.read_text()) for p in SCHEMAS.glob("*.schema.json")]
    return Registry().with_resources((d["$id"], Resource.from_contents(d)) for d in docs)


REGISTRY = _registry()
INPUT_VALIDATOR = Draft202012Validator(json.loads((SCHEMAS / "verdict-input.schema.json").read_text()),
                                       registry=REGISTRY)
OUTPUT_VALIDATOR = Draft202012Validator(json.loads((SCHEMAS / "verdict.schema.json").read_text()), registry=REGISTRY)


def precondition_passed() -> dict[str, Any]:
    return {"state": "PASSED", "detected_phase": None, "reason_codes": []}


def execution(pair: int, side: str) -> dict[str, Any]:
    return {
        "schema_version": "1.0", "run_id": RUN_ID, "pair": pair, "side": side, "started": True,
        "target": {"readiness": "READY", "oom_killed": False, "exited_during_tests": False},
        "verifier": {"termination": "EXITED", "exit_code": 0, "signal": None, "oom_killed": False},
        "deadline_exceeded": False, "canceled": False, "runtime_errors": [],
        "stream": {"status": "COMPLETE", "session_end_received": True, "events_received": 40,
                   "bytes_received": 4096, "failed_reports": 0},
    }


def observation(pair: int, side: str, test: dict[str, str], semantic: str | None = None) -> dict[str, Any]:
    return {
        "schema_version": "1.0", "run_id": RUN_ID, "pair": pair, "side": side, "test_id": test["id"],
        "nodeid": test["nodeid"], "kind": test["kind"], "stream_status": "COMPLETE",
        "lifecycle_outcome": "COMPLETED", "semantic_outcome": semantic or test[f"{side}_expected"],
        "harness_errors": [], "evidence_refs": [], "provenance": "verifier-event-stream",
    }


def verified_input(pairs: int = 1, tests: list[dict[str, str]] | None = None) -> dict[str, Any]:
    pack = copy.deepcopy(tests or TESTS)
    data = {
        "schema_version": "1.0", "run_id": RUN_ID, "pack_tests": pack, "pairs_planned": pairs,
        "result_cap_bytes": CAP,
        "preconditions": {name: precondition_passed() for name in
                          ("authorization", "pack_integrity", "source_identity", "environment_identity",
                           "result_provenance")},
        "run_termination": "normal",
        "executions": [execution(p, side) for p in range(1, pairs + 1) for side in ("baseline", "candidate")],
        "observations": [observation(p, side, t) for p in range(1, pairs + 1)
                         for side in ("baseline", "candidate") for t in pack],
    }
    return resync(data)


def _implies_failed(o: dict[str, Any]) -> bool:
    return o["lifecycle_outcome"] in ("SETUP_ERROR", "CALL_ERROR", "TEARDOWN_ERROR", "TIMED_OUT") or (
        o["lifecycle_outcome"] == "COMPLETED" and o["semantic_outcome"] in ("FAIL", "VIOLATION_CONFIRMED"))


def resync(data: dict[str, Any]) -> dict[str, Any]:
    """Recompute failed_reports and a consistent 0/1 exit code for complete, normally exited streams."""
    for e in data["executions"]:
        if e["stream"]["status"] != "COMPLETE":
            continue
        failed = sum(1 for o in data["observations"]
                     if (o["pair"], o["side"]) == (e["pair"], e["side"]) and _implies_failed(o))
        e["stream"]["failed_reports"] = failed
        if e["verifier"]["termination"] == "EXITED" and e["verifier"]["exit_code"] in (0, 1):
            e["verifier"]["exit_code"] = 1 if failed else 0
    return data


def find_execution(data: dict[str, Any], pair: int, side: str) -> dict[str, Any]:
    return next(e for e in data["executions"] if (e["pair"], e["side"]) == (pair, side))


def find_cell(data: dict[str, Any], pair: int, side: str, test_id: str) -> dict[str, Any]:
    return next(o for o in data["observations"] if (o["pair"], o["side"], o["test_id"]) == (pair, side, test_id))


def set_cell(data: dict[str, Any], pair: int, side: str, test_id: str, **fields: Any) -> dict[str, Any]:
    find_cell(data, pair, side, test_id).update(fields)
    return resync(data)


def set_stream(data: dict[str, Any], pair: int, side: str, status: str) -> dict[str, Any]:
    """Change an execution's stream status and keep its observations' stream_status equal (M6)."""
    e = find_execution(data, pair, side)
    e["stream"]["status"] = status
    e["stream"]["session_end_received"] = status in ("COMPLETE", "OVER_CAP", "MALFORMED", "IDENTITY_MISMATCH")
    for o in data["observations"]:
        if (o["pair"], o["side"]) == (pair, side):
            o["stream_status"] = status
    return data


def run(data: dict[str, Any], *, check_input_schema: bool = True) -> dict[str, Any]:
    if check_input_schema:
        errors = sorted(INPUT_VALIDATOR.iter_errors(data), key=str)
        assert not errors, [f"{list(e.absolute_path)}: {e.message}" for e in errors[:3]]
    result = evaluate(parse_verdict_input(data), EVALUATED_AT)
    output_errors = sorted(OUTPUT_VALIDATOR.iter_errors(result), key=str)
    assert not output_errors, [f"{list(e.absolute_path)}: {e.message}" for e in output_errors[:3]]
    return result


def details(result: dict[str, Any], code: str) -> list[tuple[Any, Any, Any]]:
    return [(d["pair"], d["side"], d["test_id"]) for d in result["details"] if d["reason_code"] == code]
