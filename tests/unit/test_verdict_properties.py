"""PP-004: properties P-1..P-9 (verdict specification section 14) over seeded random inputs.

Hypothesis is not installed (no new dependency is approved), so inputs are generated with
`random.Random(seed)`: a schema-valid verified input is mutated by randomly chosen
operations, and inputs the verdict-input schema rejects are skipped. The safety oracles
here re-derive trust from the raw input with code that is independent of the engine.
"""

from __future__ import annotations

import copy
import random
from collections.abc import Callable
from typing import Any

import pytest
from _verdict_builder import (
    CAP,
    EVALUATED_AT,
    INPUT_VALIDATOR,
    OUTPUT_VALIDATOR,
    find_execution,
    resync,
    set_stream,
    verified_input,
)

from patchproof.core.verdict_input import parse_verdict_input
from patchproof.core.verdicts import evaluate

SEEDS = range(400)
DISPLAY_VERDICTS = ("VERIFIED_FOR_CASES", "NOT_FIXED", "REGRESSION_DETECTED", "NOT_REPRODUCED", "INCONCLUSIVE",
                    "BLOCKED")
Data = dict[str, Any]


# ------------------------------------------------------------------- random mutation operators


def _cell(rng: random.Random, d: Data) -> Data | None:
    return rng.choice(d["observations"]) if d["observations"] else None


def op_semantic(rng: random.Random, d: Data) -> None:
    if o := _cell(rng, d):
        if o["kind"] == "security":
            o["semantic_outcome"] = rng.choice(["VIOLATION_CONFIRMED", "SECURE", "INCONCLUSIVE", "NONE"])
        elif o["lifecycle_outcome"] == "COMPLETED":
            o["semantic_outcome"] = rng.choice(["PASS", "FAIL"])


def op_lifecycle(rng: random.Random, d: Data) -> None:
    if o := _cell(rng, d):
        o["lifecycle_outcome"] = rng.choice(["SETUP_ERROR", "CALL_ERROR", "TEARDOWN_ERROR", "SKIPPED", "XFAILED",
                                             "XPASSED", "TIMED_OUT"])
        if o["kind"] == "functional" or o["lifecycle_outcome"] == "SETUP_ERROR":
            o["semantic_outcome"] = "NONE"


def op_harness(rng: random.Random, d: Data) -> None:
    if o := _cell(rng, d):
        o["harness_errors"] = [rng.choice(["MISSING_TERMINAL_OBSERVATION", "MALFORMED_EVIDENCE",
                                           "SUPPRESSED_TERMINAL_EXCEPTION", "GENERIC_FAILURE_IN_SECURITY_TEST"])]


def op_remove_observation(rng: random.Random, d: Data) -> None:
    if o := _cell(rng, d):
        d["observations"].remove(o)
        if rng.random() < 0.7:
            set_stream(d, o["pair"], o["side"], "TRUNCATED")


def op_execution_fact(rng: random.Random, d: Data) -> None:
    e = rng.choice(d["executions"])
    choice = rng.randrange(7)
    if choice == 0:
        e["deadline_exceeded"] = True
    elif choice == 1:
        e["canceled"] = True
    elif choice == 2:
        e["verifier"]["oom_killed"] = True
    elif choice == 3:
        e["target"]["oom_killed"] = True
    elif choice == 4:
        e["runtime_errors"] = ["ATTACH_FAILED"]
    elif choice == 5:
        e["verifier"].update(termination="SIGNALED", exit_code=None, signal=9)
    else:
        e["verifier"]["exit_code"] = 2


def op_stream(rng: random.Random, d: Data) -> None:
    e = rng.choice(d["executions"])
    set_stream(d, e["pair"], e["side"], rng.choice(["TRUNCATED", "OVER_CAP", "MALFORMED", "IDENTITY_MISMATCH"]))


def op_over_cap(rng: random.Random, d: Data) -> None:
    rng.choice(d["executions"])["stream"]["bytes_received"] = CAP + 1


def op_precondition(rng: random.Random, d: Data) -> None:
    name = rng.choice(list(d["preconditions"]))
    d["preconditions"][name] = rng.choice([
        {"state": "NOT_EVALUATED", "detected_phase": None, "reason_codes": []},
        {"state": "FAILED", "detected_phase": "post_execution", "reason_codes": ["EVIDENCE_INCOMPLETE"]},
    ])


def op_termination(rng: random.Random, d: Data) -> None:
    d["run_termination"] = rng.choice(["canceled", "interrupted"])


def op_duplicate(rng: random.Random, d: Data) -> None:
    if o := _cell(rng, d):
        twin = copy.deepcopy(o)
        twin["evidence_refs"] = [{"artifact_id": "art-" + "f" * 32, "sha256": "sha256:" + "e" * 64}]
        d["observations"].append(twin)


ALL_OPS: list[Callable[[random.Random, Data], None]] = [
    op_semantic, op_semantic, op_lifecycle, op_harness, op_remove_observation, op_execution_fact, op_stream,
    op_over_cap, op_precondition, op_termination, op_duplicate]


def random_input(seed: int, ops: list[Callable[[random.Random, Data], None]] = ALL_OPS) -> Data | None:
    rng = random.Random(seed)
    d = verified_input(pairs=rng.randint(1, 3))
    for _ in range(rng.randint(0, 4)):
        rng.choice(ops)(rng, d)
    if rng.random() < 0.6:
        resync(d)
    return d if INPUT_VALIDATOR.is_valid(d) else None


def evaluate_dict(d: Data) -> dict[str, Any]:
    return evaluate(parse_verdict_input(d), EVALUATED_AT)


SEMANTIC_OPS: list[Callable[[random.Random, Data], None]] = [op_semantic, op_semantic, op_semantic, op_lifecycle]
# Two streams: structural/global mutations, and semantic-only mutations that keep the
# evidence trusted, so NOT_FIXED / V-04 / V-06 / V-07 / V-08 are exercised as well.
VALID = [d for d in (random_input(s) for s in SEEDS) if d is not None] + [
    d for d in (random_input(100_000 + s, SEMANTIC_OPS) for s in SEEDS) if d is not None]


def test_generator_produces_enough_valid_inputs() -> None:
    assert len(VALID) > 600
    verdicts_seen = {evaluate_dict(d)["verdict"] for d in VALID}
    assert set(DISPLAY_VERDICTS) - {"BLOCKED"} <= verdicts_seen


# ------------------------------------------------------------------- independent oracles


def oracle_execution_trusted(e: Data) -> bool:
    v, t, s = e["verifier"], e["target"], e["stream"]
    return (e["started"] and t["readiness"] == "READY" and v["termination"] == "EXITED" and v["exit_code"] in (0, 1)
            and not (v["oom_killed"] or t["oom_killed"] or t["exited_during_tests"] or e["deadline_exceeded"]
                     or e["canceled"] or e["runtime_errors"])
            and s["status"] == "COMPLETE" and s["bytes_received"] <= CAP)


def oracle_trusted_candidate_violation_possible(d: Data) -> bool:
    """A trusted candidate violation can exist only under these raw conditions."""
    if any(p["state"] != "PASSED" for p in d["preconditions"].values()):
        return False
    for o in d["observations"]:
        if (o["side"] == "candidate" and o["kind"] == "security" and o["semantic_outcome"] == "VIOLATION_CONFIRMED"
                and o["lifecycle_outcome"] == "COMPLETED" and not o["harness_errors"]):
            owners = [e for e in d["executions"] if (e["pair"], e["side"]) == (o["pair"], o["side"])]
            if len(owners) == 1 and oracle_execution_trusted(owners[0]):
                return True
    return False


def oracle_verified_is_justified(d: Data) -> list[str]:
    """P-4 recomputed from raw input; returns the violated conditions."""
    problems = []
    pairs, pack = d["pairs_planned"], {t["id"]: t for t in d["pack_tests"]}
    required = {(p, s, t) for p in range(1, pairs + 1) for s in ("baseline", "candidate") for t in pack}
    keys = [(o["pair"], o["side"], o["test_id"]) for o in d["observations"]]
    if sorted(keys) != sorted(required):
        problems.append("observation keys are not exactly the required matrix")
    exec_keys = [(e["pair"], e["side"]) for e in d["executions"]]
    if sorted(exec_keys) != sorted((p, s) for p in range(1, pairs + 1) for s in ("baseline", "candidate")):
        problems.append("execution keys are not exactly the planned executions")
    if not all(oracle_execution_trusted(e) for e in d["executions"]):
        problems.append("an execution is untrusted")
    for o in d["observations"]:
        expected = pack[o["test_id"]][f"{o['side']}_expected"]
        if o["lifecycle_outcome"] != "COMPLETED" or o["harness_errors"] or o["semantic_outcome"] != expected:
            problems.append(f"cell {o['pair'], o['side'], o['test_id']} is not a trusted expected outcome")
    if any(p["state"] != "PASSED" for p in d["preconditions"].values()):
        problems.append("a precondition is not PASSED")
    if d["run_termination"] != "normal":
        problems.append("run did not terminate normally")
    return problems


# ------------------------------------------------------------------- properties


@pytest.mark.parametrize("index", range(len(VALID)))
def test_p7_output_is_schema_valid_and_p3_precondition_dominance(index: int) -> None:
    result = evaluate_dict(VALID[index])
    assert not list(OUTPUT_VALIDATOR.iter_errors(result))
    if any(state != "PASSED" for state in result["preconditions"].values()):
        assert result["verdict"] in ("BLOCKED", "INCONCLUSIVE") and result["counts"]["trusted_cells"] == 0


@pytest.mark.parametrize("index", range(len(VALID)))
def test_p4_verified_implies_exact_completeness(index: int) -> None:
    d = VALID[index]
    if evaluate_dict(d)["verdict"] == "VERIFIED_FOR_CASES":
        assert oracle_verified_is_justified(d) == []


@pytest.mark.parametrize("index", range(len(VALID)))
def test_p5_p8_candidate_violation_only_from_trusted_witness(index: int) -> None:
    d = VALID[index]
    result = evaluate_dict(d)
    if result["flags"]["candidate_violation"]:
        assert oracle_trusted_candidate_violation_possible(d)
        assert result["verdict"] == "NOT_FIXED"


@pytest.mark.parametrize("index", range(len(VALID)))
def test_p6_no_trusted_baseline_no_positive_or_reproduction_verdict(index: int) -> None:
    d = VALID[index]
    if not any(oracle_execution_trusted(e) for e in d["executions"] if e["side"] == "baseline"):
        assert evaluate_dict(d)["verdict"] not in ("VERIFIED_FOR_CASES", "NOT_REPRODUCED")


@pytest.mark.parametrize("index", range(len(VALID)))
def test_p2_order_independence(index: int) -> None:
    d = VALID[index]
    expected = evaluate_dict(d)
    rng = random.Random(index)
    shuffled = copy.deepcopy(d)
    rng.shuffle(shuffled["executions"])
    rng.shuffle(shuffled["observations"])
    assert evaluate_dict(shuffled) == expected


def op_inconclusive(rng: random.Random, d: Data) -> None:
    """Degrade one security cell to an INCONCLUSIVE observation (functional cells: non-COMPLETED)."""
    if o := _cell(rng, d):
        if o["kind"] == "security":
            o["semantic_outcome"] = "INCONCLUSIVE"
        else:
            o.update(lifecycle_outcome="CALL_ERROR", semantic_outcome="NONE")


DEGRADE_OPS: list[Callable[[random.Random, Data], None]] = [
    op_lifecycle, op_harness, op_execution_fact, op_stream, op_over_cap, op_precondition, op_termination,
    lambda rng, d: d["observations"].remove(rng.choice(d["observations"])) if d["observations"] else None,
    lambda rng, d: d["executions"].remove(rng.choice(d["executions"])) if d["executions"] else None,
    lambda rng, d: op_inconclusive(rng, d),
]


@pytest.mark.parametrize("index", range(len(VALID)))
def test_p1_degrading_trust_never_produces_verified(index: int) -> None:
    d = VALID[index]
    rng = random.Random(10_000 + index)
    for _ in range(3):
        degraded = copy.deepcopy(d)
        rng.choice(DEGRADE_OPS)(rng, degraded)
        if rng.random() < 0.5:
            resync(degraded)
        if degraded["observations"] == d["observations"] and degraded == d:
            continue
        result = evaluate(parse_verdict_input(degraded), EVALUATED_AT)
        assert result["verdict"] != "VERIFIED_FOR_CASES", rng


NOISE_OPS: list[Callable[[random.Random, Data], None]] = [
    op_semantic, op_lifecycle, op_harness, op_execution_fact, op_over_cap, op_termination]


@pytest.mark.parametrize("seed", range(150))
def test_p5_trusted_candidate_violation_dominates_local_noise(seed: int) -> None:
    rng = random.Random(seed)
    d = verified_input(pairs=rng.randint(2, 3))
    witness = next(o for o in d["observations"] if (o["pair"], o["side"], o["test_id"]) == (1, "candidate", "AUTH-001"))
    witness["semantic_outcome"] = "VIOLATION_CONFIRMED"
    protected = find_execution(d, 1, "candidate")
    for _ in range(rng.randint(1, 5)):
        before_witness, before_exec = copy.deepcopy(witness), copy.deepcopy(protected)
        rng.choice(NOISE_OPS)(rng, d)
        if witness != before_witness or protected != before_exec:  # noise must stay elsewhere
            witness.clear()
            witness.update(before_witness)
            protected.clear()
            protected.update(before_exec)
    resync(d)
    if not INPUT_VALIDATOR.is_valid(d):
        pytest.skip("generated input outside the schema")
    result = evaluate_dict(d)
    assert result["verdict"] == "NOT_FIXED", result["reason_codes"]


@pytest.mark.parametrize("index", range(len(VALID)))
def test_p9_over_cap_is_local_enforced_and_never_verifies(index: int) -> None:
    d = VALID[index]
    rng = random.Random(20_000 + index)
    before = evaluate_dict(d)
    over = copy.deepcopy(d)
    target = rng.choice(over["executions"])
    target["stream"]["bytes_received"] = CAP + 1
    after = evaluate_dict(over)
    assert after["verdict"] != "VERIFIED_FOR_CASES"
    assert {"reason_code": "RESULT_CAP_EXCEEDED", "pair": target["pair"], "side": target["side"],
            "test_id": None} in after["details"]
    other_violations = [x for x in before["details"] if x["reason_code"] == "CANDIDATE_VIOLATION_CONFIRMED"
                        and (x["pair"], x["side"]) != (target["pair"], target["side"])]
    if before["verdict"] == "NOT_FIXED" and other_violations:
        assert after["verdict"] == "NOT_FIXED"


@pytest.mark.parametrize("index", range(0, len(VALID), 7))
def test_evaluation_never_mutates_its_input(index: int) -> None:
    d = VALID[index]
    snapshot = copy.deepcopy(d)
    parsed = parse_verdict_input(d)
    evaluate(parsed, EVALUATED_AT)
    assert d == snapshot
