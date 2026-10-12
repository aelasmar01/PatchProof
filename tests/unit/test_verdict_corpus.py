"""PP-004: the engine reproduces the 26-scenario review-controlled corpus exactly (spec section 12)."""

from __future__ import annotations

import copy
import json
import random
from pathlib import Path
from typing import Any

import pytest
from _verdict_builder import INPUT_VALIDATOR, OUTPUT_VALIDATOR

from patchproof.core.verdict_input import REASON_CODES, parse_verdict_input
from patchproof.core.verdicts import evaluate

ROOT = Path(__file__).resolve().parents[2]
SCENARIOS = sorted(p for p in (ROOT / "schemas" / "examples" / "scenarios").iterdir() if p.is_dir())


def load(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    return json.loads((path / "verdict-input.json").read_text()), json.loads((path / "verdict.json").read_text())


def test_corpus_has_26_scenarios() -> None:
    assert len(SCENARIOS) == 26


@pytest.mark.parametrize("path", SCENARIOS, ids=lambda p: p.name)
def test_engine_reproduces_reviewed_verdict_exactly(path: Path) -> None:
    inp, expected = load(path)
    assert evaluate(parse_verdict_input(inp), expected["evaluated_at"]) == expected


@pytest.mark.parametrize("path", SCENARIOS, ids=lambda p: p.name)
def test_engine_output_is_schema_valid(path: Path) -> None:
    inp, expected = load(path)
    assert not list(INPUT_VALIDATOR.iter_errors(inp))
    result = evaluate(parse_verdict_input(inp), expected["evaluated_at"])
    assert not list(OUTPUT_VALIDATOR.iter_errors(result))


@pytest.mark.parametrize("path", SCENARIOS, ids=lambda p: p.name)
def test_output_is_independent_of_record_order(path: Path) -> None:
    inp, expected = load(path)
    rng = random.Random(path.name)
    for _ in range(5):
        shuffled = copy.deepcopy(inp)
        rng.shuffle(shuffled["executions"])
        rng.shuffle(shuffled["observations"])
        rng.shuffle(shuffled["pack_tests"])
        assert evaluate(parse_verdict_input(shuffled), expected["evaluated_at"]) == expected


@pytest.mark.parametrize("path", SCENARIOS, ids=lambda p: p.name)
def test_evaluation_does_not_mutate_input(path: Path) -> None:
    inp, expected = load(path)
    before = copy.deepcopy(inp)
    parsed = parse_verdict_input(inp)
    parsed_before = copy.deepcopy(parsed)
    evaluate(parsed, expected["evaluated_at"])
    assert inp == before and parsed == parsed_before


def test_reason_order_matches_the_accepted_schema() -> None:
    common = json.loads((ROOT / "schemas" / "common.schema.json").read_text())
    assert list(REASON_CODES) == common["$defs"]["reasonCode"]["enum"]
