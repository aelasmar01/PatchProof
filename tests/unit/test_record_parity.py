"""PP-007 / ADR-008 / ADR-002: the Pydantic models and the JSON Schemas accept and reject the same records.

1. **Corpus parity.** Every valid example, every invalid example (including the 26-scenario
   corpus) and every JSONL event goes through both validators, and the answers must be
   identical. This is the owner's acceptance condition on ADR-008.
2. **Differential parity.** Deterministic mutations of every corpus record go through both.
   The models must never accept what a schema rejects. A model may be stricter in exactly
   two documented ways, and nothing else may differ:
   - **Trailing newline:** Python's `re`, which `jsonschema` uses, lets `$` match before a
     final newline, so the schema accepts `"abc\\n"` for `^[a-z]+$`. The models use
     `re.fullmatch` and reject it.
   - **Integral float:** JSON Schema treats `1.0` as an integer. The strict models reject
     floats for integer fields rather than convert them.
   The full mutation run (223,815 mutations, 2026-10-12) is recorded in `STATUS.md`. This
   test runs a bounded deterministic sample of it.
3. **Strict loader:** duplicate keys, non-finite numbers, BOMs, invalid UTF-8, lone
   surrogates, depth and size are all refused before validation.
"""

from __future__ import annotations

import copy
import json
import random
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from test_schemas import (
    INVALID_DIR,
    RECORD_SCHEMAS,
    SCENARIO_DIR,
    VALID_DIR,
    DuplicateKeyError,
    load_records,
    schema_name_for,
    validator_for,
)

from patchproof.core.records import RECORD_MODELS, RecordError, load_record, validate_record
from patchproof.core.records.pack import PackManifest
from patchproof.core.strict_json import MAX_DEPTH, StrictJsonError, loads_strict


def _model_accepts(name: str, record: Any) -> bool:
    try:
        RECORD_MODELS[name].model_validate(record, strict=True)
    except ValidationError:
        return False
    return True


def _corpus() -> list[tuple[str, str, Any]]:
    items: list[tuple[str, str, Any]] = []
    for directory in (VALID_DIR, INVALID_DIR):
        for path in sorted(directory.iterdir()):
            try:
                records = load_records(path)
            except DuplicateKeyError:
                continue  # rejected by the strict loader before either validator; tested below
            items += [(f"{path.name}#{i}", schema_name_for(path), r) for i, r in enumerate(records)]
    for scenario in sorted(p for p in SCENARIO_DIR.iterdir() if p.is_dir()):
        for filename, name in (("verdict-input.json", "verdict-input"), ("verdict.json", "verdict")):
            items += [(f"{scenario.name}/{filename}", name, r) for r in load_records(scenario / filename)]
    return items


CORPUS = _corpus()


def test_every_record_contract_has_a_model() -> None:
    assert set(RECORD_MODELS) == set(RECORD_SCHEMAS)


def test_corpus_covers_valid_invalid_and_all_scenarios() -> None:
    scenarios = {label.split("/")[0] for label, _, _ in CORPUS if "/" in label}
    assert len(scenarios) == 26
    assert {name for _, name, _ in CORPUS} == set(RECORD_SCHEMAS)
    assert sum(1 for label, _, _ in CORPUS if label.split("#")[0] in {p.name for p in INVALID_DIR.iterdir()}) > 70


@pytest.mark.parametrize(("label", "name", "record"), CORPUS, ids=[c[0] for c in CORPUS])
def test_model_and_schema_agree_on_corpus(label: str, name: str, record: Any) -> None:
    assert _model_accepts(name, record) == validator_for(name).is_valid(record)


def test_duplicate_key_example_is_rejected_by_the_production_loader() -> None:
    path = INVALID_DIR / "pack-manifest--duplicate-key.json"
    with pytest.raises(RecordError, match="duplicate object key"):
        load_record(PackManifest, path.read_bytes(), contract="pack-manifest")


# ------------------------------------------------------------ differential mutations

_SCALARS: list[Any] = [None, True, False, 0, -1, 1, 7, 255, 4000, 65536, 10**12, 1.5, "", "a", "x" * 201,
                       "x" * 4001, "\x1b[31m", "1.0", [], {}]


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)


def _paths(value: Any, path: tuple[Any, ...] = ()) -> Iterator[tuple[tuple[Any, ...], Any]]:
    yield path, value
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _paths(v, (*path, k))
    elif isinstance(value, list):
        for i, v in enumerate(value[:2]):
            yield from _paths(v, (*path, i))


def _set(record: Any, path: tuple[Any, ...], value: Any, delete: bool = False) -> Any:
    out = copy.deepcopy(record)
    cursor = out
    for key in path[:-1]:
        cursor = cursor[key]
    if delete:
        del cursor[path[-1]]
    else:
        cursor[path[-1]] = value
    return out


def _mutations(record: Any, rng: random.Random, pool: list[str]) -> Iterator[Any]:
    for path, value in _paths(record):
        if isinstance(value, dict):
            yield _set(record, (*path, "zz_unknown"), 1)
            for key in value:
                yield _set(record, (*path, key), None, delete=True)
        if not path:
            continue
        for scalar in rng.sample(_SCALARS, 6):
            yield _set(record, path, scalar)
        for text in rng.sample(pool, 3):
            yield _set(record, path, text)
        if isinstance(value, bool):
            yield _set(record, path, not value)
        elif isinstance(value, int):
            yield from (_set(record, path, value + 1), _set(record, path, value - 1))
        elif isinstance(value, str) and value:
            yield from (_set(record, path, value + "x"), _set(record, path, value[:-1]))
        elif isinstance(value, list) and value:
            yield from (_set(record, path, value + value[:1]), _set(record, path, value[:1]))


def _model_stricter_allowed(original: Any, mutated: Any) -> bool:
    def integral_float(v: Any) -> bool:
        if isinstance(v, float):
            return v.is_integer()
        if isinstance(v, dict):
            return any(integral_float(x) for x in v.values())
        return isinstance(v, list) and any(integral_float(x) for x in v)

    def newline(v: Any) -> bool:
        return any(s.endswith("\n") for s in _strings(v))

    return (newline(mutated) and not newline(original)) or (integral_float(mutated) and not integral_float(original))


VALID_RECORDS = [(name, record) for label, name, record in CORPUS
                 if validator_for(name).is_valid(record) and ("/" in label or label.split("#")[0] in
                                                               {p.name for p in VALID_DIR.iterdir()})]


@pytest.mark.parametrize("index", range(0, len(VALID_RECORDS), 1))
def test_models_are_never_more_permissive_than_schemas(index: int) -> None:
    name, record = VALID_RECORDS[index]
    rng = random.Random(f"pp-007-{index}")
    pool = sorted({s for _, r in VALID_RECORDS for s in _strings(r) if len(s) <= 40})
    validator = validator_for(name)
    checked = 0
    for mutated in _mutations(record, rng, pool):
        schema_ok, model_ok = validator.is_valid(mutated), _model_accepts(name, mutated)
        checked += 1
        assert not (model_ok and not schema_ok), f"model accepted what the schema rejects: {json.dumps(mutated)[:300]}"
        if schema_ok and not model_ok:
            assert _model_stricter_allowed(record, mutated), f"unexplained divergence: {json.dumps(mutated)[:300]}"
        if checked >= 400:
            break
    assert checked > 10


def test_documented_stricter_cases_really_differ() -> None:
    manifest = json.loads((VALID_DIR / "pack-manifest--spec-7.2-example.json").read_text())
    newline = {**manifest, "pack_id": manifest["pack_id"] + "\n"}
    floaty = {**manifest, "repetitions": {**manifest["repetitions"], "pairs": 3.0}}
    for record in (newline, floaty):
        assert validator_for("pack-manifest").is_valid(record)
        assert not _model_accepts("pack-manifest", record)


def test_boolean_constants_reject_integers() -> None:
    record = json.loads((VALID_DIR / "source-manifest--synthetic-app.json").read_text())
    assert _model_accepts("source-manifest", record)
    assert not _model_accepts("source-manifest", {**record, "uncommitted_changes_included": 0})


# ------------------------------------------------------------ strict loader


@pytest.mark.parametrize(("raw", "message"), [
    (b'{"a": 1, "a": 2}', "duplicate object key"),
    (b'{"a": {"b": 1, "b": 1}}', "duplicate object key"),
    (b'{"a": NaN}', "non-finite"),
    (b'{"a": Infinity}', "non-finite"),
    (b'{"a": -Infinity}', "non-finite"),
    (b'\xef\xbb\xbf{"a": 1}', "byte-order mark"),
    (b'{"a": "\xff"}', "UTF-8"),
    (b'{"a": "\\ud800"}', "surrogate"),
    (b'{"a": 1} {"b": 2}', "well-formed"),
    (b"", "well-formed"),
    (b"[" * (MAX_DEPTH + 1) + b"]" * (MAX_DEPTH + 1), "nesting"),
])
def test_strict_loader_refuses(raw: bytes, message: str) -> None:
    with pytest.raises(StrictJsonError, match=message):
        loads_strict(raw)


def test_strict_loader_limits_size_and_accepts_plain_json() -> None:
    assert loads_strict(b'{"a": [1, 2.5, "x", null, true]}') == {"a": [1, 2.5, "x", None, True]}
    with pytest.raises(StrictJsonError, match="larger than"):
        loads_strict(b"[" + b"1," * 600 + b"1]", max_bytes=1000)
    assert loads_strict(b'"[[[[ inside a string ]]]]"') == "[[[[ inside a string ]]]]"


def test_record_errors_do_not_echo_rejected_input() -> None:
    manifest = json.loads((VALID_DIR / "pack-manifest--spec-7.2-example.json").read_text())
    hostile = {**manifest, "title": "\x1b]8;;http://example.invalid\x07CLICK"}
    with pytest.raises(RecordError) as caught:
        validate_record(PackManifest, hostile, "pack-manifest")
    assert "example.invalid" not in str(caught.value) and "\x1b" not in str(caught.value)


def test_models_are_frozen() -> None:
    manifest = load_record(PackManifest, (VALID_DIR / "pack-manifest--spec-7.2-example.json").read_bytes())
    with pytest.raises(ValidationError):
        manifest.pack_id = "other"  # type: ignore[misc]


def test_loader_matches_reference_strict_loader_on_corpus_files() -> None:
    for path in sorted(VALID_DIR.glob("*.json")):
        assert loads_strict(path.read_bytes()) == json.loads(path.read_text())


def test_scenario_directories_are_all_present() -> None:
    assert len([p for p in SCENARIO_DIR.iterdir() if p.is_dir()]) == 26
    assert Path(SCENARIO_DIR).is_dir()
