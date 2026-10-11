"""PP-002: machine validation of the v1.0 record schemas and their example records.

Every valid example must validate. Every invalid example must be rejected *for the
reason recorded in INVALID_CASES*, so an example cannot pass this suite by failing
on an unrelated typo. The strict loader below is the reference behavior for the
production loader in PP-007 (duplicate keys and non-finite numbers rejected before
schema validation, 7.1).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, ValidationError
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_DIR = ROOT / "schemas"
VALID_DIR = SCHEMA_DIR / "examples" / "valid"
INVALID_DIR = SCHEMA_DIR / "examples" / "invalid"

RECORD_SCHEMAS = (
    "pack-manifest",
    "execution-profile",
    "approval-record",
    "verifier-event",
    "observation",
    "verdict",
)

# filename -> (failing keyword, JSON pointer of the failing instance location).
# "duplicate_key" marks a rejection by the strict loader rather than the schema.
INVALID_CASES: dict[str, tuple[str, str]] = {
    "pack-manifest--unknown-field-command.json": ("additionalProperties", ""),
    "pack-manifest--unsupported-schema-version.json": ("const", "/schema_version"),
    "pack-manifest--nodeid-path-traversal.json": ("pattern", "/tests/0/nodeid"),
    "pack-manifest--nodeid-option-injection.json": ("pattern", "/tests/0/nodeid"),
    "pack-manifest--no-functional-control.json": ("contains", "/tests"),
    "pack-manifest--no-baseline-violation-expected.json": ("contains", "/tests"),
    "pack-manifest--security-test-expects-pass.json": ("enum", "/tests/1/baseline_expected"),
    "pack-manifest--functional-test-expects-secure.json": ("const", "/tests/2/candidate_expected"),
    "pack-manifest--ansi-escape-in-title.json": ("pattern", "/title"),
    "pack-manifest--zero-pairs.json": ("minimum", "/repetitions/pairs"),
    "pack-manifest--adapter-not-allowlisted.json": ("const", "/adapter"),
    "pack-manifest--duplicate-key.json": ("duplicate_key", ""),
    "execution-profile--privileged-flag.json": ("additionalProperties", ""),
    "execution-profile--docker-args.json": ("additionalProperties", ""),
    "execution-profile--asgi-shell-fragment.json": ("pattern", "/asgi_app"),
    "execution-profile--bridge-network.json": ("const", "/network_policy"),
    "execution-profile--source-traversal.json": ("pattern", "/source_scope/include/0"),
    "execution-profile--missing-memory-limit.json": ("required", "/resources/target"),
    "execution-profile--floating-image-tag.json": ("pattern", "/target_image_id"),
    "approval-record--claims-verified-reviewer.json": ("const", "/reviewer/basis"),
    "approval-record--abbreviated-hash.json": ("pattern", "/bindings/pack_tree_sha256"),
    "approval-record--auto-approved-field.json": ("additionalProperties", ""),
    "verifier-event--observation-outcome-pass.json": ("enum", "/payload/outcome"),
    "verifier-event--target-log-type.json": ("enum", "/type"),
    "verifier-event--failed-without-class.json": ("not", "/payload/failure_class"),
    "verifier-event--payload-carries-verdict.json": ("additionalProperties", "/payload"),
    "observation--target-stdout-provenance.json": ("const", "/provenance"),
    "observation--timeout-recorded-as-fail.json": ("const", "/semantic_outcome"),
    "observation--security-test-pass.json": ("enum", "/semantic_outcome"),
    "verdict--verified-with-flaky-flag.json": ("const", "/flags/flaky_observations"),
    "verdict--verified-with-failed-precondition.json": ("const", "/preconditions/result_provenance"),
    "verdict--verified-with-extra-reason.json": ("const", "/reason_codes"),
    "verdict--verified-without-functional-tests.json": ("minimum", "/counts/functional_tests"),
    "verdict--not-fixed-without-candidate-violation.json": ("const", "/flags/candidate_violation"),
    "verdict--regression-with-candidate-violation.json": ("const", "/flags/candidate_violation"),
    "verdict--inconclusive-with-verified-label.json": ("not", "/display_label"),
    "verdict--blocked-all-preconditions-passed.json": ("anyOf", "/preconditions"),
}


class DuplicateKeyError(ValueError):
    pass


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name} is not permitted")


def strict_loads(text: str) -> Any:
    return json.loads(text, object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant)


def load_records(path: Path) -> list[Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".jsonl":
        return [strict_loads(line) for line in text.splitlines() if line.strip()]
    return [strict_loads(text)]


def schema_name_for(path: Path) -> str:
    name = path.name.split("--", 1)[0]
    assert name in RECORD_SCHEMAS, f"{path.name}: unknown schema prefix {name!r}"
    return name


def _load_schemas() -> dict[str, dict[str, Any]]:
    return {
        p.name.removesuffix(".schema.json"): strict_loads(p.read_text(encoding="utf-8"))
        for p in sorted(SCHEMA_DIR.glob("*.schema.json"))
    }


SCHEMAS = _load_schemas()
REGISTRY: Registry = Registry().with_resources(
    (schema["$id"], Resource.from_contents(schema)) for schema in SCHEMAS.values()
)


def validator_for(name: str) -> Draft202012Validator:
    return Draft202012Validator(SCHEMAS[name], registry=REGISTRY)


def _flatten(errors: Iterator[ValidationError]) -> Iterator[ValidationError]:
    for error in errors:
        yield error
        yield from _flatten(iter(error.context or ()))


def _pointer(error: ValidationError) -> str:
    return "".join(f"/{part}" for part in error.absolute_path)


# ---------------------------------------------------------------- schema files


def test_every_record_schema_present() -> None:
    assert set(SCHEMAS) == {"common", *RECORD_SCHEMAS}


@pytest.mark.parametrize("name", sorted(SCHEMAS))
def test_schema_is_valid_draft_2020_12(name: str) -> None:
    Draft202012Validator.check_schema(SCHEMAS[name])


@pytest.mark.parametrize("name", sorted(SCHEMAS))
def test_schema_id_matches_filename_and_version(name: str) -> None:
    assert SCHEMAS[name]["$id"] == f"urn:patchproof:schema:{name}:1.0"


@pytest.mark.parametrize("name", RECORD_SCHEMAS)
def test_record_schema_is_closed(name: str) -> None:
    schema = SCHEMAS[name]
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False


# ------------------------------------------------------------- valid examples


def _valid_files() -> list[Path]:
    return sorted(p for p in VALID_DIR.iterdir() if p.suffix in {".json", ".jsonl"})


def test_every_record_schema_has_a_valid_example() -> None:
    covered = {schema_name_for(p) for p in _valid_files()}
    assert covered == set(RECORD_SCHEMAS)


@pytest.mark.parametrize("path", _valid_files(), ids=lambda p: p.name)
def test_valid_example_validates(path: Path) -> None:
    validator = validator_for(schema_name_for(path))
    for record in load_records(path):
        errors = [f"{_pointer(e)}: {e.message}" for e in validator.iter_errors(record)]
        assert errors == []


def test_spec_section_7_2_example_is_verbatim() -> None:
    spec = (ROOT / "PROJECT_SPEC.md").read_text(encoding="utf-8")
    start = spec.index("```json\n", spec.index("### 7.2 Manifest example")) + len("```json\n")
    expected = strict_loads(spec[start : spec.index("```", start)])
    assert load_records(VALID_DIR / "pack-manifest--spec-7.2-example.json") == [expected]


# ----------------------------------------------------------- invalid examples


def test_invalid_case_table_matches_files() -> None:
    on_disk = {p.name for p in INVALID_DIR.iterdir() if p.suffix == ".json"}
    assert on_disk == set(INVALID_CASES)


@pytest.mark.parametrize("filename", sorted(INVALID_CASES))
def test_invalid_example_rejected_for_recorded_reason(filename: str) -> None:
    path = INVALID_DIR / filename
    keyword, pointer = INVALID_CASES[filename]
    if keyword == "duplicate_key":
        with pytest.raises(DuplicateKeyError):
            load_records(path)
        return
    (record,) = load_records(path)
    errors = list(_flatten(validator_for(schema_name_for(path)).iter_errors(record)))
    assert errors, f"{filename} was accepted"
    found = {(e.validator, _pointer(e)) for e in errors}
    assert (keyword, pointer) in found, f"{filename} rejected for other reasons: {sorted(found)}"


# --------------------------------------------------------------- strict loader


def test_strict_loader_rejects_nested_duplicate_key() -> None:
    with pytest.raises(DuplicateKeyError):
        strict_loads('{"limits": {"case_timeout_seconds": 20, "case_timeout_seconds": 999}}')


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity"])
def test_strict_loader_rejects_non_finite_numbers(literal: str) -> None:
    with pytest.raises(ValueError, match="non-finite"):
        strict_loads(f'{{"cpus": {literal}}}')
