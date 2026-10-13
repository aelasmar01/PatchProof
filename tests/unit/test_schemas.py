"""PP-002: machine validation of the v1.0 record schemas and their example records.

Every valid example must validate. Every invalid example must be rejected *for the
reason recorded in INVALID_CASES*, so an example cannot pass this suite by failing
on an unrelated typo. The strict loader below is the reference behavior for the
production loader in PP-007 (duplicate keys and non-finite numbers rejected before
schema validation, 7.1).

The scenario corpus (schemas/examples/scenarios/) pairs a verdict-engine input with
its reviewed expected verdict. These tests check that both records are schema-valid,
mutually consistent, and listed identically in the verdict specification's scenario
table. They do not evaluate verdicts: that is the PP-004 engine's job, and PP-004
must reproduce every expected verdict exactly.
"""

from __future__ import annotations

import json
import re
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
SCENARIO_DIR = SCHEMA_DIR / "examples" / "scenarios"
VERDICT_SPEC = ROOT / "docs" / "architecture" / "verdict-specification.md"

RECORD_SCHEMAS = (
    "pack-manifest",
    "execution-profile",
    "approval-record",
    "verifier-event",
    "observation",
    "execution",
    "verdict-input",
    "verdict",
    "isolation-probe-run",
    "execution-profile.v1.1",
    "source-manifest",
    "reference-fixture",
    "run-authorization",
    "interruption-test-authorization",
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
    "execution-profile.v1.1--privileged-flag.json": ("additionalProperties", ""),
    "execution-profile.v1.1--docker-args.json": ("additionalProperties", ""),
    "execution-profile.v1.1--asgi-shell-fragment.json": ("pattern", "/asgi_app"),
    "execution-profile.v1.1--bridge-network.json": ("const", "/network_policy"),
    "execution-profile.v1.1--source-traversal.json": ("pattern", "/source_scope/include/0"),
    "execution-profile.v1.1--missing-memory-limit.json": ("required", "/resources/target"),
    "execution-profile.v1.1--floating-image-tag.json": ("pattern", "/target_image_id"),
    "execution-profile.v1.1--missing-tmp-size.json": ("required", "/resources/verifier"),
    "execution-profile.v1.1--v1-0-record.json": ("const", "/schema_version"),
    "approval-record--claims-verified-reviewer.json": ("const", "/reviewer/basis"),
    "approval-record--abbreviated-hash.json": ("pattern", "/bindings/pack_tree_sha256"),
    "approval-record--auto-approved-field.json": ("additionalProperties", ""),
    "verifier-event--observation-outcome-pass.json": ("enum", "/payload/outcome"),
    "verifier-event--target-log-type.json": ("enum", "/type"),
    "verifier-event--failed-without-class.json": ("not", "/payload/failure_class"),
    "verifier-event--payload-carries-verdict.json": ("additionalProperties", "/payload"),
    "verifier-event--setup-security-terminal.json": ("not", "/payload/failure_class"),
    "observation--target-stdout-provenance.json": ("const", "/provenance"),
    "observation--timeout-recorded-as-fail.json": ("const", "/semantic_outcome"),
    "observation--security-test-pass.json": ("enum", "/semantic_outcome"),
    "observation--complete-stream-interrupted.json": ("not", "/lifecycle_outcome"),
    "observation--setup-error-with-observation.json": ("const", "/semantic_outcome"),
    "execution--complete-stream-without-session-end.json": ("const", "/stream/session_end_received"),
    "execution--signaled-with-exit-code.json": ("type", "/verifier/exit_code"),
    "execution--not-started-with-stream.json": ("const", "/stream/status"),
    "verdict-input--identical-duplicate-observation.json": ("uniqueItems", "/observations"),
    "verdict-input--failed-precondition-without-reason.json": ("minItems", "/preconditions/authorization/reason_codes"),
    "verdict-input--target-log-field.json": ("additionalProperties", ""),
    "verdict-input--missing-result-cap.json": ("required", ""),
    "verdict--verified-with-flaky-flag.json": ("const", "/flags/flaky_observations"),
    "verdict--verified-with-failed-precondition.json": ("const", "/preconditions/result_provenance"),
    "verdict--verified-with-extra-reason.json": ("const", "/reason_codes"),
    "verdict--verified-without-functional-tests.json": ("minimum", "/counts/functional_tests"),
    "verdict--verified-canceled.json": ("const", "/run_termination"),
    "verdict--verified-with-details.json": ("maxItems", "/details"),
    "verdict--not-fixed-without-candidate-violation.json": ("const", "/flags/candidate_violation"),
    "verdict--regression-with-candidate-violation.json": ("const", "/flags/candidate_violation"),
    "verdict--inconclusive-with-verified-label.json": ("not", "/display_label"),
    "verdict--inconclusive-with-candidate-violation.json": ("const", "/flags/candidate_violation"),
    "verdict--blocked-all-preconditions-passed.json": ("anyOf", "/preconditions"),
    "verdict--blocked-after-execution-started.json": ("const", "/execution_started"),
    "verdict--not-evaluated-without-reason.json": ("contains", "/reason_codes"),
    "isolation-probe-run--passed-with-failed-probe.json": ("const", "/probes/8/outcome"),
    "isolation-probe-run--passed-without-preservation.json": ("const", "/preservation/outcome"),
    "isolation-probe-run--container-reported-pass.json": ("enum", "/probes/0/outcome"),
    "isolation-probe-run--unknown-field.json": ("additionalProperties", ""),
    "isolation-probe-run--negative-without-control.json": ("anyOf", "/probes/8"),
    "isolation-probe-run--floating-image.json": ("pattern", "/image/image_id"),
    "source-manifest--includes-uncommitted.json": ("const", "/uncommitted_changes_included"),
    "source-manifest--abbreviated-commit.json": ("pattern", "/commit_id"),
    "source-manifest--traversal-path.json": ("pattern", "/files/0/path"),
    "source-manifest--symlink-mode.json": ("enum", "/files/0/mode"),
    "source-manifest--loosened-file-limit.json": ("maximum", "/inclusion_profile/limits/max_file_bytes"),
    "source-manifest--sha1-length-in-sha256-manifest.json": ("pattern", "/commit_id"),
    "reference-fixture--claims-approval.json": ("const", "/approval_status"),
    "reference-fixture--abbreviated-commit.json": ("pattern", "/revisions/0/commit_id"),
    "reference-fixture--asgi-shell-fragment.json": ("pattern", "/target/asgi_app"),
    "reference-fixture--security-check-expects-pass.json": ("enum", "/checks/0/expected/vulnerable/semantic"),
    "reference-fixture--runtime-observation-field.json": ("additionalProperties", ""),
    "reference-fixture--no-deny-all-regression-control.json": ("contains", "/checks"),
    "reference-fixture--server-version-asserted.json": ("const", "/target/server/version"),
    "reference-fixture--security-check-without-marker.json": ("type", "/checks/1/protected_marker"),
    "reference-fixture--document-read-without-marker.json": ("type", "/checks/4/protected_marker"),
    "run-authorization--two-pairs.json": ("const", "/plan/repetitions/pairs"),
    "run-authorization--seeded-fixture.json": ("type", "/plan/fixture/seed"),
    "run-authorization--automatic-retry.json": ("const", "/plan/repetitions/automatic_retry"),
    "run-authorization--five-containers.json": ("const", "/plan/containers/max_creations"),
    "run-authorization--abbreviated-commit.json": ("pattern", "/plan/sources/baseline/commit_id"),
    "run-authorization--abbreviated-plan-hash.json": ("pattern", "/plan_sha256"),
    "run-authorization--unknown-field.json": ("additionalProperties", ""),
    "run-authorization--reusable.json": ("const", "/single_use"),
    "run-authorization--bridge-network.json": ("const", "/plan/runtime/network_policy"),
    "run-authorization--verified-reviewer.json": ("const", "/reviewer/basis"),
    "run-authorization--absolute-evidence-path.json": ("pattern", "/plan/evidence/destination"),
    "run-authorization--duplicate-key.json": ("duplicate_key", ""),
    "interruption-test-authorization--candidate-execution.json": ("const", "/plan/revision/candidate_execution"),
    "interruption-test-authorization--candidate-side.json": ("const", "/plan/revision/side"),
    "interruption-test-authorization--candidate-source.json": ("additionalProperties", "/plan/sources"),
    "interruption-test-authorization--three-containers.json": ("const", "/plan/containers/max_creations"),
    "interruption-test-authorization--two-started.json": ("const", "/plan/containers/max_started"),
    "interruption-test-authorization--verifier-started.json": ("const", "/plan/containers/verifier/start"),
    "interruption-test-authorization--bridge-network.json": ("const", "/plan/containers/target/network"),
    "interruption-test-authorization--sigkill.json": ("const", "/plan/interruption/signal"),
    "interruption-test-authorization--escalation.json": ("const", "/plan/interruption/escalation"),
    "interruption-test-authorization--two-signals.json": ("const", "/plan/interruption/signals_sent"),
    "interruption-test-authorization--long-wait.json": ("const", "/plan/interruption/synchronization_wait_seconds"),
    "interruption-test-authorization--automatic-retry.json": ("const", "/plan/interruption/automatic_retry"),
    "interruption-test-authorization--expects-verified.json": ("const", "/plan/expected_outcome/verdict"),
    "interruption-test-authorization--expects-finalized.json": ("const", "/plan/expected_outcome/evidence_status"),
    "interruption-test-authorization--wrong-exit-code.json": ("const", "/plan/expected_outcome/lifecycle_exit_code"),
    "interruption-test-authorization--run-authorization-kind.json": ("const", "/kind"),
    "interruption-test-authorization--run-authorization-id.json": ("pattern", "/authorization_id"),
    "interruption-test-authorization--ordinary-plan-kind.json": ("const", "/plan/plan_kind"),
    "interruption-test-authorization--reusable.json": ("const", "/single_use"),
    "interruption-test-authorization--ordinary-evidence-path.json": ("pattern", "/plan/evidence/destination"),
    "interruption-test-authorization--unknown-field.json": ("additionalProperties", ""),
    "interruption-test-authorization--duplicate-key.json": ("duplicate_key", ""),
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
    # A later contract version is a separate file named <record>.v<version>.schema.json (ADR-008).
    record, _, version = name.partition(".v")
    assert SCHEMAS[name]["$id"] == f"urn:patchproof:schema:{record}:{version or '1.0'}"


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
    if _scenario_dirs():
        covered |= {"verdict-input", "verdict"}
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


# ------------------------------------------------------------ scenario corpus

PRECONDITIONS = ("authorization", "pack_integrity", "source_identity", "environment_identity", "result_provenance")
SCENARIO_ROW = re.compile(r"^\| (S\d{2}) \| `([A-Za-z0-9-]+)` \| [^|]+ \| `([A-Z_]+)` \| (V-\d{2}) \|$")


def _scenario_dirs() -> list[Path]:
    return sorted(p for p in SCENARIO_DIR.iterdir() if p.is_dir()) if SCENARIO_DIR.exists() else []


def _scenario(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    (inp,) = load_records(path / "verdict-input.json")
    (out,) = load_records(path / "verdict.json")
    return inp, out


def _cell_keys(inp: dict[str, Any]) -> list[tuple[int, str, str]]:
    return [(o["pair"], o["side"], o["test_id"]) for o in inp["observations"]]


def test_scenario_table_in_spec_matches_corpus() -> None:
    rows = [m.groups() for line in VERDICT_SPEC.read_text(encoding="utf-8").splitlines() if (m := SCENARIO_ROW.match(line))]
    assert rows, "scenario table not found in verdict specification"
    on_disk = {}
    for path in _scenario_dirs():
        _, out = _scenario(path)
        on_disk[path.name] = (out["verdict"], out["decision_rule"])
    assert {name: (verdict, rule) for _, name, verdict, rule in rows} == on_disk
    assert all(name.startswith(sid + "-") for sid, name, _, _ in rows)


@pytest.mark.parametrize("path", _scenario_dirs(), ids=lambda p: p.name)
def test_scenario_records_validate(path: Path) -> None:
    inp, out = _scenario(path)
    for name, record in (("verdict-input", inp), ("verdict", out)):
        errors = [f"{_pointer(e)}: {e.message}" for e in validator_for(name).iter_errors(record)]
        assert errors == [], name


@pytest.mark.parametrize("path", _scenario_dirs(), ids=lambda p: p.name)
def test_scenario_expected_verdict_is_consistent_with_input(path: Path) -> None:
    inp, out = _scenario(path)
    tests = inp["pack_tests"]
    assert out["run_id"] == inp["run_id"]
    assert out["run_termination"] == inp["run_termination"]
    started = any(e["started"] for e in inp["executions"]) or bool(inp["observations"])
    assert out["execution_started"] is started
    counts = out["counts"]
    assert counts["security_tests"] == sum(t["kind"] == "security" for t in tests)
    assert counts["functional_tests"] == sum(t["kind"] == "functional" for t in tests)
    assert counts["pairs_planned"] == inp["pairs_planned"]
    assert counts["required_cells"] == 2 * inp["pairs_planned"] * len(tests)
    assert counts["pairs_with_trusted_evidence"] <= counts["pairs_terminated_normally"] <= counts["pairs_planned"]
    assert counts["trusted_cells"] <= counts["required_cells"]
    cells_per_pair = 2 * len(tests)
    assert counts["pairs_with_trusted_evidence"] * cells_per_pair <= counts["trusted_cells"]
    if out["verdict"] == "VERIFIED_FOR_CASES":
        assert counts["pairs_terminated_normally"] == counts["pairs_planned"]
        assert counts["pairs_with_trusted_evidence"] == counts["pairs_planned"]
        assert counts["trusted_cells"] == counts["required_cells"]
    for name in PRECONDITIONS:
        supplied, effective = inp["preconditions"][name]["state"], out["preconditions"][name]
        # The engine may only make a precondition stricter (input validation failure).
        assert effective == supplied or (name == "result_provenance" and effective == "FAILED")
    known = {(t["id"]) for t in tests}
    for detail in out["details"]:
        assert detail["test_id"] is None or detail["test_id"] in known
        assert detail["pair"] is None or detail["pair"] <= inp["pairs_planned"]


@pytest.mark.parametrize("path", _scenario_dirs(), ids=lambda p: p.name)
def test_result_cap_overflow_is_reported_per_execution(path: Path) -> None:
    """D6: an over-cap execution is identified by pair and side, judged from the host byte count."""
    inp, out = _scenario(path)
    cap = inp["result_cap_bytes"]
    over = {
        (e["pair"], e["side"])
        for e in inp["executions"]
        if e["stream"]["status"] == "OVER_CAP" or e["stream"]["bytes_received"] > cap
    }
    reported = {(d["pair"], d["side"]) for d in out["details"] if d["reason_code"] == "RESULT_CAP_EXCEEDED"}
    assert reported == over
    if over:
        assert out["verdict"] != "VERIFIED_FOR_CASES"
        assert out["flags"]["incomplete_checks"] is True
        assert out["counts"]["pairs_with_trusted_evidence"] <= inp["pairs_planned"] - len({p for p, _ in over})
        # Over-cap is local (D6): it never fails result_provenance on its own.
        if inp["preconditions"]["result_provenance"]["state"] == "PASSED" and out["preconditions"]["result_provenance"] == "FAILED":
            assert {"OBSERVATION_MATRIX_INVALID", "EXECUTION_EVIDENCE_INCONSISTENT", "EVENT_STREAM_MALFORMED",
                    "EVENT_STREAM_IDENTITY_MISMATCH"} & set(out["reason_codes"])


@pytest.mark.parametrize("path", _scenario_dirs(), ids=lambda p: p.name)
def test_duplicate_cells_only_where_expected_and_never_trusted(path: Path) -> None:
    inp, out = _scenario(path)
    keys = _cell_keys(inp)
    has_duplicate = len(keys) != len(set(keys))
    if has_duplicate:
        assert "OBSERVATION_MATRIX_INVALID" in out["reason_codes"]
        assert out["verdict"] == "INCONCLUSIVE" and out["decision_rule"] == "V-02"
        assert out["counts"]["trusted_cells"] == 0


# --------------------------------------------------------------- strict loader


def test_strict_loader_rejects_nested_duplicate_key() -> None:
    with pytest.raises(DuplicateKeyError):
        strict_loads('{"limits": {"case_timeout_seconds": 20, "case_timeout_seconds": 999}}')


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity"])
def test_strict_loader_rejects_non_finite_numbers(literal: str) -> None:
    with pytest.raises(ValueError, match="non-finite"):
        strict_loads(f'{{"cpus": {literal}}}')
