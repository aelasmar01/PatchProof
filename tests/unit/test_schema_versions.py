"""ADR-008: schema contracts are versioned and immutable.

execution-profile 1.0 (accepted in PP-002, commit 682ef63) stays addressable and unchanged
beside execution-profile 1.1 (owner-approved 2026-10-11). Neither validates the other's
records, so nothing is silently migrated or reinterpreted.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "schemas"
EXAMPLES = SCHEMAS / "examples"
# sha256 of schemas/execution-profile.schema.json as accepted at commit 682ef63.
ACCEPTED_V1_0_SHA256 = "7b72f549920327a8b8bd1aa0fd373c5d72163b58623696c973d5a48586234839"


def _validator(filename: str) -> Draft202012Validator:
    docs = [json.loads(p.read_text()) for p in SCHEMAS.glob("*.schema.json")]
    registry: Registry = Registry().with_resources((d["$id"], Resource.from_contents(d)) for d in docs)
    return Draft202012Validator(json.loads((SCHEMAS / filename).read_text()), registry=registry)


V10 = _validator("execution-profile.schema.json")
V11 = _validator("execution-profile.v1.1.schema.json")


def test_v1_0_contract_is_byte_identical_to_the_accepted_version() -> None:
    digest = hashlib.sha256((SCHEMAS / "execution-profile.schema.json").read_bytes()).hexdigest()
    assert digest == ACCEPTED_V1_0_SHA256


def test_versions_have_distinct_ids() -> None:
    assert V10.schema["$id"] == "urn:patchproof:schema:execution-profile:1.0"
    assert V11.schema["$id"] == "urn:patchproof:schema:execution-profile:1.1"


def test_each_version_accepts_only_its_own_records() -> None:
    v10_record = json.loads((EXAMPLES / "valid" / "execution-profile--papertrail-reference.json").read_text())
    v11_record = json.loads((EXAMPLES / "valid" / "execution-profile.v1.1--papertrail-reference.json").read_text())
    assert not list(V10.iter_errors(v10_record))
    assert not list(V11.iter_errors(v11_record))
    assert list(V11.iter_errors(v10_record)), "a 1.0 record must not validate as 1.1"
    assert list(V10.iter_errors(v11_record)), "a 1.1 record must not validate as 1.0"


def test_v1_1_sizes_are_the_approved_values() -> None:
    record = json.loads((EXAMPLES / "valid" / "execution-profile.v1.1--papertrail-reference.json").read_text())
    mib = 1024 * 1024
    assert record["resources"]["verifier"]["scratch_tmpfs_bytes"] == 112 * mib
    assert record["resources"]["verifier"]["tmp_tmpfs_bytes"] == 16 * mib
    assert record["resources"]["target"]["scratch_tmpfs_bytes"] == 256 * mib
    assert record["resources"]["target"]["tmp_tmpfs_bytes"] == 64 * mib
