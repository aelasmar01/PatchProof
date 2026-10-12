"""Pack manifest (schemas/pack-manifest.schema.json 1.0), execution profiles 1.0 and 1.1, and
pack approval records (schemas/approval-record.schema.json 1.0)."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AfterValidator, Field, StringConstraints, model_validator

from .common import (
    ApprovalId,
    ContainerLimitsV10,
    Identifier,
    ImageId,
    LongText,
    PytestNodeId,
    Record,
    RelativePath,
    SchemaVersion,
    Semver,
    Sha256,
    ShortText,
    TestId,
    TestKind,
    Timestamp,
    matches,
    unique_list,
)

Adapter = Literal["python-asgi-http-v1"]


class RequiredTest(Record):
    id: TestId
    nodeid: PytestNodeId
    kind: TestKind
    baseline_expected: Literal["VIOLATION_CONFIRMED", "SECURE", "PASS"]
    candidate_expected: Literal["SECURE", "PASS"]

    @model_validator(mode="after")
    def _expectations_match_kind(self) -> RequiredTest:
        if self.kind == "security" and (self.baseline_expected == "PASS" or self.candidate_expected != "SECURE"):
            raise ValueError("a security check expects VIOLATION_CONFIRMED or SECURE, and SECURE on the candidate")
        if self.kind == "functional" and (self.baseline_expected != "PASS" or self.candidate_expected != "PASS"):
            raise ValueError("a functional control must expect PASS on both revisions")
        return self


class Repetitions(Record):
    pairs: Annotated[int, Field(ge=1, le=10)]
    fixture_seed_policy: Literal["same-within-pair-different-between-pairs"]


class PackLimits(Record):
    max_response_bytes: Annotated[int, Field(ge=1, le=1048576)]
    case_timeout_seconds: Annotated[int, Field(ge=1, le=120)]


class PackManifest(Record):
    schema_version: SchemaVersion
    pack_id: Identifier
    pack_version: Semver
    title: ShortText
    expectation: LongText
    adapter: Adapter
    fixture_contract: Identifier
    tests: Annotated[list[RequiredTest], Field(min_length=2, max_length=200)]
    repetitions: Repetitions
    limits: PackLimits

    @model_validator(mode="after")
    def _can_verify_a_fix(self) -> PackManifest:
        if not any(t.kind == "functional" for t in self.tests):
            raise ValueError("INV-08: the pack needs at least one functional control")
        if not any(t.kind == "security" and t.baseline_expected == "VIOLATION_CONFIRMED" for t in self.tests):
            raise ValueError("INV-06: at least one security check must expect the baseline violation")
        return self


# ------------------------------------------------------------------ execution profiles

AsgiApp = Annotated[str, StringConstraints(max_length=200), matches(
    r"^[A-Za-z_][A-Za-z0-9_]{0,63}(\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,7}:[A-Za-z_][A-Za-z0-9_]{0,63}$")]


class SourceScopeRecord(Record):
    include: Annotated[list[RelativePath], Field(min_length=1, max_length=64),
                       AfterValidator(unique_list("source_scope.include"))]


class Timeouts(Record):
    readiness_seconds: Annotated[int, Field(ge=1, le=120)]
    request_connect_seconds: Annotated[float, Field(gt=0, le=30)]
    request_read_seconds: Annotated[float, Field(gt=0, le=30)]
    revision_deadline_seconds: Annotated[int, Field(ge=10, le=900)]
    cancellation_grace_seconds: Annotated[int, Field(ge=1, le=30)]


class Logging(Record):
    max_file_bytes: Annotated[int, Field(ge=65536, le=52428800)]
    max_files: Annotated[int, Field(ge=1, le=5)]


class ResourcesV10(Record):
    target: ContainerLimitsV10
    verifier: ContainerLimitsV10


class ExecutionProfileV10(Record):
    schema_version: SchemaVersion
    profile_id: Identifier
    profile_version: Semver
    adapter: Adapter
    target_image_id: ImageId
    verifier_image_id: ImageId
    asgi_app: AsgiApp
    fixture_contract: Identifier
    network_policy: Literal["none-shared-loopback-v1"]
    source_scope: SourceScopeRecord
    resources: ResourcesV10
    timeouts: Timeouts
    logging: Logging
    result_cap_bytes: Annotated[int, Field(ge=65536, le=52428800)]


class ContainerLimitsV11(Record):
    cpus: Annotated[float, Field(gt=0, le=4)]
    memory_bytes: Annotated[int, Field(ge=67108864, le=4294967296)]
    pids: Annotated[int, Field(ge=16, le=1024)]
    scratch_tmpfs_bytes: Annotated[int, Field(ge=1048576, le=1073741824)]
    tmp_tmpfs_bytes: Annotated[int, Field(ge=1048576, le=268435456)]


class ResourcesV11(Record):
    target: ContainerLimitsV11
    verifier: ContainerLimitsV11


class ExecutionProfileV11(Record):
    schema_version: Literal["1.1"]
    profile_id: Identifier
    profile_version: Semver
    adapter: Adapter
    target_image_id: ImageId
    verifier_image_id: ImageId
    asgi_app: AsgiApp
    fixture_contract: Identifier
    network_policy: Literal["none-shared-loopback-v1"]
    source_scope: SourceScopeRecord
    resources: ResourcesV11
    timeouts: Timeouts
    logging: Logging
    result_cap_bytes: Annotated[int, Field(ge=65536, le=52428800)]


# ------------------------------------------------------------------ approval records


class CollectedTest(Record):
    id: TestId
    nodeid: PytestNodeId


class ApprovalBindings(Record):
    pack_id: Identifier
    pack_version: Semver
    pack_schema_version: SchemaVersion
    manifest_sha256: Sha256
    pack_tree_sha256: Sha256
    expected_collection: Annotated[list[CollectedTest], Field(min_length=2, max_length=200)]
    verifier_image_id: ImageId
    verifier_plugin_version: Semver
    profile_id: Identifier
    profile_sha256: Sha256


class Reviewer(Record):
    asserted_identity: ShortText
    basis: Literal["local-assertion-unverified"]


class ApprovalRecord(Record):
    schema_version: SchemaVersion
    approval_id: ApprovalId
    kind: Literal["pack-approval"]
    created_at: Timestamp
    supersedes: ApprovalId | None
    bindings: ApprovalBindings
    reviewer: Reviewer
    rationale: LongText
    scope: LongText
