"""Run authorization records (schemas/run-authorization.schema.json 1.0; PROJECT_SPEC.md 7.5; PP-008).

A run authorization is the owner's explicit, single-use permission to execute exactly one
frozen comparison plan. It is separate from, and never implied by, a pack approval.

The plan is closed and fully explicit: every identity is a full hash or full Git object ID,
and the fixed parts of the first PaperTrail demonstration are constants (one pair, fixed
fixture, four containers, sequential, no retry, stop the candidate after a baseline
execution failure). Semantic checks that need computation, such as the plan hash and the
container names derived from the run ID, are in `core.run_authorizations`; the model and
the JSON Schema accept and reject the same documents.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AfterValidator, Field

from .common import (
    ApprovalId,
    CommitId,
    FalseOnly,
    Identifier,
    ImageId,
    LongText,
    PytestNodeId,
    Record,
    RelativePath,
    RunId,
    SchemaVersion,
    Semver,
    Sha256,
    Side,
    TestId,
    Timestamp,
    TrueOnly,
    matches,
    one_of_ints,
    unique_list,
)
from .pack import Logging, ResourcesV11, Reviewer, Timeouts

RunAuthorizationId = Annotated[str, matches(r"^rau-[0-9a-f]{32}$")]
InstallationId = Annotated[str, matches(r"^inst-[0-9a-f]{32}$")]
TagRef = Annotated[str, matches(r"^refs/tags/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")]
SnapshotName = Annotated[str, matches(r"^snapshot-[0-9a-f]{32}$")]
ContainerName = Annotated[str, matches(r"^pp-run-[0-9a-f]{12}-p1-(baseline|candidate)-(target|verifier)$")]
EvidenceDestination = Annotated[str, matches(r"^evidence/runs/run-[0-9a-f]{32}$")]


class PlanTest(Record):
    id: TestId
    nodeid: PytestNodeId


class PlanPack(Record):
    pack_id: Identifier
    pack_version: Semver
    manifest_sha256: Sha256
    pack_tree_sha256: Sha256
    expected_collection: Annotated[list[PlanTest], Field(min_length=2, max_length=200),
                                   AfterValidator(unique_list("expected_collection"))]
    verifier_plugin_version: Semver


class PlanProfile(Record):
    profile_id: Identifier
    profile_version: Semver
    profile_sha256: Sha256


class PlanImages(Record):
    target_image_id: ImageId
    verifier_image_id: ImageId


class PlanSource(Record):
    tag: TagRef
    commit_id: CommitId
    tree_id: CommitId
    snapshot_name: SnapshotName
    source_manifest_sha256: Sha256
    source_tree_sha256: Sha256


class PlanSources(Record):
    baseline: PlanSource
    candidate: PlanSource


class PlanInclusion(Record):
    include: Annotated[list[RelativePath], Field(min_length=1, max_length=64),
                       AfterValidator(unique_list("include"))]
    inclusion_profile_sha256: Sha256


class PlanFixture(Record):
    mode: Literal["fixed-fixture-v0.1-exception"]
    fixture_contract: Identifier
    fixture_sha256: Sha256
    seed: None
    identical_for_both_sides: TrueOnly
    fresh_target_per_side: TrueOnly


def _sides_in_order(value: list[str]) -> list[str]:
    if value != ["baseline", "candidate"]:
        raise ValueError("the order is baseline, then candidate")
    return value


class PlanRepetitions(Record):
    pairs: Annotated[int, one_of_ints(1)]
    order: Annotated[list[Side], AfterValidator(_sides_in_order)]
    sequential: TrueOnly
    automatic_retry: FalseOnly


class PlanContainer(Record):
    side: Side
    role: Literal["target", "verifier"]
    name: ContainerName


class PlanContainers(Record):
    max_creations: Annotated[int, one_of_ints(4)]
    sequence: Annotated[list[PlanContainer], Field(min_length=4, max_length=4),
                        AfterValidator(unique_list("sequence"))]


class PlanRuntime(Record):
    network_policy: Literal["none-shared-loopback-v1"]
    target_address: Literal["127.0.0.1:8080"]
    resources: ResourcesV11
    timeouts: Timeouts
    logging: Logging
    result_cap_bytes: Annotated[int, Field(ge=65536, le=52428800)]
    case_timeout_seconds: Annotated[int, Field(ge=1, le=120)]
    max_response_bytes: Annotated[int, Field(ge=1, le=1048576)]


class PlanEvidence(Record):
    destination: EvidenceDestination


class RunPlanDocument(Record):
    plan_kind: Literal["papertrail-authz-r1-r3-one-pair-v1"]
    run_id: RunId
    installation_id: InstallationId
    pack_approval_id: ApprovalId
    pack: PlanPack
    profile: PlanProfile
    images: PlanImages
    sources: PlanSources
    source_inclusion: PlanInclusion
    fixture: PlanFixture
    repetitions: PlanRepetitions
    baseline_failure_policy: Literal["stop-before-candidate-on-execution-failure"]
    containers: PlanContainers
    runtime: PlanRuntime
    evidence: PlanEvidence


class RunAuthorization(Record):
    schema_version: SchemaVersion
    kind: Literal["run-authorization"]
    authorization_id: RunAuthorizationId
    created_at: Timestamp
    supersedes: RunAuthorizationId | None
    single_use: TrueOnly
    plan_sha256: Sha256
    plan: RunPlanDocument
    reviewer: Reviewer
    rationale: LongText
    scope: LongText
