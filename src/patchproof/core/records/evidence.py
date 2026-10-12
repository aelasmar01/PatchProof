"""Evidence records: isolation probe runs, source manifests, and reference fixtures
(schemas isolation-probe-run, source-manifest and reference-fixture, all 1.0)."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AfterValidator, Field, StringConstraints, model_validator

from .common import (
    CommitId,
    FalseOnly,
    Identifier,
    ImageId,
    LongText,
    Record,
    RelativePath,
    RunId,
    SchemaVersion,
    Semver,
    Sha256,
    ShortText,
    TestId,
    Timestamp,
    TrueOnly,
    matches,
    one_of_ints,
    unique_list,
)
from .pack import AsgiApp, SourceScopeRecord

# ------------------------------------------------------------------ isolation probe run

ProbeId = Annotated[str, matches(r"^(PRE|NET|FS|PRV|NS|RES|POL|CLN)-(P?[0-9]{1,2})$")]
Role = Literal["target", "verifier", "memory", "pids", "cpu", "storage", "logflood", "sleeper", "decoy-other-run",
               "decoy-foreign"]
ProbeOutcome = Literal["PASS", "FAIL", "INCONCLUSIVE", "ERROR", "BLOCKED", "NOT_RUN"]


class DockerFacts(Record):
    context: Literal["desktop-linux"]
    server_version: Annotated[str, StringConstraints(max_length=32), matches(r"^[0-9A-Za-z.+-]+$")] | None


class ImageFacts(Record):
    image_id: ImageId
    repo_digests: Annotated[list[ShortText], Field(max_length=8)]
    os: Literal["linux"]
    architecture: Literal["amd64"]


class ProbeAuthorization(Record):
    a2_image_approved: bool
    a3_evidence_root_verified: bool
    a4_operator_confirmed: bool


class GateMismatch(Record):
    field: ShortText
    expected: LongText
    observed: LongText


class Gate(Record):
    passed: bool | None
    mismatches: Annotated[list[GateMismatch], Field(max_length=64)]


class ProbeStream(Record):
    observations: Annotated[int, Field(ge=0, le=400)]
    ended: bool
    truncated: bool
    malformed_lines: Annotated[int, Field(ge=0)]
    foreign_records: Annotated[int, Field(ge=0)]
    duplicates: Annotated[list[ProbeId], Field(max_length=32)]


class Cleanup(Record):
    status: Literal["REMOVED", "FORCE_REMOVED", "ALREADY_ABSENT", "REFUSED", "FAILED", "NOT_CREATED"]
    detail: Annotated[str, StringConstraints(max_length=400), matches(r"^[^\x00-\x1f\x7f]*$")]


class Container(Record):
    role: Role
    name: Annotated[str, matches(r"^pp-(probe|decoy)-[0-9a-f]{12}-[a-z][a-z0-9-]{0,23}$")]
    container_id: Annotated[str, matches(r"^[0-9a-f]{64}$")] | None
    requested_policy_sha256: Sha256
    gate: Gate
    started: bool
    exit_code: Annotated[int, Field(ge=-1, le=255)] | None
    oom_killed: bool | None
    wait_timed_out: bool
    stream: ProbeStream | None
    error: LongText | None
    cleanup: Cleanup


class Probe(Record):
    probe_id: ProbeId
    title: ShortText
    category: Literal["preflight", "network", "filesystem", "privilege", "namespace", "resource", "policy", "cleanup"]
    kind: Literal["negative", "positive_control", "configuration", "policy_refusal", "cleanup"]
    evidence_type: Literal["behavioral", "kernel_state", "inspect", "host_check"]
    critical: bool
    controls: Annotated[list[ProbeId], Field(max_length=8)]
    internal_control: ShortText | None
    expected: LongText
    outcome: ProbeOutcome
    observed: LongText
    roles: Annotated[list[Role], Field(max_length=4), AfterValidator(unique_list("roles"))]

    @model_validator(mode="after")
    def _negative_has_control(self) -> Probe:
        if self.kind == "negative" and not self.controls and self.internal_control is None:
            raise ValueError("a negative probe names a positive control or an internal control")
        return self


class ControlClaim(Record):
    control: Identifier
    status: Literal["ENFORCEMENT_EXERCISED", "CONFIGURED_ONLY", "FAILED", "UNVERIFIED"]
    probes: Annotated[list[ProbeId], Field(min_length=1, max_length=16)]


class Preservation(Record):
    outcome: Literal["PASS", "FAIL", "NOT_RUN"]
    differences: Annotated[list[LongText], Field(max_length=64)]


class ProbeExecution(Record):
    global_deadline_seconds: Annotated[float, Field(ge=0, le=1200)]
    cleanup_window_seconds: Annotated[float, Field(ge=0, le=120)]
    active_elapsed_seconds: Annotated[float, Field(ge=0, le=1000000)]
    deadline_expired: bool
    expired_during_phase: Annotated[str, matches(r"^[a-z-]{1,32}$")] | None
    interrupted: bool
    cleanup_window_expired: bool
    cleanup_status: Literal["COMPLETE", "CLEANUP_FAILED", "NOT_NEEDED"]


class IsolationProbeRun(Record):
    schema_version: SchemaVersion
    record_type: Literal["isolation-probe-run"]
    suite_version: Literal["pp-003-probes-1.0"]
    run_id: RunId
    installation_id: Annotated[str, matches(r"^inst-[0-9a-f]{32}$")]
    started_at: Timestamp
    finished_at: Timestamp
    docker: DockerFacts
    image: ImageFacts | None
    probe_script_sha256: Sha256
    authorization: ProbeAuthorization
    containers: Annotated[list[Container], Field(max_length=16)]
    probes: Annotated[list[Probe], Field(min_length=1, max_length=128)]
    control_claims: Annotated[list[ControlClaim], Field(min_length=1, max_length=64)]
    preservation: Preservation
    execution: ProbeExecution
    suite_status: Literal["ALL_PLANNED_PROBES_PASSED", "ISOLATION_FAILED", "HARNESS_INVALID", "BLOCKED", "INCOMPLETE",
                          "NOT_EXECUTED"]
    limitations: Annotated[list[LongText], Field(min_length=1, max_length=32)]

    @model_validator(mode="after")
    def _passed_means_everything_passed(self) -> IsolationProbeRun:
        if self.suite_status != "ALL_PLANNED_PROBES_PASSED":
            return self
        a, e = self.authorization, self.execution
        if (any(p.outcome != "PASS" for p in self.probes) or self.preservation.outcome != "PASS"
                or not (a.a2_image_approved and a.a3_evidence_root_verified and a.a4_operator_confirmed)
                or self.image is None
                or any(c.status not in ("ENFORCEMENT_EXERCISED", "CONFIGURED_ONLY") for c in self.control_claims)
                or e.deadline_expired or e.interrupted or e.cleanup_status != "COMPLETE"):
            raise ValueError("ALL_PLANNED_PROBES_PASSED requires every probe, claim and cleanup to pass")
        return self


# ------------------------------------------------------------------ source manifest

TreePath = Annotated[str, StringConstraints(min_length=1, max_length=4096),
                     matches(r"^(?!/)(?!.*//)(?!.*/$)(?!(.*/)?\.{1,2}(/|$))[^\x00-\x1f\x7f\\]+$")]


class SnapshotLimitsRecord(Record):
    max_total_bytes: Annotated[int, Field(ge=1, le=104857600)]
    max_entries: Annotated[int, Field(ge=1, le=20000)]
    max_file_bytes: Annotated[int, Field(ge=1, le=10485760)]


class InclusionProfile(Record):
    include: Annotated[list[RelativePath], Field(min_length=1, max_length=64), AfterValidator(unique_list("include"))]
    secret_policy: Literal["secret-files-1"]
    limits: SnapshotLimitsRecord
    sha256: Sha256


class Totals(Record):
    file_count: Annotated[int, Field(ge=1, le=20000)]
    total_bytes: Annotated[int, Field(ge=0, le=104857600)]
    excluded_count: Annotated[int, Field(ge=0, le=100000)]


class ManifestFile(Record):
    path: TreePath
    mode: Literal["100644", "100755"]
    git_object_id: CommitId
    size_bytes: Annotated[int, Field(ge=0, le=10485760)]
    sha256: Sha256


class ManifestExclusion(Record):
    path: TreePath
    reason: Literal["OUTSIDE_SOURCE_SCOPE", "SECRET_FILE_POLICY"]
    mode: Annotated[str, matches(r"^[0-7]{6}$")]


class SourceManifest(Record):
    schema_version: SchemaVersion
    kind: Literal["source-manifest"]
    object_format: Literal["sha1", "sha256"]
    requested_revision: Annotated[str, StringConstraints(max_length=255), matches(
        r"^([0-9a-f]{40}|[0-9a-f]{64}|refs/(heads|tags)/[A-Za-z0-9_][A-Za-z0-9_.+/-]{0,240})$")]
    commit_id: CommitId
    tree_id: CommitId
    git_version: Semver
    inclusion_profile: InclusionProfile
    uncommitted_changes_included: FalseOnly
    complete_commit: bool
    totals: Totals
    source_tree_sha256: Sha256
    files: Annotated[list[ManifestFile], Field(min_length=1, max_length=20000)]
    excluded: Annotated[list[ManifestExclusion], Field(max_length=100000)]

    @model_validator(mode="after")
    def _ids_match_object_format(self) -> SourceManifest:
        length = 40 if self.object_format == "sha1" else 64
        ids = [self.commit_id, self.tree_id, *(f.git_object_id for f in self.files)]
        if any(len(i) != length for i in ids):
            raise ValueError(f"object IDs must have {length} hex digits for {self.object_format}")
        return self


# ------------------------------------------------------------------ reference fixture

RevisionKey = Literal["vulnerable", "inadequate", "correct", "deny-all"]


class FixtureServer(Record):
    name: Literal["uvicorn"]
    version: Literal["UNRESOLVED"]


class FixtureTarget(Record):
    adapter: Literal["python-asgi-http-v1"]
    asgi_app: AsgiApp
    python_version: Literal["3.13"]
    third_party_runtime_dependencies: Annotated[list[object], Field(max_length=0)]
    server: FixtureServer
    bind_address: Literal["127.0.0.1:8080"]
    readiness_path: Literal["/health"]
    network_policy: Literal["none-shared-loopback-v1"]
    fixture_contract: Identifier
    fixture_file: RelativePath
    fixture_sha256: Sha256
    data_reset: Literal["immutable-fixture-fresh-process"]
    source_scope: SourceScopeRecord
    unresolved_bindings: Annotated[
        list[Literal["target_image_id", "verifier_image_id", "server_version", "dependency_lock"]],
        Field(min_length=1), AfterValidator(unique_list("unresolved_bindings"))]


class FixtureRepository(Record):
    generator: Literal["patchproof.reference.papertrail"]
    generator_version: Semver
    object_format: Literal["sha1"]
    head: Literal["refs/heads/main"]
    tag_kind: Literal["annotated"]
    varying_file: RelativePath


class FixtureCaller(Record):
    caller_id: Identifier
    user_id: Annotated[str, matches(r"^u-[a-z]{1,32}$")] | None
    authorization: Literal["fixture-bearer", "none", "invalid-bearer"]
    presented_token: Annotated[str, matches(r"^pt-synthetic-[a-z]{1,16}-[0-9a-f]{12}$")] | None
    description: ShortText


class FixtureRevision(Record):
    key: RevisionKey
    role: Literal["vulnerable-baseline", "inadequate-fix", "correct-fix", "deny-all-regression"]
    tag: Annotated[str, matches(r"^refs/tags/authz-r[1-4]-[a-z-]{1,32}$")]
    tag_object_id: CommitId
    commit_id: CommitId
    tree_id: CommitId
    parent: RevisionKey | None
    authz_sha256: Sha256
    intent: LongText


class ExpectedOutcome(Record):
    semantic: Literal["VIOLATION_CONFIRMED", "SECURE", "PASS", "FAIL"]
    status: Annotated[int, one_of_ints(200, 401, 404)]
    marker_disclosed: bool


class ExpectedByRevision(Record):
    vulnerable: ExpectedOutcome
    inadequate: ExpectedOutcome
    correct: ExpectedOutcome
    deny_all: ExpectedOutcome = Field(alias="deny-all")

    def outcomes(self) -> tuple[ExpectedOutcome, ...]:
        return self.vulnerable, self.inadequate, self.correct, self.deny_all


class FixtureCheck(Record):
    id: TestId
    kind: Literal["security", "functional"]
    caller: Identifier
    method: Literal["GET"]
    path: Annotated[str, StringConstraints(max_length=100), matches(r"^/(me|documents/doc-[a-z]{1,16}-[a-z]{1,16})$")]
    protected_marker: Annotated[str, matches(r"^PT-PROTECTED-[A-Z]{1,16}-[0-9a-f]{12}$")] | None
    description: ShortText
    expected: ExpectedByRevision

    @model_validator(mode="after")
    def _witness_rules(self) -> FixtureCheck:
        allowed = ("VIOLATION_CONFIRMED", "SECURE") if self.kind == "security" else ("PASS", "FAIL")
        if any(o.semantic not in allowed for o in self.expected.outcomes()):
            raise ValueError("expected outcome does not fit the check kind")
        if (self.kind == "security" or self.path.startswith("/documents/")) and self.protected_marker is None:
            raise ValueError("security checks and document reads name their protected marker")
        return self


class FixtureComparison(Record):
    baseline: Literal["vulnerable"]
    candidate: RevisionKey
    expected_verdict: Literal["NOT_FIXED", "VERIFIED_FOR_CASES", "REGRESSION_DETECTED"]
    basis: LongText


class ReferenceFixture(Record):
    schema_version: SchemaVersion
    kind: Literal["reference-fixture"]
    fixture_id: Identifier
    fixture_version: Semver
    synthetic: TrueOnly
    approval_status: Literal["NOT_APPROVED"]
    declared_expectations_only: TrueOnly
    family: Literal["object-level-authorization"]
    target: FixtureTarget
    repository: FixtureRepository
    callers: Annotated[list[FixtureCaller], Field(min_length=1, max_length=16)]
    revisions: Annotated[list[FixtureRevision], Field(min_length=4, max_length=4)]
    checks: Annotated[list[FixtureCheck], Field(min_length=2, max_length=32)]
    comparisons: Annotated[list[FixtureComparison], Field(min_length=4, max_length=4)]
    limitations: Annotated[list[LongText], Field(min_length=1, max_length=32)]

    @model_validator(mode="after")
    def _corpus_rules(self) -> ReferenceFixture:
        if not any(c.kind == "security" and c.expected.vulnerable.semantic == "VIOLATION_CONFIRMED"
                   for c in self.checks):
            raise ValueError("INV-06: a security check must expect the baseline violation")
        if not any(c.kind == "functional" and c.expected.deny_all.semantic == "FAIL" for c in self.checks):
            raise ValueError("INV-08: a functional control must expose the deny-all regression")
        return self
