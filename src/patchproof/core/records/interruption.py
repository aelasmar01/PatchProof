"""Interruption-test authorization records (schemas/interruption-test-authorization.schema.json 1.0; PP-008).

A separate, versioned contract for ONE deliberate interruption demonstration. It is not a run
authorization and never authorizes a comparison: the ordinary `run-authorization` 1.0
contract (four containers, both sides) is unchanged and cannot express this test, and this
contract cannot express anything broader than it.

**What the plan fixes, all as constants:**
- **Revision:** exactly one, pair 1, baseline only. No candidate execution, no retry.
- **Containers:** at most two creations. The target starts after its pre-start inspection
  gate; the verifier is created and inspected but never started.
- **Interruption:** one SIGTERM, sent by the dedicated controller to its own runner child at
  the reviewed synchronization point (`baseline-target-ready`), over the controller-child
  pipe. A 30-second synchronization wait, bounded report and cleanup timeouts, no escalation
  to SIGKILL and no retry.
- **Expected outcome:** lifecycle `INTERRUPTED`, evidence `INCOMPLETE`, cleanup `COMPLETE`,
  the accepted engine's `INCONCLUSIVE` by rule `V-05`, and lifecycle exit code 20
  (PROJECT_SPEC.md 13.2). These are expectations to compare against, never results.

The pack, profile, images, baseline source, source inclusion and runtime sections reuse the
`run-authorization` 1.0 definitions unchanged (the JSON Schema references them). Semantic
checks that need computation (the plan hash, the container names and the evidence path
derived from the run ID) are in `core.interruption_authorizations`.
"""

from __future__ import annotations

from typing import Annotated, Literal

from .authorization import PlanImages, PlanInclusion, PlanPack, PlanProfile, PlanRuntime, PlanSource
from .common import (
    ApprovalId,
    FalseOnly,
    Identifier,
    LongText,
    Record,
    RunId,
    SchemaVersion,
    Sha256,
    Timestamp,
    TrueOnly,
    matches,
    one_of_ints,
)
from .pack import Reviewer

InterruptionAuthorizationId = Annotated[str, matches(r"^iau-[0-9a-f]{32}$")]
InstallationId = Annotated[str, matches(r"^inst-[0-9a-f]{32}$")]
TargetName = Annotated[str, matches(r"^pp-run-[0-9a-f]{12}-p1-baseline-target$")]
VerifierName = Annotated[str, matches(r"^pp-run-[0-9a-f]{12}-p1-baseline-verifier$")]
InterruptionEvidenceDestination = Annotated[str, matches(r"^evidence/interruption-tests/run-[0-9a-f]{32}$")]

PLAN_KIND = "papertrail-interruption-sigterm-baseline-v1"


class InterruptionSources(Record):
    baseline: PlanSource


class InterruptionFixture(Record):
    mode: Literal["fixed-fixture-v0.1-exception"]
    fixture_contract: Identifier
    fixture_sha256: Sha256
    seed: None


class InterruptionRevision(Record):
    pair: Annotated[int, one_of_ints(1)]
    side: Literal["baseline"]
    candidate_execution: FalseOnly
    automatic_retry: FalseOnly


class InterruptionTarget(Record):
    name: TargetName
    network: Literal["none"]
    input_mount: Literal["source-snapshot-read-only-at-/app/source"]
    start: Literal["after-pre-start-inspection-gate"]


class InterruptionVerifier(Record):
    name: VerifierName
    network: Literal["container:exact-target-id"]
    input_mount: Literal["pack-read-only-at-/pack"]
    start: Literal["never"]


class InterruptionContainers(Record):
    max_creations: Annotated[int, one_of_ints(2)]
    max_started: Annotated[int, one_of_ints(1)]
    target: InterruptionTarget
    verifier: InterruptionVerifier
    cleanup: Literal["exact-id-ownership-reverified-graceful-stop-then-remove-force-only-if-running"]


class InterruptionSignal(Record):
    stage: Literal["baseline-target-ready"]
    signal: Literal["SIGTERM"]
    signals_sent: Annotated[int, one_of_ints(1)]
    escalation: Literal["none"]
    channel: Literal["controller-child-pipe-v1"]
    synchronization_wait_seconds: Annotated[int, one_of_ints(30)]
    checkpoint_report_timeout_seconds: Annotated[int, one_of_ints(600)]
    cleanup_timeout_seconds: Annotated[int, one_of_ints(600)]
    automatic_retry: FalseOnly


class InterruptionExpectation(Record):
    lifecycle: Literal["INTERRUPTED"]
    evidence_status: Literal["INCOMPLETE"]
    cleanup_status: Literal["COMPLETE"]
    verdict: Literal["INCONCLUSIVE"]
    decision_rule: Literal["V-05"]
    lifecycle_exit_code: Annotated[int, one_of_ints(20)]


class InterruptionEvidence(Record):
    destination: InterruptionEvidenceDestination


class InterruptionPlanDocument(Record):
    plan_kind: Literal["papertrail-interruption-sigterm-baseline-v1"]
    run_id: RunId
    installation_id: InstallationId
    pack_approval_id: ApprovalId
    pack: PlanPack
    profile: PlanProfile
    images: PlanImages
    sources: InterruptionSources
    source_inclusion: PlanInclusion
    fixture: InterruptionFixture
    revision: InterruptionRevision
    containers: InterruptionContainers
    interruption: InterruptionSignal
    expected_outcome: InterruptionExpectation
    runtime: PlanRuntime
    evidence: InterruptionEvidence


class InterruptionTestAuthorization(Record):
    schema_version: SchemaVersion
    kind: Literal["interruption-test-authorization"]
    authorization_id: InterruptionAuthorizationId
    created_at: Timestamp
    supersedes: InterruptionAuthorizationId | None
    single_use: TrueOnly
    plan_sha256: Sha256
    plan: InterruptionPlanDocument
    reviewer: Reviewer
    rationale: LongText
    scope: LongText
