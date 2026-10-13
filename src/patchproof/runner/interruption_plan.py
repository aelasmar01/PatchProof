"""The frozen plan for the deliberate interruption demonstration: PaperTrail r1, baseline only (PP-008).

It recomputes exactly one kind of plan, `papertrail-interruption-sigterm-baseline-v1`, from the
same private artifacts and with the same checks as `papertrail_plan.assemble_run` (whose
helpers it uses), and nothing else:
- **Pack and approval:** the current pack approval must be `APPROVED` for the recomputed
  bindings; the approved pack copy is re-hashed; its fixture must be the bound fixture.
- **Baseline only:** the one PP-005 snapshot of the pinned r1 commit, re-hashed, with the
  profile's exact source scope and the bound fixture hash. No candidate source is read or
  bound.
- **Images:** the approved r2 run images, in their roles.
- **Fixed test parameters:** two containers, one started, one SIGTERM at
  `baseline-target-ready`, the bounded waits and the expected outcome (constants of the
  record contract).

`assemble_interruption` never writes anything.

**No candidate.** The authorization, its plan document and the persisted evidence have no
candidate identity at all (the schema rejects a `sources.candidate` key). The accepted
comparison engine takes a `RunPlan`, whose dataclass has a candidate slot; the private
adapter `_BaselineOnlyEnginePlan` fills that slot with the very same baseline object, so the
engine's precondition check re-verifies the baseline and nothing else, and it refuses to
hand out a candidate source or stream identity. That refusal is a fourth guard, below the
three in `runner.interruption_run`: it happens before any container for a candidate could be
created. No record or evidence file is written from the slot.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

from ..core.interruption_authorizations import (
    InterruptionAuthorizationError,
    check_interruption_plan,
    interruption_container_names,
    interruption_evidence_destination,
    interruption_plan_sha256,
)
from ..core.records import RecordError, validate_record
from ..core.records.interruption import PLAN_KIND, InterruptionPlanDocument
from ..core.records.pack import ApprovalRecord
from ..pack_approval import ApprovalBlocked, Review, assemble_review
from .collector import StreamIdentity
from .inputs import InputIntegrityError, PackSnapshot, SourceSnapshot, verify_pack_snapshot
from .papertrail_plan import (
    _INSTALLATION_RE,
    PACK_FIXTURE_PATH,
    PAPERTRAIL_REVISIONS,
    PlanError,
    RunEnvironment,
    _approval,
    _read_small,
    _source,
)
from .policy import TARGET_LOOPBACK_HOST, TARGET_LOOPBACK_PORT, Ownership, PolicyViolation
from .run_plan import RunPlan
from .run_policy import RunRole, run_container_name

SYNCHRONIZATION_WAIT_SECONDS: Final = 30
CHECKPOINT_REPORT_TIMEOUT_SECONDS: Final = 600
CLEANUP_TIMEOUT_SECONDS: Final = 600


def interruption_environment() -> RunEnvironment:
    """The real locations. Separate authorization store and evidence root from ordinary runs."""
    from ..pack_approval import approval_store_root, data_root, papertrail_target

    data = data_root()
    return RunEnvironment(approval_target=papertrail_target(), approval_store=approval_store_root(),
                          authorization_store=data / "interruption-authorizations",
                          snapshot_store=data / "source-snapshots", pack_store=data / "pack-store",
                          evidence_root=data / "evidence" / "interruption-tests",
                          installation_id_file=data / "probe-runs" / "installation-id")


@dataclass(frozen=True)
class _BaselineOnlyEnginePlan(RunPlan):
    """Private compatibility adapter for the accepted engine: one pair, baseline only.

    `candidate` is the baseline object itself (never another snapshot); asking for the
    candidate's source or stream identity raises before anything is created.
    """

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.pairs != 1 or self.candidate is not self.baseline:
            raise PolicyViolation("the interruption plan is one pair and has no candidate source")

    def source(self, side: Literal["baseline", "candidate"]) -> SourceSnapshot:
        if side != "baseline":
            raise PolicyViolation("the interruption test has no candidate source")
        return self.baseline

    def stream_identity(self, pair: int, side: Literal["baseline", "candidate"]) -> StreamIdentity:
        if side != "baseline":
            raise PolicyViolation("the interruption test has no candidate stream")
        return super().stream_identity(pair, side)


@dataclass(frozen=True)
class AssembledInterruption:
    plan: RunPlan  # a `_BaselineOnlyEnginePlan`: engine input only, never written to evidence
    document: InterruptionPlanDocument
    sha256: str
    review: Review
    approvals: dict[str, ApprovalRecord]
    approval_raw: bytes
    source_manifest: bytes


def assemble_interruption(env: RunEnvironment, run_id: str) -> AssembledInterruption:
    """Recompute the complete interruption-test plan for `run_id` from the current artifacts. Read-only."""
    try:
        review = assemble_review(env.approval_target)
    except ApprovalBlocked as exc:
        raise PlanError("pack_integrity", "PACK_INTEGRITY_FAILED", f"pack approval bindings: {exc}") from None
    manifest = review.pack.manifest
    if manifest.repetitions.pairs != 1:
        raise PlanError("pack_integrity", "PACK_INTEGRITY_FAILED", "the interruption test supports exactly one pair")
    approval_id, history, approval_raw = _approval(env, review)
    pack = PackSnapshot(root=env.pack_store / review.pack.pack_tree_sha256.removeprefix("sha256:"),
                        pack_tree_sha256=review.pack.pack_tree_sha256, manifest_sha256=review.pack.manifest_sha256,
                        files=review.pack.files)
    try:
        verify_pack_snapshot(pack)
    except (InputIntegrityError, OSError) as exc:
        raise PlanError("pack_integrity", "PACK_INTEGRITY_FAILED", f"approved pack copy: {exc}") from None
    pack_fixture = [f for f in review.pack.files if f.path == PACK_FIXTURE_PATH]
    if len(pack_fixture) != 1 or pack_fixture[0].sha256 != env.fixture_sha256:
        raise PlanError("pack_integrity", "PACK_INTEGRITY_FAILED", "the pack's fixture differs from the bound hash")
    try:
        installation = _read_small(env.installation_id_file, 64).decode("ascii").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise PlanError("environment_identity", "RUNTIME_POLICY_FAILED", f"installation ID: {exc}") from None
    if not _INSTALLATION_RE.fullmatch(installation):
        raise PlanError("environment_identity", "RUNTIME_POLICY_FAILED", "installation ID is malformed")

    snapshot, source_manifest, source_raw = _source(env, "baseline", review)
    profile = review.profile.profile
    images = {a.role: a for a in env.approved_images}
    target, verifier = images.get(RunRole.TARGET), images.get(RunRole.VERIFIER)
    if target is None or verifier is None or len(env.approved_images) != 2:
        raise PlanError("environment_identity", "ENVIRONMENT_NONCOMPARABLE", "exactly one approved image per role")
    try:
        ownership = Ownership(installation_id=installation, run_id=run_id)
        plan = _BaselineOnlyEnginePlan(ownership=ownership, profile=profile, manifest=manifest, pack=pack,
                                       approval_id=approval_id, collection=review.collection, baseline=snapshot,
                                       candidate=snapshot, pairs=1, target_image=target, verifier_image=verifier)
    except PolicyViolation as exc:
        raise PlanError("environment_identity", "RUNTIME_POLICY_FAILED", f"run plan: {exc}") from None
    target_name, verifier_name = interruption_container_names(run_id)
    if (target_name, verifier_name) != (run_container_name(ownership, 1, "baseline", RunRole.TARGET),
                                        run_container_name(ownership, 1, "baseline", RunRole.VERIFIER)):
        raise PlanError("environment_identity", "RUNTIME_POLICY_FAILED", "container naming differs from the runner")
    inclusion = source_manifest.inclusion_profile
    pinned = env.revisions["baseline"]
    doc = {
        "plan_kind": PLAN_KIND, "run_id": run_id, "installation_id": installation, "pack_approval_id": approval_id,
        "pack": {"pack_id": manifest.pack_id, "pack_version": manifest.pack_version,
                 "manifest_sha256": review.pack.manifest_sha256, "pack_tree_sha256": review.pack.pack_tree_sha256,
                 "expected_collection": [c.model_dump() for c in review.collection],
                 "verifier_plugin_version": review.bindings.verifier_plugin_version},
        "profile": {"profile_id": profile.profile_id, "profile_version": profile.profile_version,
                    "profile_sha256": review.profile.sha256},
        "images": {"target_image_id": target.image.value, "verifier_image_id": verifier.image.value},
        "sources": {"baseline": {"tag": pinned.tag, "commit_id": source_manifest.commit_id,
                                 "tree_id": source_manifest.tree_id, "snapshot_name": snapshot.snapshot_dir.name,
                                 "source_manifest_sha256": snapshot.manifest_sha256,
                                 "source_tree_sha256": source_manifest.source_tree_sha256}},
        "source_inclusion": {"include": list(inclusion.include), "inclusion_profile_sha256": inclusion.sha256},
        "fixture": {"mode": "fixed-fixture-v0.1-exception", "fixture_contract": manifest.fixture_contract,
                    "fixture_sha256": env.fixture_sha256, "seed": None},
        "revision": {"pair": 1, "side": "baseline", "candidate_execution": False, "automatic_retry": False},
        "containers": {
            "max_creations": 2, "max_started": 1,
            "target": {"name": target_name, "network": "none",
                       "input_mount": "source-snapshot-read-only-at-/app/source",
                       "start": "after-pre-start-inspection-gate"},
            "verifier": {"name": verifier_name, "network": "container:exact-target-id",
                         "input_mount": "pack-read-only-at-/pack", "start": "never"},
            "cleanup": "exact-id-ownership-reverified-graceful-stop-then-remove-force-only-if-running"},
        "interruption": {"stage": "baseline-target-ready", "signal": "SIGTERM", "signals_sent": 1,
                         "escalation": "none", "channel": "controller-child-pipe-v1",
                         "synchronization_wait_seconds": SYNCHRONIZATION_WAIT_SECONDS,
                         "checkpoint_report_timeout_seconds": CHECKPOINT_REPORT_TIMEOUT_SECONDS,
                         "cleanup_timeout_seconds": CLEANUP_TIMEOUT_SECONDS, "automatic_retry": False},
        "expected_outcome": {"lifecycle": "INTERRUPTED", "evidence_status": "INCOMPLETE",
                             "cleanup_status": "COMPLETE", "verdict": "INCONCLUSIVE", "decision_rule": "V-05",
                             "lifecycle_exit_code": 20},
        "runtime": {"network_policy": profile.network_policy,
                    "target_address": f"{TARGET_LOOPBACK_HOST}:{TARGET_LOOPBACK_PORT}",
                    "resources": profile.resources.model_dump(mode="json"),
                    "timeouts": profile.timeouts.model_dump(mode="json"),
                    "logging": profile.logging.model_dump(mode="json"), "result_cap_bytes": profile.result_cap_bytes,
                    "case_timeout_seconds": manifest.limits.case_timeout_seconds,
                    "max_response_bytes": manifest.limits.max_response_bytes},
        "evidence": {"destination": interruption_evidence_destination(run_id)},
    }
    try:
        document = validate_record(InterruptionPlanDocument, doc, "interruption-plan")
        check_interruption_plan(document)
    except (RecordError, InterruptionAuthorizationError) as exc:
        raise PlanError("environment_identity", "RUNTIME_POLICY_FAILED", f"plan document: {exc}") from None
    check_interruption_scope(document)
    return AssembledInterruption(plan=plan, document=document, sha256=interruption_plan_sha256(document),
                                 review=review, approvals=dict(history), approval_raw=approval_raw,
                                 source_manifest=source_raw)


def check_interruption_scope(document: InterruptionPlanDocument) -> None:
    """This test's own revision rule: exactly the pinned r1 baseline (module constant, not the environment)."""
    pinned, bound = PAPERTRAIL_REVISIONS["baseline"], document.sources.baseline
    if (bound.tag, bound.commit_id, bound.tree_id) != (pinned.tag, pinned.commit_id, pinned.tree_id):
        raise PlanError("source_identity", "SOURCE_IDENTITY_MISMATCH",
                        f"the baseline is not the pinned r1 revision {pinned.commit_id}")


def interruption_plan_differences(frozen: InterruptionPlanDocument, current: InterruptionPlanDocument) -> list[str]:
    a, b = frozen.model_dump(mode="json"), current.model_dump(mode="json")
    return sorted(k for k in a if a[k] != b.get(k))
