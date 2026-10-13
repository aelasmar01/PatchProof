"""The frozen plan for the first PaperTrail comparison: r1 (vulnerable) versus r3 (correct) (PP-008).

This module is deliberately narrow. It recomputes exactly one kind of plan,
`papertrail-authz-r1-r3-one-pair-v1`, from the real private artifacts, and nothing else:
- **Pack and approval:** the PP-007/PP-008 binding recomputation
  (`pack_approval.assemble_review`); the current pack approval must be `APPROVED` for exactly
  those bindings, with an unambiguous supersession history.
- **Profile and runtime:** the versioned profile through the strict loader; every runtime
  value equals what the runner enforces (`run_plan.FIXED_PROFILE_RUNTIME`).
- **Inputs:** the existing content-addressed pack copy, re-hashed; the two PP-005 source
  snapshots, found in the private snapshot store by their full commit IDs and re-hashed
  against their manifests. Nothing is created or regenerated here.
- **Fixture (owner decision D1, 2026-10-13):** fixed-fixture mode. One pair, no seed, the
  exact `synthetic-documents-v1` SHA-256, identical for both sides, a fresh target container
  per side. A plan with more than one pair is refused: different seeds across repetitions are
  not supported (PP-019).
- **Images:** the approved r2 run images, in their roles.

`assemble_run` either returns the complete plan and its canonical `RunPlanDocument`, or
raises `PlanError` naming the verdict precondition that the failure belongs to. It never
writes anything.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Literal

from ..core.approvals import ApprovalError, ApprovalStore, check_approval, current_approval
from ..core.records import RecordError, load_record, validate_record
from ..core.records.authorization import RunPlanDocument
from ..core.records.evidence import SourceManifest
from ..core.records.pack import ApprovalRecord
from ..core.run_authorizations import RunAuthorizationError, check_plan_semantics, container_names, plan_sha256
from ..git.snapshot import MANIFEST_NAME
from ..pack_approval import ApprovalBlocked, ApprovalTarget, Review, assemble_review, papertrail_target
from .inputs import InputIntegrityError, PackSnapshot, SourceSnapshot, verify_pack_snapshot, verify_source_snapshot
from .policy import TARGET_LOOPBACK_HOST, TARGET_LOOPBACK_PORT, Ownership, PolicyViolation
from .run_plan import APPROVED_RUN_IMAGES, ApprovedRunImage, RunPlan, check_source_scope
from .run_policy import RunRole, run_container_name

Side = Literal["baseline", "candidate"]
SIDES: Final[tuple[Side, Side]] = ("baseline", "candidate")
PLAN_KIND: Final = "papertrail-authz-r1-r3-one-pair-v1"


@dataclass(frozen=True)
class PinnedRevision:
    tag: str
    commit_id: str
    tree_id: str


# Accepted PP-006 reference identities (examples/papertrail/reference-fixture.json; a test
# asserts equality). Review-controlled.
PAPERTRAIL_REVISIONS: Final[Mapping[Side, PinnedRevision]] = {
    "baseline": PinnedRevision("refs/tags/authz-r1-vulnerable", "68b2bc0e41cb7e9a074b09f2d97db3e2d2ca288a",
                               "f4a27893dc96e01b42e4b0da27cb2de5977c6063"),
    "candidate": PinnedRevision("refs/tags/authz-r3-correct", "2fb6d09378906f1df69ac32b862df4a350e8a56d",
                                "eb22f1bf9e8680971fac0af28c0557b117314803"),
}
FIXTURE_SHA256: Final = "sha256:2cbcf118fddb2cd4e38a9af5e8786911e8f85e292e637102799fd60513129eda"
SOURCE_FIXTURE_PATH: Final = "fixtures/synthetic/synthetic-documents-v1.json"
PACK_FIXTURE_PATH: Final = "fixtures/synthetic-documents-v1.json"
_SNAPSHOT_RE: Final = re.compile(r"snapshot-[0-9a-f]{32}")
_INSTALLATION_RE: Final = re.compile(r"inst-[0-9a-f]{32}")

PreconditionName = Literal["authorization", "pack_integrity", "source_identity", "environment_identity"]


class PlanError(ValueError):
    """The plan cannot be assembled from the current inputs. Names the failing precondition."""

    def __init__(self, precondition: PreconditionName, code: str, message: str) -> None:
        self.precondition = precondition
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class RunEnvironment:
    """Where every input lives. `papertrail_environment()` is the real one; tests use temporary copies."""

    approval_target: ApprovalTarget
    approval_store: Path
    authorization_store: Path
    snapshot_store: Path
    pack_store: Path
    evidence_root: Path  # <user data>/evidence/runs
    installation_id_file: Path
    approved_images: tuple[ApprovedRunImage, ...] = APPROVED_RUN_IMAGES
    revisions: Mapping[Side, PinnedRevision] = field(default_factory=lambda: dict(PAPERTRAIL_REVISIONS))
    fixture_sha256: str = FIXTURE_SHA256


def papertrail_environment() -> RunEnvironment:
    from ..pack_approval import approval_store_root, data_root

    data = data_root()
    return RunEnvironment(approval_target=papertrail_target(), approval_store=approval_store_root(),
                          authorization_store=data / "run-authorizations", snapshot_store=data / "source-snapshots",
                          pack_store=data / "pack-store", evidence_root=data / "evidence" / "runs",
                          installation_id_file=data / "probe-runs" / "installation-id")


@dataclass(frozen=True)
class AssembledRun:
    plan: RunPlan
    document: RunPlanDocument
    sha256: str
    review: Review
    approvals: Mapping[str, ApprovalRecord]
    approval_raw: bytes
    source_manifests: Mapping[Side, bytes]


def _read_small(path: Path, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise OSError(f"{path.name} is not a regular file")
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise OSError(f"{path.name} exceeds its size limit")
    return data


def _approval(env: RunEnvironment, review: Review) -> tuple[str, dict[str, ApprovalRecord], bytes]:
    try:
        store = ApprovalStore(env.approval_store)
        history = store.records()
        current = current_approval(history.values(), review.bindings.pack_id)
    except ApprovalError as exc:
        raise PlanError("authorization", "APPROVAL_MISSING", f"pack approval store: {exc}") from None
    if current is None:
        raise PlanError("authorization", "APPROVAL_MISSING", "the pack has no current approval")
    check = check_approval(history.values(), review.inputs, approval_id=current.approval_id)
    if check.status != "APPROVED":
        raise PlanError("authorization", check.status,
                        f"pack approval {current.approval_id} is {check.status} {list(check.stale_fields)}")
    try:
        raw = _read_small(env.approval_store / f"{current.approval_id}.json", 65536)
    except OSError as exc:
        raise PlanError("authorization", "APPROVAL_MISSING", f"pack approval record: {exc}") from None
    return current.approval_id, history, raw


def _source(env: RunEnvironment, side: Side, review: Review) -> tuple[SourceSnapshot, SourceManifest, bytes]:
    pinned = env.revisions[side]
    try:
        names = sorted(n for n in os.listdir(env.snapshot_store) if _SNAPSHOT_RE.fullmatch(n))
    except OSError as exc:
        raise PlanError("source_identity", "SOURCE_IDENTITY_MISMATCH", f"snapshot store: {exc}") from None
    found: list[tuple[SourceSnapshot, SourceManifest, bytes]] = []
    for name in names:
        snapshot_dir = env.snapshot_store / name
        try:
            raw = _read_small(snapshot_dir / MANIFEST_NAME, 64 * 1024 * 1024)
            snapshot = SourceSnapshot(snapshot_dir, "sha256:" + hashlib.sha256(raw).hexdigest())
            manifest = load_record(SourceManifest, raw, contract="source-manifest", max_bytes=64 * 1024 * 1024)
        except (OSError, RecordError) as exc:
            raise PlanError("source_identity", "SOURCE_IDENTITY_MISMATCH", f"{name}: {exc}") from None
        if manifest.commit_id == pinned.commit_id:
            found.append((snapshot, manifest, raw))
    if len(found) != 1:
        raise PlanError("source_identity", "SOURCE_IDENTITY_MISMATCH",
                        f"{side}: expected exactly one snapshot of {pinned.commit_id}, found {len(found)}")
    snapshot, manifest, raw = found[0]
    try:
        verified = verify_source_snapshot(snapshot)
        check_source_scope(review.profile.profile, verified)
    except InputIntegrityError as exc:
        raise PlanError("source_identity", "SOURCE_IDENTITY_MISMATCH", f"{side} snapshot: {exc}") from None
    if (manifest.tree_id, manifest.requested_revision) != (pinned.tree_id, pinned.commit_id):
        raise PlanError("source_identity", "SOURCE_IDENTITY_MISMATCH", f"{side}: tree or requested revision differs")
    fixture = [f for f in manifest.files if f.path == SOURCE_FIXTURE_PATH]
    if len(fixture) != 1 or fixture[0].sha256 != env.fixture_sha256:
        raise PlanError("source_identity", "SOURCE_IDENTITY_MISMATCH",
                        f"{side}: the synthetic fixture is missing or differs from the bound fixture hash")
    return snapshot, manifest, raw


def assemble_run(env: RunEnvironment, run_id: str) -> AssembledRun:
    """Recompute the complete plan for `run_id` from the current artifacts. Read-only."""
    try:
        review = assemble_review(env.approval_target)
    except ApprovalBlocked as exc:
        raise PlanError("pack_integrity", "PACK_INTEGRITY_FAILED", f"pack approval bindings: {exc}") from None
    manifest = review.pack.manifest
    if manifest.repetitions.pairs != 1:
        raise PlanError("pack_integrity", "PACK_INTEGRITY_FAILED",
                        "fixed-fixture mode supports exactly one pair; seeded repetition is PP-019")
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

    sources = {side: _source(env, side, review) for side in SIDES}
    profile = review.profile.profile
    images = {a.role: a for a in env.approved_images}
    target, verifier = images.get(RunRole.TARGET), images.get(RunRole.VERIFIER)
    if target is None or verifier is None or len(env.approved_images) != 2:
        raise PlanError("environment_identity", "ENVIRONMENT_NONCOMPARABLE", "exactly one approved image per role")
    try:
        ownership = Ownership(installation_id=installation, run_id=run_id)
        plan = RunPlan(ownership=ownership, profile=profile, manifest=manifest, pack=pack, approval_id=approval_id,
                       collection=review.collection, baseline=sources["baseline"][0],
                       candidate=sources["candidate"][0], pairs=1, target_image=target, verifier_image=verifier)
    except PolicyViolation as exc:
        raise PlanError("environment_identity", "RUNTIME_POLICY_FAILED", f"run plan: {exc}") from None

    names = container_names(run_id)
    if [n for _, _, n in names] != [run_container_name(ownership, 1, s, RunRole(r)) for s, r, _ in names]:
        raise PlanError("environment_identity", "RUNTIME_POLICY_FAILED", "container naming differs from the runner")
    inclusion = sources["baseline"][1].inclusion_profile
    if sources["candidate"][1].inclusion_profile != inclusion:
        raise PlanError("source_identity", "SOURCE_IDENTITY_MISMATCH", "the two snapshots use different inclusion")
    doc = {
        "plan_kind": PLAN_KIND, "run_id": run_id, "installation_id": installation, "pack_approval_id": approval_id,
        "pack": {"pack_id": manifest.pack_id, "pack_version": manifest.pack_version,
                 "manifest_sha256": review.pack.manifest_sha256, "pack_tree_sha256": review.pack.pack_tree_sha256,
                 "expected_collection": [c.model_dump() for c in review.collection],
                 "verifier_plugin_version": review.bindings.verifier_plugin_version},
        "profile": {"profile_id": profile.profile_id, "profile_version": profile.profile_version,
                    "profile_sha256": review.profile.sha256},
        "images": {"target_image_id": target.image.value, "verifier_image_id": verifier.image.value},
        "sources": {side: {"tag": env.revisions[side].tag, "commit_id": sources[side][1].commit_id,
                           "tree_id": sources[side][1].tree_id, "snapshot_name": sources[side][0].snapshot_dir.name,
                           "source_manifest_sha256": sources[side][0].manifest_sha256,
                           "source_tree_sha256": sources[side][1].source_tree_sha256} for side in SIDES},
        "source_inclusion": {"include": list(inclusion.include), "inclusion_profile_sha256": inclusion.sha256},
        "fixture": {"mode": "fixed-fixture-v0.1-exception", "fixture_contract": manifest.fixture_contract,
                    "fixture_sha256": env.fixture_sha256, "seed": None, "identical_for_both_sides": True,
                    "fresh_target_per_side": True},
        "repetitions": {"pairs": 1, "order": list(SIDES), "sequential": True, "automatic_retry": False},
        "baseline_failure_policy": "stop-before-candidate-on-execution-failure",
        "containers": {"max_creations": 4,
                       "sequence": [{"side": s, "role": r, "name": n} for s, r, n in names]},
        "runtime": {"network_policy": profile.network_policy,
                    "target_address": f"{TARGET_LOOPBACK_HOST}:{TARGET_LOOPBACK_PORT}",
                    "resources": profile.resources.model_dump(mode="json"),
                    "timeouts": profile.timeouts.model_dump(mode="json"),
                    "logging": profile.logging.model_dump(mode="json"), "result_cap_bytes": profile.result_cap_bytes,
                    "case_timeout_seconds": manifest.limits.case_timeout_seconds,
                    "max_response_bytes": manifest.limits.max_response_bytes},
        "evidence": {"destination": f"evidence/runs/{run_id}"},
    }
    try:
        document = validate_record(RunPlanDocument, doc, "run-plan")
        check_plan_semantics(document)
    except (RecordError, RunAuthorizationError) as exc:
        raise PlanError("environment_identity", "RUNTIME_POLICY_FAILED", f"plan document: {exc}") from None
    check_first_run_scope(document)
    return AssembledRun(plan=plan, document=document, sha256=plan_sha256(document), review=review,
                        approvals=history, approval_raw=approval_raw,
                        source_manifests={side: sources[side][2] for side in SIDES})


def check_first_run_scope(document: RunPlanDocument) -> None:
    """This driver's own revision rule: exactly r1 (baseline) against r3 (candidate).

    The reusable authorization contract (`check_plan_semantics`) deliberately allows any
    pair, including a revision against itself (PROJECT_SPEC.md 17.2). The first-run driver
    is authorized for one comparison only, so it compares against the module constants, not
    against a configurable environment.
    """
    for side in SIDES:
        pinned, bound = PAPERTRAIL_REVISIONS[side], getattr(document.sources, side)
        if (bound.tag, bound.commit_id, bound.tree_id) != (pinned.tag, pinned.commit_id, pinned.tree_id):
            raise PlanError("source_identity", "SOURCE_IDENTITY_MISMATCH",
                            f"{side} is not the authorized first-run revision {pinned.commit_id}")


def plan_differences(frozen: RunPlanDocument, current: RunPlanDocument) -> list[str]:
    """Top-level plan sections that differ (for messages and precondition mapping)."""
    a, b = frozen.model_dump(mode="json"), current.model_dump(mode="json")
    return sorted(k for k in a if a[k] != b.get(k))


SECTION_PRECONDITION: Final[Mapping[str, tuple[PreconditionName, str]]] = {
    "pack_approval_id": ("authorization", "APPROVAL_STALE"),
    "pack": ("pack_integrity", "PACK_INTEGRITY_FAILED"),
    "sources": ("source_identity", "SOURCE_IDENTITY_MISMATCH"),
    "source_inclusion": ("source_identity", "SOURCE_IDENTITY_MISMATCH"),
    "fixture": ("source_identity", "SOURCE_IDENTITY_MISMATCH"),
}


def difference_precondition(sections: list[str]) -> tuple[PreconditionName, str]:
    for section in sections:
        if section in SECTION_PRECONDITION:
            return SECTION_PRECONDITION[section]
    return ("environment_identity", "RUNTIME_POLICY_FAILED")
