"""Typed execution plan and pre-execution checks for one comparison (PROJECT_SPEC.md 7.5, 8.4, 10; PP-008).

**What a plan binds:**
- the owner's pack approval;
- the content-addressed pack snapshot and its exact collection;
- the validated execution profile and its hash;
- the two approved run images;
- the baseline and candidate source snapshots;
- the pair count.

**`check_preconditions`** recomputes every binding from the plan's inputs and reports the
verdict engine's preconditions (verdict specification 5.1). It never refreshes or
reinterprets an approval.

**Profile/runtime consistency:** the runner's container policy is fixed. A plan's profile
must therefore declare exactly the values the runner enforces (`FIXED_PROFILE_RUNTIME`), not
merely values below a ceiling, so that the profile an owner approves describes what actually
runs. Each source snapshot must have been materialized with exactly the profile's
`source_scope.include`.

**Approved run images:** an image's identity, environment and health check become known only
after an owner-approved build (gate B). They are review-controlled code, like
`policy.APPROVED_PROBE_IMAGE_ID`. `APPROVED_RUN_IMAGES` holds the gate-B r2 images, approved
by the owner on 2026-10-13 for gate C. Their environment and health check are copied from the
r2 `docker image inspect` records. Unit tests construct synthetic image records.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Final, Literal

from ..core.approvals import BindingInputs, canonical_sha256, check_approval
from ..core.records import RecordError, load_record
from ..core.records.evidence import SourceManifest
from ..core.records.pack import ApprovalRecord, CollectedTest, ExecutionProfileV11, PackManifest
from ..core.records.run import Precondition
from .collector import StreamIdentity
from .inputs import InputIntegrityError, PackSnapshot, SourceSnapshot, verify_pack_snapshot, verify_source_snapshot
from .policy import (
    CEILINGS,
    LOG_MAX_FILE,
    LOG_MAX_SIZE_BYTES,
    NANO_CPUS_PER_CPU,
    NETWORK_POLICY_VALUE,
    STOP_GRACE_SECONDS,
    ImageId,
    LimitClass,
    Ownership,
    PolicyViolation,
    ResourceLimits,
    check_limits,
)
from .run_policy import PACK_MOUNT, TARGET_HEALTHCHECK, RunRole

PLUGIN_VERSION: Final = "0.1.0"


# Images that must never become approved execution identities. Gate B r1 builds (2026-10-13):
# the r1 verifier is defective (G-B1: package and config directories untraversable for UID 10001),
# and the r1 target was superseded by the r2 rebuild. Both are kept only as evidence.
REJECTED_RUN_IMAGE_IDS: Final = frozenset({
    "sha256:e5d1ad51ecfcf50c3f0835e3d801c76d591396474f13179070a32a1233b1b102",
    "sha256:e57f61f8f8a8e8757935159dfaaeb1e891f50b0e44dcfe1eece7528377eef972",
})


@dataclass(frozen=True, eq=True)
class ApprovedRunImage:
    """An owner-approved, locally built run image: identity, environment and health check."""

    role: RunRole
    image: ImageId
    env: tuple[str, ...]
    healthcheck: Mapping[str, object] | None

    def __post_init__(self) -> None:
        if self.image.value in REJECTED_RUN_IMAGE_IDS:
            raise PolicyViolation("this image ID is rejected and can never be an approved run image")
        if self.role is RunRole.TARGET and self.healthcheck != TARGET_HEALTHCHECK:
            raise PolicyViolation("the target image must carry the reviewed health check")
        if self.role is RunRole.VERIFIER and self.healthcheck is not None:
            raise PolicyViolation("the verifier image has no health check")
        if self.role is RunRole.VERIFIER and "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1" not in self.env:
            raise PolicyViolation("the verifier image must disable pytest plugin autoloading")


# Owner-approved run images (gate B). Empty: no run image has been built or approved.
_R2_ENV_BASE: Final = (
    "PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "GPG_KEY=7169605F62C751356D054A26A821E680E5FA6305",
    "PYTHON_VERSION=3.13.16",
    "PYTHON_SHA256=f4b1bfb3c79b5bb11b8d228a12504163b4c0dab4d679828d8f5f26b6cb6ab35d",
)
_R2_ENV_TAIL: Final = ("PYTHONDONTWRITEBYTECODE=1", "PYTHONHASHSEED=0", "LC_ALL=C.UTF-8", "HOME=/nonexistent")

# Gate B r2 (built 2026-10-13, statically audited; owner-approved for gate C on 2026-10-13).
APPROVED_RUN_IMAGES: Final[tuple[ApprovedRunImage, ...]] = (
    ApprovedRunImage(RunRole.TARGET,
                     ImageId("sha256:98548ec48d8d796fca5adaf4aab3e461bee38210bd1d568281f79190685eac2e"),
                     _R2_ENV_BASE + _R2_ENV_TAIL, TARGET_HEALTHCHECK),
    ApprovedRunImage(RunRole.VERIFIER,
                     ImageId("sha256:e880f609a7c4d292441e22d1d0d5d7c876697dd4e1e657a668b2b6266969fecc"),
                     _R2_ENV_BASE + ("PYTEST_DISABLE_PLUGIN_AUTOLOAD=1",) + _R2_ENV_TAIL, None),
)


# Values the runner enforces, and therefore the only values a run profile may declare.
# Where each is applied:
# - resources: `limits_from_profile` -> `run_create_argv_tail` (--cpus, --memory, --memory-swap,
#   --pids-limit, --tmpfs size=), confirmed by the pre-start inspect gate. Equal to the PP-003
#   code-level ceilings.
# - readiness_seconds: the readiness poll in `revision.execute_revision`; equal to the target
#   image health check's start period.
# - request_connect_seconds / request_read_seconds: `run_policy.verifier_command`
#   (--connect-timeout / --read-timeout), applied by the verifier's HTTP transport.
# - revision_deadline_seconds: `ResourceLimits.deadline_seconds`, the per-revision deadline.
# - cancellation_grace_seconds: the fixed stop grace (`--stop-timeout`, `docker stop --time`).
# - logging: the fixed `local` log driver options (max-size=5m, max-file=2).
# - result_cap_bytes: the bound on host-read verifier stdout and the collector's OVER_CAP rule.
# - network_policy: target `--network=none`, verifier `--network=container:<exact target ID>`.
RESULT_CAP_BYTES: Final = 10 * 1024 * 1024
REQUEST_TIMEOUT_SECONDS: Final = 5.0
READINESS_SECONDS: Final = 30  # = TARGET_HEALTHCHECK StartPeriod (30 s); a test asserts it


def _limits_block(limits: ResourceLimits) -> dict[str, object]:
    return {"cpus": limits.nano_cpus / NANO_CPUS_PER_CPU, "memory_bytes": limits.memory_bytes,
            "pids": limits.pids, "scratch_tmpfs_bytes": limits.scratch_bytes, "tmp_tmpfs_bytes": limits.tmp_bytes}


FIXED_PROFILE_RUNTIME: Final[dict[str, object]] = {
    "network_policy": NETWORK_POLICY_VALUE,
    "resources": {"target": _limits_block(CEILINGS[LimitClass.TARGET]),
                  "verifier": _limits_block(CEILINGS[LimitClass.VERIFIER])},
    "timeouts": {
        "readiness_seconds": READINESS_SECONDS,
        "request_connect_seconds": REQUEST_TIMEOUT_SECONDS,
        "request_read_seconds": REQUEST_TIMEOUT_SECONDS,
        "revision_deadline_seconds": CEILINGS[LimitClass.TARGET].deadline_seconds,
        "cancellation_grace_seconds": STOP_GRACE_SECONDS,
    },
    "logging": {"max_file_bytes": LOG_MAX_SIZE_BYTES, "max_files": LOG_MAX_FILE},
    "result_cap_bytes": RESULT_CAP_BYTES,
}


def runtime_differences(profile: ExecutionProfileV11) -> list[str]:
    """Profile fields whose declared value differs from what the runner enforces (dotted paths)."""
    declared = profile.model_dump(mode="json", include=set(FIXED_PROFILE_RUNTIME))
    differences: list[str] = []

    def walk(want: object, got: object, path: str) -> None:
        if isinstance(want, dict) and isinstance(got, dict):
            for key in sorted(set(want) | set(got)):
                walk(want.get(key), got.get(key), f"{path}.{key}" if path else key)
        elif type(want) is not type(got) and not {type(want), type(got)} <= {int, float}:
            differences.append(path)
        elif want != got:
            differences.append(path)

    walk(FIXED_PROFILE_RUNTIME, declared, "")
    return differences


def check_runtime_consistency(profile: ExecutionProfileV11) -> None:
    differences = runtime_differences(profile)
    if differences:
        raise PolicyViolation("profile values differ from the enforced runtime policy: " + ", ".join(differences))


def check_source_scope(profile: ExecutionProfileV11, manifest: SourceManifest) -> None:
    """A source snapshot must have been materialized with exactly the profile's source scope."""
    if manifest.inclusion_profile.include != sorted(profile.source_scope.include):
        raise InputIntegrityError("source snapshot scope differs from the profile's source_scope.include")


def limits_from_profile(profile: ExecutionProfileV11, role: RunRole) -> ResourceLimits:
    block = profile.resources.target if role is RunRole.TARGET else profile.resources.verifier
    limit_class = LimitClass.TARGET if role is RunRole.TARGET else LimitClass.VERIFIER
    limits = ResourceLimits(nano_cpus=round(block.cpus * NANO_CPUS_PER_CPU), memory_bytes=block.memory_bytes,
                            pids=block.pids, scratch_bytes=block.scratch_tmpfs_bytes, tmp_bytes=block.tmp_tmpfs_bytes,
                            deadline_seconds=profile.timeouts.revision_deadline_seconds)
    check_limits(limits, limit_class)
    return limits


@dataclass(frozen=True)
class RunPlan:
    ownership: Ownership
    profile: ExecutionProfileV11
    manifest: PackManifest
    pack: PackSnapshot
    approval_id: str
    collection: tuple[CollectedTest, ...]
    baseline: SourceSnapshot
    candidate: SourceSnapshot
    pairs: int
    target_image: ApprovedRunImage
    verifier_image: ApprovedRunImage

    def __post_init__(self) -> None:
        if not 1 <= self.pairs <= self.manifest.repetitions.pairs:
            raise PolicyViolation("planned pairs must be between 1 and the pack's declared pairs")
        if self.target_image.role is not RunRole.TARGET or self.verifier_image.role is not RunRole.VERIFIER:
            raise PolicyViolation("image roles are swapped")
        if (self.target_image.image.value, self.verifier_image.image.value) != (
                self.profile.target_image_id, self.profile.verifier_image_id):
            raise PolicyViolation("plan images differ from the profile's image IDs")
        if self.manifest.fixture_contract != self.profile.fixture_contract:
            raise PolicyViolation("pack fixture contract differs from the profile's")
        check_runtime_consistency(self.profile)

    @property
    def profile_sha256(self) -> str:
        return canonical_sha256(self.profile)

    @property
    def test_paths(self) -> tuple[str, ...]:
        return tuple(sorted({f"{PACK_MOUNT}/{t.nodeid.split('::', 1)[0]}" for t in self.manifest.tests}))

    def source(self, side: Literal["baseline", "candidate"]) -> SourceSnapshot:
        return self.baseline if side == "baseline" else self.candidate

    def limits(self, role: RunRole) -> ResourceLimits:
        return limits_from_profile(self.profile, role)

    def stream_identity(self, pair: int, side: Literal["baseline", "candidate"]) -> StreamIdentity:
        return StreamIdentity(run_id=self.ownership.run_id, pair=pair, side=side,
                              pack_tree_sha256=self.pack.pack_tree_sha256, plugin_version=PLUGIN_VERSION,
                              collection=self.collection, kinds={t.id: t.kind for t in self.manifest.tests})

    def binding_inputs(self) -> BindingInputs:
        return BindingInputs(pack_id=self.manifest.pack_id, pack_version=self.manifest.pack_version,
                             manifest_sha256=self.pack.manifest_sha256, pack_tree_sha256=self.pack.pack_tree_sha256,
                             collection=self.collection, verifier_image_id=self.verifier_image.image.value,
                             verifier_plugin_version=PLUGIN_VERSION, profile_id=self.profile.profile_id,
                             profile_sha256=self.profile_sha256)


def _passed() -> Precondition:
    return Precondition(state="PASSED", detected_phase=None, reason_codes=[])


def _failed(phase: Literal["pre_execution", "post_execution"], *codes: str) -> Precondition:
    return Precondition.model_validate({"state": "FAILED", "detected_phase": phase, "reason_codes": list(codes)})


def check_preconditions(plan: RunPlan, approvals: Iterable[ApprovalRecord],
                        approved_images: Iterable[ApprovedRunImage] = APPROVED_RUN_IMAGES,
                        *, phase: Literal["pre_execution", "post_execution"] = "pre_execution"
                        ) -> dict[str, Precondition]:
    """Authorization, pack integrity, source identity and environment identity, recomputed now."""
    result: dict[str, Precondition] = {}
    check = check_approval(list(approvals), plan.binding_inputs(), approval_id=plan.approval_id)
    result["authorization"] = _passed() if check.status == "APPROVED" else _failed(phase, check.status)

    try:
        verify_pack_snapshot(plan.pack)
        snapshot_manifest = load_record(PackManifest, (plan.pack.root / "pack.json").read_bytes(),
                                        contract="pack-manifest", max_bytes=65536)
        if snapshot_manifest != plan.manifest:
            raise InputIntegrityError("the plan's manifest is not the approved pack's manifest")
        result["pack_integrity"] = _passed()
    except (InputIntegrityError, RecordError):
        result["pack_integrity"] = _failed(phase, "PACK_INTEGRITY_FAILED")
    pairs = [(c.id, c.nodeid) for c in plan.collection]
    if len(set(pairs)) != len(pairs) or set(pairs) != {(t.id, t.nodeid) for t in plan.manifest.tests}:
        result["pack_integrity"] = _failed(phase, "PACK_COLLECTION_MISMATCH")

    try:
        for snapshot in (plan.baseline, plan.candidate):
            check_source_scope(plan.profile, verify_source_snapshot(snapshot))
        result["source_identity"] = _passed()
    except InputIntegrityError:
        result["source_identity"] = _failed(phase, "SOURCE_IDENTITY_MISMATCH")

    approved = list(approved_images)
    if plan.target_image in approved and plan.verifier_image in approved:
        result["environment_identity"] = _passed()
    else:
        result["environment_identity"] = _failed(phase, "ENVIRONMENT_NONCOMPARABLE")
    return result
