"""Versioned execution profiles: strict, read-only loading (PROJECT_SPEC.md 7.5, 10; PP-008).

**Where profiles live:** `profiles/<profile_id>-<profile_version>.json` in the project
repository. They are review-controlled inputs, like a pack. Approval records never live here;
they belong in the private approval store.

**`load_profile`** reads one profile file and fails closed. It:
- requires an absolute canonical path inside a directory named `profiles`, whose file name is
  exactly `<profile_id>-<profile_version>.json` of the profile it holds;
- opens it without following symlinks or blocking, re-checks that it is the same regular file,
  and refuses anything over `MAX_PROFILE_BYTES`;
- parses strict JSON (duplicate keys refused) into the execution-profile 1.1 model, then
  applies the PP-003 code-level profile check;
- refuses placeholder or unapproved image IDs, the role-swapped images, an unknown fixture
  contract and a source scope outside the PP-005 grammar;
- refuses any runtime value that differs from what the runner enforces
  (`run_plan.FIXED_PROFILE_RUNTIME`);
- recomputes the canonical profile hash from the validated model and refuses it unless it
  equals the expected binding.

Nothing is migrated, normalized, defaulted or written back. A profile is either exactly the
reviewed one or refused.

**Not a profile:** the standalone collection role has no profile. It uses the verifier image
with no network and the verifier ceilings; it can never stand in for a target/verifier
execution profile, which must name both approved run images in their own roles.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from ..core.approvals import canonical_sha256
from ..core.records import RecordError, load_record
from ..core.records.pack import ExecutionProfileV11
from ..git.paths import SourceScope
from ..git.errors import SourceError
from ..packs.validation import FIXTURE_CONTRACTS
from .policy import PolicyViolation, check_profile_document
from .run_plan import APPROVED_RUN_IMAGES, REJECTED_RUN_IMAGE_IDS, ApprovedRunImage, runtime_differences
from .run_policy import RunRole

PROFILES_DIRNAME: Final = "profiles"
MAX_PROFILE_BYTES: Final = 16384
_FILE_RE: Final = re.compile(
    r"[a-z0-9][a-z0-9-]{0,62}-(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.json")
_PLACEHOLDER_RE: Final = re.compile(r"\{\{|\}\}|\$\{|<%|%>|<<[A-Z_]+>>|@@[A-Z_]+@@|__[A-Z][A-Z0-9_]*__"
                                    r"|\bTODO\b|\bTBD\b|UNRESOLVED|PLACEHOLDER", re.IGNORECASE)
_REPEATED_HEX_RE: Final = re.compile(r"sha256:([0-9a-f])\1{63}")

# PROPOSED PaperTrail reference profile (PP-008). Review-controlled: the approval entry point
# accepts the profile file only if it hashes to this value. It is NOT owner-approved; the
# owner approves it, if at all, as one binding of the pack approval.
PAPERTRAIL_PROFILE_ID: Final = "papertrail-reference"
PAPERTRAIL_PROFILE_VERSION: Final = "1.0.0"
PAPERTRAIL_PROFILE_SHA256: Final = "sha256:a1c130c2f8b90c2ada2001ef3bc336b0b8ec29886fd92635dbf5928eb8036835"


class ProfileError(ValueError):
    """The execution profile is missing, malformed, inconsistent or not the expected one."""


@dataclass(frozen=True)
class LoadedProfile:
    path: Path
    profile: ExecutionProfileV11
    sha256: str  # canonical hash of the validated model (core.approvals.canonical_sha256)
    file_sha256: str  # hash of the file bytes, for evidence only; never a binding


def profile_path(project_root: Path, profile_id: str, profile_version: str) -> Path:
    return project_root / PROFILES_DIRNAME / f"{profile_id}-{profile_version}.json"


def _read(path: Path) -> bytes:
    raw = str(path)
    if not os.path.isabs(raw) or os.path.realpath(raw) != raw:
        raise ProfileError("profile path must be absolute and canonical (no symlinks)")
    if path.parent.name != PROFILES_DIRNAME or not _FILE_RE.fullmatch(path.name):
        raise ProfileError("profile must be profiles/<profile_id>-<profile_version>.json")
    try:
        before = os.lstat(raw)
        if not stat.S_ISREG(before.st_mode):
            raise ProfileError("profile is not a regular file")
        fd = os.open(raw, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise ProfileError("profile file is missing or cannot be opened") from exc
    with os.fdopen(fd, "rb") as handle:
        st = os.fstat(handle.fileno())
        if not stat.S_ISREG(st.st_mode) or (st.st_dev, st.st_ino) != (before.st_dev, before.st_ino):
            raise ProfileError("profile changed type or identity while it was read")
        if st.st_size > MAX_PROFILE_BYTES:
            raise ProfileError("profile exceeds the size limit")
        data = handle.read(MAX_PROFILE_BYTES + 1)
    if len(data) > MAX_PROFILE_BYTES:
        raise ProfileError("profile exceeds the size limit")
    return data


def _strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in (*_strings(k), *_strings(v))]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return []


def _approved(role: RunRole, image_id: str, approved: tuple[ApprovedRunImage, ...]) -> bool:
    return any(a.role is role and a.image.value == image_id for a in approved)


def check_profile(profile: ExecutionProfileV11,
                  approved_images: tuple[ApprovedRunImage, ...] = APPROVED_RUN_IMAGES) -> None:
    """Every rule except the file and hash checks. Raises ProfileError."""
    doc = profile.model_dump(mode="json")
    try:
        check_profile_document(doc)
    except PolicyViolation as exc:
        raise ProfileError(f"profile fails the code-level policy check: {exc}") from None
    if any(_PLACEHOLDER_RE.search(s) for s in _strings(doc)):
        raise ProfileError("profile contains an unresolved placeholder")
    for role, image_id in ((RunRole.TARGET, profile.target_image_id), (RunRole.VERIFIER, profile.verifier_image_id)):
        if _REPEATED_HEX_RE.fullmatch(image_id):
            raise ProfileError(f"{role.value} image ID is a placeholder")
        if image_id in REJECTED_RUN_IMAGE_IDS:
            raise ProfileError(f"{role.value} image ID is a rejected image")
        if not _approved(role, image_id, approved_images):
            raise ProfileError(f"{role.value} image ID is not the approved {role.value} run image")
    if profile.fixture_contract not in FIXTURE_CONTRACTS:
        raise ProfileError("profile names an unknown fixture contract")
    try:
        SourceScope.of(profile.source_scope.include)
    except SourceError as exc:
        raise ProfileError(f"source scope is outside the PP-005 grammar: {exc}") from None
    differences = runtime_differences(profile)
    if differences:
        raise ProfileError("profile values differ from the enforced runtime policy: " + ", ".join(differences))


def load_profile(path: Path, *, expected_sha256: str,
                 approved_images: tuple[ApprovedRunImage, ...] = APPROVED_RUN_IMAGES) -> LoadedProfile:
    """Load, validate and identify one profile file, or raise ProfileError. Never writes."""
    data = _read(path)
    try:
        profile = load_record(ExecutionProfileV11, data, contract="execution-profile.v1.1",
                              max_bytes=MAX_PROFILE_BYTES)
    except RecordError as exc:
        raise ProfileError(f"profile is not a valid execution-profile 1.1 record: {'; '.join(exc.problems[:3])}"
                           ) from None
    if path.name != f"{profile.profile_id}-{profile.profile_version}.json":
        raise ProfileError("profile file name differs from its profile_id and profile_version")
    check_profile(profile, approved_images)
    digest = canonical_sha256(profile)
    if digest != expected_sha256:
        raise ProfileError(f"profile hash {digest} differs from the expected binding {expected_sha256}")
    return LoadedProfile(path=path, profile=profile, sha256=digest,
                         file_sha256="sha256:" + hashlib.sha256(data).hexdigest())


def profile_document(loaded: LoadedProfile) -> str:
    """The validated profile as indented JSON, for display."""
    return json.dumps(loaded.profile.model_dump(mode="json"), indent=2, sort_keys=False)
