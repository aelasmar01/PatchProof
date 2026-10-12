"""Generate the PaperTrail reference repository (PROJECT_SPEC.md 17.1, PP-006).

PaperTrail is a synthetic verification fixture, not product code. Its sources live in
``examples/papertrail/`` and are treated here as bytes only: this module never imports,
executes, or evaluates them. The generator writes a new local Git repository with four
tagged revisions of one object-level authorization case:

    authz-r1-vulnerable  baseline: any authenticated caller can read any document
    authz-r2-inadequate  adds authentication and role checks, still no object relationship
    authz-r3-correct     owner or an explicitly granted reader role only
    authz-r4-deny-all    refuses every read, breaking legitimate owner access

Only ``papertrail/authz.py`` differs between revisions. Contents, file order, identities,
timestamps and messages are fixed, so the commit IDs are reproducible; the IDs recorded in
``examples/papertrail/reference-fixture.json`` were produced by running this generator and
are re-checked by the tests, never written by hand.
"""

from __future__ import annotations

import calendar
import os
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from .gitobjects import (
    OBJECT_FORMAT,
    FixtureGenerationError,
    LooseObjectRepository,
    Signature,
    commit_payload,
    tag_payload,
)

GENERATOR_VERSION: Final = "1.0.0"
PROJECT_ROOT: Final = Path(__file__).resolve().parents[3]
DEFAULT_TEMPLATES: Final = PROJECT_ROOT / "examples" / "papertrail"
MAX_TEMPLATE_BYTES: Final = 65536

# Files common to every revision, in tree-path form, and the one file that varies.
BASE_FILES: Final = (
    "README.md",
    "fixtures/synthetic/synthetic-documents-v1.json",
    "papertrail/__init__.py",
    "papertrail/app.py",
    "papertrail/fixtures.py",
)
VARYING_FILE: Final = "papertrail/authz.py"
HEAD_BRANCH: Final = "refs/heads/main"
IDENTITY: Final = "PaperTrail Fixture <fixture@papertrail.invalid>"


def _epoch(year: int, month: int, day: int) -> int:
    return calendar.timegm((year, month, day, 9, 0, 0, 0, 0, 0))


@dataclass(frozen=True)
class RevisionSpec:
    key: str
    tag: str
    parent: str | None
    epoch_seconds: int
    message: str
    tag_message: str


REVISIONS: Final = (
    RevisionSpec(
        key="vulnerable", tag="authz-r1-vulnerable", parent=None, epoch_seconds=_epoch(2026, 1, 5),
        message=("Add PaperTrail synthetic document API\n\n"
                 "Serves GET /health, /me and /documents/{document_id} for synthetic\n"
                 "bearer-token users. Document reads require a signed-in user.\n"),
        tag_message="PatchProof reference revision 1: vulnerable baseline (synthetic fixture)\n"),
    RevisionSpec(
        key="inadequate", tag="authz-r2-inadequate", parent="vulnerable", epoch_seconds=_epoch(2026, 1, 6),
        message=("Require an identified member account to read documents\n\n"
                 "Document reads now check that the caller is signed in, has a user ID\n"
                 "and holds a role that is permitted to read documents.\n"),
        tag_message="PatchProof reference revision 2: inadequate fix (synthetic fixture)\n"),
    RevisionSpec(
        key="correct", tag="authz-r3-correct", parent="vulnerable", epoch_seconds=_epoch(2026, 1, 7),
        message=("Restrict document reads to the owner and granted roles\n\n"
                 "A document is readable by its owner and by callers whose role is listed\n"
                 "in the document's reader_roles. Everyone else receives 404.\n"),
        tag_message="PatchProof reference revision 3: correct fix (synthetic fixture)\n"),
    RevisionSpec(
        key="deny-all", tag="authz-r4-deny-all", parent="vulnerable", epoch_seconds=_epoch(2026, 1, 8),
        message=("Disable document reads pending an access review\n\n"
                 "Every document read is refused until the access rules are reviewed.\n"),
        tag_message="PatchProof reference revision 4: deny-all regression (synthetic fixture)\n"),
)


@dataclass(frozen=True)
class GeneratedRevision:
    key: str
    tag_ref: str
    tag_object_id: str
    commit_id: str
    tree_id: str
    parent_id: str | None


@dataclass(frozen=True)
class GeneratedRepository:
    root: Path
    head_ref: str
    revisions: tuple[GeneratedRevision, ...]
    object_count: int

    def as_record(self) -> dict[str, Any]:
        """Deterministic summary (no absolute paths) of what was generated."""
        return {
            "generator_version": GENERATOR_VERSION,
            "object_format": OBJECT_FORMAT,
            "head": self.head_ref,
            "head_commit_id": self.revisions[0].commit_id,
            "object_count": self.object_count,
            "revisions": [
                {"key": r.key, "tag": r.tag_ref, "tag_object_id": r.tag_object_id, "commit_id": r.commit_id,
                 "tree_id": r.tree_id, "parent_commit_id": r.parent_id}
                for r in self.revisions
            ],
        }


def _read_template(templates: Path, rel: str) -> bytes:
    """Read one reviewed template file without following symlinks at any component."""
    current = templates
    for part in rel.split("/"):
        current = current / part
        st = os.lstat(current)
        if stat.S_ISLNK(st.st_mode):
            raise FixtureGenerationError(f"template path {rel} contains a symlink")
    if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_TEMPLATE_BYTES:
        raise FixtureGenerationError(f"template {rel} is not a regular file within the size limit")
    fd = os.open(current, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(MAX_TEMPLATE_BYTES + 1)
    if len(data) > MAX_TEMPLATE_BYTES:
        raise FixtureGenerationError(f"template {rel} exceeds the size limit")
    return data


def revision_files(templates: Path = DEFAULT_TEMPLATES) -> dict[str, dict[str, bytes]]:
    """The complete file set of every revision: key -> {tree path -> bytes}."""
    if os.path.realpath(templates) != str(templates):
        raise FixtureGenerationError("template directory must be an absolute canonical path")
    base = {rel: _read_template(templates / "template", rel) for rel in BASE_FILES}
    return {spec.key: {**base, VARYING_FILE: _read_template(templates / "revisions" / spec.key, "authz.py")}
            for spec in REVISIONS}


def validate_destination(destination: Path, *, home: Path | None = None,
                         project_root: Path = PROJECT_ROOT) -> None:
    """Refuse anything but a new directory in an owned, canonical, repository-free location."""
    raw = str(destination)
    if not os.path.isabs(raw):
        raise FixtureGenerationError("destination must be an absolute path")
    if os.path.realpath(raw) != raw:
        raise FixtureGenerationError("destination must be canonical (no symlinks, '..' or trailing '/')")
    if os.path.lexists(raw):
        raise FixtureGenerationError("destination already exists; choose a new directory")
    parent = destination.parent
    pst = os.lstat(parent) if os.path.lexists(parent) else None
    if pst is None or not stat.S_ISDIR(pst.st_mode) or pst.st_uid != os.getuid():
        raise FixtureGenerationError("destination parent must be an existing directory owned by the current user")
    home_dir = Path(os.path.realpath(home if home is not None else Path.home()))
    if destination == home_dir or home_dir.is_relative_to(destination):
        raise FixtureGenerationError("destination cannot be the home directory or one of its ancestors")
    root = Path(os.path.realpath(project_root))
    if destination.is_relative_to(root) or root.is_relative_to(destination):
        raise FixtureGenerationError("destination cannot be inside the PatchProof source repository")
    for ancestor in destination.parents:
        # The home directory's own repository is a known, retained hazard (environment.lock.md 6.1);
        # every other enclosing repository makes the new one nested and is refused.
        if ancestor != home_dir and os.path.lexists(ancestor / ".git"):
            raise FixtureGenerationError(f"destination is inside another Git repository ({ancestor})")


def generate_reference_repository(destination: Path, *, templates: Path = DEFAULT_TEMPLATES,
                                  home: Path | None = None,
                                  project_root: Path = PROJECT_ROOT) -> GeneratedRepository:
    """Create the PaperTrail reference repository in a new directory. All-or-nothing."""
    validate_destination(destination, home=home, project_root=project_root)
    files = revision_files(templates)
    os.mkdir(destination, 0o700)
    try:
        repo = LooseObjectRepository(destination)
        repo.initialize(HEAD_BRANCH)
        commits: dict[str, str] = {}
        generated = []
        for spec in REVISIONS:
            signature = Signature(IDENTITY, spec.epoch_seconds)
            tree = repo.put_tree(files[spec.key])
            parent = commits[spec.parent] if spec.parent is not None else None
            commit = repo.put("commit", commit_payload(tree, (parent,) if parent else (), signature, signature,
                                                       spec.message))
            commits[spec.key] = commit
            tag_object = repo.put("tag", tag_payload(commit, spec.tag, signature, spec.tag_message))
            tag_ref = f"refs/tags/{spec.tag}"
            repo.set_ref(tag_ref, tag_object)
            generated.append(GeneratedRevision(spec.key, tag_ref, tag_object, commit, tree, parent))
        repo.set_ref(HEAD_BRANCH, commits[REVISIONS[0].key])
        count = repo.verify()
    except BaseException:
        shutil.rmtree(destination, ignore_errors=True)
        raise
    return GeneratedRepository(root=destination, head_ref=HEAD_BRANCH, revisions=tuple(generated),
                               object_count=count)
