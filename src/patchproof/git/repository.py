"""Repository registration and revision resolution (PROJECT_SPEC.md 9.1).

Registration accepts only the exact canonical root the operator selected: a directory
whose own `.git` is a real directory. It never searches upward, so selecting a
subdirectory, or a directory that sits below an unrelated parent repository (such as a
Git repository in the home directory), is refused rather than resolved to the parent.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from .command import (
    DiscoverRoot,
    GitBinary,
    GitRunner,
    ObjectFormat,
    ObjectId,
    ObjectType,
    Peel,
    RefName,
    ShowObjectFormat,
    ShowRef,
)
from .errors import Reason, SourceError, safe_text

# Layout features that make Git read objects or history from somewhere other than this
# repository's own object store, or that indicate a linked worktree/submodule gitdir.
UNSUPPORTED_LAYOUT_FILES: Final = (
    "objects/info/alternates",
    "objects/info/http-alternates",
    "info/grafts",
    "commondir",
    "gitdir",
)


@dataclass(frozen=True)
class RegisteredRepository:
    """A validated, explicitly selected local repository. Holds no repository content."""

    root: Path
    object_format: ObjectFormat
    git: GitBinary

    def runner(self) -> GitRunner:
        return GitRunner(binary=self.git, root=self.root)


@dataclass(frozen=True)
class ResolvedRevision:
    requested: str
    commit: ObjectId
    tree: ObjectId


def _lstat(path: Path) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None


def register_repository(path: str | Path, git: GitBinary, *, home: Path | None = None,
                        runner: GitRunner | None = None) -> RegisteredRepository:
    """Validate an explicitly selected repository root. Read-only; writes nothing anywhere."""
    raw = str(path)
    if not os.path.isabs(raw):
        raise SourceError(Reason.PATH_NOT_ABSOLUTE, "repository path must be absolute")
    root = Path(raw)
    canonical = os.path.realpath(raw)
    if canonical != raw:
        raise SourceError(Reason.PATH_NOT_CANONICAL,
                          f"select the canonical path {safe_text(canonical)} (no symlinks, '..' or trailing '/')")
    home_dir = Path(os.path.realpath(home if home is not None else Path.home()))
    if root == Path("/") or home_dir == root or home_dir.is_relative_to(root):
        raise SourceError(Reason.HOME_DIRECTORY_REPOSITORY,
                          "the home directory and its ancestors cannot be registered")
    st = _lstat(root)
    if st is None or not stat.S_ISDIR(st.st_mode):
        raise SourceError(Reason.NOT_A_DIRECTORY, "repository path is not an existing directory")
    if st.st_uid != os.getuid():
        raise SourceError(Reason.NOT_OWNED_BY_USER, "repository directory is not owned by the current user")

    dotgit = root / ".git"
    gst = _lstat(dotgit)
    if gst is None:
        raise SourceError(Reason.NOT_A_REPOSITORY_ROOT, "the selected directory has no .git of its own")
    if stat.S_ISLNK(gst.st_mode) or stat.S_ISREG(gst.st_mode):
        raise SourceError(Reason.UNSUPPORTED_REPOSITORY_LAYOUT,
                          ".git is a symlink or gitdir file (linked worktree or submodule)")
    if not stat.S_ISDIR(gst.st_mode):
        raise SourceError(Reason.UNSUPPORTED_REPOSITORY_LAYOUT, ".git is not a directory")
    if gst.st_uid != os.getuid():
        raise SourceError(Reason.NOT_OWNED_BY_USER, ".git is not owned by the current user")
    objects = _lstat(dotgit / "objects")
    if objects is None or not stat.S_ISDIR(objects.st_mode):
        raise SourceError(Reason.UNSUPPORTED_REPOSITORY_LAYOUT, ".git/objects is missing or not a real directory")
    for rel in UNSUPPORTED_LAYOUT_FILES:
        if _lstat(dotgit / rel) is not None:
            raise SourceError(Reason.UNSUPPORTED_REPOSITORY_LAYOUT, f".git/{rel} is not supported")

    run = runner or GitRunner(binary=git, root=root)
    lines = run.run(DiscoverRoot()).split(b"\n")
    if len(lines) != 4 or lines[3] != b"":
        raise SourceError(Reason.MALFORMED_GIT_OUTPUT, "unexpected discovery output")
    bare, git_dir, toplevel = lines[0], lines[1], lines[2]
    if bare != b"false":
        raise SourceError(Reason.UNSUPPORTED_REPOSITORY_LAYOUT, "bare repositories are not supported")
    if toplevel != raw.encode() or git_dir != str(dotgit).encode():
        raise SourceError(Reason.AMBIGUOUS_REPOSITORY,
                          f"Git discovered {safe_text(toplevel)}, not the selected root")

    fmt_out = run.run(ShowObjectFormat())
    try:
        object_format = ObjectFormat(fmt_out.decode("ascii").removesuffix("\n"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise SourceError(Reason.UNSUPPORTED_OBJECT_FORMAT, safe_text(fmt_out)) from exc
    return RegisteredRepository(root=root, object_format=object_format, git=git)


_HEXISH_RE: Final = re.compile(r"[0-9a-fA-F]{4,}")


def parse_revision(revision: str, object_format: ObjectFormat) -> ObjectId | RefName:
    """Accept only a full object ID or a fully qualified branch/tag ref; nothing else."""
    if not isinstance(revision, str) or not revision or len(revision) > 255:
        raise SourceError(Reason.UNSUPPORTED_REVISION, "revision must be a non-empty string")
    if revision.startswith("refs/"):
        return RefName(revision)
    if _HEXISH_RE.fullmatch(revision):
        if revision != revision.lower():
            raise SourceError(Reason.UNSUPPORTED_REVISION, "object IDs must be lower-case")
        if len(revision) != object_format.hex_length:
            raise SourceError(Reason.ABBREVIATED_OBJECT_ID,
                              f"a full {object_format.hex_length}-digit {object_format.value} object ID is required")
        return ObjectId(revision, object_format)
    raise SourceError(Reason.UNSUPPORTED_REVISION,
                      f"{safe_text(revision)} is not a full object ID or refs/heads/... or refs/tags/... name")


def _single_oid_line(out: bytes, object_format: ObjectFormat) -> ObjectId:
    try:
        text = out.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SourceError(Reason.MALFORMED_GIT_OUTPUT, "non-ASCII object ID") from exc
    if not text.endswith("\n") or text.count("\n") != 1:
        raise SourceError(Reason.MALFORMED_GIT_OUTPUT, "expected exactly one object ID line")
    return output_oid(text[:-1], object_format)


def output_oid(text: str, object_format: ObjectFormat) -> ObjectId:
    """An object ID printed by Git. Any deviation is malformed output, not caller error."""
    try:
        return ObjectId(text, object_format)
    except SourceError as exc:
        raise SourceError(Reason.MALFORMED_GIT_OUTPUT, f"invalid object ID in Git output: {exc.detail}") from exc


def resolve_revision(repo: RegisteredRepository, revision: str, runner: GitRunner | None = None) -> ResolvedRevision:
    """Resolve a permitted revision identifier to the full commit and tree object IDs."""
    parsed = parse_revision(revision, repo.object_format)
    run = runner or repo.runner()
    fmt = repo.object_format
    if isinstance(parsed, RefName):
        try:
            out = run.run(ShowRef(parsed))
        except SourceError as exc:
            if exc.reason is Reason.GIT_COMMAND_FAILED:
                raise SourceError(Reason.REF_NOT_FOUND, f"{parsed.value} does not exist") from exc
            raise
        try:
            text = out.decode("ascii")
        except UnicodeDecodeError as exc:
            raise SourceError(Reason.MALFORMED_GIT_OUTPUT, "non-ASCII show-ref output") from exc
        oid_text, sep, name = text.removesuffix("\n").partition(" ")
        if not text.endswith("\n") or text.count("\n") != 1 or not sep or name != parsed.value:
            raise SourceError(Reason.MALFORMED_GIT_OUTPUT, "show-ref did not return exactly the requested ref")
        target = output_oid(oid_text, fmt)
    else:
        target = parsed
        try:
            kind = run.run(ObjectType(target))
        except SourceError as exc:
            if exc.reason is Reason.GIT_COMMAND_FAILED:
                raise SourceError(Reason.MISSING_OBJECT, f"{target.value} is not in the repository") from exc
            raise
        if kind != b"commit\n":
            raise SourceError(Reason.NOT_A_COMMIT, f"{target.value} is a {safe_text(kind.strip())}, not a commit")
    try:
        commit = _single_oid_line(run.run(Peel(target, "commit")), fmt)
        tree = _single_oid_line(run.run(Peel(commit, "tree")), fmt)
    except SourceError as exc:
        if exc.reason is Reason.GIT_COMMAND_FAILED:
            raise SourceError(Reason.NOT_A_COMMIT, f"{revision} does not name a readable commit") from exc
        raise
    if isinstance(parsed, ObjectId) and commit != parsed:
        raise SourceError(Reason.MALFORMED_GIT_OUTPUT, "peeled commit differs from the requested commit")
    return ResolvedRevision(requested=revision, commit=commit, tree=tree)
