"""Read-only source snapshots of one resolved commit (PROJECT_SPEC.md 9.2, 5.2, 12.2).

Pipeline, each step fail-closed:

1. Resolve the requested revision to full commit and tree IDs (`repository.py`).
2. List the commit's tree with `ls-tree -r -z` and parse it strictly. Every path in the
   commit is validated; an unsafe name anywhere refuses the snapshot.
3. Apply the reviewed source scope and the built-in secret-file policy. Symlinks,
   gitlinks, and special entries inside the scope are refused, never silently omitted.
   Entries outside the scope or matched by the secret policy are recorded as exclusions.
4. Check case/normalization collisions and the snapshot limits *before* reading blobs.
5. Read raw blob bytes with `cat-file --batch`, verify each object's size and Git object
   hash, and refuse Git LFS pointers.
6. Write the files into a private staging directory, re-verify them against the manifest,
   make them read-only, and atomically rename the staging directory into place. Any
   failure removes the staging directory: there is no partial successful snapshot.

The manifest is deterministic: the same commit, scope, limits, and Git version always
produce byte-identical `source-manifest.json`. It records no absolute local paths and no
timestamps. Uncommitted changes are never included, and the manifest says so.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from .command import CatFileBatch, GitRunner, LsTree, ObjectFormat, ObjectId
from .errors import Reason, SourceError, safe_text
from .paths import SECRET_POLICY_VERSION, SourceScope, check_collisions, is_secret_path, validate_tree_path
from .repository import RegisteredRepository, ResolvedRevision, output_oid, resolve_revision

MIB: Final = 1024 * 1024
MANIFEST_NAME: Final = "source-manifest.json"
SOURCE_DIR: Final = "source"
MANIFEST_SCHEMA_VERSION: Final = "1.0"

REGULAR_MODES: Final = {"100644": False, "100755": True}  # mode -> executable
LFS_POINTER_PREFIXES: Final = (b"version https://git-lfs.github.com/spec/v1", b"version https://hawser.github.com/spec/v1")
LFS_POINTER_MAX_BYTES: Final = 1024


LIMIT_CEILINGS: Final = {"max_total_bytes": 100 * MIB, "max_entries": 20_000, "max_file_bytes": 10 * MIB,
                         "max_tree_entries": 100_000}


@dataclass(frozen=True)
class SnapshotLimits:
    """PROJECT_SPEC.md 5.2 source snapshot cap. Callers may tighten, never loosen, it."""

    max_total_bytes: int = 100 * MIB
    max_entries: int = 20_000
    max_file_bytes: int = 10 * MIB
    # Resource bound on listing the whole commit (not the exported snapshot).
    max_tree_entries: int = 100_000

    def __post_init__(self) -> None:
        for name, ceiling in LIMIT_CEILINGS.items():
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or not 0 < value <= ceiling:
                raise SourceError(Reason.INVALID_SOURCE_SCOPE, f"{name} must be within the approved ceiling")

    def as_record(self) -> dict[str, int]:
        return {"max_total_bytes": self.max_total_bytes, "max_entries": self.max_entries,
                "max_file_bytes": self.max_file_bytes}


@dataclass(frozen=True)
class TreeEntry:
    mode: str
    object_type: str
    oid: ObjectId
    size: int | None
    path: str


@dataclass(frozen=True)
class SnapshotResult:
    snapshot_dir: Path
    source_dir: Path
    manifest_path: Path
    manifest_sha256: str
    manifest: dict[str, Any]


# --- Parsing Git output ---------------------------------------------------------------

_LS_TREE_HEADER: Final = re.compile(
    rb"([0-7]{6}) (blob|tree|commit) ([0-9a-f]{40}|[0-9a-f]{64}) +(0|[1-9][0-9]{0,15}|-|BAD)")


def parse_ls_tree(out: bytes, object_format: ObjectFormat, max_entries: int) -> list[TreeEntry]:
    """Strictly parse NUL-delimited `ls-tree -r -z -l` records. Paths are validated."""
    if out == b"":
        return []
    if not out.endswith(b"\0"):
        raise SourceError(Reason.MALFORMED_GIT_OUTPUT, "ls-tree output is not NUL-terminated")
    records = out[:-1].split(b"\0")
    if len(records) > max_entries:
        raise SourceError(Reason.TREE_ENTRY_LIMIT, f"commit has more than {max_entries} tree entries")
    entries: list[TreeEntry] = []
    seen: set[str] = set()
    for record in records:
        header, sep, raw_path = record.partition(b"\t")
        m = _LS_TREE_HEADER.fullmatch(header)
        if not sep or not m:
            raise SourceError(Reason.MALFORMED_GIT_OUTPUT, f"unparseable ls-tree record {safe_text(record[:80])}")
        mode, object_type, oid_text, size_text = (g.decode("ascii") for g in m.groups())
        path = validate_tree_path(raw_path)
        if size_text == "BAD":  # `ls-tree -l` could not read the object (absent, e.g. a partial clone)
            raise SourceError(Reason.MISSING_OBJECT, f"object {oid_text} for {safe_text(path)} is missing")
        if path in seen:
            raise SourceError(Reason.MALFORMED_GIT_OUTPUT, f"duplicate tree path {safe_text(path)}")
        seen.add(path)
        size = None if size_text == "-" else int(size_text)
        if (object_type == "blob") == (size is None):
            raise SourceError(Reason.MALFORMED_GIT_OUTPUT, f"size field inconsistent for {safe_text(path)}")
        entries.append(TreeEntry(mode, object_type, output_oid(oid_text, object_format), size, path))
    return entries


def parse_cat_file_batch(out: bytes, requests: list[tuple[ObjectId, int]]) -> list[bytes]:
    """Parse `cat-file --batch` output for exactly the requested blobs, in order.

    Each object's header must name the requested ID, type blob, and the size ls-tree
    reported; its bytes must hash to that ID. Anything else is refused.
    """
    blobs: list[bytes] = []
    pos = 0
    for oid, expected_size in requests:
        newline = out.find(b"\n", pos, pos + 200)
        if newline < 0:
            raise SourceError(Reason.MALFORMED_GIT_OUTPUT, "cat-file header missing or too long")
        header = out[pos:newline]
        if header == oid.value.encode() + b" missing":
            raise SourceError(Reason.MISSING_OBJECT, f"blob {oid.value} is missing")
        parts = header.split(b" ")
        if len(parts) != 3 or parts[0] != oid.value.encode():
            raise SourceError(Reason.MALFORMED_GIT_OUTPUT, "cat-file header does not match the request")
        if parts[1] != b"blob":
            raise SourceError(Reason.OBJECT_TYPE_MISMATCH, f"{oid.value} is a {safe_text(parts[1])}, not a blob")
        if not parts[2].isdigit() or int(parts[2]) != expected_size:
            raise SourceError(Reason.MALFORMED_GIT_OUTPUT, f"size of {oid.value} differs from the tree listing")
        start = newline + 1
        end = start + expected_size
        if end + 1 > len(out) or out[end:end + 1] != b"\n":
            raise SourceError(Reason.MALFORMED_GIT_OUTPUT, f"content of {oid.value} is truncated or unterminated")
        content = out[start:end]
        if git_blob_id(content, oid.object_format) != oid.value:
            raise SourceError(Reason.OBJECT_HASH_MISMATCH, f"bytes returned for {oid.value} do not hash to it")
        blobs.append(content)
        pos = end + 1
    if pos != len(out):
        raise SourceError(Reason.MALFORMED_GIT_OUTPUT, "unexpected trailing cat-file output")
    return blobs


def git_blob_id(content: bytes, object_format: ObjectFormat) -> str:
    h = hashlib.new(object_format.value)
    h.update(b"blob %d\0" % len(content))
    h.update(content)
    return h.hexdigest()


def is_lfs_pointer(content: bytes) -> bool:
    return len(content) <= LFS_POINTER_MAX_BYTES and content.startswith(LFS_POINTER_PREFIXES)


# --- Manifest -------------------------------------------------------------------------


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_tag(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def inclusion_profile(scope: SourceScope, limits: SnapshotLimits) -> dict[str, Any]:
    body: dict[str, Any] = {"include": sorted(scope.include), "secret_policy": SECRET_POLICY_VERSION,
                            "limits": limits.as_record()}
    return {**body, "sha256": sha256_tag(canonical_json(body))}


# --- Planning (pure) ------------------------------------------------------------------


@dataclass(frozen=True)
class Plan:
    included: list[TreeEntry]
    excluded: list[dict[str, str]]
    total_bytes: int


def plan_snapshot(entries: list[TreeEntry], scope: SourceScope, limits: SnapshotLimits) -> Plan:
    included: list[TreeEntry] = []
    excluded: list[dict[str, str]] = []
    matched: set[str] = set()
    for entry in entries:
        prefix = scope.matching_prefix(entry.path)
        if prefix is None:
            excluded.append({"path": entry.path, "reason": "OUTSIDE_SOURCE_SCOPE", "mode": entry.mode})
            continue
        if entry.mode == "120000":
            raise SourceError(Reason.SYMLINK_ENTRY, f"symlink {safe_text(entry.path)} is inside the source scope")
        if entry.mode == "160000" or entry.object_type == "commit":
            raise SourceError(Reason.GITLINK_ENTRY, f"submodule {safe_text(entry.path)} is inside the source scope")
        if entry.mode not in REGULAR_MODES:
            raise SourceError(Reason.SPECIAL_ENTRY, f"unsupported mode {entry.mode} for {safe_text(entry.path)}")
        if entry.object_type != "blob" or entry.size is None:
            raise SourceError(Reason.OBJECT_TYPE_MISMATCH, f"{safe_text(entry.path)} is not a blob")
        if is_secret_path(entry.path):
            if entry.path == prefix:
                raise SourceError(Reason.SECRET_PATH_REQUIRED,
                                  f"required path {safe_text(entry.path)} matches the secret-file policy")
            excluded.append({"path": entry.path, "reason": "SECRET_FILE_POLICY", "mode": entry.mode})
            continue
        matched.add(prefix)
        included.append(entry)
    missing = [p for p in scope.include if p not in matched]
    if missing:
        raise SourceError(Reason.REQUIRED_PATH_MISSING,
                          f"no committed file under required path {safe_text(missing[0])}")
    check_collisions(e.path for e in included)
    if len(included) > limits.max_entries:
        raise SourceError(Reason.ENTRY_LIMIT, f"{len(included)} files exceed the {limits.max_entries}-entry limit")
    total = 0
    for entry in included:
        size = entry.size or 0  # blobs always carry a size (parse_ls_tree)
        if size > limits.max_file_bytes:
            raise SourceError(Reason.FILE_SIZE_LIMIT, f"{safe_text(entry.path)} is {size} bytes")
        total += size
    if total > limits.max_total_bytes:
        raise SourceError(Reason.TOTAL_SIZE_LIMIT, f"{total} bytes exceed the {limits.max_total_bytes}-byte limit")
    included.sort(key=lambda e: e.path.encode("utf-8"))
    excluded.sort(key=lambda e: e["path"].encode("utf-8"))
    return Plan(included=included, excluded=excluded, total_bytes=total)


def build_manifest(repo: RegisteredRepository, resolved: ResolvedRevision, scope: SourceScope,
                   limits: SnapshotLimits, plan: Plan, contents: list[bytes]) -> dict[str, Any]:
    files = [
        {"path": e.path, "mode": e.mode, "git_object_id": e.oid.value, "size_bytes": len(c),
         "sha256": sha256_tag(c)}
        for e, c in zip(plan.included, contents, strict=True)
    ]
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "kind": "source-manifest",
        "object_format": repo.object_format.value,
        "requested_revision": resolved.requested,
        "commit_id": resolved.commit.value,
        "tree_id": resolved.tree.value,
        "git_version": repo.git.version_text,
        "inclusion_profile": inclusion_profile(scope, limits),
        "uncommitted_changes_included": False,
        "complete_commit": not plan.excluded,
        "totals": {"file_count": len(files), "total_bytes": plan.total_bytes, "excluded_count": len(plan.excluded)},
        "source_tree_sha256": sha256_tag(canonical_json(files)),
        "files": files,
        "excluded": plan.excluded,
    }


# --- Destination and writing ----------------------------------------------------------


def validate_destination(destination: Path, repo_root: Path) -> None:
    """Snapshots go into a private, canonical directory that is unrelated to the repository."""
    raw = str(destination)
    if not os.path.isabs(raw) or os.path.realpath(raw) != raw:
        raise SourceError(Reason.DESTINATION_INVALID, "destination must be an absolute canonical path")
    try:
        st = os.lstat(destination)
    except FileNotFoundError as exc:
        raise SourceError(Reason.DESTINATION_INVALID, "destination does not exist") from exc
    if not stat.S_ISDIR(st.st_mode):
        raise SourceError(Reason.DESTINATION_INVALID, "destination is not a directory")
    if st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise SourceError(Reason.DESTINATION_INVALID, "destination must be owned by the user with mode 0700")
    if destination.is_relative_to(repo_root) or repo_root.is_relative_to(destination):
        raise SourceError(Reason.DESTINATION_INVALID, "destination must not contain or be inside the repository")


def _write_tree(source: Path, plan: Plan, contents: list[bytes]) -> None:
    os.mkdir(source, 0o700)
    for entry, content in zip(plan.included, contents, strict=True):
        parent = source
        for part in entry.path.split("/")[:-1]:
            parent = parent / part
            try:
                os.mkdir(parent, 0o700)
            except FileExistsError:
                if not stat.S_ISDIR(os.lstat(parent).st_mode):
                    raise SourceError(Reason.PATH_COLLISION, f"{safe_text(entry.path)} clashes on disk") from None
        target = parent / entry.path.rsplit("/", 1)[-1]
        try:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            raise SourceError(Reason.PATH_COLLISION, f"{safe_text(entry.path)} clashes on disk") from None
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)


def _verify_written(source: Path, manifest: dict[str, Any]) -> None:
    expected = {f["path"]: f for f in manifest["files"]}
    found: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(source, followlinks=False):
        for name in dirnames + filenames:
            full = Path(dirpath) / name
            st = os.lstat(full)
            if stat.S_ISDIR(st.st_mode):
                continue
            rel = full.relative_to(source).as_posix()
            record = expected.get(rel)
            if not stat.S_ISREG(st.st_mode) or record is None:
                raise SourceError(Reason.SNAPSHOT_VERIFICATION_FAILED, f"unexpected entry {safe_text(rel)}")
            data = full.read_bytes()
            if sha256_tag(data) != record["sha256"] or len(data) != record["size_bytes"]:
                raise SourceError(Reason.SNAPSHOT_VERIFICATION_FAILED, f"{safe_text(rel)} differs from the manifest")
            found.add(rel)
    if found != set(expected):
        raise SourceError(Reason.SNAPSHOT_VERIFICATION_FAILED, "written files differ from the manifest")


def _make_read_only(source: Path, plan: Plan) -> None:
    for entry in plan.included:
        os.chmod(source / entry.path, 0o555 if REGULAR_MODES[entry.mode] else 0o444, follow_symlinks=False)
    for dirpath, _dirs, _files in sorted(os.walk(source), key=lambda t: len(t[0]), reverse=True):
        os.chmod(dirpath, 0o555)


def remove_snapshot_tree(path: Path) -> None:
    """Remove a staging or snapshot directory this module created (restoring write bits first)."""
    if not os.path.lexists(path):
        return
    for dirpath, dirnames, _files in os.walk(path, followlinks=False):
        with contextlib.suppress(OSError):
            os.chmod(dirpath, 0o700)
        for name in dirnames:
            with contextlib.suppress(OSError):
                os.chmod(Path(dirpath) / name, 0o700, follow_symlinks=False)
    shutil.rmtree(path)


def create_snapshot(repo: RegisteredRepository, revision: str, scope: SourceScope, destination: Path, *,
                    limits: SnapshotLimits | None = None, runner: GitRunner | None = None) -> SnapshotResult:
    """Create one validated, read-only snapshot of a committed revision. All-or-nothing."""
    limits = limits or SnapshotLimits()
    validate_destination(destination, repo.root)
    run = runner or repo.runner()
    resolved = resolve_revision(repo, revision, run)
    listing = run.run(LsTree(resolved.commit))
    entries = parse_ls_tree(listing, repo.object_format, limits.max_tree_entries)
    plan = plan_snapshot(entries, scope, limits)
    requests = [(e.oid, e.size or 0) for e in plan.included]
    cap = plan.total_bytes + len(requests) * 160 + 1
    contents = parse_cat_file_batch(run.run(CatFileBatch(tuple(o for o, _ in requests), stdout_cap=cap)), requests)
    for entry, content in zip(plan.included, contents, strict=True):
        if is_lfs_pointer(content):
            raise SourceError(Reason.LFS_POINTER, f"{safe_text(entry.path)} is an unsupported Git LFS pointer")
    manifest = build_manifest(repo, resolved, scope, limits, plan, contents)
    manifest_bytes = canonical_json(manifest) + b"\n"

    token = secrets.token_hex(16)
    staging = destination / f".staging-{token}"
    final = destination / f"snapshot-{token}"
    os.mkdir(staging, 0o700)
    try:
        source = staging / SOURCE_DIR
        _write_tree(source, plan, contents)
        _verify_written(source, manifest)
        _make_read_only(source, plan)
        fd = os.open(staging / MANIFEST_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(fd, "wb") as handle:
            handle.write(manifest_bytes)
        if os.path.lexists(final):
            raise SourceError(Reason.DESTINATION_INVALID, "snapshot directory already exists")
        os.rename(staging, final)
    except BaseException:
        remove_snapshot_tree(staging)
        raise
    return SnapshotResult(snapshot_dir=final, source_dir=final / SOURCE_DIR, manifest_path=final / MANIFEST_NAME,
                          manifest_sha256=sha256_tag(manifest_bytes), manifest=manifest)
