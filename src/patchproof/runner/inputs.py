"""Immutable run inputs: content-addressed pack snapshots and verified source snapshots (PP-008).

**The PP-007 R2 obligation:** the bytes that were validated and approved must be exactly
the bytes the verifier sees. The live pack directory is therefore never mounted.

**`materialize_pack`** copies a validated pack into a private store, under a directory
named by its approved pack-tree hash. Each file is:
- read without following symlinks and without blocking;
- re-checked as the same regular file;
- compared with its validated size and SHA-256.

The copy is written with `O_EXCL`, made read-only (files `0444`, directories `0555`),
re-hashed, and renamed into place atomically. Any difference from the validated list is
refused, never accepted as a new version.

**`verify_pack_snapshot`** re-hashes a materialized snapshot immediately before a run and
again afterwards. **`verify_source_snapshot`** does the same for a PP-005 source snapshot
against its manifest hash. Neither repairs anything; a mismatch raises
`InputIntegrityError`.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from ..core.records import RecordError, load_record
from ..core.records.evidence import SourceManifest
from ..git.snapshot import MANIFEST_NAME, SOURCE_DIR, canonical_json
from ..packs.validation import MAX_FILE_BYTES, PackFile, ValidatedPack, pack_tree_sha256

MAX_MANIFEST_BYTES: Final = 64 * 1024 * 1024


class InputIntegrityError(ValueError):
    """A run input differs from its approved identity. Nothing is repaired."""


@dataclass(frozen=True)
class PackSnapshot:
    root: Path
    pack_tree_sha256: str
    manifest_sha256: str
    files: tuple[PackFile, ...]


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _read_exact(path: Path, *, limit: int) -> tuple[bytes, os.stat_result]:
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode):
        raise InputIntegrityError(f"{path.name} is not a regular file")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        st = os.fstat(handle.fileno())
        if not stat.S_ISREG(st.st_mode) or (st.st_dev, st.st_ino) != (before.st_dev, before.st_ino):
            raise InputIntegrityError(f"{path.name} changed type or identity while it was read")
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise InputIntegrityError(f"{path.name} exceeds the size limit")
    return data, st


def _private_dir(path: Path) -> None:
    raw = str(path)
    if not os.path.isabs(raw) or os.path.realpath(raw) != raw:
        raise InputIntegrityError("store must be an absolute canonical directory")
    st = os.lstat(raw)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077:
        raise InputIntegrityError("store must be a private (0700) directory owned by the current user")


def _tree(root: Path) -> dict[str, tuple[bytes, os.stat_result]]:
    """Every entry under root, read without following symlinks. Directories map to b''."""
    found: dict[str, tuple[bytes, os.stat_result]] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in [*dirnames, *filenames]:
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            st = os.lstat(full)
            if stat.S_ISDIR(st.st_mode):
                found[rel] = (b"", st)
            elif stat.S_ISREG(st.st_mode):
                found[rel] = _read_exact(full, limit=MAX_FILE_BYTES)
            else:
                raise InputIntegrityError(f"{rel} is a symlink or special file")
    return found


def verify_pack_snapshot(snapshot: PackSnapshot) -> None:
    """Re-hash a materialized pack. It must equal the approved file list exactly and be read-only."""
    root = snapshot.root
    st = os.lstat(root)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o555:
        raise InputIntegrityError("pack snapshot root is not an owned read-only directory")
    if root.name != snapshot.pack_tree_sha256.removeprefix("sha256:"):
        raise InputIntegrityError("pack snapshot is not stored under its content address")
    entries = _tree(root)
    expected_files = {f.path: f for f in snapshot.files}
    expected_dirs = {"/".join(p.split("/")[:i]) for p in expected_files for i in range(1, p.count("/") + 1)}
    if set(entries) != set(expected_files) | expected_dirs:
        raise InputIntegrityError("pack snapshot entries differ from the approved file list")
    for rel, (data, est) in entries.items():
        if rel in expected_dirs:
            if stat.S_IMODE(est.st_mode) != 0o555 or est.st_uid != os.getuid():
                raise InputIntegrityError(f"{rel}/ is not an owned read-only directory")
            continue
        want = expected_files[rel]
        if stat.S_IMODE(est.st_mode) != 0o444 or est.st_uid != os.getuid():
            raise InputIntegrityError(f"{rel} is not an owned read-only file")
        if (len(data), _sha256(data)) != (want.size, want.sha256):
            raise InputIntegrityError(f"{rel} differs from its approved bytes")
    if pack_tree_sha256(snapshot.files) != snapshot.pack_tree_sha256:
        raise InputIntegrityError("approved file list does not hash to the approved pack-tree hash")
    manifest = next((f for f in snapshot.files if f.path == "pack.json"), None)
    if manifest is None or manifest.sha256 != snapshot.manifest_sha256:
        raise InputIntegrityError("pack.json does not match the approved manifest hash")


def materialize_pack(pack: ValidatedPack, store: Path) -> PackSnapshot:
    """Copy a validated pack, byte-verified, into the content-addressed store (idempotent)."""
    _private_dir(store)
    snapshot = PackSnapshot(root=store / pack.pack_tree_sha256.removeprefix("sha256:"),
                            pack_tree_sha256=pack.pack_tree_sha256, manifest_sha256=pack.manifest_sha256,
                            files=pack.files)
    if pack_tree_sha256(pack.files) != pack.pack_tree_sha256:
        raise InputIntegrityError("validated file list does not hash to its pack-tree hash")
    if os.path.lexists(snapshot.root):
        verify_pack_snapshot(snapshot)
        return snapshot
    staging = store / f".staging-{secrets.token_hex(16)}"
    os.mkdir(staging, 0o700)
    try:
        for entry in pack.files:
            data, _ = _read_exact(pack.root / entry.path, limit=MAX_FILE_BYTES)
            if (len(data), _sha256(data)) != (entry.size, entry.sha256):
                raise InputIntegrityError(f"{entry.path} changed after validation; refusing to copy it")
            target = staging / entry.path
            target.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
            os.chmod(target, 0o444)
        for dirpath, _dirs, _files in sorted(os.walk(staging), key=lambda t: len(t[0]), reverse=True):
            if Path(dirpath) != staging:
                os.chmod(dirpath, 0o555)
        if os.path.lexists(snapshot.root):
            raise InputIntegrityError("a snapshot appeared at the destination concurrently")
        os.rename(staging, snapshot.root)  # renaming a directory needs write permission on it (macOS)
        os.chmod(snapshot.root, 0o555)
    except BaseException:
        for dirpath, _dirs, _files in os.walk(staging):
            os.chmod(dirpath, 0o700)
        shutil.rmtree(staging, ignore_errors=True)
        raise
    verify_pack_snapshot(snapshot)
    return snapshot


@dataclass(frozen=True)
class SourceSnapshot:
    snapshot_dir: Path
    manifest_sha256: str

    @property
    def source_dir(self) -> Path:
        return self.snapshot_dir / SOURCE_DIR


def verify_source_snapshot(snapshot: SourceSnapshot) -> SourceManifest:
    """Re-hash a PP-005 snapshot: manifest bytes, then every file against the manifest."""
    raw, _ = _read_exact(snapshot.snapshot_dir / MANIFEST_NAME, limit=MAX_MANIFEST_BYTES)
    if _sha256(raw) != snapshot.manifest_sha256:
        raise InputIntegrityError("source manifest differs from the planned manifest hash")
    try:
        manifest = load_record(SourceManifest, raw, contract="source-manifest", max_bytes=MAX_MANIFEST_BYTES)
    except RecordError as exc:
        raise InputIntegrityError("source manifest is not valid") from exc
    entries = _tree(snapshot.source_dir)
    files = {f.path: f for f in manifest.files}
    dirs = {"/".join(p.split("/")[:i]) for p in files for i in range(1, p.count("/") + 1)}
    if set(entries) != set(files) | dirs:
        raise InputIntegrityError("source snapshot entries differ from its manifest")
    for rel, (data, st) in entries.items():
        if rel in dirs:
            continue
        if stat.S_IMODE(st.st_mode) & 0o222:
            raise InputIntegrityError(f"{rel} is writable")
        if (len(data), _sha256(data)) != (files[rel].size_bytes, files[rel].sha256):
            raise InputIntegrityError(f"{rel} differs from the source manifest")
    if _sha256(canonical_json([f.model_dump() for f in manifest.files])) != manifest.source_tree_sha256:
        raise InputIntegrityError("source tree hash does not match the manifest's file list")
    return manifest
