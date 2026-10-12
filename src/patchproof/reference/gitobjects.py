"""Deterministic Git object serialization and a write-once loose-object repository writer.

The reference fixture repository is written directly as Git objects instead of by running
Git. No Git process, hook, filter, configuration, or template is involved, so generation
cannot be influenced by host Git configuration (``filter.lfs.required=true`` on this host)
and never performs a Git write against an existing repository. Object IDs are SHA-1 over
the canonical object encoding, exactly as Git computes them; tests cross-check every object
with the reviewed Git binary (``fsck --strict``, ``cat-file``) through read-only commands.
"""

from __future__ import annotations

import hashlib
import os
import re
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Final

OBJECT_FORMAT: Final = "sha1"
FILE_MODE: Final = "100644"
TREE_MODE: Final = "40000"

_NAME_RE: Final = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}")
_IDENT_RE: Final = re.compile(r"[A-Za-z0-9 ._-]{1,64} <[a-z0-9.-]{1,64}@[a-z0-9.-]{1,64}>")
_REF_RE: Final = re.compile(r"refs/(heads|tags)/[a-z0-9][a-z0-9-]{0,62}")
_OID_RE: Final = re.compile(r"[0-9a-f]{40}")

REPOSITORY_CONFIG: Final = (
    b"[core]\n"
    b"\trepositoryformatversion = 0\n"
    b"\tfilemode = true\n"
    b"\tbare = false\n"
    b"\tlogallrefupdates = false\n"
)


class FixtureGenerationError(Exception):
    """The reference repository could not be generated as specified. Nothing is published."""


def object_id(kind: str, payload: bytes) -> str:
    header = f"{kind} {len(payload)}".encode("ascii") + b"\0"
    return hashlib.sha1(header + payload, usedforsecurity=False).hexdigest()


def _check_oid(oid: str) -> str:
    if not _OID_RE.fullmatch(oid):
        raise FixtureGenerationError(f"not a full SHA-1 object ID: {oid!r}")
    return oid


@dataclass(frozen=True)
class Signature:
    """A fixed author/committer/tagger identity with an explicit UTC timestamp."""

    identity: str
    epoch_seconds: int

    def __post_init__(self) -> None:
        if not _IDENT_RE.fullmatch(self.identity) or not 0 < self.epoch_seconds < 2**32:
            raise FixtureGenerationError("invalid fixture signature")

    def encode(self) -> bytes:
        return f"{self.identity} {self.epoch_seconds} +0000".encode("ascii")


def _check_message(message: str) -> bytes:
    if not message.endswith("\n") or not message.isascii() or "\0" in message or "\r" in message:
        raise FixtureGenerationError("messages must be ASCII text ending in a newline")
    return message.encode("ascii")


def tree_payload(entries: dict[str, tuple[str, str]]) -> bytes:
    """Encode one tree level: name -> (mode, oid), sorted the way Git sorts tree entries."""
    def sort_key(name: str) -> bytes:
        return name.encode("ascii") + (b"/" if entries[name][0] == TREE_MODE else b"")

    out = bytearray()
    for name in sorted(entries, key=sort_key):
        mode, oid = entries[name]
        if mode not in (FILE_MODE, TREE_MODE) or not _NAME_RE.fullmatch(name):
            raise FixtureGenerationError(f"unsupported tree entry {name!r}")
        out += f"{mode} {name}".encode("ascii") + b"\0" + bytes.fromhex(_check_oid(oid))
    return bytes(out)


def commit_payload(tree: str, parents: tuple[str, ...], author: Signature, committer: Signature,
                   message: str) -> bytes:
    lines = [b"tree " + _check_oid(tree).encode("ascii")]
    lines += [b"parent " + _check_oid(p).encode("ascii") for p in parents]
    lines += [b"author " + author.encode(), b"committer " + committer.encode()]
    return b"\n".join(lines) + b"\n\n" + _check_message(message)


def tag_payload(target: str, name: str, tagger: Signature, message: str) -> bytes:
    if not _REF_RE.fullmatch(f"refs/tags/{name}"):
        raise FixtureGenerationError(f"unsupported tag name {name!r}")
    lines = [b"object " + _check_oid(target).encode("ascii"), b"type commit",
             b"tag " + name.encode("ascii"), b"tagger " + tagger.encode()]
    return b"\n".join(lines) + b"\n\n" + _check_message(message)


def _write_new_file(path: Path, data: bytes, mode: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


class LooseObjectRepository:
    """Writes a new non-bare repository layout into an empty directory this process created.

    Every file is created with O_EXCL|O_NOFOLLOW, so nothing pre-existing is overwritten
    and no symlink is followed. There is no index and no checked-out working tree: the
    repository exists to be read by object ID (ADR-004).
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.git_dir = root / ".git"
        self._written: dict[str, bytes] = {}

    def initialize(self, head_branch: str) -> None:
        if not _REF_RE.fullmatch(head_branch) or not head_branch.startswith("refs/heads/"):
            raise FixtureGenerationError("HEAD must name a refs/heads branch")
        os.mkdir(self.git_dir, 0o755)
        for sub in ("objects", "objects/info", "objects/pack", "refs", "refs/heads", "refs/tags"):
            os.mkdir(self.git_dir / sub, 0o755)
        _write_new_file(self.git_dir / "HEAD", f"ref: {head_branch}\n".encode("ascii"), 0o644)
        _write_new_file(self.git_dir / "config", REPOSITORY_CONFIG, 0o644)

    def put(self, kind: str, payload: bytes) -> str:
        oid = object_id(kind, payload)
        if oid in self._written:
            return oid
        directory = self.git_dir / "objects" / oid[:2]
        if not directory.is_dir():
            os.mkdir(directory, 0o755)
        raw = f"{kind} {len(payload)}".encode("ascii") + b"\0" + payload
        _write_new_file(directory / oid[2:], zlib.compress(raw, 9), 0o444)
        self._written[oid] = raw
        return oid

    def put_tree(self, files: dict[str, bytes]) -> str:
        """Write blobs and nested trees for a flat path -> content map; return the root tree ID."""
        level: dict[str, tuple[str, str]] = {}
        children: dict[str, dict[str, bytes]] = {}
        for path, content in files.items():
            head, sep, rest = path.partition("/")
            if sep:
                children.setdefault(head, {})[rest] = content
            else:
                level[head] = (FILE_MODE, self.put("blob", content))
        for name, sub in children.items():
            if name in level:
                raise FixtureGenerationError(f"{name!r} is both a file and a directory")
            level[name] = (TREE_MODE, self.put_tree(sub))
        return self.put("tree", tree_payload(level))

    def set_ref(self, ref: str, oid: str) -> None:
        if not _REF_RE.fullmatch(ref):
            raise FixtureGenerationError(f"unsupported ref name {ref!r}")
        _write_new_file(self.git_dir / ref, _check_oid(oid).encode("ascii") + b"\n", 0o644)

    def verify(self) -> int:
        """Re-read every object written, decompress it and recompute its ID. Returns the count."""
        for oid, raw in self._written.items():
            stored = zlib.decompress((self.git_dir / "objects" / oid[:2] / oid[2:]).read_bytes())
            kind, _, rest = stored.partition(b" ")
            size, _, payload = rest.partition(b"\0")
            if stored != raw or int(size) != len(payload) or object_id(kind.decode("ascii"), payload) != oid:
                raise FixtureGenerationError(f"object {oid} did not verify after writing")
        return len(self._written)
