"""Synthetic Git repositories for PP-005 tests, created only under pytest's tmp_path.

Fixture construction uses the same reviewed Git executable with an isolated environment
(no host global or system config, fixed identities and dates). Plumbing commands craft
trees that porcelain refuses to create (unsafe names, collisions, symlinks, gitlinks), so
the snapshot code is tested against what a hostile repository could actually contain.
"""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from patchproof.git.command import GitBinary, resolve_git_binary

_GIT: GitBinary | None = None


def git_binary() -> GitBinary:
    global _GIT
    if _GIT is None:
        _GIT = resolve_git_binary()
    return _GIT


def fixture_env() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin", "HOME": "/var/empty", "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_AUTHOR_NAME": "Synthetic", "GIT_AUTHOR_EMAIL": "synthetic@example.invalid",
        "GIT_COMMITTER_NAME": "Synthetic", "GIT_COMMITTER_EMAIL": "synthetic@example.invalid",
        "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
    }


def git(cwd: Path, *args: str, stdin: bytes | None = None) -> bytes:
    """Run fixture-construction Git (writes only inside the synthetic repository)."""
    proc = subprocess.run([git_binary().real_path, *args], cwd=cwd, env=fixture_env(), input=stdin,
                          capture_output=True, check=False, timeout=60)
    if proc.returncode != 0:
        raise AssertionError(f"fixture git {args!r} failed: {proc.stderr.decode(errors='replace')}")
    return proc.stdout


@dataclass
class Repo:
    root: Path
    object_format: str

    def git(self, *args: str, stdin: bytes | None = None) -> bytes:
        return git(self.root, *args, stdin=stdin)

    def text(self, *args: str) -> str:
        return self.git(*args).decode().strip()

    def blob(self, content: bytes) -> str:
        return self.git("hash-object", "-w", "--stdin", stdin=content).decode().strip()

    def tree(self, entries: Sequence[tuple[str, bytes, str]]) -> str:
        """Write a raw tree object (mode, name bytes, hex oid) without Git's validation."""
        def sort_key(entry: tuple[str, bytes, str]) -> bytes:
            mode, name, _ = entry
            return name + b"/" if mode == "40000" else name

        raw = b"".join(mode.encode() + b" " + name + b"\0" + bytes.fromhex(oid)
                       for mode, name, oid in sorted(entries, key=sort_key))
        return self.git("hash-object", "-t", "tree", "-w", "--literally", "--stdin", stdin=raw).decode().strip()

    def commit_tree(self, tree: str, message: str = "synthetic", ref: str = "refs/heads/main") -> str:
        commit = self.git("commit-tree", tree, "-m", message).decode().strip()
        self.git("update-ref", ref, commit)
        return commit

    def commit_files(self, files: Mapping[str, bytes], message: str = "synthetic") -> str:
        for rel, content in files.items():
            path = self.root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        self.git("add", "--", *files)
        self.git("commit", "-q", "-m", message)
        return self.text("rev-parse", "HEAD")


def make_repo(path: Path, files: Mapping[str, bytes] | None = None, *, object_format: str = "sha1") -> Repo:
    path.mkdir(parents=True, exist_ok=True)
    git(path, "init", "-q", f"--object-format={object_format}", "-b", "main")
    repo = Repo(path, object_format)
    if files:
        repo.commit_files(files)
    return repo


def fingerprint(root: Path) -> dict[str, tuple[object, ...]]:
    """Every path under root (including .git): type, mode, size, mtime, and content hash."""
    result: dict[str, tuple[object, ...]] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in [".", *dirnames, *filenames]:
            full = Path(dirpath) if name == "." else Path(dirpath) / name
            st = os.lstat(full)
            rel = full.relative_to(root).as_posix()
            if stat.S_ISREG(st.st_mode):
                digest: object = hashlib.sha256(full.read_bytes()).hexdigest()
            elif stat.S_ISLNK(st.st_mode):
                digest = os.readlink(full)
            else:
                digest = None
            result[rel] = (stat.S_IFMT(st.st_mode), stat.S_IMODE(st.st_mode), st.st_size, st.st_mtime_ns, digest)
    return result


def private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return Path(os.path.realpath(path))
