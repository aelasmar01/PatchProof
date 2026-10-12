"""Narrow typed Git subprocess wrapper (PROJECT_SPEC.md 9.1, 9.2; threat model AC-2).

Callers build typed operation objects; only this module turns them into argument arrays.
There is no function that accepts a caller-supplied Git argument list, no `shell=True`,
and every positional argument is a value that was validated against a strict grammar
when its object was constructed (a full object ID or a fully qualified ref name).

Configuration isolation, all of which applies to every invocation:

- The environment is built from scratch, never filtered from `os.environ`, so no
  `GIT_*` runtime variable (`GIT_DIR`, `GIT_CONFIG_PARAMETERS`, `GIT_EXEC_PATH`,
  `GIT_ALTERNATE_OBJECT_DIRECTORIES`, `GIT_SSH_COMMAND`, trace variables, ...) is inherited.
- System and global configuration are disabled (`GIT_CONFIG_NOSYSTEM`,
  `GIT_CONFIG_SYSTEM=/dev/null`, `GIT_CONFIG_GLOBAL=/dev/null`, `HOME=/var/empty`), so the
  host's `filter.lfs.*` hooks and `gh` credential helper are never loaded.
- Repository-local configuration cannot be skipped by Git, so `COMMAND_CONFIG` overrides
  the keys that could start a helper; command-line `-c` values take precedence over it.
- Replacement objects and lazy (promisor) fetches are disabled; the allowlisted commands
  never request text conversion or filters, and none of them runs hooks.
- Object reads use an explicit `GIT_DIR`; repository discovery runs only during
  registration, bounded by `GIT_CEILING_DIRECTORIES`, so a parent repository (for
  example a Git repository in the home directory) is never found.

Every invocation has a deadline and bounded stdout/stderr capture.
"""

from __future__ import annotations

import contextlib
import os
import re
import selectors
import signal
import subprocess
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Final, Protocol

from .errors import Reason, SourceError, safe_text

READ_CHUNK: Final = 65536
DEFAULT_STDERR_CAP: Final = 16 * 1024

# Reviewed supported patched release (docs/environment.lock.md section 3.2). Older
# releases are refused rather than trusted to parse untrusted repositories.
MIN_GIT_VERSION: Final = (2, 56, 0)

# Absolute locations the git executable may be resolved from (Homebrew). The macOS
# /usr/bin/git shim is not accepted: it dispatches to whichever developer tools are selected.
ALLOWED_GIT_PATHS: Final = ("/usr/local/bin/git", "/opt/homebrew/bin/git")
ALLOWED_GIT_REAL_PREFIXES: Final = ("/usr/local/Cellar/git/", "/opt/homebrew/Cellar/git/")

EMPTY_DIR: Final = "/var/empty"

# The complete environment of every Git subprocess, plus GIT_DIR or
# GIT_CEILING_DIRECTORIES set per operation. Nothing is copied from os.environ.
BASE_ENV: Final[dict[str, str]] = {
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    "HOME": EMPTY_DIR,
    "XDG_CONFIG_HOME": EMPTY_DIR,
    "LC_ALL": "C",
    "LANG": "C",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_SYSTEM": "/dev/null",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_ATTR_NOSYSTEM": "1",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_NO_LAZY_FETCH": "1",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_LITERAL_PATHSPECS": "1",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_ASKPASS": "/usr/bin/false",
    "SSH_ASKPASS": "/usr/bin/false",
    "GIT_PAGER": "cat",
    "PAGER": "cat",
    "GIT_ADVICE": "0",
}

# Fixed `-c` overrides. Command-line configuration outranks repository-local config, which
# Git always reads and which is untrusted. Each key closes a way a repository could make
# Git run a program, rewrite bytes, reach another object store, or touch the worktree.
COMMAND_CONFIG: Final[tuple[tuple[str, str], ...]] = (
    ("core.hooksPath", "/dev/null"),         # no hooks
    ("core.fsmonitor", "false"),             # no filesystem-monitor helper
    ("core.untrackedCache", "false"),
    ("core.useReplaceRefs", "false"),        # replacement objects (also GIT_NO_REPLACE_OBJECTS)
    ("core.precomposeUnicode", "false"),     # no argv/path rewriting on macOS
    ("core.attributesFile", "/dev/null"),
    ("core.sshCommand", "/usr/bin/false"),
    ("core.askPass", "/usr/bin/false"),
    ("credential.helper", ""),               # resets the helper list
    ("protocol.allow", "never"),             # no transport, including file://
    ("submodule.recurse", "false"),
    ("fetch.recurseSubmodules", "false"),
    ("gc.auto", "0"),
    ("maintenance.auto", "false"),
    ("filter.lfs.required", "false"),        # host has filter.lfs.required=true (environment.lock.md 5)
    ("filter.lfs.process", ""),
    ("filter.lfs.smudge", ""),
    ("filter.lfs.clean", ""),
    ("safe.bareRepository", "explicit"),
)

GLOBAL_OPTIONS: Final = ("--no-pager", "--no-replace-objects", "--literal-pathspecs", "--no-optional-locks")

ALLOWED_SUBCOMMANDS: Final = frozenset({"version", "rev-parse", "show-ref", "cat-file", "ls-tree"})

# Tokens that no argv built here may contain: anything that would convert, filter, fetch,
# write, or execute.
FORBIDDEN_TOKENS: Final = frozenset({
    "--textconv", "--filters", "--path", "--exec", "--upload-pack", "--receive-pack",
    "--work-tree", "--git-dir", "--output", "-o", "--ext-diff", "--recurse-submodules",
    "fetch", "clone", "push", "pull", "checkout", "switch", "reset", "clean", "stash", "init",
    "submodule", "config", "worktree", "archive", "gc", "maintenance", "update-ref", "hash-object",
})


class ObjectFormat(StrEnum):
    SHA1 = "sha1"
    SHA256 = "sha256"

    @property
    def hex_length(self) -> int:
        return 40 if self is ObjectFormat.SHA1 else 64


_HEX_RE: Final = re.compile(r"[0-9a-f]+")


@dataclass(frozen=True)
class ObjectId:
    """A full, lower-case object ID of the repository's object format. Never abbreviated."""

    value: str
    object_format: ObjectFormat

    def __post_init__(self) -> None:
        if not isinstance(self.object_format, ObjectFormat):
            raise SourceError(Reason.OPERATION_NOT_ALLOWED, "object format must be an ObjectFormat")
        if not isinstance(self.value, str) or not _HEX_RE.fullmatch(self.value):
            raise SourceError(Reason.MALFORMED_GIT_OUTPUT, "object ID is not lower-case hexadecimal")
        if len(self.value) != self.object_format.hex_length:
            raise SourceError(Reason.ABBREVIATED_OBJECT_ID,
                              f"expected {self.object_format.hex_length} hex digits for {self.object_format.value}")


# Fully qualified branch or tag names only. Every segment starts with an alphanumeric or
# underscore, so option-like values, '.', '..', hidden segments, and '@{' are unrepresentable.
_REF_SEGMENT: Final = r"[A-Za-z0-9_][A-Za-z0-9_.+-]{0,99}"
REF_NAME_RE: Final = re.compile(rf"refs/(heads|tags)/{_REF_SEGMENT}(/{_REF_SEGMENT}){{0,9}}")


@dataclass(frozen=True)
class RefName:
    value: str

    def __post_init__(self) -> None:
        v = self.value
        if (not isinstance(v, str) or len(v) > 255 or not REF_NAME_RE.fullmatch(v) or ".." in v
                or any(seg.endswith((".", ".lock")) for seg in v.split("/"))):
            raise SourceError(Reason.UNSUPPORTED_REVISION, "not a fully qualified refs/heads or refs/tags name")


# --- Typed operations ------------------------------------------------------------------


def _require(value: object, kind: type) -> None:
    """Runtime check that a positional argument is a validated value object, not a lookalike."""
    if type(value) is not kind:
        raise SourceError(Reason.OPERATION_NOT_ALLOWED, f"expected a validated {kind.__name__}")


class GitOp(Protocol):
    @property
    def op_name(self) -> str: ...

    @property
    def discovery(self) -> bool: ...

    @property
    def timeout_seconds(self) -> float: ...

    @property
    def stdout_cap(self) -> int: ...

    def argv_tail(self) -> list[str]: ...

    def stdin_bytes(self) -> bytes | None: ...


@dataclass(frozen=True)
class Version:
    op_name: str = field(default="version", init=False)
    discovery: bool = field(default=False, init=False)
    timeout_seconds: float = 15.0
    stdout_cap: int = 4096

    def argv_tail(self) -> list[str]:
        return ["version"]

    def stdin_bytes(self) -> bytes | None:
        return None


@dataclass(frozen=True)
class DiscoverRoot:
    """Registration only: what Git itself discovers from the root, bounded by the ceiling."""

    op_name: str = field(default="discover-root", init=False)
    discovery: bool = field(default=True, init=False)
    timeout_seconds: float = 15.0
    stdout_cap: int = 64 * 1024

    def argv_tail(self) -> list[str]:
        return ["rev-parse", "--is-bare-repository", "--absolute-git-dir", "--show-toplevel"]

    def stdin_bytes(self) -> bytes | None:
        return None


@dataclass(frozen=True)
class ShowObjectFormat:
    op_name: str = field(default="show-object-format", init=False)
    discovery: bool = field(default=False, init=False)
    timeout_seconds: float = 15.0
    stdout_cap: int = 4096

    def argv_tail(self) -> list[str]:
        return ["rev-parse", "--show-object-format"]

    def stdin_bytes(self) -> bytes | None:
        return None


@dataclass(frozen=True)
class ShowRef:
    """Exact-name lookup. `--verify` refuses prefixes and DWIM expansion."""

    ref: RefName
    op_name: str = field(default="show-ref", init=False)
    discovery: bool = field(default=False, init=False)
    timeout_seconds: float = 15.0
    stdout_cap: int = 4096

    def __post_init__(self) -> None:
        _require(self.ref, RefName)

    def argv_tail(self) -> list[str]:
        return ["show-ref", "--verify", "--", self.ref.value]

    def stdin_bytes(self) -> bytes | None:
        return None


@dataclass(frozen=True)
class ObjectType:
    oid: ObjectId
    op_name: str = field(default="object-type", init=False)
    discovery: bool = field(default=False, init=False)
    timeout_seconds: float = 15.0
    stdout_cap: int = 4096

    def __post_init__(self) -> None:
        _require(self.oid, ObjectId)

    def argv_tail(self) -> list[str]:
        return ["cat-file", "-t", "--end-of-options", self.oid.value]

    def stdin_bytes(self) -> bytes | None:
        return None


@dataclass(frozen=True)
class Peel:
    """Peel a full object ID to the commit or tree it names (`<oid>^{commit}` / `^{tree}`)."""

    oid: ObjectId
    target: str
    op_name: str = field(default="peel", init=False)
    discovery: bool = field(default=False, init=False)
    timeout_seconds: float = 15.0
    stdout_cap: int = 4096

    def __post_init__(self) -> None:
        _require(self.oid, ObjectId)
        if self.target not in ("commit", "tree"):
            raise SourceError(Reason.OPERATION_NOT_ALLOWED, "peel target must be commit or tree")

    def argv_tail(self) -> list[str]:
        return ["rev-parse", "--verify", "--quiet", "--end-of-options", f"{self.oid.value}^{{{self.target}}}"]

    def stdin_bytes(self) -> bytes | None:
        return None


@dataclass(frozen=True)
class LsTree:
    """Recursive, NUL-delimited long listing of one commit's tree.

    The classic `-z -l` output prints paths verbatim. (`--format` is not used: Git C-quotes
    `%(path)` even under `-z`, which would turn legitimate non-ASCII names into escapes.)
    """

    commit: ObjectId
    stdout_cap: int = 64 * 1024 * 1024
    op_name: str = field(default="ls-tree", init=False)
    discovery: bool = field(default=False, init=False)
    timeout_seconds: float = 120.0

    def __post_init__(self) -> None:
        _require(self.commit, ObjectId)

    def argv_tail(self) -> list[str]:
        return ["ls-tree", "-r", "-z", "-l", "--full-tree", "--end-of-options", self.commit.value]

    def stdin_bytes(self) -> bytes | None:
        return None


@dataclass(frozen=True)
class CatFileBatch:
    """Raw object bytes for a list of full object IDs. No --textconv, no --filters."""

    oids: tuple[ObjectId, ...]
    stdout_cap: int
    op_name: str = field(default="cat-file-batch", init=False)
    discovery: bool = field(default=False, init=False)
    timeout_seconds: float = 300.0

    def __post_init__(self) -> None:
        if not isinstance(self.oids, tuple) or not self.oids or not all(type(o) is ObjectId for o in self.oids):
            raise SourceError(Reason.OPERATION_NOT_ALLOWED, "cat-file batch needs validated object IDs")

    def argv_tail(self) -> list[str]:
        return ["cat-file", "--batch"]

    def stdin_bytes(self) -> bytes | None:
        return b"".join(o.value.encode("ascii") + b"\n" for o in self.oids)


ALLOWED_OP_TYPES: Final = (Version, DiscoverRoot, ShowObjectFormat, ShowRef, ObjectType, Peel, LsTree, CatFileBatch)


# --- Executable resolution ------------------------------------------------------------


@dataclass(frozen=True)
class GitBinary:
    path: str
    real_path: str
    version: tuple[int, int, int]

    @property
    def version_text(self) -> str:
        return ".".join(str(p) for p in self.version)


_VERSION_RE: Final = re.compile(rb"git version (\d{1,4})\.(\d{1,4})\.(\d{1,4})(?:[ .][\x21-\x7e ]{0,80})?\n?")


def parse_git_version(stdout: bytes) -> tuple[int, int, int]:
    m = _VERSION_RE.fullmatch(stdout)
    if not m:
        raise SourceError(Reason.MALFORMED_GIT_OUTPUT, "unrecognized `git version` output")
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def resolve_git_binary(candidates: Sequence[str] = ALLOWED_GIT_PATHS,
                       real_prefixes: Sequence[str] = ALLOWED_GIT_REAL_PREFIXES) -> GitBinary:
    """Find the reviewed Git executable and refuse anything older than MIN_GIT_VERSION."""
    for candidate in candidates:
        if not os.path.isabs(candidate) or not os.path.exists(candidate):
            continue
        real = os.path.realpath(candidate)
        if not any(real.startswith(prefix) for prefix in real_prefixes):
            raise SourceError(Reason.GIT_BINARY_UNAVAILABLE, f"{candidate} does not resolve into an allowed location")
        if not os.access(real, os.X_OK):
            raise SourceError(Reason.GIT_BINARY_UNAVAILABLE, f"{candidate} is not executable")
        result = run_bounded([real, *GLOBAL_OPTIONS, "version"], env=dict(BASE_ENV), cwd=EMPTY_DIR,
                             timeout_seconds=15.0, stdout_cap=4096)
        _require_ok(result)
        version = parse_git_version(result.stdout)
        if version < MIN_GIT_VERSION:
            raise SourceError(Reason.GIT_VERSION_UNSUPPORTED,
                              f"git {'.'.join(map(str, version))} is older than the reviewed "
                              f"{'.'.join(map(str, MIN_GIT_VERSION))}")
        return GitBinary(path=candidate, real_path=real, version=version)
    raise SourceError(Reason.GIT_BINARY_UNAVAILABLE, "no reviewed git executable found")


# --- Bounded execution ----------------------------------------------------------------


@dataclass(frozen=True)
class CommandResult:
    op_name: str
    argv: tuple[str, ...]
    returncode: int | None
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    timed_out: bool

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.stdout_truncated


class Executor(Protocol):
    def __call__(self, argv: Sequence[str], *, env: dict[str, str], cwd: str, timeout_seconds: float,
                 stdout_cap: int, stdin: bytes | None = None, op_name: str = "git") -> CommandResult: ...


def run_bounded(argv: Sequence[str], *, env: dict[str, str], cwd: str, timeout_seconds: float, stdout_cap: int,
                stdin: bytes | None = None, op_name: str = "git") -> CommandResult:
    """Run an argument array with a deadline and capped output. Never uses a shell.

    stdin, when given, is supplied from an unlinked temporary file so a large request can
    never deadlock against a large response. Reaching the stdout cap terminates the process.
    """
    if isinstance(argv, str) or not argv or not all(isinstance(a, str) for a in argv):
        raise SourceError(Reason.OPERATION_NOT_ALLOWED, "argv must be a non-empty sequence of strings")
    with contextlib.ExitStack() as stack:
        stdin_arg: int = subprocess.DEVNULL
        if stdin is not None:
            handle = stack.enter_context(tempfile.TemporaryFile())
            handle.write(stdin)
            handle.seek(0)
            stdin_arg = handle.fileno()
        proc = subprocess.Popen(  # noqa: S603 - argument array, shell=False, fixed binary
            list(argv), stdin=stdin_arg, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=cwd,
            shell=False, close_fds=True, start_new_session=True,
        )
        return _collect(proc, list(argv), timeout_seconds, stdout_cap, op_name)


def _collect(proc: subprocess.Popen[bytes], argv: list[str], timeout_seconds: float, stdout_cap: int,
             op_name: str) -> CommandResult:
    if proc.stdout is None or proc.stderr is None:  # pragma: no cover - PIPE always yields streams
        raise RuntimeError("subprocess pipes unavailable")
    buffers = {"out": bytearray(), "err": bytearray()}
    caps = {"out": stdout_cap, "err": DEFAULT_STDERR_CAP}
    truncated = {"out": False, "err": False}
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ, "out")
    selector.register(proc.stderr, selectors.EVENT_READ, "err")
    deadline = time.monotonic() + timeout_seconds
    timed_out = False
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            for key, _ in selector.select(timeout=min(remaining, 0.5)):
                chunk = os.read(key.fd, READ_CHUNK)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                stream = key.data
                room = caps[stream] - len(buffers[stream])
                if len(chunk) > room:
                    buffers[stream] += chunk[: max(room, 0)]
                    truncated[stream] = True
                else:
                    buffers[stream] += chunk
            if truncated["out"]:
                break
        if timed_out or truncated["out"]:
            _terminate(proc)
        try:
            returncode: int | None = proc.wait(timeout=max(deadline - time.monotonic(), 2.0))
        except subprocess.TimeoutExpired:
            timed_out = True
            _terminate(proc)
            returncode = proc.wait()
    finally:
        selector.close()
        proc.stdout.close()
        proc.stderr.close()
    return CommandResult(op_name=op_name, argv=tuple(argv), returncode=returncode, stdout=bytes(buffers["out"]),
                         stderr=bytes(buffers["err"]), stdout_truncated=truncated["out"], timed_out=timed_out)


def _terminate(proc: subprocess.Popen[bytes]) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(proc.pid, signal.SIGKILL)
    with contextlib.suppress(ProcessLookupError):
        proc.kill()


def _require_ok(result: CommandResult) -> None:
    if result.timed_out:
        raise SourceError(Reason.GIT_TIMEOUT, f"{result.op_name} exceeded its deadline")
    if result.stdout_truncated:
        raise SourceError(Reason.GIT_OUTPUT_LIMIT, f"{result.op_name} exceeded its output limit")
    if result.returncode != 0:
        raise SourceError(Reason.GIT_COMMAND_FAILED,
                          f"{result.op_name} exited {result.returncode}: {safe_text(result.stderr, 200)}")


# --- Runner ---------------------------------------------------------------------------


def build_argv(binary: GitBinary, op: GitOp) -> list[str]:
    """The only place a Git argv is assembled. Rejects anything outside the allowlist."""
    if not isinstance(op, ALLOWED_OP_TYPES):
        raise SourceError(Reason.OPERATION_NOT_ALLOWED, f"{type(op).__name__} is not an allowlisted Git operation")
    tail = op.argv_tail()
    if not tail or tail[0] not in ALLOWED_SUBCOMMANDS:
        raise SourceError(Reason.OPERATION_NOT_ALLOWED, "subcommand not allowlisted")
    for token in tail:
        if token in FORBIDDEN_TOKENS or token.split("=", 1)[0] in FORBIDDEN_TOKENS:
            raise SourceError(Reason.OPERATION_NOT_ALLOWED, f"forbidden token {safe_text(token)}")
    argv = [binary.real_path, *GLOBAL_OPTIONS]
    for key, value in COMMAND_CONFIG:
        argv += ["-c", f"{key}={value}"]
    return argv + tail


@dataclass
class GitRunner:
    """Runs allowlisted operations against one registered repository root."""

    binary: GitBinary
    root: Path
    executor: Executor = run_bounded
    history: list[tuple[str, ...]] = field(default_factory=list)

    @property
    def git_dir(self) -> Path:
        return self.root / ".git"

    def environment(self, op: GitOp) -> dict[str, str]:
        env = dict(BASE_ENV)
        # Discovery may not look above the root; object reads name the repository exactly.
        env["GIT_CEILING_DIRECTORIES"] = str(self.root.parent)
        if not op.discovery:
            env["GIT_DIR"] = str(self.git_dir)
        return env

    def run(self, op: GitOp) -> bytes:
        argv = build_argv(self.binary, op)
        cwd = str(self.root) if op.discovery else str(self.git_dir)
        self.history.append(tuple(argv))
        result = self.executor(argv, env=self.environment(op), cwd=cwd, timeout_seconds=op.timeout_seconds,
                               stdout_cap=op.stdout_cap, stdin=op.stdin_bytes(), op_name=op.op_name)
        _require_ok(result)
        return result.stdout
