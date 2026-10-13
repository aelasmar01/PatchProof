"""Narrow typed wrapper around the Docker CLI (PROJECT_SPEC.md 3.1, 10.3).

Callers build typed operation objects; this module alone turns them into argument
arrays. There is no function that accepts a caller-supplied Docker argument list, no
`shell=True`, and no bulk or filter-driven removal operation. Every invocation has a
deadline and bounded stdout/stderr capture.

Importing or unit-testing this module does not contact Docker. Only `DockerCli.run`
starts a subprocess.
"""

from __future__ import annotations

import contextlib
import os
import selectors
import shutil
import signal
import subprocess
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Protocol

from .policy import (
    APPROVED_PROBE_PLATFORM,
    CONTAINER_NAME_RE,
    CGROUPNS_MODE,
    CONTAINER_USER,
    DOCKER_CONTEXT,
    ENTRYPOINT,
    IPC_MODE,
    LOG_COMPRESS,
    LOG_DRIVER,
    LOG_MAX_FILE,
    LOG_MAX_SIZE,
    RESTART_POLICY,
    SECURITY_OPTS,
    SHM_SIZE_BYTES,
    STOP_GRACE_SECONDS,
    WORKDIR,
    ContainerId,
    ContainerSpec,
    ImageId,
    PolicyViolation,
)
from .run_policy import RunCreate, StartAttached, assert_run_create_shape, run_create_argv_tail

DEFAULT_STDOUT_CAP: Final = 1024 * 1024
DEFAULT_STDERR_CAP: Final = 64 * 1024
# The target's own log streams (`docker container logs` relays the container's stdout and
# stderr separately). Each is capped on its own; both are untrusted and never parsed.
TARGET_LOG_STREAM_CAP: Final = 5 * 1024 * 1024
READ_CHUNK: Final = 65536

# Absolute locations the docker client may be resolved from. Anything else is refused.
ALLOWED_DOCKER_DIRS: Final = (
    "/usr/local/bin",
    "/Applications/Docker.app/Contents/Resources/bin",
    "/opt/homebrew/bin",
)
SANITIZED_PATH: Final = "/usr/bin:/bin:/usr/sbin:/sbin"


# --- Typed operations ------------------------------------------------------------------


class DockerOp(Protocol):
    """A typed, allowlisted Docker CLI operation."""

    @property
    def op_name(self) -> str: ...

    def argv_tail(self) -> list[str]: ...

    @property
    def timeout_seconds(self) -> float: ...

    @property
    def stdout_cap(self) -> int: ...

    @property
    def mutates(self) -> bool: ...


@dataclass(frozen=True)
class ContainerRef:
    """An exact container reference: a full ID, or a PatchProof-scheme name."""

    value: str

    def __post_init__(self) -> None:
        try:
            ContainerId(self.value)
        except PolicyViolation as exc:
            if not CONTAINER_NAME_RE.fullmatch(self.value):
                raise PolicyViolation("container reference must be a full ID or a PatchProof name") from exc


@dataclass(frozen=True)
class ContextInspect:
    op_name: str = field(default="context-inspect", init=False)
    timeout_seconds: float = 15.0
    stdout_cap: int = 64 * 1024
    mutates: bool = field(default=False, init=False)

    def argv_tail(self) -> list[str]:
        return ["context", "inspect", "--", DOCKER_CONTEXT]


@dataclass(frozen=True)
class Version:
    op_name: str = field(default="version", init=False)
    timeout_seconds: float = 15.0
    stdout_cap: int = 64 * 1024
    mutates: bool = field(default=False, init=False)

    def argv_tail(self) -> list[str]:
        return ["version", "--format", "{{json .}}"]


@dataclass(frozen=True)
class ImageInspect:
    image: ImageId
    op_name: str = field(default="image-inspect", init=False)
    timeout_seconds: float = 15.0
    stdout_cap: int = 256 * 1024
    mutates: bool = field(default=False, init=False)

    def argv_tail(self) -> list[str]:
        return ["image", "inspect", "--", self.image.value]


@dataclass(frozen=True)
class Create:
    spec: ContainerSpec
    op_name: str = field(default="create", init=False)
    timeout_seconds: float = 30.0
    stdout_cap: int = 4096
    mutates: bool = field(default=True, init=False)

    def argv_tail(self) -> list[str]:
        return create_argv_tail(self.spec)


@dataclass(frozen=True)
class Inspect:
    ref: ContainerRef
    op_name: str = field(default="inspect", init=False)
    timeout_seconds: float = 15.0
    stdout_cap: int = 512 * 1024
    mutates: bool = field(default=False, init=False)

    def argv_tail(self) -> list[str]:
        return ["container", "inspect", "--", self.ref.value]


@dataclass(frozen=True)
class Start:
    container: ContainerId
    op_name: str = field(default="start", init=False)
    timeout_seconds: float = 30.0
    stdout_cap: int = 4096
    mutates: bool = field(default=True, init=False)

    def argv_tail(self) -> list[str]:
        return ["container", "start", "--", self.container.value]


@dataclass(frozen=True)
class Wait:
    container: ContainerId
    timeout_seconds: float
    op_name: str = field(default="wait", init=False)
    stdout_cap: int = 4096
    mutates: bool = field(default=False, init=False)

    def argv_tail(self) -> list[str]:
        return ["container", "wait", "--", self.container.value]


@dataclass(frozen=True)
class Logs:
    """The target's log streams. Its stdout and stderr arrive on the client's stdout and stderr."""

    container: ContainerId
    stdout_cap: int = DEFAULT_STDOUT_CAP
    stderr_cap: int = DEFAULT_STDERR_CAP
    op_name: str = field(default="logs", init=False)
    timeout_seconds: float = 30.0
    mutates: bool = field(default=False, init=False)

    def argv_tail(self) -> list[str]:
        return ["container", "logs", "--", self.container.value]


@dataclass(frozen=True)
class Stop:
    container: ContainerId
    op_name: str = field(default="stop", init=False)
    timeout_seconds: float = float(STOP_GRACE_SECONDS + 20)
    stdout_cap: int = 4096
    mutates: bool = field(default=True, init=False)

    def argv_tail(self) -> list[str]:
        return ["container", "stop", "--time", str(STOP_GRACE_SECONDS), "--", self.container.value]


@dataclass(frozen=True)
class Remove:
    """Remove one stopped container by exact ID. No --force, no --volumes, no filters."""

    container: ContainerId
    op_name: str = field(default="remove", init=False)
    timeout_seconds: float = 30.0
    stdout_cap: int = 4096
    mutates: bool = field(default=True, init=False)

    def argv_tail(self) -> list[str]:
        return ["container", "rm", "--", self.container.value]


@dataclass(frozen=True)
class ForceRemove:
    """Last-resort removal of one owned container that a graceful stop did not stop.

    Only `cleanup._stop_and_remove` uses it, and only after a fresh inspect has
    re-confirmed this run's ownership labels and shown the container still running.
    The argv shape is fixed and checked exactly; no other operation may carry --force.
    """

    container: ContainerId
    op_name: str = field(default="force-remove", init=False)
    timeout_seconds: float = 30.0
    stdout_cap: int = 4096
    mutates: bool = field(default=True, init=False)

    def argv_tail(self) -> list[str]:
        return ["container", "rm", "--force", "--", self.container.value]


@dataclass(frozen=True)
class SnapshotList:
    """Read-only resource listing used for the preservation check (5.4)."""

    kind: str
    op_name: str = field(default="snapshot", init=False)
    timeout_seconds: float = 30.0
    stdout_cap: int = 2 * 1024 * 1024
    mutates: bool = field(default=False, init=False)

    _ARGV: tuple[tuple[str, tuple[str, ...]], ...] = field(
        default=(
            ("images", ("image", "ls", "--all", "--digests", "--no-trunc", "--format", "{{json .}}")),
            ("containers", ("container", "ls", "--all", "--no-trunc", "--format", "{{json .}}")),
            ("volumes", ("volume", "ls", "--format", "{{json .}}")),
            ("networks", ("network", "ls", "--no-trunc", "--format", "{{json .}}")),
            ("system-df", ("system", "df", "--format", "{{json .}}")),
        ),
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        if self.kind not in dict(self._ARGV):
            raise PolicyViolation("unknown snapshot listing")

    def argv_tail(self) -> list[str]:
        return list(dict(self._ARGV)[self.kind])


SNAPSHOT_KINDS: Final = ("images", "containers", "volumes", "networks", "system-df")

ALLOWED_OP_TYPES: Final = (
    ContextInspect, Version, ImageInspect, Create, Inspect, Start, Wait, Logs, Stop, Remove,
    ForceRemove, SnapshotList,
    # PP-008 gate C (owner-approved 2026-10-13): verification-run operations, each checked
    # against its single fixed shape in assert_no_forbidden_tokens.
    RunCreate, StartAttached,
)

# Docker subcommands that must never appear in any argv this module builds.
FORBIDDEN_TOKENS: Final = frozenset(
    {
        "prune", "--filter", "-f", "--force", "--volumes", "-v", "--privileged", "--cap-add",
        "--device", "--mount", "--volume", "--publish", "-p", "--publish-all", "-P",
        "--pid", "--userns", "--uts", "--env", "-e", "--env-file", "--add-host", "--sysctl",
        "--security-opt=seccomp=unconfined", "pull", "build", "exec", "run", "push", "load",
        "import", "commit", "cp", "kill",
    }
)


def create_argv_tail(spec: ContainerSpec) -> list[str]:
    """The fixed `docker create` argument array. The only place it is constructed."""
    argv = ["container", "create", "--name", spec.name]
    for key, value in spec.labels:
        argv += ["--label", f"{key}={value}"]
    argv += [
        "--platform", APPROVED_PROBE_PLATFORM,
        "--pull=never",
        "--user", CONTAINER_USER,
        "--entrypoint", ENTRYPOINT,
        "--read-only",
        "--cap-drop", "ALL",
    ]
    for opt in SECURITY_OPTS:
        argv += ["--security-opt", opt]
    argv += [
        "--network", spec.network.mode,
        "--ipc", IPC_MODE,
        "--shm-size", str(SHM_SIZE_BYTES),
        "--cgroupns", CGROUPNS_MODE,
        "--restart", RESTART_POLICY,
        "--cpus", spec.limits.cpus_arg,
        "--memory", str(spec.limits.memory_bytes),
        "--memory-swap", str(spec.limits.memory_bytes),
        "--pids-limit", str(spec.limits.pids),
    ]
    for mount_point, options in spec.tmpfs().items():
        argv += ["--tmpfs", f"{mount_point}:{options}"]
    argv += [
        "--workdir", WORKDIR,
        "--log-driver", LOG_DRIVER,
        "--log-opt", f"max-size={LOG_MAX_SIZE}",
        "--log-opt", f"max-file={LOG_MAX_FILE}",
        "--log-opt", f"compress={LOG_COMPRESS}",
        "--stop-timeout", str(STOP_GRACE_SECONDS),
        spec.image.value,
        *spec.command,
    ]
    return argv


def docker_options_of(argv_tail: Sequence[str]) -> list[str]:
    """The Docker-parsed portion of a create argv (everything before the image ID)."""
    for index, token in enumerate(argv_tail):
        if token.startswith("sha256:"):
            return list(argv_tail[:index])
    return list(argv_tail)


# --- Bounded subprocess execution ------------------------------------------------------


@dataclass(frozen=True)
class CommandResult:
    op_name: str
    argv: tuple[str, ...]
    returncode: int | None
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    timed_out: bool
    duration_seconds: float

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


class Executor(Protocol):
    def run(self, op: DockerOp) -> CommandResult: ...


def run_bounded(
    argv: Sequence[str],
    *,
    env: dict[str, str],
    timeout_seconds: float,
    stdout_cap: int,
    stderr_cap: int = DEFAULT_STDERR_CAP,
    op_name: str = "command",
) -> CommandResult:
    """Run an argument array with a deadline and capped output. Never uses a shell.

    When stdout reaches its cap the process is terminated: the caller asked for at most
    that many bytes and must see `stdout_truncated=True`, not a silently cut stream.
    """
    if isinstance(argv, str) or not argv or not all(isinstance(a, str) for a in argv):
        raise PolicyViolation("argv must be a non-empty sequence of strings")
    started = time.monotonic()
    proc = subprocess.Popen(  # noqa: S603 - argument array, shell=False, fixed binary
        list(argv),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        shell=False,
        close_fds=True,
        start_new_session=True,
    )
    if proc.stdout is None or proc.stderr is None:  # pragma: no cover - PIPE always yields streams
        raise RuntimeError("subprocess pipes unavailable")
    buffers: dict[str, bytearray] = {"out": bytearray(), "err": bytearray()}
    caps = {"out": stdout_cap, "err": stderr_cap}
    truncated = {"out": False, "err": False}
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ, "out")
    selector.register(proc.stderr, selectors.EVENT_READ, "err")
    timed_out = False
    deadline = started + timeout_seconds
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            for key, _ in selector.select(timeout=min(remaining, 0.5)):
                stream = key.data
                chunk = os.read(key.fd, READ_CHUNK)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
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
            returncode = proc.wait(timeout=5)
    except BaseException:
        # An interrupt (Ctrl-C, or a handled SIGTERM) must not leave the client running in
        # its own session: stop it before the exception continues to the cleanup code.
        _terminate(proc)
        raise
    finally:
        selector.close()
        proc.stdout.close()
        proc.stderr.close()
    if timed_out:
        returncode = None
    return CommandResult(
        op_name=op_name,
        argv=tuple(argv),
        returncode=returncode,
        stdout=bytes(buffers["out"]),
        stderr=bytes(buffers["err"]),
        stdout_truncated=truncated["out"],
        stderr_truncated=truncated["err"],
        timed_out=timed_out,
        duration_seconds=round(time.monotonic() - started, 3),
    )


def _terminate(proc: subprocess.Popen[bytes]) -> None:
    """Stop the CLI client process (not the container) and its process group."""
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(timeout=2)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)


def resolve_docker_binary() -> str:
    """Resolve the docker client to an absolute path in an allowlisted directory."""
    found = shutil.which("docker", path=os.pathsep.join(ALLOWED_DOCKER_DIRS))
    if found is None:
        raise PolicyViolation("docker client not found in an allowlisted directory")
    resolved = str(Path(found).resolve())
    if not any(resolved.startswith(d + "/") for d in ALLOWED_DOCKER_DIRS):
        raise PolicyViolation(f"docker client resolves outside the allowlist: {resolved}")
    return resolved


def sanitized_env(home: str) -> dict[str, str]:
    """A minimal environment: no DOCKER_HOST, DOCKER_CONTEXT, proxies, or credentials."""
    return {"HOME": home, "PATH": SANITIZED_PATH, "LC_ALL": "C", "LANG": "C"}


@dataclass
class DockerCli:
    """The only Executor that starts real processes. Refuses any non-allowlisted op."""

    docker_binary: str
    home: str
    command_log: list[CommandResult] = field(default_factory=list)

    def run(self, op: DockerOp) -> CommandResult:
        if not isinstance(op, ALLOWED_OP_TYPES):
            raise PolicyViolation(f"operation {type(op).__name__} is not allowlisted")
        argv = [self.docker_binary, "--context", DOCKER_CONTEXT, *op.argv_tail()]
        assert_no_forbidden_tokens(op)
        result = run_bounded(
            argv,
            env=sanitized_env(self.home),
            timeout_seconds=op.timeout_seconds,
            stdout_cap=op.stdout_cap,
            stderr_cap=stderr_cap_of(op),
            op_name=op.op_name,
        )
        self.command_log.append(result)
        return result


def stderr_cap_of(op: DockerOp) -> int:
    """The stderr bound of an operation: its own `stderr_cap` if it declares one, else the default."""
    cap = getattr(op, "stderr_cap", DEFAULT_STDERR_CAP)
    if isinstance(cap, bool) or not isinstance(cap, int) or not 1 <= cap <= 64 * 1024 * 1024:
        raise PolicyViolation("an operation's stderr cap must be a positive bounded integer")
    return cap


def assert_no_forbidden_tokens(op: DockerOp) -> None:
    """Defense in depth: the Docker-parsed portion of any argv has no forbidden token."""
    tail = op.argv_tail()
    if isinstance(op, RunCreate):
        # The only operation that may carry --mount: exactly one read-only bind, built only by
        # run_policy.run_create_argv_tail from a validated RunContainerSpec.
        if type(op) is not RunCreate or tail != run_create_argv_tail(op.spec):
            raise PolicyViolation("run-create argv deviates from its fixed shape")
        assert_run_create_shape(tail)
        return
    if isinstance(op, StartAttached):
        if (type(op) is not StartAttached or tail != ["container", "start", "--attach", "--", op.container.value]
                or not 1 <= op.timeout_seconds <= 900 or not 1 <= op.stdout_cap <= 52428801
                or not 1 <= op.stderr_cap <= 4 * 1024 * 1024):
            raise PolicyViolation("start-attached argv or bounds deviate from the fixed shape")
        return
    if isinstance(op, ForceRemove):
        if type(op) is not ForceRemove or tail != ["container", "rm", "--force", "--", op.container.value]:
            raise PolicyViolation("force-remove argv deviates from its fixed shape")
        return
    options = docker_options_of(tail) if isinstance(op, Create) else tail[:-1]
    bad = sorted(t for t in options if t in FORBIDDEN_TOKENS or "unconfined" in t)
    if bad:
        raise PolicyViolation(f"forbidden Docker token(s) in argv: {bad}")
