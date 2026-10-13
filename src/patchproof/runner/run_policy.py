"""Fixed container policy for verification runs (PROJECT_SPEC.md 10.1-10.3; ADR-009; PP-008).

One revision execution uses exactly two containers:
- the **target** runs the approved ASGI application from a read-only source snapshot, with
  `--network=none`;
- the **verifier** runs the approved pack from a read-only pack snapshot, joined to the
  exact target's network namespace, and reaches it only at 127.0.0.1:8080.

**Reused unchanged from the accepted PP-003 policy:** every security setting and the
code-level resource ceilings. That covers the non-root fixed user, read-only root
filesystem, all capabilities dropped, no-new-privileges, the default seccomp profile,
private IPC and cgroup namespaces, bounded tmpfs, the log rotation policy, the PID, memory
and CPU limits, `--pull=never`, and the exact platform.

**The only additions**, each typed and validated, with no caller-supplied Docker
arguments, mounts, environment variables or commands:
- one read-only bind input per container, at a fixed destination (`/app/source` for the
  target, `/pack` for the verifier), whose source must be a private, canonical directory
  owned by the current user;
- fixed role commands built here from validated values;
- run labels: installation, run, pair, side, role and purpose.

**Wrapper admission (owner-approved, gate C, 2026-10-13).** `RunCreate` and `StartAttached`
are in `docker_cli.ALLOWED_OP_TYPES`. The wrapper accepts a `RunCreate` only when its argv
equals `run_create_argv_tail(spec)` and passes `assert_run_create_shape`, and a
`StartAttached` only in its single fixed shape. Every other operation still refuses `--mount`.

**Standalone verifier role (gate C).** The verifier image runs with `--network=none` and no
target, with the pack read-only at `/pack` and the fixed launcher in `collect` or `run` mode.
It is used for collection, and for the synthetic self-test, which makes no network requests.
Every other policy setting is identical to the verifier's.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Final

from .policy import (
    APPROVED_PROBE_PLATFORM,
    CGROUPNS_MODE,
    CONTAINER_USER,
    ENTRYPOINT,
    IPC_MODE,
    LABEL_INSTALLATION,
    LABEL_OWNER,
    LABEL_PREFIX,
    LABEL_PURPOSE,
    LABEL_ROLE,
    LABEL_RUN,
    LABEL_VALUE_RE,
    LOG_COMPRESS,
    LOG_DRIVER,
    LOG_MAX_FILE,
    LOG_MAX_SIZE,
    NO_NETWORK,
    OWNER_VALUE,
    RESTART_POLICY,
    SECURITY_OPTS,
    SHM_SIZE_BYTES,
    STOP_GRACE_SECONDS,
    TARGET_LOOPBACK_HOST,
    TARGET_LOOPBACK_PORT,
    TMPFS_MODE,
    TMPFS_OPTIONS,
    WORKDIR,
    ContainerId,
    ImageId,
    Network,
    Ownership,
    PolicyViolation,
    ResourceLimits,
    Role,
    check_limits,
)

RUN_PURPOSE: Final = "verification-run"
LABEL_PAIR: Final = "io.patchproof.pair"
LABEL_SIDE: Final = "io.patchproof.side"
SOURCE_MOUNT: Final = "/app/source"
PACK_MOUNT: Final = "/pack"
SIDES: Final = ("baseline", "candidate")
RUN_NAME_RE: Final = re.compile(
    r"^pp-run-[0-9a-f]{12}-p([1-9]|10)-(baseline|candidate)-(target|verifier|standalone)$")
ASGI_APP_RE: Final = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]{0,63}(\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,7}:[A-Za-z_][A-Za-z0-9_]{0,63}$")
# Characters allowed in a bind source. Commas and quotes would break Docker's --mount CSV syntax.
MOUNT_SOURCE_RE: Final = re.compile(r"^/[A-Za-z0-9 _./-]{1,1000}$")
TEST_PATH_RE: Final = re.compile(r"^/pack/tests/([A-Za-z0-9_][A-Za-z0-9_-]{0,63}/){0,4}test_[A-Za-z0-9_]{1,64}\.py$")

# Target health check, defined in the target image recipe (exec form, no shell) and verified
# by inspection. It runs in the target container; the host only reads Docker's health state.
HEALTH_SCRIPT: Final = (
    "import http.client,sys\n"
    "c=http.client.HTTPConnection('127.0.0.1',8080,timeout=1)\n"
    "try:\n"
    " c.request('GET','/health');sys.exit(0 if c.getresponse().status==200 else 1)\n"
    "except Exception:\n"
    " sys.exit(1)\n"
)
TARGET_HEALTHCHECK: Final = {
    "Test": ["CMD", "/usr/local/bin/python3", "-I", "-S", "-B", "-c", HEALTH_SCRIPT],
    "Interval": 1_000_000_000,
    "Timeout": 2_000_000_000,
    "StartPeriod": 30_000_000_000,
    "StartInterval": 1_000_000_000,
    "Retries": 3,
}


class RunRole(str, Enum):
    TARGET = "target"
    VERIFIER = "verifier"
    STANDALONE = "standalone"  # verifier image, no network, no target (collection and self-test)

    @property
    def probe_role(self) -> Role:
        """The PP-003 role whose limit class and cleanup registry entry this role uses."""
        return Role.TARGET if self is RunRole.TARGET else Role.VERIFIER

    @property
    def mount_point(self) -> str:
        return SOURCE_MOUNT if self is RunRole.TARGET else PACK_MOUNT


@dataclass(frozen=True)
class ReadOnlyInput:
    """A private, canonical, owner-only directory exposed read-only at a fixed destination."""

    source: Path
    destination: str

    def __post_init__(self) -> None:
        raw = str(self.source)
        if not MOUNT_SOURCE_RE.fullmatch(raw) or os.path.realpath(raw) != raw:
            raise PolicyViolation("read-only input must be an absolute canonical path without special characters")
        if self.destination not in (SOURCE_MOUNT, PACK_MOUNT):
            raise PolicyViolation("read-only inputs mount only at /app/source or /pack")
        st = os.lstat(raw)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o222:
            raise PolicyViolation("read-only input must be an owned directory with no write permission")

    @property
    def mount_arg(self) -> str:
        return f"type=bind,source={self.source},target={self.destination},readonly"


def target_command(asgi_app: str) -> tuple[str, ...]:
    if not ASGI_APP_RE.fullmatch(asgi_app):
        raise PolicyViolation("ASGI application must match the module:callable grammar")
    return ("-I", "-B", "-m", "uvicorn", asgi_app, "--app-dir", SOURCE_MOUNT,
            "--host", TARGET_LOOPBACK_HOST, "--port", str(TARGET_LOOPBACK_PORT), "--workers", "1",
            "--loop", "asyncio", "--http", "h11", "--ws", "none", "--interface", "asgi3", "--lifespan", "on",
            "--no-access-log", "--no-proxy-headers", "--no-server-header", "--timeout-graceful-shutdown", "3")


def _seconds(value: float) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= 30:
        raise PolicyViolation("request timeouts must be within (0, 30] seconds")
    return f"{value:g}"


def verifier_command(*, run_id: str, pair: int, side: str, test_paths: tuple[str, ...], connect_timeout: float,
                     read_timeout: float) -> tuple[str, ...]:
    if not re.fullmatch(r"run-[0-9a-f]{32}", run_id) or not 1 <= pair <= 10 or side not in SIDES:
        raise PolicyViolation("invalid run identity")
    if not test_paths or len(set(test_paths)) != len(test_paths) or not all(
            TEST_PATH_RE.fullmatch(p) for p in test_paths):
        raise PolicyViolation("test paths must be distinct pack test modules under /pack/tests")
    return ("-I", "-B", "-m", "patchproof_verifier.launch", "run", "--pack", PACK_MOUNT, "--run", run_id,
            "--pair", str(pair), "--side", side, "--connect-timeout", _seconds(connect_timeout),
            "--read-timeout", _seconds(read_timeout), "--", *test_paths)


def collect_command(test_paths: tuple[str, ...]) -> tuple[str, ...]:
    """Fixed collection invocation (equal to `packs.collection.collection_plan` after the interpreter)."""
    if not test_paths or len(set(test_paths)) != len(test_paths) or not all(
            TEST_PATH_RE.fullmatch(p) for p in test_paths):
        raise PolicyViolation("test paths must be distinct pack test modules under /pack/tests")
    return ("-I", "-B", "-m", "patchproof_verifier.launch", "collect", "--pack", PACK_MOUNT, "--", *test_paths)


def _is_fixed_run_command(command: tuple[str, ...]) -> bool:
    """True only if `command` is exactly what `verifier_command` builds from its own fields."""
    if len(command) < 19 or command[17] != "--":
        return False
    try:
        rebuilt = verifier_command(run_id=command[8], pair=int(command[10]), side=command[12],
                                   test_paths=command[18:], connect_timeout=float(command[14]),
                                   read_timeout=float(command[16]))
    except (ValueError, PolicyViolation):
        return False
    return rebuilt == command


def run_container_name(ownership: Ownership, pair: int, side: str, role: RunRole) -> str:
    return f"pp-run-{ownership.short}-p{pair}-{side}-{role.value}"


def run_labels(ownership: Ownership, pair: int, side: str, role: RunRole) -> tuple[tuple[str, str], ...]:
    return tuple(sorted({
        LABEL_OWNER: OWNER_VALUE, LABEL_INSTALLATION: ownership.installation_id, LABEL_RUN: ownership.run_id,
        LABEL_ROLE: role.value, LABEL_PURPOSE: RUN_PURPOSE, LABEL_PAIR: str(pair), LABEL_SIDE: side,
    }.items()))


@dataclass(frozen=True)
class RunContainerSpec:
    """A fully validated request for one verification-run container."""

    name: str
    role: RunRole
    pair: int
    side: str
    image: ImageId
    network: Network
    limits: ResourceLimits
    labels: tuple[tuple[str, str], ...]
    input: ReadOnlyInput
    command: tuple[str, ...]

    def __post_init__(self) -> None:
        suffix = f"-p{self.pair}-{self.side}-{self.role.value}"
        if not RUN_NAME_RE.fullmatch(self.name) or not self.name.endswith(suffix):
            raise PolicyViolation("container name is outside the verification-run naming scheme")
        check_limits(self.limits, self.role.probe_role.limit_class)
        if self.role in (RunRole.TARGET, RunRole.STANDALONE) and self.network.join_target is not None:
            raise PolicyViolation("the target and the standalone verifier have no network (--network=none)")
        if self.role is RunRole.VERIFIER and self.network.join_target is None:
            raise PolicyViolation("the verifier must join the exact target's network namespace")
        if self.input.destination != self.role.mount_point:
            raise PolicyViolation("the target receives only the source snapshot; the verifier only the pack")
        keys = [k for k, _ in self.labels]
        if len(keys) != len(set(keys)) or any(not k.startswith(LABEL_PREFIX) or not LABEL_VALUE_RE.fullmatch(v)
                                              for k, v in self.labels):
            raise PolicyViolation("labels must be unique io.patchproof.* keys with bounded values")
        label_map = dict(self.labels)
        if label_map.get(LABEL_ROLE) != self.role.value or label_map.get(LABEL_PURPOSE) != RUN_PURPOSE or (
                label_map.get(LABEL_PAIR), label_map.get(LABEL_SIDE)) != (str(self.pair), self.side):
            raise PolicyViolation("labels do not match the container's role, pair and side")
        for required in (LABEL_OWNER, LABEL_INSTALLATION, LABEL_RUN):
            if required not in label_map:
                raise PolicyViolation(f"run containers must carry {required}")
        launcher = ("-I", "-B", "-m", "patchproof_verifier.launch", "run")
        if self.role is RunRole.TARGET and self.command[:4] != ("-I", "-B", "-m", "uvicorn"):
            raise PolicyViolation("the target command is the fixed uvicorn invocation")
        if self.role is RunRole.TARGET and self.command != target_command(self.command[4]):
            raise PolicyViolation("the target command differs from the fixed invocation")
        if self.role is RunRole.VERIFIER and self.command[:5] != launcher:
            raise PolicyViolation("the verifier command is the fixed launcher invocation")
        if self.role is RunRole.STANDALONE and self.command[:4] != launcher[:4]:
            raise PolicyViolation("the standalone verifier runs only the fixed launcher")
        if self.role is RunRole.STANDALONE and self.command[4] == "collect" and self.command != collect_command(
                self.command[8:]):
            raise PolicyViolation("the standalone collection command differs from the fixed invocation")
        if self.role is RunRole.STANDALONE and self.command[4] not in ("collect", "run"):
            raise PolicyViolation("the standalone verifier runs collect or run only")
        if self.role is RunRole.STANDALONE and self.command[4] == "run" and not _is_fixed_run_command(self.command):
            raise PolicyViolation("the standalone run command differs from the fixed invocation")

    @property
    def label_map(self) -> dict[str, str]:
        return dict(self.labels)

    def tmpfs(self) -> dict[str, str]:
        return {
            WORKDIR: f"{TMPFS_OPTIONS},size={self.limits.scratch_bytes},mode={TMPFS_MODE}",
            "/tmp": f"{TMPFS_OPTIONS},size={self.limits.tmp_bytes},mode={TMPFS_MODE}",
        }


def build_run_spec(*, ownership: Ownership, pair: int, side: str, role: RunRole, image: ImageId,
                   limits: ResourceLimits, input_dir: Path, command: tuple[str, ...],
                   join_target: ContainerId | None = None) -> RunContainerSpec:
    return RunContainerSpec(
        name=run_container_name(ownership, pair, side, role), role=role, pair=pair, side=side, image=image,
        network=Network(join_target) if join_target is not None else NO_NETWORK, limits=limits,
        labels=run_labels(ownership, pair, side, role), input=ReadOnlyInput(input_dir, role.mount_point),
        command=command)


def run_create_argv_tail(spec: RunContainerSpec) -> list[str]:
    """The fixed `docker create` argument array for a run container. The only place it is built."""
    argv = ["container", "create", "--name", spec.name]
    for key, value in spec.labels:
        argv += ["--label", f"{key}={value}"]
    argv += ["--platform", APPROVED_PROBE_PLATFORM, "--pull=never", "--user", CONTAINER_USER,
             "--entrypoint", ENTRYPOINT, "--read-only", "--cap-drop", "ALL"]
    for opt in SECURITY_OPTS:
        argv += ["--security-opt", opt]
    argv += ["--network", spec.network.mode, "--ipc", IPC_MODE, "--shm-size", str(SHM_SIZE_BYTES),
             "--cgroupns", CGROUPNS_MODE, "--restart", RESTART_POLICY, "--cpus", spec.limits.cpus_arg,
             "--memory", str(spec.limits.memory_bytes), "--memory-swap", str(spec.limits.memory_bytes),
             "--pids-limit", str(spec.limits.pids)]
    for mount_point, options in spec.tmpfs().items():
        argv += ["--tmpfs", f"{mount_point}:{options}"]
    argv += ["--mount", spec.input.mount_arg,
             "--workdir", WORKDIR, "--log-driver", LOG_DRIVER, "--log-opt", f"max-size={LOG_MAX_SIZE}",
             "--log-opt", f"max-file={LOG_MAX_FILE}", "--log-opt", f"compress={LOG_COMPRESS}",
             "--stop-timeout", str(STOP_GRACE_SECONDS), spec.image.value, *spec.command]
    return argv


# Tokens that may never appear among a run container's Docker options. `--mount` is permitted
# exactly once, with the fixed read-only shape checked in `assert_run_create_shape`.
RUN_FORBIDDEN: Final = frozenset({
    "prune", "--filter", "-f", "--force", "--volumes", "-v", "--volume", "--privileged", "--cap-add", "--device",
    "--publish", "-p", "--publish-all", "-P", "--pid", "--userns", "--uts", "--env", "-e", "--env-file",
    "--add-host", "--sysctl", "--group-add", "--volumes-from", "--link", "--dns", "--health-cmd",
    "--no-healthcheck", "--init", "--tty", "-t", "--interactive", "-i", "--detach-keys",
})


def _docker_options(argv_tail: list[str]) -> list[str]:
    for index, token in enumerate(argv_tail):
        if token.startswith("sha256:"):
            return list(argv_tail[:index])
    return list(argv_tail)


def assert_run_create_shape(argv_tail: list[str]) -> None:
    """Defense in depth over the create argv: no forbidden token, exactly one read-only bind."""
    options = _docker_options(argv_tail)
    bad = sorted(t for t in options if t in RUN_FORBIDDEN or "unconfined" in t or t.startswith("--privileged"))
    if bad:
        raise PolicyViolation(f"forbidden Docker token(s) in run argv: {bad}")
    mounts = [options[i + 1] for i, t in enumerate(options) if t == "--mount"]
    if len(mounts) != 1 or not mounts[0].startswith("type=bind,source=/") or not mounts[0].endswith(",readonly"):
        raise PolicyViolation("a run container has exactly one read-only bind input")
    if not re.fullmatch(r"type=bind,source=/[^,\"']+,target=(/app/source|/pack),readonly", mounts[0]):
        raise PolicyViolation("the bind input has an unexpected shape")
    if any(t.startswith(("--mount=", "--volume=", "--network=", "--env=")) for t in options):
        raise PolicyViolation("option=value spellings are not used by the fixed argv")


@dataclass(frozen=True)
class RunCreate:
    """`docker container create` for one verification-run container (not in DockerCli's allowlist)."""

    spec: RunContainerSpec
    op_name: str = field(default="run-create", init=False)
    timeout_seconds: float = 30.0
    stdout_cap: int = 4096
    mutates: bool = field(default=True, init=False)

    def argv_tail(self) -> list[str]:
        argv = run_create_argv_tail(self.spec)
        assert_run_create_shape(argv)
        return argv


@dataclass(frozen=True)
class StartAttached:
    """Start the verifier and stream its standard output (the event channel), bounded by size and time."""

    container: ContainerId
    timeout_seconds: float
    stdout_cap: int
    # The verifier's console (pytest's own terminal output) arrives on stderr: untrusted
    # diagnostics, bounded separately and never part of the event channel.
    stderr_cap: int = 1024 * 1024
    op_name: str = field(default="start-attached", init=False)
    mutates: bool = field(default=True, init=False)

    def argv_tail(self) -> list[str]:
        return ["container", "start", "--attach", "--", self.container.value]
