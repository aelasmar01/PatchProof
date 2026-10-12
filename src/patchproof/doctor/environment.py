"""Observed environment facts for `patchproof doctor`, gathered read-only.

Every subprocess is one of a closed set of typed read-only operations, run as an
argument array from an allowlisted absolute path, with a deadline, capped output, and
the runner's sanitized environment (no DOCKER_HOST, proxies, or credentials). Docker is
reached only through the `desktop-linux` context, exactly as the probe runner does.

Nothing here creates, starts, or removes a container, pulls an image, writes a file, or
changes a setting. The accepted PP-003 `DockerCli` and its allowlist are untouched:
doctor has its own narrower executor that refuses every mutating operation.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Final, Protocol

from platformdirs import user_data_path

from ..probes import evidence as ev
from ..runner.docker_cli import (
    CommandResult,
    ContextInspect,
    ImageInspect,
    Version,
    assert_no_forbidden_tokens,
    resolve_docker_binary,
    run_bounded,
    sanitized_env,
)
from ..runner.policy import APPROVED_PROBE_IMAGE_ID, DOCKER_CONTEXT, ImageId, PolicyViolation

APP_NAME: Final = "PatchProof"
TEXT_LIMIT: Final = 200  # longest string copied from tool output into the report

# Absolute directories host tools may be resolved from. Anything else is refused.
TOOL_DIRS: Final = ("/usr/local/bin", "/opt/homebrew/bin", "/usr/bin")
SYSCTL: Final = "/usr/sbin/sysctl"


def evidence_root() -> Path:
    """The fixed A3 probe evidence directory. Computed, never created, never overridable."""
    return user_data_path(APP_NAME, appauthor=False, ensure_exists=False) / "probe-runs"


# --- Typed read-only operations ---------------------------------------------------------


class Tool(Enum):
    GIT = "git"
    UV = "uv"


@dataclass(frozen=True)
class DockerInfo:
    """`docker info` as JSON. Read-only; not part of the probe runner's allowlist."""

    op_name: str = field(default="info", init=False)
    timeout_seconds: float = 15.0
    stdout_cap: int = 256 * 1024
    mutates: bool = field(default=False, init=False)

    def argv_tail(self) -> list[str]:
        return ["info", "--format", "{{json .}}"]


DoctorDockerOp = ContextInspect | Version | DockerInfo | ImageInspect
READ_ONLY_DOCKER_OPS: Final = (ContextInspect, Version, DockerInfo, ImageInspect)


class HostQueries(Protocol):
    """Everything doctor may run. Tests substitute synthetic results."""

    def docker_binary(self) -> str: ...

    def docker(self, op: DoctorDockerOp) -> CommandResult: ...

    def tool_path(self, tool: Tool) -> str | None: ...

    def tool_version(self, tool: Tool, path: str) -> CommandResult: ...

    def memory_bytes(self) -> CommandResult: ...


@dataclass
class ReadOnlyHost:
    """The only HostQueries implementation that starts processes."""

    home: str
    _docker: str | None = None

    def docker_binary(self) -> str:
        if self._docker is None:
            self._docker = resolve_docker_binary()
        return self._docker

    def docker(self, op: DoctorDockerOp) -> CommandResult:
        if not isinstance(op, READ_ONLY_DOCKER_OPS) or op.mutates:
            raise PolicyViolation(f"doctor refuses Docker operation {type(op).__name__}")
        assert_no_forbidden_tokens(op)
        argv = [self.docker_binary(), "--context", DOCKER_CONTEXT, *op.argv_tail()]
        return run_bounded(argv, env=sanitized_env(self.home), timeout_seconds=op.timeout_seconds,
                           stdout_cap=op.stdout_cap, op_name=op.op_name)

    def tool_path(self, tool: Tool) -> str | None:
        return shutil.which(tool.value, path=os.pathsep.join(TOOL_DIRS))

    def tool_version(self, tool: Tool, path: str) -> CommandResult:
        if Path(path).parent.as_posix() not in TOOL_DIRS or Path(path).name != tool.value:
            raise PolicyViolation(f"{tool.value} path is outside the allowlist: {path}")
        return run_bounded([path, "--version"], env=sanitized_env(self.home), timeout_seconds=10.0,
                           stdout_cap=4096, op_name=f"{tool.value}-version")

    def memory_bytes(self) -> CommandResult:
        return run_bounded([SYSCTL, "-n", "hw.memsize"], env=sanitized_env(self.home), timeout_seconds=5.0,
                           stdout_cap=256, op_name="sysctl-memsize")


# --- Observed facts ---------------------------------------------------------------------


@dataclass(frozen=True)
class HostFacts:
    system: str
    macos_version: str | None
    machine: str
    cpu_count: int | None
    memory_bytes: int | None
    home_disk_free_bytes: int | None
    home_git_repository: bool


@dataclass(frozen=True)
class PythonFacts:
    version: str
    implementation: str
    executable: str
    base_prefix: str


@dataclass(frozen=True)
class ToolFacts:
    name: str
    path: str | None
    resolved_path: str | None
    version_output: str | None
    error: str | None = None


@dataclass(frozen=True)
class DockerFacts:
    binary: str | None = None
    context_endpoint: str | None = None
    expected_endpoint: str | None = None
    client_version: str | None = None
    server_version: str | None = None
    platform_name: str | None = None
    os_type: str | None = None
    architecture: str | None = None
    cgroup_version: str | None = None
    security_options: tuple[str, ...] = ()
    default_runtime: str | None = None
    network_drivers: tuple[str, ...] = ()
    ncpu: int | None = None
    mem_total: int | None = None
    warnings: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()


@dataclass(frozen=True)
class ImageFacts:
    approved_id: str | None
    present: bool | None
    observed_id: str | None = None
    os: str | None = None
    architecture: str | None = None
    repo_digests: tuple[str, ...] = ()
    error: str | None = None


@dataclass(frozen=True)
class EvidenceRootFacts:
    path: str
    ready: bool
    detail: str


@dataclass(frozen=True)
class EnvironmentFacts:
    host: HostFacts
    python: PythonFacts
    git: ToolFacts
    uv: ToolFacts
    docker: DockerFacts
    image: ImageFacts
    evidence_root: EvidenceRootFacts


# --- Collection -------------------------------------------------------------------------


def _text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace").strip()[:TEXT_LIMIT]


def _failure(res: CommandResult) -> str:
    if res.timed_out:
        return f"{res.op_name}: timed out"
    if res.stdout_truncated:
        return f"{res.op_name}: output exceeded its cap"
    return f"{res.op_name}: exit {res.returncode}: {_text(res.stderr) or 'no message'}"


def _json(res: CommandResult) -> Any:
    if not res.ok or res.stdout_truncated:
        raise ValueError(_failure(res))
    return json.loads(res.stdout.decode("utf-8"))


def _str(value: Any) -> str | None:
    return value[:TEXT_LIMIT] if isinstance(value, str) else None


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _strings(value: Any) -> tuple[str, ...]:
    return tuple(v[:TEXT_LIMIT] for v in value[:64] if isinstance(v, str)) if isinstance(value, list) else ()


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, dict) else {}


def collect_host(queries: HostQueries, home: Path) -> HostFacts:
    mem = queries.memory_bytes()
    memory = int(_text(mem.stdout)) if mem.ok and _text(mem.stdout).isdigit() else None
    try:
        free: int | None = shutil.disk_usage(home).free
    except OSError:
        free = None
    return HostFacts(
        system=platform.system(), macos_version=platform.mac_ver()[0] or None, machine=platform.machine(),
        cpu_count=os.cpu_count(), memory_bytes=memory, home_disk_free_bytes=free,
        home_git_repository=os.path.lexists(home / ".git"),
    )


def collect_python() -> PythonFacts:
    return PythonFacts(version=platform.python_version(), implementation=platform.python_implementation(),
                       executable=sys.executable, base_prefix=sys.base_prefix)


def collect_tool(queries: HostQueries, tool: Tool) -> ToolFacts:
    path = queries.tool_path(tool)
    if path is None:
        return ToolFacts(tool.value, None, None, None, f"{tool.value} not found in {', '.join(TOOL_DIRS)}")
    resolved = str(Path(path).resolve())
    try:
        res = queries.tool_version(tool, path)
    except (PolicyViolation, OSError) as exc:
        return ToolFacts(tool.value, path, resolved, None, str(exc)[:TEXT_LIMIT])
    if not res.ok:
        return ToolFacts(tool.value, path, resolved, None, _failure(res))
    return ToolFacts(tool.value, path, resolved, _text(res.stdout))


def collect_docker(queries: HostQueries, home: Path) -> DockerFacts:
    """Inspect the desktop-linux context first and query nothing else unless it points at
    the Docker Desktop user socket (the probe runner's PRE-01 rule)."""
    try:
        binary = queries.docker_binary()
    except (PolicyViolation, OSError) as exc:
        return DockerFacts(errors=(str(exc)[:TEXT_LIMIT],))
    expected = f"unix://{home}/.docker/run/docker.sock"
    try:
        ctx = _json(queries.docker(ContextInspect()))
        endpoint = _str(ctx[0]["Endpoints"]["docker"]["Host"]) if isinstance(ctx, list) and len(ctx) == 1 else None
    except (ValueError, KeyError, TypeError, IndexError, PolicyViolation, OSError) as exc:
        return DockerFacts(binary=binary, expected_endpoint=expected,
                           errors=(str(exc)[:TEXT_LIMIT] or "context-inspect: unreadable output",))
    if endpoint != expected:
        return DockerFacts(binary=binary, context_endpoint=endpoint, expected_endpoint=expected,
                           errors=("context endpoint is not the Docker Desktop user socket; daemon not queried",))

    errors: list[str] = []
    version: Mapping[str, Any] = {}
    info: Mapping[str, Any] = {}
    try:
        version = _mapping(_json(queries.docker(Version())))
    except (ValueError, PolicyViolation, OSError) as exc:
        errors.append(str(exc)[:TEXT_LIMIT] or "version: unreadable output")
    try:
        info = _mapping(_json(queries.docker(DockerInfo())))
    except (ValueError, PolicyViolation, OSError) as exc:
        errors.append(str(exc)[:TEXT_LIMIT] or "info: unreadable output")
    server = _mapping(version.get("Server"))
    return DockerFacts(
        binary=binary, context_endpoint=endpoint, expected_endpoint=expected,
        client_version=_str(_mapping(version.get("Client")).get("Version")),
        server_version=_str(server.get("Version")),
        platform_name=_str(_mapping(server.get("Platform")).get("Name")),
        os_type=_str(info.get("OSType")), architecture=_str(info.get("Architecture")),
        cgroup_version=_str(info.get("CgroupVersion")), security_options=_strings(info.get("SecurityOptions")),
        default_runtime=_str(info.get("DefaultRuntime")),
        network_drivers=_strings(_mapping(info.get("Plugins")).get("Network")),
        ncpu=_int(info.get("NCPU")), mem_total=_int(info.get("MemTotal")), warnings=_strings(info.get("Warnings")),
        errors=tuple(errors),
    )


def collect_image(queries: HostQueries, docker_usable: bool) -> ImageFacts:
    approved = APPROVED_PROBE_IMAGE_ID
    if approved is None:
        return ImageFacts(approved_id=None, present=None, error="no approved probe image identity in policy code")
    if not docker_usable:
        return ImageFacts(approved_id=approved, present=None, error="Docker not reachable; image not inspected")
    try:
        res = queries.docker(ImageInspect(ImageId(approved)))
    except (PolicyViolation, OSError) as exc:
        return ImageFacts(approved_id=approved, present=None, error=str(exc)[:TEXT_LIMIT])
    if not res.ok:
        # `docker image inspect` exits 1 for an absent image. Doctor never pulls.
        return ImageFacts(approved_id=approved, present=False, error=_failure(res))
    try:
        doc = json.loads(res.stdout.decode("utf-8"))
        obj = _mapping(doc[0]) if isinstance(doc, list) and len(doc) == 1 else None
    except ValueError:
        obj = None
    if obj is None:
        return ImageFacts(approved_id=approved, present=None, error="image-inspect: unreadable output")
    return ImageFacts(approved_id=approved, present=True, observed_id=_str(obj.get("Id")), os=_str(obj.get("Os")),
                      architecture=_str(obj.get("Architecture")), repo_digests=_strings(obj.get("RepoDigests")))


def collect_evidence_root(root: Path) -> EvidenceRootFacts:
    try:
        ev.verify_evidence_root(root)  # lstat only; never creates the directory
    except PolicyViolation as exc:
        return EvidenceRootFacts(str(root), False, str(exc)[:TEXT_LIMIT])
    return EvidenceRootFacts(str(root), True, "exists, is a real directory owned by this user, mode 0700")


def collect(queries: HostQueries, home: Path, root: Path) -> EnvironmentFacts:
    docker = collect_docker(queries, home)
    return EnvironmentFacts(
        host=collect_host(queries, home),
        python=collect_python(),
        git=collect_tool(queries, Tool.GIT),
        uv=collect_tool(queries, Tool.UV),
        docker=docker,
        image=collect_image(queries, docker.server_version is not None),
        evidence_root=collect_evidence_root(root),
    )
