"""Inspect-before-start gate (PROJECT_SPEC.md 10.2; ADR-009 "absence of a field is not proof").

After `docker create`, the runner inspects the container and compares what the runtime
recorded against the fixed policy. Any mismatch, missing field, or contradictory value
means the container is not started. This is pure logic over parsed JSON.

Passing this gate is *configuration* evidence only. It shows what Docker says it will
apply; the probes show whether the kernel enforced it.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from .docker_cli import create_argv_tail
from .policy import (
    APPROVED_PROBE_PLATFORM,
    CGROUPNS_MODE,
    CONTAINER_USER,
    ENTRYPOINT,
    EXPECTED_RUNTIME,
    IPC_MODE,
    LOG_COMPRESS,
    LOG_DRIVER,
    LOG_MAX_FILE,
    LOG_MAX_SIZE,
    SECURITY_OPTS,
    SHM_SIZE_BYTES,
    WORKDIR,
    ContainerId,
    ContainerSpec,
)

_MISSING: Final = object()

# Fields Docker serialises with `omitempty`; absence is equivalent to the empty value.
_OMITEMPTY: Final = frozenset({"HostConfig.Init", "HostConfig.Sysctls", "HostConfig.Annotations"})

# Security-relevant fields that Docker 29.8.2 also omits when empty (observed in A4 run
# run-d109d3606276fd75137241a6a1bc6b92). Absence alone proves nothing, so an absent key is
# accepted only when every listed always-serialized field independently shows the same
# property: present and empty (or false). Otherwise the gate fails closed.
_OMITEMPTY_CORROBORATED: Final[dict[str, tuple[tuple[str, str], ...]]] = {
    # No requested --mount entries: the effective mount list and the bind/volume inputs are empty.
    "HostConfig.Mounts": (("Mounts", "empty-list"), ("HostConfig.Binds", "empty"),
                          ("HostConfig.VolumesFrom", "empty"), ("Config.Volumes", "empty")),
    # No exposed ports: nothing bound, nothing auto-published, no runtime port map.
    "Config.ExposedPorts": (("HostConfig.PortBindings", "empty"), ("HostConfig.PublishAllPorts", "false"),
                            ("NetworkSettings.Ports", "empty")),
}


def _corroborates(value: Any, form: str) -> bool:
    if value is _MISSING:
        return False
    if form == "false":
        return value is False
    if form == "empty-list":
        return value == [] and isinstance(value, list)
    return value is None or (isinstance(value, (list, dict)) and not value)


@dataclass(frozen=True)
class Mismatch:
    field: str
    expected: str
    observed: str


@dataclass(frozen=True)
class GateResult:
    passed: bool
    mismatches: tuple[Mismatch, ...]
    checked_fields: int

    def summary(self) -> str:
        if self.passed:
            return f"all {self.checked_fields} inspected fields match the fixed policy"
        return "; ".join(f"{m.field}: expected {m.expected}, observed {m.observed}" for m in self.mismatches)


def _get(obj: Any, dotted: str) -> Any:
    current = obj
    for part in dotted.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return _MISSING
        current = current[part]
    return current


def _render(value: Any) -> str:
    if value is _MISSING:
        return "<missing>"
    text = json.dumps(value, sort_keys=True, default=str)
    return text if len(text) <= 200 else text[:197] + "..."


def _is_empty(value: Any) -> bool:
    return value is None or value == [] or value == {} or value == ""


def parse_single_inspect(stdout: bytes, expected_id: ContainerId | None = None) -> dict[str, Any]:
    """Parse `docker container inspect` output: exactly one object, matching ID if given."""
    try:
        data = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"inspect output is not JSON: {exc}") from exc
    if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
        raise ValueError("inspect output must be a list holding exactly one object")
    obj = data[0]
    if expected_id is not None and obj.get("Id") != expected_id.value:
        raise ValueError("inspect returned a different container ID than requested")
    return obj


def check_create_argv(executed_tail: Sequence[str] | None, spec: ContainerSpec) -> list[Mismatch]:
    """The executed `create` argv must be exactly the fixed one, with --platform and --pull=never.

    `--pull=never` leaves no trace in `docker inspect`, so the executed command itself is
    part of the pre-start evidence.
    """
    if executed_tail is None:
        return [Mismatch("create argv", "the executed create argv", "<missing>")]
    tail = list(executed_tail)
    problems = []
    if tail != create_argv_tail(spec):
        problems.append(Mismatch("create argv", "exactly the fixed policy argv", "differs"))
    image_at = tail.index(spec.image.value) if spec.image.value in tail else -1
    options = tail[:image_at] if image_at >= 0 else tail
    if options.count("--pull=never") != 1 or any(t.startswith("--pull") and t != "--pull=never" for t in options):
        problems.append(Mismatch("create argv --pull", "--pull=never exactly once", _render(options)))
    pairs = [(options[i], options[i + 1]) for i in range(len(options) - 1)]
    if pairs.count(("--platform", APPROVED_PROBE_PLATFORM)) != 1 or sum(
            t.startswith("--platform") for t in options) != 1:
        problems.append(Mismatch("create argv --platform", f"--platform {APPROVED_PROBE_PLATFORM}", _render(options)))
    if image_at < 0:
        problems.append(Mismatch("create argv image", spec.image.value, "<absent>"))
    return problems


def check_created_container(
    inspect: Mapping[str, Any],
    spec: ContainerSpec,
    container_id: ContainerId,
    image_env: Sequence[str],
    *,
    expected_state: str = "created",
    create_argv: Sequence[str] | None = None,
    check_argv: bool = True,
) -> GateResult:
    """Compare one inspected container (and its create argv) with the fixed policy for `spec`."""
    mismatches: list[Mismatch] = check_create_argv(create_argv, spec) if check_argv else []
    checked = 1 if check_argv else 0

    def exact(path: str, expected: Any) -> None:
        nonlocal checked
        checked += 1
        observed = _get(inspect, path)
        if observed != expected:
            mismatches.append(Mismatch(path, _render(expected), _render(observed)))

    def empty(path: str) -> None:
        nonlocal checked
        checked += 1
        observed = _get(inspect, path)
        if observed is _MISSING and path in _OMITEMPTY:
            return
        if observed is _MISSING and path in _OMITEMPTY_CORROBORATED:
            unproven = [c for c, form in _OMITEMPTY_CORROBORATED[path] if not _corroborates(_get(inspect, c), form)]
            if unproven:
                mismatches.append(Mismatch(path, "empty, or absent with corroborating empty fields",
                                           f"<missing>; not corroborated by {unproven}"))
            return
        if observed is _MISSING or not _is_empty(observed):
            mismatches.append(Mismatch(path, "empty", _render(observed)))

    def falsy(path: str) -> None:
        nonlocal checked
        checked += 1
        observed = _get(inspect, path)
        if observed is _MISSING and path in _OMITEMPTY:
            return
        if observed not in (False, None):
            mismatches.append(Mismatch(path, "false", _render(observed)))

    def non_empty_list(path: str) -> None:
        nonlocal checked
        checked += 1
        observed = _get(inspect, path)
        if not isinstance(observed, list) or not observed:
            mismatches.append(Mismatch(path, "non-empty list (runtime default masking)", _render(observed)))

    limits = spec.limits
    exact("Id", container_id.value)
    exact("Name", "/" + spec.name)
    exact("Image", spec.image.value)
    platform_os, platform_arch = APPROVED_PROBE_PLATFORM.split("/")
    exact("Platform", platform_os)
    # containerd image store: the platform the daemon selected from the index. When the
    # field is absent the architecture is evidenced by PRE-02 and the in-container PRV-P4.
    descriptor = _get(inspect, "ImageManifestDescriptor")
    if descriptor is not _MISSING and descriptor is not None:
        checked += 1
        plat = descriptor.get("platform") if isinstance(descriptor, Mapping) else None
        if not isinstance(plat, Mapping) or (plat.get("os"), plat.get("architecture")) != (platform_os, platform_arch):
            mismatches.append(Mismatch("ImageManifestDescriptor.platform", APPROVED_PROBE_PLATFORM, _render(plat)))
    exact("State.Status", expected_state)
    exact("Config.Image", spec.image.value)
    exact("Config.User", CONTAINER_USER)
    exact("Config.Entrypoint", [ENTRYPOINT])
    exact("Config.Cmd", list(spec.command))
    exact("Config.Labels", spec.label_map)
    exact("Config.Env", list(image_env))
    exact("Config.WorkingDir", WORKDIR)
    exact("Config.Tty", False)
    exact("Config.OpenStdin", False)
    exact("Config.AttachStdin", False)
    empty("Config.ExposedPorts")
    empty("Config.Volumes")

    exact("HostConfig.Privileged", False)
    exact("HostConfig.CapDrop", ["ALL"])
    empty("HostConfig.CapAdd")
    exact("HostConfig.ReadonlyRootfs", True)
    exact("HostConfig.SecurityOpt", list(SECURITY_OPTS))
    exact("HostConfig.NetworkMode", spec.network.mode)
    empty("HostConfig.PortBindings")
    exact("HostConfig.PublishAllPorts", False)
    empty("HostConfig.Binds")
    empty("HostConfig.Mounts")
    empty("HostConfig.VolumesFrom")
    empty("HostConfig.Links")
    empty("HostConfig.Devices")
    empty("HostConfig.DeviceRequests")
    empty("HostConfig.DeviceCgroupRules")
    empty("HostConfig.ExtraHosts")
    empty("HostConfig.GroupAdd")
    empty("HostConfig.Sysctls")
    empty("HostConfig.CgroupParent")
    exact("HostConfig.Tmpfs", spec.tmpfs())
    exact("HostConfig.Memory", limits.memory_bytes)
    exact("HostConfig.MemorySwap", limits.memory_bytes)
    exact("HostConfig.NanoCpus", limits.nano_cpus)
    exact("HostConfig.PidsLimit", limits.pids)
    falsy("HostConfig.OomKillDisable")
    falsy("HostConfig.Init")
    exact("HostConfig.PidMode", "")
    exact("HostConfig.IpcMode", IPC_MODE)
    exact("HostConfig.ShmSize", SHM_SIZE_BYTES)
    exact("HostConfig.UTSMode", "")
    exact("HostConfig.UsernsMode", "")
    exact("HostConfig.CgroupnsMode", CGROUPNS_MODE)
    exact("HostConfig.Runtime", EXPECTED_RUNTIME)
    exact("HostConfig.AutoRemove", False)
    exact(
        "HostConfig.LogConfig",
        {
            "Type": LOG_DRIVER,
            "Config": {"max-size": LOG_MAX_SIZE, "max-file": str(LOG_MAX_FILE), "compress": LOG_COMPRESS},
        },
    )
    non_empty_list("HostConfig.MaskedPaths")
    non_empty_list("HostConfig.ReadonlyPaths")

    checked += 1
    restart = _get(inspect, "HostConfig.RestartPolicy.Name")
    if restart not in ("no", ""):
        mismatches.append(Mismatch("HostConfig.RestartPolicy.Name", '"no"', _render(restart)))

    empty("Mounts")
    empty("NetworkSettings.Ports")

    return GateResult(passed=not mismatches, mismatches=tuple(mismatches), checked_fields=checked)


# Namespace- and network-related fields, re-used by the probe interpretation (NS-03, NET-08).
NAMESPACE_FIELDS: Final = (
    "HostConfig.PidMode", "HostConfig.IpcMode", "HostConfig.UTSMode", "HostConfig.UsernsMode",
    "HostConfig.CgroupnsMode", "HostConfig.NetworkMode",
)
PORT_FIELDS: Final = ("HostConfig.PortBindings", "HostConfig.PublishAllPorts", "NetworkSettings.Ports",
                      "Config.ExposedPorts")
LOG_FIELDS: Final = ("HostConfig.LogConfig",)
