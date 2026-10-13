"""Inspect-before-start gate for verification-run containers (PROJECT_SPEC.md 10.2; ADR-009).

The same discipline as the accepted PP-003 gate (`inspect_gate.check_created_container`):
compare what Docker recorded with the fixed policy, and refuse to start on any mismatch,
missing field or contradiction. Every security field of the probe gate is checked again
here. Only these three differ:
- **Command:** the fixed role command.
- **Input:** exactly one read-only bind, with the exact source and the fixed destination.
  `HostConfig.Mounts` and the effective `Mounts` list must both show it, with `RW: false`.
- **Health check:** the target's image-defined check must equal the reviewed one, and the
  verifier must have none.

Passing is configuration evidence only. It does not prove that the kernel enforced the
policy (PP-003 probes do that).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Final

from .inspect_gate import _MISSING, GateResult, Mismatch, _corroborates, _get, _is_empty, _render
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
)
from .run_policy import TARGET_HEALTHCHECK, RunContainerSpec, RunRole, run_create_argv_tail

_OMITEMPTY: Final = frozenset({"HostConfig.Init", "HostConfig.Sysctls", "HostConfig.Annotations"})
_PORTS_CORROBORATION: Final = (("HostConfig.PortBindings", "empty"), ("HostConfig.PublishAllPorts", "false"),
                               ("NetworkSettings.Ports", "empty"))
_ALLOWED_MOUNT_EXTRAS: Final = frozenset({"BindOptions", "Consistency"})


def check_run_container(inspect: Mapping[str, Any], spec: RunContainerSpec, container_id: ContainerId,
                        image_env: Sequence[str], *, create_argv: Sequence[str] | None,
                        expected_state: str = "created") -> GateResult:
    mismatches: list[Mismatch] = []
    checked = 0

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
        if observed is _MISSING and path == "Config.ExposedPorts":
            if all(_corroborates(_get(inspect, c), form) for c, form in _PORTS_CORROBORATION):
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

    checked += 1
    if create_argv is None or list(create_argv) != run_create_argv_tail(spec):
        mismatches.append(Mismatch("create argv", "exactly the fixed run-container argv", "differs or missing"))

    limits = spec.limits
    exact("Id", container_id.value)
    exact("Name", "/" + spec.name)
    exact("Image", spec.image.value)
    exact("Platform", APPROVED_PROBE_PLATFORM.split("/")[0])
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
    checked += 1
    health = _get(inspect, "Config.Healthcheck")
    if spec.role is RunRole.TARGET:
        if health != TARGET_HEALTHCHECK:
            mismatches.append(Mismatch("Config.Healthcheck", "the reviewed target health check", _render(health)))
    elif health not in (_MISSING, None):
        mismatches.append(Mismatch("Config.Healthcheck", "absent for the verifier", _render(health)))

    exact("HostConfig.Privileged", False)
    exact("HostConfig.CapDrop", ["ALL"])
    empty("HostConfig.CapAdd")
    exact("HostConfig.ReadonlyRootfs", True)
    exact("HostConfig.SecurityOpt", list(SECURITY_OPTS))
    exact("HostConfig.NetworkMode", spec.network.mode)
    empty("HostConfig.PortBindings")
    exact("HostConfig.PublishAllPorts", False)
    empty("HostConfig.Binds")
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
    exact("HostConfig.LogConfig", {"Type": LOG_DRIVER, "Config": {
        "max-size": LOG_MAX_SIZE, "max-file": str(LOG_MAX_FILE), "compress": LOG_COMPRESS}})
    for path in ("HostConfig.MaskedPaths", "HostConfig.ReadonlyPaths"):
        checked += 1
        observed = _get(inspect, path)
        if not isinstance(observed, list) or not observed:
            mismatches.append(Mismatch(path, "non-empty list (runtime default masking)", _render(observed)))
    checked += 1
    if _get(inspect, "HostConfig.RestartPolicy.Name") not in ("no", ""):
        mismatches.append(Mismatch("HostConfig.RestartPolicy.Name", '"no"',
                                   _render(_get(inspect, "HostConfig.RestartPolicy.Name"))))
    empty("NetworkSettings.Ports")

    source, destination = str(spec.input.source), spec.input.destination
    checked += 2
    requested = _get(inspect, "HostConfig.Mounts")
    ok_requested = (isinstance(requested, list) and len(requested) == 1 and isinstance(requested[0], Mapping)
                    and requested[0].get("Type") == "bind" and requested[0].get("Source") == source
                    and requested[0].get("Target") == destination and requested[0].get("ReadOnly") is True
                    and set(requested[0]) <= {"Type", "Source", "Target", "ReadOnly", *_ALLOWED_MOUNT_EXTRAS})
    if not ok_requested:
        mismatches.append(Mismatch("HostConfig.Mounts", f"one read-only bind {source} -> {destination}",
                                   _render(requested)))
    effective = _get(inspect, "Mounts")
    ok_effective = (isinstance(effective, list) and len(effective) == 1 and isinstance(effective[0], Mapping)
                    and effective[0].get("Type") == "bind" and effective[0].get("Source") == source
                    and effective[0].get("Destination") == destination and effective[0].get("RW") is False)
    if not ok_effective:
        mismatches.append(Mismatch("Mounts", f"one read-only bind {source} -> {destination} (RW false)",
                                   _render(effective)))
    return GateResult(passed=not mismatches, mismatches=tuple(mismatches), checked_fields=checked)
