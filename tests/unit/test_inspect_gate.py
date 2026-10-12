"""PP-003: the inspect-before-start gate refuses drift, missing, and contradictory evidence."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from typing import Any

import pytest
from _fakes import IMAGE, IMAGE_ENV, OWNERSHIP, good_inspect

from patchproof.runner.docker_cli import create_argv_tail
from patchproof.runner.inspect_gate import check_create_argv, check_created_container, parse_single_inspect
from patchproof.runner.policy import ContainerId, Role, build_spec

CID = "a" * 64
SPEC = build_spec(ownership=OWNERSHIP, role=Role.TARGET, image=IMAGE, script="x=1", args=("target", "c" * 32))
VSPEC = build_spec(ownership=OWNERSHIP, role=Role.VERIFIER, image=IMAGE, script="x=1", args=("verifier", "c" * 32),
                   join_target=ContainerId("f" * 64))


def gate(obj: dict[str, Any], spec: Any = SPEC, argv: list[str] | None = None) -> Any:
    return check_created_container(obj, spec, ContainerId(CID), IMAGE_ENV,
                                   create_argv=create_argv_tail(spec) if argv is None else argv)


def test_matching_inspect_passes() -> None:
    assert gate(good_inspect(SPEC, CID)).passed
    assert gate(good_inspect(VSPEC, CID), VSPEC).passed


def hc(key: str, value: Any) -> Callable[[dict[str, Any]], None]:
    return lambda o: o["HostConfig"].__setitem__(key, value)


def cfg(key: str, value: Any) -> Callable[[dict[str, Any]], None]:
    return lambda o: o["Config"].__setitem__(key, value)


DRIFT: dict[str, tuple[Callable[[dict[str, Any]], None], str]] = {
    "privileged": (hc("Privileged", True), "HostConfig.Privileged"),
    "cap-add": (hc("CapAdd", ["NET_ADMIN"]), "HostConfig.CapAdd"),
    "cap-drop partial": (hc("CapDrop", ["NET_RAW"]), "HostConfig.CapDrop"),
    "rw rootfs": (hc("ReadonlyRootfs", False), "HostConfig.ReadonlyRootfs"),
    "seccomp unconfined": (hc("SecurityOpt", ["no-new-privileges=true", "seccomp=unconfined"]), "HostConfig.SecurityOpt"),
    "no-new-privileges missing": (hc("SecurityOpt", []), "HostConfig.SecurityOpt"),
    "apparmor unconfined": (hc("SecurityOpt", ["no-new-privileges=true", "apparmor=unconfined"]), "HostConfig.SecurityOpt"),
    "bridge": (hc("NetworkMode", "bridge"), "HostConfig.NetworkMode"),
    "host net": (hc("NetworkMode", "host"), "HostConfig.NetworkMode"),
    "port binding": (hc("PortBindings", {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]}),
                     "HostConfig.PortBindings"),
    "publish all": (hc("PublishAllPorts", True), "HostConfig.PublishAllPorts"),
    "socket bind": (hc("Binds", ["/var/run/docker.sock:/var/run/docker.sock"]), "HostConfig.Binds"),
    "home mount": (hc("Mounts", [{"Type": "bind", "Source": "/Users", "Target": "/h"}]), "HostConfig.Mounts"),
    "volumes-from": (hc("VolumesFrom", ["other"]), "HostConfig.VolumesFrom"),
    "device": (hc("Devices", [{"PathOnHost": "/dev/kvm"}]), "HostConfig.Devices"),
    "gpu": (hc("DeviceRequests", [{"Count": -1}]), "HostConfig.DeviceRequests"),
    "extra host gateway": (hc("ExtraHosts", ["host.docker.internal:host-gateway"]), "HostConfig.ExtraHosts"),
    "sysctl": (hc("Sysctls", {"net.ipv4.ip_forward": "1"}), "HostConfig.Sysctls"),
    "memory unlimited": (hc("Memory", 0), "HostConfig.Memory"),
    "swap allowed": (hc("MemorySwap", -1), "HostConfig.MemorySwap"),
    "cpu unlimited": (hc("NanoCpus", 0), "HostConfig.NanoCpus"),
    "pids unlimited": (hc("PidsLimit", None), "HostConfig.PidsLimit"),
    "oom kill disabled": (hc("OomKillDisable", True), "HostConfig.OomKillDisable"),
    "host pid": (hc("PidMode", "host"), "HostConfig.PidMode"),
    "host ipc": (hc("IpcMode", "host"), "HostConfig.IpcMode"),
    "shareable ipc": (hc("IpcMode", "shareable"), "HostConfig.IpcMode"),
    "host uts": (hc("UTSMode", "host"), "HostConfig.UTSMode"),
    "host userns": (hc("UsernsMode", "host"), "HostConfig.UsernsMode"),
    "host cgroupns": (hc("CgroupnsMode", "host"), "HostConfig.CgroupnsMode"),
    "other runtime": (hc("Runtime", "sysbox-runc"), "HostConfig.Runtime"),
    "json-file logs": (hc("LogConfig", {"Type": "json-file", "Config": {}}), "HostConfig.LogConfig"),
    "unbounded logs": (hc("LogConfig", {"Type": "local", "Config": {"max-size": "100m", "max-file": "2",
                                                                     "compress": "false"}}), "HostConfig.LogConfig"),
    "systempaths unconfined": (hc("MaskedPaths", []), "HostConfig.MaskedPaths"),
    "tmpfs exec": (hc("Tmpfs", {"/scratch": "rw,size=268435456,mode=1777", "/tmp": "rw"}), "HostConfig.Tmpfs"),
    "restart always": (lambda o: o["HostConfig"].__setitem__("RestartPolicy", {"Name": "always"}),
                       "HostConfig.RestartPolicy.Name"),
    "root user": (cfg("User", "0:0"), "Config.User"),
    "no user": (cfg("User", ""), "Config.User"),
    "entrypoint wrapper": (cfg("Entrypoint", ["/bin/sh", "-c"]), "Config.Entrypoint"),
    "command changed": (cfg("Cmd", ["-c", "import os"]), "Config.Cmd"),
    "label dropped": (cfg("Labels", {}), "Config.Labels"),
    "host env injected": (cfg("Env", [*IMAGE_ENV, "AWS_SECRET_ACCESS_KEY=x"]), "Config.Env"),
    "stdin open": (cfg("OpenStdin", True), "Config.OpenStdin"),
    "tty": (cfg("Tty", True), "Config.Tty"),
    "anonymous volume": (cfg("Volumes", {"/data": {}}), "Config.Volumes"),
    "exposed port": (cfg("ExposedPorts", {"8080/tcp": {}}), "Config.ExposedPorts"),
    "mount listed": (lambda o: o.__setitem__("Mounts", [{"Type": "volume", "Name": "x"}]), "Mounts"),
    "published ports": (lambda o: o["NetworkSettings"].__setitem__("Ports", {"8080/tcp": [{"HostPort": "1"}]}),
                        "NetworkSettings.Ports"),
    "different image": (lambda o: o.__setitem__("Image", "sha256:" + "2" * 64), "Image"),
    "different id": (lambda o: o.__setitem__("Id", "b" * 64), "Id"),
    "different name": (lambda o: o.__setitem__("Name", "/unrelated_db"), "Name"),
    "already running": (lambda o: o["State"].__setitem__("Status", "running"), "State.Status"),
    "default 64 MiB shm": (hc("ShmSize", 67108864), "HostConfig.ShmSize"),
    "shm size missing": (lambda o: o["HostConfig"].pop("ShmSize"), "HostConfig.ShmSize"),
    "windows platform": (lambda o: o.__setitem__("Platform", "windows"), "Platform"),
    "arm64 manifest selected": (lambda o: o["ImageManifestDescriptor"]["platform"].__setitem__(
        "architecture", "arm64"), "ImageManifestDescriptor.platform"),
    "manifest platform missing": (lambda o: o["ImageManifestDescriptor"].pop("platform"),
                                  "ImageManifestDescriptor.platform"),
}


@pytest.mark.parametrize("name", sorted(DRIFT))
def test_drift_is_refused_and_named(name: str) -> None:
    mutate, field = DRIFT[name]
    obj = good_inspect(SPEC, CID)
    mutate(obj)
    result = gate(obj)
    assert not result.passed
    assert field in {m.field for m in result.mismatches}, result.summary()


def test_verifier_must_join_exact_target() -> None:
    obj = good_inspect(VSPEC, CID)
    obj["HostConfig"]["NetworkMode"] = "container:" + "e" * 64
    assert not gate(obj, VSPEC).passed


@pytest.mark.parametrize("path", ["HostConfig.CapDrop", "HostConfig.ReadonlyRootfs", "HostConfig.SecurityOpt",
                                  "HostConfig.Privileged", "HostConfig.Binds", "HostConfig.Devices", "Config.User",
                                  "HostConfig.LogConfig", "HostConfig", "Config", "NetworkSettings.Ports", "Mounts"])
def test_missing_evidence_is_refused(path: str) -> None:
    obj = good_inspect(SPEC, CID)
    parent: Any = obj
    *head, last = path.split(".")
    for part in head:
        parent = parent[part]
    del parent[last]
    assert not gate(obj).passed


ARGV_DRIFT = {
    "no --pull=never": lambda a: [t for t in a if t != "--pull=never"],
    "--pull=always": lambda a: ["--pull=always" if t == "--pull=never" else t for t in a],
    "--pull missing value form": lambda a: ["--pull" if t == "--pull=never" else t for t in a],
    "no --platform": lambda a: [t for i, t in enumerate(a) if t != "--platform" and a[i - 1] != "--platform"],
    "arm64 platform": lambda a: ["linux/arm64" if t == "linux/amd64" else t for t in a],
    "tag instead of ID": lambda a: ["python:3.13-slim" if t == IMAGE.value else t for t in a],
    "extra privileged option": lambda a: ["--privileged", *a],
}


@pytest.mark.parametrize("name", sorted(ARGV_DRIFT))
def test_create_argv_drift_is_refused_before_start(name: str) -> None:
    argv = ARGV_DRIFT[name](create_argv_tail(SPEC))
    result = gate(good_inspect(SPEC, CID), argv=argv)
    assert not result.passed
    assert any(m.field.startswith("create argv") for m in result.mismatches)


def test_missing_create_argv_is_refused() -> None:
    assert not check_created_container(good_inspect(SPEC, CID), SPEC, ContainerId(CID), IMAGE_ENV).passed
    assert check_create_argv(None, SPEC)


def test_absent_manifest_descriptor_is_tolerated_but_platform_os_is_required() -> None:
    obj = good_inspect(SPEC, CID)
    del obj["ImageManifestDescriptor"]
    assert gate(obj).passed  # architecture then rests on PRE-02 and the in-container PRV-P4
    del obj["Platform"]
    assert not gate(obj).passed


def test_omitempty_fields_may_be_absent() -> None:
    obj = good_inspect(SPEC, CID)
    obj["HostConfig"].pop("Sysctls", None)
    obj["HostConfig"].pop("Init", None)
    assert gate(obj).passed


def test_init_true_is_refused() -> None:
    obj = good_inspect(SPEC, CID)
    obj["HostConfig"]["Init"] = True
    assert not gate(obj).passed


def test_mutation_does_not_leak_between_checks() -> None:
    obj = good_inspect(SPEC, CID)
    snapshot = copy.deepcopy(obj)
    gate(obj)
    assert obj == snapshot


@pytest.mark.parametrize("raw", [b"not json", b"{}", b"[]", b"[{}, {}]", b'["x"]', b"\xff"])
def test_parse_single_inspect_rejects_malformed(raw: bytes) -> None:
    with pytest.raises(ValueError):
        parse_single_inspect(raw)


def test_parse_single_inspect_rejects_wrong_id() -> None:
    with pytest.raises(ValueError, match="different container"):
        parse_single_inspect(json.dumps([{"Id": "b" * 64}]).encode(), ContainerId(CID))
    assert parse_single_inspect(json.dumps([{"Id": CID}]).encode(), ContainerId(CID))["Id"] == CID
