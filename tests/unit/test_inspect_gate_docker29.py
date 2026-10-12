"""PP-003 regression: the inspect gate against REAL Docker Engine 29.8.2 inspect output.

A4 run run-d109d3606276fd75137241a6a1bc6b92 was BLOCKED because Docker 29.8.2 omits
`Config.ExposedPorts` and `HostConfig.Mounts` when empty, which the gate (built against
synthetic fixtures) read as missing evidence. The fixture below is that real output,
sanitized; tests rebind only identity fields (ID, name, command, labels) to a test spec,
so Docker's actual key presence, nesting, and value types are what is exercised.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from patchproof.probes.orchestrator import gate_mutation_results
from patchproof.runner.docker_cli import create_argv_tail
from patchproof.runner.inspect_gate import check_created_container
from patchproof.runner.policy import ContainerId, ContainerSpec, ImageId, Ownership, Role, build_spec

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "docker-29.8.2-inspect-created.json"
DOC = json.loads(FIXTURE.read_text())
OWNERSHIP = Ownership("inst-" + "a" * 32, "run-" + "b" * 32)
ROLES = sorted(DOC["containers"])


def rebound(role_name: str) -> tuple[dict[str, Any], ContainerSpec, ContainerId, list[str]]:
    obj = copy.deepcopy(DOC["containers"][role_name])
    role = Role(role_name)
    spec = build_spec(ownership=OWNERSHIP, role=role, image=ImageId(obj["Image"]), script="x=1",
                      args=tuple(obj["Config"]["Cmd"][5:]))
    cid = ContainerId(obj["Id"])
    obj["Name"] = "/" + spec.name
    obj["Config"]["Cmd"] = obj["Args"] = list(spec.command)
    obj["Config"]["Labels"] = spec.label_map
    return obj, spec, cid, obj["Config"]["Env"]


def gate(obj: dict[str, Any], spec: ContainerSpec, cid: ContainerId, env: list[str]) -> Any:
    return check_created_container(obj, spec, cid, env, create_argv=create_argv_tail(spec))


def test_fixture_really_omits_the_two_fields() -> None:
    for role in ROLES:
        obj = DOC["containers"][role]
        assert "ExposedPorts" not in obj["Config"], role
        assert "Mounts" not in obj["HostConfig"], role
        assert obj["Mounts"] == [] and obj["HostConfig"]["Binds"] is None, role
        assert obj["HostConfig"]["PortBindings"] == {} and obj["NetworkSettings"]["Ports"] == {}, role
    assert "verifier" not in ROLES, "the verifier was never created in run d109d360; its shape is still untested"


@pytest.mark.parametrize("role", ROLES)
def test_observed_compliant_representation_passes_for_every_role(role: str) -> None:
    result = gate(*rebound(role))
    assert result.passed, result.summary()


Mutation = Callable[[dict[str, Any]], None]

UNSAFE: dict[str, tuple[Mutation, str]] = {
    "bind mount requested": (lambda o: o["HostConfig"].__setitem__(
        "Mounts", [{"Type": "bind", "Source": "/Users", "Target": "/h"}]), "HostConfig.Mounts"),
    "socket mount requested": (lambda o: o["HostConfig"].__setitem__(
        "Mounts", [{"Type": "bind", "Source": "/var/run/docker.sock", "Target": "/s"}]), "HostConfig.Mounts"),
    "port exposed": (lambda o: o["Config"].__setitem__("ExposedPorts", {"8080/tcp": {}}), "Config.ExposedPorts"),
    "ExposedPorts wrong type": (lambda o: o["Config"].__setitem__("ExposedPorts", "8080/tcp"), "Config.ExposedPorts"),
    "Mounts wrong type": (lambda o: o["HostConfig"].__setitem__("Mounts", "bind"), "HostConfig.Mounts"),
    # Absent key, but the always-serialized evidence is missing, malformed, or contradictory.
    "effective mounts missing": (lambda o: o.pop("Mounts"), "HostConfig.Mounts"),
    "effective mounts non-empty": (lambda o: o.__setitem__(
        "Mounts", [{"Type": "bind", "Source": "/host_mnt/Users", "Destination": "/h"}]), "HostConfig.Mounts"),
    "effective mounts malformed": (lambda o: o.__setitem__("Mounts", False), "HostConfig.Mounts"),
    "binds missing": (lambda o: o["HostConfig"].pop("Binds"), "HostConfig.Mounts"),
    "binds present": (lambda o: o["HostConfig"].__setitem__("Binds", ["/Users:/h"]), "HostConfig.Mounts"),
    "volumes declared": (lambda o: o["Config"].__setitem__("Volumes", {"/data": {}}), "HostConfig.Mounts"),
    "runtime port map": (lambda o: o["NetworkSettings"].__setitem__(
        "Ports", {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]}), "Config.ExposedPorts"),
    "port bindings": (lambda o: o["HostConfig"].__setitem__(
        "PortBindings", {"8080/tcp": [{"HostPort": "8080"}]}), "Config.ExposedPorts"),
    "publish-all": (lambda o: o["HostConfig"].__setitem__("PublishAllPorts", True), "Config.ExposedPorts"),
    "publish-all missing": (lambda o: o["HostConfig"].pop("PublishAllPorts"), "Config.ExposedPorts"),
    "publish-all null": (lambda o: o["HostConfig"].__setitem__("PublishAllPorts", None), "Config.ExposedPorts"),
    "network settings missing": (lambda o: o.pop("NetworkSettings"), "Config.ExposedPorts"),
}


@pytest.mark.parametrize("name", sorted(UNSAFE))
def test_unsafe_or_unproven_variants_of_real_output_fail_closed(name: str) -> None:
    obj, spec, cid, env = rebound("target")
    mutate, field = UNSAFE[name]
    mutate(obj)
    result = gate(obj, spec, cid, env)
    assert not result.passed
    assert field in {m.field for m in result.mismatches}, result.summary()


@pytest.mark.parametrize("name,mutate", [
    ("ExposedPorts present and empty", lambda o: o["Config"].__setitem__("ExposedPorts", {})),
    ("ExposedPorts present and null", lambda o: o["Config"].__setitem__("ExposedPorts", None)),
    ("HostConfig.Mounts present and empty", lambda o: o["HostConfig"].__setitem__("Mounts", [])),
    ("HostConfig.Mounts present and null", lambda o: o["HostConfig"].__setitem__("Mounts", None)),
])
def test_explicitly_empty_forms_remain_accepted(name: str, mutate: Mutation) -> None:
    obj, spec, cid, env = rebound("target")
    mutate(obj)
    assert gate(obj, spec, cid, env).passed, name


def test_pol05_drift_mutations_on_real_output() -> None:
    obj, spec, cid, env = rebound("target")
    results = gate_mutation_results(obj, spec, cid, tuple(env), create_argv_tail(spec))
    assert results[0] == ("", False), "unmutated real inspect must pass (POL-05 internal control)"
    missed = [name for name, rejected in results[1:] if not rejected]
    assert not missed, missed


def test_other_security_fields_in_real_output_are_still_enforced() -> None:
    for field, value in (("Privileged", True), ("CapAdd", ["SYS_ADMIN"]), ("ReadonlyRootfs", False),
                         ("SecurityOpt", ["no-new-privileges=true", "seccomp=unconfined"]), ("ShmSize", 67108864),
                         ("NetworkMode", "host"), ("PidMode", "host"), ("IpcMode", "host")):
        obj, spec, cid, env = rebound("target")
        obj["HostConfig"][field] = value
        assert not gate(obj, spec, cid, env).passed, field
