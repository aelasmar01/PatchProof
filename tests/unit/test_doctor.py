"""v0.0 closeout C2: the read-only `patchproof doctor` (SYNTHETIC host responses).

No test starts a process or contacts Docker: `FakeHost` returns synthetic command
results and records every operation requested, so tests can assert what doctor asked
for as well as what it concluded.
"""

from __future__ import annotations

import json
import os
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import pytest

from patchproof.doctor import assessment as asm
from patchproof.doctor import environment as env
from patchproof.doctor.assessment import Overall, Status, assess, render_text, report_document
from patchproof.doctor.environment import DockerInfo, ReadOnlyHost, Tool, collect
from patchproof.runner import docker_cli
from patchproof.runner.docker_cli import (
    CommandResult,
    ContainerRef,
    ContextInspect,
    Create,
    ForceRemove,
    ImageInspect,
    Inspect,
    Logs,
    Remove,
    SnapshotList,
    Start,
    Stop,
    Version,
    Wait,
)
from patchproof.runner.policy import APPROVED_PROBE_IMAGE_ID, ContainerId, ImageId, PolicyViolation

ROOT = Path(__file__).resolve().parents[2]
HOME = Path("/Users/synthetic")
SOCKET = f"unix://{HOME}/.docker/run/docker.sock"
APPROVED = APPROVED_PROBE_IMAGE_ID or ""


def result(op_name: str, rc: int | None = 0, out: Any = b"", err: bytes = b"", *, timed_out: bool = False,
           truncated: bool = False) -> CommandResult:
    data = out if isinstance(out, bytes) else json.dumps(out).encode()
    return CommandResult(op_name=op_name, argv=(op_name,), returncode=rc, stdout=data, stderr=err,
                         stdout_truncated=truncated, stderr_truncated=False, timed_out=timed_out,
                         duration_seconds=0.01)


GOOD_CONTEXT = [{"Name": "desktop-linux", "Endpoints": {"docker": {"Host": SOCKET}}}]
GOOD_VERSION = {"Client": {"Version": "29.8.2"},
                "Server": {"Version": "29.8.2", "Platform": {"Name": "Docker Desktop 4.94.0 (999999)"}}}
GOOD_INFO = {"OSType": "linux", "Architecture": "x86_64", "CgroupVersion": "2",
             "SecurityOptions": ["name=seccomp,profile=builtin", "name=cgroupns"], "DefaultRuntime": "runc",
             "Plugins": {"Network": ["bridge", "host", "ipvlan", "macvlan", "null", "overlay"]},
             "NCPU": 16, "MemTotal": 8320897024, "Warnings": None}
GOOD_IMAGE = [{"Id": APPROVED, "Os": "linux", "Architecture": "amd64",
               "RepoDigests": [f"python@{APPROVED}"]}]


@dataclass
class FakeHost:
    """Synthetic HostQueries. Each response is a CommandResult or an exception to raise."""

    docker_path: str | Exception = "/usr/local/bin/docker"
    responses: dict[str, Any] = field(default_factory=lambda: {
        "context-inspect": result("context-inspect", out=GOOD_CONTEXT),
        "version": result("version", out=GOOD_VERSION),
        "info": result("info", out=GOOD_INFO),
        "image-inspect": result("image-inspect", out=GOOD_IMAGE),
    })
    tools: dict[Tool, tuple[str | None, CommandResult]] = field(default_factory=lambda: {
        Tool.GIT: ("/usr/local/bin/git", result("git-version", out=b"git version 2.56.0\n")),
        Tool.UV: ("/usr/local/bin/uv", result("uv-version", out=b"uv 0.12.24 (5411378eb 2026-10-08)\n")),
    })
    memory: CommandResult = field(default_factory=lambda: result("sysctl-memsize", out=b"34359738368\n"))
    calls: list[Any] = field(default_factory=list)

    def docker_binary(self) -> str:
        if isinstance(self.docker_path, Exception):
            raise self.docker_path
        return self.docker_path

    def docker(self, op: Any) -> CommandResult:
        self.calls.append(op)
        response = self.responses[op.op_name]
        if isinstance(response, Exception):
            raise response
        assert isinstance(response, CommandResult)
        return response

    def tool_path(self, tool: Tool) -> str | None:
        return self.tools[tool][0]

    def tool_version(self, tool: Tool, path: str) -> CommandResult:
        return self.tools[tool][1]

    def memory_bytes(self) -> CommandResult:
        return self.memory


@pytest.fixture
def ready_root(tmp_path: Path) -> Path:
    root = tmp_path / "probe-runs"
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    return root


def run_doctor(host: FakeHost, root: Path) -> tuple[env.EnvironmentFacts, asm.Assessment]:
    facts = collect(host, HOME, root)
    return facts, assess(facts)


def check(assessment: asm.Assessment, check_id: str) -> asm.Check:
    return next(c for c in assessment.checks if c.check_id == check_id)


def as_pinned_python(facts: env.EnvironmentFacts) -> env.EnvironmentFacts:
    """The test interpreter may differ from the pin; host-dependent facts are fixed here."""
    return replace(facts, python=env.PythonFacts("3.13.16", "CPython", "/x/.venv/bin/python", "/x"),
                   host=replace(facts.host, system="Darwin", machine="x86_64", home_git_repository=False))


# --- the healthy case ----------------------------------------------------------------


def test_healthy_environment_is_ready_and_never_claims_isolation(ready_root: Path) -> None:
    facts, _ = run_doctor(FakeHost(), ready_root)
    result_ = assess(as_pinned_python(facts))
    blocking = [c for c in result_.checks if c.blocks]
    assert result_.overall is Overall.READY, blocking
    assert all(c.status is Status.OK for c in result_.checks), [c for c in result_.checks if c.status is not Status.OK]
    assert result_.isolation_verified_by_doctor is False
    doc = report_document(as_pinned_python(facts), result_)
    assert doc["isolation_verified_by_doctor"] is False
    assert set(doc) == {"report", "overall", "scope", "isolation_verified_by_doctor", "observed", "checks",
                        "assumptions"}
    assert doc["scope"].startswith("v0.0 environment readiness") and "Not isolation" in doc["scope"]
    json.dumps(doc)  # serializable
    assert "NOT VERIFIED by doctor" in render_text(facts, result_)


def test_doctor_requests_only_the_four_read_only_docker_operations(ready_root: Path) -> None:
    host = FakeHost()
    run_doctor(host, ready_root)
    assert [type(op) for op in host.calls] == [ContextInspect, Version, DockerInfo, ImageInspect]
    assert all(op.mutates is False for op in host.calls)
    assert host.calls[-1].image.value == APPROVED


def test_observed_facts_come_from_tool_output(ready_root: Path) -> None:
    facts, _ = run_doctor(FakeHost(), ready_root)
    d = facts.docker
    assert (d.context_endpoint, d.server_version) == (SOCKET, "29.8.2")
    assert d.platform_name == "Docker Desktop 4.94.0 (999999)"
    assert d.network_drivers[-2:] == ("null", "overlay") and d.cgroup_version == "2" and d.warnings == ()
    assert facts.host.memory_bytes == 34359738368
    assert facts.image.present is True and facts.image.observed_id == APPROVED
    assert facts.git.version_output == "git version 2.56.0"


# --- Docker unavailable or wrong: never "ready", never further queries ---------------


def test_docker_client_missing_blocks_without_any_docker_query(ready_root: Path) -> None:
    host = FakeHost(docker_path=PolicyViolation("docker client not found in an allowlisted directory"))
    facts, result_ = run_doctor(host, ready_root)
    assert host.calls == []
    assert check(result_, "DKR-01").status is Status.FAIL and result_.overall is Overall.BLOCKED
    assert check(result_, "IMG-01").status is Status.UNKNOWN
    assert not any(c.check_id.startswith("DKR-0") and c.check_id != "DKR-01" for c in result_.checks)


@pytest.mark.parametrize("context", [
    [{"Endpoints": {"docker": {"Host": "tcp://198.51.100.7:2375"}}}],
    [{"Endpoints": {"docker": {"Host": "unix:///var/run/docker.sock"}}}],
    [], {"not": "a list"},
])
def test_unexpected_context_endpoint_stops_all_daemon_queries(ready_root: Path, context: Any) -> None:
    host = FakeHost()
    host.responses["context-inspect"] = result("context-inspect", out=context)
    _, result_ = run_doctor(host, ready_root)
    assert [type(op) for op in host.calls] == [ContextInspect]  # PRE-01 rule: nothing else is asked
    assert check(result_, "DKR-02").blocks and result_.overall is Overall.BLOCKED


@pytest.mark.parametrize("response", [
    result("version", rc=1, err=b"Cannot connect to the Docker daemon"),
    result("version", rc=None, timed_out=True),
    result("version", out=b"{" * 10, truncated=True),
    result("version", out=b"not json"),
])
def test_unreachable_daemon_blocks_and_skips_image_inspection(ready_root: Path, response: CommandResult) -> None:
    host = FakeHost()
    host.responses["version"] = response
    facts, result_ = run_doctor(host, ready_root)
    assert ImageInspect not in [type(op) for op in host.calls]
    assert check(result_, "DKR-03").status is Status.FAIL and result_.overall is Overall.BLOCKED
    assert facts.docker.errors


def test_context_inspect_failure_is_unknown_and_blocks(ready_root: Path) -> None:
    host = FakeHost()
    host.responses["context-inspect"] = result("context-inspect", rc=1, err=b"context not found")
    _, result_ = run_doctor(host, ready_root)
    assert check(result_, "DKR-02").status is Status.UNKNOWN and result_.overall is Overall.BLOCKED


@pytest.mark.parametrize("platform_name,status", [
    ("Docker Desktop 4.44.2 (1)", Status.FAIL),   # CVE-2025-9074 affected
    ("Docker Desktop 4.42.1 (1)", Status.FAIL),
    ("Docker Desktop 4.44.3 (1)", Status.OK),
    ("Docker Engine - Community", Status.UNKNOWN),  # not Docker Desktop: version cannot be judged
    (None, Status.UNKNOWN),
])
def test_docker_desktop_security_floor(ready_root: Path, platform_name: str | None, status: Status) -> None:
    host = FakeHost()
    server: dict[str, Any] = {"Version": "29.8.2"}
    if platform_name is not None:
        server["Platform"] = {"Name": platform_name}
    host.responses["version"] = result("version", out={"Client": {"Version": "29.8.2"}, "Server": server})
    _, result_ = run_doctor(host, ready_root)
    assert check(result_, "DKR-04").status is status
    assert (result_.overall is Overall.BLOCKED) if status is not Status.OK else not check(result_, "DKR-04").blocks


@pytest.mark.parametrize("change,check_id,status", [
    ({"CgroupVersion": "1"}, "DKR-06", Status.FAIL),
    ({"CgroupVersion": None}, "DKR-06", Status.UNKNOWN),
    ({"SecurityOptions": ["name=cgroupns"]}, "DKR-07", Status.FAIL),
    ({"SecurityOptions": None}, "DKR-07", Status.UNKNOWN),
    ({"Plugins": {"Network": ["bridge", "host"]}}, "DKR-08", Status.FAIL),
    ({"Plugins": {}}, "DKR-08", Status.UNKNOWN),
    ({"Architecture": "aarch64"}, "DKR-05", Status.FAIL),
    ({"OSType": None}, "DKR-05", Status.UNKNOWN),
])
def test_required_daemon_capabilities_block_when_absent(ready_root: Path, change: dict[str, Any], check_id: str,
                                                         status: Status) -> None:
    host = FakeHost()
    host.responses["info"] = result("info", out={**GOOD_INFO, **change})
    _, result_ = run_doctor(host, ready_root)
    assert check(result_, check_id).status is status and result_.overall is Overall.BLOCKED


def test_daemon_warnings_are_advisory(ready_root: Path) -> None:
    host = FakeHost()
    host.responses["info"] = result("info", out={**GOOD_INFO, "Warnings": ["WARNING: No swap limit support"]})
    facts, _ = run_doctor(host, ready_root)
    result_ = assess(as_pinned_python(facts))
    assert check(result_, "DKR-09").status is Status.WARN and result_.overall is Overall.READY


def test_info_failure_leaves_capabilities_unknown(ready_root: Path) -> None:
    host = FakeHost()
    host.responses["info"] = result("info", rc=1, err=b"permission denied")
    _, result_ = run_doctor(host, ready_root)
    assert {check(result_, i).status for i in ("DKR-05", "DKR-06", "DKR-07", "DKR-08")} == {Status.UNKNOWN}
    assert result_.overall is Overall.BLOCKED


# --- approved image -----------------------------------------------------------------


@pytest.mark.parametrize("image,expected", [
    (result("image-inspect", rc=1, err=b"No such image"), "not present locally"),
    (result("image-inspect", out=[{**GOOD_IMAGE[0], "Id": "sha256:" + "1" * 64}]), "sha256:" + "1" * 64),
    (result("image-inspect", out=[{**GOOD_IMAGE[0], "Architecture": "arm64"}]), "linux/arm64"),
])
def test_image_absent_or_different_blocks_and_is_never_pulled(ready_root: Path, image: CommandResult,
                                                               expected: str) -> None:
    host = FakeHost()
    host.responses["image-inspect"] = image
    _, result_ = run_doctor(host, ready_root)
    img = check(result_, "IMG-01")
    assert img.status is Status.FAIL and expected in img.observed and result_.overall is Overall.BLOCKED
    assert all(type(op) in env.READ_ONLY_DOCKER_OPS for op in host.calls)


def test_no_approved_image_identity_blocks_without_inspection(ready_root: Path,
                                                               monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(env, "APPROVED_PROBE_IMAGE_ID", None)
    host = FakeHost()
    _, result_ = run_doctor(host, ready_root)
    assert ImageInspect not in [type(op) for op in host.calls]
    assert check(result_, "IMG-01").status is Status.FAIL and "A2" in (check(result_, "IMG-01").action or "")


# --- evidence root: checked, never created ------------------------------------------


def test_missing_evidence_root_blocks_and_is_not_created(tmp_path: Path) -> None:
    root = tmp_path / "probe-runs"
    _, result_ = run_doctor(FakeHost(), root)
    assert check(result_, "EVD-01").status is Status.FAIL and not root.exists()


@pytest.mark.parametrize("mode", [0o755, 0o750, 0o777])
def test_evidence_root_with_loose_mode_blocks(tmp_path: Path, mode: int) -> None:
    root = tmp_path / "probe-runs"
    root.mkdir()
    os.chmod(root, mode)
    _, result_ = run_doctor(FakeHost(), root)
    assert check(result_, "EVD-01").status is Status.FAIL
    assert (root.stat().st_mode & 0o777) == mode  # doctor did not repair it


def test_symlinked_evidence_root_blocks(tmp_path: Path, ready_root: Path) -> None:
    link = tmp_path / "link"
    link.symlink_to(ready_root)
    _, result_ = run_doctor(FakeHost(), link)
    assert check(result_, "EVD-01").status is Status.FAIL


def test_evidence_root_is_the_fixed_platform_location_and_is_not_created(tmp_path: Path,
                                                                          monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    root = env.evidence_root()
    assert root == tmp_path / "Library" / "Application Support" / "PatchProof" / "probe-runs"
    assert not (tmp_path / "Library").exists()


# --- interpreter and tools ------------------------------------------------------------


@pytest.mark.parametrize("version,status,blocks", [
    ("3.13.16", Status.OK, False), ("3.13.1", Status.WARN, False), ("3.12.13", Status.FAIL, True),
])
def test_python_pin(ready_root: Path, version: str, status: Status, blocks: bool) -> None:
    facts, _ = run_doctor(FakeHost(), ready_root)
    facts = replace(as_pinned_python(facts), python=env.PythonFacts(version, "CPython", "/py", "/py"))
    assert check(assess(facts), "PY-01").status is status and check(assess(facts), "PY-01").blocks is blocks


def test_old_git_and_home_repository_are_advisories_not_v00_blockers(ready_root: Path) -> None:
    host = FakeHost()
    host.tools[Tool.GIT] = ("/usr/local/bin/git", result("git-version", out=b"git version 2.42.0\n"))
    facts, _ = run_doctor(host, ready_root)
    facts = replace(as_pinned_python(facts), host=replace(as_pinned_python(facts).host, home_git_repository=True))
    result_ = assess(facts)
    git = check(result_, "GIT-01")
    assert git.status is Status.WARN and "approval item 3" in (git.action or "")
    assert check(result_, "HOST-03").status is Status.WARN
    assert result_.overall is Overall.READY
    text = render_text(facts, result_)
    assert "Overall (v0.0 environment readiness): READY, 2 advisory warning(s) unresolved." in text
    assert "GIT-01" in text and "HOST-03" in text


def test_missing_tools_are_reported_not_invented(ready_root: Path) -> None:
    host = FakeHost()
    host.tools[Tool.GIT] = (None, result("git-version"))
    host.tools[Tool.UV] = ("/usr/local/bin/uv", result("uv-version", rc=1, err=b"broken"))
    facts, result_ = run_doctor(host, ready_root)
    assert facts.git.version_output is None and "not found" in (facts.git.error or "")
    assert facts.uv.version_output is None and "exit 1" in (facts.uv.error or "")
    assert check(result_, "GIT-01").status is Status.WARN and check(result_, "UV-01").status is Status.WARN


def test_pins_match_the_packaging_files() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert (ROOT / ".python-version").read_text().strip() == asm.SUPPORTED_PYTHON
    assert pyproject["tool"]["uv"]["required-version"] == "==" + asm.SUPPORTED_UV
    assert pyproject["project"]["requires-python"] == "==3.13.*"
    pins = pyproject["project"]["dependencies"] + pyproject["dependency-groups"]["dev"]
    assert all("==" in p for p in pins), pins


# --- the real executor refuses anything but read-only queries ---------------------------


@pytest.fixture
def no_processes(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    started: list[list[str]] = []

    def fake_run_bounded(argv: list[str], **kwargs: Any) -> CommandResult:
        started.append(list(argv))
        return result(kwargs.get("op_name", "x"))

    monkeypatch.setattr(env, "run_bounded", fake_run_bounded)
    return started


def _spec() -> Any:
    from patchproof.probes.catalogue import load_probe_script
    from patchproof.runner.policy import Ownership, Role, build_spec

    return build_spec(ownership=Ownership("inst-" + "0" * 32, "run-" + "0" * 32), role=Role.SLEEPER,
                      image=ImageId(APPROVED), script=load_probe_script(), args=("sleeper", "0" * 32))


@pytest.mark.parametrize("make_op", [
    lambda: Create(_spec()),
    lambda: Start(ContainerId("a" * 64)),
    lambda: Stop(ContainerId("a" * 64)),
    lambda: Remove(ContainerId("a" * 64)),
    lambda: ForceRemove(ContainerId("a" * 64)),
    lambda: SnapshotList("containers"),
    lambda: Inspect(ContainerRef("a" * 64)),
    lambda: Wait(ContainerId("a" * 64), 5.0),
    lambda: Logs(ContainerId("a" * 64)),
])
def test_read_only_host_refuses_every_runner_operation(no_processes: list[list[str]], make_op: Any) -> None:
    op = make_op()
    host = ReadOnlyHost(home=str(HOME), _docker="/usr/local/bin/docker")
    with pytest.raises(PolicyViolation):
        host.docker(op)
    assert no_processes == []


def test_read_only_host_argv_shapes(no_processes: list[list[str]]) -> None:
    host = ReadOnlyHost(home=str(HOME), _docker="/usr/local/bin/docker")
    for op in (ContextInspect(), Version(), DockerInfo(), ImageInspect(ImageId(APPROVED))):
        host.docker(op)
    host.tool_version(Tool.GIT, "/usr/local/bin/git")
    host.memory_bytes()
    assert no_processes == [
        ["/usr/local/bin/docker", "--context", "desktop-linux", "context", "inspect", "--", "desktop-linux"],
        ["/usr/local/bin/docker", "--context", "desktop-linux", "version", "--format", "{{json .}}"],
        ["/usr/local/bin/docker", "--context", "desktop-linux", "info", "--format", "{{json .}}"],
        ["/usr/local/bin/docker", "--context", "desktop-linux", "image", "inspect", "--", APPROVED],
        ["/usr/local/bin/git", "--version"],
        ["/usr/sbin/sysctl", "-n", "hw.memsize"],
    ]


@pytest.mark.parametrize("tool,path", [
    (Tool.GIT, "/tmp/git"), (Tool.GIT, "/usr/local/bin/uv"), (Tool.UV, "/Users/x/.local/bin/uv"),
])
def test_tools_outside_the_allowlist_are_refused(no_processes: list[list[str]], tool: Tool, path: str) -> None:
    with pytest.raises(PolicyViolation):
        ReadOnlyHost(home=str(HOME)).tool_version(tool, path)
    assert no_processes == []


def test_doctor_does_not_widen_the_probe_runner_allowlist() -> None:
    assert DockerInfo not in docker_cli.ALLOWED_OP_TYPES
    assert set(env.READ_ONLY_DOCKER_OPS) == {ContextInspect, Version, DockerInfo, ImageInspect}
