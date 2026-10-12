"""v0.0 closeout C2/C3: the `patchproof` CLI (Docker-free; SYNTHETIC runner outcomes).

`doctor --probe-isolation` must reach the accepted PP-003 `run` path with the approved
image and the fixed evidence directory, and nothing else. These tests drive that real
path (A2/A3 gate checks and the A4 interactive confirmation are the runner's own code)
with a synthetic ProbeSuite in place of Docker, so no process is started.
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from patchproof.cli import main as cli_main
from patchproof.doctor import environment as env
from patchproof.probes import cli as probe_cli
from patchproof.probes.interpret import SuiteStatus
from patchproof.runner.policy import APPROVED_PROBE_IMAGE_ID

RUNNER = CliRunner()
APPROVED = APPROVED_PROBE_IMAGE_ID or ""


def invoke(*args: str) -> Any:
    return RUNNER.invoke(cli_main.app, list(args), prog_name="patchproof")


# --- read-only doctor ------------------------------------------------------------------


def _facts(root: Path) -> env.EnvironmentFacts:
    from test_doctor import FakeHost, as_pinned_python  # synthetic host shared with the doctor tests

    return as_pinned_python(env.collect(FakeHost(), Path("/Users/synthetic"), root))


@pytest.fixture
def ready_root(tmp_path: Path) -> Path:
    root = tmp_path / "probe-runs"
    root.mkdir()
    os.chmod(root, 0o700)
    return root


def test_doctor_ready_exits_0_and_prints_the_report(monkeypatch: pytest.MonkeyPatch, ready_root: Path) -> None:
    monkeypatch.setattr(cli_main, "collect", lambda *a: _facts(ready_root))
    res = invoke("doctor")
    assert res.exit_code == 0, res.output
    assert "Overall (v0.0 environment readiness): READY" in res.output and "NOT VERIFIED by doctor" in res.output


def test_doctor_blocked_exits_21(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cli_main, "collect", lambda *a: _facts(tmp_path / "missing"))
    res = invoke("doctor")
    assert res.exit_code == 21 and "EVD-01" in res.output
    assert "Overall (v0.0 environment readiness): BLOCKED" in res.output


def test_doctor_json_separates_observed_checks_and_assumptions(monkeypatch: pytest.MonkeyPatch,
                                                                ready_root: Path) -> None:
    monkeypatch.setattr(cli_main, "collect", lambda *a: _facts(ready_root))
    res = invoke("doctor", "--json")
    doc = json.loads(res.output)
    assert res.exit_code == 0 and doc["overall"] == "READY" and doc["isolation_verified_by_doctor"] is False
    assert doc["assumptions"] and doc["observed"]["docker"]["server_version"] == "29.8.2"


def test_doctor_does_not_invoke_the_probe_runner(monkeypatch: pytest.MonkeyPatch, ready_root: Path) -> None:
    monkeypatch.setattr(cli_main, "collect", lambda *a: _facts(ready_root))
    monkeypatch.setattr(probe_cli, "main", lambda argv: pytest.fail("read-only doctor reached the probe runner"))
    assert invoke("doctor").exit_code == 0


def test_doctor_uses_the_real_read_only_host_and_fixed_evidence_root(monkeypatch: pytest.MonkeyPatch,
                                                                     tmp_path: Path) -> None:
    seen: dict[str, Any] = {}

    def fake_collect(queries: Any, home: Path, root: Path) -> env.EnvironmentFacts:
        seen.update(queries=queries, home=home, root=root)
        return _facts(root)

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(cli_main, "collect", fake_collect)
    invoke("doctor")
    assert isinstance(seen["queries"], env.ReadOnlyHost)
    assert seen["root"] == tmp_path / "Library" / "Application Support" / "PatchProof" / "probe-runs"


# --- --probe-isolation: argument surface ----------------------------------------------


@pytest.mark.parametrize("extra", [
    ["--image-id", "sha256:" + "1" * 64], ["--evidence-root", "/tmp/x"], ["--privileged"], ["--yes"],
    ["--platform", "linux/arm64"], ["--json"],
])
def test_probe_isolation_accepts_no_overrides(monkeypatch: pytest.MonkeyPatch, extra: list[str]) -> None:
    monkeypatch.setattr(probe_cli, "main", lambda argv: pytest.fail("runner reached with an override"))
    res = invoke("doctor", "--probe-isolation", *extra)
    assert res.exit_code == 2


def test_probe_isolation_passes_only_the_approved_image_and_fixed_root(monkeypatch: pytest.MonkeyPatch,
                                                                       tmp_path: Path) -> None:
    seen: list[list[str]] = []
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(probe_cli, "main", lambda argv: seen.append(argv) or 0)
    res = invoke("doctor", "--probe-isolation")
    assert res.exit_code == 0
    assert seen == [["run", "--image-id", APPROVED, "--evidence-root",
                     str(tmp_path / "Library" / "Application Support" / "PatchProof" / "probe-runs")]]
    assert "ACTIVE DOCKER OPERATION" in res.output and "separate owner execution authorization" in res.output


@pytest.mark.parametrize("code", [0, 1, 20, 21])
def test_probe_isolation_returns_the_runner_exit_code_unchanged(monkeypatch: pytest.MonkeyPatch, code: int) -> None:
    monkeypatch.setattr(probe_cli, "main", lambda argv: code)
    assert invoke("doctor", "--probe-isolation").exit_code == code


def test_probe_isolation_without_approved_image_refuses_before_the_runner(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_main, "APPROVED_PROBE_IMAGE_ID", None)
    monkeypatch.setattr(probe_cli, "main", lambda argv: pytest.fail("runner reached without A2"))
    res = invoke("doctor", "--probe-isolation")
    assert res.exit_code == 21 and "A2 not satisfied" in res.output


# --- --probe-isolation through the real PP-003 run path (synthetic suite) -------------


class SyntheticSuite:
    """Stands in for ProbeSuite; returns a synthetic record. Never touches Docker."""

    created: list[dict[str, Any]] = []
    status = SuiteStatus.ALL_PLANNED_PROBES_PASSED

    def __init__(self, executor: Any, ownership: Any, image: Any, script: str, *, home: str, run_dir: Path) -> None:
        SyntheticSuite.created.append({"image": image.value, "run_dir": run_dir, "executor": executor})

    def run(self, authorizations: dict[str, bool]) -> dict[str, Any]:
        assert authorizations == {"a2_image_approved": True, "a3_evidence_root_verified": True,
                                  "a4_operator_confirmed": True}
        return {"suite_status": SyntheticSuite.status.value,
                "execution": {"active_elapsed_seconds": 1.0, "global_deadline_seconds": 600.0,
                              "deadline_expired": False, "cleanup_status": "COMPLETE"},
                "probes": [{"probe_id": "SYN-01", "outcome": "PASS", "observed": "synthetic"}]}


class TtyInput(io.StringIO):
    def isatty(self) -> bool:
        return True


@pytest.fixture
def real_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """HOME with a ready A3 directory; Docker client and suite replaced by synthetic ones."""
    monkeypatch.setenv("HOME", str(tmp_path))
    root = env.evidence_root()
    root.mkdir(parents=True)
    os.chmod(root, 0o700)
    SyntheticSuite.created = []
    monkeypatch.setattr(probe_cli, "ProbeSuite", SyntheticSuite)
    monkeypatch.setattr(probe_cli, "resolve_docker_binary", lambda: "/usr/local/bin/docker")
    monkeypatch.setattr(probe_cli.secrets, "token_hex", lambda n: "ab" * n)
    return root


def run_wrapper(monkeypatch: pytest.MonkeyPatch, stdin: io.StringIO) -> int:
    monkeypatch.setattr("sys.stdin", stdin)
    return cli_main.run_probe_isolation()


def test_non_interactive_stdin_is_refused_and_nothing_is_written(monkeypatch: pytest.MonkeyPatch,
                                                                 real_path: Path) -> None:
    code = run_wrapper(monkeypatch, io.StringIO("run abababababab\n"))  # correct phrase, but not a TTY
    assert code == probe_cli.EXIT_BLOCKED
    assert SyntheticSuite.created == [] and list(real_path.iterdir()) == []


def test_wrong_confirmation_phrase_is_refused_and_nothing_is_written(monkeypatch: pytest.MonkeyPatch,
                                                                     real_path: Path) -> None:
    code = run_wrapper(monkeypatch, TtyInput("yes\n"))
    assert code == probe_cli.EXIT_BLOCKED
    assert SyntheticSuite.created == [] and list(real_path.iterdir()) == []


def test_unready_evidence_root_is_refused_before_confirmation(monkeypatch: pytest.MonkeyPatch,
                                                              real_path: Path) -> None:
    os.chmod(real_path, 0o755)
    stdin = TtyInput("run abababababab\n")
    code = run_wrapper(monkeypatch, stdin)
    assert code == probe_cli.EXIT_BLOCKED and stdin.tell() == 0  # A3 refused before A4 was asked
    assert SyntheticSuite.created == []


@pytest.mark.parametrize("status,code", [
    (SuiteStatus.ALL_PLANNED_PROBES_PASSED, 0),
    (SuiteStatus.ISOLATION_FAILED, 1),
    (SuiteStatus.BLOCKED, 21),
    *[(s, 20) for s in SuiteStatus if s not in (SuiteStatus.ALL_PLANNED_PROBES_PASSED, SuiteStatus.ISOLATION_FAILED,
                                                 SuiteStatus.BLOCKED)],
])
def test_confirmed_run_uses_the_approved_image_and_a_private_run_directory(
        monkeypatch: pytest.MonkeyPatch, real_path: Path, status: SuiteStatus, code: int) -> None:
    monkeypatch.setattr(SyntheticSuite, "status", status)
    assert run_wrapper(monkeypatch, TtyInput("run abababababab\n")) == code
    [created] = SyntheticSuite.created
    assert created["image"] == APPROVED
    assert created["run_dir"] == real_path / ("run-" + "ab" * 16)
    assert (created["run_dir"].stat().st_mode & 0o777) == 0o700
    assert isinstance(created["executor"], probe_cli.DockerCli)
    assert created["executor"].docker_binary == "/usr/local/bin/docker"


def test_wrapper_adds_nothing_to_the_runner_module() -> None:
    """The runner's own gate and confirmation functions are the ones the wrapper reaches."""
    assert cli_main.probe_cli is probe_cli
    source = Path(cli_main.__file__).read_text()
    for forbidden in ("subprocess", "DockerCli", "build_spec", "ProbeSuite", "check_execution_gates", "shell=True"):
        assert forbidden not in source, forbidden
