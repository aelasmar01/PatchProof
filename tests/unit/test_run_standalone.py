"""PP-008 gate C: the standalone verifier lifecycle (fake Docker) and the SYNTHETIC self-test pack.

The self-test pack's host run (pytest 8.4.2, subprocess) records the outcome set that the
in-image run (pytest 9.0.3, gate C step C1b) must reproduce. Nothing here contacts Docker.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

import pytest
from _run_fixtures import OWNERSHIP, VERIFIER_RECORD, FakeDocker, private
from test_run_plugin import identity, launch

from patchproof.core.approvals import ApprovalError, BindingInputs, ReviewDecision, create_approval
from patchproof.core.records.pack import CollectedTest
from patchproof.packs.collection import parse_collected, review_collection
from patchproof.packs.validation import PackError, load_selftest_pack, validate_pack
from patchproof.runner.cleanup import CleanupStatus, OwnershipRegistry
from patchproof.runner.collector import collect_stream
from patchproof.runner.docker_cli import Stop
from patchproof.runner.inputs import materialize_pack
from patchproof.runner.policy import CEILINGS, LimitClass, ResourceLimits
from patchproof.runner.run_policy import RunCreate, StartAttached, collect_command, verifier_command
from patchproof.runner.standalone import StandalonePlan, run_standalone

ROOT = Path(__file__).resolve().parents[2]
SELFTEST = Path(os.path.realpath(ROOT / "examples" / "packs" / "verifier-selftest"))
EXPECTED_SELFTEST = {
    "test_violation": ("COMPLETED", "VIOLATION_CONFIRMED", ()),
    "test_secure": ("COMPLETED", "SECURE", ()),
    "test_inconclusive": ("COMPLETED", "INCONCLUSIVE", ()),
    "test_generic_assertion": ("CALL_ERROR", "NONE",
                               ("GENERIC_FAILURE_IN_SECURITY_TEST", "MISSING_TERMINAL_OBSERVATION")),
    "test_suppressed": ("COMPLETED", "VIOLATION_CONFIRMED", ("SUPPRESSED_TERMINAL_EXCEPTION",)),
    "test_twice": ("CALL_ERROR", "SECURE", ()),
    "test_timeout": ("TIMED_OUT", "NONE", ("MISSING_TERMINAL_OBSERVATION",)),
    "test_pass": ("COMPLETED", "PASS", ()),
    "test_fail": ("COMPLETED", "FAIL", ()),
    "test_crash": ("CALL_ERROR", "NONE", ()),
    "test_skipped": ("SKIPPED", "NONE", ()),
}
# Call reports with outcome "failed". SEC-005 swallows its own terminal exception, so its call
# passes (recorded as SUPPRESSED_TERMINAL_EXCEPTION); FUN-011 is skipped, not failed.
EXPECTED_FAILED_CALLS = ("SEC-001", "SEC-004", "SEC-006", "SEC-007", "FUN-009", "FUN-010")


def failed_calls(stream: bytes) -> tuple[str, ...]:
    events = [json.loads(line) for line in stream.splitlines()]
    return tuple(e["payload"]["test_id"] for e in events
                 if e.get("type") == "test_report" and e["payload"]["outcome"] == "failed")


def limits(deadline: int) -> ResourceLimits:
    c = CEILINGS[LimitClass.VERIFIER]
    return ResourceLimits(nano_cpus=c.nano_cpus, memory_bytes=c.memory_bytes, pids=c.pids,
                          scratch_bytes=c.scratch_bytes, tmp_bytes=c.tmp_bytes, deadline_seconds=deadline)


@pytest.fixture
def snapshot(tmp_path: Path) -> Any:
    return materialize_pack(load_selftest_pack(SELFTEST), private(tmp_path / "store"))


def plan_for(snapshot: Any, command: tuple[str, ...], cap: int = 262144, deadline: int = 30) -> StandalonePlan:
    return StandalonePlan(ownership=OWNERSHIP, image=VERIFIER_RECORD, pack=snapshot, command=command,
                          limits=limits(deadline), output_cap_bytes=cap)


def collected_line(snapshot: Any) -> bytes:
    tests = [{"id": t.id, "nodeid": t.nodeid} for t in load_selftest_pack(SELFTEST).manifest.tests]
    return json.dumps({"tests": tests}, separators=(",", ":")).encode() + b"\n"


# ------------------------------------------------------------ the self-test pack


def test_selftest_pack_is_loadable_only_as_selftest_and_never_approvable(tmp_path: Path) -> None:
    pack = load_selftest_pack(SELFTEST)
    assert pack.manifest.pack_id == "verifier-selftest" and len(pack.manifest.tests) == 11
    with pytest.raises(PackError):
        validate_pack(SELFTEST)
    with pytest.raises(PackError, match="only the verifier self-test"):
        load_selftest_pack(Path(os.path.realpath(ROOT / "examples" / "packs" / "papertrail-document-access")))
    bindings = BindingInputs(pack_id="verifier-selftest", pack_version="1.0.0", manifest_sha256=pack.manifest_sha256,
                             pack_tree_sha256=pack.pack_tree_sha256,
                             collection=tuple(CollectedTest(id=t.id, nodeid=t.nodeid) for t in pack.manifest.tests),
                             verifier_image_id=VERIFIER_RECORD.image.value, verifier_plugin_version="0.1.0",
                             profile_id="example-profile", profile_sha256="sha256:" + "0" * 64).bindings()
    from datetime import UTC, datetime

    with pytest.raises(ApprovalError, match="never be approved"):
        create_approval(bindings, ReviewDecision("Synthetic Reviewer", "x", "x", "x"), supersedes=None,
                        now=datetime(2026, 10, 13, tzinfo=UTC))


def test_selftest_pack_on_host_pytest_gives_the_expected_outcomes(tmp_path: Path) -> None:
    """Baseline for gate C step C1b: the same pack under host pytest 8.4.2 (subprocess, synthetic)."""
    root = tmp_path / "pack"
    shutil.copytree(SELFTEST, root)
    tests = json.loads((root / "pack.json").read_text())["tests"]
    proc = launch(root, "run", "--pack", str(root), "--run", "run-" + "3" * 32, "--pair", "1", "--side", "baseline",
                  "--connect-timeout", "5", "--read-timeout", "5", "--", str(root / "tests" / "test_selftest.py"))
    result = collect_stream(proc.stdout, identity(root, tests), result_cap_bytes=1048576)
    assert result.status == "COMPLETE" and proc.returncode == 1
    assert {c.nodeid.split("::")[1]: (c.lifecycle_outcome, c.semantic_outcome, tuple(c.harness_errors))
            for c in result.cells} == EXPECTED_SELFTEST
    assert failed_calls(proc.stdout) == EXPECTED_FAILED_CALLS
    assert result.failed_reports == len(EXPECTED_FAILED_CALLS)  # nonzero, consistent with exit status 1


def test_selftest_collection_on_host_matches_the_manifest(tmp_path: Path) -> None:
    root = tmp_path / "pack"
    shutil.copytree(SELFTEST, root)
    proc = launch(root, "collect", "--pack", str(root), "--", str(root / "tests" / "test_selftest.py"))
    assert proc.returncode == 0
    manifest = load_selftest_pack(Path(os.path.realpath(root))).manifest.tests
    assert [c.id for c in review_collection(manifest, parse_collected(proc.stdout))] == [t.id for t in manifest]


# ------------------------------------------------------------ standalone lifecycle (fake Docker)


def test_standalone_collection_happy_path(snapshot: Any) -> None:
    docker = FakeDocker(streams={"baseline": collected_line(snapshot)})
    result = run_standalone(docker, plan_for(snapshot, collect_command(("/pack/tests/test_selftest.py",))),
                            OwnershipRegistry(OWNERSHIP))
    assert result.failure is None and result.gate is not None and result.gate.passed
    assert (result.termination, result.exit_code) == ("EXITED", 0)
    assert parse_collected(result.stdout)[0].id == "SEC-001"
    assert result.pack_verified_before and result.pack_verified_after
    assert [c.status for c in result.cleanup] == [CleanupStatus.REMOVED]
    creates = [op for op in docker.log if isinstance(op, RunCreate)]
    assert len(creates) == 1 and creates[0].spec.network.mode == "none"
    assert [op.op_name for op in docker.log].count("start-attached") == 1
    assert not any(op.op_name in ("start",) for op in docker.log)


def test_gate_failure_removes_the_container_unstarted(snapshot: Any) -> None:
    docker = FakeDocker()
    original = docker._inspect

    def bridged(cid: str) -> dict[str, Any]:
        obj = original(cid)
        obj["HostConfig"]["NetworkMode"] = "bridge"
        return obj

    docker._inspect = bridged  # type: ignore[method-assign]
    result = run_standalone(docker, plan_for(snapshot, collect_command(("/pack/tests/test_selftest.py",))),
                            OwnershipRegistry(OWNERSHIP))
    assert result.failure is not None and "policy gate" in result.failure
    assert not result.started and not any(isinstance(op, StartAttached) for op in docker.log)
    assert [c.status for c in result.cleanup] == [CleanupStatus.REMOVED]


def test_image_mismatch_creates_nothing(snapshot: Any) -> None:
    docker = FakeDocker(image_tamper=lambda o: o.update(Os="windows"))
    result = run_standalone(docker, plan_for(snapshot, collect_command(("/pack/tests/test_selftest.py",))),
                            OwnershipRegistry(OWNERSHIP))
    assert result.failure is not None and not any(isinstance(op, RunCreate) for op in docker.log)


def test_tampered_pack_creates_nothing(snapshot: Any) -> None:
    readme = snapshot.root / "README.md"
    os.chmod(snapshot.root, 0o755)
    os.chmod(readme, 0o644)
    readme.write_text("changed")
    os.chmod(readme, 0o444)
    os.chmod(snapshot.root, 0o555)
    docker = FakeDocker()
    result = run_standalone(docker, plan_for(snapshot, collect_command(("/pack/tests/test_selftest.py",))),
                            OwnershipRegistry(OWNERSHIP))
    assert result.failure is not None and "pack integrity" in result.failure
    assert not any(isinstance(op, RunCreate) for op in docker.log)


def test_deadline_stops_the_container(snapshot: Any) -> None:
    docker = FakeDocker(verifier_timeout=True)
    result = run_standalone(docker, plan_for(snapshot, verifier_command(
        run_id=OWNERSHIP.run_id, pair=1, side="baseline", test_paths=("/pack/tests/test_selftest.py",),
        connect_timeout=5, read_timeout=5), cap=10485760, deadline=120), OwnershipRegistry(OWNERSHIP))
    assert result.failure == "deadline exceeded" and result.termination == "SIGNALED"
    assert any(isinstance(op, Stop) for op in docker.log)


def test_output_over_the_cap_is_a_failure(snapshot: Any) -> None:
    docker = FakeDocker(verifier_truncated=True, streams={"baseline": b"x" * 300000})
    result = run_standalone(docker, plan_for(snapshot, collect_command(("/pack/tests/test_selftest.py",))),
                            OwnershipRegistry(OWNERSHIP))
    assert result.failure == "output exceeded the cap"


def test_cleanup_refuses_a_container_whose_labels_changed(snapshot: Any) -> None:
    docker = FakeDocker(streams={"baseline": collected_line(snapshot)})
    original = docker._inspect

    def foreign(cid: str) -> dict[str, Any]:
        obj = original(cid)
        if cid in docker.started:
            obj["Config"]["Labels"] = {"com.example.owner": "someone-else"}
        return obj

    docker._inspect = foreign  # type: ignore[method-assign]
    result = run_standalone(docker, plan_for(snapshot, collect_command(("/pack/tests/test_selftest.py",))),
                            OwnershipRegistry(OWNERSHIP))
    assert [c.status for c in result.cleanup] == [CleanupStatus.REFUSED]
    assert docker.removed == []


# ------------------------------------------------------------ gate C C1b adjudication (2026-10-13)


def test_fake_event_write_executes_but_never_enters_the_event_channel(tmp_path: Path) -> None:
    """The invariant behind C1b: test-authored fake events never reach the trusted channel.

    Under the approved configuration, pytest captures a passing test's output and discards it,
    so nothing is required to appear on stderr. To prove that the fake-event write in
    `test_secure` really executes, this host-only run disables capture (`-s`) through a copy of
    the approved ini. The write then surfaces on stderr, the launcher's descriptor 1, and the
    event channel is still exactly the plugin's events. The self-test pack bytes are unchanged.
    """
    import subprocess
    import sys

    from test_run_plugin import INI

    root = tmp_path / "pack"
    shutil.copytree(SELFTEST, root)
    tests = json.loads((root / "pack.json").read_text())["tests"]
    ini = tmp_path / "pytest-nocapture.ini"
    ini.write_text(INI.read_text().replace("    --noconftest\n", "    --noconftest\n    -s\n"))
    assert "-s" in ini.read_text().split() and "-s" not in INI.read_text().split()
    argv = ["run", "--pack", str(root), "--run", "run-" + "3" * 32, "--pair", "1", "--side", "baseline",
            "--connect-timeout", "5", "--read-timeout", "5", "--", str(root / "tests" / "test_selftest.py")]
    env = {"PATH": "/usr/bin:/bin", "HOME": str(root), "LC_ALL": "C.UTF-8", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
           "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": str(ROOT / "verifier")}

    def run(ini_path: Path) -> subprocess.CompletedProcess[bytes]:
        code = ("import sys\nfrom patchproof_verifier import launch\n"
                f"raise SystemExit(launch.main(sys.argv[1:], ini={str(ini_path)!r}))")
        return subprocess.run([sys.executable, "-B", "-c", code, *argv], cwd=root, env=env, capture_output=True,
                              timeout=120, check=False)

    uncaptured, captured = run(ini), run(INI)
    # The write executes: with capture off it surfaces on descriptor 1, which the launcher points at stderr.
    assert b'{"forged":"event on fd 1"}' in uncaptured.stderr and b"captured print" in uncaptured.stderr
    # Approved configuration: a passing test's captured output is discarded (not required on stderr).
    assert b"forged" not in captured.stderr
    for proc in (uncaptured, captured):
        assert b"forged" not in proc.stdout and b"captured print" not in proc.stdout
        events = [json.loads(line) for line in proc.stdout.splitlines()]
        assert all(set(e) <= {"seq", "type", "payload", "run_id", "pair", "side", "schema_version"} for e in events)
        result = collect_stream(proc.stdout, identity(root, tests), result_cap_bytes=1048576)
        assert result.status == "COMPLETE" and len(events) == result.events_received == 41
        assert {c.nodeid.split("::")[1]: (c.lifecycle_outcome, c.semantic_outcome, tuple(c.harness_errors))
                for c in result.cells} == EXPECTED_SELFTEST
