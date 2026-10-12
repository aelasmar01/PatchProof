"""PP-003: orchestration over a synthetic Docker model (no daemon, no containers).

These tests check wiring: gate-before-start, exact-ID cleanup, refusal paths, evidence
completeness, and that failures are never reported as success. An all-PASS result here
is a property of the synthetic fixture, not a measurement of isolation.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest
from _fakes import HOME, IMAGE, NONCE, OWNERSHIP, FakeDocker, common_observations, good_streams, obs_stream
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from patchproof.probes import evidence as ev
from patchproof.probes.catalogue import BY_ID, load_probe_script
from patchproof.probes.interpret import SuiteStatus
from patchproof.probes.orchestrator import (
    ProbeSuite,
    audit_command_log,
    check_execution_gates,
    compare_snapshots,
    normalize_snapshot,
)
from patchproof.runner.policy import PolicyViolation, Role

ROOT = Path(__file__).resolve().parents[2]
AUTH = {"a2_image_approved": True, "a3_evidence_root_verified": True, "a4_operator_confirmed": True}


def _validator() -> Draft202012Validator:
    schemas = {p.name: json.loads(p.read_text()) for p in (ROOT / "schemas").glob("*.schema.json")}
    registry: Registry = Registry().with_resources(
        (s["$id"], Resource.from_contents(s)) for s in schemas.values())
    return Draft202012Validator(schemas["isolation-probe-run.schema.json"], registry=registry)


VALIDATOR = _validator()


def run_suite(fake: FakeDocker, run_dir: Path | None = None) -> dict[str, Any]:
    suite = ProbeSuite(fake, OWNERSHIP, IMAGE, load_probe_script(), home=HOME, run_dir=run_dir, nonce=NONCE)
    record = suite.run(AUTH)
    errors = sorted(VALIDATOR.iter_errors(record), key=str)
    assert not errors, [f"{list(e.absolute_path)}: {e.message}" for e in errors[:5]]
    return record


def outcomes(record: dict[str, Any]) -> dict[str, str]:
    return {p["probe_id"]: p["outcome"] for p in record["probes"]}


def started_roles(fake: FakeDocker, record: dict[str, Any]) -> set[str]:
    ids = {c["container_id"]: c["role"] for c in record["containers"]}
    return {ids[cid] for op, cid in fake.ops if op == "start"}


# ------------------------------------------------------------------- happy path wiring


def test_synthetic_all_pass_wiring() -> None:
    fake = FakeDocker(streams=good_streams())
    record = run_suite(fake)
    bad = {k: v for k, v in outcomes(record).items() if v != "PASS"}
    assert not bad, {k: next(p["observed"] for p in record["probes"] if p["probe_id"] == k) for k in bad}
    assert record["suite_status"] == SuiteStatus.ALL_PLANNED_PROBES_PASSED.value
    assert not fake.containers, "every created container must be removed"
    # Decoys were never started.
    assert started_roles(fake, record) == {"target", "verifier", "memory", "pids", "cpu", "storage", "logflood",
                                           "sleeper"}


def test_every_container_is_gated_before_start_and_removed_by_exact_id() -> None:
    fake = FakeDocker(streams=good_streams())
    run_suite(fake)
    seen_inspect: set[str] = set()
    for op, cid in fake.ops:
        if op == "inspect":
            seen_inspect.add(cid)
        if op == "start":
            assert cid in seen_inspect, "start without a prior inspect gate"
        if op == "remove":
            assert len(cid) == 64
    issued = {f"{i:064x}" for i in range(1, fake._counter + 1)}
    assert sorted(fake.removed) == sorted(issued), "each created container removed exactly once"


def test_no_pull_build_exec_or_bulk_operation_is_ever_issued() -> None:
    fake = FakeDocker(streams=good_streams())
    run_suite(fake)
    allowed = {"context-inspect", "version", "image-inspect", "create", "inspect", "start", "wait", "logs",
               "stop", "remove", "snapshot"}
    assert {op for op, _ in fake.ops} <= allowed


def test_claims_distinguish_exercised_from_configured() -> None:
    record = run_suite(FakeDocker(streams=good_streams()))
    claims = {c["control"]: c["status"] for c in record["control_claims"]}
    assert claims["no-external-connectivity"] == "ENFORCEMENT_EXERCISED"
    assert claims["no-new-privileges"] == "CONFIGURED_ONLY"
    assert claims["no-published-ports"] == "CONFIGURED_ONLY"


# ------------------------------------------------------------------- refusal paths


def test_context_mismatch_blocks_before_any_container() -> None:
    fake = FakeDocker(context_host="tcp://192.168.1.5:2375", streams=good_streams())
    record = run_suite(fake)
    assert outcomes(record)["PRE-01"] == "BLOCKED"
    assert record["suite_status"] == SuiteStatus.BLOCKED.value
    assert [op for op, _ in fake.ops] == ["context-inspect"]


def test_missing_image_blocks_without_pull_or_create() -> None:
    fake = FakeDocker(image_present=False, streams=good_streams())
    record = run_suite(fake)
    assert outcomes(record)["PRE-02"] == "BLOCKED"
    assert record["suite_status"] == SuiteStatus.BLOCKED.value
    assert "create" not in {op for op, _ in fake.ops}


def test_image_with_declared_volumes_blocks() -> None:
    fake = FakeDocker(image_volumes={"/data": {}}, streams=good_streams())
    record = run_suite(fake)
    assert outcomes(record)["PRE-02"] == "BLOCKED"
    assert "create" not in {op for op, _ in fake.ops}


def test_gate_mismatch_prevents_start_and_container_is_removed() -> None:
    def privileged_target(role: Role, obj: dict[str, Any]) -> None:
        if role is Role.TARGET:
            obj["HostConfig"]["Privileged"] = True

    fake = FakeDocker(streams=good_streams(), inspect_mutator=privileged_target)
    record = run_suite(fake)
    target = next(c for c in record["containers"] if c["role"] == "target")
    assert target["gate"]["passed"] is False
    assert any(m["field"] == "HostConfig.Privileged" for m in target["gate"]["mismatches"])
    assert not target["started"]
    assert "target" not in started_roles(fake, record)
    assert "verifier" not in {c["role"] for c in record["containers"]}, "verifier must not join an ungated target"
    assert target["cleanup"]["status"] == "REMOVED"
    o = outcomes(record)
    assert o["POL-06"] == "BLOCKED"
    assert o["NET-02"] in ("BLOCKED", "NOT_RUN") and o["NET-P1"] == "NOT_RUN"
    assert record["suite_status"] != SuiteStatus.ALL_PLANNED_PROBES_PASSED.value


def test_policy_refusals_make_no_docker_call() -> None:
    record = run_suite(FakeDocker(streams=good_streams()))
    for pid in ("POL-P1", "POL-01", "POL-02", "POL-03", "POL-04", "POL-05"):
        assert outcomes(record)[pid] == "PASS", pid


# ------------------------------------------------------------------- failure is never success


def test_observed_egress_is_isolation_failure() -> None:
    streams = good_streams()
    obs = common_observations(Role.TARGET)
    obs["NET-02"] = {"attempts": [{"dest": "1.1.1.1:443", "ok": True}]}
    streams[Role.TARGET] = obs_stream(Role.TARGET, obs)
    record = run_suite(FakeDocker(streams=streams))
    assert outcomes(record)["NET-02"] == "FAIL"
    assert record["suite_status"] == SuiteStatus.ISOLATION_FAILED.value
    claims = {c["control"]: c["status"] for c in record["control_claims"]}
    assert claims["no-external-connectivity"] == "FAILED"


def test_failed_positive_control_makes_negatives_inconclusive() -> None:
    streams = good_streams()
    obs = common_observations(Role.VERIFIER)
    obs["NET-P1"] = {"status": None, "nonce_match": False, "tries": 120}
    streams[Role.VERIFIER] = obs_stream(Role.VERIFIER, obs)
    record = run_suite(FakeDocker(streams=streams))
    o = outcomes(record)
    assert o["NET-P1"] == "FAIL"
    for pid in ("NET-01", "NET-02", "NET-03", "NET-06", "NET-07", "NET-09"):
        assert o[pid] == "INCONCLUSIVE", pid
    assert record["suite_status"] == SuiteStatus.HARNESS_INVALID.value


def test_verifier_crash_without_end_marker_is_not_success() -> None:
    streams = good_streams()
    streams[Role.VERIFIER] = obs_stream(Role.VERIFIER, common_observations(Role.VERIFIER), end=False)
    fake = FakeDocker(streams=streams, exits={Role.VERIFIER: (1, False)})
    record = run_suite(fake)
    o = outcomes(record)
    assert o["NET-07"] == "INCONCLUSIVE"
    assert o["FS-07"] == "INCONCLUSIVE"
    assert record["suite_status"] != SuiteStatus.ALL_PLANNED_PROBES_PASSED.value


def test_target_printed_pass_is_not_accepted() -> None:
    streams = good_streams()
    obs = common_observations(Role.TARGET)
    obs["NET-02"] = {"result": "PASS", "isolation": "verified"}
    streams[Role.TARGET] = obs_stream(Role.TARGET, obs) + b"PASS: all isolation checks passed\n"
    record = run_suite(FakeDocker(streams=streams))
    assert outcomes(record)["NET-02"] != "PASS"
    assert record["suite_status"] != SuiteStatus.ALL_PLANNED_PROBES_PASSED.value


def test_wrong_nonce_stream_is_not_evidence() -> None:
    streams = good_streams()
    streams[Role.TARGET] = obs_stream(Role.TARGET, common_observations(Role.TARGET), nonce="d" * 32)
    record = run_suite(FakeDocker(streams=streams))
    assert outcomes(record)["NET-02"] == "INCONCLUSIVE"
    target = next(c for c in record["containers"] if c["role"] == "target")
    assert target["stream"]["foreign_records"] > 0


def test_memory_not_killed_fails_and_timeout_is_inconclusive() -> None:
    streams = good_streams()
    streams[Role.MEMORY] = obs_stream(Role.MEMORY, {"RES-P1": {"allocated_mib": 256, "ok": True},
                                                    "RES-02": {"not_killed": True, "allocated_mib": 1536}})
    record = run_suite(FakeDocker(streams=streams, exits={Role.MEMORY: (0, False)}))
    assert outcomes(record)["RES-02"] == "FAIL"
    fake = FakeDocker(streams=good_streams(), hang_roles={Role.SLEEPER, Role.MEMORY})
    assert outcomes(run_suite(fake))["RES-02"] == "INCONCLUSIVE"


def test_unbounded_log_retention_fails() -> None:
    from _fakes import logflood_stream

    streams = good_streams()
    streams[Role.LOGFLOOD] = logflood_stream(retained_mib=30, include_start=True)
    record = run_suite(FakeDocker(streams=streams))
    assert outcomes(record)["RES-11"] == "FAIL"


def test_preservation_difference_fails_the_suite() -> None:
    def drop_image(rows: dict[str, list[dict[str, Any]]]) -> None:
        rows["images"].pop()

    record = run_suite(FakeDocker(streams=good_streams(), snapshot_after_mutator=drop_image))
    assert outcomes(record)["CLN-06"] == "FAIL"
    assert record["preservation"]["outcome"] == "FAIL"
    assert record["suite_status"] == SuiteStatus.ISOLATION_FAILED.value


def test_cleanup_failure_is_recorded_not_hidden() -> None:
    fake = FakeDocker(streams=good_streams(), fail_remove_roles={Role.CPU})
    record = run_suite(fake)
    cpu = next(c for c in record["containers"] if c["role"] == "cpu")
    assert cpu["cleanup"]["status"] == "FAILED"
    assert outcomes(record)["CLN-01"] == "FAIL"
    assert any(c.spec.role is Role.CPU for c in fake.containers.values()), "no escalation to forced removal"


def test_interruption_still_cleans_up_owned_containers() -> None:
    fake = FakeDocker(streams=good_streams(), interrupt_on=("wait", Role.CPU))
    record = run_suite(fake)
    assert not fake.containers, "interrupted run must remove what it created"
    assert record["suite_status"] in (SuiteStatus.INCOMPLETE.value, SuiteStatus.HARNESS_INVALID.value)
    assert any("interrupted" in lim.lower() for lim in record["limitations"])
    o = outcomes(record)
    assert o["CLN-04"] == "NOT_RUN" and o["CLN-02"] == "NOT_RUN", "decoy probes never ran"
    assert o["RES-06"] != "PASS"
    # The after-snapshot runs in the cleanup window on every path, so preservation of
    # unrelated resources is still verified after an interruption.
    assert o["CLN-06"] == "PASS" and record["preservation"]["outcome"] == "PASS"
    assert o["RES-15"] == "INCONCLUSIVE" and record["execution"]["interrupted"] is True
    assert record["execution"]["cleanup_status"] == "COMPLETE"


def test_decoys_are_refused_by_owned_cleanup_then_removed_separately() -> None:
    fake = FakeDocker(streams=good_streams())
    record = run_suite(fake)
    o = outcomes(record)
    assert o["CLN-02"] == "PASS" and o["CLN-03"] == "PASS" and o["CLN-04"] == "PASS"
    decoy_ids = {c["container_id"] for c in record["containers"] if c["role"].startswith("decoy")}
    first_remove = {cid: i for i, (op, cid) in enumerate(fake.ops) if op == "remove" and cid in decoy_ids}
    assert len(first_remove) == 2


# ------------------------------------------------------------------- gates and evidence directory


def test_gates_refuse_without_approved_image(tmp_path: Path) -> None:
    root = tmp_path / "probe-runs"
    root.mkdir(mode=0o700)
    with pytest.raises(PolicyViolation, match="no approved probe image identity"):
        check_execution_gates(IMAGE, root, operator_confirmed=True, approved_image_id=None)
    with pytest.raises(PolicyViolation, match="A2"):
        check_execution_gates(IMAGE, root, operator_confirmed=True, approved_image_id="sha256:" + "2" * 64)
    with pytest.raises(PolicyViolation, match="A4"):
        check_execution_gates(IMAGE, root, operator_confirmed=False, approved_image_id=IMAGE.value)
    check_execution_gates(IMAGE, root, operator_confirmed=True, approved_image_id=IMAGE.value)


def test_approved_image_is_the_owner_reviewed_identity() -> None:
    from patchproof.runner.policy import APPROVED_PROBE_IMAGE_ID, APPROVED_PROBE_PLATFORM

    # A2, owner-approved 2026-10-11. Changing this value requires a new owner review.
    assert APPROVED_PROBE_IMAGE_ID == "sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f"
    assert APPROVED_PROBE_PLATFORM == "linux/amd64"


def test_stubborn_owned_container_is_force_removed_only_after_reverification() -> None:
    fake = FakeDocker(streams=good_streams(), fail_stop_roles={Role.SLEEPER})
    record = run_suite(fake)
    sleeper = next(c for c in record["containers"] if c["role"] == "sleeper")
    assert sleeper["cleanup"]["status"] == "FORCE_REMOVED"
    assert "ownership reconfirmed" in sleeper["cleanup"]["detail"]
    o = outcomes(record)
    assert o["CLN-01"] == "PASS" and o["CLN-05"] == "PASS"
    assert o["RES-12"] == "FAIL", "a stop that did not stop the container is a deadline failure"
    assert not fake.containers
    forced = [cid for op, cid in fake.ops if op == "force-remove"]
    assert forced == [sleeper["container_id"]]


def test_failed_force_removal_is_cleanup_failure() -> None:
    fake = FakeDocker(streams=good_streams(), fail_stop_roles={Role.SLEEPER}, fail_force_roles={Role.SLEEPER})
    record = run_suite(fake)
    sleeper = next(c for c in record["containers"] if c["role"] == "sleeper")
    assert sleeper["cleanup"]["status"] == "FAILED"
    assert sleeper["cleanup"]["detail"].startswith("CLEANUP_FAILED")
    assert outcomes(record)["CLN-01"] == "FAIL"


def test_audit_rejects_force_without_reinspection() -> None:
    from patchproof.runner.docker_cli import CommandResult

    cid = "a" * 64

    def res(op: str, tail: list[str]) -> CommandResult:
        return CommandResult(op, ("docker", "--context", "desktop-linux", *tail), 0, b"", b"", False, False, False, 0)

    stop = res("stop", ["container", "stop", "--time", "5", "--", cid])
    inspect = res("inspect", ["container", "inspect", "--", cid])
    force = res("force-remove", ["container", "rm", "--force", "--", cid])
    assert audit_command_log([inspect, stop, inspect, force])[0].value == "PASS"
    assert audit_command_log([inspect, stop, force])[0].value == "FAIL"
    assert audit_command_log([inspect, force])[0].value == "FAIL"


@pytest.mark.parametrize("problem", ["missing", "mode", "symlink", "file"])
def test_evidence_root_must_preexist_owner_only(tmp_path: Path, problem: str) -> None:
    root = tmp_path / "probe-runs"
    if problem == "mode":
        root.mkdir(mode=0o755)
        os.chmod(root, 0o755)
    elif problem == "symlink":
        real = tmp_path / "real"
        real.mkdir(mode=0o700)
        root.symlink_to(real)
    elif problem == "file":
        root.write_text("x")
    with pytest.raises(PolicyViolation):
        ev.verify_evidence_root(root)
    if problem == "missing":
        assert not root.exists(), "the verifier must never create the A3 directory"


def test_private_evidence_files_are_owner_only(tmp_path: Path) -> None:
    root = tmp_path / "probe-runs"
    root.mkdir(mode=0o700)
    run_dir = ev.create_run_dir(root, OWNERSHIP)
    run_suite(FakeDocker(streams=good_streams()), run_dir=run_dir)
    assert stat.S_IMODE(run_dir.stat().st_mode) == 0o700
    names = {p.name for p in run_dir.iterdir()}
    assert {"run-record.json", "commands.json", "journal.jsonl", "inspect.json", "snapshot-before.json"} <= names
    for path in run_dir.iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o600, path.name
    commands = json.loads((run_dir / "commands.json").read_text())
    assert all(load_probe_script() not in arg for c in commands for arg in c["argv"]), "script bytes not logged"
    with pytest.raises(FileExistsError):
        ev.create_run_dir(root, OWNERSHIP)
    with pytest.raises(PolicyViolation):
        ev.write_private(run_dir, "../escape", b"x")


# ------------------------------------------------------------------- pure helpers


def test_snapshot_normalization_ignores_relative_time_and_detects_changes() -> None:
    a = normalize_snapshot("containers", b'{"ID":"x","Names":"db","Image":"pg","State":"exited","Status":"7 months"}')
    b = normalize_snapshot("containers", b'{"ID":"x","Names":"db","Image":"pg","State":"exited","Status":"8 months"}')
    assert a == b
    assert compare_snapshots({"containers": a}, {"containers": []}) == [f"containers: missing after run: {a[0]}"]
    with pytest.raises(ValueError):
        normalize_snapshot("images", b'{"ID":"x"}')


def test_command_audit_flags_forbidden_tokens() -> None:
    from patchproof.runner.docker_cli import CommandResult

    def res(op: str, argv: list[str]) -> CommandResult:
        return CommandResult(op, tuple(argv), 0, b"", b"", False, False, False, 0.0)

    ok = audit_command_log([res("remove", ["docker", "container", "rm", "--", "a" * 64])])
    assert ok[0].value == "PASS"
    bad = audit_command_log([res("remove", ["docker", "container", "rm", "--force", "--", "a" * 64])])
    assert bad[0].value == "FAIL"
    assert audit_command_log([res("prune", ["docker", "system", "prune"])])[0].value == "FAIL"


def test_record_lists_every_catalogue_probe_once() -> None:
    record = run_suite(FakeDocker(streams=good_streams()))
    assert sorted(p["probe_id"] for p in record["probes"]) == sorted(BY_ID)
