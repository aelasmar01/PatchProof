"""PP-003 / 10.6: removal is exact-ID and ownership-checked; refusals leave containers in place."""

from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any

import pytest
from _fakes import IMAGE, OWNERSHIP, FakeDocker

from patchproof.runner import cleanup as cl
from patchproof.runner.docker_cli import Create
from patchproof.runner.policy import ContainerId, Ownership, PolicyViolation, Role, build_spec

NONCE = "c" * 32


def create(fake: FakeDocker, registry: cl.OwnershipRegistry, role: Role = Role.TARGET,
           start: bool = False) -> ContainerId:
    spec = build_spec(ownership=OWNERSHIP, role=role, image=IMAGE, script="x=1",
                      args=("sleeper" if role.is_decoy else role.value, NONCE))
    registry.plan(spec.name, role)
    cid = ContainerId(fake.run(Create(spec)).stdout.decode().strip())
    registry.record_created(spec.name, cid)
    if start:
        fake.containers[cid.value].state = "running"
    return cid


def write_ops(fake: FakeDocker) -> list[str]:
    return [op for op, _ in fake.ops if op in ("stop", "remove", "create", "start")]


def test_owned_running_container_is_stopped_removed_and_confirmed() -> None:
    fake = FakeDocker()
    reg = cl.OwnershipRegistry(ownership=OWNERSHIP)
    cid = create(fake, reg, start=True)
    fake.ops.clear()
    result = cl.remove_owned(fake, reg, cid)
    assert result.status is cl.CleanupStatus.REMOVED
    assert [op for op, _ in fake.ops] == ["inspect", "stop", "remove", "inspect"]
    assert all(target == cid.value for _, target in fake.ops)


def test_unregistered_id_is_refused_without_any_docker_call() -> None:
    fake = FakeDocker()
    result = cl.remove_owned(fake, cl.OwnershipRegistry(ownership=OWNERSHIP), ContainerId("e" * 64))
    assert result.status is cl.CleanupStatus.REFUSED
    assert fake.ops == []


LABEL_TAMPER = {
    "other run": lambda labels: labels.__setitem__("io.patchproof.run", "run-" + "9" * 32),
    "other installation": lambda labels: labels.__setitem__("io.patchproof.installation", "inst-" + "9" * 32),
    "not patchproof": lambda labels: labels.__setitem__("io.patchproof.owner", "someone-else"),
    "no owner": lambda labels: labels.pop("io.patchproof.owner"),
    "no labels": lambda labels: labels.clear(),
}


@pytest.mark.parametrize("name", sorted(LABEL_TAMPER))
def test_label_mismatch_is_refused_and_left_in_place(name: str) -> None:
    def tamper(role: Role, obj: dict[str, Any]) -> None:
        LABEL_TAMPER[name](obj["Config"]["Labels"])

    fake = FakeDocker(inspect_mutator=tamper)
    reg = cl.OwnershipRegistry(ownership=OWNERSHIP)
    cid = create(fake, reg)
    fake.ops.clear()
    result = cl.remove_owned(fake, reg, cid)
    assert result.status is cl.CleanupStatus.REFUSED
    assert write_ops(fake) == []
    assert cid.value in fake.containers


@pytest.mark.parametrize("field,value", [("Name", "/unrelated_db"), ("Id", "d" * 64)])
def test_identity_mismatch_is_refused(field: str, value: str) -> None:
    fake = FakeDocker(inspect_mutator=lambda role, obj: obj.__setitem__(field, value))
    reg = cl.OwnershipRegistry(ownership=OWNERSHIP)
    cid = create(fake, reg)
    assert cl.remove_owned(fake, reg, cid).status is cl.CleanupStatus.REFUSED
    assert cid.value in fake.containers


def test_failed_remove_is_reported_and_not_escalated() -> None:
    fake = FakeDocker(fail_remove_roles={Role.TARGET})
    reg = cl.OwnershipRegistry(ownership=OWNERSHIP)
    cid = create(fake, reg)
    result = cl.remove_owned(fake, reg, cid)
    assert result.status is cl.CleanupStatus.FAILED
    assert [op for op, _ in fake.ops].count("remove") == 1


def test_already_absent_is_not_reported_as_removed() -> None:
    fake = FakeDocker()
    reg = cl.OwnershipRegistry(ownership=OWNERSHIP)
    cid = create(fake, reg)
    del fake.containers[cid.value]
    assert cl.remove_owned(fake, reg, cid).status is cl.CleanupStatus.ALREADY_ABSENT


def test_owned_routine_refuses_decoys_and_decoy_routine_refuses_owned() -> None:
    fake = FakeDocker()
    reg = cl.OwnershipRegistry(ownership=OWNERSHIP)
    owned = create(fake, reg)
    decoy = create(fake, reg, Role.DECOY_FOREIGN)
    assert cl.remove_owned(fake, reg, decoy).status is cl.CleanupStatus.REFUSED
    assert cl.remove_decoy(fake, reg, owned).status is cl.CleanupStatus.REFUSED
    assert cl.remove_decoy(fake, reg, decoy).status is cl.CleanupStatus.REMOVED
    assert owned.value in fake.containers


def test_started_decoy_is_refused() -> None:
    fake = FakeDocker()
    reg = cl.OwnershipRegistry(ownership=OWNERSHIP)
    decoy = create(fake, reg, Role.DECOY_OTHER_RUN, start=True)
    assert cl.remove_decoy(fake, reg, decoy).status is cl.CleanupStatus.REFUSED


def test_registry_refuses_double_planning_and_unplanned_ids() -> None:
    reg = cl.OwnershipRegistry(ownership=OWNERSHIP)
    reg.plan("pp-probe-bbbbbbbbbbbb-target", Role.TARGET)
    with pytest.raises(PolicyViolation):
        reg.plan("pp-probe-bbbbbbbbbbbb-target", Role.TARGET)
    with pytest.raises(PolicyViolation):
        reg.record_created("pp-probe-bbbbbbbbbbbb-cpu", ContainerId("1" * 64))
    reg.record_created("pp-probe-bbbbbbbbbbbb-target", ContainerId("1" * 64))
    with pytest.raises(PolicyViolation):
        reg.record_created("pp-probe-bbbbbbbbbbbb-target", ContainerId("2" * 64))


def test_cleanup_all_reports_planned_but_never_created() -> None:
    fake = FakeDocker()
    reg = cl.OwnershipRegistry(ownership=OWNERSHIP)
    reg.plan("pp-probe-bbbbbbbbbbbb-cpu", Role.CPU)
    created = create(fake, reg)
    results = {r.name: r.status for r in cl.cleanup_all(fake, reg)}
    assert results["pp-probe-bbbbbbbbbbbb-cpu"] is cl.CleanupStatus.NOT_CREATED
    assert created.value not in fake.containers


# ------------------------------------------------------------------- journal and recovery


def test_journal_is_owner_only_and_write_ahead(tmp_path: Path) -> None:
    journal = tmp_path / "journal.jsonl"
    fake = FakeDocker()
    reg = cl.OwnershipRegistry(ownership=OWNERSHIP, journal_path=journal)
    create(fake, reg)
    events = [json.loads(line)["event"] for line in journal.read_text().splitlines()]
    assert events == ["planned", "created"]
    assert stat.S_IMODE(journal.stat().st_mode) == 0o600


def test_recovery_removes_only_this_runs_leftovers(tmp_path: Path) -> None:
    journal = tmp_path / "journal.jsonl"
    fake = FakeDocker()
    reg = cl.OwnershipRegistry(ownership=OWNERSHIP, journal_path=journal)
    leftover = create(fake, reg, Role.CPU, start=True)
    decoy = create(fake, reg, Role.DECOY_OTHER_RUN)
    # A container from another run exists too; it is not in this journal.
    other = cl.OwnershipRegistry(ownership=Ownership(OWNERSHIP.installation_id, "run-" + "9" * 32))
    stranger = create(fake, other, Role.TARGET)
    # Interrupted: the planned-but-unrecorded case is resolved by exact name.
    reg.plan("pp-probe-bbbbbbbbbbbb-pids", Role.PIDS)
    results = {r.name: r.status for r in cl.recover_interrupted(fake, journal, OWNERSHIP)}
    assert results["pp-probe-bbbbbbbbbbbb-cpu"] is cl.CleanupStatus.REMOVED
    assert results["pp-decoy-bbbbbbbbbbbb-decoy-other-run"] is cl.CleanupStatus.REMOVED
    assert results["pp-probe-bbbbbbbbbbbb-pids"] is cl.CleanupStatus.NOT_CREATED
    assert leftover.value not in fake.containers and decoy.value not in fake.containers
    assert stranger.value in fake.containers


def test_recovery_refuses_foreign_or_malformed_journal(tmp_path: Path) -> None:
    journal = tmp_path / "journal.jsonl"
    journal.write_text(json.dumps({"run_id": "run-" + "9" * 32, "event": "planned", "name": "x", "role": "target"})
                       + "\n")
    with pytest.raises(PolicyViolation, match="different run"):
        cl.recover_interrupted(FakeDocker(), journal, OWNERSHIP)
    journal.write_text("not json\n")
    with pytest.raises(PolicyViolation):
        cl.recover_interrupted(FakeDocker(), journal, OWNERSHIP)
    journal.write_text("x" * (cl.MAX_JOURNAL_BYTES + 1))
    with pytest.raises(PolicyViolation, match="size"):
        cl.recover_interrupted(FakeDocker(), journal, OWNERSHIP)


def test_recovery_by_name_still_checks_labels(tmp_path: Path) -> None:
    journal = tmp_path / "journal.jsonl"
    fake = FakeDocker(inspect_mutator=lambda role, obj: obj["Config"]["Labels"].clear())
    reg = cl.OwnershipRegistry(ownership=OWNERSHIP, journal_path=journal)
    spec = build_spec(ownership=OWNERSHIP, role=Role.CPU, image=IMAGE, script="x=1", args=("cpu", NONCE))
    reg.plan(spec.name, Role.CPU)  # crash before the ID was journaled
    cid = fake.run(Create(spec)).stdout.decode().strip()
    results = cl.recover_interrupted(fake, journal, OWNERSHIP)
    assert [r.status for r in results] == [cl.CleanupStatus.REFUSED]
    assert cid in fake.containers


# ------------------------------------------------------------------- force-removal fallback (owner-approved)


def test_force_only_after_stop_failure_and_reconfirmed_ownership() -> None:
    fake = FakeDocker(fail_stop_roles={Role.TARGET})
    reg = cl.OwnershipRegistry(ownership=OWNERSHIP)
    cid = create(fake, reg, start=True)
    fake.ops.clear()
    result = cl.remove_owned(fake, reg, cid)
    assert result.status is cl.CleanupStatus.FORCE_REMOVED
    assert [op for op, _ in fake.ops] == ["inspect", "stop", "inspect", "force-remove", "inspect"]
    assert "ownership reconfirmed" in result.detail


def test_ownership_change_before_escalation_refuses_force() -> None:
    calls = {"n": 0}

    def tamper_on_reinspect(role: Role, obj: dict[str, Any]) -> None:
        calls["n"] += 1
        if calls["n"] >= 2:
            obj["Config"]["Labels"]["io.patchproof.run"] = "run-" + "9" * 32

    fake = FakeDocker(fail_stop_roles={Role.TARGET}, inspect_mutator=tamper_on_reinspect)
    reg = cl.OwnershipRegistry(ownership=OWNERSHIP)
    cid = create(fake, reg, start=True)
    result = cl.remove_owned(fake, reg, cid)
    assert result.status is cl.CleanupStatus.FAILED
    assert result.detail.startswith("CLEANUP_FAILED: ownership not reconfirmed")
    assert "force-remove" not in [op for op, _ in fake.ops]
    assert cid.value in fake.containers


def test_stopped_container_with_failed_removal_is_not_forced() -> None:
    fake = FakeDocker(fail_remove_roles={Role.TARGET})
    reg = cl.OwnershipRegistry(ownership=OWNERSHIP)
    cid = create(fake, reg, start=True)
    result = cl.remove_owned(fake, reg, cid)
    assert result.status is cl.CleanupStatus.FAILED and "CLEANUP_FAILED" in result.detail
    assert "force-remove" not in [op for op, _ in fake.ops]


def test_unreadable_reinspect_refuses_force() -> None:
    calls = {"n": 0}

    def break_reinspect(role: Role, obj: dict[str, Any]) -> None:
        calls["n"] += 1
        if calls["n"] >= 2:
            obj["Id"] = "d" * 64

    fake = FakeDocker(fail_stop_roles={Role.TARGET}, inspect_mutator=break_reinspect)
    reg = cl.OwnershipRegistry(ownership=OWNERSHIP)
    cid = create(fake, reg, start=True)
    assert cl.remove_owned(fake, reg, cid).status is cl.CleanupStatus.FAILED
    assert "force-remove" not in [op for op, _ in fake.ops]


def test_decoys_never_take_the_force_path() -> None:
    fake = FakeDocker(fail_remove_roles={Role.DECOY_FOREIGN})
    reg = cl.OwnershipRegistry(ownership=OWNERSHIP)
    decoy = create(fake, reg, Role.DECOY_FOREIGN)
    assert cl.remove_decoy(fake, reg, decoy).status is cl.CleanupStatus.FAILED
    assert "force-remove" not in [op for op, _ in fake.ops]


def test_journal_treats_force_removed_as_settled(tmp_path: Path) -> None:
    journal = tmp_path / "journal.jsonl"
    fake = FakeDocker(fail_stop_roles={Role.CPU})
    reg = cl.OwnershipRegistry(ownership=OWNERSHIP, journal_path=journal)
    cid = create(fake, reg, Role.CPU, start=True)
    assert cl.remove_owned(fake, reg, cid).status is cl.CleanupStatus.FORCE_REMOVED
    assert cl.recover_interrupted(fake, journal, OWNERSHIP) == []


# ------------------------------------------------------------------- owner-requested: running decoy of another run


def _running_other_run_decoy(fake: FakeDocker) -> tuple[cl.OwnershipRegistry, ContainerId]:
    """A running container labeled for a *different* run, presented to the owned-cleanup path
    as if this run had registered it (the strongest form of a confused-deputy attempt)."""
    reg = cl.OwnershipRegistry(ownership=OWNERSHIP)
    spec = build_spec(ownership=OWNERSHIP, role=Role.DECOY_OTHER_RUN, image=IMAGE, script="x=1",
                      args=("sleeper", NONCE))
    cid = ContainerId(fake.run(Create(spec)).stdout.decode().strip())
    fake.containers[cid.value].state = "running"
    reg.entries[spec.name] = cl.RegistryEntry(spec.name, Role.TARGET, cid)  # bypass the role check
    return reg, cid


def test_running_other_run_container_is_refused_without_force(tmp_path: Path) -> None:
    fake = FakeDocker(fail_stop_roles={Role.DECOY_OTHER_RUN})
    reg, cid = _running_other_run_decoy(fake)
    reg.journal_path = tmp_path / "journal.jsonl"
    fake.ops.clear()
    result = cl.remove_owned(fake, reg, cid)
    assert result.status is cl.CleanupStatus.REFUSED
    assert "run label does not match this run" in result.detail
    ops = [op for op, _ in fake.ops]
    assert "force-remove" not in ops and "stop" not in ops and "remove" not in ops
    assert cid.value in fake.containers and fake.containers[cid.value].state == "running"
    recorded = [json.loads(line) for line in reg.journal_path.read_text().splitlines()]
    assert recorded[-1]["status"] == "REFUSED"


def test_escalation_step_itself_refuses_another_runs_container() -> None:
    """Direct test of the force-removal function's own re-verification guard."""
    fake = FakeDocker(fail_stop_roles={Role.DECOY_OTHER_RUN})
    reg, cid = _running_other_run_decoy(fake)
    name = next(iter(reg.entries))
    fake.ops.clear()
    status, detail = cl._stop_and_remove(fake, cid, True, expected_name=name, ownership=OWNERSHIP,
                                         allow_force=True)
    assert status is cl.CleanupStatus.FAILED
    assert detail.startswith("CLEANUP_FAILED: ownership not reconfirmed")
    assert "force-remove" not in [op for op, _ in fake.ops]
    assert cid.value in fake.containers
