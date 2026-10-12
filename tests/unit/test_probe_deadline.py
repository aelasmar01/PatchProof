"""PP-003: 20-minute monotonic global deadline and the separate 2-minute cleanup window.

Synthetic clock and Docker model only; no daemon, no containers.
"""

from __future__ import annotations

from typing import Any

import pytest
from _fakes import HOME, IMAGE, NONCE, OWNERSHIP, FakeDocker, good_streams
from test_probe_orchestrator import VALIDATOR, outcomes

from patchproof.probes import evidence as ev
from patchproof.probes.catalogue import load_probe_script
from patchproof.probes.interpret import Outcome, ProbeOutcome, SuiteStatus
from patchproof.probes.orchestrator import (
    CLEANUP_WINDOW_SECONDS,
    GLOBAL_DEADLINE_SECONDS,
    ProbeSuite,
)
from patchproof.runner.policy import Role

AUTH = {"a2_image_approved": True, "a3_evidence_root_verified": True, "a4_operator_confirmed": True}
CLEANUP_OPS = {"inspect", "stop", "remove", "force-remove", "snapshot"}


def run(fake: FakeDocker, deadline: float = GLOBAL_DEADLINE_SECONDS,
        cleanup: float = CLEANUP_WINDOW_SECONDS) -> tuple[ProbeSuite, dict[str, Any]]:
    suite = ProbeSuite(fake, OWNERSHIP, IMAGE, load_probe_script(), home=HOME, nonce=NONCE,
                       clock=lambda: fake.clock[0], deadline_seconds=deadline, cleanup_seconds=cleanup)
    record = suite.run(AUTH)
    assert not list(VALIDATOR.iter_errors(record))
    return suite, record


def test_approved_budgets() -> None:
    assert GLOBAL_DEADLINE_SECONDS == 20 * 60 and CLEANUP_WINDOW_SECONDS == 2 * 60


def test_normal_run_finishes_within_deadline() -> None:
    fake = FakeDocker(streams=good_streams(), op_cost={"create": 1.0, "logs": 1.0}, wait_cost={Role.TARGET: 20.0})
    _, record = run(fake)
    assert record["suite_status"] == SuiteStatus.ALL_PLANNED_PROBES_PASSED.value
    assert outcomes(record)["RES-15"] == "PASS"
    assert record["execution"]["deadline_expired"] is False and record["execution"]["cleanup_status"] == "COMPLETE"


def test_expiry_stops_new_probes_keeps_completed_evidence_and_cleans_up() -> None:
    fake = FakeDocker(streams=good_streams(), wait_cost={Role.MEMORY: 400.0})
    suite, record = run(fake, deadline=50)
    o = outcomes(record)
    ex = record["execution"]
    assert ex["deadline_expired"] is True and ex["expired_during_phase"] == "memory"
    assert o["RES-15"] == "INCONCLUSIVE"
    assert record["suite_status"] != SuiteStatus.ALL_PLANNED_PROBES_PASSED.value
    # Completed target/verifier observations are preserved.
    assert o["NET-02"] == "PASS" and o["FS-06"] == "PASS"
    # Later phases never started: their checks are NOT_RUN, not PASS.
    for pid in ("RES-04", "RES-06", "RES-07", "RES-11", "RES-12", "CLN-02"):
        assert o[pid] == "NOT_RUN", pid
    assert o["RES-02"] != "PASS"
    created_roles = {c["role"] for c in record["containers"]}
    assert created_roles == {"target", "verifier", "memory"}
    # After expiry, only cleanup operations were issued, and everything tracked was removed.
    assert suite.budget.cleanup_started is not None
    after = [op for op, start, _ in fake.timeline if start >= suite.budget.cleanup_started]
    assert set(after) <= CLEANUP_OPS
    assert not fake.containers and ex["cleanup_status"] == "COMPLETE"
    assert any("deadline" in lim for lim in record["limitations"])


def test_every_operation_timeout_is_bounded_by_the_remaining_budget() -> None:
    fake = FakeDocker(streams=good_streams(), op_cost={"create": 5.0, "logs": 5.0, "inspect": 1.0},
                      wait_cost={Role.TARGET: 30.0, Role.CPU: 400.0})
    suite, _ = run(fake, deadline=250)
    cleanup_start = suite.budget.cleanup_started
    assert cleanup_start is not None
    for op, start, timeout in fake.timeline:
        if start < cleanup_start:
            assert timeout <= 250 - start + 1e-9, (op, start, timeout)
        else:
            assert timeout <= CLEANUP_WINDOW_SECONDS - (start - cleanup_start) + 1e-9, (op, start, timeout)


def test_deadline_already_spent_issues_no_docker_operation() -> None:
    fake = FakeDocker(streams=good_streams())
    _, record = run(fake, deadline=0)
    assert fake.ops == []
    assert outcomes(record)["RES-15"] == "INCONCLUSIVE"
    assert record["suite_status"] not in (SuiteStatus.ALL_PLANNED_PROBES_PASSED.value,)
    assert record["execution"]["cleanup_status"] == "NOT_NEEDED"


def test_expiry_during_target_verifier_leaves_evidence_incomplete_not_passed() -> None:
    fake = FakeDocker(streams=good_streams(), wait_cost={Role.VERIFIER: 900.0})
    _, record = run(fake, deadline=120)
    o = outcomes(record)
    assert record["execution"]["expired_during_phase"] == "target-verifier"
    for pid in ("NET-07", "FS-07", "NET-P1", "NS-02"):
        assert o[pid] in ("NOT_RUN", "INCONCLUSIVE"), pid
    assert record["suite_status"] in (SuiteStatus.INCOMPLETE.value, SuiteStatus.HARNESS_INVALID.value)


def test_hung_stop_and_force_are_cleanup_failed_without_retry() -> None:
    fake = FakeDocker(streams=good_streams(), wait_cost={Role.MEMORY: 400.0},
                      op_cost={"stop": 500.0, "force-remove": 500.0})
    _, record = run(fake, deadline=50)
    ex = record["execution"]
    assert ex["cleanup_status"] == "CLEANUP_FAILED"
    memory = next(c for c in record["containers"] if c["role"] == "memory")
    assert memory["cleanup"]["detail"].startswith("CLEANUP_FAILED")
    assert [op for op, cid in fake.ops if cid == memory["container_id"]].count("force-remove") == 1
    assert memory["container_id"] in fake.containers


def test_cleanup_window_expiry_is_cleanup_failed_without_retry() -> None:
    fake = FakeDocker(streams=good_streams(), wait_cost={Role.MEMORY: 400.0}, op_cost={"stop": 500.0})
    suite, record = run(fake, deadline=50, cleanup=20)
    ex = record["execution"]
    assert ex["cleanup_window_expired"] is True and ex["cleanup_status"] == "CLEANUP_FAILED"
    memory = next(c for c in record["containers"] if c["role"] == "memory")
    assert memory["cleanup"]["status"] == "FAILED"
    assert memory["cleanup"]["detail"].startswith("CLEANUP_FAILED")
    # The tracked container is reported, not silently abandoned, and nothing else was touched.
    assert memory["container_id"] in fake.containers
    stops = [cid for op, cid in fake.ops if op == "stop" and cid == memory["container_id"]]
    assert len(stops) <= 2, "no indefinite retry"
    cleanup_start = suite.budget.cleanup_started
    assert cleanup_start is not None
    assert all(start - cleanup_start <= 20 + 1e-9 for _, start, _ in fake.timeline if start >= cleanup_start)
    assert outcomes(record)["CLN-06"] == "NOT_RUN", "no after-snapshot once the window is spent"
    assert outcomes(record)["CLN-01"] == "FAIL"
    assert record["suite_status"] != SuiteStatus.ALL_PLANNED_PROBES_PASSED.value


def test_interruption_uses_the_cleanup_window() -> None:
    fake = FakeDocker(streams=good_streams(), interrupt_on=("wait", Role.PIDS))
    _, record = run(fake)
    assert record["execution"]["interrupted"] is True
    assert outcomes(record)["RES-15"] == "INCONCLUSIVE"
    assert not fake.containers


@pytest.mark.parametrize("execution", [
    {"deadline_expired": True}, {"interrupted": True}, {"cleanup_status": "CLEANUP_FAILED"},
])
def test_record_refuses_success_after_expiry_interruption_or_failed_cleanup(execution: dict[str, Any]) -> None:
    from patchproof.probes.catalogue import CATALOGUE

    base = {"global_deadline_seconds": 1200, "cleanup_window_seconds": 120, "active_elapsed_seconds": 1.0,
            "deadline_expired": False, "expired_during_phase": None, "interrupted": False,
            "cleanup_window_expired": False, "cleanup_status": "COMPLETE"}
    with pytest.raises(ValueError):
        ev.build_record(
            ownership=OWNERSHIP, started_at="2026-10-11T00:00:00Z", finished_at="2026-10-11T00:00:01Z",
            server_version="29.8.2", image={"image_id": IMAGE.value, "repo_digests": [], "os": "linux",
                                            "architecture": "amd64"},
            script_digest="sha256:" + "0" * 64, authorization=AUTH, containers=[],
            outcomes=[ProbeOutcome(s.probe_id, Outcome.PASS, "x") for s in CATALOGUE],
            status=SuiteStatus.ALL_PLANNED_PROBES_PASSED, preservation={"outcome": "PASS", "differences": []},
            execution={**base, **execution})


def test_budgets_above_the_approved_ceilings_are_refused() -> None:
    from patchproof.runner.policy import PolicyViolation

    for kwargs in ({"deadline_seconds": 1201}, {"cleanup_seconds": 121}, {"deadline_seconds": -1}):
        with pytest.raises(PolicyViolation):
            ProbeSuite(FakeDocker(), OWNERSHIP, IMAGE, "x=1", home=HOME, **kwargs)  # type: ignore[arg-type]
