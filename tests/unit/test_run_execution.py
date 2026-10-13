"""PP-008: revision execution and comparison through a scripted fake Docker (no Docker, no PaperTrail).

The verifier streams here are synthetic, built from PP-006's declared outcomes. A
`VERIFIED_FOR_CASES` in these tests shows that the orchestration and the accepted engine
compose correctly. It is not an application-security result.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
from _run_fixtures import (
    APPROVED_IMAGES,
    OWNERSHIP,
    Environment,
    FakeDocker,
    build_environment,
    declared_outcomes,
    stream,
)

from patchproof.runner.cleanup import CleanupStatus, OwnershipRegistry
from patchproof.runner.comparison import ComparisonResult, run_comparison
from patchproof.runner.docker_cli import DockerCli, ForceRemove, Remove, Start
from patchproof.runner.run_policy import RunCreate, StartAttached

EVALUATED_AT = "2026-10-12T12:00:00Z"


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture(scope="module")
def env(tmp_path_factory: pytest.TempPathFactory) -> Environment:
    return build_environment(tmp_path_factory.mktemp("pp008"))


def run(env: Environment, docker: FakeDocker | None = None, *, candidate: str = "correct",
        baseline: str = "vulnerable", streams: dict[str, bytes] | None = None, **kwargs: Any) -> ComparisonResult:
    docker = docker or FakeDocker()
    docker.streams = streams or {"baseline": stream(env.plan, 1, "baseline", declared_outcomes(baseline)),
                                 "candidate": stream(env.plan, 1, "candidate", declared_outcomes(candidate))}
    if "health" in kwargs:
        docker.target_health = list(kwargs["health"])
    result = run_comparison(docker, env.plan, env.approvals, OwnershipRegistry(OWNERSHIP), clock=FakeClock(),
                            evaluated_at=EVALUATED_AT, approved_images=kwargs.get("approved_images", APPROVED_IMAGES),
                            cancel=kwargs.get("cancel", lambda: False))
    result.__dict__["docker"] = docker
    return result


# ------------------------------------------------------------ the four PP-006 comparisons (synthetic streams)


@pytest.mark.parametrize(("candidate", "verdict"), [("vulnerable", "NOT_FIXED"), ("inadequate", "NOT_FIXED"),
                                                     ("correct", "VERIFIED_FOR_CASES"),
                                                     ("deny-all", "REGRESSION_DETECTED")])
def test_declared_comparisons_compose_with_the_engine(env: Environment, candidate: str, verdict: str) -> None:
    result = run(env, candidate=candidate)
    assert result.verdict["verdict"] == verdict
    assert [r.execution.stream.status for r in result.revisions] == ["COMPLETE", "COMPLETE"]
    assert all(r.execution.verifier.termination == "EXITED" for r in result.revisions)


def test_successful_execution_uses_exactly_two_containers_per_revision(env: Environment) -> None:
    result = run(env)
    docker: FakeDocker = result.__dict__["docker"]
    creates = [op for op in docker.log if isinstance(op, RunCreate)]
    assert [(c.spec.side, c.spec.role.value) for c in creates] == [
        ("baseline", "target"), ("baseline", "verifier"), ("candidate", "target"), ("candidate", "verifier")]
    for c in creates:
        args = c.argv_tail()
        if c.spec.role.value == "target":
            assert args[args.index("--network") + 1] == "none"
            assert f"target={'/app/source'},readonly" in args[args.index("--mount") + 1]
        else:
            assert args[args.index("--network") + 1].startswith("container:c")
            assert args[args.index("--mount") + 1].endswith("target=/pack,readonly")
            assert str(env.plan.pack.root) in args[args.index("--mount") + 1]
        assert "--publish" not in args and "-p" not in args and "bridge" not in args
    for r in result.revisions:
        assert {c.status for c in r.cleanup} == {CleanupStatus.REMOVED}


def test_unrelated_resources_are_never_touched(env: Environment) -> None:
    result = run(env)
    docker: FakeDocker = result.__dict__["docker"]
    assert docker.touched_ids() <= set(docker.created) and len(docker.created) == 4
    assert not any(isinstance(op, ForceRemove) for op in docker.log)
    assert all(op.op_name not in ("prune", "build", "pull") for op in docker.log)


# ------------------------------------------------------------ preconditions block before anything is created


def test_stale_approval_blocks_without_docker(env: Environment) -> None:
    from patchproof.runner.run_plan import RunPlan

    from patchproof.runner.policy import PolicyViolation

    stale_plan = RunPlan(**{**env.plan.__dict__, "verifier_image": env.plan.verifier_image})
    # A runtime value that differs from the enforced policy is refused when the plan is built.
    inconsistent = stale_plan.profile.model_copy(update={"timeouts": stale_plan.profile.timeouts.model_copy(
        update={"readiness_seconds": 29})})
    with pytest.raises(PolicyViolation, match="timeouts.readiness_seconds"):
        RunPlan(**{**stale_plan.__dict__, "profile": inconsistent})
    # A consistent but different profile changes the profile hash: the approval is stale.
    profile = stale_plan.profile.model_copy(update={"profile_version": "0.2.1"})
    changed = RunPlan(**{**stale_plan.__dict__, "profile": profile})
    docker = FakeDocker()

    class Exec:
        def run(self, op: Any) -> Any:
            return docker.run(op)

    result = run_comparison(Exec(), changed, env.approvals, OwnershipRegistry(OWNERSHIP), clock=FakeClock(),
                            evaluated_at=EVALUATED_AT, approved_images=APPROVED_IMAGES)
    assert result.verdict["verdict"] == "BLOCKED"
    assert "APPROVAL_STALE" in result.verdict["reason_codes"]
    assert docker.log == []


def test_unapproved_images_block_without_docker(env: Environment) -> None:
    result = run(env, approved_images=())
    assert result.verdict["verdict"] == "BLOCKED"
    assert "ENVIRONMENT_NONCOMPARABLE" in result.verdict["reason_codes"]
    assert result.__dict__["docker"].log == []


def test_images_outside_the_default_registry_block_before_any_docker_operation(env: Environment) -> None:
    """The default registry holds only the gate-B r2 images (gate C, 2026-10-13); any other image blocks."""
    from patchproof.runner.run_plan import APPROVED_RUN_IMAGES

    approved = {i.image.value for i in APPROVED_RUN_IMAGES}
    assert env.plan.target_image.image.value not in approved and env.plan.verifier_image.image.value not in approved
    docker = FakeDocker()

    class Exec:
        def run(self, op: Any) -> Any:
            return docker.run(op)

    result = run_comparison(Exec(), env.plan, env.approvals, OwnershipRegistry(OWNERSHIP), clock=FakeClock(),
                            evaluated_at=EVALUATED_AT)
    assert result.verdict["verdict"] == "BLOCKED" and docker.log == []


def test_image_identity_mismatch_is_pre_execution(env: Environment) -> None:
    docker = FakeDocker(image_tamper=lambda obj: obj["Config"].update(Env=["PYTHONPATH=/evil"]))
    result = run(env, docker)
    assert result.verdict["verdict"] == "BLOCKED"
    assert result.verdict_input.preconditions.environment_identity.detected_phase == "pre_execution"
    assert not any(isinstance(op, (RunCreate, Start)) for op in docker.log)


@pytest.mark.parametrize("tamper", [
    lambda o: o["HostConfig"].update(Privileged=True),
    lambda o: o["HostConfig"].update(NetworkMode="bridge"),
    lambda o: o["HostConfig"].update(PortBindings={"8080/tcp": [{"HostPort": "8080"}]}),
    lambda o: o["Mounts"][0].update(RW=True),
    lambda o: o["HostConfig"]["Mounts"].append({"Type": "bind", "Source": "/", "Target": "/host", "ReadOnly": False}),
    lambda o: o["HostConfig"].update(CapAdd=["SYS_ADMIN"]),
    lambda o: o["Config"].update(Env=["PATH=/x", "PYTEST_ADDOPTS=-p evil"]),
])
def test_policy_gate_failure_blocks_before_any_start(env: Environment, tamper: Any) -> None:
    docker = FakeDocker(gate_tamper=tamper)
    result = run(env, docker)
    assert result.verdict["verdict"] == "BLOCKED"
    assert "RUNTIME_POLICY_FAILED" in result.verdict["reason_codes"]
    assert not any(isinstance(op, (Start, StartAttached)) for op in docker.log)
    assert all(c.status is CleanupStatus.REMOVED for r in result.revisions for c in r.cleanup)


# ------------------------------------------------------------ local execution failures


def test_target_startup_failure_is_inconclusive_and_verifier_never_starts(env: Environment) -> None:
    docker = FakeDocker(target_dies=True)
    result = run(env, docker)
    assert result.verdict["verdict"] == "INCONCLUSIVE"
    assert {r.execution.target.readiness for r in result.revisions} == {"STARTUP_FAILED"}
    assert not any(isinstance(op, StartAttached) for op in docker.log)
    assert {r.execution.stream.status for r in result.revisions} == {"ABSENT"}


def test_readiness_timeout(env: Environment) -> None:
    result = run(env, health=["starting"])
    assert {r.execution.target.readiness for r in result.revisions} == {"READINESS_TIMEOUT"}
    assert result.verdict["verdict"] == "INCONCLUSIVE"


def test_target_oom_during_tests_is_untrusted(env: Environment) -> None:
    docker = FakeDocker(target_oom=True)
    result = run(env, docker)
    assert all(r.execution.target.oom_killed for r in result.revisions)
    assert result.verdict["verdict"] == "INCONCLUSIVE"


def test_verifier_timeout_is_stopped_and_untrusted(env: Environment) -> None:
    docker = FakeDocker(verifier_timeout=True)
    result = run(env, docker)
    for r in result.revisions:
        assert r.execution.deadline_exceeded
        assert (r.execution.verifier.termination, r.execution.verifier.signal) == ("SIGNALED", 9)
    assert {c for c in docker.created if c.startswith("d")} <= docker.stopped
    assert result.verdict["verdict"] == "INCONCLUSIVE"


@pytest.mark.parametrize("code", [2, 3, 4, 5])
def test_abnormal_verifier_exit_is_untrusted(env: Environment, code: int) -> None:
    result = run(env, FakeDocker(verifier_exit=code))
    assert {r.execution.verifier.exit_code for r in result.revisions} == {code}
    assert result.verdict["verdict"] == "INCONCLUSIVE"


def test_session_end_alone_does_not_make_an_oom_execution_trusted(env: Environment) -> None:
    result = run(env, FakeDocker(verifier_oom=True))
    assert all(r.execution.stream.status == "COMPLETE" for r in result.revisions)
    assert result.verdict["verdict"] == "INCONCLUSIVE"


def test_output_flood_over_cap_is_local(env: Environment) -> None:
    cap = env.plan.profile.result_cap_bytes
    flood = b"x" * (cap + 1)
    result = run(env, FakeDocker(verifier_truncated=True), streams={"baseline": flood, "candidate": flood})
    assert {r.execution.stream.status for r in result.revisions} == {"OVER_CAP"}
    assert result.verdict["verdict"] == "INCONCLUSIVE"
    assert "RESULT_CAP_EXCEEDED" in result.verdict["reason_codes"]


def test_trusted_candidate_violation_survives_a_local_baseline_failure(env: Environment) -> None:
    cap = env.plan.profile.result_cap_bytes
    streams = {"baseline": b"x" * (cap + 1),
               "candidate": stream(env.plan, 1, "candidate", declared_outcomes("vulnerable"))}
    result = run(env, streams=streams)
    assert [r.execution.stream.status for r in result.revisions] == ["OVER_CAP", "COMPLETE"]
    assert result.verdict["verdict"] == "NOT_FIXED"


def test_malformed_stream_is_a_global_provenance_failure(env: Environment) -> None:
    good = stream(env.plan, 1, "candidate", declared_outcomes("correct"))
    forged = stream(env.plan, 1, "baseline", declared_outcomes("vulnerable")).replace(b'"seq":3', b'"seq":4', 1)
    result = run(env, streams={"baseline": forged, "candidate": good})
    assert result.revisions[0].execution.stream.status == "MALFORMED"
    assert result.verdict["verdict"] == "INCONCLUSIVE"
    assert result.verdict_input.preconditions.result_provenance.state == "FAILED"


def test_identity_mismatch_stream(env: Environment) -> None:
    wrong_side = stream(env.plan, 1, "candidate", declared_outcomes("vulnerable"))
    result = run(env, streams={"baseline": wrong_side,
                               "candidate": stream(env.plan, 1, "candidate", declared_outcomes("correct"))})
    assert result.revisions[0].execution.stream.status == "IDENTITY_MISMATCH"
    assert result.verdict["verdict"] == "INCONCLUSIVE"


def test_target_log_text_is_never_evidence(env: Environment) -> None:
    docker = FakeDocker()
    docker.target_logs = stream(env.plan, 1, "candidate", declared_outcomes("correct"))
    result = run(env, docker, candidate="vulnerable")
    assert result.verdict["verdict"] == "NOT_FIXED"
    assert all(r.target_log == docker.target_logs for r in result.revisions)


def test_create_failure_records_a_runtime_error(env: Environment) -> None:
    result = run(env, FakeDocker(create_fails="verifier"))
    assert "CONTAINER_CREATE_FAILED" in result.revisions[0].execution.runtime_errors
    assert result.verdict["verdict"] == "INCONCLUSIVE"


def test_attach_failure_is_recorded(env: Environment) -> None:
    result = run(env, FakeDocker(verifier_never_started=True))
    assert all("ATTACH_FAILED" in r.execution.runtime_errors for r in result.revisions)
    assert result.verdict["verdict"] == "INCONCLUSIVE"


def test_cancellation_before_start(env: Environment) -> None:
    result = run(env, cancel=lambda: True)
    assert result.verdict_input.run_termination == "canceled"
    assert not any(isinstance(op, Start) for op in result.__dict__["docker"].log)


def test_cleanup_refuses_containers_whose_labels_no_longer_match(env: Environment) -> None:
    docker = FakeDocker(foreign_labels_on_cleanup=True)
    result = run(env, docker)
    targets = {c for c in docker.created if c.startswith("c")}
    by_id = {c.container_id: c.status for r in result.revisions for c in r.cleanup}
    assert {by_id[t] for t in targets} == {CleanupStatus.REFUSED}
    assert {s for cid, s in by_id.items() if cid not in targets} == {CleanupStatus.REMOVED}
    removed = {op.argv_tail()[-1] for op in docker.log if isinstance(op, (Remove, ForceRemove))}
    assert not removed & targets


# ------------------------------------------------------------ the accepted wrapper still refuses run operations


def test_real_docker_cli_admits_only_the_fixed_run_operations(env: Environment, monkeypatch: Any) -> None:
    """After the gate-C wrapper change, DockerCli passes the fixed shapes through (to a blocked spawn)."""
    import subprocess

    spawned: list[list[str]] = []

    def no_spawn(argv: list[str], *_a: Any, **_k: Any) -> None:
        spawned.append(argv)
        raise RuntimeError("spawn intercepted")

    monkeypatch.setattr(subprocess, "Popen", no_spawn)
    cli = DockerCli(docker_binary="/usr/local/bin/docker", home=str(Path.home()))
    docker = FakeDocker()

    class Capture:
        def run(self, op: Any) -> Any:
            if isinstance(op, (RunCreate, StartAttached)):
                with pytest.raises(RuntimeError, match="intercepted"):
                    cli.run(op)
            return docker.run(op)

    run_comparison(Capture(), env.plan, env.approvals, OwnershipRegistry(OWNERSHIP), clock=FakeClock(),
                   evaluated_at=EVALUATED_AT, approved_images=APPROVED_IMAGES)
    assert spawned and all(argv[:3] == ["/usr/local/bin/docker", "--context", "desktop-linux"] for argv in spawned)
    assert {argv[3:5][1] if argv[3] == "container" else argv[3] for argv in spawned} == {"create", "start"}

def test_pack_modified_during_the_run_fails_integrity_post_execution(tmp_path: Path) -> None:
    own = build_environment(tmp_path)
    readme = own.plan.pack.root / "README.md"

    def tamper(side: str) -> None:
        if side == "candidate":
            os.chmod(own.plan.pack.root, 0o755)
            os.chmod(readme, 0o644)
            readme.write_text(readme.read_text() + "\nchanged during the run\n")
            os.chmod(readme, 0o444)
            os.chmod(own.plan.pack.root, 0o555)

    result = run(own, FakeDocker(on_attach=tamper))
    pack = result.verdict_input.preconditions.pack_integrity
    assert (pack.state, pack.detected_phase, pack.reason_codes) == (
        "FAILED", "post_execution", ["PACK_INTEGRITY_FAILED"])
    assert result.verdict["verdict"] == "INCONCLUSIVE"


def test_plan_manifest_must_be_the_approved_packs_manifest(env: Environment) -> None:
    from patchproof.runner.run_plan import RunPlan, check_preconditions

    forged = env.plan.manifest.model_copy(update={"title": "A different manifest object"})
    plan = RunPlan(**{**env.plan.__dict__, "manifest": forged})
    result = check_preconditions(plan, env.approvals, APPROVED_IMAGES)
    assert (result["pack_integrity"].state, result["pack_integrity"].reason_codes) == (
        "FAILED", ["PACK_INTEGRITY_FAILED"])
