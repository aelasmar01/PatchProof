"""PP-008 evidence hardening: output routing, journal metadata, timestamps, and the interruption point.

Docker-free: fake Docker responses, temporary evidence directories, and small local child
processes for real signal delivery. Nothing here contacts Docker or reads real evidence.
"""

from __future__ import annotations

import inspect
import json
import os
import re
import signal
import subprocess
import sys
import time
from collections.abc import Iterator
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from _run_fixtures import ok
from test_authorized_run import (  # noqa: F401 - `shared` is a fixture
    NOW,
    RUN_ID,
    Env,
    FakeClock,
    FakeTerminal,
    authorize,
    creates,
    execute,
    fake,
    make_env,
    manifest,
    outcome,
    shared,
)

from patchproof import run_papertrail_once
from patchproof.recover_run import recover
from patchproof.run_papertrail_once import run_once
from patchproof.runner import authorized_run
from patchproof.runner.cleanup import OwnershipRegistry
from patchproof.runner.comparison import run_comparison
from patchproof.runner.docker_cli import (
    DEFAULT_STDERR_CAP,
    TARGET_LOG_STREAM_CAP,
    ContainerRef,
    Inspect,
    Logs,
    assert_no_forbidden_tokens,
    run_bounded,
    stderr_cap_of,
)
from patchproof.runner.interrupts import RunTerminated, graceful_termination
from patchproof.runner.interruption_point import InterruptionPoint, InterruptionTestAborted, deliver_at_checkpoint
from patchproof.runner.revision import CheckpointState
from patchproof.runner.papertrail_plan import assemble_run
from patchproof.runner.policy import ContainerId, PolicyViolation
from patchproof.runner.run_evidence import (
    JOURNAL_FORMAT,
    RecordingExecutor,
    RunEvidence,
    check_operation_journal,
    journal_format,
    utc_stamp,
    verify_evidence,
)
from patchproof.runner.run_policy import StartAttached

# Controlled synthetic secrets: none may ever appear in operational metadata.
TOKEN = b"pp-synthetic-bearer-token-0f1e2d3c4b5a"
MARKER = b"PP-SYNTHETIC-PROTECTED-MARKER-77aa"
STAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
METADATA = ("docker-ops.jsonl", "outcome.json", "manifest.json", "revalidation.jsonl", "ownership-journal.jsonl",
            "reconciliation.json", "inventory-before.json", "inventory-after.json", "verdict.json",
            "verdict-input.json")


@pytest.fixture
def e(tmp_path: Path, shared: Path) -> Env:  # noqa: F811
    return make_env(tmp_path, shared)


def journal(e: Env, name: str = "docker-ops.jsonl") -> list[dict[str, Any]]:
    return [json.loads(line) for line in (e.evidence / name).read_text().splitlines()]


def hostile(e: Env) -> Any:
    """Target and verifier-console output carrying a complete valid event stream, a token and a marker."""
    docker = fake(e)
    valid = docker.streams["baseline"]
    docker.target_logs = b"stdout " + TOKEN + b"\n" + valid
    docker.target_stderr = b"INFO:     Uvicorn running\n" + MARKER + b"\n" + valid
    docker.verifier_console = b"E   AssertionError: body contained " + MARKER + b" for " + TOKEN + b"\n" + valid
    return docker


class Ticking:
    """A wall clock that advances one millisecond per reading, so every timestamp is distinct."""

    def __init__(self, start: datetime = NOW, step: timedelta = timedelta(milliseconds=1)) -> None:
        self.current, self.step, self.readings = start, step, 0

    def __call__(self) -> datetime:
        self.readings += 1
        self.current += self.step
        return self.current


def run_with(e: Env, docker: Any, now: Any) -> int:
    terminal = FakeTerminal({"To execute": f"EXECUTE {RUN_ID}"})
    return run_once(e.env, terminal, lambda: docker, clock=FakeClock(), now=now)


# ------------------------------------------------------------------ 2/3: output routing


def test_target_and_console_output_never_enter_operational_metadata(e: Env) -> None:
    assert authorize(e)[0] == 0
    docker = hostile(e)
    code, _, _ = execute(e, docker)
    assert code == 0 and outcome(e)["verdict"] == "VERIFIED_FOR_CASES"  # logs never decide anything
    for name in [*METADATA, *(n for n in os.listdir(e.evidence) if n.startswith(("revision-", "execution-",
                                                                                  "observations-")))]:
        data = (e.evidence / name).read_bytes()
        assert TOKEN not in data and MARKER not in data, name
        assert b"Uvicorn" not in data and b"AssertionError" not in data, name
    for side in ("baseline", "candidate"):
        tag = f"pair-001-{side}"
        assert (e.evidence / f"untrusted-target-stdout-{tag}.log").read_bytes() == docker.target_logs
        assert (e.evidence / f"untrusted-target-stderr-{tag}.log").read_bytes() == docker.target_stderr
        assert (e.evidence / f"untrusted-verifier-console-{tag}.log").read_bytes() == docker.verifier_console
        revision = json.loads((e.evidence / f"revision-{tag}.json").read_text())
        stderr = revision["untrusted_outputs"]["untrusted-target-stderr"]
        assert stderr["capture"] == "CAPTURED" and stderr["bytes"] == len(docker.target_stderr)
        assert stderr["artifact"] == f"untrusted-target-stderr-{tag}.log" and stderr["truncated"] is False
    # Docker CLI output artifacts hold Docker's own output, never these streams.
    for name in os.listdir(e.evidence):
        if name.startswith("docker-ops-") and name.endswith(".out"):
            data = (e.evidence / name).read_bytes()
            assert TOKEN not in data and MARKER not in data, name


def test_event_shaped_target_and_console_output_is_never_parsed(e: Env) -> None:
    assert authorize(e)[0] == 0
    docker = hostile(e)
    docker.streams["baseline"] = b""  # the only real event channel is empty
    code, _, _ = execute(e, docker)
    out = outcome(e)
    assert code == 5 and out["verdict"] != "VERIFIED_FOR_CASES" and out["engine_verdict"] != "VERIFIED_FOR_CASES"
    assert creates(docker) == [("baseline", "target"), ("baseline", "verifier")]  # D2: candidate never ran
    assert (e.evidence / "observations-pair-001-baseline.jsonl").read_bytes() == b""
    execution = json.loads((e.evidence / "execution-pair-001-baseline.json").read_text())
    assert execution["stream"]["status"] == "ABSENT" and execution["stream"]["events_received"] == 0


def test_the_journal_holds_only_structured_metadata(e: Env) -> None:
    assert authorize(e)[0] == 0
    assert execute(e, hostile(e))[0] == 0
    lines = journal(e)
    assert lines and all(line["format"] == JOURNAL_FORMAT for line in lines)
    assert check_operation_journal(e.evidence, "docker-ops.jsonl") == []
    for line in lines:
        assert not {"stdout", "stderr"} & set(line) or line["phase"] == "completed"
        if line["phase"] == "completed":
            for stream in ("stdout", "stderr"):
                described = line[stream]
                assert set(described) == {"bytes", "sha256", "truncated", "cap", "artifact", "class", "stored"}
                assert isinstance(described["bytes"], int) and described["sha256"].startswith("sha256:")
    logs = [line for line in lines if line["op"] == "logs" and line["phase"] == "completed"]
    assert [line["stderr"]["class"] for line in logs] == ["untrusted-target-stderr"] * 2
    assert all(line["stderr"]["cap"] == TARGET_LOG_STREAM_CAP for line in logs)
    attached = [line for line in lines if line["op"] == "start-attached" and line["phase"] == "completed"]
    assert [line["stdout"]["class"] for line in attached] == ["verifier-event-channel"] * 2
    assert [line["stderr"]["class"] for line in attached] == ["untrusted-verifier-console"] * 2
    stream = (e.evidence / "verifier-stream-pair-001-baseline.bin").read_bytes()
    assert attached[0]["stdout"]["sha256"] == "sha256:" + __import__("hashlib").sha256(stream).hexdigest()


def test_a_failed_target_log_read_is_recorded_not_treated_as_empty(e: Env) -> None:
    assert authorize(e)[0] == 0
    docker = fake(e)
    docker.logs_fail = True
    code, term, _ = execute(e, docker)
    out = outcome(e)
    assert code == 4 and out["evidence_status"] == "INCOMPLETE" and out["verdict"] is None
    assert out["engine_verdict"] == "INCONCLUSIVE" and out["lifecycle"] == "INTERRUPTED"
    revision = json.loads((e.evidence / "revision-pair-001-baseline.json").read_text())
    for prefix in ("untrusted-target-stdout", "untrusted-target-stderr"):
        described = revision["untrusted_outputs"][prefix]
        assert described["capture"] == "CAPTURE_FAILED" and described["artifact"] is None
        assert described["detail"] == "the read exited 1"
        assert not (e.evidence / f"{prefix}-pair-001-baseline.log").exists()
    assert any("output capture failed" in f for f in out["evidence_failures"])
    assert "EVIDENCE_WRITE_FAILED" in out["stop_reason"]  # stopped before the candidate


def test_truncated_target_output_is_bounded_and_recorded(e: Env) -> None:
    assert authorize(e)[0] == 0
    docker = fake(e)
    real = docker.run

    def run(op: Any) -> Any:
        if isinstance(op, Logs):
            assert op.stdout_cap == op.stderr_cap == TARGET_LOG_STREAM_CAP
            return ok(op, b"o" * 16, stderr=b"e" * 32, stderr_truncated=True)
        return real(op)

    docker.run = run  # type: ignore[method-assign]
    assert execute(e, docker)[0] == 0
    revision = json.loads((e.evidence / "revision-pair-001-candidate.json").read_text())
    stderr = revision["untrusted_outputs"]["untrusted-target-stderr"]
    assert stderr["truncated"] is True and stderr["bytes"] == 32 and stderr["capture"] == "CAPTURED"
    logs = [line for line in journal(e) if line["op"] == "logs" and line["phase"] == "completed"]
    assert all(line["stderr"]["truncated"] is True for line in logs)


def test_each_stream_has_its_own_enforced_cap(tmp_path: Path) -> None:
    script = "import os; os.write(1, b'o' * 300); os.write(2, b'e' * 5000)"
    result = run_bounded([sys.executable, "-I", "-c", script], env={"PATH": "/usr/bin:/bin"}, timeout_seconds=30,
                         stdout_cap=1000, stderr_cap=1024)
    assert result.stdout == b"o" * 300 and not result.stdout_truncated
    assert result.stderr == b"e" * 1024 and result.stderr_truncated
    cid = ContainerId("c" * 64)
    assert stderr_cap_of(Inspect(ContainerRef(cid.value))) == DEFAULT_STDERR_CAP
    assert stderr_cap_of(Logs(cid, stdout_cap=10, stderr_cap=20)) == 20
    assert_no_forbidden_tokens(StartAttached(cid, timeout_seconds=10, stdout_cap=100, stderr_cap=4 * 1024 * 1024))
    with pytest.raises(PolicyViolation, match="bounds"):
        assert_no_forbidden_tokens(StartAttached(cid, timeout_seconds=10, stdout_cap=100,
                                                 stderr_cap=4 * 1024 * 1024 + 1))
    with pytest.raises(PolicyViolation, match="stderr cap"):
        stderr_cap_of(Logs(cid, stderr_cap=0))


# ------------------------------------------------------------------ 5: the recorder


def _recorder(tmp_path: Path, docker: Any, **kwargs: Any) -> RecordingExecutor:
    from test_authorized_run import private

    evidence = RunEvidence.claim(private(tmp_path / "ev") / "runs", RUN_ID)
    return RecordingExecutor(docker, evidence, **kwargs)


def test_operation_lines_carry_bounded_utc_timestamps(tmp_path: Path) -> None:
    from _run_fixtures import FakeDocker

    clock = Ticking()
    recorder = _recorder(tmp_path, FakeDocker(), wall_clock=clock)
    recorder.run(Inspect(ContainerRef("c" * 64)))  # a failed inspect is still journaled
    lines = [json.loads(x) for x in (recorder.evidence.directory / "docker-ops.jsonl").read_text().splitlines()]
    assert [line["phase"] for line in lines] == ["requested", "completed"]
    done = lines[1]
    assert STAMP_RE.match(done["started_at"]) and STAMP_RE.match(done["finished_at"])
    assert done["started_at"] < done["finished_at"] and done["monotonic_duration_seconds"] >= 0
    assert done["termination"] == "EXITED" and done["returncode"] == 1 and done["timed_out"] is False
    assert done["stderr"]["stored"] == "STORED"  # the client's error text is an artifact, not inline
    assert (recorder.evidence.directory / done["stderr"]["artifact"]).read_bytes().startswith(b"Error")
    with pytest.raises(ValueError, match="timezone-aware"):
        utc_stamp(datetime(2026, 10, 13, 12, 0))


def test_an_interrupted_operation_has_no_invented_end(tmp_path: Path) -> None:
    class Interrupting:
        def run(self, op: Any) -> Any:
            raise RunTerminated("SIGTERM")

    recorder = _recorder(tmp_path, Interrupting())
    with pytest.raises(RunTerminated):
        recorder.run(Inspect(ContainerRef("c" * 64)))
    lines = [json.loads(x) for x in (recorder.evidence.directory / "docker-ops.jsonl").read_text().splitlines()]
    assert lines[-1]["phase"] == "interrupted" and lines[-1]["finished_at"] is None
    assert lines[-1]["termination"] == "INTERRUPTED" and lines[-1]["exception_type"] == "RunTerminated"
    assert check_operation_journal(recorder.evidence.directory, "docker-ops.jsonl") == []


def test_the_output_budget_and_write_failures_are_recorded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from _run_fixtures import FakeDocker

    from patchproof.runner import run_evidence

    recorder = _recorder(tmp_path, FakeDocker())
    monkeypatch.setattr(run_evidence, "MAX_DOCKER_OUTPUT_BYTES", 10)
    recorder.run(Inspect(ContainerRef("c" * 64)))  # 'Error: No such container: ...' exceeds 10 bytes
    lines = [json.loads(x) for x in (recorder.evidence.directory / "docker-ops.jsonl").read_text().splitlines()]
    assert lines[-1]["stderr"]["stored"] == "NOT_STORED_BUDGET" and lines[-1]["stderr"]["artifact"] is None
    assert lines[-1]["stderr"]["bytes"] > 10 and recorder.failures == [
        "output: op 1 stderr not stored: output budget exhausted"]
    monkeypatch.setattr(run_evidence, "MAX_DOCKER_OUTPUT_BYTES", 1 << 20)

    def refuse(self: Any, name: str, data: bytes) -> str:
        raise run_evidence.EvidenceError("synthetic")

    monkeypatch.setattr(RunEvidence, "write", refuse)
    recorder.run(Inspect(ContainerRef("c" * 64)))
    lines = [json.loads(x) for x in (recorder.evidence.directory / "docker-ops.jsonl").read_text().splitlines()]
    assert lines[-1]["stderr"]["stored"] == "WRITE_FAILED"
    assert recorder.failures[-1] == "output: op 2 stderr: EvidenceError"


def test_a_journal_failure_never_blocks_cleanup(e: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    from patchproof.runner import run_evidence

    assert authorize(e)[0] == 0
    docker = fake(e)
    real = RunEvidence.append_line

    def append(self: Any, name: str, value: Any) -> None:
        if name == "docker-ops.jsonl" and value.get("op") == "start-attached":
            raise run_evidence.EvidenceError("synthetic journal failure")
        real(self, name, value)

    monkeypatch.setattr(RunEvidence, "append_line", append)
    code, _, _ = execute(e, docker)
    out = outcome(e)
    assert code == 4 and out["evidence_status"] == "INCOMPLETE" and out["verdict"] is None
    assert out["cleanup_status"] == "COMPLETE" and sorted(docker.removed) == sorted(docker.created)
    assert creates(docker) == [("baseline", "target"), ("baseline", "verifier")]  # nothing new after the failure
    assert any(f.startswith("journal: docker-ops.jsonl") for f in out["evidence_failures"])


def test_after_a_journal_failure_creation_is_refused_but_removal_proceeds(tmp_path: Path) -> None:
    from _run_fixtures import FakeDocker

    from patchproof.runner.docker_cli import Remove

    recorder = _recorder(tmp_path, FakeDocker())
    recorder.failures.append("journal: docker-ops.jsonl line 1 requested: OSError")
    with pytest.raises(PolicyViolation, match="journal is unavailable"):
        recorder.run(StartAttached(ContainerId("d" * 64), timeout_seconds=5, stdout_cap=10))
    recorder.run(Remove(ContainerId("c" * 64)))
    assert recorder.operations == 1


def test_verify_evidence_checks_journal_artifacts_and_keys(e: Env) -> None:
    from test_authorized_run import writable

    assert authorize(e)[0] == 0
    assert execute(e)[0] == 0
    assert journal_format(e.evidence) == JOURNAL_FORMAT
    writable(e.evidence)
    lines = journal(e)
    stored = next(line for line in lines if line["phase"] == "completed" and line["stdout"]["stored"] == "STORED")
    (e.evidence / stored["stdout"]["artifact"]).write_bytes(b"[]")
    problems = verify_evidence(e.evidence)["problems"]
    assert f"docker-ops.jsonl line {lines.index(stored) + 1}: stdout artifact differs from the journal" in problems


def test_legacy_v1_journal_lines_are_reported_by_format_not_as_problems(tmp_path: Path) -> None:
    (tmp_path / "docker-ops.jsonl").write_text(json.dumps({"seq": 1, "op": "logs", "phase": "completed",
                                                           "stderr": "inline text"}) + "\n")
    assert check_operation_journal(tmp_path, "docker-ops.jsonl") == []
    assert journal_format(tmp_path) == "v1"
    (tmp_path / "docker-ops.jsonl").write_text(json.dumps({
        "format": JOURNAL_FORMAT, "seq": 1, "op": "logs", "argv_tail": [], "started_at": "x", "phase": "requested",
        "stderr": "raw output smuggled into a v2 line"}) + "\n")
    assert check_operation_journal(tmp_path, "docker-ops.jsonl") == [
        "docker-ops.jsonl line 1: unexpected keys ['stderr']"]


# ------------------------------------------------------------------ 4: timestamps


def test_evaluated_at_is_taken_at_evaluation_and_ordered(e: Env) -> None:
    assert authorize(e)[0] == 0
    clock = Ticking()
    docker = fake(e)
    assert run_with(e, docker, clock) == 0
    out = outcome(e)
    times = out["timestamps"]
    verdict = json.loads((e.evidence / "verdict.json").read_text())
    assert verdict["evaluated_at"] == times["evaluated_at"]
    assert all(STAMP_RE.match(times[k]) for k in ("execution_started_at", "evaluated_at", "execution_finished_at"))
    assert times["execution_started_at"] < times["evaluated_at"] < times["execution_finished_at"]
    assert times["order"] == "CONSISTENT"
    lines = journal(e)
    last_revision_op = max(line["finished_at"] for line in lines if line["phase"] == "completed"
                           and line["op"] in ("remove", "force-remove"))
    assert last_revision_op < times["evaluated_at"]  # after the last revision's cleanup, not at the start
    first_after_inventory = min(line["started_at"] for line in lines if line["op"] == "snapshot"
                                and line["started_at"] > times["evaluated_at"])
    assert times["evaluated_at"] < first_after_inventory


def test_a_backwards_clock_is_reported_never_corrected(e: Env) -> None:
    assert authorize(e)[0] == 0
    assert run_with(e, fake(e), Ticking(step=timedelta(milliseconds=-1))) in (0, 5)
    times = outcome(e)["timestamps"]
    assert times["order"] == "INCONSISTENT" and times["execution_started_at"] > times["execution_finished_at"]


def test_run_comparison_reads_a_callable_evaluation_time_once_after_the_revisions(e: Env) -> None:
    assert authorize(e)[0] == 0
    assembled = assemble_run(e.env, RUN_ID)
    docker = fake(e)
    calls: list[int] = []

    def evaluated_at() -> str:
        calls.append(len(docker.log))
        return "2026-10-13T12:00:09.000001Z"

    result = run_comparison(docker, assembled.plan, assembled.approvals.values(),
                            OwnershipRegistry(assembled.plan.ownership), clock=FakeClock(), evaluated_at=evaluated_at)
    assert calls == [len(docker.log)] and result.verdict["evaluated_at"] == "2026-10-13T12:00:09.000001Z"


def test_the_engine_still_rejects_naive_or_malformed_times() -> None:
    from patchproof.core.verdicts import TIMESTAMP_RE

    assert TIMESTAMP_RE.fullmatch(utc_stamp(NOW)) and utc_stamp(NOW) == "2026-10-13T12:00:00.000000Z"
    assert not TIMESTAMP_RE.fullmatch("2026-10-13T12:00:00+00:00")


# ------------------------------------------------------------------ 7: interruption point


@pytest.fixture
def pipe() -> Iterator[tuple[int, int]]:
    r, w = os.pipe()
    yield r, w
    for fd in (r, w):
        try:
            os.close(fd)
        except OSError:
            pass


def test_interruption_point_refuses_unsafe_configuration(pipe: tuple[int, int], tmp_path: Path) -> None:
    _, w = pipe
    for bad in ({"run_id": "run-x"}, {"wait_seconds": 0.5}, {"wait_seconds": 61}, {"wait_seconds": True},
                {"report_fd": 1}, {"report_fd": 2}):
        with pytest.raises(PolicyViolation):
            InterruptionPoint(**{"run_id": RUN_ID, "report_fd": w, "wait_seconds": 5, **bad})
    regular = os.open(tmp_path / "f", os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        with pytest.raises(PolicyViolation, match="pipe"):
            InterruptionPoint(RUN_ID, regular, 5)
    finally:
        os.close(regular)


TARGET_ID, VERIFIER_ID = "c" * 64, "d" * 64


def reached(**change: Any) -> CheckpointState:
    """The runner's facts at the reviewed synchronization point, optionally changed."""
    values: dict[str, Any] = {"pair": 1, "side": "baseline", "stage": "target-ready", "target_id": TARGET_ID,
                              "target_started": True, "target_readiness": "READY", "verifier_id": VERIFIER_ID,
                              "verifier_gate_passed": True, "verifier_started": False}
    return CheckpointState(**{**values, **change})


def report_for(pid: int, run_id: str = RUN_ID, **change: Any) -> dict[str, Any]:
    return {"checkpoint": "baseline-target-ready", "pid": pid, "run_id": run_id, "target_id": TARGET_ID,
            "target_readiness": "READY", "verifier_id": VERIFIER_ID,
            "verifier_state": "CREATED_INSPECTED_NOT_STARTED", **change}


def without_deadline(report: dict[str, Any] | None, wait: float) -> dict[str, Any]:
    """The report minus its send-by time, after checking that time: the wait's end minus its margin."""
    assert report is not None
    send_by = report.pop("send_by_monotonic")
    margin = min(5.0, wait / 2)
    assert time.monotonic() - 60 < send_by - (wait - margin) <= time.monotonic()
    return report


def test_interruption_point_reports_once_then_fails_closed(pipe: tuple[int, int]) -> None:
    r, w = pipe
    point = InterruptionPoint(RUN_ID, w, 1)
    with pytest.raises(InterruptionTestAborted, match="no signal within 1"):
        point(reached(), FakeClock())
    assert without_deadline(json.loads(os.read(r, 512)), 1) == report_for(os.getpid())
    assert without_deadline(dict(point.report or {}), 1) == report_for(os.getpid())
    assert point.observed is None and point.closed
    with pytest.raises(InterruptionTestAborted, match="already used"):
        point(reached(), FakeClock())


@pytest.mark.parametrize(("change", "problem"), [
    ({"side": "candidate"}, "not the reviewed stage"),
    ({"pair": 2}, "not the reviewed stage"),
    ({"target_started": False}, "has not started and passed readiness"),
    ({"target_readiness": "READINESS_TIMEOUT"}, "has not started and passed readiness"),
    ({"verifier_gate_passed": False}, "not passed its pre-start inspection"),
    ({"verifier_started": True}, "already started"),
    ({"verifier_id": TARGET_ID}, "two distinct full IDs"),
    ({"target_id": "c" * 12}, "two distinct full IDs"),
])
def test_interruption_point_reports_nothing_in_any_other_state(pipe: tuple[int, int], change: dict[str, Any],
                                                               problem: str) -> None:
    r, w = pipe
    point = InterruptionPoint(RUN_ID, w, 1)
    with pytest.raises(InterruptionTestAborted, match=problem):
        point(reached(**change), FakeClock())
    assert os.read(r, 512) == b"" and point.report is None  # closed without a report: the controller sends nothing


class SignallingClock(FakeClock):
    """The first sleep at the checkpoint delivers a real SIGTERM to this process."""

    def __init__(self, at_checkpoint: list[bool]) -> None:
        super().__init__()
        self.at_checkpoint = at_checkpoint

    def sleep(self, seconds: float) -> None:
        if self.at_checkpoint and not self.at_checkpoint[-1]:
            self.at_checkpoint.append(True)
            os.kill(os.getpid(), signal.SIGTERM)
            time.sleep(1)  # the handler raises out of this sleep
        super().sleep(seconds)


def _interruption_run(e: Env, point: InterruptionPoint, clock: Any, docker: Any) -> Any:
    assembled = assemble_run(e.env, RUN_ID)
    evidence = RunEvidence.claim(e.env.evidence_root, RUN_ID)
    recorder = RecordingExecutor(docker, evidence, max_creations=2)
    return run_comparison(recorder, assembled.plan, assembled.approvals.values(),
                          OwnershipRegistry(assembled.plan.ownership), clock=clock,
                          evaluated_at=lambda: utc_stamp(NOW), checkpoint=point)


def test_sigterm_at_the_checkpoint_cleans_up_both_baseline_containers(e: Env, pipe: tuple[int, int]) -> None:
    r, w = pipe
    assert authorize(e)[0] == 0
    docker = fake(e)
    at_checkpoint: list[bool] = []
    point = InterruptionPoint(RUN_ID, w, 5)
    original = point.__call__

    def tracked(state: CheckpointState, clock: Any) -> None:
        at_checkpoint.append(False)
        original(state, clock)

    with graceful_termination() as received:
        comparison = _interruption_run(e, tracked, SignallingClock(at_checkpoint), docker)  # type: ignore[arg-type]
    assert received.received == ["SIGTERM"] and point.observed == "SIGTERM"
    (result,) = comparison.revisions
    assert result.interruption == "SIGTERM" and result.execution.verifier.termination == "NOT_STARTED"
    assert comparison.verdict_input.run_termination == "interrupted"
    assert (comparison.verdict["verdict"], comparison.verdict["decision_rule"]) == ("INCONCLUSIVE", "V-05")
    assert json.loads(os.read(r, 1024))["checkpoint"] == "baseline-target-ready"
    assert creates(docker) == [("baseline", "target"), ("baseline", "verifier")]
    assert [op.op_name for op in docker.log if op.op_name in ("start", "start-attached")] == ["start"]
    assert sorted(docker.removed) == sorted(docker.created) and len(docker.created) == 2
    lines = journal(e)
    assert not any(line["op"] == "start-attached" for line in lines)  # the verifier never started
    assert check_operation_journal(e.evidence, "docker-ops.jsonl") == []


def test_no_signal_fails_closed_without_retry(e: Env, pipe: tuple[int, int]) -> None:
    _, w = pipe
    assert authorize(e)[0] == 0
    docker = fake(e)
    comparison = _interruption_run(e, InterruptionPoint(RUN_ID, w, 2), FakeClock(), docker)
    (result,) = comparison.revisions
    assert result.interruption.startswith("ABORTED") and "without retry" in result.interruption
    assert comparison.verdict["verdict"] == "INCONCLUSIVE"
    assert creates(docker) == [("baseline", "target"), ("baseline", "verifier")]
    assert sorted(docker.removed) == sorted(docker.created)
    assert not any(op.op_name == "start-attached" for op in docker.log)


def test_an_unreadable_report_channel_fails_closed(e: Env, pipe: tuple[int, int]) -> None:
    r, w = pipe
    os.close(r)  # the controller is gone: writing raises EPIPE (SIGPIPE is ignored by Python)
    assert authorize(e)[0] == 0
    docker = fake(e)
    comparison = _interruption_run(e, InterruptionPoint(RUN_ID, w, 2), FakeClock(), docker)
    assert "could not be reported" in comparison.revisions[0].interruption
    assert sorted(docker.removed) == sorted(docker.created) and len(docker.created) == 2


def test_the_interruption_budget_refuses_a_third_container(tmp_path: Path) -> None:
    from _run_fixtures import FakeDocker

    recorder = _recorder(tmp_path, FakeDocker(), max_creations=2)

    class Create:
        op_name = "run-create"

        def argv_tail(self) -> list[str]:
            return ["container", "create"]

    recorder.creations = 2
    with pytest.raises(PolicyViolation, match="at most two"):
        recorder.run(Create())  # type: ignore[arg-type]
    for bad in (0, 5):
        with pytest.raises(PolicyViolation, match="between one and four"):
            _recorder(tmp_path / str(bad), FakeDocker(), max_creations=bad).run(Create())  # type: ignore[arg-type]


def test_the_production_path_cannot_reach_the_interruption_point() -> None:
    assert "checkpoint" not in inspect.signature(authorized_run.execute_authorized_run).parameters
    for module in (authorized_run, run_papertrail_once):
        source = inspect.getsource(module)
        assert "checkpoint" not in source and "interruption_point" not in source, module.__name__


def test_the_current_authorization_contract_cannot_express_an_interruption_test(e: Env) -> None:
    from patchproof.core.records import RecordError, validate_record
    from patchproof.core.records.authorization import RunPlanDocument

    document = assemble_run(e.env, RUN_ID).document.model_dump(mode="json")
    for change in ({"containers": {**document["containers"], "max_creations": 2,
                                   "sequence": document["containers"]["sequence"][:2]}},
                   {"plan_kind": "papertrail-interruption-test-v1"}):
        with pytest.raises(RecordError):
            validate_record(RunPlanDocument, {**document, **change}, "run-plan")


# ------------------------------------------------------------------ 7: controller, with real local processes

_CHILD = """
import json, os, sys, time
from patchproof.runner.interrupts import RunTerminated, graceful_termination
from patchproof.runner.interruption_point import InterruptionPoint, InterruptionTestAborted
from patchproof.runner.revision import CheckpointState

class Clock:
    def monotonic(self): return time.monotonic()
    def sleep(self, s): time.sleep(s)

def report(change):
    return json.dumps({"checkpoint": "baseline-target-ready", "pid": os.getpid(), "run_id": run_id,
                       "target_id": "c" * 64, "target_readiness": "READY", "verifier_id": "d" * 64,
                       "verifier_state": "CREATED_INSPECTED_NOT_STARTED",
                       "send_by_monotonic": time.monotonic() + 60, **change}).encode() + b"\\n"

fd, run_id, mode = int(sys.argv[1]), sys.argv[2], sys.argv[3]
with graceful_termination() as received:
    if mode == "silent":
        time.sleep(5); print("SILENT-END"); sys.exit(0)
    if mode in ("foreign-pid", "target-not-ready", "verifier-started", "extra-key", "late", "no-deadline",
                "wrong-stage"):
        change = {"foreign-pid": {"pid": 1}, "target-not-ready": {"target_readiness": "READINESS_TIMEOUT"},
                  "wrong-stage": {"checkpoint": "verifier-ready"},
                  "verifier-started": {"verifier_state": "STARTED"}, "extra-key": {"command": "rm"},
                  "late": {"send_by_monotonic": time.monotonic() - 1},
                  "no-deadline": {"send_by_monotonic": True}}[mode]
        os.write(fd, report(change))
        os.close(fd); time.sleep(3); print("NOT-SIGNALLED"); sys.exit(0)
    if mode == "exit-after-report":
        os.write(fd, report({}))
        sys.exit(0)
    if mode == "before-target-start":
        state = CheckpointState(1, "baseline", "target-ready", "c" * 64, False, "NOT_STARTED", "d" * 64, True, False)
    else:
        state = CheckpointState(1, "baseline", "target-ready", "c" * 64, True, "READY", "d" * 64, True, False)
    try:
        InterruptionPoint(run_id, fd, 3)(state, Clock())
    except RunTerminated as exc:
        os.kill(os.getpid(), 15)  # a second signal during "cleanup" is ignored
        time.sleep(0.2)
        print("TERMINATED", exc.signal_name, received.received)
    except InterruptionTestAborted as exc:
        print("ABORTED", exc)
"""

OTHER_RUN = "run-" + "ab" * 16


def _spawn(mode: str, run_id: str = RUN_ID) -> tuple[subprocess.Popen[bytes], int]:
    r, w = os.pipe()
    child = subprocess.Popen([sys.executable, "-c", _CHILD, str(w), run_id, mode], pass_fds=(w,),
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    os.close(w)
    return child, r


def _finish(child: subprocess.Popen[bytes]) -> str:
    out, err = child.communicate(timeout=30)
    assert child.returncode == 0, err.decode()[-2000:]
    return out.decode()


def test_the_controller_signals_its_own_child_once_at_the_checkpoint() -> None:
    child, r = _spawn("checkpoint")
    delivery = deliver_at_checkpoint(child, r, run_id=RUN_ID, report_timeout_seconds=20)
    assert delivery.delivered and delivery.reason == "SIGTERM_SENT" and delivery.pid == child.pid
    assert delivery.signals_sent == 1 and without_deadline(dict(delivery.report or {}), 3) == report_for(child.pid)
    assert "TERMINATED SIGTERM ['SIGTERM', 'SIGTERM']" in _finish(child)


@pytest.mark.parametrize(("mode", "run_id", "reason", "child_says"), [
    ("checkpoint", OTHER_RUN, "WRONG_STAGE_OR_RUN", "ABORTED no signal within 3 seconds"),
    ("foreign-pid", RUN_ID, "REPORT_FROM_ANOTHER_PROCESS", "NOT-SIGNALLED"),
    ("wrong-stage", RUN_ID, "WRONG_STAGE_OR_RUN", "NOT-SIGNALLED"),
    ("silent", RUN_ID, "NO_CHECKPOINT_REPORT_IN_TIME", "SILENT-END"),
    ("target-not-ready", RUN_ID, "TARGET_NOT_READY", "NOT-SIGNALLED"),
    ("verifier-started", RUN_ID, "VERIFIER_NOT_IN_REVIEWED_STATE", "NOT-SIGNALLED"),
    ("extra-key", RUN_ID, "MALFORMED_REPORT", "NOT-SIGNALLED"),
    ("late", RUN_ID, "REPORT_TOO_LATE", "NOT-SIGNALLED"),
    ("no-deadline", RUN_ID, "MALFORMED_REPORT", "NOT-SIGNALLED"),
    ("before-target-start", RUN_ID, "NO_CHECKPOINT_REPORT", "ABORTED the checkpoint was reached in the wrong state"),
])
def test_the_controller_sends_nothing_unless_the_report_is_exact(mode: str, run_id: str, reason: str,
                                                                 child_says: str) -> None:
    child, r = _spawn(mode, RUN_ID)
    # Only the silent child tests the report timeout itself. Every other child does report, so it gets
    # time to start a Python interpreter under load; a 1 s bound made those cases race (PP-009 finding).
    timeout = 1 if mode == "silent" else 20
    delivery = deliver_at_checkpoint(child, r, run_id=run_id, report_timeout_seconds=timeout)
    assert not delivery.delivered and delivery.reason == reason and delivery.signals_sent == 0
    assert child_says in _finish(child)


def test_the_controller_never_signals_an_exited_child() -> None:
    child, r = _spawn("exit-after-report")
    child.wait(timeout=30)
    delivery = deliver_at_checkpoint(child, r, run_id=RUN_ID, report_timeout_seconds=5)
    assert not delivery.delivered and delivery.reason == "CHILD_ALREADY_EXITED"


# ------------------------------------------------------------------ 8: after an interrupted run


def test_after_an_interrupted_run_the_authorization_is_spent_and_recovery_finds_nothing(e: Env) -> None:
    assert authorize(e)[0] == 0
    docker = fake(e)
    docker.on_attach = lambda side: os.kill(os.getpid(), signal.SIGTERM) if side == "baseline" else None
    with graceful_termination():
        code, _, _ = execute(e, docker)
    assert code == 4 and manifest(e)["status"] == "INCOMPLETE"
    out = outcome(e)
    assert out["lifecycle"] == "INTERRUPTED" and out["verdict"] is None and out["cleanup_status"] == "COMPLETE"
    attached = [line for line in journal(e) if line["op"] == "start-attached"]
    assert [line["phase"] for line in attached] == ["requested", "interrupted"]
    assert attached[-1]["finished_at"] is None and attached[-1]["termination"] == "INTERRUPTED"
    assert verify_evidence(e.evidence)["state"] == "CONSISTENT"

    again = fake(e)
    code, term, _ = execute(e, again)
    assert code == 2 and again.log == [] and "no unused run authorization" in term.output()
    start = len(docker.log)
    assert recover(e.env, FakeTerminal({"Run to inspect": RUN_ID}), lambda: docker) == 0
    assert {op.op_name for op in docker.log[start:]} <= {"inspect", "snapshot"}
    (directory,) = (e.env.evidence_root.parent / "recoveries" / RUN_ID).iterdir()
    recovered = json.loads((directory / "outcome.json").read_text())
    assert recovered["result"] == "NOTHING_TO_REMOVE" and recovered["evidence_failures"] == []


def test_failed_capture_of_cleanup_listing_output_is_explicit(tmp_path: Path) -> None:
    from _run_fixtures import FakeDocker

    docker = FakeDocker()
    docker.listing_fails = {"containers"}
    recorder = _recorder(tmp_path, docker)
    from patchproof.runner.run_evidence import capture_inventory

    inventory = capture_inventory(recorder, ("containers",))
    assert not inventory.complete
    line = [json.loads(x) for x in (recorder.evidence.directory / "docker-ops.jsonl").read_text().splitlines()][-1]
    assert line["returncode"] == 1 and line["stdout"]["stored"] == "EMPTY" and line["stderr"]["stored"] == "STORED"


def test_the_docker_client_passes_each_operation_s_own_caps(monkeypatch: pytest.MonkeyPatch) -> None:
    from patchproof.runner import docker_cli

    seen: list[tuple[str, int, int]] = []

    def bounded(argv: Any, *, env: Any, timeout_seconds: float, stdout_cap: int, stderr_cap: int,
                op_name: str) -> Any:
        seen.append((op_name, stdout_cap, stderr_cap))
        return docker_cli.CommandResult(op_name, tuple(argv), 0, b"", b"", False, False, False, 0.0)

    monkeypatch.setattr(docker_cli, "run_bounded", bounded)
    cli = docker_cli.DockerCli("/usr/local/bin/docker", "/nonexistent")
    cid = ContainerId("c" * 64)
    cli.run(Logs(cid, stdout_cap=TARGET_LOG_STREAM_CAP, stderr_cap=TARGET_LOG_STREAM_CAP))
    cli.run(StartAttached(cid, timeout_seconds=10, stdout_cap=100, stderr_cap=2048))
    cli.run(Inspect(ContainerRef(cid.value)))
    assert seen == [("logs", TARGET_LOG_STREAM_CAP, TARGET_LOG_STREAM_CAP), ("start-attached", 100, 2048),
                    ("inspect", 512 * 1024, DEFAULT_STDERR_CAP)]


def test_a_pipe_on_a_standard_stream_is_still_refused(pipe: tuple[int, int]) -> None:
    _, w = pipe
    saved = os.dup(0)
    try:
        os.dup2(w, 0)  # stdin is now a real pipe: refused for its number, not its type
        with pytest.raises(PolicyViolation, match="inherited pipe"):
            InterruptionPoint(RUN_ID, 0, 5)
    finally:
        os.dup2(saved, 0)
        os.close(saved)


def test_recovery_with_a_failed_journal_write_is_incomplete(e: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    from patchproof.runner import run_evidence

    assert authorize(e)[0] == 0
    code, _, docker = execute(e)
    assert code == 0
    real = RunEvidence.append_line

    def append(self: Any, name: str, value: Any) -> None:
        if "recoveries" in str(self.directory) and name == "docker-ops.jsonl":
            raise run_evidence.EvidenceError("synthetic")
        real(self, name, value)

    monkeypatch.setattr(RunEvidence, "append_line", append)
    assert recover(e.env, FakeTerminal({"Run to inspect": RUN_ID}), lambda: docker) == 0
    (directory,) = (e.env.evidence_root.parent / "recoveries" / RUN_ID).iterdir()
    recovered = json.loads((directory / "outcome.json").read_text())
    assert recovered["evidence_failures"] and json.loads((directory / "manifest.json").read_text())[
        "status"] == "INCOMPLETE"


def test_a_verdict_time_other_than_the_recorded_one_is_incomplete(e: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    assert authorize(e)[0] == 0
    real = authorized_run.run_comparison

    def shifted(*args: Any, **kwargs: Any) -> Any:
        result = real(*args, **kwargs)
        result.verdict["evaluated_at"] = "2000-01-01T00:00:00.000000Z"
        return result

    monkeypatch.setattr(authorized_run, "run_comparison", shifted)
    code, _, _ = execute(e)
    out = outcome(e)
    assert code == 4 and out["verdict"] is None
    assert "the verdict's evaluated_at is not the recorded evaluation time" in out["evidence_failures"]
