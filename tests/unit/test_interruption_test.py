"""PP-008: the deliberate interruption test, Docker-free.

Covers the separate `interruption-test-authorization` contract and its private single-use
store, the owner command, the baseline-only driver with its two-container budget, the
lifecycle/verdict/exit-code classification, the controller and its runner child (real local
processes for the pipe and the signal), and recovery afterwards.

Everything is SYNTHETIC and lives in temporary directories: a renamed copy of the PaperTrail
pack with a synthetic approval, a snapshot of a freshly generated PP-006 reference
repository, and the scripted fake Docker (`_run_fixtures.FakeDocker`). No real store, real
evidence directory or Docker daemon is touched, and PaperTrail is never executed.
"""

from __future__ import annotations

import copy
import dataclasses
import inspect
import json
import os
import pickle
import signal
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from _run_fixtures import FakeDocker
from test_authorized_run import (  # noqa: F401 - `shared` is a fixture
    NOW,
    RUN_ID,
    Env,
    FakeClock,
    FakeTerminal,
    creates,
    make_env,
    shared,
)

from patchproof import interruption_child, interruption_test, recover_run, run_papertrail_once
from patchproof.core.interruption_authorizations import (
    InterruptionAuthorizationError,
    InterruptionAuthorizationStore,
    check_interruption_authorization,
    interruption_authorization_phrase,
    interruption_execution_phrase,
    interruption_plan_sha256,
    parse_claim,
)
from patchproof.core.records import RecordError, load_record, validate_record
from patchproof.core.records.authorization import RunAuthorization
from patchproof.core.records.interruption import InterruptionPlanDocument, InterruptionTestAuthorization
from patchproof.core.run_authorizations import RunAuthorizationError, RunAuthorizationStore
from patchproof.interruption_authorization import run_interruption_authorization
from patchproof.interruption_child import ChildRefused, parse_arguments, run_child
from patchproof.interruption_test import Delivery, harness_deviations, run_interruption_test
from patchproof.recover_run import recover
from patchproof.runner import authorized_run, interruption_run
from patchproof.runner.comparison import ComparisonResult, RevisionGate
from patchproof.runner.interrupts import graceful_termination
from patchproof.runner.interruption_plan import assemble_interruption
from patchproof.runner.interruption_point import InterruptionPoint
from patchproof.runner.interruption_run import execute_interruption_test, lifecycle_exit_code
from patchproof.runner.papertrail_plan import RunEnvironment
from patchproof.runner.policy import PolicyViolation
from patchproof.runner.run_evidence import EvidenceError, RunEvidence, check_operation_journal, verify_evidence
from patchproof.runner.run_plan import APPROVED_RUN_IMAGES

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = json.loads((ROOT / "schemas/examples/valid/"
                      "interruption-test-authorization--papertrail-r1-baseline-example.json").read_text())
RUN_EXAMPLE = json.loads((ROOT / "schemas/examples/valid/run-authorization--papertrail-r1-r3-example.json").read_text())
GOOD = {"Your name": "Synthetic Owner", "Rationale": "Synthetic interruption-test authorization for unit tests.",
        "Authorization scope": "Unit tests in a temporary directory; authorizes nothing real."}
POLL = 0.05  # interruption_point._POLL_SECONDS: the only sleep the checkpoint makes


@dataclasses.dataclass
class IEnv:
    base: Env
    env: RunEnvironment

    @property
    def evidence(self) -> Path:
        return self.env.evidence_root / RUN_ID


@pytest.fixture
def ie(tmp_path: Path, shared: Path) -> IEnv:  # noqa: F811
    base = make_env(tmp_path, shared)
    os.mkdir(base.env.authorization_store, 0o700)  # the ordinary store exists (empty), as on a real installation
    env = replace(base.env, authorization_store=base.data / "interruption-authorizations",
                  evidence_root=base.data / "evidence" / "interruption-tests")
    return IEnv(base, env)


def authorize(ie: IEnv, overrides: dict[str, str] | None = None, run_id: str = RUN_ID,
              on_prompt: dict[str, Any] | None = None) -> tuple[int, FakeTerminal]:
    phrase = interruption_authorization_phrase(assemble_interruption(ie.env, run_id).document)
    terminal = FakeTerminal({**GOOD, "Confirmation": phrase, **(overrides or {})}, on_prompt=on_prompt or {})
    return run_interruption_authorization(ie.env, terminal, now=lambda: NOW, new_run_id=lambda: run_id), terminal


def store(ie: IEnv) -> InterruptionAuthorizationStore:
    return InterruptionAuthorizationStore(ie.env.authorization_store)


def docker_for() -> FakeDocker:
    return FakeDocker(records=APPROVED_RUN_IMAGES)


class SignalAtCheckpoint(FakeClock):
    """Delivers a real SIGTERM to this process on the checkpoint's first wait, and only there."""

    def __init__(self, at: float = POLL) -> None:
        super().__init__()
        self.at, self.sent = at, 0

    def sleep(self, seconds: float) -> None:
        if seconds == self.at and not self.sent:
            self.sent += 1
            os.kill(os.getpid(), signal.SIGTERM)
            time.sleep(1)  # the handler raises out of this sleep
        super().sleep(seconds)


def drive(ie: IEnv, docker: FakeDocker, clock: Any, *, wait: float = 5) -> tuple[Any, int]:
    """Claim and run the driver in-process, as the child does. Returns the outcome and the report read end."""
    s = store(ie)
    stored = s.executable()
    assert stored is not None
    claim_raw = s.claim(stored.record.authorization_id, run_id=RUN_ID, now=NOW)
    assembled = assemble_interruption(ie.env, RUN_ID)
    evidence = RunEvidence.claim(ie.env.evidence_root, RUN_ID)
    r, w = os.pipe()
    point = InterruptionPoint(RUN_ID, w, wait)
    with graceful_termination():
        outcome = execute_interruption_test(ie.env, stored.record, stored.raw, claim_raw, assembled, evidence,
                                            docker, point, clock=clock, now=lambda: NOW)
    return outcome, r


def read_outcome(ie: IEnv) -> dict[str, Any]:
    return dict(json.loads((ie.evidence / "outcome.json").read_text()))


def starts(docker: FakeDocker) -> list[str]:
    return [op.op_name for op in docker.log if op.op_name in ("start", "start-attached")]


# ------------------------------------------------------------------ contract and schema


def test_the_example_is_valid_and_hash_consistent() -> None:
    record = load_record(InterruptionTestAuthorization, json.dumps(EXAMPLE).encode())
    check_interruption_authorization(record)
    assert record.plan_sha256 == interruption_plan_sha256(record.plan)


def test_the_two_contracts_never_accept_each_other() -> None:
    with pytest.raises(RecordError):
        load_record(RunAuthorization, json.dumps(EXAMPLE).encode())
    with pytest.raises(RecordError):
        load_record(InterruptionTestAuthorization, json.dumps(RUN_EXAMPLE).encode())


@pytest.mark.parametrize(("path", "value"), [
    (("revision", "candidate_execution"), True), (("revision", "side"), "candidate"),
    (("containers", "max_creations"), 3), (("containers", "max_started"), 2),
    (("containers", "verifier", "start"), "after-pre-start-inspection-gate"),
    (("interruption", "signal"), "SIGKILL"), (("interruption", "escalation"), "SIGKILL"),
    (("interruption", "signals_sent"), 2), (("interruption", "synchronization_wait_seconds"), 31),
    (("interruption", "automatic_retry"), True), (("expected_outcome", "verdict"), "VERIFIED_FOR_CASES"),
    (("expected_outcome", "lifecycle_exit_code"), 0), (("sources", "candidate"), {}),
])
def test_broader_execution_cannot_be_authorized(path: tuple[str, ...], value: Any) -> None:
    plan = copy.deepcopy(EXAMPLE["plan"])
    cursor = plan
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value
    with pytest.raises(RecordError):
        validate_record(InterruptionPlanDocument, plan, "interruption-plan")


@pytest.mark.parametrize(("change", "message"), [
    ({"containers": "verifier-name"}, "container names"),
    ({"evidence": "elsewhere"}, "evidence destination"),
    ({"plan_sha256": "sha256:" + "0123456789abcdef" * 4}, "not the hash"),
    ({"images": "same"}, "must differ"),
])
def test_semantic_rules_the_schema_cannot_express(change: dict[str, str], message: str) -> None:
    doc = copy.deepcopy(EXAMPLE)
    if "containers" in change:
        doc["plan"]["containers"]["verifier"]["name"] = "pp-run-ffffffffffff-p1-baseline-verifier"
    if "evidence" in change:
        doc["plan"]["evidence"]["destination"] = "evidence/interruption-tests/run-" + "ab" * 16
    if "images" in change:
        doc["plan"]["images"]["verifier_image_id"] = doc["plan"]["images"]["target_image_id"]
    if "plan_sha256" in change:
        doc["plan_sha256"] = change["plan_sha256"]
    else:
        doc["plan_sha256"] = interruption_plan_sha256(validate_record(InterruptionPlanDocument, doc["plan"]))
    record = load_record(InterruptionTestAuthorization, json.dumps(doc).encode())
    with pytest.raises(InterruptionAuthorizationError, match=message):
        check_interruption_authorization(record)


def test_the_recomputed_plan_binds_only_the_r1_baseline_and_the_approved_images(ie: IEnv) -> None:
    run = assemble_interruption(ie.env, RUN_ID)
    d = run.document
    assert set(d.sources.model_dump()) == {"baseline"}
    assert d.sources.baseline.commit_id == "68b2bc0e41cb7e9a074b09f2d97db3e2d2ca288a"
    assert (d.images.target_image_id, d.images.verifier_image_id) == tuple(a.image.value for a in APPROVED_RUN_IMAGES)
    assert (d.containers.max_creations, d.containers.max_started) == (2, 1)
    assert (d.interruption.signal, d.interruption.signals_sent, d.interruption.escalation) == ("SIGTERM", 1, "none")
    assert d.expected_outcome.model_dump() == {
        "lifecycle": "INTERRUPTED", "evidence_status": "INCOMPLETE", "cleanup_status": "COMPLETE",
        "verdict": "INCONCLUSIVE", "decision_rule": "V-05", "lifecycle_exit_code": 20}
    assert run.plan.baseline == run.plan.candidate  # RunPlan's slot only; never executed
    assert interruption_plan_sha256(d) == run.sha256
    assert interruption_authorization_phrase(d) == f"AUTHORIZE INTERRUPTION TEST {RUN_ID} {run.sha256}"
    assert interruption_execution_phrase(d) == f"INTERRUPT {RUN_ID}"


def test_the_test_is_pinned_to_the_r1_baseline_whatever_the_environment_says(ie: IEnv) -> None:
    from patchproof.runner.papertrail_plan import PAPERTRAIL_REVISIONS, PlanError

    swapped = replace(ie.env, revisions={"baseline": PAPERTRAIL_REVISIONS["candidate"],
                                         "candidate": PAPERTRAIL_REVISIONS["baseline"]})
    with pytest.raises(PlanError, match="not the pinned r1 revision"):
        assemble_interruption(swapped, RUN_ID)


# ------------------------------------------------------------------ store: single use, crash safety


def test_authorize_save_scan_claim_once(ie: IEnv) -> None:
    code, terminal = authorize(ie)
    assert code == 0, terminal.output()
    s = store(ie)
    stored = s.executable()
    assert stored is not None and stat.S_IMODE(os.lstat(s.root / f"{stored.record.authorization_id}.json").st_mode) \
        == 0o400
    raw = s.claim(stored.record.authorization_id, run_id=RUN_ID, now=NOW)
    assert s.executable() is None
    claim = parse_claim(raw, stored.record.authorization_id)
    assert (claim.state, claim.run_id, claim.pid) == ("CLAIMED", RUN_ID, os.getpid())
    with pytest.raises(InterruptionAuthorizationError, match="already been claimed"):
        s.claim(stored.record.authorization_id, run_id=RUN_ID, now=NOW)


def test_simultaneous_claims_have_exactly_one_winner(ie: IEnv) -> None:
    assert authorize(ie)[0] == 0
    s = store(ie)
    stored = s.executable()
    assert stored is not None
    barrier, results = threading.Barrier(8), []

    def attempt() -> None:
        barrier.wait()
        try:
            s.claim(stored.record.authorization_id, run_id=RUN_ID, now=NOW)
            results.append("won")
        except InterruptionAuthorizationError:
            results.append("refused")

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == ["refused"] * 7 + ["won"]


def test_a_crash_during_the_claim_leaves_it_consumed(ie: IEnv) -> None:
    assert authorize(ie)[0] == 0
    s = store(ie)
    stored = s.executable()
    assert stored is not None
    fd = os.open(s.root / f"{stored.record.authorization_id}.claim", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    os.close(fd)  # created, never written: the process died here
    records, claims = s.scan()
    assert claims[stored.record.authorization_id].state == "INDETERMINATE" and s.executable() is None
    terminal = FakeTerminal({"To execute": f"INTERRUPT {RUN_ID}"})
    assert run_interruption_test(ie.env, terminal, _never_spawn, now=lambda: NOW) == 2
    assert "no unused interruption-test authorization" in terminal.output()
    logs: list[str] = []
    r, w = os.pipe()
    assert run_child(ie.env, RUN_ID, w, _no_docker, parent_pid=os.getpid(), clock=FakeClock(), now=lambda: NOW,
                     log=logs.append) == 2
    assert "no complete claim" in logs[0] and os.read(r, 64) == b""  # the report channel was closed
    with pytest.raises(InterruptionAuthorizationError, match="no unused authorization to supersede"):
        _supersede(ie, stored.record)


@pytest.mark.parametrize("damage", ["partial", "corrupt-hash", "foreign-run-record", "stray", "claim-other-run"])
def test_a_damaged_store_is_refused(ie: IEnv, damage: str) -> None:
    assert authorize(ie)[0] == 0
    s = store(ie)
    stored = s.executable()
    assert stored is not None
    name = s.root / f"{stored.record.authorization_id}.json"
    os.chmod(name, 0o600)
    if damage == "partial":
        name.write_bytes(stored.raw[: len(stored.raw) // 2])
    elif damage == "corrupt-hash":
        doc = json.loads(stored.raw)
        doc["plan_sha256"] = "sha256:" + "0123456789abcdef" * 4
        name.write_text(json.dumps(doc))
    elif damage == "foreign-run-record":
        (s.root / "rau-0123456789abcdef0123456789abcdef.json").write_text(json.dumps(RUN_EXAMPLE))
    elif damage == "stray":
        (s.root / "notes.txt").write_text("x")
    else:
        s.claim(stored.record.authorization_id, run_id="run-" + "ab" * 16, now=NOW)
    with pytest.raises(InterruptionAuthorizationError):
        store(ie).scan()


def test_the_ordinary_store_refuses_interruption_records(ie: IEnv) -> None:
    assert authorize(ie)[0] == 0
    stored = store(ie).executable()
    assert stored is not None
    root = ie.base.env.authorization_store
    (root / f"{stored.record.authorization_id}.json").write_bytes(stored.raw)
    with pytest.raises(RunAuthorizationError, match="unexpected entry"):
        RunAuthorizationStore(root).scan()


def test_the_store_must_be_private_and_stable(ie: IEnv, tmp_path: Path) -> None:
    assert authorize(ie)[0] == 0
    root = ie.env.authorization_store
    os.chmod(root, 0o755)
    with pytest.raises(InterruptionAuthorizationError, match="0700"):
        store(ie)
    os.chmod(root, 0o700)
    opened = store(ie)
    os.rename(root, tmp_path / "moved")
    os.symlink(tmp_path / "moved", root)
    with pytest.raises(InterruptionAuthorizationError):
        opened.scan()


def _supersede(ie: IEnv, old: InterruptionTestAuthorization, run_id: str = "run-" + "fe" * 16) -> Path:
    from patchproof.core.interruption_authorizations import create_interruption_authorization
    from patchproof.core.run_authorizations import AuthorizationDecision

    document = assemble_interruption(ie.env, run_id).document
    record = create_interruption_authorization(document, AuthorizationDecision(
        "Synthetic Owner", "Replace.", "Tests.", interruption_authorization_phrase(document)), supersedes=old, now=NOW)
    return store(ie).save(record)


def test_only_an_unused_authorization_can_be_superseded(ie: IEnv) -> None:
    assert authorize(ie)[0] == 0
    old = store(ie).executable()
    assert old is not None
    _supersede(ie, old.record)  # unused: allowed, the old record stays and can never execute
    current = store(ie).executable()
    assert current is not None and current.record.supersedes == old.record.authorization_id
    store(ie).claim(current.record.authorization_id, run_id=current.record.plan.run_id, now=NOW)
    with pytest.raises(InterruptionAuthorizationError, match="no unused authorization to supersede"):
        _supersede(ie, current.record, "run-" + "fd" * 16)


@pytest.mark.parametrize("raw", [
    b"", b"{", b'{"authorization_id": "X", "run_id": "run-x", "pid": 5, "claimed_at": "2026-10-13T12:00:00Z"}',
    b'{"authorization_id": "ID", "run_id": "' + RUN_ID.encode() + b'", "pid": true, "claimed_at": '
    b'"2026-10-13T12:00:00Z"}',
    b'{"authorization_id": "ID", "run_id": "' + RUN_ID.encode() + b'", "pid": 5, "claimed_at": '
    b'"2026-10-13T12:00:00Z", "retry": true}',
])
def test_a_claim_is_read_strictly(raw: bytes) -> None:
    assert parse_claim(raw.replace(b'"ID"', b'"iau-' + b"0" * 32 + b'"'), "iau-" + "0" * 32).state == "INDETERMINATE"


# ------------------------------------------------------------------ owner command


def test_the_review_states_what_the_run_can_and_cannot_show(ie: IEnv) -> None:
    code, terminal = authorize(ie)
    out = terminal.output()
    assert code == 0, out
    for text in ("DELIBERATELY INTERRUPTED", "CANNOT produce a verified-fix result", "BASELINE ONLY",
                 APPROVED_RUN_IMAGES[0].image.value, APPROVED_RUN_IMAGES[1].image.value, "at most 2 creations",
                 "never started", "1 SIGTERM", "never SIGKILL", "Residual risks", "NOT killed",
                 "INCONCLUSIVE (V-05", "lifecycle exit code 20", "Cleanup: exact id"):
        assert text in out, text


@pytest.mark.parametrize(("overrides", "message"), [
    ({"Confirmation": f"AUTHORIZE {RUN_ID} sha256:" + "0" * 64}, "does not match"),
    ({"Confirmation": "INTERRUPT " + RUN_ID}, "does not match"),
    ({"Rationale": "AUTHORIZE INTERRUPTION TEST {phrase}"}, "contains the confirmation phrase"),
    ({"Your name": ""}, "is required"),
])
def test_the_owner_command_refuses_without_writing(ie: IEnv, overrides: dict[str, str], message: str) -> None:
    if "{phrase}" in overrides.get("Rationale", ""):
        overrides = {"Rationale": interruption_authorization_phrase(assemble_interruption(ie.env, RUN_ID).document)}
    code, terminal = authorize(ie, overrides)
    assert code == 2 and message in terminal.output() and "Nothing was written" in terminal.output()
    assert store(ie).scan() == ({}, {})


def test_an_input_change_during_review_aborts(ie: IEnv) -> None:
    def change() -> None:
        ie.env.installation_id_file.chmod(0o600)
        ie.env.installation_id_file.write_text("inst-" + "ab" * 16 + "\n")

    code, terminal = authorize(ie, on_prompt={"Confirmation": change})
    assert code == 2 and "an input changed" in terminal.output() and store(ie).scan() == ({}, {})


@pytest.mark.parametrize("module", ["patchproof.interruption_authorization", "patchproof.interruption_test"])
@pytest.mark.parametrize(("args", "env", "stdin", "message"), [
    ((), None, b"Me\nWhy\nScope\nAUTHORIZE INTERRUPTION TEST run-x sha256:x\nINTERRUPT run-x\n",
     "interactive terminal"),
    (("--confirm", "INTERRUPT run-x"), None, b"", "takes no arguments"),
    ((), {"PATCHPROOF_CONFIRM": "yes"}, b"", "environment variables are not accepted"),
])
def test_noninteractive_invocation_is_refused(tmp_path: Path, module: str, args: tuple[str, ...],
                                              env: dict[str, str] | None, stdin: bytes, message: str) -> None:
    home = tmp_path / "home"
    os.mkdir(home, 0o700)
    result = subprocess.run([sys.executable, "-I", "-m", module, *args], input=stdin,
                            env={"PATH": "/usr/bin:/bin", "HOME": str(home), "LC_ALL": "C.UTF-8", **(env or {})},
                            capture_output=True, timeout=60, cwd=ROOT, check=False)
    assert result.returncode == 2
    assert message in result.stderr.decode() and "NOT " in result.stderr.decode()
    assert list(home.rglob("*")) == []


# ------------------------------------------------------------------ driver: lifecycle, verdict, exit code


def test_the_reviewed_interruption_is_interrupted_inconclusive_v05_exit_20(ie: IEnv) -> None:
    assert authorize(ie)[0] == 0
    docker = docker_for()
    outcome, r = drive(ie, docker, SignalAtCheckpoint())
    assert (outcome.lifecycle, outcome.evidence_status, outcome.cleanup_status) == ("INTERRUPTED", "INCOMPLETE",
                                                                                    "COMPLETE")
    assert (outcome.verdict, outcome.decision_rule, outcome.lifecycle_exit_code) == ("INCONCLUSIVE", "V-05", 20)
    assert outcome.signal_observed == "SIGTERM" and outcome.checkpoint_reached
    assert outcome.matches_expected and outcome.deviations == []
    assert {"RUN_INTERRUPTED", "REQUIRED_CHECK_INCOMPLETE", "REPETITION_INCOMPLETE"} <= set(outcome.reason_codes)
    assert creates(docker) == [("baseline", "target"), ("baseline", "verifier")]
    assert starts(docker) == ["start"] and sorted(docker.removed) == sorted(docker.created)
    report = json.loads(os.read(r, 1024))
    assert report["pid"] == os.getpid() and report["target_id"] == docker.created[0]
    assert report["verifier_id"] == docker.created[1] and report["verifier_state"] == "CREATED_INSPECTED_NOT_STARTED"

    out = read_outcome(ie)
    assert out["verified"] is False and out["verdict"] == "INCONCLUSIVE" and out["candidate_executed"] is False
    assert out["verifier_started"] is False and out["start_operations"] == ["start"]
    assert out["remaining_owned_container_ids"] == [] and out["reconciliation"] == "CONSISTENT"
    assert out["evidence_failures"] == [] and out["timestamps"]["order"] == "CONSISTENT"
    check = verify_evidence(ie.evidence)
    assert check == {"state": "CONSISTENT", "status": "INCOMPLETE", "problems": []}
    assert check_operation_journal(ie.evidence, "docker-ops.jsonl") == []
    execution = json.loads((ie.evidence / "execution-pair-001-baseline.json").read_text())
    assert execution["started"] and execution["target"]["readiness"] == "READY"
    assert execution["verifier"]["termination"] == "NOT_STARTED" and execution["stream"]["status"] == "ABSENT"
    assert (ie.evidence / "verifier-stream-pair-001-baseline.bin").read_bytes() == b""  # nothing fabricated
    revision = json.loads((ie.evidence / "revision-pair-001-baseline.json").read_text())
    assert revision["interruption"] == "SIGTERM"
    assert revision["untrusted_outputs"]["untrusted-verifier-console"]["capture"] == "NOT_ATTEMPTED"
    interruption = json.loads((ie.evidence / "interruption.json").read_text())
    assert interruption["checkpoint_reached"] and interruption["signal_observed"] == "SIGTERM"
    assert not (ie.base.data / "evidence" / "runs").exists()  # nothing from or for an ordinary run


def test_an_abrupt_termination_before_the_checkpoint_has_no_verdict_and_is_never_finalized(ie: IEnv) -> None:
    assert authorize(ie)[0] == 0
    docker = docker_for()
    outcome, r = drive(ie, docker, SignalAtCheckpoint(at=0.5))  # 0.5 s: the readiness poll, before the checkpoint
    assert outcome.verdict is None and outcome.decision_rule is None and not outcome.checkpoint_reached
    assert (outcome.lifecycle, outcome.evidence_status, outcome.lifecycle_exit_code) == ("INTERRUPTED",
                                                                                         "INCOMPLETE", 20)
    assert outcome.cleanup_status == "COMPLETE" and not outcome.matches_expected
    assert os.read(r, 64) == b"" and starts(docker) == ["start"]
    out = read_outcome(ie)
    assert out["verified"] is False and out["engine_verdict"] is None and "INTERRUPTED_BY_SIGTERM" in out["exception"]
    assert json.loads((ie.evidence / "manifest.json").read_text())["status"] == "INCOMPLETE"
    assert not (ie.evidence / "verdict.json").exists()


def test_no_signal_at_the_synchronization_point_fails_closed(ie: IEnv) -> None:
    assert authorize(ie)[0] == 0
    docker = docker_for()
    outcome, r = drive(ie, docker, FakeClock(), wait=2)
    assert json.loads(os.read(r, 1024))["checkpoint"] == "baseline-target-ready"
    assert outcome.signal_observed is None and outcome.checkpoint_reached
    assert (outcome.verdict, outcome.decision_rule, outcome.lifecycle) == ("INCONCLUSIVE", "V-05", "INTERRUPTED")
    assert not outcome.matches_expected and any("signal" in d for d in outcome.deviations)
    assert starts(docker) == ["start"] and sorted(docker.removed) == sorted(docker.created)
    assert read_outcome(ie)["notes"] == [] and "without retry" in json.loads(
        (ie.evidence / "revision-pair-001-baseline.json").read_text())["interruption"]


class TamperedVerifier(FakeDocker):
    def _inspect(self, cid: str) -> dict[str, Any]:
        obj = super()._inspect(cid)
        if self.specs[cid].role.value == "verifier":
            obj["HostConfig"]["Privileged"] = True
        return obj


def test_an_unverified_verifier_blocks_before_anything_starts(ie: IEnv) -> None:
    assert authorize(ie)[0] == 0
    docker = TamperedVerifier(records=APPROVED_RUN_IMAGES)
    outcome, r = drive(ie, docker, SignalAtCheckpoint())
    assert os.read(r, 64) == b"" and starts(docker) == [] and not outcome.checkpoint_reached
    assert (outcome.lifecycle, outcome.verdict, outcome.lifecycle_exit_code) == ("BLOCKED", "BLOCKED", 21)
    assert outcome.cleanup_status == "COMPLETE" and sorted(docker.removed) == sorted(docker.created)
    assert not outcome.matches_expected


def test_a_target_that_never_becomes_ready_reports_nothing(ie: IEnv) -> None:
    assert authorize(ie)[0] == 0
    docker = docker_for()
    docker.target_health = ["unhealthy"]
    outcome, r = drive(ie, docker, SignalAtCheckpoint())
    assert os.read(r, 64) == b"" and not outcome.checkpoint_reached and outcome.signal_observed is None
    assert outcome.lifecycle == "INTERRUPTED" and outcome.verdict == "INCONCLUSIVE" and starts(docker) == ["start"]
    assert "TARGET_STARTUP_FAILED" in outcome.reason_codes and not outcome.matches_expected
    # guard 1 (baseline only) stopped the run; the candidate gate was never even consulted
    assert read_outcome(ie)["stop_reason"].startswith("BASELINE_ONLY")
    assert not json.loads((ie.evidence / "interruption.json").read_text())["candidate_refused_by_gate"]
    lines = [json.loads(x) for x in (ie.evidence / "revalidation.jsonl").read_text().splitlines()]
    assert [x["side"] for x in lines] == ["baseline"]


def _comparison_wrapper(monkeypatch: pytest.MonkeyPatch, **forced: Any) -> None:
    real = interruption_run.run_comparison

    def wrapped(*args: Any, **kwargs: Any) -> ComparisonResult:
        if forced.get("continue_after"):
            kwargs["continue_after"] = lambda result: True
            kwargs["checkpoint"] = None
        if forced.get("no_candidate_gate"):
            inner = kwargs["before_revision"]

            def gate(pair: int, side: str, started: bool) -> RevisionGate | None:
                return None if side == "candidate" else inner(pair, side, started)

            kwargs["before_revision"] = gate
        result = real(*args, **kwargs)
        if "verdict" in forced:
            return dataclasses.replace(result, verdict={**result.verdict, "verdict": forced["verdict"]})
        return result

    monkeypatch.setattr(interruption_run, "run_comparison", wrapped)


def test_the_candidate_gate_refuses_a_candidate_when_scheduling_would_allow_one(
        ie: IEnv, monkeypatch: pytest.MonkeyPatch) -> None:
    assert authorize(ie)[0] == 0
    _comparison_wrapper(monkeypatch, continue_after=True)
    docker = docker_for()
    docker.streams = {"baseline": b""}
    outcome, _ = drive(ie, docker, FakeClock())
    assert creates(docker) == [("baseline", "target"), ("baseline", "verifier")]
    assert json.loads((ie.evidence / "interruption.json").read_text())["candidate_refused_by_gate"]
    lines = [json.loads(x) for x in (ie.evidence / "revalidation.jsonl").read_text().splitlines()]
    assert [(x["side"], x["passed"], x["interrupt"]) for x in lines] == [("baseline", True, False),
                                                                         ("candidate", False, True)]
    assert outcome.lifecycle == "INTERRUPTED" and read_outcome(ie)["candidate_executed"] is False
    assert not outcome.matches_expected and any(d.startswith("execution:") for d in outcome.deviations)


def test_the_container_budget_refuses_a_third_creation(ie: IEnv, monkeypatch: pytest.MonkeyPatch) -> None:
    assert authorize(ie)[0] == 0
    _comparison_wrapper(monkeypatch, continue_after=True, no_candidate_gate=True)
    from patchproof.runner import interruption_plan
    from patchproof.runner.run_plan import RunPlan

    for name in ("source", "stream_identity"):  # guard 4 (the engine adapter) disabled as well
        monkeypatch.setattr(interruption_plan._BaselineOnlyEnginePlan, name, getattr(RunPlan, name))
    docker = docker_for()
    outcome, _ = drive(ie, docker, FakeClock())
    assert len(docker.created) == 2 and creates(docker) == [("baseline", "target"), ("baseline", "verifier")]
    out = read_outcome(ie)
    assert "at most two containers" in out["exception"] and out["containers_created"] == 2
    assert outcome.verdict is None and outcome.lifecycle == "INTERRUPTED" and outcome.cleanup_status == "COMPLETE"


@pytest.mark.parametrize("contradiction", ["VERIFIED_FOR_CASES", "BLOCKED", "NOT_FIXED"])
def test_an_engine_contradiction_is_never_presented_as_the_verdict(ie: IEnv, monkeypatch: pytest.MonkeyPatch,
                                                                   contradiction: str) -> None:
    assert authorize(ie)[0] == 0
    _comparison_wrapper(monkeypatch, verdict=contradiction)
    outcome, _ = drive(ie, docker_for(), SignalAtCheckpoint())
    out = read_outcome(ie)
    assert outcome.verdict is None and out["verdict"] is None and out["verified"] is False
    assert any(contradiction in f for f in out["evidence_failures"]) and not outcome.matches_expected
    assert outcome.lifecycle == "INTERRUPTED" and outcome.lifecycle_exit_code == 20


def test_a_claim_changed_before_the_baseline_stops_it_before_any_container(ie: IEnv) -> None:
    assert authorize(ie)[0] == 0
    s = store(ie)
    stored = s.executable()
    assert stored is not None
    claim_raw = s.claim(stored.record.authorization_id, run_id=RUN_ID, now=NOW)
    claim_file = s.root / f"{stored.record.authorization_id}.claim"
    os.chmod(claim_file, 0o600)
    claim_file.write_bytes(claim_raw.replace(b"12:00:00Z", b"12:00:01Z"))  # still a valid claim, but not this one
    docker = docker_for()
    r, w = os.pipe()
    with graceful_termination():
        outcome = execute_interruption_test(
            ie.env, stored.record, stored.raw, claim_raw, assemble_interruption(ie.env, RUN_ID),
            RunEvidence.claim(ie.env.evidence_root, RUN_ID), docker, InterruptionPoint(RUN_ID, w, 5),
            clock=SignalAtCheckpoint(), now=lambda: NOW)
    assert docker.created == [] and os.read(r, 64) == b""
    assert (outcome.lifecycle, outcome.verdict, outcome.lifecycle_exit_code) == ("BLOCKED", "BLOCKED", 21)
    assert "changed" in read_outcome(ie)["stop_reason"]


def test_the_child_never_runs_twice(ie: IEnv) -> None:
    assert authorize(ie)[0] == 0
    drive(ie, docker_for(), SignalAtCheckpoint())
    logs: list[str] = []
    r, w = os.pipe()
    assert run_child(ie.env, RUN_ID, w, _no_docker, parent_pid=os.getpid(), clock=FakeClock(), now=lambda: NOW,
                     log=logs.append) == 2
    assert "already exists" in logs[0] and os.read(r, 64) == b""
    os.close(r)


def test_a_cleanup_failure_is_reported_not_hidden(ie: IEnv) -> None:
    assert authorize(ie)[0] == 0
    docker = docker_for()
    docker.foreign_labels_on_cleanup = True
    outcome, _ = drive(ie, docker, SignalAtCheckpoint())
    out = read_outcome(ie)
    assert outcome.cleanup_status == "FAILED" and out["remaining_owned_container_ids"] == [docker.created[0]]
    assert outcome.verdict == "INCONCLUSIVE" and outcome.lifecycle_exit_code == 20
    assert any(d.startswith("cleanup_status") for d in outcome.deviations)


def test_any_unverified_cleanup_outcome_fails_cleanup_even_beside_a_removal(ie: IEnv,
                                                                          monkeypatch: pytest.MonkeyPatch) -> None:
    """Defence in depth. The accepted registry gives each owned ID exactly one outcome (it refuses a
    duplicate ID), so this cannot arise through it; but if a second, failed outcome for an already
    removed container were ever recorded, cleanup must not be reported COMPLETE."""
    from patchproof.runner.cleanup import CleanupStatus

    assert authorize(ie)[0] == 0

    class SecondAttemptFails(interruption_run.OutcomeRegistry):
        def record_outcome(self, result: Any) -> None:
            super().record_outcome(result)
            if result.status is not CleanupStatus.FAILED and not any(
                    o.status is CleanupStatus.FAILED for o in self.outcomes):
                super().record_outcome(replace(result, status=CleanupStatus.FAILED, detail="synthetic second attempt"))

    monkeypatch.setattr(interruption_run, "OutcomeRegistry", SecondAttemptFails)
    docker = docker_for()
    outcome, _ = drive(ie, docker, SignalAtCheckpoint())
    out = read_outcome(ie)
    assert sorted(docker.removed) == sorted(docker.created) and out["remaining_owned_container_ids"] == []
    assert outcome.cleanup_status == "FAILED" and out["cleanup_complete"] is False
    assert [c["status"] for c in out["cleanup"]].count("FAILED") == 1 and not outcome.matches_expected


class GhostListing(FakeDocker):
    """Inspect reports the containers gone, but the container listing still shows them."""

    def run(self, op: Any) -> Any:
        result = super().run(op)
        if getattr(op, "kind", None) == "containers" and result.ok:
            rows = b"".join(json.dumps({"ID": c, "Names": self.specs[c].name, "Image": "x", "State": "exited",
                                        "Labels": ""}).encode() + b"\n" for c in self.removed)
            result = dataclasses.replace(result, stdout=result.stdout + rows)
        return result


def test_a_container_still_listed_after_removal_is_not_complete_cleanup(ie: IEnv) -> None:
    assert authorize(ie)[0] == 0
    docker = GhostListing(records=APPROVED_RUN_IMAGES)
    outcome, _ = drive(ie, docker, SignalAtCheckpoint())
    remaining = read_outcome(ie)["remaining_owned_container_ids"]
    assert outcome.cleanup_status == "FAILED" and sorted(remaining) == sorted(docker.created)


def test_an_evidence_write_failure_is_recorded_and_cleanup_proceeds(ie: IEnv, monkeypatch: pytest.MonkeyPatch) -> None:
    assert authorize(ie)[0] == 0
    real = RunEvidence.write

    def write(self: Any, name: str, data: bytes) -> str:
        if name == "execution-pair-001-baseline.json":
            raise EvidenceError("synthetic write failure")
        return real(self, name, data)

    monkeypatch.setattr(RunEvidence, "write", write)
    docker = docker_for()
    outcome, _ = drive(ie, docker, SignalAtCheckpoint())
    assert sorted(docker.removed) == sorted(docker.created) and outcome.cleanup_status == "COMPLETE"
    assert any("synthetic write failure" in f for f in read_outcome(ie)["evidence_failures"])
    assert not outcome.matches_expected


def test_lifecycle_exit_codes_follow_the_specification() -> None:
    assert lifecycle_exit_code("INTERRUPTED", "INCONCLUSIVE") == 20
    assert lifecycle_exit_code("INTERRUPTED", "NOT_FIXED") == 20  # lifecycle takes precedence
    assert lifecycle_exit_code("INTERRUPTED", None) == 20
    assert lifecycle_exit_code("CANCELED", "NOT_FIXED") == 22
    assert lifecycle_exit_code("BLOCKED", "BLOCKED") == 21
    assert [lifecycle_exit_code("COMPLETE", v) for v in ("VERIFIED_FOR_CASES", "NOT_FIXED", "REGRESSION_DETECTED",
                                                         "NOT_REPRODUCED", "INCONCLUSIVE", "BLOCKED")] == [
        0, 10, 11, 12, 20, 21]
    for bad in (("COMPLETE", None), ("RUNNING", "INCONCLUSIVE")):
        with pytest.raises(ValueError):
            lifecycle_exit_code(*bad)


# ------------------------------------------------------------------ the child and the controller


def _never_spawn(run_id: str, fd: int) -> Any:
    raise AssertionError("no child may be started")


def _no_docker() -> Any:
    raise AssertionError("no Docker client may be created")


@pytest.mark.parametrize(("argv", "environ", "message"), [
    (["x", RUN_ID], {}, "only accepted form"),
    (["x", RUN_ID, "5", "--force"], {}, "only accepted form"),
    (["x", "--interrupt", "5"], {}, "only accepted form"),
    (["x", RUN_ID, "-1"], {}, "only accepted form"),
    (["x", RUN_ID, "5"], {"PATCHPROOF_INTERRUPT": "1"}, "environment variables"),
])
def test_the_child_accepts_exactly_one_argument_form(argv: list[str], environ: dict[str, str], message: str) -> None:
    with pytest.raises(ChildRefused, match=message):
        parse_arguments(argv, environ)


def test_the_child_refuses_a_claim_made_by_another_process(ie: IEnv) -> None:
    assert authorize(ie)[0] == 0
    s = store(ie)
    stored = s.executable()
    assert stored is not None
    s.claim(stored.record.authorization_id, run_id=RUN_ID, now=NOW)
    for parent, run_id, message in ((os.getpid() + 1, RUN_ID, "not claimed by this process's parent"),
                                    (os.getpid(), "run-" + "ab" * 16, "no interruption authorization")):
        logs: list[str] = []
        r, w = os.pipe()
        assert run_child(ie.env, run_id, w, _no_docker, parent_pid=parent, clock=FakeClock(), now=lambda: NOW,
                         log=logs.append) == 2
        assert message in logs[0] and os.read(r, 64) == b""
        os.close(r)
    assert not ie.evidence.exists()


def test_the_child_refuses_stale_inputs(ie: IEnv) -> None:
    assert authorize(ie)[0] == 0
    s = store(ie)
    stored = s.executable()
    assert stored is not None
    s.claim(stored.record.authorization_id, run_id=RUN_ID, now=NOW)
    ie.env.installation_id_file.chmod(0o600)
    ie.env.installation_id_file.write_text("inst-" + "ab" * 16 + "\n")
    logs: list[str] = []
    r, w = os.pipe()
    assert run_child(ie.env, RUN_ID, w, _no_docker, parent_pid=os.getpid(), clock=FakeClock(), now=lambda: NOW,
                     log=logs.append) == 2
    assert "differ from the authorized plan" in logs[0] and "installation_id" in logs[0]
    os.close(r)


@pytest.mark.parametrize("stale", ["installation", "snapshot", "typed"])
def test_the_controller_refuses_without_claiming(ie: IEnv, stale: str) -> None:
    assert authorize(ie)[0] == 0
    typed = f"INTERRUPT {RUN_ID}"
    if stale == "installation":
        ie.env.installation_id_file.chmod(0o600)
        ie.env.installation_id_file.write_text("inst-" + "ab" * 16 + "\n")
    elif stale == "snapshot":
        snapshot = ie.env.snapshot_store / assemble_interruption(ie.env, RUN_ID).document.sources.baseline.snapshot_name
        target = next(p for p in sorted(snapshot.rglob("*.py")) if p.is_file())
        os.chmod(target, 0o600)
        target.write_text("# changed\n")
    else:
        typed = f"EXECUTE {RUN_ID}"
    terminal = FakeTerminal({"To execute": typed})
    assert run_interruption_test(ie.env, terminal, _never_spawn, now=lambda: NOW) == 2
    assert "Nothing was claimed" in terminal.output() and store(ie).scan()[1] == {}


CHILD_SCRIPT = """
import os, pickle, sys
from datetime import UTC, datetime
sys.path.insert(0, {tests!r})
from _run_fixtures import FakeDocker
from patchproof.interruption_child import run_child
from patchproof.run_papertrail_once import SystemClock
from patchproof.runner.interrupts import graceful_termination
from patchproof.runner.run_plan import APPROVED_RUN_IMAGES
env = pickle.loads(open(sys.argv[1], "rb").read())
docker = FakeDocker(records=APPROVED_RUN_IMAGES)
with graceful_termination():
    code = run_child(env, sys.argv[2], int(sys.argv[3]), lambda: docker, parent_pid=os.getppid(),
                     clock=SystemClock(), now=lambda: datetime.now(UTC), log=sys.stderr.write)
sys.exit(code)
"""


def _real_child(ie: IEnv, tmp_path: Path, spawned: list[subprocess.Popen[bytes]]) -> Any:
    env_file = tmp_path / "env.pickle"
    env_file.write_bytes(pickle.dumps(ie.env))

    def spawn(run_id: str, fd: int) -> subprocess.Popen[bytes]:
        child = subprocess.Popen([sys.executable, "-c", CHILD_SCRIPT.format(tests=str(Path(__file__).parent)),
                                  str(env_file), run_id, str(fd)], pass_fds=(fd,), stdin=subprocess.DEVNULL,
                                 stderr=subprocess.PIPE)
        spawned.append(child)
        return child

    return spawn


def test_the_controller_and_a_real_child_produce_the_expected_outcome(ie: IEnv, tmp_path: Path) -> None:
    assert authorize(ie)[0] == 0
    spawned: list[subprocess.Popen[bytes]] = []
    terminal = FakeTerminal({"To execute": f"INTERRUPT {RUN_ID}"})
    with graceful_termination():
        code = run_interruption_test(ie.env, terminal, _real_child(ie, tmp_path, spawned), now=lambda: NOW)
    (child,) = spawned
    stderr = child.stderr.read().decode() if child.stderr else ""
    assert code == 0, terminal.output() + stderr
    assert child.returncode == 20 and "lifecycle INTERRUPTED" in stderr
    controller = json.loads((ie.base.data / "evidence" / "interruption-controller" / RUN_ID /
                             "controller.json").read_text())
    assert controller["result"] == "EXPECTED_OUTCOME_OBSERVED" and controller["harness_exit_code"] == 0
    assert controller["child_lifecycle_exit_code"] == 20 and controller["signals_sent"] == 1
    assert controller["delivery"]["report"]["pid"] == child.pid == controller["child_pid"]
    assert controller["child_evidence_check"]["state"] == "CONSISTENT" and controller["deviations"] == []
    assert verify_evidence(ie.base.data / "evidence" / "interruption-controller" / RUN_ID)["state"] == "CONSISTENT"
    out = read_outcome(ie)
    assert (out["lifecycle"], out["verdict"], out["decision_rule"], out["cleanup_status"]) == (
        "INTERRUPTED", "INCONCLUSIVE", "V-05", "COMPLETE")

    again = FakeTerminal({"To execute": f"INTERRUPT {RUN_ID}"})  # no retry: the authorization is spent
    assert run_interruption_test(ie.env, again, _never_spawn, now=lambda: NOW) == 2
    assert "no unused interruption-test authorization" in again.output()

    docker = docker_for()
    start = len(docker.log)
    rec = FakeTerminal({"Run to inspect": RUN_ID})
    assert recover(ie.base.env, rec, lambda: docker, interruption_env=ie.env) == 0, rec.output()
    assert {op.op_name for op in docker.log[start:]} <= {"inspect", "snapshot"}
    (directory,) = (ie.base.data / "evidence" / "recoveries" / RUN_ID).iterdir()
    assert json.loads((directory / "outcome.json").read_text())["result"] == "NOTHING_TO_REMOVE"


class FakeChild:
    """A child handle whose process is this test: records every signal; never actually signalled."""

    def __init__(self, report: dict[str, Any] | None, exits: bool) -> None:
        self.pid, self.signals, self.exits, self.report = 4_000_000, [], exits, report

    def poll(self) -> int | None:
        return None

    def send_signal(self, sig: int) -> None:
        self.signals.append(sig)

    def wait(self, timeout: float | None = None) -> int:
        if not self.exits:
            raise subprocess.TimeoutExpired("child", timeout or 0)
        return 20


def _fake_spawn(child: FakeChild) -> Any:
    def spawn(run_id: str, fd: int) -> FakeChild:
        if child.report is not None:
            os.write(fd, json.dumps({**child.report, "pid": child.pid}).encode() + b"\n")
        return child

    return spawn


def _report() -> dict[str, Any]:
    return {"checkpoint": "baseline-target-ready", "run_id": RUN_ID, "target_id": "c" * 64,
            "target_readiness": "READY", "verifier_id": "d" * 64, "verifier_state": "CREATED_INSPECTED_NOT_STARTED",
            "send_by_monotonic": time.monotonic() + 3600}


def test_a_child_that_does_not_exit_is_reported_never_killed(ie: IEnv) -> None:
    assert authorize(ie)[0] == 0
    child = FakeChild(_report(), exits=False)
    terminal = FakeTerminal({"To execute": f"INTERRUPT {RUN_ID}"})
    assert run_interruption_test(ie.env, terminal, _fake_spawn(child), now=lambda: NOW) == 1
    assert child.signals == [signal.SIGTERM]  # exactly one, never SIGKILL
    assert "it was NOT killed" in terminal.output()


@pytest.mark.parametrize("report", [None, {**_report(), "run_id": "run-" + "ab" * 16},
                                    {**_report(), "verifier_state": "STARTED"},
                                    {**_report(), "send_by_monotonic": 0.0}])
def test_the_controller_sends_nothing_for_a_missing_or_wrong_report(ie: IEnv, report: dict[str, Any] | None) -> None:
    assert authorize(ie)[0] == 0
    child = FakeChild(report, exits=True)
    terminal = FakeTerminal({"To execute": f"INTERRUPT {RUN_ID}"})
    assert run_interruption_test(ie.env, terminal, _fake_spawn(child), now=lambda: NOW) == 1
    assert child.signals == [] and store(ie).executable() is None  # consumed; never retried


def test_a_child_that_cannot_start_leaves_the_authorization_consumed(ie: IEnv) -> None:
    assert authorize(ie)[0] == 0

    def spawn(run_id: str, fd: int) -> Any:
        raise OSError("synthetic exec failure")

    terminal = FakeTerminal({"To execute": f"INTERRUPT {RUN_ID}"})
    assert run_interruption_test(ie.env, terminal, spawn, now=lambda: NOW) == 3
    assert store(ie).executable() is None and not ie.evidence.exists()
    rec = FakeTerminal({"Run to inspect": RUN_ID})
    assert recover(ie.base.env, rec, lambda: docker_for(), interruption_env=ie.env) == 0
    assert f"{RUN_ID}" in rec.output() and "evidence ABSENT" in rec.output()


def test_harness_and_lifecycle_exit_codes_are_kept_apart() -> None:
    delivered = Delivery(True, "SIGTERM_SENT", 7, {"pid": 7}, 1)
    expected = EXAMPLE["plan"]["expected_outcome"]
    outcome = {**expected, "signal_observed": "SIGTERM", "checkpoint_reached": True, "candidate_executed": False,
               "verifier_started": False, "containers_created": 2, "start_operations": ["start"],
               "remaining_owned_container_ids": [], "reconciliation": "CONSISTENT", "verified": False,
               "matches_expected": True}
    check = {"state": "CONSISTENT", "status": "INCOMPLETE", "problems": []}
    assert harness_deviations(delivered, 20, check, outcome, expected) == []
    assert harness_deviations(delivered, 0, check, outcome, expected)  # a lifecycle 0 is never "expected"
    assert harness_deviations(delivered, 20, {**check, "status": "FINALIZED"}, outcome, expected)
    assert harness_deviations(Delivery(False, "NO_CHECKPOINT_REPORT", 7, None), 20, check, outcome, expected)
    assert harness_deviations(Delivery(False, "REPORT_TOO_LATE", 7, {"pid": 7}), 20, check, outcome, expected) == [
        "signal not delivered: REPORT_TOO_LATE"]
    assert harness_deviations(delivered, 20, check, {**outcome, "verified": True}, expected)


# ------------------------------------------------------------------ the ordinary path cannot reach any of this


def test_the_ordinary_run_path_cannot_select_the_test_mode() -> None:
    for module in (authorized_run, run_papertrail_once):
        source = inspect.getsource(module)
        assert "interruption" not in source and "checkpoint" not in source, module.__name__
    assert "checkpoint" not in inspect.signature(authorized_run.execute_authorized_run).parameters
    for module in (interruption_child, interruption_test):
        source = inspect.getsource(module)
        assert "getenv" not in source and "environ.get" not in source, module.__name__
    assert "argv" not in inspect.getsource(recover_run.recover)


def test_the_controller_starts_only_the_fixed_child(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    class Popen:
        def __init__(self, argv: list[str], **kwargs: Any) -> None:
            seen.update(argv=argv, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", Popen)
    interruption_test.spawn_child(RUN_ID, 9)
    assert seen["argv"] == [sys.executable, "-I", "-m", "patchproof.interruption_child", RUN_ID, "9"]
    assert seen["pass_fds"] == (9,) and seen["close_fds"] is True and "shell" not in seen
    assert seen["stdin"] == subprocess.DEVNULL


def test_the_child_environment_is_explicit_and_arguments_are_validated(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[dict[str, Any]] = []

    class Popen:
        def __init__(self, argv: list[str], **kwargs: Any) -> None:
            seen.append({"argv": argv, **kwargs})

    monkeypatch.setattr(subprocess, "Popen", Popen)
    monkeypatch.setenv("HOME", "/Users/synthetic")
    monkeypatch.setenv("DOCKER_HOST", "tcp://198.51.100.1:2375")  # never reaches the child
    monkeypatch.setenv("PYTHONPATH", "/tmp/planted")
    interruption_test.spawn_child(RUN_ID, 9)
    assert seen[0]["env"] == {"HOME": "/Users/synthetic", "PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"}
    for run_id, fd in ((RUN_ID + " --force", 9), ("run-" + "AB" * 16, 9), ("-c", 9), (RUN_ID, 2), (RUN_ID, True),
                       (RUN_ID, 10_000)):
        with pytest.raises(PolicyViolation):
            interruption_test.spawn_child(run_id, fd)
    for home in ("relative/home", "/Users/x\nPATH=/tmp", ""):
        with pytest.raises(PolicyViolation):
            interruption_test.child_environment(home)
    assert len(seen) == 1  # nothing refused ever reached Popen


def test_the_controller_has_no_general_process_interface() -> None:
    import ast

    tree = ast.parse(inspect.getsource(interruption_test))
    calls = [ast.unparse(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)]
    names = {ast.unparse(n) for n in ast.walk(tree) if isinstance(n, (ast.Attribute, ast.Name))}
    imported = {a.name for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names} | {
        n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert calls.count("subprocess.Popen") == 1 and not any(c.startswith("subprocess.") and c != "subprocess.Popen"
                                                            for c in calls)
    assert not any(k.arg == "shell" for n in ast.walk(tree) if isinstance(n, ast.Call) for k in n.keywords)
    for name in ("os.kill", "os.killpg", "signal.SIGKILL", "os.system", "os.execv", "os.execvp", "os.spawnv",
                 "os.fork", "os.posix_spawn", "__import__", "eval", "exec"):
        assert name not in names, name
    assert not imported & {"importlib", "DockerCli", "runner.docker_cli", "shlex", "pty"}
    assert list(inspect.signature(interruption_test.spawn_child).parameters) == ["run_id", "report_fd"]


# ------------------------------------------------------------------ no candidate, anywhere


def test_the_engine_adapter_has_no_candidate_source(ie: IEnv) -> None:
    plan = assemble_interruption(ie.env, RUN_ID).plan
    assert type(plan).__name__ == "_BaselineOnlyEnginePlan" and plan.candidate is plan.baseline and plan.pairs == 1
    assert plan.source("baseline") is plan.baseline and plan.stream_identity(1, "baseline").side == "baseline"
    with pytest.raises(PolicyViolation, match="no candidate source"):
        plan.source("candidate")
    with pytest.raises(PolicyViolation, match="no candidate stream"):
        plan.stream_identity(1, "candidate")
    other = assemble_interruption(ie.env, RUN_ID).plan.baseline  # an equal but distinct object is refused too
    two_pairs = plan.manifest.model_copy(update={"repetitions": plan.manifest.repetitions.model_copy(
        update={"pairs": 2})})
    replace(plan, manifest=two_pairs)  # the base plan accepts one of two declared pairs ...
    for change in ({"candidate": other}, {"pairs": 2}, {"manifest": two_pairs, "pairs": 2}):
        with pytest.raises(PolicyViolation):  # ... but the adapter never runs a second pair
            replace(plan, **change)


def test_the_adapter_alone_stops_a_candidate_before_any_container(ie: IEnv, monkeypatch: pytest.MonkeyPatch) -> None:
    """Guard 4: scheduling, the candidate gate and the container budget all disabled."""
    assert authorize(ie)[0] == 0
    _comparison_wrapper(monkeypatch, continue_after=True, no_candidate_gate=True)
    monkeypatch.setattr(interruption_run, "MAX_CONTAINERS", 4)  # the recorder's budget is read from it
    docker = docker_for()
    outcome, _ = drive(ie, docker, FakeClock())
    assert creates(docker) == [("baseline", "target"), ("baseline", "verifier")]
    out = read_outcome(ie)
    assert "no candidate source" in out["exception"] and out["candidate_executed"] is False
    assert outcome.verdict is None and outcome.cleanup_status == "COMPLETE" and not outcome.matches_expected


def _all_bytes(*roots: Path) -> dict[str, bytes]:
    return {str(f): f.read_bytes() for root in roots for f in sorted(root.rglob("*")) if f.is_file()}


def test_no_stored_record_implies_that_a_second_revision_was_tested(ie: IEnv) -> None:
    assert authorize(ie)[0] == 0
    drive(ie, docker_for(), SignalAtCheckpoint())
    candidate = ie.env.revisions["candidate"]
    candidate_snapshot = assemble_interruption(ie.env, RUN_ID).document.sources.baseline.snapshot_name
    files = _all_bytes(ie.env.authorization_store, ie.evidence)
    assert files and not any("candidate" in Path(name).name for name in files)
    for name, data in files.items():
        for forbidden in (candidate.commit_id, candidate.tree_id, candidate.tag):
            assert forbidden.encode() not in data, (name, forbidden)
    assert candidate_snapshot.encode() in files[str(ie.evidence / "plan.json")]  # the baseline, and only it
    record = json.loads((ie.evidence / "authorization.json").read_text())
    assert list(record["plan"]["sources"]) == ["baseline"]
    assert record["plan"]["revision"]["candidate_execution"] is False
    verdict_input = json.loads((ie.evidence / "verdict-input.json").read_text())
    assert [e["side"] for e in verdict_input["executions"]] == ["baseline"]
    assert {o["side"] for o in verdict_input["observations"]} <= {"baseline"}
    assert verdict_input["run_termination"] == "interrupted" and verdict_input["pairs_planned"] == 1
    out = read_outcome(ie)
    assert out["revisions_executed"] == ["1-baseline"] and out["candidate_executed"] is False
    assert sorted(p.name for p in ie.evidence.glob("source-manifest-*.json")) == ["source-manifest-baseline.json"]


# ------------------------------------------------------------------ a child that does not exit


class SlowChild:
    """A REAL local process that ignores SIGTERM and never reports; the bounded wait is scaled down."""

    def __init__(self) -> None:
        self.proc = subprocess.Popen([sys.executable, "-I", "-c", "import signal, time\n"
                                      "signal.signal(signal.SIGTERM, signal.SIG_IGN)\ntime.sleep(60)"],
                                     stdin=subprocess.DEVNULL)
        self.pid, self.signals, self.waits = self.proc.pid, [], []

    def poll(self) -> int | None:
        return self.proc.poll()

    def send_signal(self, sig: int) -> None:
        self.signals.append(sig)
        self.proc.send_signal(sig)

    def wait(self, timeout: float | None = None) -> int:
        self.waits.append(timeout)
        return self.proc.wait(timeout=0.5)  # the plan's 600 s bound, scaled for the test


def test_a_real_child_that_never_exits_leaves_everything_unconfirmed(ie: IEnv, monkeypatch: pytest.MonkeyPatch) -> None:
    assert authorize(ie)[0] == 0
    monkeypatch.setattr(interruption_test, "deliver_at_checkpoint", lambda child, fd, **kw: (
        os.close(fd), Delivery(True, "SIGTERM_SENT", child.pid, {**_report(), "pid": child.pid}, 1))[1])
    holder: list[SlowChild] = []

    def spawn(run_id: str, fd: int) -> SlowChild:
        holder.append(SlowChild())
        return holder[0]

    terminal = FakeTerminal({"To execute": f"INTERRUPT {RUN_ID}"})
    docker = docker_for()
    try:
        code = run_interruption_test(ie.env, terminal, spawn, now=lambda: NOW)
        assert holder[0].proc.poll() is None  # still running: the controller did not kill it
    finally:
        holder[0].proc.kill()  # test teardown only
        holder[0].proc.wait()
    assert code == 1 and holder[0].waits == [600] and holder[0].signals == []  # no further signal from the controller
    assert store(ie).executable() is None  # the authorization stays consumed
    root = ie.base.data / "evidence" / "interruption-controller" / RUN_ID
    controller = json.loads((root / "controller.json").read_text())
    assert controller["result"] == "DEVIATION" and controller["child_exited"] is False
    assert controller["child_evidence_check"]["state"] == "NOT_READ" and controller["child_outcome"] is None
    assert controller["cleanup_confirmed"] is False and controller["manual_recovery_may_be_required"] is True
    assert controller["possibly_remaining_container_ids"] == ["c" * 64, "d" * 64]
    assert verify_evidence(root)["status"] == "INCOMPLETE"  # never FINALIZED while the child runs
    text = terminal.output()
    assert "CLEANUP NOT CONFIRMED: manual recovery may be required" in text and "still running" in text
    assert "recover_run" in text and "NOT killed" in text and "Cleanup is confirmed" not in text
    assert docker.log == []  # the controller has no Docker client at all


def test_an_exited_child_without_confirmed_cleanup_still_points_to_recovery(ie: IEnv) -> None:
    assert authorize(ie)[0] == 0
    child = FakeChild(_report(), exits=True)  # exits 20, but writes no evidence
    terminal = FakeTerminal({"To execute": f"INTERRUPT {RUN_ID}"})
    assert run_interruption_test(ie.env, terminal, _fake_spawn(child), now=lambda: NOW) == 1
    controller = json.loads((ie.base.data / "evidence" / "interruption-controller" / RUN_ID /
                             "controller.json").read_text())
    assert controller["child_exited"] and controller["child_evidence_check"]["state"] == "ABSENT"
    assert controller["cleanup_confirmed"] is False and controller["possibly_remaining_container_ids"]
    assert "manual recovery may be required" in terminal.output()


@pytest.fixture(autouse=True)
def _no_leaked_handlers() -> Iterator[None]:
    before = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
    yield
    assert {s: signal.getsignal(s) for s in before} == before

