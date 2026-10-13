"""PP-008 limited recovery: read-only status and owner-confirmed exact-ID cleanup, Docker-free.

Every scenario starts from a real synthetic run of the authorized driver (temporary stores,
scripted fake Docker) that left containers behind, or from a SIGKILLed child process. No
real store, evidence directory or Docker daemon is touched.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from _run_fixtures import fail, ok
from test_authorized_run import (  # noqa: F401 - `shared` is a fixture
    RUN_ID,
    Env,
    FakeTerminal,
    authorize,
    execute,
    fake,
    make_env,
    shared,
    sigkilled_run,
)

from patchproof.core.run_authorizations import RunAuthorizationStore
from patchproof.recover_run import cleanup_phrase, recover
from patchproof.runner.docker_cli import ContainerRef, DockerOp, Inspect, Logs, Start, StartAttached
from patchproof.runner.papertrail_plan import RunEnvironment
from patchproof.runner.policy import LABEL_INSTALLATION, LABEL_OWNER, LABEL_RUN, ContainerId, PolicyViolation
from patchproof.runner.run_recovery import CLEANUP_OPS, READ_ONLY_OPS, AllowlistExecutor

READ_ONLY = {"inspect", "snapshot"}


@pytest.fixture
def e(tmp_path: Path, shared: Path) -> Env:  # noqa: F811
    return make_env(tmp_path, shared)


def left_behind(e: Env) -> Any:
    """A run whose daemon vanished during the candidate: both candidate containers remain."""
    assert authorize(e)[0] == 0
    docker = fake(e)
    docker.on_attach = lambda side: setattr(docker, "down", side == "candidate")
    assert execute(e, docker)[0] == 4
    docker.down = False
    remaining = [c for c in docker.created if c not in docker.removed]
    assert len(remaining) == 2
    return docker


def answers(run_id: str = RUN_ID, confirm: str | None = None) -> dict[str, str]:
    return {"Run to inspect": run_id, "To stop and remove": confirm if confirm is not None else cleanup_phrase(run_id)}


def tree_digest(path: Path) -> dict[str, str]:
    return {str(p.relative_to(path)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(path.rglob("*")) if p.is_file()}


def recovery_dir(env: RunEnvironment) -> Path:
    (directory,) = (env.evidence_root.parent / "recoveries" / RUN_ID).iterdir()
    return directory


def recovery_outcome(env: RunEnvironment) -> dict[str, Any]:
    return dict(json.loads((recovery_dir(env) / "outcome.json").read_text()))


def ops_since(docker: Any, start: int) -> list[str]:
    return [op.op_name for op in docker.log[start:]]


def test_confirmed_cleanup_removes_exactly_the_verified_owned_containers(e: Env) -> None:
    docker = left_behind(e)
    before = tree_digest(e.evidence)
    remaining = [c for c in docker.created if c not in docker.removed]
    start = len(docker.log)
    terminal = FakeTerminal(answers())
    assert recover(e.env, terminal, lambda: docker) == 0
    assert sorted(docker.removed[-2:]) == sorted(remaining)
    assert "f0" * 32 not in docker.touched_ids()  # the unrelated container is never touched
    assert set(ops_since(docker, start)) <= set(CLEANUP_OPS)  # never create, start, attach or logs
    assert tree_digest(e.evidence) == before  # the run's own evidence is only read
    out = recovery_outcome(e.env)
    assert out["result"] == "CLEANED"
    rec = recovery_dir(e.env)
    assert json.loads((rec / "manifest.json").read_text())["status"] == "FINALIZED"
    assessment = json.loads((rec / "assessment.json").read_text())
    assert [f["state"] for f in assessment["findings"]] == ["ABSENT", "ABSENT", "OWNED", "OWNED"]
    after = json.loads((rec / "assessment-after.json").read_text())
    assert [f["state"] for f in after["findings"]] == ["ABSENT"] * 4
    cleanup = json.loads((rec / "cleanup.json").read_text())
    assert {c["status"] for c in cleanup} == {"REMOVED"}
    assert any(kind == "prompt" and cleanup_phrase(RUN_ID) in t for kind, t in terminal.transcript)


def test_without_the_typed_confirmation_nothing_is_removed(e: Env) -> None:
    docker = left_behind(e)
    start, removed = len(docker.log), list(docker.removed)
    assert recover(e.env, FakeTerminal(answers(confirm=f"cleanup {RUN_ID}")), lambda: docker) == 2
    assert docker.removed == removed and set(ops_since(docker, start)) <= READ_ONLY
    assert recovery_outcome(e.env)["result"] == "NOT_CONFIRMED"


@pytest.mark.parametrize("problem", ["foreign-labels", "extra-container", "no-journal", "docker-down"])
def test_ambiguity_refuses_all_cleanup(e: Env, problem: str) -> None:
    docker = left_behind(e)
    if problem == "foreign-labels":
        docker.foreign_labels_on_cleanup = True
    elif problem == "extra-container":
        docker.listings["containers"].append({"ID": "e7" * 32, "Names": f"pp-run-{RUN_ID[4:16]}-p1-other",
                                              "Image": "x:1", "State": "running", "Labels": ""})
    elif problem == "no-journal":
        os.chmod(e.evidence, 0o700)
        os.unlink(e.evidence / "ownership-journal.jsonl")
    else:
        docker.down = True
    start, removed = len(docker.log), list(docker.removed)
    assert recover(e.env, FakeTerminal(answers()), lambda: docker) == 5
    assert docker.removed == removed and set(ops_since(docker, start)) <= READ_ONLY
    out = recovery_outcome(e.env)
    assert out["result"] == "REFUSED_AMBIGUOUS" and out["problems"]
    expected = {"foreign-labels": "FOREIGN", "extra-container": "other container(s) carry this run's",
                "no-journal": "never planned it", "docker-down": "UNKNOWN"}[problem]
    assert any(expected in p for p in out["problems"]), out["problems"]


def test_a_change_after_confirmation_refuses_cleanup(e: Env) -> None:
    docker = left_behind(e)
    removed = list(docker.removed)
    terminal = FakeTerminal(answers(), on_prompt={"To stop and remove": lambda: setattr(
        docker, "foreign_labels_on_cleanup", True)})
    assert recover(e.env, terminal, lambda: docker) == 5
    assert docker.removed == removed
    assert recovery_outcome(e.env)["result"] == "CHANGED_BEFORE_CLEANUP"


def test_a_failed_removal_is_reported_as_incomplete(e: Env) -> None:
    docker = left_behind(e)
    real_run = docker.run

    def run(op: DockerOp) -> Any:
        return fail(op, b"synthetic removal failure") if op.op_name in ("remove", "force-remove") else real_run(op)

    docker.run = run  # type: ignore[method-assign]
    assert recover(e.env, FakeTerminal(answers()), lambda: docker) == 5
    out = recovery_outcome(e.env)
    assert out["result"] == "CLEANUP_INCOMPLETE" and all("FAILED" in c for c in out["cleanup"])


def test_a_clean_run_has_nothing_to_remove(e: Env) -> None:
    assert authorize(e)[0] == 0
    code, _, docker = execute(e)
    assert code == 0
    start = len(docker.log)
    assert recover(e.env, FakeTerminal(answers()), lambda: docker) == 0
    assert recovery_outcome(e.env)["result"] == "NOTHING_TO_REMOVE"
    assert set(ops_since(docker, start)) <= READ_ONLY
    subject = json.loads((recovery_dir(e.env) / "subject.json").read_text())
    assert subject["run_evidence"]["state"] == "CONSISTENT" and subject["claim_state"] == "CLAIMED"


def test_no_claim_no_store_and_wrong_run_ids(e: Env) -> None:
    docker = fake(e)
    terminal = FakeTerminal(answers())
    assert recover(e.env, terminal, lambda: docker) == 2 and "run-authorization store" in terminal.output()
    assert authorize(e)[0] == 0  # authorized but never executed: nothing can exist
    terminal = FakeTerminal(answers())
    assert recover(e.env, terminal, lambda: docker) == 0 and "Nothing to do" in terminal.output()
    assert execute(e, docker)[0] == 0
    terminal = FakeTerminal(answers(run_id="run-" + "ab" * 16))
    assert recover(e.env, terminal, lambda: docker) == 2 and "not a consumed run ID" in terminal.output()
    assert not (e.env.evidence_root.parent / "recoveries").exists()


def test_recovery_never_resumes_or_reauthorizes(e: Env) -> None:
    docker = left_behind(e)
    store = RunAuthorizationStore(e.env.authorization_store)
    before = sorted(os.listdir(store.root))
    assert recover(e.env, FakeTerminal(answers()), lambda: docker) == 0
    assert sorted(os.listdir(store.root)) == before and store.executable() is None
    code, term, _ = execute(e, fake(e))
    assert code == 2 and "there is no unused run authorization" in term.output()


def test_an_interrupt_during_recovery_is_reported(e: Env) -> None:
    docker = left_behind(e)

    def interrupt() -> None:
        raise KeyboardInterrupt

    removed = list(docker.removed)
    assert recover(e.env, FakeTerminal(answers(), on_prompt={"To stop and remove": interrupt}), lambda: docker) == 4
    assert docker.removed == removed


def test_the_allowlist_refuses_every_creating_or_executing_operation() -> None:
    from _run_fixtures import FakeDocker

    docker = FakeDocker()
    for allowed in (READ_ONLY_OPS, CLEANUP_OPS):
        executor = AllowlistExecutor(docker, allowed)
        for op in (StartAttached(ContainerId("d" * 64), timeout_seconds=1.0, stdout_cap=1), Start(ContainerId(
                "c" * 64)), Logs(ContainerId("c" * 64), stdout_cap=1)):
            with pytest.raises(PolicyViolation, match="recovery never performs"):
                executor.run(op)

        for name in ("run-create", "create", "start-attached", "wait"):
            with pytest.raises(PolicyViolation, match="recovery never performs"):
                executor.run(type("Op", (), {"op_name": name, "argv_tail": lambda self: []})())
    assert docker.log == []
    assert AllowlistExecutor(docker, READ_ONLY_OPS).run(Inspect(ContainerRef("c" * 64))).returncode == 1


@dataclass
class Leftovers:
    """Docker after a SIGKILL: only the containers the dead driver left, nothing else scripted."""

    containers: dict[str, dict[str, Any]]
    log: list[DockerOp] = field(default_factory=list)

    def run(self, op: DockerOp) -> Any:
        self.log.append(op)
        cid = op.argv_tail()[-1]
        if op.op_name == "snapshot":
            return ok(op, b"".join(json.dumps({"ID": i, "Names": c["Name"][1:], "Image": "x", "State": "running",
                                               "Labels": ",".join(f"{k}={v}" for k, v in c["Config"]["Labels"].items())
                                               }).encode() + b"\n" for i, c in self.containers.items()))
        if op.op_name == "inspect":
            if cid not in self.containers:
                return fail(op, b"Error: No such container: " + cid.encode())
            return ok(op, json.dumps([self.containers[cid]]).encode())
        if op.op_name == "stop":
            self.containers[cid]["State"]["Running"] = False
            return ok(op)
        if op.op_name == "remove" and not self.containers[cid]["State"]["Running"]:
            del self.containers[cid]
            return ok(op)
        raise AssertionError(op.op_name)


def test_recovery_after_a_real_sigkill(tmp_path: Path, shared: Path) -> None:  # noqa: F811
    data = sigkilled_run(tmp_path, shared)
    evidence = data / "evidence" / "runs" / RUN_ID
    journal = [json.loads(line) for line in (evidence / "ownership-journal.jsonl").read_text().splitlines()]
    plan = json.loads((evidence / "plan.json").read_text())
    containers = {j["id"]: {"Id": j["id"], "Name": "/" + j["name"], "State": {"Running": True, "Status": "running"},
                            "Config": {"Labels": {LABEL_OWNER: "patchproof", LABEL_RUN: RUN_ID,
                                                  LABEL_INSTALLATION: plan["installation_id"]}}}
                  for j in journal if j["event"] == "created"}
    docker = Leftovers(containers)
    before = tree_digest(evidence)
    env = RunEnvironment(approval_target=None, approval_store=data / "approvals",  # type: ignore[arg-type]
                         authorization_store=data / "run-authorizations",
                         snapshot_store=data / "source-snapshots", pack_store=data / "pack-store",
                         evidence_root=data / "evidence" / "runs",
                         installation_id_file=data / "probe-runs" / "installation-id")
    terminal = FakeTerminal(answers())
    assert recover(env, terminal, lambda: docker) == 0
    assert docker.containers == {} and "evidence NO_MANIFEST" in terminal.output()
    assert {op.op_name for op in docker.log} == {"snapshot", "inspect", "stop", "remove"}
    assert tree_digest(evidence) == before
    assert recovery_outcome(env)["result"] == "CLEANED"


# ---- the assessment's identity rules, directly


def _journal(tmp_path: Path, entries: list[tuple[str, str, str | None]]) -> Path:
    path = tmp_path / "ownership-journal.jsonl"
    lines = []
    for event, name, cid in entries:
        record: dict[str, Any] = {"run_id": RUN_ID, "event": event, "name": name}
        if event == "planned":
            record["role"] = "target" if name.endswith("target") else "verifier"
        if cid:
            record["id"] = cid
        lines.append(json.dumps(record, sort_keys=True))
    path.write_text("\n".join(lines) + "\n")
    return path


def _container(cid: str, name: str, *, run_id: str = RUN_ID, installation: str = "inst-" + "fe" * 16,
               running: bool = True) -> dict[str, Any]:
    return {"Id": cid, "Name": "/" + name, "State": {"Running": running, "Status": "running" if running else "exited"},
            "Config": {"Labels": {LABEL_OWNER: "patchproof", LABEL_RUN: run_id, LABEL_INSTALLATION: installation}}}


TARGET = f"pp-run-{RUN_ID[4:16]}-p1-baseline-target"
OWNERSHIP_INST = "inst-" + "fe" * 16


@pytest.mark.parametrize(("journal", "containers", "state", "detail"), [
    ([("planned", TARGET, None), ("created", TARGET, "a1" * 32)], {"a1" * 32: _container("a1" * 32, TARGET)},
     "OWNED", "verified"),
    ([("planned", TARGET, None)], {"a1" * 32: _container("a1" * 32, TARGET)},  # crash between create and record
     "OWNED", "verified"),
    ([("planned", TARGET, None), ("created", TARGET, "a1" * 32)], {"b2" * 32: _container("b2" * 32, TARGET)},
     "AMBIGUOUS", "not only the recorded ID"),
    ([("planned", TARGET, None), ("created", TARGET, "a1" * 32)], {"a1" * 32: _container("a1" * 32, "renamed")},
     "AMBIGUOUS", "under a different name"),
    ([("planned", TARGET, None), ("created", TARGET, "a1" * 32)],
     {"a1" * 32: _container("a1" * 32, TARGET, run_id="run-" + "cd" * 16)}, "FOREIGN", "run label"),
    ([("planned", TARGET, None), ("created", TARGET, "a1" * 32)],
     {"a1" * 32: _container("a1" * 32, TARGET, installation="inst-" + "0a" * 16)}, "FOREIGN", "installation"),
    ([], {"a1" * 32: _container("a1" * 32, TARGET)}, "AMBIGUOUS", "never planned"),
    ([("planned", TARGET, None), ("created", TARGET, "a1" * 32)], {}, "ABSENT", "does not exist"),
    ([("planned", TARGET, None), ("created", TARGET, "a1" * 32), ("cleanup", TARGET, None)], {}, "ABSENT", ""),
])
def test_assessment_identity_rules(tmp_path: Path, journal: list[tuple[str, str, str | None]],
                                   containers: dict[str, dict[str, Any]], state: str, detail: str) -> None:
    from patchproof.runner.policy import Ownership
    from patchproof.runner.run_recovery import assess

    box = Leftovers(containers)
    found = assess(box, Ownership(OWNERSHIP_INST, RUN_ID), _journal(tmp_path, journal))
    first = found.findings[0]
    assert (first.state, first.name) == (state, TARGET) and detail in first.detail
    assert [f.state for f in found.findings[1:]] == ["ABSENT"] * 3
    assert found.cleanup_permitted == (state in ("OWNED", "ABSENT"))
    assert {op.op_name for op in box.log} <= READ_ONLY


def test_a_listed_container_that_inspect_cannot_find_is_ambiguous(tmp_path: Path) -> None:
    from patchproof.runner.policy import Ownership
    from patchproof.runner.run_recovery import assess

    box = Leftovers({"a1" * 32: _container("a1" * 32, TARGET)})
    real = box.run

    def run(op: DockerOp) -> Any:
        return fail(op, b"Error: No such container") if op.op_name == "inspect" else real(op)

    box.run = run  # type: ignore[method-assign]
    journal = _journal(tmp_path, [("planned", TARGET, None), ("created", TARGET, "a1" * 32)])
    found = assess(box, Ownership(OWNERSHIP_INST, RUN_ID), journal)
    assert found.findings[0].state == "AMBIGUOUS" and not found.cleanup_permitted


def test_a_foreign_journal_line_refuses_the_assessment(tmp_path: Path) -> None:
    from patchproof.runner.policy import Ownership
    from patchproof.runner.run_recovery import assess

    journal = _journal(tmp_path, [("planned", TARGET, None)])
    with journal.open("a") as handle:
        handle.write(json.dumps({"run_id": "run-" + "cd" * 16, "event": "planned", "name": TARGET}) + "\n")
    found = assess(Leftovers({}), Ownership(OWNERSHIP_INST, RUN_ID), journal)
    assert not found.cleanup_permitted and "journal is unreadable or inconsistent" in found.problems[0]
