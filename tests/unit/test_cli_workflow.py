"""PP-009: the v0.1 CLI workflow, its exit codes and its safe reports. Docker-free.

Synthetic inputs only: a freshly generated PP-006 reference repository and its r1/r3
snapshots, a synthetic pack approval in a temporary store, and the scripted fake Docker of
`_run_fixtures`. PaperTrail is never imported or executed and no container exists. Real
approval records, authorizations and run evidence are never touched; the one test that reads
the owner's accepted PP-008 evidence does so read-only, skips when it is absent, and checks the
bytes are unchanged afterwards.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import shutil
import stat
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from test_authorized_run import (  # noqa: F401  (pytest fixtures)
    NOW,
    RUN_ID,
    Env,
    FakeClock,
    authorize,
    e,
    execute,
    fake,
    outcome,
    shared,
    writable,
)
from test_pack_approval import FakeTerminal
from typer.testing import CliRunner

from patchproof import pack_approval as pa
from patchproof.cli.main import app
from patchproof.core.records import RecordError, validate_record
from patchproof.core.records.project import ProjectRegistration
from patchproof.core.run_authorizations import RunAuthorizationStore, authorization_phrase, execution_phrase
from patchproof.git.command import resolve_git_binary
from patchproof.runner.papertrail_plan import assemble_run
from patchproof.runner.profiles import load_profile
from patchproof.workflow import exit_codes, plans, reports, safe_text
from patchproof.workflow.preflight import Preflight
from patchproof.workflow.projects import ProjectStore, project_id_for, register_project, registration_phrase
from patchproof.workflow.store import PrivateStore, StoreError

ROOT = Path(__file__).resolve().parents[2]
RUNNER = CliRunner()
GOOD_PROJECT = {"Your name": "Synthetic Owner",
                "Rationale": "Registering the generated synthetic reference repository for workflow unit tests.",
                "Registration scope": "Read committed revisions into temporary snapshots; nothing real is touched."}
GOOD_AUTH = {"Your name": "Synthetic Owner",
             "Rationale": "Synthetic authorization of the stored plan for the workflow unit tests.",
             "Authorization scope": "Exactly this plan in a temporary directory; authorizes nothing real."}


# ------------------------------------------------------------------ helpers


def wenv_for(e: Env) -> plans.WorkflowEnv:  # noqa: F811
    return plans.WorkflowEnv(run=e.env, projects=ProjectStore(e.data / "projects"), plans_root=e.data / "plans")


def repo_path(shared: Path) -> str:  # noqa: F811
    return str(shared / "repo")


def profile_for(e: Env) -> Any:  # noqa: F811
    t = e.env.approval_target
    return load_profile(t.profile_path, expected_sha256=t.profile_sha256)


def register(e: Env, shared: Path, overrides: dict[str, str] | None = None) -> tuple[int, FakeTerminal, str]:  # noqa: F811
    pid = project_id_for(repo_path(shared))
    terminal = FakeTerminal({**GOOD_PROJECT, "Confirmation": registration_phrase(pid), **(overrides or {})})
    code = register_project(repo_path(shared), resolve_git_binary(), wenv_for(e).projects, terminal, profile_for(e),
                            now=lambda: NOW)
    return code, terminal, pid


def create(e: Env, shared: Path, *, baseline: str = "refs/tags/authz-r1-vulnerable",  # noqa: F811
           candidate: str = "refs/tags/authz-r3-correct", create_snapshots: bool = False,
           answers: dict[str, str] | None = None, run_id: str = RUN_ID) -> tuple[int, str | None, FakeTerminal]:
    terminal = FakeTerminal(answers or {})
    code, plan_id = plans.create_plan(wenv_for(e), terminal, resolve_git_binary(),
                                      project_id=project_id_for(repo_path(shared)), baseline=baseline,
                                      candidate=candidate, create_snapshots=create_snapshots,
                                      new_run_id=lambda: run_id)
    return code, plan_id, terminal


def approve(e: Env, plan_id: str, overrides: dict[str, str] | None = None) -> tuple[int, FakeTerminal]:  # noqa: F811
    phrase = authorization_phrase(assemble_run(e.env, RUN_ID).document)
    terminal = FakeTerminal({**GOOD_AUTH, "Confirmation": phrase, **(overrides or {})})
    return plans.approve_plan(wenv_for(e), terminal, plan_id, now=lambda: NOW), terminal


def run(e: Env, plan_id: str, docker: Any, typed: str | None = None) -> tuple[plans.RunResult, FakeTerminal]:  # noqa: F811
    terminal = FakeTerminal({"To execute": typed if typed is not None else f"EXECUTE {RUN_ID}"})
    return plans.run_plan(wenv_for(e), terminal, plan_id, lambda: docker, clock=FakeClock(), now=lambda: NOW), terminal


def planned(e: Env, shared: Path) -> str:  # noqa: F811
    assert register(e, shared)[0] == 0
    code, plan_id, _ = create(e, shared)
    assert code == 0 and plan_id
    return plan_id


def finished_run(e: Env, shared: Path, **knobs: Any) -> str:  # noqa: F811
    plan_id = planned(e, shared)
    assert approve(e, plan_id)[0] == 0
    run(e, plan_id, fake(e, **knobs))
    return plan_id


def report(e: Env) -> reports.Report:  # noqa: F811
    return reports.build_report(e.data, RUN_ID, home=Path("/nonexistent-home"))


def rehash_manifest(evidence: Path, *names: str) -> None:
    """Make a tampered file consistent with the manifest, so only the deeper checks can catch it."""
    manifest = json.loads((evidence / "manifest.json").read_text())
    for name in names:
        data = (evidence / name).read_bytes()
        manifest["files"][name]["sha256"] = "sha256:" + hashlib.sha256(data).hexdigest()
        manifest["files"][name]["bytes"] = len(data)
    (evidence / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))


def evidence_hashes(path: Path) -> dict[str, str]:
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(path.iterdir())}


# ------------------------------------------------------------------ exit codes (PROJECT_SPEC.md 13.2)


@pytest.mark.parametrize(("verdict", "code"), [("VERIFIED_FOR_CASES", 0), ("NOT_FIXED", 10),
                                               ("REGRESSION_DETECTED", 11), ("NOT_REPRODUCED", 12),
                                               ("INCONCLUSIVE", 20), ("BLOCKED", 21)])
def test_every_verdict_maps_to_its_exit_code(verdict: str, code: int) -> None:
    assert exit_codes.run_exit_code("COMPLETE", verdict, "FINALIZED") == code


@pytest.mark.parametrize("verdict", ["VERIFIED_FOR_CASES", "NOT_FIXED", "REGRESSION_DETECTED", "NOT_REPRODUCED", None])
def test_lifecycle_takes_precedence_over_verdict(verdict: str | None) -> None:
    assert exit_codes.run_exit_code("INTERRUPTED", verdict, "FINALIZED") == 20
    assert exit_codes.run_exit_code("CANCELED", verdict, "FINALIZED") == 22
    assert exit_codes.run_exit_code("BLOCKED", verdict, "FINALIZED") == 21


@pytest.mark.parametrize(("lifecycle", "verdict", "status"), [
    ("COMPLETE", "VERIFIED_FOR_CASES", "INCOMPLETE"), ("COMPLETE", None, "FINALIZED"),
    ("COMPLETE", "SOMETHING_NEW", "FINALIZED"), (None, "VERIFIED_FOR_CASES", "FINALIZED"),
    ("RUNNING", "VERIFIED_FOR_CASES", "FINALIZED")])
def test_nothing_unfinished_or_unknown_ever_exits_zero(lifecycle: str | None, verdict: str | None,
                                                      status: str) -> None:
    assert exit_codes.run_exit_code(lifecycle, verdict, status) == 20


# ------------------------------------------------------------------ safe text


@pytest.mark.parametrize("hostile", [
    "\x1b[31mred\x1b[0m", "\x1b]8;;http://evil\x07link\x1b]8;;\x07", "a‮evil", "zero​width", "\x9bC1",
    "line1\nline2\r\n", "bell\x07"])
def test_unsafe_characters_never_reach_a_terminal(hostile: str) -> None:
    out = safe_text.plain(hostile)
    assert not any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F or ord(c) in (0x202E, 0x200B) for c in out)
    assert "\n" not in safe_text.md(hostile)


@pytest.mark.parametrize("hostile", [
    "[click](http://evil.example/x)", "![img](http://evil.example/p.png)", "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>", "| cell | break |", "# heading", "**bold** _em_", "`code`",
    "[local](file:///etc/passwd)", "<a href='javascript:alert(1)'>x</a>"])
def test_markdown_and_html_injection_is_escaped(hostile: str) -> None:
    out = safe_text.md(hostile)
    assert "<" not in out and ">" not in out  # HTML-significant characters become entities
    for i, ch in enumerate(out):  # every other Markdown-significant character is backslash-escaped
        if ch in "[]()|#`*_!":
            assert i > 0 and out[i - 1] == "\\", (hostile, out)


def test_values_are_bounded_and_secrets_redacted() -> None:
    assert safe_text.plain("x" * 1000, 50).endswith(safe_text.TRUNCATED) and len(safe_text.plain("x" * 1000, 50)) < 70
    leaked = "token pt-synthetic-alice-0123456789ab marker PT-PROTECTED-ALICE-0123456789ab Bearer abcdefgh1234"
    out = safe_text.plain(leaked)
    assert "pt-synthetic" not in out and "PT-PROTECTED" not in out and "abcdefgh1234" not in out
    assert safe_text.code("sha256:" + "a" * 64).startswith("`") and not safe_text.code("a`b").startswith("`")


# ------------------------------------------------------------------ substantive statements (PP-008 follow-up)


@pytest.mark.parametrize("bad", ["idk", "test", "testing", "n/a", "ok ok ok ok ok ok", "testing for implementation",
                                 "TODO TBD idk test", "   ", "asdf asdf asdf asdf asdf",
                                 "idk test todo tbd none okay whatever"])
def test_non_substantive_rationale_or_scope_is_refused(bad: str) -> None:
    assert pa.statement_problem(bad, "AUTHORIZE run-x sha256:" + "a" * 64) is not None


def test_a_copied_phrase_or_its_hash_is_refused_and_scope_must_differ() -> None:
    phrase = "AUTHORIZE run-0123 sha256:" + "ab" * 32
    assert "confirmation phrase" in str(pa.statement_problem(f"I approve: {phrase.lower()}", phrase))
    assert "confirmation phrase" in str(pa.statement_problem(
        "Approved after review of plan " + "ab" * 32 + " for the tests", phrase))
    good = "Reviewed the frozen plan, the container budget and the declared expectations."
    assert pa.statement_problem(good, phrase) is None
    assert "repeats the rationale" in str(pa.statement_problem(good, phrase, differs_from=good))


def test_the_interactive_gate_still_refuses_arguments_and_patchproof_variables() -> None:
    with pytest.raises(pa.NotInteractive):
        pa.require_interactive(["prog", "--yes"], {})
    with pytest.raises(pa.NotInteractive):
        pa.require_terminal({"PATCHPROOF_AUTO": "1"})
    r, w = os.pipe()
    try:
        with pytest.raises(pa.NotInteractive):
            pa.require_terminal({}, stdin_fd=r, stdout_fd=w)
    finally:
        os.close(r)
        os.close(w)


# ------------------------------------------------------------------ preflight


def test_preflight_is_decided_only_by_mandatory_checks() -> None:
    p = Preflight()
    assert not p.passed  # no mandatory check ran: never a pass
    p.diagnostic("optional note", False, "diagnostics never block")
    p.mandatory("gate", True)
    assert p.passed and "NOTE" in p.render() and "Result: PASS" in p.render()
    p.mandatory("second gate", False, "failed")
    assert not p.passed and "BLOCKED: 1 mandatory" in p.render() and p.document()["passed"] is False


# ------------------------------------------------------------------ private store


def test_store_writes_once_read_only_and_never_overwrites(tmp_path: Path) -> None:
    parent = tmp_path / "data"
    parent.mkdir(mode=0o700)
    store = PrivateStore(parent / "plans", max_record_bytes=100)
    path = store.write_once("plan-" + "0" * 32 + ".json", b"{}")
    assert stat.S_IMODE(os.lstat(path).st_mode) == 0o400 and stat.S_IMODE(os.lstat(parent / "plans").st_mode) == 0o700
    with pytest.raises(StoreError, match="never overwritten"):
        store.write_once("plan-" + "0" * 32 + ".json", b"{}")
    with pytest.raises(StoreError, match="size"):
        store.write_once("plan-" + "1" * 32 + ".json", b"x" * 101)
    with pytest.raises(StoreError, match="invalid record name"):
        store.read("../escape.json")
    assert store.read("plan-" + "2" * 32 + ".json") is None


def test_store_refuses_symlinks_writable_records_and_strays(tmp_path: Path) -> None:
    parent = tmp_path / "data"
    parent.mkdir(mode=0o700)
    (tmp_path / "elsewhere").mkdir(mode=0o700)
    os.symlink(tmp_path / "elsewhere", parent / "plans")
    with pytest.raises(StoreError):
        PrivateStore(parent / "plans", max_record_bytes=100).names()
    os.unlink(parent / "plans")
    store = PrivateStore(parent / "plans", max_record_bytes=100)
    name = "plan-" + "3" * 32 + ".json"
    store.write_once(name, b"{}")
    os.chmod(parent / "plans" / name, 0o600)
    with pytest.raises(StoreError, match="read-only"):
        store.read(name)
    (parent / "plans" / "notes.txt").write_text("x")
    with pytest.raises(StoreError, match="unexpected"):
        store.names()
    open_parent = tmp_path / "open"
    open_parent.mkdir(mode=0o755)
    with pytest.raises(StoreError, match="private"):
        PrivateStore(open_parent / "plans", max_record_bytes=100).names()


# ------------------------------------------------------------------ project add


def test_registration_shows_scope_and_records_explicit_approval(e: Env, shared: Path) -> None:  # noqa: F811
    code, terminal, pid = register(e, shared)
    assert code == 0 and "PROJECT REGISTERED" in terminal.output()
    out = terminal.output()
    assert "uncommitted edits" in out and "papertrail" in out and "approves nothing else" in out.lower() or \
        "approves no pack" in out
    record = wenv_for(e).projects.load(pid)
    assert record is not None and record.canonical_path == repo_path(shared)
    assert record.confirmation == f"REGISTER {pid}"
    assert record.reviewer.basis == "local-assertion-unverified"
    assert stat.S_IMODE(os.lstat(e.data / "projects" / f"{pid}.json").st_mode) == 0o400


def test_registering_again_writes_nothing(e: Env, shared: Path) -> None:  # noqa: F811
    assert register(e, shared)[0] == 0
    before = os.listdir(e.data / "projects")
    code, terminal, _ = register(e, shared)
    assert code == 0 and "Already registered" in terminal.output() and os.listdir(e.data / "projects") == before


@pytest.mark.parametrize(("overrides", "message"), [
    ({"Confirmation": "REGISTER prj-0000000000000000"}, "does not match"),
    ({"Rationale": "idk"}, "not a substantive statement"),
    ({"Registration scope": "test"}, "not a substantive statement"),
])
def test_registration_refusals_write_nothing(e: Env, shared: Path, overrides: dict[str, str], message: str) -> None:  # noqa: F811
    code, terminal, _ = register(e, shared, overrides)
    assert code == 2 and message in terminal.output() and "Nothing was written" in terminal.output()
    assert not (e.data / "projects").exists() or os.listdir(e.data / "projects") == []


@pytest.mark.parametrize("which", ["relative", "subdirectory", "not-a-repo", "home", "trailing-slash"])
def test_unsafe_repository_paths_are_refused(e: Env, shared: Path, tmp_path: Path, which: str) -> None:  # noqa: F811
    plain_dir = tmp_path / "plain"
    plain_dir.mkdir()
    path = {"relative": "repo", "subdirectory": repo_path(shared) + "/papertrail", "not-a-repo": str(plain_dir),
            "home": str(shared), "trailing-slash": repo_path(shared) + "/"}[which]
    terminal = FakeTerminal({})
    home = shared if which == "home" else None
    code = register_project(path, resolve_git_binary(), wenv_for(e).projects, terminal, profile_for(e),
                            now=lambda: NOW, home=home)
    assert code == 2 and "NOT REGISTERED" in terminal.output()
    assert not any(kind == "prompt" for kind, _ in terminal.transcript)  # refused before any question


def test_a_tampered_project_record_is_refused(e: Env, shared: Path) -> None:  # noqa: F811
    _, _, pid = register(e, shared)
    path = e.data / "projects" / f"{pid}.json"
    data = json.loads(path.read_text())
    data["canonical_path"] = "/Users/someone/else"
    os.chmod(path, 0o600)
    path.write_text(json.dumps(data))
    os.chmod(path, 0o400)
    with pytest.raises(RecordError, match="derived"):
        wenv_for(e).projects.load(pid)


def test_project_contract_rejects_a_mismatched_confirmation_semantically() -> None:
    record = validate_record(ProjectRegistration, json.loads(
        (ROOT / "schemas/examples/valid/project-registration--papertrail-reference-example.json").read_text()),
        "project-registration")
    from patchproof.workflow.projects import check_registration
    with pytest.raises(RecordError):
        check_registration(record)  # the example's ID is not derived from its path


# ------------------------------------------------------------------ plan create / show


def test_plan_create_previews_and_stores_an_immutable_plan_without_approving(e: Env, shared: Path) -> None:  # noqa: F811
    assert register(e, shared)[0] == 0
    code, plan_id, terminal = create(e, shared)
    out = terminal.output()
    assert code == 0 and plan_id is not None and "PLAN CREATED" in out
    run = assemble_run(e.env, RUN_ID)
    document, sha = plans.load_plan(wenv_for(e), plan_id)
    assert document == run.document and sha == run.sha256 and plan_id == plans.plan_id_for(run.sha256)
    for needle in (run.document.sources.baseline.commit_id, run.document.sources.candidate.commit_id,
                   run.document.pack.pack_tree_sha256, run.document.profile.profile_sha256,
                   run.document.images.target_image_id, "AUTH-001", "at most 4 container creations",
                   "Known limitations", "MANDATORY", "uncommitted edits are excluded"):
        assert needle in out
    assert stat.S_IMODE(os.lstat(e.data / "plans" / f"{plan_id}.json").st_mode) == 0o400
    assert not e.env.authorization_store.exists() and not e.env.evidence_root.exists()


@pytest.mark.parametrize(("baseline", "candidate"), [
    ("refs/tags/authz-r1-vulnerable", "refs/tags/authz-r2-inadequate"),
    ("refs/tags/authz-r1-vulnerable", "refs/tags/authz-r4-deny-all"),
    ("refs/tags/authz-r3-correct", "refs/tags/authz-r1-vulnerable")])
def test_revisions_outside_the_accepted_contract_are_refused(e: Env, shared: Path, baseline: str,  # noqa: F811
                                                              candidate: str) -> None:
    assert register(e, shared)[0] == 0
    code, plan_id, terminal = create(e, shared, baseline=baseline, candidate=candidate)
    assert code == 21 and plan_id is None and "outside the accepted v0.1 plan contract" in terminal.output()
    assert not (e.data / "plans").exists()


def test_an_unregistered_project_is_refused(e: Env, shared: Path) -> None:  # noqa: F811
    code, plan_id, terminal = create(e, shared)
    assert code == 21 and plan_id is None and "not a registered project" in terminal.output()


def test_missing_snapshots_need_a_typed_confirmation(e: Env, shared: Path) -> None:  # noqa: F811
    assert register(e, shared)[0] == 0
    writable(e.env.snapshot_store)
    shutil.rmtree(e.env.snapshot_store)
    code, _, terminal = create(e, shared)
    assert code == 21 and "--create-snapshots" in terminal.output()
    code, _, terminal = create(e, shared, create_snapshots=True, answers={"To create them": "yes"})
    assert code == 21 and not e.env.snapshot_store.exists() or os.listdir(e.env.snapshot_store) == []
    pid = project_id_for(repo_path(shared))
    code, plan_id, terminal = create(e, shared, create_snapshots=True, answers={"To create them": f"SNAPSHOT {pid}"})
    assert code == 0 and plan_id and len(os.listdir(e.env.snapshot_store)) == 2


def test_a_stale_pack_approval_blocks_plan_creation(e: Env, shared: Path) -> None:  # noqa: F811
    assert register(e, shared)[0] == 0
    writable(e.env.approval_store)
    shutil.rmtree(e.env.approval_store)
    code, plan_id, terminal = create(e, shared)
    assert code == 21 and plan_id is None and "plan precondition authorization" in terminal.output()


def test_plan_show_detects_changed_inputs(e: Env, shared: Path) -> None:  # noqa: F811
    plan_id = planned(e, shared)
    terminal = FakeTerminal({})
    assert plans.show_plan(wenv_for(e), terminal, plan_id) == 0 and "not approved yet" in terminal.output()
    writable(e.env.approval_store)
    shutil.rmtree(e.env.approval_store)
    terminal = FakeTerminal({})
    assert plans.show_plan(wenv_for(e), terminal, plan_id) == 21


@pytest.mark.parametrize("tamper", ["edit", "rename", "bad-id"])
def test_a_tampered_or_unknown_plan_is_refused(e: Env, shared: Path, tamper: str) -> None:  # noqa: F811
    plan_id = planned(e, shared)
    path = e.data / "plans" / f"{plan_id}.json"
    if tamper == "edit":
        doc = json.loads(path.read_text())
        doc["containers"]["max_creations"] = 4
        doc["repetitions"]["pairs"] = 1
        doc["runtime"]["case_timeout_seconds"] = 119
        os.chmod(path, 0o600)
        path.write_text(json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n")
        os.chmod(path, 0o400)
        target = plan_id
    elif tamper == "rename":
        target = "plan-" + "e" * 32
        os.chmod(e.data / "plans", 0o700)
        os.rename(path, e.data / "plans" / f"{target}.json")
    else:
        target = "plan-XYZ"
    with pytest.raises((plans.WorkflowRefused, RecordError)):
        plans.load_plan(wenv_for(e), target)


# ------------------------------------------------------------------ plan approve


def test_plan_approve_binds_the_authorization_to_the_exact_plan(e: Env, shared: Path) -> None:  # noqa: F811
    plan_id = planned(e, shared)
    code, terminal = approve(e, plan_id)
    assert code == 0 and "RUN AUTHORIZED" in terminal.output() and f"patchproof run {plan_id}" in terminal.output()
    _, sha = plans.load_plan(wenv_for(e), plan_id)
    stored = RunAuthorizationStore(e.env.authorization_store).executable()
    assert stored is not None and stored.record.plan_sha256 == sha and stored.record.plan.run_id == RUN_ID
    assert not e.env.evidence_root.exists() or os.listdir(e.env.evidence_root) == []  # nothing executed


def test_plan_approve_is_not_repeated_and_writes_nothing_twice(e: Env, shared: Path) -> None:  # noqa: F811
    plan_id = planned(e, shared)
    assert approve(e, plan_id)[0] == 0
    before = sorted(os.listdir(e.env.authorization_store))
    code, terminal = approve(e, plan_id)
    assert code == 0 and "already authorized and unused" in terminal.output()
    assert sorted(os.listdir(e.env.authorization_store)) == before


@pytest.mark.parametrize(("overrides", "message"), [
    ({"Rationale": "idk"}, "not a substantive statement"),
    ({"Authorization scope": "test"}, "not a substantive statement"),
    ({"Confirmation": "AUTHORIZE something else"}, "does not match"),
])
def test_plan_approve_refusals_write_nothing(e: Env, shared: Path, overrides: dict[str, str], message: str) -> None:  # noqa: F811
    plan_id = planned(e, shared)
    code, terminal = approve(e, plan_id, overrides)
    assert code == 21 and message in terminal.output()
    assert not e.env.authorization_store.exists() or RunAuthorizationStore(e.env.authorization_store).scan() == ({}, {})


def test_plan_approve_refuses_when_inputs_changed_since_the_plan(e: Env, shared: Path) -> None:  # noqa: F811
    plan_id = planned(e, shared)
    phrase = authorization_phrase(assemble_run(e.env, RUN_ID).document)
    writable(e.env.approval_store)
    shutil.rmtree(e.env.approval_store)  # the current pack approval disappears after the plan was created
    terminal = FakeTerminal({**GOOD_AUTH, "Confirmation": phrase})
    code = plans.approve_plan(wenv_for(e), terminal, plan_id, now=lambda: NOW)
    assert code == 21 and "RUN AUTHORIZED" not in terminal.output()
    assert not e.env.authorization_store.exists() or RunAuthorizationStore(e.env.authorization_store).scan() == ({}, {})


def test_the_expected_hash_guard_alone_refuses_a_different_plan(e: Env, shared: Path) -> None:  # noqa: F811
    from patchproof.run_authorization import run_authorization

    plan_id = planned(e, shared)
    phrase = authorization_phrase(assemble_run(e.env, RUN_ID).document)
    terminal = FakeTerminal({**GOOD_AUTH, "Confirmation": phrase})
    code = run_authorization(e.env, terminal, now=lambda: NOW, new_run_id=lambda: RUN_ID,
                             expected_plan_sha256="sha256:" + "0" * 64)
    assert code == 2 and "differs from the selected plan" in terminal.output() and plan_id
    assert not any(kind == "prompt" for kind, _ in terminal.transcript)


# ------------------------------------------------------------------ run


def test_run_refuses_an_unapproved_plan_without_any_docker_operation(e: Env, shared: Path) -> None:  # noqa: F811
    plan_id = planned(e, shared)
    docker = fake(e)
    result, terminal = run(e, plan_id, docker)
    assert result.exit_code == 21 and "not authorized" in terminal.output() and docker.log == []


def test_run_executes_once_and_maps_the_verdict(e: Env, shared: Path) -> None:  # noqa: F811
    plan_id = planned(e, shared)
    assert approve(e, plan_id)[0] == 0
    docker = fake(e)
    result, terminal = run(e, plan_id, docker)
    assert result.exit_code == 0 and result.verdict == "VERIFIED_FOR_CASES" and result.lifecycle == "COMPLETE"
    assert f"patchproof report {RUN_ID}" in terminal.output()
    again = fake(e)
    result2, terminal2 = run(e, plan_id, again)
    assert result2.exit_code == 21 and "already consumed" in terminal2.output() and again.log == []


@pytest.mark.parametrize(("candidate", "verdict", "code"), [("inadequate", "NOT_FIXED", 10),
                                                            ("deny_all", "REGRESSION_DETECTED", 11),
                                                            ("vulnerable", "NOT_FIXED", 10)])
def test_run_exit_codes_follow_the_semantic_verdict(e: Env, shared: Path, candidate: str, verdict: str,  # noqa: F811
                                                    code: int) -> None:
    plan_id = planned(e, shared)
    assert approve(e, plan_id)[0] == 0
    result, _ = run(e, plan_id, fake(e, candidate=candidate.replace("_", "-")))
    assert (result.verdict, result.exit_code) == (verdict, code)
    assert result.document()["verdict"] == verdict  # JSON keeps the semantic verdict separately


def test_a_baseline_failure_interrupts_and_exits_20(e: Env, shared: Path) -> None:  # noqa: F811
    plan_id = planned(e, shared)
    assert approve(e, plan_id)[0] == 0
    result, _ = run(e, plan_id, fake(e, verifier_oom=True))
    assert result.lifecycle == "INTERRUPTED" and result.exit_code == 20


def test_a_wrong_execution_phrase_claims_nothing(e: Env, shared: Path) -> None:  # noqa: F811
    plan_id = planned(e, shared)
    assert approve(e, plan_id)[0] == 0
    docker = fake(e)
    result, _ = run(e, plan_id, docker, typed="EXECUTE run-wrong")
    assert result.exit_code == 21 and docker.log == []
    assert RunAuthorizationStore(e.env.authorization_store).executable() is not None


def test_run_refuses_when_the_unused_authorization_binds_another_plan(e: Env, shared: Path) -> None:  # noqa: F811
    plan_id = planned(e, shared)
    assert authorize(e, run_id="run-" + "ab" * 16)[0] == 0  # an authorization for a different plan
    docker = fake(e)
    result, terminal = run(e, plan_id, docker)
    assert result.exit_code == 21 and docker.log == []


def test_execute_once_hash_guard_alone_refuses_before_the_claim(e: Env, shared: Path) -> None:  # noqa: F811
    from patchproof.run_papertrail_once import execute_once

    plan_id = planned(e, shared)
    assert approve(e, plan_id)[0] == 0
    docker = fake(e)
    terminal = FakeTerminal({"To execute": execution_phrase(assemble_run(e.env, RUN_ID).document)})
    once = execute_once(e.env, terminal, lambda: docker, clock=FakeClock(), now=lambda: NOW,
                        expected_plan_sha256="sha256:" + "1" * 64)
    assert once.stage == "REFUSED" and docker.log == []
    assert RunAuthorizationStore(e.env.authorization_store).executable() is not None


@pytest.mark.parametrize(("stage", "code"), [("REFUSED", 21), ("CLAIMED_NOT_EXECUTED", 20), ("INCOMPLETE", 20)])
def test_pre_outcome_stages_never_exit_zero(stage: str, code: int) -> None:
    from patchproof.run_papertrail_once import OnceResult

    assert plans.result_from(OnceResult(0, stage), RUN_ID).exit_code == code  # type: ignore[arg-type]


# ------------------------------------------------------------------ reports


def test_report_on_a_verified_run(e: Env, shared: Path) -> None:  # noqa: F811
    finished_run(e, shared)
    r = report(e)
    d = r.document
    assert r.exit_code == 0 and d["integrity"]["verified"] and d["headline"] == "Verified for the selected cases."
    assert d["result"]["decision_rule"] == "V-09" and d["observations"]["trusted_cells"] == 16
    assert d["integrity"]["journal_format"] == "docker-ops-v2"
    assert all(c["passed"] for c in d["integrity"]["checks"])
    assert {w["test_id"] for w in d["witnesses"]} == {"AUTH-001", "AUTH-002", "AUTH-003", "AUTH-004"}
    md = reports.render_markdown(r)
    assert "## Security witnesses" in md and "Reproducibility prerequisites" in md and "not a runnable" in md


def test_reports_are_deterministic(e: Env, shared: Path) -> None:  # noqa: F811
    finished_run(e, shared)
    assert reports.render_json(report(e)) == reports.render_json(report(e))
    assert reports.render_markdown(report(e)) == reports.render_markdown(report(e))


@pytest.mark.parametrize(("candidate", "code"), [("inadequate", 10), ("deny-all", 11)])
def test_report_exit_codes_match_the_run(e: Env, shared: Path, candidate: str, code: int) -> None:  # noqa: F811
    finished_run(e, shared, candidate=candidate)
    assert report(e).exit_code == code


def test_an_interrupted_run_is_reported_incomplete_and_never_successful(e: Env, shared: Path) -> None:  # noqa: F811
    finished_run(e, shared, verifier_oom=True)
    r = report(e)
    d = r.document
    assert d["integrity"]["verified"] and r.exit_code == 20
    assert d["result"]["lifecycle"] == "INTERRUPTED" and d["result"]["verdict"] != "VERIFIED_FOR_CASES"
    assert d["headline"].startswith("INTERRUPTED") and "Not a verification result" in d["headline"]
    assert d["cleanup"]["status"] == "COMPLETE"  # cleanup completed, the run still is not a success
    assert "Verified for the selected cases" not in reports.render_markdown(r)


def test_a_signal_interrupted_run_without_a_verdict_is_reported_consistently(e: Env, shared: Path) -> None:  # noqa: F811
    import signal

    from patchproof.runner.interrupts import graceful_termination

    plan_id = planned(e, shared)
    assert approve(e, plan_id)[0] == 0
    docker = fake(e)
    docker.on_attach = lambda side: os.kill(os.getpid(), signal.SIGTERM) if side == "baseline" else None
    with graceful_termination():
        result, _ = run(e, plan_id, docker)
    assert result.exit_code == 20
    r = report(e)
    assert r.exit_code == 20 and r.document["integrity"]["verified"], r.document["integrity"]
    assert r.document["result"]["verdict"] is None and r.document["result"]["engine_verdict"] is None


def test_a_changed_artifact_fails_verification(e: Env, shared: Path) -> None:  # noqa: F811
    finished_run(e, shared)
    writable(e.evidence)
    (e.evidence / "collection.json").write_text("[]")
    r = report(e)
    assert r.exit_code == 20 and not r.document["integrity"]["verified"]
    assert r.document["headline"].startswith("EVIDENCE NOT VERIFIED")


def test_a_rewritten_verdict_is_caught_by_recomputation(e: Env, shared: Path) -> None:  # noqa: F811
    finished_run(e, shared, candidate="inadequate")
    writable(e.evidence)
    verdict = json.loads((e.evidence / "verdict.json").read_text())
    verdict["verdict"] = "VERIFIED_FOR_CASES"
    verdict["decision_rule"] = "V-09"
    (e.evidence / "verdict.json").write_text(json.dumps(verdict))
    rehash_manifest(e.evidence, "verdict.json")
    r = report(e)
    failed = [c["name"] for c in r.document["integrity"]["checks"] if not c["passed"]]
    assert r.exit_code == 20 and not r.document["integrity"]["verified"]
    assert any("recomputed" in n or "strictly loaded" in n for n in failed), failed


def test_rewritten_observations_are_caught_against_the_raw_stream(e: Env, shared: Path) -> None:  # noqa: F811
    finished_run(e, shared, candidate="inadequate")
    writable(e.evidence)
    name = "observations-pair-001-candidate.jsonl"
    lines = [json.loads(x) for x in (e.evidence / name).read_text().splitlines()]
    for line in lines:
        if line["semantic_outcome"] == "VIOLATION_CONFIRMED":
            line["semantic_outcome"] = "SECURE"
    (e.evidence / name).write_text("".join(json.dumps(x) + "\n" for x in lines))
    rehash_manifest(e.evidence, name)
    r = report(e)
    failed = [c["name"] for c in r.document["integrity"]["checks"] if not c["passed"]]
    assert r.exit_code == 20 and any("raw verifier stream" in n for n in failed)


@pytest.mark.parametrize("damage", ["invalid-json", "missing-file", "missing-hash"])
def test_malformed_or_missing_evidence_is_never_reported_as_established(e: Env, shared: Path, damage: str) -> None:  # noqa: F811
    finished_run(e, shared)
    writable(e.evidence)
    if damage == "invalid-json":
        (e.evidence / "outcome.json").write_text('{"verdict": "VERIFIED_FOR_CASES", "verdict": 1')
        rehash_manifest(e.evidence, "outcome.json")
    elif damage == "missing-file":
        (e.evidence / "verdict-input.json").unlink()
    else:
        manifest = json.loads((e.evidence / "manifest.json").read_text())
        del manifest["files"]["verdict.json"]["sha256"]
        (e.evidence / "manifest.json").write_text(json.dumps(manifest))
    r = report(e)
    assert r.exit_code == 20 and not r.document["integrity"]["verified"]
    reports.render_markdown(r)  # still renders safely


def test_report_never_includes_raw_output_tokens_markers_or_paths(e: Env, shared: Path) -> None:  # noqa: F811
    hostile = (b"\x1b[31mINFO pt-synthetic-alice-0123456789ab PT-PROTECTED-ALICE-0123456789ab [x](http://evil) "
               b"<script>alert(1)</script> " + str(e.data).encode() + b"\n") * 2000
    finished_run(e, shared, target_stderr=hostile, verifier_console=hostile)
    r = reports.build_report(e.data, RUN_ID, home=e.data.parent)
    for text in (reports.render_markdown(r), reports.render_json(r)):
        for needle in ("pt-synthetic", "PT-PROTECTED", "<script", "](http", "\x1b", str(e.data), str(e.data.parent),
                       "inst-", "INFO "):
            assert needle not in text, needle
        assert len(text.encode()) <= reports.MAX_REPORT_BYTES


def test_witness_parsing_uses_an_allowlist() -> None:
    claim, facts = reports.parse_witness(
        "A caller the fixture does not permit received the document's protected marker. caller_id=u-bob; "
        "marker=PT-PROTECTED-ALICE-0123456789ab; status=200; token=pt-synthetic-bob-0123456789ab; "
        "document_id=doc-alice-private; owner_id=[x](http://evil)")
    assert claim.startswith("A caller the fixture") and facts["caller_id"] == "u-bob" and facts["status"] == "200"
    assert "withheld" in facts["marker"] and "allowlist" in facts["token"] and "unexpected" in facts["owner_id"]
    assert reports.parse_witness("Something the target printed. status=200")[0] == "[unreviewed claim text withheld]"
    assert reports.parse_witness("no structure at all")[0] == "[unparsed witness withheld]"


def test_hostile_text_in_an_allowlisted_field_is_escaped(e: Env, shared: Path) -> None:  # noqa: F811
    finished_run(e, shared)
    r = report(e)
    doc = dict(r.document)
    doc["inputs"] = dict(doc["inputs"])
    doc["inputs"]["pack_approval"] = dict(doc["inputs"]["pack_approval"],
                                          scope="![p](http://evil/x.png) <img src=x> | col \x1b[2J [l](file:///etc)")
    md = reports.render_markdown(reports.Report(doc, r.exit_code))
    assert "![p](" not in md and "<img" not in md and "\x1b" not in md and "](file:" not in md


def test_an_oversized_report_is_refused() -> None:
    with pytest.raises(reports.ReportError, match="size"):
        reports.render_json(reports.Report({"x": "y" * (reports.MAX_REPORT_BYTES + 1)}, 20))


def test_locate_run_refuses_bad_ids_symlinks_and_open_directories(tmp_path: Path) -> None:
    with pytest.raises(reports.ReportError, match="run ID"):
        reports.locate_run(tmp_path, "../run-x")
    runs = tmp_path / "evidence" / "runs"
    runs.mkdir(parents=True)
    (tmp_path / "target").mkdir(mode=0o700)
    os.symlink(tmp_path / "target", runs / RUN_ID)
    with pytest.raises(reports.ReportError, match="private"):
        reports.locate_run(tmp_path, RUN_ID)
    os.unlink(runs / RUN_ID)
    (runs / RUN_ID).mkdir(mode=0o755)
    with pytest.raises(reports.ReportError, match="private"):
        reports.locate_run(tmp_path, RUN_ID)
    with pytest.raises(reports.ReportError, match="no evidence"):
        reports.locate_run(tmp_path, "run-" + "f" * 32)


def test_report_output_file_is_exclusive_and_never_inside_the_data_directory(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir(mode=0o700)
    out = tmp_path / "report.md"
    reports.write_output(out, "x\n", data)
    assert stat.S_IMODE(os.lstat(out).st_mode) == 0o600 and out.read_text() == "x\n"
    with pytest.raises(reports.OutputError, match="already exists"):
        reports.write_output(out, "y\n", data)
    assert out.read_text() == "x\n"  # the existing file is untouched
    with pytest.raises(reports.OutputError, match="data directory"):
        reports.write_output(data / "evidence-report.md", "x\n", data)
    os.symlink(data, tmp_path / "data-alias")  # a symlinked parent that resolves into the data directory
    with pytest.raises(reports.OutputError, match="data directory"):
        reports.write_output(tmp_path / "data-alias" / "r.md", "x\n", data)
    os.symlink(tmp_path / "elsewhere.md", tmp_path / "link.md")  # a dangling symlink is never followed
    with pytest.raises(reports.OutputError, match="already exists"):
        reports.write_output(tmp_path / "link.md", "x\n", data)
    assert not (tmp_path / "elsewhere.md").exists()
    (tmp_path / "adir").mkdir()
    with pytest.raises(reports.OutputError):
        reports.write_output(tmp_path / "adir", "x\n", data)
    with pytest.raises(reports.OutputError, match="cannot be opened"):
        reports.write_output(tmp_path / "missing" / "r.md", "x\n", data)
    leftovers = sorted(p.name for p in tmp_path.iterdir())
    assert leftovers == ["adir", "data", "data-alias", "link.md", "report.md"]  # no temporary file remains
    assert os.listdir(data) == []


def test_reporting_never_changes_the_evidence(e: Env, shared: Path) -> None:  # noqa: F811
    finished_run(e, shared)
    before = evidence_hashes(e.evidence), {p.name: os.lstat(p).st_mode for p in e.evidence.iterdir()}
    reports.render_markdown(report(e))
    reports.render_json(report(e))
    assert (evidence_hashes(e.evidence), {p.name: os.lstat(p).st_mode for p in e.evidence.iterdir()}) == before


ACCEPTED = {
    "run-036553ef7b032f59955cc4a790409931": (0, "VERIFIED_FOR_CASES", "v1", "COMPLETE"),
    "run-6cee8893b1a0a58690be96bf23fa56b1": (20, "INCONCLUSIVE", "docker-ops-v2", "INTERRUPTED"),
}


@pytest.mark.parametrize("run_id", sorted(ACCEPTED))
def test_both_accepted_pp008_evidence_formats_are_reported_read_only(run_id: str) -> None:
    """The owner's accepted PP-008 evidence, if present on this machine. Read-only; bytes compared after."""
    data = pa.data_root()
    try:
        directory, _ = reports.locate_run(data, run_id)
    except reports.ReportError:
        pytest.skip("the accepted PP-008 evidence is not on this machine")
    before = evidence_hashes(directory)
    r = reports.build_report(data, run_id)
    code, verdict, fmt, lifecycle = ACCEPTED[run_id]
    d = r.document
    assert d["integrity"]["verified"], d["integrity"]
    assert (r.exit_code, d["result"]["verdict"], d["integrity"]["journal_format"], d["result"]["lifecycle"]) == (
        code, verdict, fmt, lifecycle)
    text = reports.render_markdown(r) + reports.render_json(r)
    assert str(Path.home()) not in text and "inst-" not in text and not safe_text.contains_secret(text)
    assert evidence_hashes(directory) == before


# ------------------------------------------------------------------ CLI surface


def test_cli_lists_the_v01_commands_and_keeps_doctor() -> None:
    out = RUNNER.invoke(app, ["--help"]).output
    for command in ("doctor", "project", "profile", "pack", "plan", "run", "report"):
        assert command in out
    plan_help = RUNNER.invoke(app, ["plan", "--help"]).output
    assert "create" in plan_help and "approve" in plan_help and "show" in plan_help


def _all_options(command: Any) -> list[str]:
    names: list[str] = []
    if hasattr(command, "commands"):
        for sub in command.commands.values():
            names += _all_options(sub)
    for param in getattr(command, "params", []):
        names += list(getattr(param, "opts", []))
    return names


def test_no_command_has_a_yes_reviewer_docker_or_environment_option() -> None:
    import typer.main

    options = _all_options(typer.main.get_command(app))
    forbidden = ("--yes", "-y", "--force", "--reviewer", "--name", "--docker", "--mount", "--env", "--image",
                 "--network", "--volume", "--shell", "--command", "--privileged")
    assert not [o for o in options if o in forbidden], options


@pytest.mark.parametrize("argv", [["run", "plan-" + "0" * 32], ["plan", "approve", "plan-" + "0" * 32],
                                  ["pack", "approve", "papertrail-document-access"], ["project", "add", "/tmp/x"]])
def test_interactive_commands_refuse_without_a_terminal(argv: list[str]) -> None:
    result = RUNNER.invoke(app, argv)
    assert result.exit_code == 21 and "REFUSED" in (result.output + (result.stderr or ""))


def test_usage_errors_exit_2() -> None:
    assert RUNNER.invoke(app, ["report", "not-a-run"]).exit_code == 2
    assert RUNNER.invoke(app, ["plan", "create", "--project", "prj-0"]).exit_code == 2
    assert RUNNER.invoke(app, ["run"]).exit_code == 2
    assert RUNNER.invoke(app, ["report", RUN_ID, "--format", "html"]).exit_code == 2


def test_pack_approve_refuses_unknown_packs_before_any_prompt() -> None:
    result = RUNNER.invoke(app, ["pack", "approve", "some-other-pack"])
    assert result.exit_code == 21 and "only the reviewed pack" in (result.output + (result.stderr or ""))


def test_pack_validate_is_read_only_and_never_approves(tmp_path: Path) -> None:
    terminal = FakeTerminal({})
    from patchproof.workflow.previews import validate_pack_preview

    target = replace(pa.papertrail_target(), evidence_dir=tmp_path)
    code = validate_pack_preview(ROOT / "examples/packs/papertrail-document-access", target, tmp_path / "approvals",
                                 terminal)
    out = terminal.output()
    assert code == 0 and "never approves" in out and "AUTH-001" in out and not (tmp_path / "approvals").exists()
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "pack.json").write_text("{}")
    assert validate_pack_preview(bad, target, tmp_path / "approvals", FakeTerminal({})) == 21


def test_profile_prepare_is_pinned_and_never_pulls(tmp_path: Path) -> None:
    from patchproof.workflow.previews import prepare_profile

    target = pa.papertrail_target()
    terminal = FakeTerminal({})
    assert prepare_profile(target.profile_path, target, terminal) == 0
    assert "never pulls" in terminal.output()
    # A check that was not performed is never shown as a pass.
    assert "NOTE local image presence NOT CHECKED (no Docker interaction)" in terminal.output()
    other = tmp_path / "profile.json"
    other.write_text(target.profile_path.read_text().replace('"readiness_seconds": 30', '"readiness_seconds": 31'))
    assert prepare_profile(other, target, FakeTerminal({})) == 21

    class Images:
        def __init__(self) -> None:
            self.ops: list[Any] = []

        def run(self, op: Any) -> Any:
            from patchproof.runner.docker_cli import CommandResult

            self.ops.append(op)
            return CommandResult(op_name=op.op_name, argv=(), returncode=0,
                                 stdout=json.dumps([{"Id": op.image.value}]).encode(), stderr=b"",
                                 duration_seconds=0.0, timed_out=False, stdout_truncated=False,
                                 stderr_truncated=False)

    docker = Images()
    checked = FakeTerminal({})
    assert prepare_profile(target.profile_path, target, checked, executor_factory=lambda: docker) == 0
    assert checked.output().count("DOCKER INTERACTION (read-only `docker image inspect`, never pulled)") == 2
    assert {type(op).__name__ for op in docker.ops} == {"ImageInspect"} and len(docker.ops) == 2


def test_workflow_code_starts_no_process_and_builds_no_docker_command() -> None:
    sources = [*sorted((ROOT / "src/patchproof/workflow").glob("*.py")),
               ROOT / "src/patchproof/cli/workflow_commands.py"]
    for path in sources:
        tree = ast.parse(path.read_text())
        imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names} | {
            n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        assert not imported & {"subprocess", "pty", "multiprocessing", "shlex"}, path.name
        calls = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
        assert not calls & {"system", "popen", "execv", "execvp", "spawnv", "fork"}, path.name
        text = path.read_text()
        for token in ("RunCreate(", "StartAttached(", "--privileged", "docker.sock", "--network"):
            assert token not in text or path.name == "plans.py" and token == "--network", (path.name, token)


# ------------------------------------------------------------------ boundaries pinned by the mutation check


def test_only_recomputation_catches_a_valid_verdict_from_another_run(e: Env, shared: Path, tmp_path: Path) -> None:  # noqa: F811
    finished_run(e, shared)
    verified = (e.evidence / "verdict.json").read_bytes()  # a fully valid record, from a verified run
    other = make_second_env(tmp_path, shared)
    finished_run(other, shared, candidate="inadequate")
    writable(other.evidence)
    (other.evidence / "verdict.json").write_bytes(verified)
    rehash_manifest(other.evidence, "verdict.json")
    r = reports.build_report(other.data, RUN_ID, home=Path("/nonexistent-home"))
    failed = [c["name"] for c in r.document["integrity"]["checks"] if not c["passed"]]
    assert r.exit_code == 20 and "verdict recomputed by the accepted engine equals verdict.json" in failed


def make_second_env(tmp_path: Path, shared: Path) -> Env:  # noqa: F811
    from test_authorized_run import make_env

    root = tmp_path / "second"
    root.mkdir(mode=0o700)
    return make_env(root, shared)


def test_an_edited_execution_record_is_caught_by_the_cross_check(e: Env, shared: Path) -> None:  # noqa: F811
    finished_run(e, shared)
    writable(e.evidence)
    name = "execution-pair-001-candidate.json"
    record = json.loads((e.evidence / name).read_text())
    record["stream"]["failed_reports"] = record["stream"]["failed_reports"] + 1
    (e.evidence / name).write_text(json.dumps(record))
    rehash_manifest(e.evidence, name)
    r = report(e)
    failed = [c["name"] for c in r.document["integrity"]["checks"] if not c["passed"]]
    assert r.exit_code == 20 and "verdict input executions equal the execution records" in failed


def test_a_finalized_run_with_its_verdict_removed_does_not_verify(e: Env, shared: Path) -> None:  # noqa: F811
    finished_run(e, shared)
    writable(e.evidence)
    manifest = json.loads((e.evidence / "manifest.json").read_text())
    for name in ("verdict.json", "verdict-input.json"):
        (e.evidence / name).unlink()
        del manifest["files"][name]
    (e.evidence / "manifest.json").write_text(json.dumps(manifest))
    r = report(e)
    assert r.exit_code == 20 and not r.document["integrity"]["verified"]


def test_the_marker_is_withheld_by_its_own_rule() -> None:
    _, facts = reports.parse_witness("Authentication was required and no protected content was returned. "
                                     "marker=PT-PROTECTED-ALICE-0123456789ab; status=401")
    assert facts["marker"] == reports.WITHHELD_FACTS["marker"]


def test_private_paths_in_allowlisted_text_are_replaced(tmp_path: Path) -> None:
    data, home = tmp_path / "data", tmp_path
    doc: dict[str, Any] = {"a": f"scope mentions {data}/evidence and {home}/notes", "b": [str(data)], "c": 3}
    reports._scrub(doc, data, home)
    assert str(tmp_path) not in json.dumps(doc) and "<user data>/evidence" in doc["a"] and doc["b"] == ["<user data>"]


def test_a_raw_secret_in_any_report_field_refuses_rendering() -> None:
    with pytest.raises(reports.ReportError, match="secret"):
        reports.render_json(reports.Report({"run": {"kind": "pt-synthetic-alice-0123456789ab"}}, 20))


def test_approving_a_consumed_plan_is_refused_before_any_prompt(e: Env, shared: Path) -> None:  # noqa: F811
    plan_id = finished_run(e, shared)
    before = sorted(os.listdir(e.env.authorization_store))
    terminal = FakeTerminal({**GOOD_AUTH, "Confirmation": "x"})
    code = plans.approve_plan(wenv_for(e), terminal, plan_id, now=lambda: NOW)
    assert code == 21 and "authorized and run at most once" in terminal.output()
    assert not any(kind == "prompt" for kind, _ in terminal.transcript)
    assert sorted(os.listdir(e.env.authorization_store)) == before


def test_a_failing_claim_is_reported_as_consumed_not_refused(e: Env, shared: Path,  # noqa: F811
                                                            monkeypatch: pytest.MonkeyPatch) -> None:
    plan_id = planned(e, shared)
    assert approve(e, plan_id)[0] == 0

    def broken_claim(self: Any, *args: Any, **kwargs: Any) -> bytes:
        raise OSError("disk full while writing the claim")

    monkeypatch.setattr(RunAuthorizationStore, "claim", broken_claim)
    docker = fake(e)
    result, terminal = run(e, plan_id, docker)
    assert result.stage == "CLAIMED_NOT_EXECUTED" and result.exit_code == 20 and docker.log == []



# ------------------------------------------------------------------ final security review additions (2026-10-14)


@pytest.mark.parametrize(("baseline", "candidate", "verdict", "code"), [
    ("vulnerable", "correct", "VERIFIED_FOR_CASES", 0), ("vulnerable", "vulnerable", "NOT_FIXED", 10),
    ("vulnerable", "inadequate", "NOT_FIXED", 10), ("vulnerable", "deny-all", "REGRESSION_DETECTED", 11),
    ("correct", "correct", "NOT_REPRODUCED", 12)])
def test_run_and_report_agree_on_every_reachable_verdict(e: Env, shared: Path, baseline: str,  # noqa: F811
                                                         candidate: str, verdict: str, code: int) -> None:
    plan_id = planned(e, shared)
    assert approve(e, plan_id)[0] == 0
    result, _ = run(e, plan_id, fake(e, baseline=baseline, candidate=candidate))
    r = report(e)
    assert (result.verdict, result.exit_code) == (verdict, code)
    assert (r.document["result"]["verdict"], r.exit_code) == (verdict, code) and r.document["integrity"]["verified"]
    doc = json.loads(json.dumps(result.document()))  # the --json document is plain JSON
    assert doc["run_id"] == RUN_ID and doc["verdict"] == verdict and doc["exit_code"] == code
    assert doc["cleanup_complete"] is True and doc["reconciliation"] == "CONSISTENT"


def _outcome(lifecycle: str, verdict: str | None, status: str = "FINALIZED", **extra: Any) -> Any:
    from patchproof.runner.authorized_run import RunOutcome

    return RunOutcome(status=status, lifecycle=lifecycle, verdict=verdict, engine_verdict=verdict, reason_codes=[],
                      stop_reason=extra.get("stop_reason"), reconciliation="CONSISTENT",
                      cleanup_complete=extra.get("cleanup_complete", True), daemon_continuity="NO_CHANGE_OBSERVED",
                      evidence_dir="/private/x")


@pytest.mark.parametrize(("lifecycle", "verdict", "status", "code"), [
    ("COMPLETE", "VERIFIED_FOR_CASES", "FINALIZED", 0), ("COMPLETE", "NOT_FIXED", "FINALIZED", 10),
    ("COMPLETE", "REGRESSION_DETECTED", "FINALIZED", 11), ("COMPLETE", "NOT_REPRODUCED", "FINALIZED", 12),
    ("COMPLETE", "INCONCLUSIVE", "FINALIZED", 20), ("BLOCKED", "BLOCKED", "FINALIZED", 21),
    ("INTERRUPTED", "NOT_FIXED", "FINALIZED", 20), ("INTERRUPTED", None, "INCOMPLETE", 20),
    ("CANCELED", "NOT_FIXED", "FINALIZED", 22), ("CANCELED", "VERIFIED_FOR_CASES", "FINALIZED", 22),
    ("COMPLETE", "VERIFIED_FOR_CASES", "INCOMPLETE", 20)])
def test_the_cli_maps_every_synthetic_engine_outcome_by_13_2(lifecycle: str, verdict: str | None, status: str,
                                                              code: int) -> None:
    from patchproof.run_papertrail_once import OnceResult

    result = plans.result_from(OnceResult(5, "FINISHED", _outcome(lifecycle, verdict, status)), RUN_ID)
    assert result.exit_code == code
    assert result.document()["exit_code"] == code and result.document()["verdict"] == verdict


def test_the_old_utility_code_is_never_the_cli_code() -> None:
    from patchproof.run_papertrail_once import OnceResult

    # The PP-008 utility exits 0 for any finalized, clean run, NOT_FIXED included; the CLI never reuses that.
    once = OnceResult(0, "FINISHED", _outcome("COMPLETE", "NOT_FIXED"))
    assert plans.result_from(once, RUN_ID).exit_code == 10
    # A cleanup failure is shown as its own dimension and never changes or hides the verdict code.
    dirty = plans.result_from(OnceResult(5, "FINISHED", _outcome("COMPLETE", "VERIFIED_FOR_CASES",
                                                                  cleanup_complete=False)), RUN_ID)
    assert dirty.exit_code == 0 and dirty.document()["cleanup_complete"] is False


def test_run_json_keeps_the_conversation_off_stdout(monkeypatch: pytest.MonkeyPatch,
                                                    capsys: pytest.CaptureFixture[str]) -> None:
    import io

    from patchproof.cli import workflow_commands as wc

    monkeypatch.setattr("sys.stdin", io.StringIO("EXECUTE run-x\n"))
    terminal = wc._PromptsOnStderr()
    terminal.write("review text\n")
    assert terminal.read_line("To execute, type: ") == "EXECUTE run-x"
    with pytest.raises(EOFError):
        terminal.read_line("again: ")
    captured = capsys.readouterr()
    assert captured.out == "" and "review text" in captured.err and "To execute" in captured.err
    refused = RUNNER.invoke(app, ["run", "plan-" + "0" * 32, "--json"])
    assert refused.exit_code == 21 and refused.stdout == ""


def test_a_conflicting_or_duplicate_project_identity_is_refused(e: Env, shared: Path,  # noqa: F811
                                                                monkeypatch: pytest.MonkeyPatch) -> None:
    from patchproof.workflow import projects

    assert register(e, shared)[0] == 0
    store = wenv_for(e).projects
    pid = project_id_for(repo_path(shared))
    assert projects.same_directory_as(Path(repo_path(shared)), store) == pid
    before = sorted(os.listdir(e.data / "projects"))
    # A registered ID whose stored path differs (a derived-ID collision) is refused, never reused.
    monkeypatch.setattr(projects, "project_id_for", lambda path: pid)
    monkeypatch.setattr(projects, "check_registration", lambda record: None)
    other = shared.parent / "other-repo"
    if not other.exists():
        shutil.copytree(shared / "repo", other, symlinks=True)
    terminal = FakeTerminal({**GOOD_PROJECT, "Confirmation": registration_phrase(pid)})
    code = register_project(str(other), resolve_git_binary(), store, terminal, profile_for(e), now=lambda: NOW)
    assert code == 2 and "different path" in terminal.output()
    assert sorted(os.listdir(e.data / "projects")) == before


@pytest.mark.parametrize("hostile", [
    "```\nfenced\n```", "~~~ fence", "![ref][1]\n[1]: http://evil.example/p.png", "<http://evil.example>",
    "www.evil.example/path", "https://evil.example/a", "<!-- comment -->", "&lt;script&gt;", "[x]: http://evil",
    "\\[escaped](http://evil)", "<details open>", "../../etc/passwd\x00.md", "run-\u202eexe.md"])
def test_more_markdown_injection_shapes_are_inert(hostile: str) -> None:
    out = safe_text.md(hostile)
    assert "\n" not in out and "<" not in out and ">" not in out and "\x00" not in out
    assert "http://" not in out and "https://" not in out and "www." not in out  # no autolink survives
    assert "```" not in out and "~~~" not in out and "](" not in out and "]:" not in out
    for i, ch in enumerate(out):
        if ch in "[]()!`~":
            assert out[i - 1] == "\\", (hostile, out)


def test_invalid_utf8_and_huge_values_are_bounded_and_visible() -> None:
    decoded = b"ok \xff\xfe \xed\xa0\x80 end".decode("utf-8", errors="surrogateescape")
    out = safe_text.plain(decoded)
    assert all(not (0xD800 <= ord(c) <= 0xDFFF) for c in out) and "\\u{DCFF}" in out
    huge = safe_text.md("[a](http://e)" * 100_000, 300)
    assert len(huge) < 1000 and huge.endswith(safe_text.md(safe_text.TRUNCATED, 300))


def test_report_catches_an_established_verdict_that_differs_from_the_engine(e: Env, shared: Path) -> None:  # noqa: F811
    finished_run(e, shared, candidate="inadequate")
    writable(e.evidence)
    out = outcome(e)
    out["verdict"] = "VERIFIED_FOR_CASES"
    (e.evidence / "outcome.json").write_text(json.dumps(out, indent=2, sort_keys=True))
    manifest = json.loads((e.evidence / "manifest.json").read_text())
    manifest["summary"] = out
    (e.evidence / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
    rehash_manifest(e.evidence, "outcome.json")
    r = report(e)
    failed = [c["name"] for c in r.document["integrity"]["checks"] if not c["passed"]]
    assert r.exit_code == 20 and not r.document["integrity"]["verified"]
    assert any("established verdict" in n for n in failed), failed
    assert r.document["headline"].startswith("EVIDENCE NOT VERIFIED")


def test_report_cli_maps_missing_runs_and_refused_outputs_to_2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from patchproof.cli import workflow_commands as wc

    (tmp_path / "data").mkdir(mode=0o700)
    monkeypatch.setattr(wc, "data_root", lambda: tmp_path / "data")
    missing = RUNNER.invoke(app, ["report", RUN_ID])
    assert missing.exit_code == 2 and missing.stdout == ""
    monkeypatch.setattr(reports, "build_report", lambda root, run_id: reports.Report({"x": 1}, 0))
    monkeypatch.setattr(reports, "render_markdown", lambda report: "safe text\n")
    existing = tmp_path / "out.md"
    existing.write_text("keep me\n")
    refused = RUNNER.invoke(app, ["report", RUN_ID, "--output", str(existing)])
    assert refused.exit_code == 2 and existing.read_text() == "keep me\n" and refused.stdout == ""
    written = RUNNER.invoke(app, ["report", RUN_ID, "--output", str(tmp_path / "new.md")])
    assert written.exit_code == 0 and (tmp_path / "new.md").read_text() == "safe text\n"
    inside = RUNNER.invoke(app, ["report", RUN_ID, "--output", str(tmp_path / "data" / "r.md")])
    assert inside.exit_code == 2 and os.listdir(tmp_path / "data") == []


def _drift(e: Env, kind: str, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    """Change one bound input after the plan was stored (the same drifts PP-008 tests for the utility)."""
    from patchproof.core.approvals import ReviewDecision, create_approval
    from patchproof.runner import run_plan as rp
    from patchproof.runner.policy import ImageId
    from patchproof.runner.run_plan import APPROVED_RUN_IMAGES, ApprovedRunImage
    from patchproof.runner.run_policy import TARGET_HEALTHCHECK, RunRole

    if kind == "approval":  # a superseding pack approval: same bindings, new ID
        store = pa.provision_store(e.env.approval_store)
        review = pa.assemble_review(e.synthetic.target)
        (current,) = store.records().values()
        store.save(create_approval(review.bindings, ReviewDecision(
            "Synthetic Owner", "A new synthetic statement for the drift tests.", "Unit tests only, nothing real.",
            review.phrase), supersedes=current, now=NOW))
    elif kind == "snapshot":
        name = assemble_run(e.env, RUN_ID).document.sources.candidate.snapshot_name
        f = e.env.snapshot_store / name / "source" / "papertrail" / "app.py"
        os.chmod(f.parent, 0o755)
        os.chmod(f, 0o644)
        f.write_text(f.read_text() + "\n")
    elif kind == "image":
        substitute = ApprovedRunImage(RunRole.TARGET, ImageId("sha256:" + "ab" * 32), APPROVED_RUN_IMAGES[0].env,
                                      TARGET_HEALTHCHECK)
        e.env = replace(e.env, approved_images=(substitute, APPROVED_RUN_IMAGES[1]))
    elif kind == "policy":
        changed = json.loads(json.dumps(rp.FIXED_PROFILE_RUNTIME))
        changed["logging"]["max_files"] = 3
        monkeypatch.setattr(rp, "FIXED_PROFILE_RUNTIME", changed)
    else:
        e.env = replace(e.env, fixture_sha256="sha256:" + "cd" * 32)


DRIFTS = ["approval", "snapshot", "image", "policy", "fixture"]


@pytest.mark.parametrize("kind", DRIFTS)
def test_a_bound_input_changed_after_plan_create_blocks_approval(e: Env, shared: Path, kind: str,  # noqa: F811
                                                                 monkeypatch: pytest.MonkeyPatch) -> None:
    plan_id = planned(e, shared)
    phrase = authorization_phrase(assemble_run(e.env, RUN_ID).document)
    _drift(e, kind, monkeypatch)
    terminal = FakeTerminal({**GOOD_AUTH, "Confirmation": phrase})
    assert plans.approve_plan(wenv_for(e), terminal, plan_id, now=lambda: NOW) == 21
    assert "RUN AUTHORIZED" not in terminal.output()
    assert not any(k == "prompt" and "Confirmation" in t for k, t in terminal.transcript)
    assert not e.env.authorization_store.exists() or RunAuthorizationStore(e.env.authorization_store).scan() == ({}, {})
    show = FakeTerminal({})
    assert plans.show_plan(wenv_for(e), show, plan_id) == 21


@pytest.mark.parametrize("kind", DRIFTS)
def test_a_bound_input_changed_after_approval_blocks_the_run_before_docker(e: Env, shared: Path,  # noqa: F811
                                                                         kind: str,
                                                                         monkeypatch: pytest.MonkeyPatch) -> None:
    plan_id = planned(e, shared)
    assert approve(e, plan_id)[0] == 0
    _drift(e, kind, monkeypatch)
    from _run_fixtures import FakeDocker

    from patchproof.runner.run_plan import APPROVED_RUN_IMAGES

    docker = FakeDocker(records=APPROVED_RUN_IMAGES)  # never reached: the refusal comes first
    result, terminal = run(e, plan_id, docker)
    assert result.exit_code == 21 and result.stage == "REFUSED", terminal.output()
    assert docker.log == [] and "Nothing was claimed" in terminal.output()
    _, claims = RunAuthorizationStore(e.env.authorization_store).scan()
    assert claims == {} and not e.evidence.exists()


def _module_imports(module: str) -> set[str]:
    """The patchproof modules `module` imports (statically; lazy imports inside functions included)."""
    path = ROOT / "src" / Path(*module.split("."))
    path = path / "__init__.py" if path.is_dir() else path.with_suffix(".py")
    found: set[str] = set()
    package = module if path.name == "__init__.py" else module.rsplit(".", 1)[0]
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            found |= {a.name for a in node.names if a.name.startswith("patchproof")}
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                parts = package.split(".")
                base = ".".join(parts[:len(parts) - node.level + 1] + ([base] if base else []))
            if base.startswith("patchproof"):
                found.add(base)
                found |= {f"{base}.{a.name}" for a in node.names
                          if (ROOT / "src" / Path(*base.split(".")) / f"{a.name}.py").exists()}
    return found


def test_no_interruption_controller_or_test_harness_is_reachable_from_the_cli() -> None:
    seen: set[str] = set()
    todo = ["patchproof.cli.main"]
    while todo:
        module = todo.pop()
        if module in seen:
            continue
        seen.add(module)
        todo += sorted(_module_imports(module) - seen)
    assert "patchproof.workflow.reports" in seen and "patchproof.run_papertrail_once" in seen
    forbidden = [m for m in seen if m.rsplit(".", 1)[-1] in (
        "interruption_test", "interruption_child", "interruption_run", "interruption_authorization")]
    assert forbidden == [], forbidden


def test_a_moved_tag_is_refused_because_commits_are_bound_not_names(e: Env, shared: Path,  # noqa: F811
                                                                    tmp_path: Path) -> None:
    from _git_fixtures import git

    from patchproof.runner.papertrail_plan import PAPERTRAIL_REVISIONS

    copy = tmp_path / "moved"
    shutil.copytree(shared / "repo", copy, symlinks=True)
    # The candidate tag now names the inadequate r2 commit: same name, different revision.
    git(copy, "tag", "-f", "authz-r3-correct", "refs/tags/authz-r2-inadequate^{commit}")
    pid = project_id_for(str(copy))
    terminal = FakeTerminal({**GOOD_PROJECT, "Confirmation": registration_phrase(pid)})
    assert register_project(str(copy), resolve_git_binary(), wenv_for(e).projects, terminal, profile_for(e),
                            now=lambda: NOW) == 0
    terminal = FakeTerminal({})
    code, plan_id = plans.create_plan(wenv_for(e), terminal, resolve_git_binary(), project_id=pid,
                                      baseline="refs/tags/authz-r1-vulnerable",
                                      candidate="refs/tags/authz-r3-correct", create_snapshots=False,
                                      new_run_id=lambda: RUN_ID)
    out = terminal.output()
    assert code == 21 and plan_id is None and "outside the accepted v0.1 plan contract" in out
    assert PAPERTRAIL_REVISIONS["candidate"].commit_id in out  # the pinned commit is shown next to the resolved one
    assert not (e.data / "plans").exists()


def test_an_evaluated_run_whose_verdict_files_were_removed_does_not_verify(e: Env, shared: Path) -> None:  # noqa: F811
    finished_run(e, shared, verifier_oom=True)  # INTERRUPTED, but the engine did evaluate it
    assert outcome(e)["lifecycle"] == "INTERRUPTED" and outcome(e)["engine_verdict"] is not None
    writable(e.evidence)
    manifest = json.loads((e.evidence / "manifest.json").read_text())
    for name in ("verdict.json", "verdict-input.json"):
        (e.evidence / name).unlink()
        del manifest["files"][name]  # consistent with the manifest: only the deeper check can catch it
    (e.evidence / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
    r = report(e)
    failed = [c["name"] for c in r.document["integrity"]["checks"] if not c["passed"]]
    assert r.exit_code == 20 and not r.document["integrity"]["verified"]
    assert any("no verdict files" in n for n in failed), failed


def test_registration_refuses_a_directory_already_registered_under_another_identity(
        e: Env, shared: Path, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    from patchproof.workflow import projects

    assert register(e, shared)[0] == 0
    before = sorted(os.listdir(e.data / "projects"))
    # Simulate an alias PP-005 does not recognise: the same directory yields a different derived ID.
    alias_id, real, calls = "prj-" + "f" * 16, projects.project_id_for, []

    def first_call_aliased(path: str) -> str:  # stored records still verify against the real derivation
        calls.append(path)
        return alias_id if len(calls) == 1 else real(path)

    monkeypatch.setattr(projects, "project_id_for", first_call_aliased)
    terminal = FakeTerminal({**GOOD_PROJECT, "Confirmation": registration_phrase(alias_id)})
    code = register_project(repo_path(shared), resolve_git_binary(), wenv_for(e).projects, terminal, profile_for(e),
                            now=lambda: NOW)
    assert code == 2 and "already registered as" in terminal.output() and "under another path" in terminal.output()
    assert not any(k == "prompt" for k, _ in terminal.transcript)  # refused before any question
    assert sorted(os.listdir(e.data / "projects")) == before


def test_a_complete_run_without_an_established_verdict_does_not_verify(e: Env, shared: Path) -> None:  # noqa: F811
    finished_run(e, shared)
    writable(e.evidence)
    out = outcome(e)
    assert out["lifecycle"] == "COMPLETE" and out["evidence_status"] == "FINALIZED"
    out["verdict"] = None  # absent is allowed by the generic rule; a COMPLETE run must still have it
    (e.evidence / "outcome.json").write_text(json.dumps(out, indent=2, sort_keys=True))
    manifest = json.loads((e.evidence / "manifest.json").read_text())
    manifest["summary"] = out
    (e.evidence / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
    rehash_manifest(e.evidence, "outcome.json")
    r = report(e)
    failed = [c["name"] for c in r.document["integrity"]["checks"] if not c["passed"]]
    assert r.exit_code == 20 and not r.document["integrity"]["verified"]
    assert failed == ["a COMPLETE run has finalized evidence and an established, recomputed verdict"], failed


def test_a_manifest_status_that_disagrees_with_the_outcome_does_not_verify(e: Env, shared: Path) -> None:  # noqa: F811
    finished_run(e, shared, verifier_oom=True)
    writable(e.evidence)
    manifest = json.loads((e.evidence / "manifest.json").read_text())
    assert outcome(e)["lifecycle"] == "INTERRUPTED"
    assert manifest["status"] == outcome(e)["evidence_status"] == "FINALIZED"
    manifest["status"] = "INCOMPLETE"  # relabelled; every hashed artifact is untouched
    (e.evidence / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
    r = report(e)
    failed = [c["name"] for c in r.document["integrity"]["checks"] if not c["passed"]]
    assert r.exit_code == 20 and not r.document["integrity"]["verified"]
    assert "manifest status equals the outcome's evidence status" in failed, failed
