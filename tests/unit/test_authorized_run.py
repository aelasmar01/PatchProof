"""PP-008: single-use run authorization, the PaperTrail driver and evidence capture, Docker-free.

Everything here is SYNTHETIC and lives in temporary directories:
- a renamed copy of the PaperTrail pack (`synthetic-approval-test`) with a synthetic approval;
- r1/r3 snapshots taken from a freshly generated PP-006 reference repository;
- a scripted fake Docker (`_run_fixtures.FakeDocker`) and synthetic verifier streams built
  from PP-006's *declared* outcomes.

No real approval store, authorization store, snapshot or evidence directory is opened, no
container is started and PaperTrail is never imported or executed. A `VERIFIED_FOR_CASES`
here proves only that the orchestration composes with the accepted engine.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import stat
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from _run_fixtures import FakeDocker, declared_outcomes, private, stream
from test_pack_approval import FakeTerminal, build

from patchproof import pack_approval as pa
from patchproof.core.approvals import ReviewDecision, create_approval
from patchproof.core.run_authorizations import RunAuthorizationStore, authorization_phrase
from patchproof.git.command import resolve_git_binary
from patchproof.git.paths import SourceScope
from patchproof.git.repository import register_repository
from patchproof.git.snapshot import create_snapshot
from patchproof.reference.papertrail import generate_reference_repository
from patchproof.run_authorization import run_authorization
from patchproof.run_papertrail_once import run_once
from patchproof.runner import run_plan
from patchproof.runner.docker_cli import SnapshotList
from patchproof.runner.inputs import materialize_pack
from patchproof.runner.papertrail_plan import PAPERTRAIL_REVISIONS, RunEnvironment, assemble_run
from patchproof.runner.policy import ImageId
from patchproof.runner.run_plan import APPROVED_RUN_IMAGES, ApprovedRunImage
from patchproof.runner.run_evidence import verify_evidence
from patchproof.runner.run_policy import TARGET_HEALTHCHECK, RunCreate, RunRole

RUN_ID = "run-0123456789abcdef0123456789abcdef"
NOW = datetime(2026, 10, 13, 12, 0, tzinfo=UTC)
GOOD = {"Your name": "Synthetic Owner", "Rationale": "Synthetic test authorization for the orchestration only.",
        "Authorization scope": "Unit tests in a temporary directory; authorizes nothing real."}


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture(scope="module")
def shared(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One generated reference repository and its r1/r3 snapshots, copied into each test."""
    root = private(tmp_path_factory.mktemp("pp008-authorized") / "shared")
    generated = generate_reference_repository(root / "repo")
    repo = register_repository(generated.root, resolve_git_binary())
    store = private(root / "snapshots")
    for pinned in PAPERTRAIL_REVISIONS.values():
        create_snapshot(repo, pinned.commit_id, SourceScope.of(["papertrail", "fixtures/synthetic"]), store)
    return root


@dataclass
class Env:
    env: RunEnvironment
    data: Path
    synthetic: Any  # test_pack_approval.Synthetic

    @property
    def evidence(self) -> Path:
        return self.env.evidence_root / RUN_ID


def make_env(tmp_path: Path, shared: Path) -> Env:
    s = build(tmp_path)
    data = s.store_root.parent
    review = pa.assemble_review(s.target)
    approvals = pa.provision_store(s.store_root)
    approvals.save(create_approval(review.bindings, ReviewDecision(
        "Synthetic Owner", "Synthetic approval for unit tests.", "Unit tests only.", review.phrase),
        supersedes=None, now=NOW))
    pack_store = private(data / "pack-store")
    materialize_pack(review.pack, pack_store)
    shutil.copytree(shared / "snapshots", data / "source-snapshots")
    os.chmod(data / "source-snapshots", 0o700)
    private(data / "probe-runs")
    (data / "probe-runs" / "installation-id").write_text("inst-" + "fedcba9876543210" * 2 + "\n")
    private(data / "evidence")
    env = RunEnvironment(approval_target=s.target, approval_store=s.store_root,
                         authorization_store=data / "run-authorizations", snapshot_store=data / "source-snapshots",
                         pack_store=pack_store, evidence_root=data / "evidence" / "runs",
                         installation_id_file=data / "probe-runs" / "installation-id")
    return Env(env=env, data=data, synthetic=s)


@pytest.fixture
def e(tmp_path: Path, shared: Path) -> Env:
    return make_env(tmp_path, shared)


def authorize(e: Env, overrides: dict[str, str] | None = None, run_id: str = RUN_ID,
              on_prompt: dict[str, Callable[[], None]] | None = None) -> tuple[int, FakeTerminal]:
    phrase = authorization_phrase(assemble_run(e.env, run_id).document)
    terminal = FakeTerminal({**GOOD, "Confirmation": phrase, **(overrides or {})}, on_prompt=on_prompt or {})
    return run_authorization(e.env, terminal, now=lambda: NOW, new_run_id=lambda: run_id), terminal


def fake(e: Env, *, baseline: str = "vulnerable", candidate: str = "correct", **knobs: Any) -> FakeDocker:
    plan = assemble_run(e.env, RUN_ID).plan
    docker = FakeDocker(records=APPROVED_RUN_IMAGES, **knobs)
    docker.streams = {"baseline": stream(plan, 1, "baseline", declared_outcomes(baseline)),
                      "candidate": stream(plan, 1, "candidate", declared_outcomes(candidate))}
    return docker


def execute(e: Env, docker: FakeDocker | None = None, typed: str | None = None) -> tuple[int, FakeTerminal, FakeDocker]:
    docker = docker or fake(e)
    terminal = FakeTerminal({"To execute": typed if typed is not None else f"EXECUTE {RUN_ID}"})
    code = run_once(e.env, terminal, lambda: docker, clock=FakeClock(), now=lambda: NOW)
    return code, terminal, docker


def outcome(e: Env) -> dict[str, Any]:
    return dict(json.loads((e.evidence / "outcome.json").read_text()))


def manifest(e: Env) -> dict[str, Any]:
    return dict(json.loads((e.evidence / "manifest.json").read_text()))


def creates(docker: FakeDocker) -> list[tuple[str, str]]:
    return [(op.spec.side, op.spec.role.value) for op in docker.log if isinstance(op, RunCreate)]


def store_names(e: Env) -> list[str]:
    root = e.env.authorization_store
    return sorted(os.listdir(root)) if root.exists() else []


def writable(path: Path) -> None:
    for dirpath, _dirs, files in os.walk(path):
        os.chmod(dirpath, 0o700)
        for f in files:
            os.chmod(Path(dirpath) / f, 0o600)


# ------------------------------------------------------------------ plan assembly


def test_plan_binds_every_full_identity(e: Env) -> None:
    run = assemble_run(e.env, RUN_ID)
    d = run.document
    review = pa.assemble_review(e.synthetic.target)
    assert d.run_id == RUN_ID and d.installation_id == "inst-" + "fedcba9876543210" * 2
    assert d.pack.manifest_sha256 == review.pack.manifest_sha256
    assert d.pack.pack_tree_sha256 == review.pack.pack_tree_sha256
    assert [(t.id, t.nodeid) for t in d.pack.expected_collection] == [(t.id, t.nodeid) for t in review.collection]
    assert d.profile.profile_sha256 == review.profile.sha256
    assert (d.images.target_image_id, d.images.verifier_image_id) == tuple(a.image.value for a in APPROVED_RUN_IMAGES)
    for side, pinned in PAPERTRAIL_REVISIONS.items():
        src = getattr(d.sources, side)
        assert (src.tag, src.commit_id, src.tree_id) == (pinned.tag, pinned.commit_id, pinned.tree_id)
        raw = (e.env.snapshot_store / src.snapshot_name / "source-manifest.json").read_bytes()
        assert src.source_manifest_sha256 == "sha256:" + hashlib.sha256(raw).hexdigest()
    assert d.source_inclusion.include == ["fixtures/synthetic", "papertrail"]
    assert d.fixture.seed is None and d.fixture.mode == "fixed-fixture-v0.1-exception"
    assert d.repetitions.pairs == 1 and d.containers.max_creations == 4
    assert [c.name for c in d.containers.sequence] == [
        f"pp-run-{RUN_ID[4:16]}-p1-{s}-{r}" for s in ("baseline", "candidate") for r in ("target", "verifier")]
    assert run.sha256 == assemble_run(e.env, RUN_ID).sha256  # deterministic


def test_pinned_revisions_equal_the_accepted_reference_record() -> None:
    truth = json.loads((Path(__file__).resolve().parents[2] / "examples/papertrail/reference-fixture.json")
                       .read_text())
    by_role = {r["key"]: r for r in truth["revisions"]}
    for side, key in (("baseline", "vulnerable"), ("candidate", "correct")):
        pinned = PAPERTRAIL_REVISIONS[side]  # type: ignore[index]
        assert (pinned.tag, pinned.commit_id, pinned.tree_id) == (
            by_role[key]["tag"], by_role[key]["commit_id"], by_role[key]["tree_id"])


def _remove_approvals(e: Env) -> None:
    for name in os.listdir(e.env.approval_store):
        os.chmod(e.env.approval_store / name, 0o600)
        os.unlink(e.env.approval_store / name)


@pytest.mark.parametrize(("mutate", "message"), [
    (_remove_approvals, "no current approval"),
    (lambda e: setattr(e, "env", replace(e.env, fixture_sha256="sha256:" + "ab" * 32)), "fixture"),
    (lambda e: setattr(e, "env", replace(e.env, approved_images=APPROVED_RUN_IMAGES[:1])), "image"),
    (lambda e: e.env.installation_id_file.write_text("inst-bad\n"), "installation ID"),
    (lambda e: (writable(e.env.pack_store), shutil.rmtree(e.env.pack_store)), "approved pack copy"),
])
def test_missing_or_inconsistent_inputs_refuse_the_plan(e: Env, mutate: Callable[[Env], Any], message: str) -> None:
    from patchproof.runner.papertrail_plan import PlanError

    mutate(e)
    with pytest.raises(PlanError, match=message):
        assemble_run(e.env, RUN_ID)
    terminal = FakeTerminal({**GOOD, "Confirmation": "AUTHORIZE anything"})
    code = run_authorization(e.env, terminal, now=lambda: NOW, new_run_id=lambda: RUN_ID)
    assert code == 2 and "NOT AUTHORIZED" in terminal.output() and store_names(e) == []
    assert not any(k == "prompt" for k, _ in terminal.transcript)


def test_wrong_bound_fixture_hash_is_refused_by_the_pack_check(e: Env) -> None:
    from patchproof.runner.papertrail_plan import PlanError

    e.env = replace(e.env, fixture_sha256="sha256:" + "ab" * 32)
    with pytest.raises(PlanError, match="the pack's fixture differs"):
        assemble_run(e.env, RUN_ID)


def test_a_self_consistent_snapshot_with_a_different_fixture_is_refused(e: Env) -> None:
    from patchproof.git.snapshot import canonical_json
    from patchproof.runner.papertrail_plan import PlanError

    name = assemble_run(e.env, RUN_ID).document.sources.candidate.snapshot_name
    snap = e.env.snapshot_store / name
    writable(snap)
    fixture = snap / "source" / "fixtures" / "synthetic" / "synthetic-documents-v1.json"
    data = fixture.read_bytes().replace(b"Alice", b"Alicia", 1)
    fixture.write_bytes(data)
    manifest = json.loads((snap / "source-manifest.json").read_text())
    for f in manifest["files"]:
        if f["path"] == "fixtures/synthetic/synthetic-documents-v1.json":
            f["sha256"], f["size_bytes"] = "sha256:" + hashlib.sha256(data).hexdigest(), len(data)
    manifest["totals"]["total_bytes"] = sum(f["size_bytes"] for f in manifest["files"])
    manifest["source_tree_sha256"] = "sha256:" + hashlib.sha256(canonical_json(manifest["files"])).hexdigest()
    (snap / "source-manifest.json").write_bytes(canonical_json(manifest) + b"\n")
    for dirpath, _dirs, files in os.walk(snap / "source"):
        for f in files:
            os.chmod(Path(dirpath) / f, 0o444)
        os.chmod(dirpath, 0o555)
    with pytest.raises(PlanError, match="synthetic fixture is missing or differs"):
        assemble_run(e.env, RUN_ID)


def test_a_current_but_stale_approval_is_refused(e: Env) -> None:
    from patchproof.runner.papertrail_plan import PlanError

    _remove_approvals(e)
    review = pa.assemble_review(e.synthetic.target)
    other = review.bindings.model_copy(update={"verifier_plugin_version": "0.0.9"})
    from patchproof.core.approvals import confirmation_phrase
    pa.provision_store(e.env.approval_store).save(create_approval(other, ReviewDecision(
        "Synthetic Owner", "Approval of different bindings.", "Unit tests only.", confirmation_phrase(other)),
        supersedes=None, now=NOW))
    with pytest.raises(PlanError, match="APPROVAL_STALE"):
        assemble_run(e.env, RUN_ID)


def test_more_than_one_pair_is_refused_in_fixed_fixture_mode(e: Env) -> None:
    from patchproof.runner.papertrail_plan import PlanError

    target = e.synthetic.target
    doc = json.loads((target.pack_dir / "pack.json").read_text())
    doc["repetitions"]["pairs"] = 2
    (target.pack_dir / "pack.json").write_text(json.dumps(doc, indent=2) + "\n")
    e.synthetic.rewrite_evidence()
    e.env = replace(e.env, approval_target=e.synthetic.target)
    with pytest.raises(PlanError, match="exactly one pair"):
        assemble_run(e.env, RUN_ID)


def test_ambiguous_or_modified_snapshots_are_refused(e: Env, shared: Path) -> None:
    from patchproof.runner.papertrail_plan import PlanError

    name = assemble_run(e.env, RUN_ID).document.sources.baseline.snapshot_name
    shutil.copytree(e.env.snapshot_store / name, e.env.snapshot_store / ("snapshot-" + "9e" * 16))
    with pytest.raises(PlanError, match="exactly one snapshot"):
        assemble_run(e.env, RUN_ID)
    writable(e.env.snapshot_store / ("snapshot-" + "9e" * 16))
    shutil.rmtree(e.env.snapshot_store / ("snapshot-" + "9e" * 16))
    authz = e.env.snapshot_store / name / "source" / "papertrail" / "authz.py"
    os.chmod(authz.parent, 0o755)
    os.chmod(authz, 0o644)
    authz.write_text(authz.read_text() + "\n# changed\n")
    os.chmod(authz, 0o444)
    with pytest.raises(PlanError, match="baseline snapshot"):
        assemble_run(e.env, RUN_ID)


def test_invalid_run_id_is_refused(e: Env) -> None:
    from patchproof.runner.papertrail_plan import PlanError

    with pytest.raises(PlanError, match="run ID"):
        assemble_run(e.env, "run-XYZ")


def test_changed_runtime_policy_is_refused(e: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    from patchproof.runner.papertrail_plan import PlanError

    changed = json.loads(json.dumps(run_plan.FIXED_PROFILE_RUNTIME))
    changed["timeouts"]["readiness_seconds"] = 29
    monkeypatch.setattr(run_plan, "FIXED_PROFILE_RUNTIME", changed)
    with pytest.raises(PlanError):
        assemble_run(e.env, RUN_ID)


# ------------------------------------------------------------------ the authorization command


def test_successful_synthetic_authorization(e: Env) -> None:
    code, term = authorize(e)
    assert code == 0, term.output()
    (stored,) = RunAuthorizationStore(e.env.authorization_store).scan()[0].values()
    assert stored.record.plan == assemble_run(e.env, RUN_ID).document
    assert stored.record.reviewer.basis == "local-assertion-unverified" and stored.record.single_use is True
    path = e.env.authorization_store / f"{stored.record.authorization_id}.json"
    assert stat.S_IMODE(os.lstat(path).st_mode) == 0o400
    assert stat.S_IMODE(os.lstat(e.env.authorization_store).st_mode) == 0o700
    from test_schemas import validator_for
    assert validator_for("run-authorization").is_valid(json.loads(path.read_text()))
    out = term.output()
    assert "RUN AUTHORIZED" in out and "Nothing has been executed" in out
    first_prompt = next(i for i, (k, _) in enumerate(term.transcript) if k == "prompt")
    shown = "".join(t for k, t in term.transcript[:first_prompt] if k == "out")
    for text in (RUN_ID, stored.record.plan_sha256, "pp-run-0123456789ab-p1-candidate-verifier", "--network none",
                 "EXPECTATIONS, not results", "VERIFIED_FOR_CASES", "fixed-fixture-v0.1-exception", "D2"):
        assert text in shown, text


@pytest.mark.parametrize("overrides", [
    {"Confirmation": "AUTHORIZE something else"},
    {"Rationale": "   "},
    {"Authorization scope": "fine"} | {"Rationale": "__PHRASE__"},
    {"Authorization scope": "Also __PHRASE__ in the scope"},
])
def test_wrong_phrase_or_statement_writes_nothing(e: Env, overrides: dict[str, str]) -> None:
    phrase = authorization_phrase(assemble_run(e.env, RUN_ID).document)
    overrides = {k: v.replace("__PHRASE__", phrase) for k, v in overrides.items()}
    code, term = authorize(e, overrides)
    assert code == 2 and "NOT AUTHORIZED" in term.output() and "Nothing was written" in term.output()
    assert store_names(e) == []
    if "Confirmation" in overrides:  # refused by the command itself, before any record is built
        assert "the confirmation does not match the phrase" in term.output()


def test_input_change_during_review_writes_nothing(e: Env) -> None:
    def change() -> None:
        e.env.installation_id_file.write_text("inst-" + "0f" * 16 + "\n")

    code, term = authorize(e, on_prompt={"Confirmation": change})
    assert code == 2 and "changed between review and confirmation" in term.output() and store_names(e) == []


def test_a_new_authorization_supersedes_only_an_unused_one(e: Env) -> None:
    assert authorize(e)[0] == 0
    second = "run-" + "13579bdf02468ace" * 2
    code, term = authorize(e, run_id=second)
    assert code == 0, term.output()
    records, claims = RunAuthorizationStore(e.env.authorization_store).scan()
    assert len(records) == 2 and claims == {}
    current = RunAuthorizationStore(e.env.authorization_store).executable()
    assert current is not None and current.record.plan.run_id == second and current.record.supersedes is not None


def test_a_run_id_is_never_reused(e: Env) -> None:
    assert authorize(e)[0] == 0
    code, term = authorize(e)
    assert code == 2 and "never reused" in term.output()


def test_failure_after_the_write_is_reported_distinctly(e: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    import patchproof.run_authorization as ra

    real, calls = ra.assemble_run, []

    def third_fails(env: RunEnvironment, run_id: str) -> Any:
        calls.append(run_id)
        if len(calls) == 4:  # review(+phrase in the test), pre-write, post-write
            from patchproof.runner.papertrail_plan import PlanError
            raise PlanError("environment_identity", "RUNTIME_POLICY_FAILED", "synthetic post-write failure")
        return real(env, run_id)

    phrase = authorization_phrase(assemble_run(e.env, RUN_ID).document)
    calls.append("phrase")
    monkeypatch.setattr(ra, "assemble_run", third_fails)
    terminal = FakeTerminal({**GOOD, "Confirmation": phrase})
    code = run_authorization(e.env, terminal, now=lambda: NOW, new_run_id=lambda: RUN_ID)
    assert code == 4 and "FAILED VERIFICATION: synthetic post-write failure" in terminal.output()
    assert "RUN AUTHORIZED" not in terminal.output() and len(store_names(e)) == 1


# ------------------------------------------------------------------ the driver: refusals consume nothing


def test_driver_refuses_without_an_authorization(e: Env) -> None:
    os.mkdir(e.env.authorization_store, 0o700)
    code, term, docker = execute(e)
    assert code == 2 and "no unused run authorization" in term.output() and docker.log == []


def test_wrong_execution_phrase_consumes_nothing(e: Env) -> None:
    assert authorize(e)[0] == 0
    code, term, docker = execute(e, typed="EXECUTE run-somethingelse")
    assert code == 2 and docker.log == [] and not any(n.endswith(".claim") for n in store_names(e))
    assert not e.evidence.exists()


@pytest.mark.parametrize("drift", ["approval", "snapshot", "image", "policy", "fixture", "tampered-record"])
def test_drift_after_authorization_blocks_before_the_claim(e: Env, drift: str,
                                                           monkeypatch: pytest.MonkeyPatch) -> None:
    assert authorize(e)[0] == 0
    if drift == "approval":  # a superseding pack approval: same bindings, new ID
        store = pa.provision_store(e.env.approval_store)
        review = pa.assemble_review(e.synthetic.target)
        (current,) = store.records().values()
        store.save(create_approval(review.bindings, ReviewDecision("Synthetic Owner", "New statement for tests.",
                                                                   "Unit tests only.", review.phrase),
                                   supersedes=current, now=NOW))
    elif drift == "snapshot":
        name = assemble_run(e.env, RUN_ID).document.sources.candidate.snapshot_name
        f = e.env.snapshot_store / name / "source" / "papertrail" / "app.py"
        os.chmod(f.parent, 0o755)
        os.chmod(f, 0o644)
        f.write_text(f.read_text() + "\n")
    elif drift == "image":
        substitute = ApprovedRunImage(RunRole.TARGET, ImageId("sha256:" + "ab" * 32), APPROVED_RUN_IMAGES[0].env,
                                      TARGET_HEALTHCHECK)
        e.env = replace(e.env, approved_images=(substitute, APPROVED_RUN_IMAGES[1]))
    elif drift == "policy":
        changed = json.loads(json.dumps(run_plan.FIXED_PROFILE_RUNTIME))
        changed["logging"]["max_files"] = 3
        monkeypatch.setattr(run_plan, "FIXED_PROFILE_RUNTIME", changed)
    elif drift == "fixture":
        e.env = replace(e.env, fixture_sha256="sha256:" + "cd" * 32)
    else:
        (name,) = [n for n in store_names(e) if n.endswith(".json")]
        path = e.env.authorization_store / name
        doc = json.loads(path.read_text())
        doc["plan"]["runtime"]["result_cap_bytes"] = 65536
        os.chmod(path, 0o600)
        path.write_text(json.dumps(doc))
    code, term, docker = execute(e, FakeDocker(records=APPROVED_RUN_IMAGES))
    assert code == 2, term.output()
    assert "Nothing was claimed" in term.output() and docker.log == []
    assert not any(kind == "prompt" for kind, _ in term.transcript)  # refused before asking
    if drift == "approval":  # the plan still assembles; it differs from the frozen one
        assert "differ from the authorized plan in ['pack_approval_id']" in term.output()
    assert not any(n.endswith(".claim") for n in store_names(e)) and not e.evidence.exists()


# ------------------------------------------------------------------ single use and crash safety


def test_successful_run_consumes_the_authorization_and_cannot_repeat(e: Env) -> None:
    assert authorize(e)[0] == 0
    code, term, docker = execute(e)
    assert code == 0, term.output()
    out = outcome(e)
    assert out["verdict"] == "VERIFIED_FOR_CASES" and out["containers_created"] == 4
    assert out["reconciliation"] == "CONSISTENT" and out["cleanup_complete"] is True
    assert creates(docker) == [("baseline", "target"), ("baseline", "verifier"), ("candidate", "target"),
                               ("candidate", "verifier")]
    code2, term2, docker2 = execute(e)
    assert code2 == 2 and "no unused run authorization" in term2.output() and docker2.log == []


def test_two_processes_competing_for_one_claim(e: Env) -> None:
    assert authorize(e)[0] == 0
    store = RunAuthorizationStore(e.env.authorization_store)
    stored = store.executable()
    assert stored is not None
    go_r, go_w = os.pipe()
    children = []
    for _ in range(2):
        pid = os.fork()
        if pid == 0:
            code = 1
            try:
                os.close(go_w)
                os.read(go_r, 1)
                store.claim(stored.record.authorization_id, run_id=RUN_ID, now=NOW)
                code = 0
            except Exception:
                code = 7
            finally:
                os._exit(code)
        children.append(pid)
    os.close(go_r)
    os.write(go_w, b"xx")
    os.close(go_w)
    codes = sorted(os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]) for pid in children)
    assert codes == [0, 7]
    assert store.executable() is None


def test_crash_before_the_claim_leaves_the_authorization_usable(e: Env) -> None:
    assert authorize(e)[0] == 0
    pid = os.fork()
    if pid == 0:  # the "crash": input ends at the execution prompt
        try:
            run_once(e.env, FakeTerminal({}), lambda: FakeDocker(), clock=FakeClock(), now=lambda: NOW)
        finally:
            os._exit(9)
    os.waitpid(pid, 0)
    assert RunAuthorizationStore(e.env.authorization_store).executable() is not None


def test_crash_immediately_after_the_claim_consumes_the_authorization(e: Env) -> None:
    assert authorize(e)[0] == 0
    store = RunAuthorizationStore(e.env.authorization_store)
    stored = store.executable()
    assert stored is not None
    pid = os.fork()
    if pid == 0:
        store.claim(stored.record.authorization_id, run_id=RUN_ID, now=NOW)
        os._exit(9)  # killed before the evidence directory or any Docker operation
    os.waitpid(pid, 0)
    code, term, docker = execute(e)
    assert code == 2 and docker.log == [] and store.executable() is None


def test_an_indeterminate_claim_counts_as_consumed(e: Env) -> None:
    assert authorize(e)[0] == 0
    store = RunAuthorizationStore(e.env.authorization_store)
    stored = store.executable()
    assert stored is not None
    fd = os.open(e.env.authorization_store / f"{stored.record.authorization_id}.claim",
                 os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    os.close(fd)  # a crash between create and write
    _, claims = store.scan()
    assert claims[stored.record.authorization_id].state == "INDETERMINATE"
    assert store.executable() is None
    code, _, docker = execute(e)
    assert code == 2 and docker.log == []


def test_existing_evidence_directory_after_claim_runs_nothing(e: Env) -> None:
    assert authorize(e)[0] == 0
    os.makedirs(e.evidence, mode=0o700)
    os.chmod(e.env.evidence_root, 0o700)
    code, term, docker = execute(e)
    assert code == 2 and docker.log == []  # refused before the claim: evidence already exists


# ------------------------------------------------------------------ D2 baseline stop and execution failures


def _assert_stopped_after_baseline(e: Env, docker: FakeDocker, code: int) -> dict[str, Any]:
    out = outcome(e)
    assert code == 5, out
    assert creates(docker) == [("baseline", "target"), ("baseline", "verifier")]
    assert out["revisions_executed"] == ["1-baseline"] and out["run_termination"] == "interrupted"
    assert out["stop_reason"].startswith("D2_BASELINE_EXECUTION_FAILURE") and out["lifecycle"] == "INTERRUPTED"
    assert out["verdict"] != "VERIFIED_FOR_CASES" and out["verdict"] == "INCONCLUSIVE"
    assert (e.evidence / "execution-pair-001-baseline.json").exists()
    assert not (e.evidence / "execution-pair-001-candidate.json").exists()
    assert manifest(e)["status"] == "FINALIZED"
    return out


@pytest.mark.parametrize("knobs", [
    {"target_health": ["starting", "unhealthy"]},
    {"target_dies": True},
    {"target_oom": True, "target_health": ["starting", "unhealthy"]},
    {"verifier_oom": True},
    {"verifier_timeout": True},
    {"verifier_truncated": True},
    {"verifier_exit": 3},
    {"target_exits_during_tests": True},
])
def test_baseline_execution_failure_stops_before_the_candidate(e: Env, knobs: dict[str, Any]) -> None:
    assert authorize(e)[0] == 0
    code, _, docker = execute(e, fake(e, **knobs))
    _assert_stopped_after_baseline(e, docker, code)


@pytest.mark.parametrize("mangle", ["malformed", "truncated", "absent", "identity", "over-cap"])
def test_bad_baseline_streams_stop_before_the_candidate(e: Env, mangle: str) -> None:
    assert authorize(e)[0] == 0
    docker = fake(e)
    good = docker.streams["baseline"]
    docker.streams["baseline"] = {
        "malformed": good.replace(b'"seq":3', b'"seq":30', 1),
        "truncated": good[: len(good) // 2],
        "absent": b"",
        "identity": good.replace(RUN_ID.encode(), b"run-" + b"7" * 32),
        "over-cap": good + b" " * (10 * 1024 * 1024),
    }[mangle]
    code, _, _ = execute(e, docker)
    _assert_stopped_after_baseline(e, docker, code)


def test_uncertain_baseline_cleanup_stops_and_never_touches_foreign_resources(e: Env) -> None:
    assert authorize(e)[0] == 0
    docker = fake(e, foreign_labels_on_cleanup=True)
    code, _, _ = execute(e, docker)
    out = _assert_stopped_after_baseline(e, docker, code)
    assert out["cleanup_complete"] is False and out["reconciliation"] == "ATTENTION"
    findings = json.loads((e.evidence / "reconciliation.json").read_text())["findings"]
    assert {f["classification"] for f in findings} == {"OWNED_CONTAINER_REMAINS"}
    assert "f0" * 32 not in docker.touched_ids() and set(docker.removed) <= set(docker.created)


def test_a_trusted_baseline_with_unexpected_outcomes_still_runs_the_candidate(e: Env) -> None:
    assert authorize(e)[0] == 0
    docker = fake(e, baseline="correct")  # nothing reproduced: a semantic, not an execution, failure
    code, _, _ = execute(e, docker)
    out = outcome(e)
    assert len(creates(docker)) == 4 and out["stop_reason"] is None
    assert out["verdict"] not in ("VERIFIED_FOR_CASES", None)
    assert "BASELINE_NOT_REPRODUCED" in out["reason_codes"] and code == 0


def test_candidate_preparation_failure_is_post_execution(e: Env) -> None:
    assert authorize(e)[0] == 0
    code, _, docker = execute(e, fake(e, create_fails_side="candidate"))
    out = outcome(e)
    verdict = json.loads((e.evidence / "verdict.json").read_text())
    assert creates(docker) == [("baseline", "target"), ("baseline", "verifier"), ("candidate", "target")]
    assert out["verdict"] != "VERIFIED_FOR_CASES" and verdict["execution_started"] is True


@pytest.mark.parametrize("drift", ["approval", "claim", "snapshot", "policy", "installation"])
def test_drift_during_the_baseline_stops_the_candidate(e: Env, drift: str, monkeypatch: pytest.MonkeyPatch) -> None:
    assert authorize(e)[0] == 0

    def during_baseline(side: str) -> None:
        if side != "baseline":
            return
        if drift == "approval":
            store = pa.provision_store(e.env.approval_store)
            review = pa.assemble_review(e.synthetic.target)
            (current,) = store.records().values()
            store.save(create_approval(review.bindings, ReviewDecision("Synthetic Owner", "Changed mid-run.",
                                                                       "Unit tests only.", review.phrase),
                                       supersedes=current, now=NOW))
        elif drift == "claim":
            (claim,) = [n for n in store_names(e) if n.endswith(".claim")]
            os.chmod(e.env.authorization_store / claim, 0o600)
            (e.env.authorization_store / claim).write_text('{"authorization_id": "tampered"}\n')
        elif drift == "snapshot":
            name = assemble_run(e.env, RUN_ID).document.sources.candidate.snapshot_name
            f = e.env.snapshot_store / name / "source" / "papertrail" / "authz.py"
            os.chmod(f.parent, 0o755)
            os.chmod(f, 0o644)
            f.write_text("# replaced mid-run\n")
        elif drift == "installation":  # the plan still assembles, but differs from the frozen one
            e.env.installation_id_file.write_text("inst-" + "0f" * 16 + "\n")
        else:
            changed = json.loads(json.dumps(run_plan.FIXED_PROFILE_RUNTIME))
            changed["result_cap_bytes"] = 65536
            monkeypatch.setattr(run_plan, "FIXED_PROFILE_RUNTIME", changed)

    code, _, docker = execute(e, fake(e, on_attach=during_baseline))
    out = outcome(e)
    assert creates(docker) == [("baseline", "target"), ("baseline", "verifier")]
    # Detected after execution began: never BLOCKED (PROJECT_SPEC.md 17.3 items 6 and 9).
    assert out["verdict"] == "INCONCLUSIVE" and code == 5
    assert json.loads((e.evidence / "verdict.json").read_text())["execution_started"] is True
    assert out["stop_reason"].startswith("REVALIDATION_FAILED before candidate")
    log = [json.loads(line) for line in (e.evidence / "revalidation.jsonl").read_text().splitlines()]
    assert [entry["passed"] for entry in log] == [True, False]
    expected_note = {"approval": "pack approval is APPROVAL_STALE", "claim": "its claim changed",
                     "snapshot": "plan inputs:", "policy": "plan inputs:", "installation": "plan drift in"}[drift]
    assert expected_note in log[1]["note"], log[1]
    assert log[1]["failure"] == {"approval": ["authorization", "APPROVAL_STALE"],
                                 "claim": ["authorization", "APPROVAL_STALE"],
                                 "snapshot": ["source_identity", "SOURCE_IDENTITY_MISMATCH"],
                                 "policy": ["pack_integrity", "PACK_INTEGRITY_FAILED"],
                                 "installation": ["environment_identity", "RUNTIME_POLICY_FAILED"]}[drift]


def test_daemon_restart_before_the_candidate_interrupts_and_is_explained(e: Env) -> None:
    assert authorize(e)[0] == 0
    docker = fake(e)

    def restart(side: str) -> None:
        if side == "baseline":
            docker.listings["networks"][0] = {"ID": "6a" * 32, "Name": "bridge", "Driver": "bridge", "Scope": "local"}

    docker.on_attach = restart
    code, _, _ = execute(e, docker)
    out = outcome(e)
    assert creates(docker) == [("baseline", "target"), ("baseline", "verifier")]
    assert out["run_termination"] == "interrupted" and out["verdict"] == "INCONCLUSIVE"
    assert out["reconciliation"] == "EXPLAINED_DAEMON_MANAGED" and out["daemon_restart_suspected"] is True
    assert "Docker continuity lost" in out["stop_reason"] and code == 5


def test_target_log_text_never_becomes_an_event(e: Env) -> None:
    assert authorize(e)[0] == 0
    docker = fake(e)
    docker.target_logs = docker.streams["baseline"]  # a complete, valid-looking stream in the target log
    docker.streams["baseline"] = b""
    code, _, _ = execute(e, docker)
    out = _assert_stopped_after_baseline(e, docker, code)
    assert (e.evidence / "untrusted-target-stdout-pair-001-baseline.log").read_bytes() == docker.target_logs
    assert (e.evidence / "verifier-stream-pair-001-baseline.bin").read_bytes() == b""
    assert (e.evidence / "observations-pair-001-baseline.jsonl").read_bytes() == b""
    assert "EVENT_STREAM_TRUNCATED" in out["reason_codes"] or "REQUIRED_CHECK_INCOMPLETE" in out["reason_codes"]


# ------------------------------------------------------------------ evidence


def test_complete_evidence_set_and_integrity(e: Env) -> None:
    assert authorize(e)[0] == 0
    code, _, _ = execute(e)
    assert code == 0
    m = manifest(e)
    assert m["status"] == "FINALIZED" and m["summary"]["verdict"] == "VERIFIED_FOR_CASES"
    for name in ("claim.json", "authorization.json", "plan.json", "pack-approval.json", "pack-approval-history.json",
                 "source-manifest-baseline.json", "source-manifest-candidate.json", "collection.json",
                 "inventory-before.json", "inventory-after.json", "reconciliation.json", "docker-ops.jsonl",
                 "ownership-journal.jsonl", "revalidation.jsonl", "verdict-input.json", "verdict.json",
                 "outcome.json", *(f"{p}-pair-001-{s}.{x}" for s in ("baseline", "candidate") for p, x in (
                     ("execution", "json"), ("observations", "jsonl"), ("verifier-stream", "bin"),
                     ("untrusted-target-stdout", "log"), ("untrusted-target-stderr", "log"),
                     ("untrusted-verifier-console", "log"), ("revision", "json")))):
        assert name in m["files"], name
        data = (e.evidence / name).read_bytes()
        assert m["files"][name]["sha256"] == "sha256:" + hashlib.sha256(data).hexdigest()
        assert stat.S_IMODE(os.lstat(e.evidence / name).st_mode) == 0o600
    assert stat.S_IMODE(os.lstat(e.evidence).st_mode) == 0o700
    plan = json.loads((e.evidence / "plan.json").read_text())
    stored = json.loads((e.evidence / "authorization.json").read_text())
    assert plan == stored["plan"]
    ops = [json.loads(line) for line in (e.evidence / "docker-ops.jsonl").read_text().splitlines()]
    attached = [o for o in ops if o["op"] == "start-attached" and o["phase"] == "completed"]
    assert len(attached) == 2 and all(o["stdout"]["stored"] == "REVISION_ARTIFACT" and o["stdout"]["artifact"] is None
                                      for o in attached)
    assert all(o[s]["stored"] == "REVISION_ARTIFACT" for o in ops if o["op"] == "logs" and o["phase"] == "completed"
               for s in ("stdout", "stderr"))
    inspected = [o for o in ops if o["op"] == "inspect" and o["phase"] == "completed" and o["returncode"] == 0]
    assert inspected and all(json.loads((e.evidence / o["stdout"]["artifact"]).read_bytes()) for o in inspected)
    assert verify_evidence(e.evidence) == {"state": "CONSISTENT", "status": "FINALIZED", "problems": []}


def test_evidence_files_are_never_overwritten(e: Env, tmp_path: Path) -> None:
    from patchproof.runner.run_evidence import EvidenceError, RunEvidence

    root = private(tmp_path / "ev") / "runs"
    evidence = RunEvidence.claim(root, RUN_ID)
    evidence.write("a.json", b"1")
    with pytest.raises(EvidenceError, match="never overwritten"):
        evidence.write("a.json", b"2")
    assert (evidence.directory / "a.json").read_bytes() == b"1"
    with pytest.raises(EvidenceError, match="already exists"):
        RunEvidence.claim(root, RUN_ID)
    with pytest.raises(EvidenceError, match="invalid"):
        evidence.write("../escape", b"x")


def test_an_exception_mid_run_leaves_incomplete_evidence(e: Env) -> None:
    assert authorize(e)[0] == 0
    docker = fake(e)

    def boom(side: str) -> None:
        if side == "candidate":
            raise OSError("synthetic host failure during the candidate")

    docker.on_attach = boom
    code, term, _ = execute(e, docker)
    assert code == 4 and "INCOMPLETE" in term.output()
    m = manifest(e)
    assert m["status"] == "INCOMPLETE" and m["summary"]["verdict"] is None
    assert "synthetic host failure" in m["summary"]["exception"]
    assert (e.evidence / "execution-pair-001-baseline.json").exists()
    assert m["summary"]["cleanup_complete"] is True  # the candidate's containers were still removed


def test_a_container_left_by_a_failing_cleanup_is_detected_by_identity(e: Env) -> None:
    assert authorize(e)[0] == 0
    docker = fake(e)
    real_run = docker.run

    def run(op: Any) -> Any:
        if op.op_name == "remove" and docker.specs[op.argv_tail()[-1]].side == "candidate":
            raise OSError("synthetic daemon failure during removal")
        return real_run(op)

    docker.run = run  # type: ignore[method-assign]
    code, _, _ = execute(e, docker)
    out = json.loads((e.evidence / "manifest.json").read_text())["summary"]
    assert code == 4 and out["cleanup_complete"] is False and out["verdict"] is None
    assert out["reconciliation"] == "ATTENTION"


def test_incomplete_inventory_before_creates_nothing_and_is_blocked(e: Env) -> None:
    assert authorize(e)[0] == 0
    docker = fake(e, listing_fails={"volumes"})
    code, _, _ = execute(e, docker)
    assert code == 4 and creates(docker) == []
    out = outcome(e)
    assert manifest(e)["status"] == "INCOMPLETE" and out["lifecycle"] == "BLOCKED"
    # A pre-execution failure is the engine's BLOCKED; incomplete evidence never establishes it.
    assert out["engine_verdict"] == "BLOCKED" and out["verdict"] is None
    assert json.loads((e.evidence / "verdict.json").read_text())["execution_started"] is False
    assert out["stop_reason"].startswith("REVALIDATION_FAILED before baseline: the before-inventory is incomplete")
    assert all(op.op_name == "snapshot" for op in docker.log)


def test_the_fifth_container_creation_is_refused_before_docker(tmp_path: Path) -> None:
    from _run_fixtures import OWNERSHIP

    from patchproof.runner.policy import PolicyViolation
    from patchproof.runner.run_evidence import RecordingExecutor, RunEvidence

    evidence = RunEvidence.claim(private(tmp_path / "ev") / "runs", RUN_ID)
    docker = FakeDocker()
    recorder = RecordingExecutor(docker, evidence)

    class Create:
        op_name = "run-create"

        def argv_tail(self) -> list[str]:
            return ["container", "create"]

    recorder.creations = 4
    with pytest.raises(PolicyViolation, match="at most four"):
        recorder.run(Create())  # type: ignore[arg-type]
    assert docker.log == [] and OWNERSHIP


# ------------------------------------------------------------------ inventory reconciliation (pure)


def _inventory(**changes: Any) -> Any:
    from _run_fixtures import default_listings

    from patchproof.runner.run_evidence import capture_inventory

    docker = FakeDocker()
    listings = default_listings()
    for kind, rows in changes.items():
        listings[kind] = rows
    docker.listings = listings
    return capture_inventory(docker)


def test_reconciliation_classifies_by_identity() -> None:
    from _run_fixtures import default_listings

    from patchproof.runner.run_evidence import reconcile

    before = _inventory()
    assert reconcile(before, _inventory(), [])["status"] == "CONSISTENT"
    nets = default_listings()["networks"]
    restarted = _inventory(networks=[{**nets[0], "ID": "6a" * 32}, *nets[1:]])
    result = reconcile(before, restarted, [])
    assert result["status"] == "EXPLAINED_DAEMON_MANAGED" and result["daemon_restart_suspected"] is True
    other = _inventory(networks=[*nets[:3], {**nets[3], "ID": "7b" * 32}])
    assert reconcile(before, other, [])["status"] == "ATTENTION"  # a non-built-in network is never explained
    both = _inventory(networks=[{**nets[0], "ID": "6a" * 32}, *nets[1:3], {**nets[3], "ID": "7b" * 32}])
    assert reconcile(before, both, [])["status"] == "ATTENTION"
    same_count = _inventory(volumes=[{"Name": "a-different-volume", "Driver": "local"}])
    assert reconcile(before, same_count, [])["status"] == "ATTENTION"  # identity, not count
    image = _inventory(images=[])
    assert reconcile(before, image, [])["status"] == "ATTENTION"
    owned = _inventory(containers=[*default_listings()["containers"], {"ID": "c1" * 32, "Names": "x"}])
    assert {f["classification"] for f in reconcile(before, owned, ["c1" * 32])["findings"]} == {
        "OWNED_CONTAINER_REMAINS"}
    with_owned = _inventory(containers=[*default_listings()["containers"], {"ID": "c1" * 32, "Names": "x"}])
    assert {f["classification"] for f in reconcile(with_owned, with_owned, ["c1" * 32])["findings"]} == {
        "OWNED_CONTAINER_REMAINS"}
    foreign = _inventory(containers=[])
    assert reconcile(before, foreign, [])["findings"][0]["classification"] == "UNEXPLAINED_REMOVED"


def test_a_failed_listing_makes_reconciliation_incomplete() -> None:
    from patchproof.runner.run_evidence import capture_inventory, reconcile

    docker = FakeDocker(listing_fails={"images"})
    broken = capture_inventory(docker)
    assert not broken.complete and reconcile(_inventory(), broken, [])["status"] == "INCOMPLETE"
    assert all(isinstance(op, SnapshotList) for op in docker.log)


# ------------------------------------------------------------------ the real repository is untouched


def test_real_inputs_are_unchanged_by_these_tests() -> None:
    from patchproof.runner.profiles import PAPERTRAIL_PROFILE_SHA256, load_profile

    target = pa.papertrail_target()
    assert load_profile(target.profile_path, expected_sha256=PAPERTRAIL_PROFILE_SHA256).sha256 == \
        PAPERTRAIL_PROFILE_SHA256
    from patchproof.packs.validation import validate_pack
    pack = validate_pack(target.pack_dir)
    assert pack.manifest_sha256 == "sha256:a4c4ce48d5d2aaa512c746e7ba90d06fd76e879de3a3dea5280079531a8804c8"
    assert pack.pack_tree_sha256 == "sha256:529d3cd3ebf307586dcecef43a0df8ab9b55296849182f8f43c4ad7d6a8a6c31"


# ------------------------------------------------------------------ security review (PP-008 final review)


def test_the_driver_refuses_a_same_revision_authorization(e: Env) -> None:
    """The reusable contract allows r1 against r1 (17.2); this driver executes only r1 against r3."""
    from patchproof.core.records import validate_record
    from patchproof.core.records.authorization import RunPlanDocument
    from patchproof.core.run_authorizations import AuthorizationDecision, create_authorization
    from patchproof.run_authorization import provision_authorization_store

    doc = assemble_run(e.env, RUN_ID).document.model_dump(mode="json")
    doc["sources"]["candidate"] = doc["sources"]["baseline"]
    plan = validate_record(RunPlanDocument, doc)
    store = provision_authorization_store(e.env.authorization_store)
    decision = AuthorizationDecision("Synthetic Owner", "R", "S", authorization_phrase(plan))
    store.save(create_authorization(plan, decision, supersedes=None, now=NOW))
    code, term, docker = execute(e)
    assert code == 2 and "candidate is not the authorized first-run revision" in term.output()
    assert docker.log == [] and not any(n.endswith(".claim") for n in store_names(e))
    assert not e.evidence.exists()


# ---- the D2 boundary to the engine


def _revision(e: Env, docker: FakeDocker) -> Any:
    from patchproof.runner.cleanup import OwnershipRegistry
    from patchproof.runner.revision import execute_revision

    plan = assemble_run(e.env, RUN_ID).plan
    return execute_revision(docker, plan, 1, "baseline", OwnershipRegistry(plan.ownership), clock=FakeClock())


@pytest.mark.parametrize("fault", [
    {}, {"target_health": ["starting", "unhealthy"]}, {"target_dies": True}, {"verifier_oom": True},
    {"verifier_timeout": True}, {"verifier_truncated": True}, {"verifier_exit": 3}, {"verifier_exit": 1},
    {"target_exits_during_tests": True}, {"verifier_never_started": True}, {"stream": b""},
    {"stream": "half"}, {"stream": "over-cap"}])
def test_d2_boundary_agrees_with_the_public_engine(e: Env, fault: dict[str, Any]) -> None:
    """D2 reads two engine internals; this pins them to the public `evaluate` result.

    A complete, trusted run's verdict input is taken, its baseline execution is replaced by
    the faulted one, and the public engine's `pairs_terminated_normally` (which counts
    trusted executions) must agree with D2, and every D2 engine code must be a public
    execution reason for that baseline.
    """
    from patchproof.core.verdict_input import parse_verdict_input
    from patchproof.core.verdicts import evaluate
    from patchproof.runner.authorized_run import engine_execution_trust, execution_failure_reasons

    assert authorize(e)[0] == 0
    assert execute(e)[0] == 0
    good = json.loads((e.evidence / "verdict-input.json").read_text())
    knobs = {k: v for k, v in fault.items() if k != "stream"}
    docker = fake(e, **knobs)
    if "stream" in fault:
        full = docker.streams["baseline"]
        docker.streams["baseline"] = {"half": full[: len(full) // 2], "over-cap": full + b" " * (10 * 1024 * 1024)}.get(
            fault["stream"], fault["stream"]) if isinstance(fault["stream"], str) else fault["stream"]
    result = _revision(e, docker)
    cap = good["result_cap_bytes"]
    trusted, codes = engine_execution_trust(result.execution, cap)
    doc = copy.deepcopy(good)
    doc["executions"] = [result.execution.model_dump(mode="json") if x["side"] == "baseline" else x
                         for x in doc["executions"]]
    public = evaluate(parse_verdict_input(doc), "2026-10-13T12:00:00Z")
    assert trusted == (public["counts"]["pairs_terminated_normally"] == 1)
    baseline_codes = {d["reason_code"] for d in public["details"] if d["side"] == "baseline" and d["test_id"] is None}
    assert set(codes) == baseline_codes
    d2 = execution_failure_reasons(result, cap)
    assert (not d2) == trusted, (d2, fault)  # cleanup succeeded in every case here
    assert trusted == (fault in ({}, {"verifier_exit": 1}))  # exit 1 is pytest's ordinary "a check failed"


# ---- signals and interruption


@pytest.mark.parametrize("signame", ["SIGINT", "SIGTERM", "SIGHUP"])
def test_a_termination_signal_cleans_up_and_finalizes_incomplete(e: Env, signame: str) -> None:
    import signal

    from patchproof.runner.interrupts import graceful_termination

    assert authorize(e)[0] == 0
    docker = fake(e)
    real_run = docker.run
    repeated: list[str] = []

    def run(op: Any) -> Any:
        if op.op_name == "remove" and not repeated:  # a second signal during cleanup is ignored
            repeated.append(op.op_name)
            os.kill(os.getpid(), getattr(signal, signame))
        return real_run(op)

    docker.run = run  # type: ignore[method-assign]
    docker.on_attach = lambda side: os.kill(os.getpid(), getattr(signal, signame)) if side == "baseline" else None
    with graceful_termination() as received:
        code, term, _ = execute(e, docker)
    assert received.received == [signame, signame]
    assert code == 4 and "RUN evidence INCOMPLETE, lifecycle INTERRUPTED" in term.output()
    out = outcome(e)
    assert out["exception"] == f"INTERRUPTED_BY_{signame}" and out["verdict"] is None
    assert out["lifecycle"] == "INTERRUPTED" and out["cleanup_status"] == "COMPLETE"
    assert creates(docker) == [("baseline", "target"), ("baseline", "verifier")]
    assert sorted(docker.removed) == sorted(docker.created)  # cleanup ran to completion despite the repeat
    assert manifest(e)["status"] == "INCOMPLETE"
    assert any(n.endswith(".claim") for n in store_names(e))
    assert signal.getsignal(signal.SIGTERM) is signal.SIG_DFL  # handlers restored


def test_an_interrupt_stops_the_docker_client_process(tmp_path: Path) -> None:
    """`run_bounded` starts the client in its own session, so Ctrl-C never reaches it: stop it."""
    import signal
    import time

    from patchproof.runner.docker_cli import run_bounded

    pid_file = tmp_path / "pid"
    give_up = time.monotonic() + 30  # a bound on waiting for the client to start, not a timing assumption

    def interrupt(signum: int, frame: Any) -> None:
        # Synchronized: interrupt only once the client is running (its PID line is complete),
        # however long a loaded machine takes to start it.
        try:
            ready = pid_file.read_text().endswith("\n")
        except FileNotFoundError:
            ready = False
        if ready or time.monotonic() > give_up:
            signal.setitimer(signal.ITIMER_REAL, 0)
            raise KeyboardInterrupt

    previous = signal.signal(signal.SIGALRM, interrupt)
    signal.setitimer(signal.ITIMER_REAL, 0.05, 0.05)
    try:
        with pytest.raises(KeyboardInterrupt):
            run_bounded(["/bin/sh", "-c", f"echo $$ > {pid_file}; exec /bin/sleep 30"], env={"PATH": "/bin"},
                        timeout_seconds=60, stdout_cap=1024)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    assert pid_file.read_text().endswith("\n"), "the client never started"
    pid = int(pid_file.read_text())
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.05)
    os.kill(pid, signal.SIGKILL)
    raise AssertionError("the client process outlived the interrupt")


def sigkilled_run(tmp_path: Path, shared: Path) -> Path:
    """Run the driver in a child process that is SIGKILLed while the baseline verifier is attached.

    Returns the child's data directory. Nothing in the child can react to SIGKILL.
    """
    import signal
    import subprocess
    import sys

    script = (
        "import os, signal, sys\n"
        f"sys.path.insert(0, {str(Path(__file__).parent)!r})\n"
        "from pathlib import Path\n"
        "import test_authorized_run as t\n"
        "from patchproof.runner.interrupts import graceful_termination\n"
        "e = t.make_env(Path(sys.argv[1]), Path(sys.argv[2]))\n"
        "assert t.authorize(e)[0] == 0\n"
        "docker = t.fake(e)\n"
        "docker.on_attach = lambda side: os.kill(os.getpid(), signal.SIGKILL)\n"
        "with graceful_termination():\n"
        "    t.execute(e, docker)\n"
        "raise SystemExit('not killed')\n")
    work = tmp_path / "child"
    work.mkdir()
    result = subprocess.run([sys.executable, "-c", script, str(work), str(shared)], capture_output=True,
                            timeout=300, check=False)
    assert result.returncode == -signal.SIGKILL, result.stderr.decode()[-2000:]
    return work / "work" / "data"


def test_sigkill_leaves_a_consumed_claim_journaled_ids_and_no_manifest(tmp_path: Path, shared: Path) -> None:
    from patchproof.runner.run_evidence import verify_evidence

    data = sigkilled_run(tmp_path, shared)
    claims = [n for n in os.listdir(data / "run-authorizations") if n.endswith(".claim")]
    assert len(claims) == 1  # consumed: fsynced before the first Docker operation
    evidence = data / "evidence" / "runs" / RUN_ID
    assert not (evidence / "manifest.json").exists()
    assert verify_evidence(evidence)["state"] == "NO_MANIFEST"
    journal = [json.loads(line) for line in (evidence / "ownership-journal.jsonl").read_text().splitlines()]
    assert [(j["event"], j["name"].rsplit("-", 2)[-2:]) for j in journal] == [
        ("planned", ["baseline", "target"]), ("created", ["baseline", "target"]),
        ("planned", ["baseline", "verifier"]), ("created", ["baseline", "verifier"])]
    ops = [json.loads(line) for line in (evidence / "docker-ops.jsonl").read_text().splitlines()]
    assert ops[-1]["op"] == "start-attached" and ops[-1]["phase"] == "requested"
    assert not any(o["op"] in ("stop", "remove", "force-remove") for o in ops)  # no cleanup ran


# ---- evidence failures, incomplete evidence and preserved verdicts


def _failing_write(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    from patchproof.runner.run_evidence import EvidenceError, RunEvidence

    real = RunEvidence.write

    def write(self: Any, file_name: str, data: bytes) -> str:
        if file_name == name:
            raise EvidenceError(f"synthetic write failure for {file_name}")
        return real(self, file_name, data)

    monkeypatch.setattr(RunEvidence, "write", write)


def test_a_baseline_evidence_failure_stops_before_the_candidate(e: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    assert authorize(e)[0] == 0
    _failing_write(monkeypatch, "verifier-stream-pair-001-baseline.bin")
    code, term, docker = execute(e)
    out = outcome(e)
    assert code == 4 and creates(docker) == [("baseline", "target"), ("baseline", "verifier")]
    assert out["stop_reason"].startswith("EVIDENCE_WRITE_FAILED") and out["evidence_failures"]
    assert out["verdict"] is None and out["engine_verdict"] == "INCONCLUSIVE"
    assert manifest(e)["status"] == "INCOMPLETE" and "NOT ESTABLISHED" in term.output()


@pytest.mark.parametrize(("candidate", "engine"), [("vulnerable", "NOT_FIXED"), ("correct", "VERIFIED_FOR_CASES")])
def test_incomplete_evidence_keeps_the_engine_verdict_but_never_establishes_it(
        e: Env, monkeypatch: pytest.MonkeyPatch, candidate: str, engine: str) -> None:
    assert authorize(e)[0] == 0
    _failing_write(monkeypatch, "untrusted-target-stderr-pair-001-candidate.log")
    code, term, _ = execute(e, fake(e, candidate=candidate))
    out = outcome(e)
    assert code == 4 and out["evidence_status"] == "INCOMPLETE" and out["lifecycle"] == "INTERRUPTED"
    assert out["engine_verdict"] == engine and out["verdict"] is None and out["verdict_established"] is False
    assert json.loads((e.evidence / "verdict.json").read_text())["verdict"] == engine  # never discarded
    assert f"NOT ESTABLISHED (evidence incomplete); the engine evaluated {engine}" in term.output()


def test_a_trusted_candidate_violation_survives_a_cleanup_failure(e: Env) -> None:
    assert authorize(e)[0] == 0
    docker = fake(e, candidate="vulnerable")
    docker.on_attach = lambda side: setattr(docker, "foreign_labels_on_cleanup", side == "candidate")
    code, _, _ = execute(e, docker)
    out = outcome(e)
    assert out["verdict"] == "NOT_FIXED" and out["evidence_status"] == "FINALIZED"
    assert out["cleanup_status"] == "FAILED" and len(out["remaining_owned_container_ids"]) == 1 and code == 5


def test_the_after_inventory_failing_makes_the_evidence_incomplete(e: Env) -> None:
    assert authorize(e)[0] == 0
    docker = fake(e)
    docker.on_attach = lambda side: docker.listing_fails.add("images") if side == "candidate" else None
    code, _, _ = execute(e, docker)
    out = outcome(e)
    assert code == 4 and out["engine_verdict"] == "VERIFIED_FOR_CASES" and out["verdict"] is None
    assert out["reconciliation"] == "INCOMPLETE" and out["daemon_continuity"] == "UNKNOWN"
    assert out["cleanup_status"] == "FAILED"  # absence cannot be confirmed without a complete inventory


def test_evidence_file_and_journal_line_bounds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from patchproof.runner import run_evidence
    from patchproof.runner.run_evidence import EvidenceError, RunEvidence

    evidence = RunEvidence.claim(private(tmp_path / "ev") / "runs", RUN_ID)
    monkeypatch.setattr(run_evidence, "MAX_EVIDENCE_FILE_BYTES", 8)
    monkeypatch.setattr(run_evidence, "MAX_JOURNAL_LINE_BYTES", 16)
    evidence.write("ok.bin", b"12345678")
    with pytest.raises(EvidenceError, match="bound"):
        evidence.write("big.bin", b"123456789")
    with pytest.raises(EvidenceError, match="bound"):
        evidence.append_line("j.jsonl", {"k": "x" * 20})
    assert sorted(os.listdir(evidence.directory)) == ["ok.bin"]


def test_verify_evidence_detects_changes_and_recomputes_the_verdict(e: Env) -> None:
    from patchproof.runner.run_evidence import verify_evidence

    assert authorize(e)[0] == 0
    assert execute(e)[0] == 0
    assert verify_evidence(e.evidence) == {"state": "CONSISTENT", "status": "FINALIZED", "problems": []}
    writable(e.evidence)
    verdict = json.loads((e.evidence / "verdict.json").read_text())
    verdict["verdict"] = "NOT_FIXED"
    data = json.dumps(verdict).encode()
    (e.evidence / "verdict.json").write_bytes(data)
    m = manifest(e)  # a consistent forgery of manifest and file: only the recomputation catches it
    m["files"]["verdict.json"] = {**m["files"]["verdict.json"], "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
                                  "bytes": len(data)}
    (e.evidence / "manifest.json").write_text(json.dumps(m))
    assert verify_evidence(e.evidence)["problems"] == [
        "verdict.json differs from the engine's evaluation of verdict-input.json"]
    (e.evidence / "plan.json").write_text("{}")
    (e.evidence / "extra.txt").write_text("x")
    os.unlink(e.evidence / "collection.json")
    problems = verify_evidence(e.evidence)["problems"]
    assert "plan.json: content differs from the manifest" in problems
    assert "extra.txt: present but not in the manifest" in problems
    assert "collection.json: listed in the manifest but missing" in problems


def test_the_fixed_fixture_limitation_is_in_the_plan_and_the_outcome(e: Env) -> None:
    assert authorize(e)[0] == 0
    assert execute(e)[0] == 0
    plan = json.loads((e.evidence / "plan.json").read_text())
    fixture_sha256 = "sha256:2cbcf118fddb2cd4e38a9af5e8786911e8f85e292e637102799fd60513129eda"
    assert plan["fixture"] == {"mode": "fixed-fixture-v0.1-exception", "fixture_contract": "synthetic-documents-v1",
                               "fixture_sha256": fixture_sha256, "seed": None, "identical_for_both_sides": True,
                               "fresh_target_per_side": True}
    assert plan["repetitions"]["pairs"] == 1
    fixture = outcome(e)["fixture"]
    assert fixture["seed"] is None and fixture["pairs"] == 1 and "no seed variation" in fixture["limitation"]


# ---- verdict semantics through the driver


@pytest.mark.parametrize("fault", ["verifier_timeout", "verifier_oom", "crash", "absent"])
def test_a_failing_candidate_execution_is_never_a_regression(e: Env, fault: str) -> None:
    """17.3 item 3: a timeout, OOM, crash or absent stream is uncertainty, not a regression."""
    assert authorize(e)[0] == 0
    docker = fake(e, candidate="deny-all")  # failing legitimate requests in the stream

    def break_candidate(side: str) -> None:
        if side != "candidate":
            return
        if fault == "crash":
            docker.verifier_exit = 3
        elif fault == "absent":
            docker.streams["candidate"] = b""
        else:
            setattr(docker, fault, True)

    docker.on_attach = break_candidate
    code, _, _ = execute(e, docker)
    out = outcome(e)
    assert out["verdict"] == "INCONCLUSIVE" and "FUNCTIONAL_REGRESSION" not in out["reason_codes"]
    assert out["evidence_status"] == "FINALIZED" and out["lifecycle"] == "COMPLETE" and code == 0


def test_a_trusted_deny_all_candidate_is_a_regression(e: Env) -> None:
    assert authorize(e)[0] == 0
    code, _, _ = execute(e, fake(e, candidate="deny-all"))
    assert outcome(e)["verdict"] == "REGRESSION_DETECTED" and code == 0


# ---- Docker daemon continuity


def test_a_restart_after_the_candidate_needs_attention(e: Env) -> None:
    assert authorize(e)[0] == 0
    docker = fake(e)
    real_run = docker.run

    def run(op: Any) -> Any:  # the bridge network is recreated after the last revision
        if isinstance(op, SnapshotList) and op.kind == "images" and len(docker.created) == 4:
            docker.listings["networks"][0] = {"ID": "6a" * 32, "Name": "bridge", "Driver": "bridge", "Scope": "local"}
        return real_run(op)

    docker.run = run  # type: ignore[method-assign]
    code, term, _ = execute(e, docker)
    out = outcome(e)
    assert out["reconciliation"] == "EXPLAINED_DAEMON_MANAGED" and out["daemon_continuity"] == "BROKEN_SUSPECTED"
    assert code == 5 and "daemon continuity BROKEN_SUSPECTED" in term.output()
    ops = [json.loads(line) for line in (e.evidence / "docker-ops.jsonl").read_text().splitlines()]
    network_ops = [o for o in ops if "network" in o["argv_tail"]]
    assert network_ops and all(o["op"] == "snapshot" for o in network_ops)  # PatchProof only ever lists networks


def test_unchanged_network_ids_are_reported_as_no_change_observed_not_proof(e: Env) -> None:
    assert authorize(e)[0] == 0
    assert execute(e)[0] == 0
    out = outcome(e)
    assert out["daemon_continuity"] == "NO_CHANGE_OBSERVED"
    assert "does NOT prove the daemon stayed online" in out["daemon_continuity_note"]


def test_an_unexplained_resource_change_during_the_run_needs_attention(e: Env) -> None:
    assert authorize(e)[0] == 0
    docker = fake(e)

    def appear(side: str) -> None:
        if side == "candidate":
            docker.listings["containers"].append({"ID": "e7" * 32, "Names": "appeared-mid-run", "Image": "x:1",
                                                  "State": "running", "Labels": ""})
            docker.listings["networks"][3] = {**docker.listings["networks"][3], "ID": "7b" * 32}

    docker.on_attach = appear
    code, _, _ = execute(e, docker)
    out = outcome(e)
    findings = json.loads((e.evidence / "reconciliation.json").read_text())["findings"]
    assert out["reconciliation"] == "ATTENTION" and code == 5
    assert {f["classification"] for f in findings} == {"UNEXPLAINED_ADDED", "UNEXPLAINED_REMOVED"}
    assert "e7" * 32 not in docker.touched_ids()


def test_docker_unavailable_before_the_candidate_interrupts(e: Env) -> None:
    assert authorize(e)[0] == 0
    docker = fake(e)
    docker.on_attach = lambda side: docker.listing_fails.add("networks") if side == "baseline" else None
    code, _, _ = execute(e, docker)
    out = outcome(e)
    assert creates(docker) == [("baseline", "target"), ("baseline", "verifier")]
    assert out["run_termination"] == "interrupted" and out["daemon_continuity"] == "UNKNOWN"
    assert out["engine_verdict"] == "INCONCLUSIVE" and out["verdict"] is None and code == 4


def test_the_daemon_disappearing_during_the_candidate_fails_closed(e: Env) -> None:
    from patchproof.runner.run_recovery import assess

    assert authorize(e)[0] == 0
    docker = fake(e)

    def vanish(side: str) -> None:
        if side == "candidate":
            docker.down = True

    docker.on_attach = vanish
    code, _, _ = execute(e, docker)
    out = outcome(e)
    assert out["engine_verdict"] == "INCONCLUSIVE" and out["verdict"] is None and code == 4
    assert out["cleanup_status"] == "FAILED" and len(out["remaining_owned_container_ids"]) == 0
    assert out["reconciliation"] == "INCOMPLETE" and out["daemon_continuity"] == "UNKNOWN"
    revision = json.loads((e.evidence / "revision-pair-001-candidate.json").read_text())
    assert {c["status"] for c in revision["cleanup"]} == {"FAILED"}  # never assumed removed
    # The daemon comes back: the read-only assessment finds both candidate containers, still owned.
    docker.down = False
    from patchproof.runner.policy import Ownership

    plan = assemble_run(e.env, RUN_ID).plan
    found = assess(docker, Ownership(plan.ownership.installation_id, RUN_ID), e.evidence / "ownership-journal.jsonl")
    assert [(f.name.rsplit("-", 2)[-2], f.state) for f in found.findings] == [
        ("baseline", "ABSENT"), ("baseline", "ABSENT"), ("candidate", "OWNED"), ("candidate", "OWNED")]
