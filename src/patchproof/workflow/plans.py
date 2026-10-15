"""`patchproof plan create | show | approve` and `patchproof run` (PROJECT_SPEC.md 6, 13.1, 13.2; PP-009).

**Plans.** `plan create` resolves two revisions in a registered project through the PP-005
wrapper, checks them against the accepted plan contract, and recomputes the complete frozen plan
with the accepted `runner.papertrail_plan.assemble_run` (current pack approval, pack copy,
profile, source snapshots, fixture, images, every limit). The plan is stored once, read-only, as
the canonical JSON of that `RunPlanDocument`; its ID is derived from its SHA-256. Creating a plan
approves nothing and executes nothing.

**Approval.** `plan approve <plan-id>` delegates to the accepted owner-operated
`run_authorization.run_authorization`, bound to the stored plan's run ID and hash: if the plan
recomputed now differs in any byte, nothing is shown for confirmation and nothing is written.

**Execution.** `run <plan-id>` delegates to the accepted `run_papertrail_once.execute_once`,
bound to the stored plan's hash, with its typed `EXECUTE <run-id>` confirmation, exclusive
single-use claim, exact-ID cleanup and verdict engine. A consumed authorization never runs again;
there is no retry and no `--yes`.

**Scope (v0.1).** The executable contract is the accepted `papertrail-authz-r1-r3-one-pair-v1`:
the PaperTrail reference profile, baseline r1 against candidate r3, one pair, fixed fixture.
Other revisions are refused before any plan is written. Widening the contract is a
security-contract change that needs owner review.
"""

from __future__ import annotations

import os
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Final, Literal

from ..core.approvals import canonical_sha256
from ..core.records import RecordError, load_record
from ..core.records.authorization import RunPlanDocument
from ..core.records.evidence import SourceManifest
from ..core.run_authorizations import (
    RunAuthorizationError,
    RunAuthorizationStore,
    check_plan_semantics,
    is_superseded,
    plan_sha256,
)
from ..git.command import GitBinary
from ..git.errors import SourceError
from ..git.paths import SourceScope
from ..git.repository import ResolvedRevision, register_repository, resolve_revision
from ..git.snapshot import MANIFEST_NAME, create_snapshot
from ..pack_approval import ApprovalBlocked, Terminal
from ..run_authorization import run_authorization
from ..run_papertrail_once import OnceResult, execute_once
from ..runner.docker_cli import Executor
from ..runner.papertrail_plan import (
    SIDES,
    AssembledRun,
    PlanError,
    RunEnvironment,
    Side,
    assemble_run,
    papertrail_environment,
    plan_differences,
)
from ..runner.policy import PolicyViolation
from ..runner.profiles import load_profile
from ..runner.revision import Clock
from . import exit_codes
from .invocation import command
from .preflight import Preflight
from .projects import ProjectStore
from .safe_text import plain
from .store import PrivateStore, StoreError

MAX_PLAN_BYTES: Final = 256 * 1024
PLAN_ID_RE: Final = re.compile(r"plan-[0-9a-f]{32}")
_SNAPSHOT_RE: Final = re.compile(r"snapshot-[0-9a-f]{32}")
ROLES: Final[dict[Side, str]] = {"baseline": "vulnerable reference revision (r1); must reproduce the violation",
                                 "candidate": "proposed fix (r3); must be secure and keep functional controls"}

AuthorizationState = Literal["NONE", "UNUSED", "CLAIMED", "SUPERSEDED"]


class WorkflowRefused(Exception):
    """A precondition failed. Nothing was approved, claimed or executed."""


@dataclass(frozen=True)
class WorkflowEnv:
    run: RunEnvironment
    projects: ProjectStore
    plans_root: Path


def workflow_environment() -> WorkflowEnv:
    from ..pack_approval import data_root

    data = data_root()
    return WorkflowEnv(run=papertrail_environment(), projects=ProjectStore(data / "projects"),
                       plans_root=data / "plans")


# ------------------------------------------------------------------ the plan store


def plan_id_for(sha256: str) -> str:
    return "plan-" + sha256.removeprefix("sha256:")[:32]


def plan_bytes(document: RunPlanDocument) -> bytes:
    import json

    return json.dumps(document.model_dump(mode="json", by_alias=True), sort_keys=True,
                      separators=(",", ":")).encode("utf-8") + b"\n"


def _plans(wenv: WorkflowEnv) -> PrivateStore:
    return PrivateStore(wenv.plans_root, max_record_bytes=MAX_PLAN_BYTES)


def save_plan(wenv: WorkflowEnv, document: RunPlanDocument) -> tuple[str, str]:
    sha = plan_sha256(document)
    plan_id = plan_id_for(sha)
    _plans(wenv).write_once(f"{plan_id}.json", plan_bytes(document))
    return plan_id, sha


def load_plan(wenv: WorkflowEnv, plan_id: str) -> tuple[RunPlanDocument, str]:
    """The stored plan, validated: strict JSON, the plan contract, its semantics and its ID."""
    if not PLAN_ID_RE.fullmatch(plan_id):
        raise WorkflowRefused("a plan ID is 'plan-' followed by 32 lower-case hex digits")
    raw = _plans(wenv).read(f"{plan_id}.json")
    if raw is None:
        raise WorkflowRefused(f"there is no stored plan {plan_id}")
    document = load_record(RunPlanDocument, raw, contract="run-plan", max_bytes=MAX_PLAN_BYTES)
    check_plan_semantics(document)
    sha = plan_sha256(document)
    if plan_id_for(sha) != plan_id or raw != plan_bytes(document) or canonical_sha256(document) != sha:
        raise WorkflowRefused("the stored plan does not match its ID; it is not used")
    return document, sha


def authorization_state(env: RunEnvironment, document: RunPlanDocument, sha: str) -> AuthorizationState:
    if not env.authorization_store.exists():
        return "NONE"
    records, claims = RunAuthorizationStore(env.authorization_store).scan()
    matching = [r for r in records.values() if r.record.plan.run_id == document.run_id]
    if not matching:
        return "NONE"
    if len(matching) != 1 or matching[0].record.plan_sha256 != sha:
        raise WorkflowRefused("the authorization store holds a different plan for this run ID")
    ident = matching[0].record.authorization_id
    if ident in claims:
        return "CLAIMED"
    return "SUPERSEDED" if is_superseded(records, ident) else "UNUSED"


# ------------------------------------------------------------------ snapshots


def snapshot_counts(env: RunEnvironment) -> dict[str, int]:
    """How many snapshots of each commit the private store holds (manifests strictly loaded)."""
    counts: dict[str, int] = {}
    if not env.snapshot_store.exists():
        return counts
    for name in sorted(os.listdir(env.snapshot_store)):
        if not _SNAPSHOT_RE.fullmatch(name):
            continue
        path = env.snapshot_store / name / MANIFEST_NAME
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as handle:
            raw = handle.read(64 * 1024 * 1024 + 1)
        manifest = load_record(SourceManifest, raw, contract="source-manifest", max_bytes=64 * 1024 * 1024)
        counts[manifest.commit_id] = counts.get(manifest.commit_id, 0) + 1
    return counts


def _ensure_private_dir(path: Path) -> None:
    parent = path.parent
    st = os.lstat(parent)
    if st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise WorkflowRefused("the private data directory must be owned by you and not group/world accessible")
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        pass
    st = os.lstat(path)
    if not os.path.isdir(path) or os.path.islink(path) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise WorkflowRefused(f"{path.name} must be a private directory owned by you")


# ------------------------------------------------------------------ previews


PREVIEW_TITLES: Final = {
    "show": "EXECUTION PLAN PREVIEW (read-only: this approves and executes nothing)",
    "create": "EXECUTION PLAN: stored once as an immutable record. Creating it approves and executes nothing;",
}
CREATE_TITLE_NOTE: Final = ("approval (plan approve) and execution (run) are separate steps, each with its own typed "
                            "confirmation.")


def render_plan_preview(run: AssembledRun, plan_id: str | None, project_line: str | None,
                        resolved: dict[Side, ResolvedRevision] | None, preflight: Preflight, *,
                        mode: Literal["show", "create"] = "show") -> str:
    d = run.document
    rt = d.runtime
    res, to = rt.resources, rt.timeouts
    tests = {t.id: t for t in run.review.pack.manifest.tests}
    lines = ["=" * 78, PREVIEW_TITLES[mode], *([CREATE_TITLE_NOTE] if mode == "create" else []), "=" * 78, ""]
    if plan_id:
        lines += [f"Plan ID           {plan_id}", f"Plan SHA-256      {run.sha256}"]
    lines += [f"Run ID            {d.run_id}   (bound into the plan; a run never reuses it)",
              f"Plan kind         {d.plan_kind}"]
    if project_line:
        lines.append(f"Project           {project_line}")
    lines += ["", "Revisions (committed objects only; uncommitted edits are excluded):"]
    for side in ("baseline", "candidate"):
        s = getattr(d.sources, side)
        req = f"requested {plain(resolved[side].requested, 120)} -> " if resolved else ""
        lines += [f"  {side:9} {ROLES[side]}", f"            {req}commit {s.commit_id}",
                  f"            tag {s.tag}; tree {s.tree_id}",
                  f"            snapshot {s.snapshot_name}; manifest {s.source_manifest_sha256}",
                  f"            source files {s.source_tree_sha256}"]
    lines += [
        f"  inclusion  {', '.join(d.source_inclusion.include)} (profile {d.source_inclusion.inclusion_profile_sha256})",
        "  exclusions everything else; symlinks, submodules, LFS pointers, '.git' paths, secret-looking paths",
        "             and files over the snapshot limits are never included",
        "",
        f"Pack              {d.pack.pack_id} {d.pack.pack_version}; tree {d.pack.pack_tree_sha256}",
        f"                  manifest {d.pack.manifest_sha256}; verifier plugin {d.pack.verifier_plugin_version}",
        f"Pack approval     {d.pack_approval_id} (current and APPROVED for the recomputed bindings)",
        f"Profile           {d.profile.profile_id} {d.profile.profile_version} {d.profile.profile_sha256}",
        f"Target image      {d.images.target_image_id}",
        f"Verifier image    {d.images.verifier_image_id}",
        f"Fixture           {d.fixture.mode}; {d.fixture.fixture_contract} {d.fixture.fixture_sha256}; no seed",
        "",
        "Expected collection and declared expectations (expectations, not results):",
    ]
    for t in d.pack.expected_collection:
        test = tests[t.id]
        lines.append(f"  {t.id:9} {test.kind:10} baseline {test.baseline_expected:19} candidate "
                     f"{test.candidate_expected:6} {t.nodeid}")
    lines += ["", f"Exact execution scope: {d.repetitions.pairs} pair, sequential, no automatic retry, at most "
                  f"{d.containers.max_creations} container creations:"]
    for i, c in enumerate(d.containers.sequence, 1):
        network = "--network none" if c.role == "target" else "--network container:<that exact target ID>"
        mount = "source snapshot read-only at /app/source" if c.role == "target" else "pack read-only at /pack"
        lines.append(f"  {i}. {c.name} ({network}; {mount})")
    lines += [
        "  Fixed policy, inspected before each start: user 10001:10001, read-only root, all capabilities",
        "  dropped, no-new-privileges, default seccomp, private namespaces, no ports, no Docker socket, no host",
        "  credentials, --pull=never. No caller-supplied Docker option, mount, environment or command exists.",
        f"  Baseline failure policy: {d.baseline_failure_policy}.",
        f"Limits            target {res.target.cpus} CPU, {res.target.memory_bytes} B, {res.target.pids} PIDs; "
        f"verifier {res.verifier.cpus} CPU, {res.verifier.memory_bytes} B, {res.verifier.pids} PIDs",
        f"Deadlines         readiness {to.readiness_seconds} s; per case {rt.case_timeout_seconds} s; revision "
        f"{to.revision_deadline_seconds} s; stop grace {to.cancellation_grace_seconds} s",
        f"Evidence          <user data>/{d.evidence.destination}/ (private)",
        "",
        "Known limitations: one pair and one fixed synthetic fixture; 8 selected checks; container inspection is",
        "configuration evidence, not proof of kernel enforcement; structured witnesses are kept, raw HTTP",
        "responses are not; the reviewer identity is a local assertion and these gates are procedural.",
        "",
        preflight.render(),
    ]
    return "\n".join(lines)


# ------------------------------------------------------------------ plan create


def create_plan(wenv: WorkflowEnv, terminal: Terminal, git: GitBinary, *, project_id: str, baseline: str,
                candidate: str, create_snapshots: bool, home: Path | None = None,
                new_run_id: Callable[[], str] = lambda: "run-" + secrets.token_hex(16)) -> tuple[int, str | None]:
    """Returns (exit code, plan ID). Writes only the plan record, and snapshots after a typed confirmation."""
    env = wenv.run
    pre = Preflight()
    try:
        project = wenv.projects.load(project_id) if re.fullmatch(r"prj-[0-9a-f]{16}", project_id) else None
        if not pre.mandatory("project is registered", project is not None, project_id):
            raise WorkflowRefused(f"{project_id} is not a registered project (register it first: "
                                  f"{command('project', 'add')} <absolute-repository-path>)")
        assert project is not None
        repo = register_repository(project.canonical_path, git, home=home)
        pre.mandatory("repository re-validated at its registered canonical root",
                      repo.object_format.value == project.object_format, repo.object_format.value)
        profile = load_profile(env.approval_target.profile_path, expected_sha256=env.approval_target.profile_sha256)
        pre.mandatory("project supports the reviewed profile",
                      profile.profile.profile_id in project.supported_profiles, profile.profile.profile_id)
        resolved: dict[Side, ResolvedRevision] = {"baseline": resolve_revision(repo, baseline),
                                                  "candidate": resolve_revision(repo, candidate)}
        for side in SIDES:
            pinned = env.revisions[side]
            got = resolved[side]
            pre.mandatory(f"{side} is the {side} the accepted v0.1 plan contract binds",
                          (got.commit.value, got.tree.value) == (pinned.commit_id, pinned.tree_id),
                          f"{got.commit.value} (contract {pinned.commit_id}, {pinned.tag})")
        if not pre.passed:
            raise WorkflowRefused("the revisions are outside the accepted v0.1 plan contract (PaperTrail r1 -> r3); "
                                  "widening it is a security-contract change that needs owner review")
        counts = snapshot_counts(env)
        missing: list[Side] = [s for s in SIDES if counts.get(resolved[s].commit.value, 0) == 0]
        if missing and not create_snapshots:
            pre.mandatory("source snapshots exist", False, f"missing for {', '.join(missing)}")
            raise WorkflowRefused("a source snapshot is missing; rerun with --create-snapshots at your terminal to "
                                  "review and create it")
        if missing:
            scope = SourceScope.of(profile.profile.source_scope.include)
            terminal.write("SOURCE SNAPSHOTS to create (read-only copies, through the PP-005 Git wrapper; no "
                           "checkout, no repository code runs):\n")
            for side in missing:
                terminal.write(f"  {side:9} commit {resolved[side].commit.value} tree {resolved[side].tree.value}\n")
            terminal.write(f"  scope {', '.join(scope.include)}; destination <user data>/source-snapshots\n")
            phrase = f"SNAPSHOT {project_id}"
            if terminal.read_line(f"To create them, type exactly:  {phrase}\nConfirmation: ") != phrase:
                raise WorkflowRefused("the snapshot confirmation does not match; nothing was created")
            _ensure_private_dir(env.snapshot_store)
            for side in missing:
                create_snapshot(repo, resolved[side].commit.value, scope, env.snapshot_store)
            counts = snapshot_counts(env)
        for side in SIDES:
            n = counts.get(resolved[side].commit.value, 0)
            pre.mandatory(f"exactly one {side} snapshot", n == 1, f"{n} found")
        run_id = new_run_id()
        run = assemble_run(env, run_id)
        pre.mandatory("frozen plan recomputed from the current approval, pack, profile, snapshots and images", True,
                      run.sha256)
        pre.mandatory("no evidence exists for the new run ID", not os.path.lexists(env.evidence_root / run_id))
        if env.authorization_store.exists():
            unused = RunAuthorizationStore(env.authorization_store).executable()
            pre.diagnostic("no other unused run authorization", unused is None,
                           "approving this plan would supersede the unused authorization "
                           f"{unused.record.authorization_id} (kept, never executable)" if unused else "")
        if not pre.passed:
            raise WorkflowRefused("a mandatory preflight check failed")
        plan_id, sha = save_plan(wenv, run.document)
        loaded, loaded_sha = load_plan(wenv, plan_id)
        if loaded != run.document or loaded_sha != run.sha256 or sha != run.sha256:
            raise WorkflowRefused("the stored plan did not read back as written")
    except (WorkflowRefused, PlanError, SourceError, RecordError, StoreError, RunAuthorizationError, ApprovalBlocked,
            PolicyViolation, OSError) as exc:
        if isinstance(exc, PlanError):
            pre.mandatory(f"plan precondition {exc.precondition}", False, f"{exc.code}: {exc}")
        terminal.write(pre.render())
        terminal.write(f"\nNO PLAN CREATED: {plain(exc, 600)}. Nothing was approved or executed.\n")
        return exit_codes.BLOCKED, None
    except (EOFError, KeyboardInterrupt):
        terminal.write("\nNO PLAN CREATED: input ended.\n")
        return exit_codes.BLOCKED, None
    terminal.write(render_plan_preview(run, plan_id, f"{project_id} at {plain(project.canonical_path, 1024)}",
                                       resolved, pre, mode="create"))
    terminal.write(f"\nPLAN CREATED: {plan_id}\n  Nothing has been approved or executed. To review and authorize it, "
                   f"run at your terminal, from the PatchProof checkout:  "
                   f"{command('plan', 'approve', plan_id)}\n")
    return exit_codes.OK, plan_id


def show_plan(wenv: WorkflowEnv, terminal: Terminal, plan_id: str) -> int:
    pre = Preflight()
    try:
        document, sha = load_plan(wenv, plan_id)
        pre.mandatory("stored plan valid and matching its ID", True, sha)
        state = authorization_state(wenv.run, document, sha)
        pre.diagnostic(f"authorization state {state}", state in ("NONE", "UNUSED"),
                       {"CLAIMED": "consumed; this plan can never run again",
                        "SUPERSEDED": "replaced; create a new plan", "NONE": "not approved yet",
                        "UNUSED": "approved; not yet executed"}[state])
        run = assemble_run(wenv.run, document.run_id)
        current = run.document == document and run.sha256 == sha
        pre.mandatory("plan still equals the plan recomputed from current inputs", current,
                      "" if current else f"differs in {plan_differences(document, run.document)}")
    except (WorkflowRefused, PlanError, RecordError, StoreError, RunAuthorizationError, OSError) as exc:
        terminal.write(pre.render())
        terminal.write(f"\nPLAN NOT SHOWN: {plain(exc, 600)}\n")
        return exit_codes.BLOCKED
    terminal.write(render_plan_preview(run, plan_id, None, None, pre))
    return exit_codes.OK if pre.passed else exit_codes.BLOCKED


# ------------------------------------------------------------------ plan approve


def approve_plan(wenv: WorkflowEnv, terminal: Terminal, plan_id: str, *, now: Callable[[], datetime]) -> int:
    """Delegates to the accepted run authorization, bound to this plan. 0 only for a verified authorization."""
    try:
        document, sha = load_plan(wenv, plan_id)
        state = authorization_state(wenv.run, document, sha)
        if state == "UNUSED":
            terminal.write(f"{plan_id} is already authorized and unused. Nothing was written. To execute it, run at "
                           f"your terminal, from the PatchProof checkout:  {command('run', plan_id)}\n")
            return exit_codes.OK
        if state != "NONE":
            raise WorkflowRefused(f"this plan's authorization is {state}; a plan is authorized and run at most once. "
                                  "Create a new plan")
    except (WorkflowRefused, RecordError, StoreError, RunAuthorizationError, OSError) as exc:
        terminal.write(f"\nNOT AUTHORIZED: {plain(exc, 600)}. Nothing was written.\n")
        return exit_codes.BLOCKED
    terminal.write(f"Selected plan {plan_id}\n  plan SHA-256 {sha}\n  The review below is recomputed from the current "
                   "inputs and must equal this plan exactly.\n\n")
    code = run_authorization(wenv.run, terminal, now=now, new_run_id=lambda: document.run_id,
                             expected_plan_sha256=sha)
    if code == 0:
        terminal.write(f"  CLI: to execute this plan once, run at your terminal, from the PatchProof checkout:  "
                       f"{command('run', plan_id)}\n")
        return exit_codes.OK
    return exit_codes.BLOCKED


# ------------------------------------------------------------------ run


@dataclass(frozen=True)
class RunResult:
    exit_code: int
    run_id: str | None
    stage: str
    lifecycle: str | None
    evidence_status: str | None
    verdict: str | None  # established semantic verdict (finalized evidence only)
    engine_verdict: str | None
    reason_codes: tuple[str, ...]
    # Separate dimensions (PROJECT_SPEC.md 8.1): they never change the exit code, and the exit code
    # never implies them. A verified verdict with a cleanup failure exits 0 and says so here.
    cleanup_complete: bool | None = None
    reconciliation: str | None = None
    daemon_continuity: str | None = None
    stop_reason: str | None = None

    def document(self) -> dict[str, Any]:
        return {"run_id": self.run_id, "stage": self.stage, "lifecycle": self.lifecycle,
                "evidence_status": self.evidence_status, "verdict": self.verdict, "engine_verdict": self.engine_verdict,
                "reason_codes": list(self.reason_codes), "exit_code": self.exit_code,
                "cleanup_complete": self.cleanup_complete, "reconciliation": self.reconciliation,
                "daemon_continuity": self.daemon_continuity, "stop_reason": self.stop_reason,
                "exit_code_contract": "PROJECT_SPEC.md 13.2 (lifecycle first, then the semantic verdict)"}


def result_from(once: OnceResult, run_id: str) -> RunResult:
    if once.stage == "REFUSED":
        return RunResult(exit_codes.BLOCKED, run_id, once.stage, None, None, None, None, ())
    if once.stage in ("CLAIMED_NOT_EXECUTED", "INCOMPLETE") or once.outcome is None:
        return RunResult(exit_codes.INCONCLUSIVE, run_id, once.stage, None, "INCOMPLETE", None, None, ())
    o = once.outcome
    return RunResult(exit_codes.run_exit_code(o.lifecycle, o.verdict, o.status), run_id, once.stage, o.lifecycle,
                     o.status, o.verdict, o.engine_verdict, tuple(o.reason_codes), o.cleanup_complete,
                     o.reconciliation, o.daemon_continuity, o.stop_reason)


def run_plan(wenv: WorkflowEnv, terminal: Terminal, plan_id: str, executor_factory: Callable[[], Executor], *,
             clock: Clock, now: Callable[[], datetime]) -> RunResult:
    try:
        document, sha = load_plan(wenv, plan_id)
        state = authorization_state(wenv.run, document, sha)
        if state == "NONE":
            raise WorkflowRefused(f"{plan_id} is not authorized; first run: {command('plan', 'approve', plan_id)}")
        if state == "CLAIMED":
            raise WorkflowRefused("this plan's single-use authorization is already consumed; it never runs again")
        if state == "SUPERSEDED":
            raise WorkflowRefused("this plan's authorization was superseded and can never execute")
    except (WorkflowRefused, RecordError, StoreError, RunAuthorizationError, OSError) as exc:
        terminal.write(f"\nNOT EXECUTED: {plain(exc, 600)}. Nothing was claimed and no Docker operation ran.\n")
        return RunResult(exit_codes.BLOCKED, None, "REFUSED", None, None, None, None, ())
    once = execute_once(wenv.run, terminal, executor_factory, clock=clock, now=now, expected_plan_sha256=sha)
    result = result_from(once, document.run_id)
    terminal.write(f"\nCLI exit code {result.exit_code} (PROJECT_SPEC.md 13.2; lifecycle takes precedence over "
                   f"verdict). Report:  {command('report', document.run_id)}\n")
    return result
