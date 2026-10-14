"""Owner-operated authorization of ONE deliberate interruption demonstration (PP-008 integration utility).

This is NOT a run authorization and NOT the PP-009 CLI. It authorizes exactly one plan kind,
`papertrail-interruption-sigterm-baseline-v1`, and nothing else. Run it yourself, in your own
terminal, from the project directory:

    uv run --locked --offline python -I -m patchproof.interruption_authorization

**What it does:**
1. Refuses to run with any argument, any `PATCHPROOF*` environment variable, or unless
   standard input and output are a terminal in the foreground (the pack-approval gate), so
   no confirmation can come from the command line or redirected input.
2. Generates a fresh run ID and recomputes the complete interruption plan from the real
   private artifacts (`runner.interruption_plan.assemble_interruption`): the current pack
   approval, the pack copy, the profile, the r1 source snapshot, the fixture hash, the
   approved images and every limit. It computes the canonical plan hash.
3. Shows every binding, the two-container budget, the signal behavior, why the run cannot
   produce a verified-fix result, the cleanup behavior and the residual risks.
4. Asks for the reviewer's asserted identity, a rationale and a scope (neither may contain
   the confirmation phrase), then the exact phrase
   `AUTHORIZE INTERRUPTION TEST <run-id> <plan-sha256>`.
5. Recomputes the plan and re-reads the store immediately before writing. Any change aborts
   with nothing written.
6. Writes one immutable record to `<user data>/interruption-authorizations/`, reads it back
   and verifies it. A failure after the write is `FAILED VERIFICATION` (exit 4).

It executes nothing. Execution is the separate controller `patchproof.interruption_test`.
**Limits:** a procedural control, not proof of a human; the reviewer identity is a local
assertion.
"""

from __future__ import annotations

import os
import secrets
import stat
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from .core.interruption_authorizations import (
    InterruptionAuthorizationError,
    InterruptionAuthorizationStore,
    StoredInterruptionAuthorization,
    create_interruption_authorization,
    interruption_authorization_phrase,
    is_superseded,
)
from .core.run_authorizations import AuthorizationDecision
from .pack_approval import (
    ApprovalBlocked,
    NotInteractive,
    Terminal,
    _ask,
    _ask_statement,
    _ConsoleTerminal,
    require_interactive,
)
from .runner.interruption_plan import AssembledInterruption, assemble_interruption, interruption_environment
from .runner.papertrail_plan import PlanError, RunEnvironment


def provision_interruption_store(root: Path) -> InterruptionAuthorizationStore:
    """Create (once) and open the private store. Never follows or repairs anything."""
    parent = root.parent
    if not os.path.isabs(str(root)) or os.path.realpath(str(parent)) != str(parent):
        raise ApprovalBlocked("interruption-authorization store parent must be an absolute canonical directory")
    try:
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise ApprovalBlocked("interruption-authorization store parent is missing, not a directory, or a symlink") \
            from exc
    try:
        pst = os.fstat(parent_fd)
        if pst.st_uid != os.getuid() or stat.S_IMODE(pst.st_mode) & 0o077:
            raise ApprovalBlocked("interruption-authorization store parent must be a private directory owned by you")
        try:
            os.mkdir(root.name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        st = os.stat(root.name, dir_fd=parent_fd, follow_symlinks=False)
    finally:
        os.close(parent_fd)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
        raise ApprovalBlocked("interruption-authorization store must be a directory owned by you with mode 0700")
    try:
        store = InterruptionAuthorizationStore(root)
    except InterruptionAuthorizationError as exc:
        raise ApprovalBlocked(f"interruption-authorization store: {exc}") from None
    if store.identity != (st.st_dev, st.st_ino):
        raise ApprovalBlocked("interruption-authorization store was replaced while it was being opened")
    return store


def render_interruption_plan(run: AssembledInterruption, replaces: StoredInterruptionAuthorization | None,
                             store_root: Path) -> str:
    d = run.document
    rt, c, i, x = d.runtime, d.containers, d.interruption, d.expected_outcome
    res, to = rt.resources, rt.timeouts
    s = d.sources.baseline
    lines = [
        "=" * 78,
        "INTERRUPTION TEST AUTHORIZATION REVIEW: this authorizes ONE deliberately interrupted run, once.",
        "=" * 78,
        "",
        "THIS RUN IS DELIBERATELY INTERRUPTED. It executes the baseline target only, never starts the",
        "verifier and never runs the candidate, so it CANNOT produce a verified-fix result. Its purpose is",
        "to show that an interruption is cleaned up and recorded truthfully.",
        "",
        f"Run ID            {d.run_id}   (generated now; never reused)",
        f"Plan kind         {d.plan_kind}",
        f"Plan SHA-256      {run.sha256}",
        f"Installation      {d.installation_id}",
        f"Pack approval     {d.pack_approval_id}   (current; APPROVED for the recomputed bindings)",
        f"Pack              {d.pack.pack_id} {d.pack.pack_version}",
        f"  manifest        {d.pack.manifest_sha256}",
        f"  tree            {d.pack.pack_tree_sha256}",
        f"Profile           {d.profile.profile_id} {d.profile.profile_version} {d.profile.profile_sha256}",
        f"Target image      {d.images.target_image_id}",
        f"Verifier image    {d.images.verifier_image_id}   (created and inspected; never started)",
        "",
        "Source (PP-005 snapshot, read-only, re-hashed now), BASELINE ONLY:",
        f"  {s.tag}",
        f"    commit   {s.commit_id}",
        f"    tree     {s.tree_id}",
        f"    snapshot {s.snapshot_name}",
        f"    manifest {s.source_manifest_sha256}",
        f"    files    {s.source_tree_sha256}",
        f"  inclusion  {d.source_inclusion.include}  {d.source_inclusion.inclusion_profile_sha256}",
        f"Fixture: {d.fixture.mode}; {d.fixture.fixture_contract} {d.fixture.fixture_sha256}; no seed.",
        "",
        f"Container budget: at most {c.max_creations} creations, at most {c.max_started} started; a third "
        "creation is refused before it reaches Docker.",
        f"  1. {c.target.name}  (--network {c.target.network}; {c.target.input_mount}; "
        f"start: {c.target.start})",
        f"  2. {c.verifier.name}  (--network {c.verifier.network}; {c.verifier.input_mount}; "
        f"start: {c.verifier.start})",
        "  Each container is inspected and must match the fixed policy before anything starts: user",
        "  10001:10001, read-only root, all capabilities dropped, no-new-privileges, default seccomp, private",
        "  IPC and cgroup namespaces, no published ports, no Docker socket, no host credentials, --pull=never.",
        f"  Limits: target {res.target.cpus} CPU, {res.target.memory_bytes} B, {res.target.pids} PIDs, tmpfs "
        f"{res.target.scratch_tmpfs_bytes} + {res.target.tmp_tmpfs_bytes} B; verifier {res.verifier.cpus} CPU, "
        f"{res.verifier.memory_bytes} B, {res.verifier.pids} PIDs, tmpfs {res.verifier.scratch_tmpfs_bytes} + "
        f"{res.verifier.tmp_tmpfs_bytes} B.",
        f"  Timeouts: readiness {to.readiness_seconds} s; revision deadline {to.revision_deadline_seconds} s; "
        f"stop grace {to.cancellation_grace_seconds} s.",
        "",
        "Signal behavior:",
        f"  The controller patchproof.interruption_test starts the runner as its own child. At {i.stage}",
        "  (target started and healthy; verifier created and through its inspection gate, not started) the",
        f"  child reports once over a private pipe ({i.channel}) and waits at most "
        f"{i.synchronization_wait_seconds} s.",
        f"  The controller checks the report exactly and sends {i.signals_sent} {i.signal} to that child only:",
        f"  never another PID or a process group, escalation: {i.escalation} (never SIGKILL), "
        f"automatic retry: {i.automatic_retry}.",
        f"  Report timeout {i.checkpoint_report_timeout_seconds} s; cleanup timeout "
        f"{i.cleanup_timeout_seconds} s. If the checkpoint is not reached, no signal is sent (fail closed).",
        "",
        "Cleanup: " + c.cleanup.replace("-", " ") + ";",
        "  then a complete after-inventory. Cleanup is COMPLETE only when both containers are confirmed gone.",
        "",
        "Expected outcome (EXPECTATIONS, not results):",
        f"  lifecycle {x.lifecycle}, evidence {x.evidence_status}, cleanup {x.cleanup_status}, verdict "
        f"{x.verdict} ({x.decision_rule}: required observations missing), lifecycle exit code "
        f"{x.lifecycle_exit_code}.",
        "",
        "Residual risks:",
        "  - The run starts the r1 PaperTrail target in Docker; the policy is configuration evidence, not",
        "    proof that the kernel enforced it.",
        "  - SIGKILL, a host shutdown or a crash of the child cannot clean up; the claim keeps the",
        "    authorization consumed and patchproof.recover_run removes what remains, by exact ID.",
        "  - If the child does not exit within the cleanup timeout, it is reported and NOT killed.",
        "  - The reviewer identity is a local assertion; this terminal check is a procedural control.",
        "  - Executing requires the separate controller and a typed confirmation, and separate Docker approval.",
        "",
        f"Evidence: <user data>/{d.evidence.destination}/ (private, 0600 files)",
        f"Store: {store_root}",
        "Supersedes: " + (f"{replaces.record.authorization_id} (unused; kept, and never executable)"
                          if replaces else "nothing"),
        "",
    ]
    return "\n".join(lines) + "\n"


def run_interruption_authorization(env: RunEnvironment, terminal: Terminal, *, now: Callable[[], datetime],
                                   new_run_id: Callable[[], str] = lambda: "run-" + secrets.token_hex(16)) -> int:
    """The interactive flow. Returns 0 only when a verified authorization was written."""
    written: Path | None = None
    try:
        run_id = new_run_id()
        run = assemble_interruption(env, run_id)
        store = provision_interruption_store(env.authorization_store)
        before = store.scan()
        replaces = store.executable()
        if os.path.lexists(env.evidence_root / run_id):
            raise ApprovalBlocked("evidence for this run ID already exists")
        terminal.write(render_interruption_plan(run, replaces, store.root))
        phrase = interruption_authorization_phrase(run.document)
        identity = _ask(terminal, "Your name (asserted, not verified): ")
        rationale = _ask_statement(terminal, "Rationale for authorizing this interruption test: ", phrase)
        scope = _ask_statement(terminal, "Authorization scope: ", phrase, differs_from=rationale)
        terminal.write(f"\nTo authorize, type exactly:  {phrase}\n")
        typed = terminal.read_line("Confirmation: ")
        if typed != phrase:
            raise ApprovalBlocked("the confirmation does not match the phrase")

        fresh = assemble_interruption(env, run_id)
        if fresh.document != run.document or fresh.sha256 != run.sha256:
            raise ApprovalBlocked("an input changed between review and confirmation")
        if store.scan() != before:
            raise ApprovalBlocked("the interruption-authorization store changed during the review")
        record = create_interruption_authorization(
            fresh.document, AuthorizationDecision(identity, rationale, scope, typed),
            supersedes=replaces.record if replaces else None, now=now())
        written = store.save(record)

        records, claims = store.scan()
        problems = []
        stored = records.get(record.authorization_id)
        if stored is None or stored.record != record:
            problems.append("the record read back differs from the record written")
        if any(records.get(k) != v for k, v in before[0].items()) or set(records) != set(before[0]) | {
                record.authorization_id} or claims != before[1]:
            problems.append("the earlier authorization history is not intact")
        if stat.S_IMODE(os.lstat(written).st_mode) != 0o400:
            problems.append("the record file is not read-only")
        current = store.executable()
        if current is None or current.record.authorization_id != record.authorization_id:
            problems.append("the new record is not the single unused authorization")
        if replaces is not None and not is_superseded(records, replaces.record.authorization_id):
            problems.append("the replaced authorization is not marked superseded")
        if assemble_interruption(env, run_id).document != record.plan:
            problems.append("the plan no longer matches the current inputs")
        if problems:
            terminal.write(f"\nFAILED VERIFICATION. A record was written at {written}, but it is NOT a verified "
                           f"authorization: {'; '.join(problems)}. It has not been deleted.\n")
            return 4
    except (ApprovalBlocked, PlanError, InterruptionAuthorizationError, OSError) as exc:
        if written:
            terminal.write(f"\nFAILED VERIFICATION: {exc}. A record was written at {written}, but it was not "
                           "verified. It has not been deleted.\n")
            return 4
        terminal.write(f"\nNOT AUTHORIZED: {exc}. Nothing was written.\n")
        return 2
    except (EOFError, KeyboardInterrupt):
        terminal.write("\nNOT AUTHORIZED: input ended. Nothing was written.\n")
        return 2
    terminal.write(f"\nINTERRUPTION TEST AUTHORIZED: {record.authorization_id}\n  run {record.plan.run_id}\n  plan "
                   f"{record.plan_sha256}\n  record {written}\n  Nothing has been executed. To execute, run "
                   "patchproof.interruption_test yourself, with separate Docker approval.\n")
    return 0


def main() -> int:
    try:
        require_interactive(sys.argv, os.environ)
    except NotInteractive as exc:
        sys.stderr.write(f"NOT AUTHORIZED: {exc}. Nothing was read or written.\n")
        return 2
    return run_interruption_authorization(interruption_environment(), _ConsoleTerminal(),
                                          now=lambda: datetime.now(UTC))


if __name__ == "__main__":
    raise SystemExit(main())
