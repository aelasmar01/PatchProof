"""Owner-operated run authorization for the first PaperTrail comparison (PP-008 integration utility).

This is NOT the general PP-009 CLI. It authorizes exactly one plan kind,
`papertrail-authz-r1-r3-one-pair-v1` (r1 versus r3, one pair, fixed fixture), and nothing
else. Run it yourself, in your own terminal, from the project directory:

    uv run --locked --offline python -I -m patchproof.run_authorization

**What it does:**
1. Refuses to run with any argument, any `PATCHPROOF*` environment variable, or unless
   standard input and output are a terminal in the foreground (the pack-approval gate).
2. Generates a fresh run ID and freezes it, then recomputes the complete plan from the real
   private artifacts (`runner.papertrail_plan.assemble_run`): the current pack approval and
   its history, the pack copy, the profile, both source snapshots, the fixture hash, the
   approved images and every runtime limit. It computes the canonical plan hash.
3. Shows every binding, the four-container sequence, the limits, the declared expectations
   and the limitations. If an unused authorization exists, it says that the new one
   supersedes it (the old one is kept, and can never execute).
4. Asks for the reviewer's asserted identity, a rationale and a scope (neither may contain
   the confirmation phrase), then the exact phrase `AUTHORIZE <run-id> <plan-sha256>`.
5. Recomputes the plan and re-reads the store immediately before writing. Any change aborts
   with nothing written.
6. Writes one immutable record, reads it back and verifies it. A failure after the write is
   reported as `FAILED VERIFICATION` (exit 4), never as success.

**Limits:** a procedural control, not proof of a human (the same OS account can allocate a
pseudo-terminal); the reviewer identity is a local assertion. The authorization does not
execute anything: execution is the separate command `patchproof.run_papertrail_once`.
"""

from __future__ import annotations

import os
import secrets
import stat
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from .core.run_authorizations import (
    AuthorizationDecision,
    RunAuthorizationError,
    RunAuthorizationStore,
    StoredAuthorization,
    authorization_phrase,
    create_authorization,
    is_superseded,
)
from .pack_approval import (
    ApprovalBlocked,
    NotInteractive,
    Terminal,
    _ask,
    _ask_statement,
    _ConsoleTerminal,
    require_interactive,
)
from .runner.papertrail_plan import AssembledRun, PlanError, RunEnvironment, assemble_run, papertrail_environment

# The standalone PP-008 utility's documented invocation (this module's docstring), shown only on that path.
UTILITY_COMMAND = "uv run --locked --offline python -I -m patchproof.run_papertrail_once"


def provision_authorization_store(root: Path) -> RunAuthorizationStore:
    """Create (once) and open the private store. Never follows or repairs anything."""
    parent = root.parent
    if not os.path.isabs(str(root)) or os.path.realpath(str(parent)) != str(parent):
        raise ApprovalBlocked("run-authorization store parent must be an absolute canonical directory")
    try:
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise ApprovalBlocked("run-authorization store parent is missing, not a directory, or a symlink") from exc
    try:
        pst = os.fstat(parent_fd)
        if pst.st_uid != os.getuid() or stat.S_IMODE(pst.st_mode) & 0o077:
            raise ApprovalBlocked("run-authorization store parent must be a private directory owned by you")
        try:
            os.mkdir(root.name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        st = os.stat(root.name, dir_fd=parent_fd, follow_symlinks=False)
    finally:
        os.close(parent_fd)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
        raise ApprovalBlocked("run-authorization store must be a directory owned by you with mode 0700")
    try:
        store = RunAuthorizationStore(root)
    except RunAuthorizationError as exc:
        raise ApprovalBlocked(f"run-authorization store: {exc}") from None
    if store.identity != (st.st_dev, st.st_ino):
        raise ApprovalBlocked("run-authorization store was replaced while it was being opened")
    return store


def render_plan(run: AssembledRun, replaces: StoredAuthorization | None, store_root: Path) -> str:
    d = run.document
    rt = d.runtime
    res, to = rt.resources, rt.timeouts
    lines = [
        "=" * 78,
        "RUN AUTHORIZATION REVIEW: this authorizes ONE execution of the plan below, once.",
        "=" * 78,
        "",
        f"Run ID            {d.run_id}   (generated now; never reused)",
        f"Plan SHA-256      {run.sha256}",
        f"Installation      {d.installation_id}",
        f"Pack approval     {d.pack_approval_id}   (current; APPROVED for the recomputed bindings)",
        f"Pack              {d.pack.pack_id} {d.pack.pack_version}",
        f"  manifest        {d.pack.manifest_sha256}",
        f"  tree            {d.pack.pack_tree_sha256}",
        f"  verifier plugin {d.pack.verifier_plugin_version}",
        f"Profile           {d.profile.profile_id} {d.profile.profile_version} {d.profile.profile_sha256}",
        f"Target image      {d.images.target_image_id}",
        f"Verifier image    {d.images.verifier_image_id}",
        "",
        "Sources (PP-005 snapshots, read-only, re-hashed now):",
    ]
    for side in ("baseline", "candidate"):
        s = getattr(d.sources, side)
        lines += [f"  {side:9} {s.tag}", f"            commit   {s.commit_id}", f"            tree     {s.tree_id}",
                  f"            snapshot {s.snapshot_name}", f"            manifest {s.source_manifest_sha256}",
                  f"            files    {s.source_tree_sha256}"]
    lines += [
        f"  inclusion  {d.source_inclusion.include}  {d.source_inclusion.inclusion_profile_sha256}",
        "",
        f"Fixture: {d.fixture.mode}; {d.fixture.fixture_contract} {d.fixture.fixture_sha256}; no seed; identical",
        "  synthetic data for both sides; a fresh target container per side. Owner decision D1: a v0.1",
        "  exception to seeded repetition (PP-019). One pair only.",
        "",
        "Expected collection, in order:",
        *(f"  {t.id:9} {t.nodeid}" for t in d.pack.expected_collection),
        "",
        "Execution (sequential; no automatic retry; at most 4 container creations):",
    ]
    for i, c in enumerate(d.containers.sequence, 1):
        network = "--network none" if c.role == "target" else "--network container:<that exact target ID>"
        mount = "source snapshot read-only at /app/source" if c.role == "target" else "pack read-only at /pack"
        lines.append(f"  {i}. {c.name}  ({network}; {mount})")
    lines += [
        "  Each container is inspected and must match the fixed policy before it starts: user 10001:10001,",
        "  read-only root, all capabilities dropped, no-new-privileges, default seccomp, private IPC and",
        "  cgroup namespaces, no published ports, no Docker socket, no host credentials, --pull=never.",
        f"  The verifier reaches the target only at {rt.target_address}. Both are removed by exact ID.",
        "  Baseline failure policy (D2): after a baseline execution-level failure the candidate is NOT started.",
        "",
        "Limits:",
        f"  target   {res.target.cpus} CPU, {res.target.memory_bytes} B memory, {res.target.pids} PIDs, "
        f"tmpfs {res.target.scratch_tmpfs_bytes} + {res.target.tmp_tmpfs_bytes} B",
        f"  verifier {res.verifier.cpus} CPU, {res.verifier.memory_bytes} B memory, {res.verifier.pids} PIDs, "
        f"tmpfs {res.verifier.scratch_tmpfs_bytes} + {res.verifier.tmp_tmpfs_bytes} B",
        f"  readiness {to.readiness_seconds} s; connect/read {to.request_connect_seconds}/{to.request_read_seconds} s;"
        f" per case {rt.case_timeout_seconds} s; revision deadline {to.revision_deadline_seconds} s;"
        f" stop grace {to.cancellation_grace_seconds} s",
        f"  result cap {rt.result_cap_bytes} B; logs {rt.logging.max_files} x {rt.logging.max_file_bytes} B;"
        f" response cap {rt.max_response_bytes} B",
        f"  evidence  <user data>/{d.evidence.destination}/ (private, 0600 files)",
        "",
        "Declared EXPECTATIONS, not results. The outcomes below are the expected results for this proposed run;",
        "they are not observations from this execution:",
    ]
    tests = {t.id: t for t in run.review.pack.manifest.tests}
    for t in d.pack.expected_collection:
        test = tests[t.id]
        lines.append(f"  {t.id:9} baseline {test.baseline_expected:19} candidate {test.candidate_expected}")
    lines += [
        "  Expected verdict if, and only if, every runtime gate passes: VERIFIED_FOR_CASES.",
        "",
        "Limitations:",
        "  - Inspection is configuration evidence, not proof that the kernel enforced the policy.",
        "  - One pair, fixed synthetic data: no statement about other data, endpoints or seeds.",
        "  - The reviewer identity is a local assertion; this terminal check is a procedural control.",
        "  - Executing is a separate step with its own typed confirmation; authorizing executes nothing.",
        "",
        f"Store: {store_root}",
        "Supersedes: " + (f"{replaces.record.authorization_id} (unused; kept, and never executable)"
                          if replaces else "nothing"),
        "",
    ]
    return "\n".join(lines) + "\n"


def run_authorization(env: RunEnvironment, terminal: Terminal, *, now: Callable[[], datetime],
                      new_run_id: Callable[[], str] = lambda: "run-" + secrets.token_hex(16),
                      expected_plan_sha256: str | None = None) -> int:
    """The interactive flow. Returns 0 only when a verified authorization was written.

    `expected_plan_sha256` (the `patchproof plan approve` path) binds the review to a plan the
    operator already inspected: if the plan recomputed now has any other hash, nothing is shown
    for confirmation and nothing is written.
    """
    written: Path | None = None
    try:
        run_id = new_run_id()
        run = assemble_run(env, run_id)
        if expected_plan_sha256 is not None and run.sha256 != expected_plan_sha256:
            raise ApprovalBlocked("the plan recomputed now from the current inputs differs from the selected plan; "
                                  "create and inspect a new plan")
        store = provision_authorization_store(env.authorization_store)
        before = store.scan()
        replaces = store.executable()
        terminal.write(render_plan(run, replaces, store.root))
        phrase = authorization_phrase(run.document)
        identity = _ask(terminal, "Your name (asserted, not verified): ")
        rationale = _ask_statement(terminal, "Rationale for authorizing this run: ", phrase)
        scope = _ask_statement(terminal, "Authorization scope: ", phrase, differs_from=rationale)
        terminal.write(f"\nTo authorize, type exactly:  {phrase}\n")
        typed = terminal.read_line("Confirmation: ")
        if typed != phrase:
            raise ApprovalBlocked("the confirmation does not match the phrase")

        fresh = assemble_run(env, run_id)
        if fresh.document != run.document or fresh.sha256 != run.sha256 or (
                expected_plan_sha256 is not None and fresh.sha256 != expected_plan_sha256):
            raise ApprovalBlocked("an input changed between review and confirmation")
        if store.scan() != before:
            raise ApprovalBlocked("the run-authorization store changed during the review")
        record = create_authorization(fresh.document, AuthorizationDecision(identity, rationale, scope, typed),
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
        if assemble_run(env, run_id).document != record.plan:
            problems.append("the plan no longer matches the current inputs")
        if problems:
            terminal.write(f"\nFAILED VERIFICATION. A record was written at {written}, but it is NOT a verified "
                           f"authorization: {'; '.join(problems)}. It has not been deleted.\n")
            return 4
    except (ApprovalBlocked, PlanError, RunAuthorizationError, OSError) as exc:
        if written:
            terminal.write(f"\nFAILED VERIFICATION: {exc}. A record was written at {written}, but it was not "
                           "verified. It has not been deleted.\n")
            return 4
        terminal.write(f"\nNOT AUTHORIZED: {exc}. Nothing was written.\n")
        return 2
    except (EOFError, KeyboardInterrupt):
        terminal.write("\nNOT AUTHORIZED: input ended. Nothing was written.\n")
        return 2
    terminal.write(f"\nRUN AUTHORIZED: {record.authorization_id}\n  run {record.plan.run_id}\n  plan "
                   f"{record.plan_sha256}\n  record {written}\n  Nothing has been executed.\n")
    if expected_plan_sha256 is None:  # the standalone PP-008 path; `plan approve` prints its own next step
        terminal.write(f"  To execute, run at your terminal, from the PatchProof checkout:  {UTILITY_COMMAND}\n")
    return 0


def main() -> int:
    try:
        require_interactive(sys.argv, os.environ)
    except NotInteractive as exc:
        sys.stderr.write(f"NOT AUTHORIZED: {exc}. Nothing was read or written.\n")
        return 2
    return run_authorization(papertrail_environment(), _ConsoleTerminal(), now=lambda: datetime.now(UTC))


if __name__ == "__main__":
    raise SystemExit(main())
