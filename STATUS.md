# STATUS

**Updated:** 2026-10-14 (**PP-009 `IN_PROGRESS`, READY_FOR_REVIEW** (local checkpoints `9bc4268` and a reporting-remediation commit; first live CLI run audited; acceptance gate prepared; not accepted): the v0.1 CLI
workflow (`project add`, `profile prepare`, `pack validate|approve`, `plan create|show|approve`, `run`, `report`)
delegating to the accepted PP-005 to PP-008 modules; safe verified JSON/Markdown reports; PROJECT_SPEC.md 13.2
exit codes; 8,869 Docker-free tests; final security review F1–F8 corrected. **PP-008 `ACCEPTED`** (2026-10-14) and **published**: `origin/main` =
`0d7d42d` (ordinary fast-forward of six commits). v0.1 release NOT YET ACCEPTED; PP-010 not started)
**Specification:** `PROJECT_SPEC.md` v1.0

---

## Current release and issue

**Release:** v0.1 — Useful CLI verification
**Issue:** PP-009 — CLI workflow and JSON/Markdown evidence. **State:** `IN_PROGRESS`, READY_FOR_REVIEW
(started 2026-10-14 on the owner's authorization; local checkpoint `9bc4268`; one owner-executed live CLI run,
independently audited; reporting findings U1–U7 corrected Docker-free; acceptance gate
`docs/evidence/pp-009-acceptance-gate.md`).
**Release state:** v0.1 is NOT YET ACCEPTED (PP-009 review and PP-010 remain).
**Previous issue:** PP-008, `ACCEPTED` 2026-10-14 and published (`d85b6db..0d7d42d`, six commits, ordinary
fast-forward, 2026-10-14).
**Safe to demonstrate with synthetic fixtures:** the v0.0 foundation, yes. PP-005 to PP-008 are
libraries, fixtures and owner-operated integration utilities with no general CLI workflow yet (PP-009).
PaperTrail was executed twice under owner authorization (one comparison, one deliberate interruption);
the claims are limited to those two audited runs.

## PP-009 CLI workflow and safe reports (2026-10-14); READY_FOR_REVIEW; design `docs/architecture/cli-workflow.md`

The owner authorized publishing PP-008 and implementing PP-009 only. PP-008 was published first: Git root and
HEAD `0d7d42d` verified, remote `aelasmar01/PatchProof` `main` at `d85b6db`, an ancestor; `git rev-list --count
origin/main..main` = **6** (all PP-008: `98b5cf8`, `e25f106`, `b2cdedd`, `48e2d8e`, `c33d580`, `0d7d42d`; the
earlier report's "five commits ahead" was a miscount, "all six" was right); the outgoing diff holds no ADR-010
file, approval record, private evidence or secret (the only path- and ID-shaped strings are synthetic test values
and generic documentation); one ordinary `git push origin main` (`d85b6db..0d7d42d`); remote verified.

| Area | Result |
|---|---|
| Commands | `project add\|list`, `profile prepare [--check-images]`, `pack validate\|approve`, `plan create\|show\|approve`, `run`, `report`; `doctor` and `doctor --probe-isolation` unchanged. No Docker option, mount, environment, shell command, reviewer name, `--yes` or `--force` anywhere (test-scanned) |
| Delegation | registration: `register_repository`; snapshots: `create_snapshot` after typed `SNAPSHOT <project>`; plans: `assemble_run`; approval: `run_approval`; authorization: `run_authorization(expected_plan_sha256)`; execution: `execute_once(expected_plan_sha256)`; reports: `verify_evidence`, `evaluate`, `collect_stream` |
| Scope | executable contract unchanged: PaperTrail r1 -> r3, one pair. Other revisions refused before a plan is written (widening needs owner review) |
| New records | `project-registration` 1.0 (schema, model, 1 valid + 7 invalid examples, parity); plans stored as the canonical accepted `RunPlanDocument`. Private 0700 stores, 0400 write-once records |
| Reports | verified before rendering (accepted verifier, strict records, engine recomputation, stream re-derivation, execution/observation cross-checks, engine trust rules); allowlisted fields and witness facts (marker withheld); entity/escape rendering; size, secret and path guards; 20 when evidence does not verify. Both accepted PP-008 runs report verified, read-only: `run-036553ef…` exit 0 (`VERIFIED_FOR_CASES`, V-09, journal v1), `run-6cee8893…` exit 20 (`INTERRUPTED`/`INCOMPLETE`/`INCONCLUSIVE`, V-05, `docker-ops-v2`) |
| Exit codes | PROJECT_SPEC.md 13.2, lifecycle first; JSON keeps the semantic verdict; the interruption controller's harness code is never a run code |
| PP-008 follow-ups | substantive rationale/scope for all owner commands (no placeholder, phrase or hash copy, scope != rationale); MANDATORY/DIAGNOSTIC preflight; exit codes through pipelines documented, `report --output`; both journal formats; witness/response-retention limits documented; live verifier-console check planned, not run |
| Changes to accepted modules | `pack_approval` (`require_terminal` split out, `statement_problem`), `run_authorization` (`expected_plan_sha256`), `run_papertrail_once` (`execute_once`/`OnceResult`, `expected_plan_sha256`; utility exit codes unchanged), `interruption_authorization` (scope differs from rationale). One test fixture rationale lengthened |
| Flaky PP-008 test fixed | `test_the_controller_sends_nothing_unless_the_report_is_exact` gave a real child 1 s to report; failed 1/15 here and 4/15 on the clean committed tree `0d7d42d`. The 1 s bound now applies only to the `silent` case it tests; 15/15 and 10/10 under 14 CPU-bound processes |

**Validation after the final security review (2026-10-14):**
- **Unit tests:** 8,869 passed, 0 failed (`tests/unit/test_cli_workflow.py`: 182). The earlier pass, before the
  review corrections, was 8,818.
- **Strict typing:** `mypy --strict src` clean, 81 files.
- **Ruff, documented gate** (`--select E,F,W,B,UP --line-length 120 src containers`): clean.
- **Ruff on every changed file:** clean, except the two pre-existing E501 in `tests/unit/test_schemas.py`
  (moved by the inserted lines, not changed).
- **Mutation check** (49 mutants: exit codes, report integrity, witness allowlist, escaping, plan/run
  authorization states, plan and claim guards, statement rules, terminal gate, stores, project semantics, CLI
  gates, preflight):
  - First pass: 40 killed, 9 survived. All 9 were closed by new tests and killed on re-run.
  - R11 was first a malformed mutant (it left one clause of the condition intact). Corrected, it was killed.
  - R5 was equivalent in effect: the marker was still withheld by the generic allowlist rule. The test now
    pins the explicit rule.
  - Every source and test file was byte-identical to the backup after each pass.
- **Final-review mutation check** (64 mutants: the 49 above, two adapted to the changed code, and 15 for
  F1–F7):
  - First pass: 60 killed, 4 survived: R11, the COMPLETE-run rule, the manifest/outcome status rule and the
    duplicate-directory refusal. The new COMPLETE-run check now overlapped R11's old killing test.
  - Each survivor was closed by a test that reaches only that rule: an evaluated interrupted run with its
    verdict files removed; a COMPLETE outcome without its established verdict; a relabelled manifest status;
    and a directory registered under a second identity.
  - One new test first failed on unmutated code (wrong precondition). It was corrected, and the survivors
    were re-run against a clean passing baseline: 4/4 killed, one failure each.
  - Every source file was byte-identical after every pass.

**Preservation:** both accepted PP-008 runs' evidence, the controller record, both approval records and both
authorization stores are byte-identical to the PP-008 audit snapshot. No real project, plan, approval,
authorization or run was created. No Docker command was run. ADR-010 is unchanged (`8f1fc685…`, `dd5cad81…`).
The home repository and the dropped stash object are untouched.

**Final security review (owner request, 2026-10-14).** The whole PP-009 diff was re-read against PROJECT_SPEC.md
7, 10, 12, 13, 15.2 and 16. Findings and corrections:

| # | Finding | Correction |
|---|---|---|
| F1 | `project add` checked only the object format of an existing record with the same derived ID; a conflicting identity (a different stored path) or the same directory under another path was not refused explicitly | refuses an ID whose stored path differs; refuses a directory already registered under another path (same device and inode). PP-005 already refuses case-variant and firmlinked spellings (checked on this host) |
| F2 | `run --json` printed the JSON after the interactive conversation on the same standard output, so stdout was not valid JSON | with `--json` the conversation goes to standard error, which must be the foreground terminal (same gate); stdout carries only the JSON document |
| F3 | the `run --json` document omitted cleanup, reconciliation, daemon continuity and stop reason, so a 0 exit with a failed cleanup was indistinguishable | the document carries these as separate fields and names the exit-code contract; cleanup never changes the code |
| F4 | `report` did not check that the established verdict (outcome) equals the recomputed engine verdict, or that the manifest status equals the outcome's evidence status | both are integrity checks; a `COMPLETE` run must have finalized evidence and an established verdict equal to the recomputed one |
| F5 | `--output` wrote the file in place (a failure could leave a partial file), raised a raw `OSError`, and chose the exit code by matching message text | atomic write: hidden temporary file, fsync, hard link (never overwrites, never follows a dangling symlink), temporary always removed; the directory is opened once and re-checked; typed `RunNotFound`/`OutputError` map to 2 |
| F6 | `profile prepare` showed "local image presence not checked" as a passing diagnostic, and the image check did not say it was a Docker interaction | an unperformed check renders `NOTE`, never `PASS`; the image check is labelled `DOCKER INTERACTION (read-only docker image inspect, never pulled)` |
| F7 | the PP-008 utility's operational exit codes (0 for any finalized clean run, `NOT_FIXED` included) could be mistaken for verdict codes | documented in the utility and in `docs/architecture/cli-workflow.md`; a test pins utility 0 with a `NOT_FIXED` record to CLI 10 |
| F8 | the 15.2 release-gate evidence this scope cannot produce, and what PP-010 would need, were not written down | documented, with a proposed separate work item (not started) |

New tests cover every finding, plus:
- every reachable verdict through `run` and `report` (0, 10, 11, 12) and every 13.2 code from synthetic
  engine outcomes (0, 10, 11, 12, 20, 21, 22);
- five bound-input drifts (approval, snapshot, image, runtime policy, fixture) after `plan create`, which
  block approval, and after `plan approve`, which block the run before any claim or Docker operation;
- a moved tag (same name, another commit) refused;
- Markdown fences, reference images, autolinks, comments, HTML, invalid UTF-8, huge values and hostile
  filenames;
- a static transitive-import check that no interruption controller or harness module is reachable from the CLI.

**Checkpoint and first live CLI run (2026-10-14/15).** Implementation checkpoint `9bc4268` (local, not
pushed). The owner registered `prj-fc41aa023d78b8c6`, created and approved `plan-89e25ceb…`, and ran
`run-dd93a78f930812bddca76e025eef5d31` through the CLI: `COMPLETE`, `FINALIZED`, `VERIFIED_FOR_CASES` (V-09),
16/16 trusted cells, 4 containers created and removed, inventory `CONSISTENT`. An independent read-only audit
(110 scripted checks, 0 failed) rebuilt the verdict input from raw records, reproduced the verdict in every
field, and confirmed the hardened verifier-console capture live (captured, bounded, hashed, separate from the
event channel, absent from the `docker-ops-v2` journal). `report` exits 0 (Markdown and JSON); the original
`run` shell status was not observed. Report-accuracy and documentation defects U1–U4 must be corrected before
acceptance (U5–U7 recommended; none is a security defect). Evidence
`docs/evidence/pp-009-first-live-cli-comparison.md`.

**Reporting remediation (owner-approved, Docker-free, 2026-10-14).** U1–U7 corrected:
- **U1:** pinned `uv run --locked --offline patchproof …` in every hint, the README and `cli-workflow.md`.
- **U2:** the authorization review no longer claims PaperTrail never ran.
- **U3:** the fixed-fixture claim label is derived from the validated plan.
- **U4:** fixed wording is literal after `safe_text.prose` proves it inert; values stay escaped.
- **U5:** "Evidence integrity checks passed", plus a separate "Fix verified for the selected cases".
- **U6:** a relative path is a usage error (2); policy refusals stay 21.
- **U7:** `plan create` says it stores an immutable plan.

**Also found and fixed during testing:**
- A value with leading spaces at the start of a list item could become an indented code block; `md` now
  makes a leading space an entity.
- The CLI `plan approve` path no longer points at the PP-008 utility.

**Unchanged:** the accepted modules are unchanged except `run_authorization`, where only display text
changed. No evidence was modified; the three recorded runs re-report with exit codes 0, 0 and 20.

**Validation after the remediation:**
- **Unit tests:** 8,986 Docker-free tests passed, 0 failed (8,985 before the last added test).
- **Typing and lint:** `mypy --strict` clean on 82 files; Ruff clean.
- **Mutation check:** 31 mutants; 30 killed on the first pass. U5b (an interrupted run that preserves a
  verified verdict) was closed by a new test and killed on re-run. Sources were byte-identical after every
  mutant.

**Owner gates still open:**
1. Formal review and acceptance of PP-009 (acceptance gate `docs/evidence/pp-009-acceptance-gate.md`).
2. Approval to push.
3. Widening the plan contract for r2/r4 comparisons, which the PP-010 exit gate needs: a security-contract
   decision.

## PP-008 gate C — collection and protocol validation COMPLETED with a documented C1b exception (2026-10-13); evidence `docs/evidence/pp-008-gate-c.md`

This is **not** three unconditional PASS results.

| Step | Recorded result | Owner adjudication |
|---|---|---|
| Gate C code changes | done, Docker-free tested: wrapper admits exactly `RunCreate` and `StartAttached` in fixed shapes; `STANDALONE` verifier role (`--network=none`); `runner/standalone.py`; r2 `APPROVED_RUN_IMAGES`; r1 rejected; SYNTHETIC self-test pack (never approvable) | — |
| C1a SYNTHETIC collection (pytest 9.0.3) | **PASS**: 11/11 in manifest order; exit 0; gate 59/59 | — |
| C1b SYNTHETIC event protocol | **FAIL**: an erroneous auxiliary assertion (it expected a passing test's captured fake event on stderr) | **ACCEPTED_FOR_C2_PROGRESSION**, recorded separately and bound to the original result hash; the FAIL is kept |
| Correction (no Docker) | the driver now checks the real invariant (no test text and no non-event object on the event channel); new unit test proves the fake write executes and never enters the channel; image and pack identities unchanged | — |
| C2 PaperTrail **collection only** | **PASS**: AUTH-001…004 and FUNC-001…004, node IDs and order exactly the PP-007 manifest; exit 0; 746 B; 1.88 s; gate 59/59; pack `529d3cd3…` verified before and after; no test executed | — |
| PaperTrail pack | **NOT_APPROVED**; a private unapproved collection record awaits owner review | — |
| PaperTrail test execution and live comparison | **NOT_AUTHORIZED** | — |

**Containers:** 3 of 3 used, one after the other; all removed by exact ID after an ownership
check. Counts are unchanged (14 images, 7 containers, 5 networks, 10 volumes), and no image,
container, volume or user network changed. **Correction:** Docker's built-in `bridge` network was
recreated (new ID) by a Docker Desktop idle VM restart between C1b and C2, shown in Docker
Desktop's log. It was not a PatchProof operation; the earlier "listing unchanged" claim was wrong.
The target image was never started.

**Observation G-C1** (pre-existing; the same under pytest 8.4.2): a `PytestAssertRewriteWarning`
for `patchproof_verifier.plugin`, because the package `__init__` imports it. The asserts still
execute; loading and outcomes are unaffected.

**Remaining PP-008 work:**
1. the owner's PaperTrail pack approval decision (PP-007 workflow);
2. the first live baseline/candidate comparison (separate approval; plan in `run-images.md` §7);
3. host pytest 9.0.3 remediation (delta prepared in `environment.lock.md`; not executed).

## PP-008 live interruption demonstration and independent audit (2026-10-14); READY_FOR_REVIEW; evidence `docs/evidence/pp-008-interruption-demonstration.md`

The owner authorized and ran one deliberately interrupted baseline run themselves, after a read-only
preflight: `run-6cee8893b1a0a58690be96bf23fa56b1`, authorization
`iau-92e4f72c5e2b9c251845c13f3e7dde6a`, plan `sha256:faa4245d…`. A read-only audit followed: no
Docker command, nothing re-executed, all private evidence byte-, mode-, mtime- and inode-identical
before and after; 159/159 checks.

| Item | Result |
|---|---|
| Integrity | accepted `verify_evidence`: child `CONSISTENT`/`INCOMPLETE`, controller `CONSISTENT`/`FINALIZED`; independent manifest re-check agrees; authorization and claim byte-identical to the store; consumed once, none executable; plan recomputes unchanged; approvals unchanged |
| Containers | 2 created, 1 started (target), 1 stop, 2 removals by full ID, both confirmed absent; verifier never started (Docker `created`, start time zero); no candidate; only owned IDs touched |
| Signal | checkpoint `baseline-target-ready` (target healthy, verifier created and inspected); one SIGTERM to the reported child PID, 25.0 s before send-by; observed once by the child |
| Recomputed | verdict input rebuilt from records equals the stored one; the accepted engine reproduces `verdict.json` exactly: `INCONCLUSIVE` V-05; lifecycle `INTERRUPTED`, evidence `INCOMPLETE`, cleanup `COMPLETE`, exit 20; controller `EXPECTED_OUTCOME_OBSERVED` (harness 0, separate). Shell exit codes not captured |
| Isolation | create argv equals policy; accepted gate re-run passes; independent field check agrees |
| Inventory | before = after by identity (14/7/5/10); seven unrelated stopped containers untouched; `bridge` ID changed since the preflight, attributed to a Docker Desktop idle VM stop at 04:04:44Z and restart by the run's first listing, from Docker Desktop's host log (outside the saved evidence) |
| Hardening | `docker-ops-v2` descriptors only; separate target stdout/stderr artifacts; verifier console `NOT_ATTEMPTED`; real `evaluated_at` |

**Findings:** (1) the authorization's rationale ("testing for implementation") and scope ("idk")
are not substantive. The record is kept as is. An unsigned draft post-run note and proposed
field validation are in the evidence report; nothing is implemented. (2) Docker 29.8.2 reports the
stop flag `--time` as deprecated (low; accepted-policy change needs owner review). (3) The
checkpoint has only monotonic times (info).
**Preflight correction:** the preflight's one failed check (empty-daemon assertion) was an auxiliary
diagnostic, stricter than the requirement. The script exited 1 (masked by `tee`). The overall
result should have read "PASS on every mandatory check; one auxiliary diagnostic FAILED". The
check stays FAILED.
**PP-008 assessment:** every requirement PASS on the two live runs.
**Owner decisions (2026-10-14):** ACCEPT PP-008, conditional on the final documentation review and
committed-tree validation. No signed post-run note is required; finding 1 is accepted as audit-quality
limitation L1, not a runtime-policy failure. Rationale and scope validation and fail-closed preflight
reporting (exit codes kept through pipelines; mandatory gates distinguished from diagnostics) are
carried forward to PP-009. The acceptance gate is `docs/evidence/pp-008-acceptance-gate.md`: 15
requirements, all PASS, limitations L1–L12.

## PP-008 final interruption security review and checkpoint (2026-10-13); READY_FOR_REVIEW

Owner-approved architecture and narrow subprocess exception; one local checkpoint commit
authorized conditionally. The live interruption demonstration is NOT authorized and was not
run: no Docker command, no PaperTrail execution, no real interruption authorization, no signal
to any Docker-backed process. PP-008 stays `IN_PROGRESS`.

| Item | Result |
|---|---|
| Subprocess exception | `tests/unit/test_docker_cli.py`: the rule is one predicate, `subprocess_allowed`; the PP-003 basename entries (`docker_cli.py`, `isolation_probe.py`) are unchanged; exact project paths `src/patchproof/git/command.py` and `src/patchproof/interruption_test.py`. Ten negative cases (same filename elsewhere, case variants, suffix tricks) are refused; a second test pins the exact set of importing modules (four). The controller: one `subprocess.Popen` call (AST check), no `shell`, no `os.kill`/`killpg`/`exec*`/`fork`/`spawn*`/`importlib`, no Docker client; argv is this interpreter, `-I -m patchproof.interruption_child`, a regex-validated run ID and a descriptor in 3..9999; **explicit environment** `HOME`, `PATH=/usr/bin:/bin`, `LC_ALL`/`LANG=C`, nothing inherited (new) |
| Candidate slot | The authorization, plan, verdict input and evidence carry no candidate identity (the schema rejects `sources.candidate`; unchanged). The engine's `RunPlan` slot is filled by a private adapter `interruption_plan._BaselineOnlyEnginePlan`: the slot is the very same baseline object (the precondition check re-verifies only the baseline), and asking for a candidate source or stream raises before anything is created, a fourth independent guard. A test checks that no stored byte (authorization store or evidence) names the candidate's tag, commit or tree and that the verdict input holds baseline executions only. The ordinary `run-authorization` schema and `RunPlan` are unchanged |
| Nonterminating child | No further signal and no Docker operation (the controller has none); the child's evidence is not read while it may still be written; cleanup is not confirmed; the controller record stays `INCOMPLETE`; the output lists the container IDs from the child's report and the `recover_run` step (recovery finds the containers by their fixed names and the child's ownership journal); the authorization stays consumed. Tested with a real local process that ignores SIGTERM (bounded wait scaled for the test) and with an exited child that left no evidence |
| Timing | Checkpoint only at pair 1 baseline, target started and `READY`, verifier created and through its inspection gate and not started; the controller checks stage, run ID, the PID of its own unreaped child, both IDs, readiness, verifier state and the send-by deadline; a wrong stage (new case), run, PID, state, extra key, late or malformed deadline sends nothing; with no signal the child aborts after 30 s and never starts the verifier or a candidate; report 600 s and cleanup 600 s bounds; no retry |
| Flaky test | `test_an_interrupt_stops_the_docker_client_process` failed under concurrent load with `FileNotFoundError` on the PID file: its fixed 1 s timer fired before the shell had started (a timing assumption, not the security property). It now interrupts only once the client has written its PID (bounded at 30 s); the property (the client process group is stopped) is unchanged. 25/25 passed on a quiet machine and 25/25 with 14 CPU-bound processes on 16 cores |
| D10 | No longer reported as equivalent. Through the accepted registry each owned ID has exactly one cleanup outcome (`record_created` refuses a duplicate ID), so the clause is redundant on every reachable path; but it also rejects an extra or duplicate failed outcome, and a new defence-in-depth test injecting one now kills D10 |

**Mutation (this round, sources and tests restored byte-identical afterwards, 118 files hashed):**
75 interruption mutations (the previous 58, D2 re-anchored to the renumbered guard comment, plus 17 new:
P20' checkpoint stage, E1-E4 child environment and argument validation, A1-A5 engine adapter, N1-N5
nonterminating child, AL1-AL2 allowlist broadening): **74 of 75 killed in the pass**; the survivor A3
("adapter accepts two pairs", masked because the base plan already caps pairs at the pack's declared one)
was closed by an added two-pair-manifest test and then killed on re-run, so all 75 now fail their tests;
D10 is killed (not claimed equivalent). The earlier 92-case suite re-run on this tree: 87 killed, 0
survived, 5 no longer apply to refactored code: N21, N24 and P27 re-expressed as N21', N24', P27' and all
three killed; P20 superseded by P20' (killed in the 75) and P24 by P3 (foreign PID, killed in the 75).

**Validation:** full Docker-free suite **8,667 passed, 0 failed** (twice, on a quiet machine, before and
after the A3 test); mypy strict clean (80 files); Ruff clean on all 23 new or modified Python files apart
from four long lines already present in the committed `test_docker_cli.py` and `test_schemas.py`; parity and
schema tests 585 passed. The live run still verifies `CONSISTENT`/`FINALIZED` (journal `v1`) and its plan
recomputes to `b3b0593a…`. Owner-facing output and a synthetic stored record were captured in temporary
directories and reviewed (record 0400 in a 0700 store; claim names the controller PID).

**Preservation:** the live run `run-036553ef…` evidence and the run-authorization store are byte-, mode-, mtime-
and inode-identical to the audit snapshot; both approval records unchanged (0400, `06f89515…`, `3b6354eb…`);
no interruption store or interruption evidence exists in the private data directory. ADR-010 diff hash
`8f1fc685…` and file hash `dd5cad81…` unchanged; stash list empty; the dropped stash object `885e7cce…` still
present (checked read-only with `git cat-file -t`); home-directory repository unchanged.

## PP-008 interruption authorization implementation (2026-10-13); READY_FOR_REVIEW

Owner-authorized implementation only. No Docker command, no real interruption authorization
(the private data directory has no `interruption-authorizations/` and no interruption
evidence), no PaperTrail execution, no signal to any Docker-backed run, no package change.
Not committed. PP-008 stays `IN_PROGRESS`; the live interruption demonstration needs a
separate execution approval.

| Item | Result |
|---|---|
| Result contract (owner correction) | Reviewed interruption: lifecycle `INTERRUPTED`, evidence `INCOMPLETE` (always), cleanup `COMPLETE` only when every created ID has a verified removal and is absent from a complete after-inventory, verdict `INCONCLUSIVE` by the accepted engine's `V-05`, lifecycle exit code 20 (13.2). `execute_revision` records a checkpoint signal as the revision's `interruption` and returns, so the engine evaluates the recorded execution; the PP-004 decision table is unchanged. A signal elsewhere: no verdict, `INCOMPLETE`, `INTERRUPTED`, 20. `VERIFIED_FOR_CASES`, or `BLOCKED` after start, is never recorded as the verdict. Harness exit codes (0/1/2/3) are separate from the child's lifecycle exit code. |
| Contract | `interruption-test-authorization` 1.0 (`schemas/interruption-test-authorization.schema.json`, `core/records/interruption.py`): baseline r1 only, no candidate source, `max_creations` 2, `max_started` 1, verifier `start: never`, one SIGTERM, `escalation: none`, 30 s synchronization wait, 600 s report and cleanup timeouts, no retry, expected outcome, private evidence path; reuses the run-authorization 1.0 definitions by reference, which are unchanged. 1 valid and 22 invalid examples; model/schema parity |
| Store | `core/interruption_authorizations.py`, `<user data>/interruption-authorizations/`: the accepted discipline (0700, owner, no symlinks, stable identity, `O_EXCL` 0400 records and claims, strict validation, history checks); the claim names the controller PID; supersession only of the single unused record; each store refuses the other's files |
| Commands | `patchproof.interruption_authorization` (owner; display, identity/rationale/scope, `AUTHORIZE INTERRUPTION TEST <run-id> <plan-sha256>`, revalidation, verified write); `patchproof.interruption_test` (owner controller; `INTERRUPT <run-id>`, claim, one fixed child, one SIGTERM after an exact report, bounded waits, never SIGKILL, never kills a lingering child); `patchproof.interruption_child` (only argv form `<run-id> <fd>`; refuses unless the claim names its parent) |
| Driver | `runner/interruption_run.py`: three independent candidate guards (stop after baseline, candidate gate, two-creation budget); revalidation of approval, authorization, claim and plan; evidence incl. `interruption.json` and the expected-outcome comparison; `recover_run` also lists consumed interruption-test authorizations |
| Evidence-hardening review | Confirmed: separate bounded, hashed, untrusted target stdout/stderr and verifier console; journal metadata only; synthetic tokens/markers never in metadata; journal failure refuses create/start but not cleanup; failed capture is `INCOMPLETE`; real `evaluated_at`; UTC/monotonic operation times; no event-grammar, pack, profile or image identity change. One residual noted: Docker inspect JSON (stored as `docker-ops-*.out`, not in the journal) includes the fixed health probe's `State.Health.Log` output |

**Security-test change for owner review:** `tests/unit/test_docker_cli.py`'s single-subprocess-module
guard now also admits exactly `src/patchproof/interruption_test.py`, which starts its one fixed child
argv with `subprocess.Popen` (no shell). The guard is otherwise unchanged.

**Late-signal guard (found in self-review):** the child's report carries `send_by_monotonic` (the end of
its 30 s wait minus a margin); the controller refuses to signal after it (`REPORT_TOO_LATE`), so a stalled
controller can never interrupt the cleanup that follows a fail-closed abort.

**Validation:** full Docker-free suite **8,647 passed, 0 failed** on a quiet machine (an earlier run
made while other suites ran concurrently had one load-dependent failure,
`test_an_interrupt_stops_the_docker_client_process`, a 1-second timer; it passed 3 of 3 alone and in the
final run; and one real failure, the single-subprocess-module guard, resolved by the allowlist entry
above). mypy strict clean (80 files); Ruff clean on all 23 new or modified Python files apart from four
long lines already present in the committed `test_docker_cli.py` and `test_schemas.py`. Schema/model
parity, valid and invalid examples, evidence-consistency, signal (real local processes, including a real
controller and child end to end) and cleanup tests included. **Mutation:** interruption and authorization
controls 57 of 58 killed in the final pass (the first pass left D12 "revalidation skips the claim" and T5
"undelivered signal unchecked" alive, both closed by added tests; D10 "cleanup failures ignored" was
reported as equivalent; superseded by the final review above, where a new test kills it); the 92 earlier PP-008 mutations re-run on the changed code: 87 killed, 3 re-expressed for
refactored code and killed (N21', N24', P27'), 2 superseded by this pass (P20, P24: checkpoint state and
foreign PID); sources verified byte-identical to the pre-mutation backup after every pass. The live run
`run-036553ef…` is still `CONSISTENT`/`FINALIZED` (journal `v1`) and its plan recomputes to `b3b0593a…`
(the current approval `APPROVED`); its evidence and the run-authorization store are byte-, mode-, mtime-
and inode-identical to the audit snapshot; both approval records unchanged (0400, `06f89515…`,
`3b6354eb…`). Not executed: Docker, PaperTrail, any real authorization, any live interruption.

**Earlier process incident (recorded as the owner asked):** the stray `git stash` in the previous step was
popped at once with no conflicts; ADR-010's contents were restored; its diff hash (`8f1fc685…`) and file
hash (`dd5cad81…`) are unchanged (re-checked after this work); working-tree modification times changed;
the dropped stash object (`885e7cce…`) remains in the object database and was not deleted, pruned,
expired, recovered or rewritten. No stash, reset, clean or checkout was used in this step; the
home-directory repository is unchanged.

**Proposed checkpoint commit scope (not committed):** everything in `git status` except the owner's
`CLAUDE.md`, `PROJECT_SPEC.md`, `docs/threat-model.md` and `docs/adr/ADR-010-agent-permission-mode.md`.

**Next (each needs owner approval):** review this change set (including the subprocess-guard entry);
a checkpoint commit; then, separately, the owner creates the real interruption-test authorization and
approves Docker for the one live demonstration.

## PP-008 evidence hardening and interruption-test preparation (2026-10-13); READY_FOR_REVIEW

Owner-authorized, Docker-free. No Docker command, no comparison, no new or reused run
authorization, no signal to any live run. The first live run's private evidence and the
authorization store were re-compared after the work: byte-, mode-, mtime- and
inode-identical. The corrected `verify_evidence` still reports that run
`CONSISTENT`/`FINALIZED` (journal format `v1`), and its frozen plan still recomputes to
`b3b0593a…`, so the pack, profile, plugin, images and policy identities are unchanged. Both
approval records are unchanged (0400). The verdict engine, approved pack, verifier plugin,
profile and r2 images were not modified. Not committed. PP-008 stays `IN_PROGRESS`.

| Item | Change (future runs only) |
|---|---|
| Target logs | `Logs` reads the target's stdout and stderr with separate 5 MiB caps into `untrusted-target-stdout-<tag>.log` / `untrusted-target-stderr-<tag>.log`; `revision-<tag>.json` records capture status, size, hash, truncation; a failed read is `CAPTURE_FAILED` (no file) and makes the evidence `INCOMPLETE` |
| Verifier console | `StartAttached` caps stderr at 1 MiB (bound checked, ≤ 4 MiB) into `untrusted-verifier-console-<tag>.log`; the event channel is unchanged |
| Operation journal | format `docker-ops-v2`: metadata only (UTC start and end, monotonic and client durations, exit or `TIMED_OUT`, `interrupted` lines with `finished_at: null`; per stream class, bytes, SHA-256, cap, truncation, storage, artifact); other Docker output in `docker-ops-<seq>-<stream>.out` (96 MiB budget); journal or artifact write failures are collected, never raised; after a journal failure, create/start/attach are refused while inspect/stop/remove continue; `verify_evidence` checks v2 keys and artifact hashes; v1 lines are reported by format, not as problems |
| Timestamps | `evaluated_at` read when the engine evaluates; `outcome.json.timestamps` adds execution start and finish and their `order`; a backward clock is reported, never corrected |
| Recovery | `recover_run` finalizes `INCOMPLETE` if any of its own journal writes failed |
| Interruption test (proposed) | `runner/interruption_point.py`: one checkpoint (`baseline-target-ready`) reporting over an inherited pipe with a bounded wait and fail-closed abort, and a controller that sends one SIGTERM only to its own unreaped child after an exact report; reachable only through an optional `checkpoint` argument no production caller passes. The current authorization contract cannot express this test (tested); a separate versioned contract is proposed in `docs/architecture/verification-runs.md` |
| Response retention | unchanged (no raw responses); documented in `verification-runs.md` |

**Validation:** full Docker-free suite 8,499 passed (8,463 before plus 36 new in `tests/unit/test_run_evidence_hardening.py`); mypy strict clean (73 files); Ruff clean on every changed file. Mutation: 92 of 92 killed (the 60 earlier PP-008 mutations re-run against the changed code plus 32 new ones for routing, caps, capture failure, journal keys, timestamps, the output budget, journal-failure handling and the interruption point and controller); the first pass left 3 survivors (P23 standard-stream refusal, P30 recovery failure reporting, P32 evaluated_at mismatch), closed by three added tests, not by weakening a check; sources verified byte-identical to the pre-mutation backup after both passes. Not executed: Docker, PaperTrail, any live interruption, the proposed authorization contract.

**Process note:** during the work, a stray `git stash` was run by mistake and immediately
popped. The owner's ADR-010 diff hash (`8f1fc685…`), the ADR file hash (`dd5cad81…`) and the
home-directory repository stats were re-checked and are unchanged; file modification times of
the working-tree files were refreshed by the stash and pop, and one dropped stash object
remains unreferenced in the object store.

**Next (each needs owner approval):** review this change set; approve or amend the proposed
interruption-test authorization contract; then its implementation (schema, store, owner
command, controller driver), a new single-use interruption authorization, and a separate
Docker approval for the live demonstration.

## PP-008 first live comparison — independent read-only evidence review (2026-10-13); READY_FOR_REVIEW

The owner authorized and executed the first live comparison personally:
`run-036553ef7b032f59955cc4a790409931`, authorization `rau-ed8bb6944af5d7681d52a9947199a37e`
(consumed), plan `sha256:b3b0593a…e47e`. This review was read-only: no Docker command, no
re-execution, raw evidence and the authorization store unchanged (bytes, modes, mtimes,
inodes compared before and after). Sanitized report: `docs/evidence/pp-008-first-live-comparison.md`.

| Item | Result |
|---|---|
| Evidence integrity | accepted `verify_evidence` CONSISTENT/FINALIZED; 164 independent checks, 0 failed (scratch script, not committed) |
| Identities | r1 `68b2bc0e…` and r3 `2fb6d093…`, manifests `1444803c…`/`42d82e22…`, pack tree `529d3cd3…`, approval `apr-f4b493f9…`, profile `a1c130c2…`, images `98548ec4…`/`e880f609…`; the plan recomputed now equals the frozen plan |
| Observations | baseline AUTH-001 and AUTH-003 `VIOLATION_CONFIRMED` (this document's marker in the body; caller not permitted), AUTH-002/004 `SECURE` (401); candidate all `SECURE` (404/401); FUNC-001–004 `PASS` on both sides (reviewed assertions; bodies not retained). 16/16 equal the PP-006 declared table, statuses and markers included |
| Transport | both streams COMPLETE, 31 contiguous events, exact ordered collection, session_end agrees, 8,921 and 8,900 bytes of a 10 MiB cap; verifier exits 1 and 0 agree with the failed-report counts |
| Recomputed verdict | rebuilt input equals the stored one; the engine reproduces the stored `verdict.json` exactly: `VERIFIED_FOR_CASES`, V-09, `ALL_CONDITIONS_SATISFIED`, 16/16 trusted cells, no flags |
| Containers | 4 created, sequential; pre-start gate re-run on saved inspects passes for all four; `--network=none` targets, verifiers joined their own target; read-only separate mounts; limits and log policy as the profile; each removed by exact ID and confirmed absent; inventory identical before and after; continuity `NO_CHANGE_OBSERVED` (not proof) |
| Timeline | readiness 1.38 s and 1.33 s; verifiers 1.21 s (exit 1) and 1.03 s (exit 0); about 14 s claim to manifest; cleanup 0.56 s and 0.63 s; shell exit code not captured |
| Findings (not fixed) | target standard error lands inline in the operation journal and the target-log files are empty; verifier console output with synthetic tokens inline in the journal; `evaluated_at` is the start time; no wall-clock times per operation; witnesses are attested facts without retained bodies |
| PP-008 criteria | source/test separation, successful run, labels and first dynamic reproduction met live; **a deliberately interrupted live run is not yet demonstrated** (smallest proposal in the report; not executed) |

## PP-008 final run-authorization security review (2026-10-13) — READY_FOR_REVIEW; local checkpoint

Owner-authorized final review and one local checkpoint commit. Still no real run
authorization, no claim, no run or recovery evidence, no Docker operation, PaperTrail not
executed. Not pushed, not tagged. PP-008 stays `IN_PROGRESS`.

**Findings and fixes:**
1. **SIGTERM/SIGHUP skipped all cleanup** (Python's default action ends the process at once).
   `runner/interrupts.py` now turns SIGINT, SIGTERM and SIGHUP into one interrupt; the revision
   in progress is cleaned up by exact ID, evidence is finalized `INCOMPLETE`/`INTERRUPTED`, and
   a repeated signal is ignored so it cannot abort cleanup. `run_bounded` now stops the Docker
   client (started in its own session, so Ctrl-C never reached it) on any interrupt.
2. **Hard kill had no recovery path.** SIGKILL, a host shutdown or a crash runs nothing: the
   containers of the revision in progress remain. New limited `patchproof.recover_run`
   (`runner/run_recovery.py`): read-only assessment by exact ID against the run's journal,
   any ambiguity refuses everything, a typed `CLEANUP <run-id>`, a repeated assessment that
   must match, exact-ID removal through the accepted `remove_owned`, an allowlist that cannot
   create or start, separate `evidence/recoveries/<run-id>/rec-<id>/` evidence. Not PP-014.
3. **The reusable contract refused a revision against itself**, which spec 17.2 requires. The
   rule moved to the driver: `check_first_run_scope` pins r1 `68b2bc0e…` against r3 `2fb6d093…`
   (tag, commit, tree) from module constants, in plan assembly and on the stored plan.
4. **A failed evidence write aborted the comparison and lost the verdict** (including a trusted
   candidate violation). It is now recorded, stops the run before the candidate, and the
   engine's evaluation is kept as `engine_verdict` while `verdict` is only set with finalized
   evidence, so incomplete evidence never establishes `VERIFIED_FOR_CASES`.
5. **A suspected Docker restart exited 0.** Any inventory change, including an explained
   built-in network recreation, now needs attention (exit 5); `daemon_continuity` is
   `BROKEN_SUSPECTED`, `UNKNOWN` or `NO_CHANGE_OBSERVED`, never "proven".
6. **States were conflated.** `outcome.json` now separates evidence status, lifecycle
   (`COMPLETE`/`BLOCKED`/`CANCELED`/`INTERRUPTED`) and cleanup status. `FINALIZED` also requires
   both inventories complete. An incomplete before-inventory now yields the engine's
   pre-execution `BLOCKED` with no container.
7. **Smaller:** per-file (64 MiB) and journal-line (1 MiB) bounds; `verify_evidence` re-hashes
   against the manifest and recomputes the verdict; the fixed-fixture limitation is restated
   in `outcome.json`; the D2 engine dependency is one boundary function pinned to the public
   engine by a contract test. The verdict engine is unchanged (`git diff` empty).

| Item | Result |
|---|---|
| Tests | 8463 passed, Docker-free (was 8396: +37 `test_authorized_run.py` (106), +5 `test_run_authorization_store.py` (31), +25 new `test_run_recovery.py`); includes a real SIGKILL of a child driver and real SIGINT/SIGTERM/SIGHUP delivery |
| mypy strict | clean, 72 files |
| Ruff | changed files clean except 2 pre-existing E501 in `test_schemas.py`; repository total unchanged at 11 |
| Mutation check | 60 mutants (scratch harness, not committed): the 30 earlier ones re-applied to the changed code plus 30 for the review's controls (signals, client stop, evidence states and bounds, verification, continuity exit, first-run scope, recovery ambiguity, confirmation, re-assessment, allowlist, separate evidence). **60/60 killed**; sources restored byte-identical |
| Durable repository (D3) | re-verified read-only: byte-identical to the scratch generation; four tags, commits, trees and tag objects match; `git fsck --strict --full` clean; both snapshot manifests re-derive byte-for-byte (`1444803c…`, `42d82e22…`); unchanged by verification |
| Approval chain | current `apr-f4b493f9…` (`06f89515…`), superseded `apr-f30bd943…` (`3b6354eb…`); both 0400, unchanged |
| Real stores | no `run-authorizations/`, no `evidence/runs/`, no `evidence/recoveries/` |

**Limitations that remain:** SIGKILL, power loss and crashes leave containers until the owner
runs `recover_run`; unchanged network IDs do not prove daemon continuity; the recovery
command itself needs Docker approval (even its status check runs `docker inspect`); terminal
gating is procedural, not proof of a human; the `source-snapshots/` mount has never been used
by Docker Desktop.

## PP-008 single-use run authorization and evidence capture — implemented Docker-free (2026-10-13); READY_FOR_REVIEW

Owner-authorized Docker-free implementation, narrowly scoped to the first synthetic
PaperTrail comparison (r1 against r3). No real run authorization, no claim, no evidence
directory, no Docker operation, PaperTrail not executed or imported. Not committed.

**Owner decisions applied:**
- **D1, fixed fixture:** `synthetic-documents-v1` `sha256:2cbcf118…9eda`, one pair, no seed, identical
  data for both sides, a fresh target per side. A v0.1 exception; more than one pair is refused. Seed
  variation stays PP-019.
- **D2, baseline stop:** after a baseline execution-level failure the candidate is not started. The
  run ends `interrupted`, so it is `INCONCLUSIVE`, never `VERIFIED_FOR_CASES`.
- **D3, durable reference repository:** generated with the accepted PP-006 generator at
  `<user data>/reference-repos/papertrail-authz` (parent `reference-repos/`, 0700). Byte-identical to
  the scratch generation; all four tags, commits, trees and tag objects equal the PP-006 record;
  `git fsck --strict --full` clean; unchanged by verification. Both existing snapshots re-verified,
  and their manifests re-derived from the durable repository byte-for-byte (`1444803c…`, `42d82e22…`).
  The scratch repository was not modified.

| Item | Result |
|---|---|
| Record | `schemas/run-authorization.schema.json` 1.0 and `core/records/authorization.py`, in parity with each other (corpus and sampled mutations); 1 valid and 12 invalid examples |
| Store and claim | `core/run_authorizations.py`; `<user data>/run-authorizations/` (0700, not created). `O_EXCL` 0400 records; a run ID is never reused; an unused authorization may be superseded, a claimed one never; the claim is an `O_EXCL` fsynced file, never removed; an unreadable claim counts as consumed |
| Plan | `runner/papertrail_plan.py`: recomputed from the real artifacts; plan hash over canonical JSON |
| Owner commands | `patchproof.run_authorization` (authorize once) and `patchproof.run_papertrail_once` (execute once); interactive foreground terminal only |
| Driver | `runner/authorized_run.py`: per-revision re-validation, D2, Docker-continuity check before the candidate; `comparison.py` gained three optional hooks with no-effect defaults; verdict engine unchanged |
| Evidence | `runner/run_evidence.py`: `<user data>/evidence/runs/<run-id>/`, exclusive, write-once 0600 files, journals, manifest written last |
| Inventory | images, containers, networks, volumes compared by identity; built-in network recreation explained as daemon-managed and flagged; everything else needs attention |
| Tests | 8396 passed (Docker-free; was 8272: +69 `test_authorized_run.py`, +26 `test_run_authorization_store.py`, +29 schema and parity cases for the new contract); mypy strict clean (69 files); Ruff clean on changed files (11 pre-existing E501 elsewhere) |
| Mutation check | 30 guards (scratch harness, not committed): first pass 18 killed, 12 survived; the survivors were covered by overlapping checks or unreached paths, and targeted tests were added; one mutant was corrected (M22b). Final: **30/30 killed** |
| DRAFT | private `evidence/pp-008-live-plan/run-authorization-DRAFT.json`, assembled from the real artifacts under run ID `run-c82590b4f16239641cea77a2031e2035`, plan `sha256:dd13c0bc…1ece4`; labeled DRAFT, not a record, not stored |

**Owner commands (the owner runs them; never run on the owner's behalf):**
- `cd ~/Desktop/PatchProof && uv run --locked --offline python -I -m patchproof.run_authorization`
- after a separate Docker execution approval:
  `cd ~/Desktop/PatchProof && uv run --locked --offline python -I -m patchproof.run_papertrail_once`

## PP-008 first live comparison — PLANNING ONLY (2026-10-13); blocked on run authorization

Owner-authorized planning. No Docker operation, no container, PaperTrail not executed or
imported, no approval or authorization record written, no repository code changed.

| Item | Result |
|---|---|
| Pack approval | current `apr-f4b493f9be53db6b0eff607f79508a65` (supersedes `apr-f30bd943…`; original byte-identical, SHA-256 `3b6354eb…8735`); exactly one current; `check_approval` APPROVED against recomputed bindings; original `APPROVAL_STALE (superseded)`; both records `0400` and schema-valid |
| Reference repository | the PP-006 generation in the session scratchpad (`pp006/final-a`, byte-identical to three other generations); registered through PP-005; all four tags resolve to the accepted commits; no worktree files; repository content, modes, mtimes and inodes unchanged by snapshotting |
| Source snapshots (PP-005, private `source-snapshots/`, `0700`) | baseline r1 `68b2bc0e…` tree `f4a27893…`, manifest `sha256:1444803c19d7c826f88243850f44c0590008d5c828f755cd43cf48c997b1a3f7`; candidate r3 `2fb6d093…` tree `eb22f1bf…`, manifest `sha256:42d82e22e879969b96b737e42f89b1d7ea65c28e628ec09141e4b33f06604d4f`; scope exactly `fixtures/synthetic`, `papertrail`; inclusion profile `sha256:2224cc8e…`; 5 files each, `README.md` excluded `OUTSIDE_SOURCE_SCOPE`; only `papertrail/authz.py` differs; `uncommitted_changes_included: false` |
| One-pair plan (proposed, private) | built from the accepted runner code; all four pre-execution preconditions PASSED Docker-free; 4 containers, sequential, no retry |
| Blocker | **No run-authorization record or mechanism exists** (spec 7.5; deferred to PP-009). No committed live-execution driver or evidence-bundle writer exists either. A minimal proposal awaits the owner |
| Tests | 8272 passed (Docker-free); mypy strict clean; Ruff unchanged (11 pre-existing E501) |

## PP-008 approval statement correction by supersession (2026-10-13) — workflow ready, owner action pending

The owner ran `patchproof.pack_approval` personally. It wrote
`apr-f30bd94302802ad9aa8b394be066d1fa` and reported PACK APPROVED. The phrase was typed into the
rationale and scope fields. This is an audit-quality deficiency of the reviewer's statement, not
of the pack identity. Owner-authorized: a narrowly scoped, owner-operated supersession workflow.
No replacement was created; the original was not modified; no Docker operation; PaperTrail was not run. Recorded in an owner-authorized local checkpoint commit (not pushed, not tagged, not acceptance).

| Item | Result |
|---|---|
| Original record, read through the PP-007 `ApprovalStore` (read-only) | exists; the only record; current (supersedes nothing); valid against `approval-record` (schema and model); file name equals its approval ID; mode `0400`, 2056 B, SHA-256 `3b6354eb59d097224c4d958064c0c11907a7c4982e2298d2ed01322f9b048735`; `check_approval` **APPROVED** against freshly recomputed bindings (no stale field); `rationale` and `scope` are each exactly `APPROVE papertrail-document-access 1.0.0 a4c4ce48d5d2`. There is no cryptographic signature in a PP-007 record; integrity is the immutable file, its ID and the binding check. |
| Supersession workflow | `run_supersession` in `src/patchproof/pack_approval.py`; entry point `python -I -m patchproof.pack_approval_supersede`. Reuses `ApprovalStore`, `ReviewDecision`, `create_approval`, `check_approval` and `supersedes`; no new schema or store. Same interactive gate as the approval command. Refuses: no store (never created), no current approval, any stale binding, a phrase mismatch, a store or binding change before the write. Shows the current record, its rationale and scope, and the full review before any prompt. After the write: every earlier record byte-for-byte and mode-identical, history = earlier history + one record, new record read back and `0400`, new record `APPROVED`, original `APPROVAL_STALE (superseded)`. Exit 0 verified; 2 nothing written; 4 written but not verified (reported, never deleted). |
| Phrase refusal | Both commands refuse a rationale or scope that contains the confirmation phrase (case and spacing ignored). This also prevents the incident on a first approval. |
| Tests | Full suite 8272 passed (Docker-free; +24 supersession tests in `test_pack_approval_supersede.py`); mypy strict clean (62 files); Ruff clean on changed files. Mutation check of 9 guards (scratch, not committed): 9 killed. One gap found by the check (the pre-write binding re-check was unreachable with a pinned target) was closed with a dedicated test. |

**Owner command (the owner runs it; never run on the owner's behalf):**
`cd ~/Desktop/PatchProof && uv run --locked --offline python -I -m patchproof.pack_approval_supersede`

## PP-008 pre-approval checkpoint (2026-10-13)

Owner-authorized: one local checkpoint commit of the reviewed PP-008 implementation, before
the owner's own pack approval. **Not** issue acceptance, pack approval or run permission.
Nothing was pushed or tagged; no Docker operation; PaperTrail was not run.

| Item | Result |
|---|---|
| Final source review | One defect fixed: an error *after* the record write returned exit 2 ("nothing written") although a record existed. It now returns 4 and reports `FAILED VERIFICATION`, never approval. Two new tests cover a failed final `check_approval` and an error during post-write revalidation. No other change. |
| Approval identity, recomputed read-only | pack `papertrail-document-access` 1.0.0; manifest `sha256:a4c4ce48d5d2aaa512c746e7ba90d06fd76e879de3a3dea5280079531a8804c8` (equal to the raw `pack.json` SHA-256); tree `sha256:529d3cd3ebf307586dcecef43a0df8ab9b55296849182f8f43c4ad7d6a8a6c31`; fixture `sha256:2cbcf118fddb2cd4e38a9af5e8786911e8f85e292e637102799fd60513129eda` (pack copy and reference template copy); profile `sha256:a1c130c2f8b90c2ada2001ef3bc336b0b8ec29886fd92635dbf5928eb8036835` with no runtime difference; verifier `sha256:e880f609a7c4d292441e22d1d0d5d7c876697dd4e1e657a668b2b6266969fecc`; plugin 0.1.0; C2 `stdout.bin` and `result.json` equal their pinned hashes, and the collection is the manifest's eight node IDs in order. The pack and the reference are unchanged since `d85b6db`. |
| Approval command | `uv run --locked --offline python -I -m patchproof.pack_approval`. Verified under a pseudo-terminal with a probe (not the approval flow): `uv run` keeps Python in its foreground process group, so the interactive gate passes, and no `PATCHPROOF*` variable is set. `uv sync --locked --offline --dry-run`: no change. |
| Tests | 8248 passed (Docker-free; +2 approval-entry tests); mypy strict clean (61 files); Ruff: no new finding in the committed files (2 pre-existing E501 in `test_docker_cli.py`; 11 in the whole repository) |
| Approval state | No approval record exists; the store directory does not exist. |

## PP-008 profile and approval-infrastructure blockers — resolved, awaiting owner review (2026-10-13)

Owner-authorized within PP-008. This does **not** approve the pack or the profile, create an
approval record, authorize a live comparison or begin PP-009. No Docker operation, no
PaperTrail execution, no collection, no image build or pull, no approval record.

| Item | Result |
|---|---|
| Versioned profile | `profiles/papertrail-reference-1.0.0.json` (contract 1.1; r2 images; `papertrail.app:app`; `synthetic-documents-v1`; `none-shared-loopback-v1`; scope `papertrail`, `fixtures/synthetic`). The readiness-review draft was reused unchanged. Canonical hash **re-verified** `sha256:a1c130c2f8b90c2ada2001ef3bc336b0b8ec29886fd92635dbf5928eb8036835` (unchanged: every value already equalled the enforced runtime). File SHA-256 `2abf6ab6…1554` (evidence only). **PROPOSED**, not owner-approved. |
| Loader | `runner/profiles.load_profile`: canonical path in `profiles/`, no symlinks or special files, ≤ 16 KiB, strict JSON + model + PP-003 check, name = ID-version, no placeholders, only approved r2 images in their roles, hash must equal the expected binding; never writes |
| Profile/runtime consistency | `run_plan.FIXED_PROFILE_RUNTIME`: resources, readiness, connect/read, revision deadline, cancellation grace, logging, result cap and network policy must **equal** the enforced values (stricter values are refused too). `RunPlan` refuses an inconsistent profile. G-P1 (logging) and G-P2 (cancellation grace) are closed by equality; G-P3 (store and loader) is closed. `limits_from_profile` no longer clamps the deadline silently; above the ceiling is refused. Each source snapshot must record exactly the profile's `source_scope.include` (`source_identity`). |
| Approval entry point | `src/patchproof/pack_approval.py`, reusing PP-007 `BindingInputs`, `create_approval`, `ApprovalStore`, `check_approval`. Interactive foreground terminal only; no arguments, no `PATCHPROOF*` variables, no piped input. Bindings recomputed from the pack, profile, pinned C2 evidence (`stdout.bin` `c9e54895…`, `result.json` `9b721cda…`), r2 verifier image and plugin source. Full review screen; recompute and store re-read before writing; read-back verification after. A procedural control, not proof of a human. |
| Approval store | `<platformdirs user data>/PatchProof/approvals/` (macOS `~/Library/Application Support/PatchProof/approvals/`), `mkdir(0700)` via the parent descriptor; never followed, never repaired. **Not yet created**: the owner's first run creates it. |
| Tests | 8246 passed at the time (Docker-free; +47 profile, +35 approval-entry tests; one run-execution test now changes `profile_version` to make its approval stale, and asserts that the earlier readiness change is refused at plan construction); mypy strict clean (61 files); Ruff on changed files clean (11 pre-existing E501 elsewhere) |
| Evidence handling | C1a, C1b, C2 and the C1b adjudication unchanged. Inventory correction kept; future reconciliation compares resource identities and accounts for daemon restarts. The old `0644` ledger is kept as-is; future private ledgers and raw evidence use `0600`. |

**Owner command (the owner runs it; never run on the owner's behalf):**
`cd ~/Desktop/PatchProof && uv run --locked --offline python -I -m patchproof.pack_approval`

## PP-008 PaperTrail pack approval readiness review (2026-10-13) — approval was BLOCKED (since resolved, see above)

This was a read-only review. No approval record, no Docker operation, and no pytest run. The
full packet is private: `APPROVAL-REVIEW-DRAFT.md`, plus the proposed profile and draft
bindings, in a 0700 directory outside the repository.

| Item | Result |
|---|---|
| C2 evidence integrity | **consistent**: record, standard output, result, create argv, journal and ledger agree; 8/8 in order; exit 0; 1.88 s; 746/990 B; no test executed; gate 59/59; pack verified before and after; 3/3 containers removed. One correction: the bridge recreation above. |
| Pack identity, recomputed independently | `papertrail-document-access` 1.0.0; manifest `a4c4ce48…`; tree `529d3cd3…`; fixture `2cbcf118…`; all equal to the PP-007 records; unchanged since `698e78d` |
| Source review of the 8 checks | violation only on the protected marker plus a fixture-proven non-permission; secure needs the reviewed denial, no marker and no content; everything else inconclusive; request errors are never witnesses; functional controls check content and identity |
| Execution profile | **no final profile exists**; the corpus example has placeholder image IDs. **Proposed** `papertrail-reference` 1.0.0 (r2 images, ceilings, fixed timeouts and logs) validates on schema, model and code checks; `canonical_sha256` = `a1c130c2…6835`. **Awaiting owner review.** |
| Approval entry point | **missing**: nothing calls `create_approval` (PP-009 CLI), the typed confirmation is not tied to a terminal, and no store location is defined. A smallest reviewable remedy is proposed. |
| Profile gaps | G-P1: profile `logging` is bounded but not applied (fixed 5m × 2). G-P2: `cancellation_grace_seconds` is unused (fixed 5 s). G-P3: no profile store or loader. |
| Existing approvals | none; no supersession needed; approval tests 36/36 |

**Next owner decisions:**
1. Review and accept (or amend) the proposed profile, and where it is stored.
2. Authorize the minimal approval entry point, or defer to PP-009.
3. Only then, perform the typed approval yourself.

## PP-008 gate B — COMPLETE (r2, 2026-10-13); evidence `docs/evidence/pp-008-gate-b-images.md`

| Gate | State |
|---|---|
| A: Docker-free implementation | done |
| B: image preparation | **COMPLETE** (r2 corrective rebuild) |
| C: live execution | **NOT_AUTHORIZED**; proposal in `docs/architecture/run-images.md` §6 |
| PaperTrail pack | **NOT_APPROVED** |
| Actual verifier collection | **NOT_PERFORMED** |
| Live PaperTrail security verification | **NOT_PERFORMED** |

**Approved run-image candidates (r2):**
- target `sha256:98548ec48d8d796fca5adaf4aab3e461bee38210bd1d568281f79190685eac2e`;
- verifier `sha256:e880f609a7c4d292441e22d1d0d5d7c876697dd4e1e657a668b2b6266969fecc`.

They do not become approved execution identities until the gate-C review.

**The r1 images** (`e5d1ad51…` target, and `e57f61f8…`, the defective verifier) are kept as
evidence and **rejected** by `run_plan.REJECTED_RUN_IMAGE_IDS` (tested).

**Gate B history:**
1. **r1 builds (2026-10-13):**
   - a recipe fix removed `# syntax=docker/dockerfile:1`, which would have pulled an
     unapproved frontend image;
   - **G-B1:** the verifier's directories were `0644`, untraversable for UID 10001;
   - **G-B2:** the build left bytecode in both images.
2. **r2 corrective rebuild** (owner-approved, exactly two builds):
   - recipe: `python3 -B -m pip --no-compile`, plus pre-created `0755` directories, plus
     ownership and mode enforcement **after the final COPY**;
   - static audit of the **final merged filesystem**: verifier access PASS (9 directories
     `0755`, 11 files `0644`, root-owned, byte-identical to the staged sources);
   - 0 `.pyc` in the base and 0 in either final image;
   - only approved distributions; no unapproved content;
   - configuration as reviewed;
   - inventory: +2 images and +8 build-cache entries; the r1 images, the 10 pre-existing
     images, 7 containers, 5 networks and 10 volumes are unchanged; no container was created.
3. **Open host remediation:** the dev pytest 8.4.2 is affected by CVE-2025-71176 and was not
   changed. The minimal upgrade plan is in `environment.lock.md` §3.1, not executed.

**Requested next approval: gate C**, as proposed in `run-images.md` §6:
1. the reviewed code changes: wrapper allowlist, the collection-only verifier spec, the
   self-test pack, and the r2 `ApprovedRunImage` entries;
2. C1a/C1b: pytest 9.0.3 compatibility on a synthetic self-test pack (2 containers, no
   network);
3. C2: the first real PaperTrail collection (1 container, no network; no approval implied).

At most 3 containers in total. The first live comparison is a later, separate request.

## PP-008 — `IN_PROGRESS` (state A complete; stopped at gate B, 2026-10-12)

**Owner authorization (2026-10-12):**
- publish PP-007;
- begin the **Docker-free** PP-008 implementation and the image and dependency planning.
- **Not authorized:** pulls, builds, containers, new dependency installs, or a live run.

**State A: built and validated without Docker.** Details are in
`docs/architecture/verification-runs.md`.
- **New `src/patchproof/runner/` modules:**
  - `run_policy.py`: fixed run policy and typed read-only inputs;
  - `run_gate.py`: the inspect gate for run containers;
  - `inputs.py`: content-addressed pack snapshots and source re-verification, which closes
    PP-007 R2;
  - `collector.py`: the trusted event collector;
  - `run_plan.py`: the plan and recomputed preconditions. The approved run-image registry is
    **empty**.
  - `revision.py`: one target and one verifier per revision;
  - `comparison.py`: feeds the unchanged PP-004 engine.
- **New `verifier/patchproof_verifier/` modules:**
  - `launch.py`: the event channel opened before pytest starts;
  - `events.py`;
  - `transport.py`: a fixed standard-library HTTP client;
  - `plugin.py` (rewritten): run mode, failure classes, per-test deadline.
- **`verifier/pytest.ini`:** `-p no:tmpdir` added.
- **Proposed, unbuilt recipes:** `containers/target-python/` and `containers/verifier/`.

**Findings during PP-008:**
- **P1 (fixed): pytest output in the event channel.** Under real pytest 8.4.2, pytest's own
  output reached standard output, the event channel, because pytest keeps a copy of stdout
  from startup. A real run would have been MALFORMED every time. The fix is the launcher,
  which redirects descriptor 1 before pytest is imported. The PP-007 collection command
  changed accordingly (`-m patchproof_verifier.launch collect ... --`), and its accepted test
  now pins the new exact argv.
- **P2 (owner decision): pytest advisory.** pytest 8.4.2 is affected by CVE-2025-71176
  (GHSA-6w46-j5rx-g56g); the fix is 9.0.3. The verifier recipe proposes 9.0.3. `-p no:tmpdir`
  mitigates either way.
- **P3 (owner decision): HTTP client.** The verifier transport uses `http.client`, not HTTPX
  (§3.1); this is recommended, and the HTTPX set is reviewed in the plan.
- **P4 (gate C): wrapper change.** The accepted Docker wrapper forbids `--mount` and has no
  attached start. `RunCreate` and `StartAttached` are therefore separate operations that the
  real `DockerCli` refuses (tested). Admitting them is a reviewed wrapper change before any
  live run.

**Validation (pinned environment, 2026-10-12):**
- **Full unit suite:** **8145 passed**, 0 failed, 0 skipped. That is 7964 + 181 PP-008 tests:
  policy, gate and inputs 64; collector 35; execution and comparison 38; transport 15;
  plugin end-to-end 23; recipes 6.
- **mypy `--strict`:** clean (58 files). **Ruff:** clean on new and changed code. `ruff check .`
  still reports the 11 pre-existing E501 lines, none in PP-008 files.
- **Lockfile:** `pyproject.toml` and `uv.lock` unchanged, and `uv lock --check` consistent.
  No dependency was installed.
- **Plugin under real pytest 8.4.2** (subprocess, synthetic packs only):
  - the event channel carries only events, even with prints and raw writes to descriptor 1;
  - the host collector accepts the stream as COMPLETE and derives all 11 outcome classes
    exactly;
  - the `launch collect ... -- <path>` command works, and its output passes
    `review_collection`;
  - skip and xfail markers, extra tests, autoloading, and running without the launcher are
    each refused;
  - an early stop yields TRUNCATED with no `session_end`.
- **Comparisons:** all four PP-006 comparisons compose end to end through the fake Docker
  with **synthetic** streams: NOT_FIXED, NOT_FIXED, VERIFIED_FOR_CASES and
  REGRESSION_DETECTED. **These are not application-security results.**
- **Mutation check** (scratch, not committed; logs `scratchpad/pp008/mut.log` and
  `mut-survivors.log`): 31 weakenings of the new boundaries.
  - The first run caught 26.
  - Four real test gaps were closed: the role-input swap, the plan manifest identity, a pack
    tampered with mid-run, and `session_end` after an early stop. Each is now caught in
    isolation.
  - **P15** (the collector's observation-window check) is equivalent: 0 differences over
    3,072 streams with an observation inserted at every position, because PP-007's
    `derive_outcome` rejects the same streams.
  - **Final: 30/31, with one equivalent mutant.** The baseline passed under the identical
    command, and the sources were hash-verified after each run.

**Not executed and not claimed:**
- no image pulled or built;
- no container, real collection or PaperTrail execution;
- no pack approval (test approvals are synthetic and in temporary directories);
- no run-authorization record (PP-009).

**Required owner decisions (gate B; details in `docs/architecture/run-images.md`):**
1. **Base image:** approve `python:3.13-slim@sha256:70729b46…` for the target and verifier
   roles. It is already local, so no pull is needed, and it is identical to Docker Hub
   today.
2. **Target dependencies:** uvicorn 0.54.0, click 8.5.0, h11 0.16.0 (hashes in
   `containers/target-python/requirements.lock`).
3. **Verifier pytest:** **9.0.3 (recommended, fixes CVE-2025-71176)** or 8.4.2 with
   mitigations. If 9.0.3, also decide on the host dev pin.
4. **HTTP client:** the standard-library transport (recommended) or HTTPX 0.28.1 and its six
   dependencies.
5. **Preparation steps:** wheel download from `files.pythonhosted.org` with hash verification,
   then two `docker build --network=none --pull=false` builds. This creates two local images
   and build cache, and nothing else.

**Then gate C (separate approval):**
- the wrapper change admitting `RunCreate` and `StartAttached`;
- the first real collection;
- the first live run plan;
- only after that, the owner's PaperTrail pack approval.

## PP-007 — implementation `ACCEPTED` by owner (2026-10-12)

**Owner decision (2026-10-12):** conditionally ACCEPT the PP-007 implementation, subject to
the final security review and validation. All checks passed, so the condition is met. The
acceptance is of the implementation only. It does not approve the PaperTrail verification
pack, certify its tests, or authorize container execution.

**Acceptance record:**

| Item | Value |
|---|---|
| Implementation commit | `698e78d32e3c3111be335813b59af57180822cfe` ("PP-007: implement strict verification packs and approval records"), 35 files, tree `410094e` |
| Committed-tree verification | The staged tree `410094e` was exported with `git archive` and tested in isolation, with its environment built offline from the lockfile: 7964 passed; mypy strict clean; Ruff clean; lockfile consistent. The commit's tree is identical to it |
| Unit tests | **7964** passed, 0 failed, 0 skipped |
| Schema/model parity | 160 corpus records (all valid and invalid examples, the JSONL stream, all 26 scenarios): 0 disagreements. 223,815 differential mutations: no model more permissive than its schema; only the two documented model-stricter classes |
| Mutation check | 34/35 on the final sources (the 33 original mutants plus 2 for the new store-root controls). M26 is equivalent, shown exhaustively over 3,320 valid blocks, and its reachability invariant is pinned by a test |
| Approvals | Write-once (`O_EXCL`, `0400`), with root-descriptor identity checks, explicit typed confirmation, supersession that preserves history, and staleness on every binding, each tested |
| Dependencies | pydantic 2.13.5, pydantic-core 2.46.5, annotated-types 0.8.0 and typing-inspection 0.4.4 only. No other package changed |
| Not done | **No pack approval exists. No verifier image, real collection, container or PaperTrail execution.** No application-security result is verified |


**Owner authorization (2026-10-12):**
- push PP-006, then implement PP-007 only;
- approve the Pydantic 2.13.5 dependency plan exactly as proposed;
- do not approve a pack on the owner's behalf;
- no containers, images, PaperTrail execution, PP-008, commit, push or tag.

**Dependency change (approved plan, applied as proposed):**
- **`pyproject.toml`:** `pydantic==2.13.5` added; mypy uses the `pydantic.mypy` plugin and
  also checks `verifier/patchproof_verifier`.
- **`uv lock`:** added exactly pydantic 2.13.5, pydantic-core 2.46.5, annotated-types 0.8.0
  and typing-inspection 0.4.4 (23 → 27 packages). The recorded hashes equal the reviewed
  ones.
- **`uv sync --frozen`:** installed them with hash verification.
- **Cooldown:** the `exclude-newer` date is unchanged.
- **Record:** `docs/environment.lock.md` §3.1.

**What was built** (details in `docs/architecture/packs-and-approvals.md`):
- **Strict loader and models:** `core/strict_json.py`, and `core/records/` with strict,
  closed, frozen Pydantic models for all 12 record contracts.
- **Pack validation:** `packs/validation.py`. It is static and never imports pack code;
  hashes are computed over the manifest and the whole pack tree, and the fixture copy must
  match its contract hash.
- **Collection:** `packs/collection.py` builds the fixed verifier-side collection plan and
  checks that the collection is exact at review time and in the approved order at run time.
- **Approvals:** `core/approvals.py` provides immutable approval records with an explicit
  typed confirmation, an append-only store, supersession, and staleness for every binding.
- **Outcome rules:** `core/outcomes.py` implements lifecycle and semantic derivation, rules
  L1–L11.
- **Verifier helpers:** `verifier/patchproof_verifier/` holds
  `check.secure/violation/inconclusive`, bounded evidence, the authorization witnesses, the
  hash-checked fixture copy, path checks and the collection plugin. `verifier/pytest.ini` is
  the PatchProof-owned configuration.
- **Pack:** `examples/packs/papertrail-document-access/` covers the eight PP-006 checks.
  - manifest `sha256:a4c4ce48d5d2aaa512c746e7ba90d06fd76e879de3a3dea5280079531a8804c8`
  - pack tree `sha256:529d3cd3ebf307586dcecef43a0df8ab9b55296849182f8f43c4ad7d6a8a6c31`

**Validation (pinned environment, 2026-10-12):**
- **Full unit suite:** **7964 passed**, 0 failed, 0 skipped. That is 7439 + 525 PP-007
  tests: 260 parity and loader tests, 61 outcome tests, 95 verifier-helper tests, 73 pack and
  collection tests, and 36 approval tests.
- **mypy `--strict`:** clean, 48 files, including `verifier/`.
- **Ruff:** clean on all new and changed code. `ruff check .` still reports the 11
  pre-existing E501 lines.
- **Lockfile:** `uv lock --check` is consistent.
- **JSON Schema / Pydantic parity (ADR-008 condition):**
  - 160 corpus records (all valid and invalid examples, the JSONL stream, and all 26
    scenarios), **0 disagreements**.
  - Full differential run: 223,815 mutations, **0** cases of a model accepting what a
    schema rejects and 0 unexplained differences. 2,606 differences are model-stricter only
    (trailing newline, integral float), as documented.
  - The unit suite runs a bounded deterministic sample every time.
- **Fixed during development:**
  - Pydantic `Literal[False]`/`Literal[True]` accepted `0`/`1` in strict mode, which made the
    model more permissive than the schema on 3 fields. They are now strict booleans with an
    identity check.
  - The first mutation run showed that a file swapped for a FIFO between `lstat` and
    `open` would block pack validation, or the approval store, forever. Both now open with
    `O_NONBLOCK` and re-check the opened descriptor with `fstat`. A race test, run in a
    watchdog thread, covers it.
- **PaperTrail pack against PP-006 (synthetic):** the helpers judge synthetic responses
  shaped like PaperTrail's documented replies, and all 32 check × revision combinations give
  the declared outcome. This is not an observation of PaperTrail running.
- **Final mutation check** (owner's final review, 2026-10-12; scratch log
  `scratchpad/pp007/mut-final-review.log`, not committed). It covered the 33 original
  mutants plus 2 for the new store-root controls, all on the final sources. The baseline
  passed under the identical command (524 tests), and all 20 source files were
  hash-verified after restoration. **34/35 caught.**
  - **M00–M25 and M27–M32 (the original 33 except M26):** all caught. That includes M14,
    the post-open identity check, which is now caught by
    `test_file_swapped_for_another_same_size_file_after_lstat_is_refused`.
  - **M33 and M34 (the new store-root identity and `O_NOFOLLOW` controls):** caught by the
    replaced-root and symlinked-root tests.
  - **M26 survives and is equivalent.** It replaces
    `elif call.failure_class == "assertion": FAIL` with `else: FAIL` for a functional test.
    An exhaustive comparison over every valid block found **0** differences between the
    original and the mutant:
    - 12 setup × 14 call × 10 teardown valid reports;
    - 0–2 observations;
    - complete and truncated blocks;
    - both test kinds;
    - 3,320 blocks in all.

    The code-level reason is that L6, L7 and L9 route every other failed-call class away
    from `COMPLETED`, and the report model forbids `failure_class: none` on a failed report.
    `test_functional_fail_is_reachable_only_through_an_assertion` pins this reachability
    invariant. The explicit check is kept as a redundant layer.

**Final review findings (2026-10-12):**
- **R1 (fixed):** `ApprovalStore` checked its root once, at construction, and later
  operations re-resolved the path. A root swapped for a symlink or another directory would
  have been followed. Every operation now opens the root with `O_DIRECTORY|O_NOFOLLOW`,
  checks the device, inode, owner and mode, and creates, lists and reads entries relative to
  that descriptor. Three tests were added.
- **R2 (PP-008 obligation):** validation hashes the pack as it was read. The runner must mount
  exactly those bytes, or re-hash what it mounts and refuse a mismatch.
- **Documentation:** it now states that the static pack checks are not a sandbox.
- **Reviewed with no change needed:**
  - `tests/conftest.py` only adds `verifier/` to `sys.path`; the plugin is never registered
    with the host pytest.
  - Pack code cannot reach the plugin's recorder, because `_private` attribute access is
    refused.
  - A second terminal call raises `HelperMisuse`.
  - HTTP errors and failed requests are never violations: a 500 is inconclusive, and an
    exception is `CALL_ERROR`.

**Edits to existing accepted files:**
- `tests/conftest.py`: adds `verifier/` to `sys.path` (additive).
- `pyproject.toml` and `uv.lock`: the approved dependency change.
- No assertion in an accepted test was changed. `test_schemas.py` and the verdict engine
  are unchanged.

**Not executed, and not claimed:**
- no verifier image, container, collection or HTTP request;
- no PaperTrail execution;
- **no pack approval**: none exists, and a test asserts that no `apr-*.json` is present;
- no run-authorization record (PP-009).

**Pending, for PP-008 and PP-009:**
- **Verifier image:** pytest, `patchproof_verifier`, `pytest.ini`, and an HTTP client
  library (§3.1 names HTTPX). This needs owner approval and pinned hashes.
- **Plugin transport and event channel:** session, phase reports with `failure_class`,
  observations, session end.
- **Collector:** grammar checks, then `derive_outcome`.
- **First real collection:** `collection_plan` run in the container, checked with
  `review_collection`.
- **Approval:** only then, the owner's explicit approval through the PP-009 CLI.
- **Run time:** `check_run_collection` against the approved list.

**Limits of this design:**
- **Narrow pack policy:** the static checks (imports, no `try`/`with`, no decorators) are a
  deliberately narrow v1 policy.
- **Reviewer identity:** it is only locally asserted.
- **Approval files:** they are protected by convention and permissions, not by cryptography
  (ADR-007).

## PP-006 — `ACCEPTED` by owner (2026-10-12)

**Owner decision (2026-10-12):** conditionally ACCEPT the PaperTrail reference design,
subject to the final source and staged-commit checks. All checks passed, so the condition is
met. The owner approved:
- the four authorization revisions;
- the existing inadequate-fix design for the v0.1 reference corpus;
- the topology with r2–r4 based directly on r1;
- one annotated tag per revision;
- runtime verification deferred to PP-007 and PP-008.

**Acceptance record:**

| Item | Value |
|---|---|
| Implementation commit | `4b8f2888909cea0eab8bdf65e56fb5fa894fe981` ("PP-006: add deterministic PaperTrail authorization reference"), 30 files, tree `40bfc71` |
| Committed-tree verification | The staged tree `40bfc71` was exported with `git archive` and tested in isolation: 7439 passed; mypy strict clean; Ruff clean. The commit's tree is identical to it |
| Revisions (sha1, annotated tags) | `authz-r1-vulnerable` → `68b2bc0e41cb7e9a074b09f2d97db3e2d2ca288a`; `authz-r2-inadequate` → `38f178748f156d5f39e05ac3f19f1a9f47fea39d`; `authz-r3-correct` → `2fb6d09378906f1df69ac32b862df4a350e8a56d`; `authz-r4-deny-all` → `f31cb4b159d1859a3614d97a492389a0f823104e` |
| Unit tests | **7439** passed, 0 failed, 0 skipped |
| Determinism | Two independent generations are identical in every object, ref and file. The independent porcelain rebuild gives the same commit and tag-object IDs |
| Git validity | Git 2.56.0 `fsck --strict --full` is clean. Tag objects are distinct from their peeled commits. r2–r4 have the single parent r1 |
| PP-005 compatibility | Every tag and full commit ID is registered and snapshotted (5 files; `README.md` excluded as `OUTSIDE_SOURCE_SCOPE`). Manifests are deterministic and the repository is unchanged. `src/patchproof/git` is unchanged since `c8128a7` and its 319 tests pass |
| Mutation check | Final run on the final sources: **19/19** caught. The earlier 19/19 report overstated M08, which is now covered (F2) |
| Not executed | **PaperTrail has not been dynamically executed** on any revision. Every behavior in the ground truth is declared and checked statically only |
| Pending obligations | PP-007: a pack for AUTH-001–004 and FUNC-001–004 with marker witnesses, bound to `fixture_sha256`. PP-008: the target and verifier images, the uvicorn version and wheel hashes, and the first dynamic reproduction compared against the declared table |


**Owner authorization (2026-10-12):** publish the accepted PP-005 commits, then implement
PP-006 only. Do not begin PP-007, run the target, build or run containers, install
software, commit or push PP-006, tag, or touch the owner's ADR-010 work.

**PP-005 publication:** `git push origin main` was an ordinary fast-forward,
`84b0e18..aa3a0a3`. Before pushing: worktree root PatchProof, `HEAD` `aa3a0a3`, origin
`https://github.com/aelasmar01/PatchProof.git`, remote `main` at `84b0e18` (an ancestor), and
no ADR-010 path in either commit. Afterwards `git ls-remote` showed
`aa3a0a326ced575470defe5356f85ffa7ce09e98 refs/heads/main`. There was no force, rebase, amend
or tag.

**What was built:**
- **PaperTrail.** A dependency-free ASGI document API with synthetic bearer-token users
  (`examples/papertrail/template/`). Four revisions differ only in `papertrail/authz.py`
  (`examples/papertrail/revisions/`):
  - `vulnerable`: any authenticated caller reads any document;
  - `inadequate`: adds authentication, identity and role checks, but still never consults the
    document;
  - `correct`: owner, or a role listed in the document's `reader_roles`;
  - `deny-all`: refuses every read.
- **Generator.** `src/patchproof/reference/` (`gitobjects.py`, `papertrail.py`,
  `__main__.py`). It writes Git objects directly: no Git process, no subprocess, no Git write
  against any existing repository. It refuses any destination that is not new, absolute,
  canonical and owned, or that is the home directory or an ancestor, inside PatchProof, or
  inside another repository. All files are created with `O_EXCL|O_NOFOLLOW`, every object is
  re-hashed after writing, and a failure removes the partial directory. Entry point:
  `uv run python -m patchproof.reference <new-directory>`.
- **Ground truth and profile material.**
  - `examples/papertrail/reference-fixture.json`, with the new schema
    `schemas/reference-fixture.schema.json` (1 valid and 7 invalid examples).
  - The schema makes approval, runtime observations and an asserted server version
    unrepresentable.
- **Documentation:** `docs/architecture/papertrail-reference.md`.

**Actual generated identities** (object format sha1; annotated tags; candidates are children
of r1). These were produced by running the generator, not written by hand:

| Tag | Commit |
|---|---|
| `refs/tags/authz-r1-vulnerable` | `68b2bc0e41cb7e9a074b09f2d97db3e2d2ca288a` |
| `refs/tags/authz-r2-inadequate` | `38f178748f156d5f39e05ac3f19f1a9f47fea39d` |
| `refs/tags/authz-r3-correct` | `2fb6d09378906f1df69ac32b862df4a350e8a56d` |
| `refs/tags/authz-r4-deny-all` | `f31cb4b159d1859a3614d97a492389a0f823104e` |

**Validation (pinned environment, 2026-10-12):**
- **Full unit suite:** **7439 passed**, 0 failed, 0 skipped. That is 7337 + 89 PP-006 tests
  + 13 new schema-table cases. It was 7436 at READY_FOR_REVIEW; the final review added 3
  (F1, F2 below).
- **mypy `--strict`:** clean (30 files). **Ruff:** clean on `src`, `examples` and the
  changed tests. `ruff check .` still reports the 11 pre-existing E501 lines in `tests/`.
- **`uv lock --check --offline`:** consistent. No dependency was added.
- **Determinism:** two generations are byte-identical, including every file under `.git`.
- **Git cross-checks:** Git 2.56.0 `fsck --strict` is clean. An independent rebuild with
  ordinary `git commit`/`git tag -a` gives the same commit and tag-object IDs.
- **PP-005:**
  - registers the generated repository and snapshots every tag and full commit ID;
  - each snapshot holds 5 files with `README.md` excluded as `OUTSIDE_SOURCE_SCOPE`;
  - manifests are byte-identical across independent generations;
  - the repository fingerprint is unchanged.
- **Static expectation check:** an AST interpreter limited to `authz.py`'s small language,
  plus structural checks of `app.py`, derives all 32 declared outcomes (8 checks × 4
  revisions). The test process never imports `papertrail`.
- **Verdict engine:** feeding the declared outcomes to the accepted PP-004 engine gives
  `NOT_FIXED`, `NOT_FIXED`, `VERIFIED_FOR_CASES` and `REGRESSION_DETECTED`.
- **Mutation check (scratch, not committed):** final run on the final sources **19/19**
  weakenings caught, covering
  destination rules, symlink refusal, cleanup, `O_EXCL`, object verification, tree ordering,
  ref grammar, each authz revision, the 401-before-lookup order, token matching, fixture
  grants and the declared verdicts. The baseline passes with the identical command, and the
  sources were hash-verified after restoration.
  - Template mutants are also caught by the pinned commit IDs, so for those the ID check is
    not the only guard; the semantic tests catch M12–M16 independently.

**Final review (2026-10-12), after the owner's conditional acceptance:**
- **F1 (fixed, schema).** `reference-fixture.schema.json` allowed `protected_marker: null` on a
  security check or a document read. The data was correct, but the contract would have let a
  status code alone stand as a witness (§7.3). The schema now requires a marker on every
  security check and every `/documents/` read. Two new invalid examples are rejected for
  exactly that reason. The data and commit IDs are unchanged.
- **F2 (fixed, test gap; earlier figure corrected).** The READY_FOR_REVIEW report said 19/19.
  On re-running, mutant M08 (the stored-bytes comparison in `LooseObjectRepository.verify`)
  **survived** in three isolated reruns, so that earlier 19/19 overstated the result by one. Why
  that earlier run marked M08 as caught was not determined.
  - M08 is not an equivalent mutant: only the byte comparison rejects an object stored with a
    non-canonical header (for example `blob 010`) whose payload still hashes correctly.
  - A test now covers it, and the final run caught 19/19 (log
    `scratchpad/pp006/mut-final2.log`).

**Edits to existing accepted files:** `tests/unit/test_schemas.py` only, with 10 additive
lines: `reference-fixture` added to `RECORD_SCHEMAS`, plus 9 invalid-case rows. No assertion
was changed or removed.

**Not executed:**
- PaperTrail, on any revision;
- any container, image build or pull;
- any installation;
- `patchproof doctor`, because its code is unchanged.

**Limitations and obligations:**
- **Nothing dynamic yet.** No dynamic reproduction exists. The §15.2 witness requirement
  remains for PP-008.
- **PP-007:** a pack implementing AUTH-001–004 and FUNC-001–004 with semantic witnesses,
  bound to `fixture_sha256`.
- **PP-008:**
  - the target image (Python 3.13, uvicorn version and wheel hashes still UNRESOLVED) and the
    verifier image;
  - the read-only snapshot mount and `/health` readiness;
  - the first runtime observations, compared with the declared table.
- **Fixed fixture data:** identities and markers are fixed; seeded variation is PP-019.
- **Packaging:** the generator reads templates from the source checkout; packaging is
  PP-023.
- **Generated repository shape:** it has no index or worktree, so `git status` shows staged
  deletions. A SIGKILL during generation can leave a partial directory, which is never
  reported as generated.
- **Threat model:** AC-1 lists PP-006 for deny-all evidence. `docs/threat-model.md` is not
  updated because it holds the owner's uncommitted ADR-010 hunk.

## PP-005 — `ACCEPTED` by owner (2026-10-12)

**Owner decision (2026-10-12):** conditionally ACCEPT PP-005, subject to the final
staged-code checks. All checks passed, so the condition is met. The owner also decided:
1. **APPROVED:** `src/patchproof/git/command.py` is the only new production file allowed to
   import `subprocess`, matched by its exact project-relative path. The PP-003 exceptions
   are unchanged.
2. **ACCEPTED:** the Homebrew changes that came with Git 2.56.0: cmake 4.4.4, json-c 0.19,
   pcre2 10.49, gettext 1.0, libunistring 1.4.2 and pkgconf 3.0.8. The linkage checks are
   sufficient for this phase. No further upgrades or cleanup.
3. **ACCEPTED:** mutation M11 survives because `ObjectId` enforces the identical length
   rule with the same error. Verified that no callable path bypasses `ObjectId`
   validation (F1 below). The redundant check is kept.
4. **ACCEPTED:** the 11 pre-existing Ruff E501 findings in `tests/` are not PP-005
   regressions. They are documented, not suppressed.

**Acceptance record:**

| Item | Value |
|---|---|
| Implementation commit | `c8128a7b2bbecfa6c542734c19c357296e3d204f` ("PP-005: implement safe Git repository registration and snapshots"), 23 files |
| Committed-tree verification | `git archive c8128a7` exported to scratch and tested in isolation: 7337 passed; mypy strict clean; Ruff clean on `src` and the PP-005 tests |
| Environment | Git 2.56.0 (Homebrew `2.56.0_1`), with the dependency changes above (`docs/environment.lock.md` §3.2); `~/.git` retained (§6.1), hazard remains |
| Unit tests | 7320 at READY_FOR_REVIEW; **7337** after the final review (+17: F1, F2) |
| Negative tests | Refs/revisions, registration and ambiguity, unsafe paths, symlinks/gitlinks/LFS, collisions, limits, secret policy, malformed output, environment/config injection, replace objects, partial clone, crash and interruption: see the criteria table below |
| Mutation check | Final single pass on the committed sources: **33/34 caught**. M11 is the accepted equivalent mutant. Sources hash-verified after restoration |
| Repository preservation | Every snapshot and resolve test asserts an unchanged fingerprint (content, mode, size, mtime_ns of every path including `.git`); uncommitted edits survive, including under SIGKILL |
| Accepted residual risks | Listed under "Residual risks" below. Crash-leftover reconciliation is a PP-014 obligation |

**Owner authorization (2026-10-12):** start PP-005, beginning with Git remediation.

**Owner decisions recorded in this issue:**
- **Approval item 3, Git upgrade: done.**
  - Homebrew Git 2.42.0 → **2.56.0** (`2.56.0_1`) at `/usr/local/bin/git` →
    `/usr/local/Cellar/git/2.56.0_1/bin/git`. Built from source; exit 0.
  - Dependency changes the upgrade required (owner: "if git fails then fix it, you have
    permission"):
    - new build tools: cmake 4.4.4 and json-c 0.19;
    - upgraded shared libraries: pcre2 10.49, gettext 1.0, libunistring 1.4.2 and
      pkgconf 3.0.8.
  - Old kegs are retained for rollback; no `brew cleanup` was run.
  - `brew linkage --test` is clean for Git and the seven formulae that share those
    libraries.
  - That check switched Homebrew's developer mode on automatically; it was switched back
    off.
  - Details, source tarball hash, and the 14 CVEs that 2.42.0 lacked fixes for:
    `docs/environment.lock.md` §3.2.
- **Approval item 4, `~/.git`: RETAINED by owner decision.** The item is resolved; **the
  hazard is not.**
  - `~/.git` was not deleted, moved, reinitialized, reset, cleaned, staged or modified.
    Its `HEAD`, `config` and `index` have the same modification times and sizes before
    and after.
  - Git write commands must never run rooted at the home directory.
  - PP-005 registration refuses the home directory and its ancestors and never searches
    upward, so a parent repository cannot be registered by accident.
  - `patchproof doctor` keeps reporting HOST-03 as an advisory warning, which is correct.

**Implementation:**
- **Code:** `src/patchproof/git/` (`command.py`, `repository.py`, `paths.py`,
  `snapshot.py`, `errors.py`).
- **Schema:** `schemas/source-manifest.schema.json`, with one valid and six invalid
  examples.
- **Design and residual risks:** `docs/architecture/source-snapshots.md`.
- **Scope:** library services only. There is no CLI (PP-009) and no persistence (PP-011),
  and no container is involved.

**Acceptance criteria (§9.1, §9.2, §16 "No original-repo mutation; path/ref/size
rejection tests", owner prompt §4–§6):**

| Criterion | Evidence |
|---|---|
| Register only an explicitly selected canonical local repository; reject parent/ambiguous discovery | Canonical-path, subdirectory, parent-repo (`~/.git` analogue), home/ancestor, `/`, gitdir file, symlinked `.git`, bare, alternates/grafts/commondir, and `core.worktree`/`core.bare` redirection tests |
| Full commit IDs; object format recorded, SHA-1 and SHA-256 | Registration and snapshot tests in both formats; 64-digit IDs; manifest `object_format` |
| Reject option-like, abbreviated, ambiguous refs and revision expressions | 30 refused expressions; short `main` that is both branch and tag; abbreviated/missing/non-commit IDs; a branch named like an ID cannot redirect a full ID; seeded property test (10,000 inputs) |
| Read objects without checkout or modification | Only `version`, `rev-parse`, `show-ref`, `cat-file`, `ls-tree`. Every snapshot/resolve call in the tests asserts the repository fingerprint is unchanged: every path under the root and `.git` with type, mode, size, mtime_ns and content hash |
| NUL-delimited parsing; path and object-type validation | Strict `ls-tree -z -l` and `cat-file --batch` parsers; malformed-output table tests; per-object size and Git-hash verification; single-bit corruption property test |
| Symlinks, gitlinks, LFS pointers, special files, traversal, absolute, unsafe names, case/normalization collisions | Crafted-tree tests with real Git, plus parser-level tests |
| Limits: 100 MiB total, 20,000 entries, 10 MiB per file | Default-limit tests: 20,001 entries; 10 MiB + 1 byte; 11 × 10 MiB rejected before any blob is read. Limits cannot be loosened |
| Inclusion/exclusion rules; secret paths conflicting with required inclusion | Exclusions recorded with reasons; `SECRET_PATH_REQUIRED`; `REQUIRED_PATH_MISSING` |
| Complete manifests, hashes, identities; deterministic | Schema-validated manifest; byte-identical manifests across runs; order-independence property test; profile hash binds scope and limits |
| Preserve original repository and uncommitted changes | Staged, modified and untracked edits survive byte-for-byte (fingerprint and `git status` equal) and are never included |
| No partial successful snapshot on failure | Write failure, `KeyboardInterrupt`, and post-write tampering leave the destination empty |
| Sanitized Git execution | Environment built from scratch. Injected `GIT_*` / `HOME` / `GIT_CONFIG_*` / `GIT_EXEC_PATH` / alternates / namespace / trace variables have no effect. A host-style global `filter.lfs` with `required=true` is not applied. Hostile repository config (fsmonitor, hooks, filters, textconv, aliases, pager, credential, ssh, include, gc) runs nothing. Replace refs ignored, each of three layers tested alone. Partial clone: no lazy fetch, with the protocol block tested alone. Deadlines and output caps enforced |
| Caller input cannot invoke arbitrary Git commands | Typed operation allowlist, including duck-typed lookalikes that use an allowed subcommand; fixed argv prefix; seeded property test over random revisions checks every argv |

**Final owner-requested review (2026-10-12), before commit:**
- **F1, hardening, fixed.** `ShowRef`, `ObjectType`, `Peel` and `LsTree` only declared
  their positional types, so a direct library caller could pass a lookalike or raw string.
  - Every operation now checks at construction time that its argument is exactly
    `ObjectId` or `RefName`.
  - `ObjectId` requires a real `ObjectFormat`.
  - Added 16 tests, including option-shaped lookalikes (`--output=...`,
    `--batch-all-objects`).
  - All `ObjectId` constructions go through its validation (`parse_revision`,
    `output_oid`). The redundant hex-length check in `parse_revision` (M11) is kept as
    defence in depth.
- **F2, crash evidence, added.** A child process is SIGKILLed during materialization.
  Only a `.staging-*` directory remains: never `snapshot-*`, and no manifest published.
  The repository fingerprint, including an uncommitted edit, is unchanged.
  - **PP-014 obligation:** reconcile such leftovers automatically.
- **Confirmed without change:**
  - staging lives inside the validated private (`0700`, canonical) destination;
  - the manifest is written inside staging before the atomic rename;
  - limits are checked before reading, per object during reading, and per file after
    writing;
  - the subprocess-allowlist exception matches only the exact project-relative path
    `src/patchproof/git/command.py`; the PP-003 exceptions are unchanged.
- **Test counts:** 7320 before this review; **7337** after it (+16 F1 tests, +1 F2 test).

**Validation (2026-10-12, pinned CPython 3.13.16, `uv run --locked --offline`):**
- `pytest tests/unit`: **7337 passed**, 0 failed, 0 skipped. This is 7008 accepted tests
  plus 329 PP-005 tests: `test_git_snapshot.py` 119, `test_git_isolation.py` 200, and 10
  added rows in `test_schemas.py`.
- `mypy --strict`: clean, 26 source files. `ruff check src`: clean.
- `ruff check tests`: 11 E501 findings, all pre-existing at HEAD and byte-identical (the
  `test_schemas.py` ones are shifted 7 lines by the added rows). PP-005 test files are
  clean. Nothing suppressed.
- `uv lock --check --offline`: consistent. No dependency was added; Hypothesis is not
  approved, so property tests use seeded `random.Random`.
- `patchproof doctor` (offline, read-only): READY for v0.0 scope, exit 0. GIT-01 is now OK
  (2.56.0). One advisory: HOST-03 (`~/.git`, retained by owner decision).

**Mutation check** (scratchpad script, not committed). Each of 34 controls was removed
individually and the PP-005 test files and `test_docker_cli.py` were re-run.
- **First pass:** 27/34 caught. The 7 survivors were defence-in-depth layers masked by
  another layer:
  - `core.useReplaceRefs` and `--no-replace-objects` (masked by `GIT_NO_REPLACE_OBJECTS`);
  - `protocol.allow=never` (masked by `GIT_NO_LAZY_FETCH`);
  - `core.fsmonitor=false` (unreachable through the allowlisted commands);
  - the operation-type allowlist (masked by the subcommand allowlist);
  - the revision hex-length check (masked by `ObjectId`);
  - the collision key (masked by APFS `O_EXCL` at write time).
- **Tests added:** each layer is now tested alone, the reviewed override table is pinned,
  and a lookalike-operation test and pure collision tests were added.
- **Re-run of the 7:** 6 now caught. **Final: 33/34.** The survivor (revision hex-length
  check) is an equivalent mutant: `ObjectId` enforces the identical rule with the same
  reason code.
- **Restoration:** all six sources were restored. SHA-256 matches the pre-mutation copies,
  and no tracked `src/` file is modified.

**Change to an accepted test (owner review requested):**
`tests/unit/test_docker_cli.py::test_no_shell_true_and_single_subprocess_module` now also
permits `subprocess` in exactly `src/patchproof/git/command.py`, matched by full relative
path. Every other file is still refused. `shell=True` and `os.system`-style checks are
unchanged.

**Not changed:**
- `docs/threat-model.md`: it carries the owner's uncommitted ADR-010 hunk. AC-2 evidence
  for PP-005 is recorded here and in `docs/architecture/source-snapshots.md`; marking it in
  the threat model is left to the owner.
- The accepted verdict engine, runner, probes and doctor.
- No container was run.

**Residual risks** (details in `docs/architecture/source-snapshots.md`):
- Git still parses untrusted repository config, refs and objects. A Git parser bug is
  mitigated only by the patched release, deadlines and output caps.
- No repository lock: refs may move between runs, but resolved commits are pinned by full
  ID and objects are hash-verified.
- A SIGKILL can leave a `.staging-*` directory, never a `snapshot-*` (tested). Automatic
  reconciliation belongs to PP-014.
- The secret policy is filename-based only. Gitleaks scanning is planned for PP-026.
- Python `casefold` + NFC may differ from APFS for rare characters. Write-time `O_EXCL`
  still refuses any clash.
- Single-user ownership checks only (§4.1).

**PP-005 implementation commit scope** (committed as `c8128a7`):
- `src/patchproof/git/`: `__init__.py`, `command.py`, `errors.py`, `paths.py`,
  `repository.py`, `snapshot.py`;
- `schemas/source-manifest.schema.json`;
- `schemas/examples/valid/source-manifest--synthetic-app.json`;
- the six `schemas/examples/invalid/source-manifest--*.json`;
- `tests/unit/_git_fixtures.py`, `tests/unit/test_git_snapshot.py`,
  `tests/unit/test_git_isolation.py`;
- `tests/unit/test_schemas.py` and `tests/unit/test_docker_cli.py` (additive);
- `docs/architecture/source-snapshots.md`, `docs/environment.lock.md`, `STATUS.md`,
  `docs/backlog.md`.

**Excluded from the commit scope:** the owner's ADR-010 files (`CLAUDE.md`,
`PROJECT_SPEC.md`, `docs/threat-model.md`, `docs/adr/ADR-010-agent-permission-mode.md`).

## v0.0 foundation release — `ACCEPTED` by owner (2026-10-12)

**Owner decision (2026-10-12):** ACCEPT v0.0.
- This covers the v0.0 foundation only.
- It does not claim v0.1 functionality, vulnerability comparison against real Git
  revisions, or broader target execution.

**E1, environment accepted by the owner:**
- macOS 26.3.1 on the tested Intel Mac;
- managed CPython 3.13.16 and uv 0.12.24;
- the committed, hash-locked dependency environment (`uv.lock`);
- Docker Desktop 4.94.0 with Engine 29.8.2;
- the approved probe image `sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f`;
- the recorded isolation policy and resource limits.

**Accepted limitations:**
- the user namespace is shared with the Docker VM;
- CPU measurements are statistical;
- four claims rest on configuration evidence (`no-new-privileges`,
  `no-host-namespaces`, `no-host-environment`, `no-published-ports`);
- physical Docker log-storage consumption was not measured (retention is measured via
  `docker logs`);
- results apply to one installation on one date, with no guarantee against
  container-runtime vulnerabilities;
- hashes support local consistency checks only (ADR-007).

**E5:** this entry records v0.0 as passed, now that the evidence exists.

**Gate checklist:** `docs/evidence/v0.0-release-gate.md`.
- All build, capability, and demonstration requirements, and E2–E4: PASS.
- E1 and E5, which were INCOMPLETE pending the owner's action, are now satisfied by this
  decision.
- No mandatory requirement remains incomplete. None failed.

**Release record:**

| Item | Value |
|---|---|
| Accepted issues | PP-001, PP-002, PP-003, PP-004, v0.0-CLOSEOUT |
| C1–C3 implementation commit | `62887bf26122a0df96a18f8f82ec3e1f148071ba` |
| v0.0 evidence commit | `d1bcbfce7a8fef91a5af3d91d2542aecafddea97` ("v0.0: document successful foundation gate demonstration") |
| C4 run | `run-883e1a62b93ced171a8cd9275ceb9a66`: ALL_PLANNED_PROBES_PASSED. 82/82 probes and 17/17 positive controls passed. 43.764 s active. Cleanup COMPLETE; all 10 owned containers removed; unrelated Docker resources preserved |
| C4 evidence-consistency review | 52/52 checks, by a read-only script that imports no PatchProof code. Not a human audit |
| C4 shell exit code | **Not captured.** The run evidence reports success |
| Validation | 7008 Docker-free unit tests passed under pinned CPython 3.13.16 (`uv run --locked --offline`); mypy strict and Ruff clean; `uv.lock` consistent offline |
| Evidence | `docs/evidence/v0.0-release-gate.md`, `docs/evidence/v0.0-c4-isolation-demonstration.md` and `.json`, `docs/evidence/pp-003-isolation-probes.md` and `.json` (runs 1–3, including the two failed runs) |

**Future obligations:**
- **Before PP-005:** an owner decision on and approval of upgrading Git 2.42.0 to the
  reviewed 2.56.0 (approval item 3), and a decision on the unrelated home-directory
  repository `~/.git` (approval item 4). Neither has been changed.
- **PP-007:** strict loader, full schema validation, Pydantic parity, and pack ID
  uniqueness.
- **PP-008:** event-derived engine inputs, D6 encoding and bounding, and code-level
  resource ceilings.
- **At each release gate:** re-verify Docker Desktop advisories and re-run the isolation
  probes after runtime upgrades.

## v0.0 release gate — review record (2026-10-12)

**Gate assessment:** `docs/evidence/v0.0-release-gate.md`, requirement by requirement
against §15.1 and §13.1.
- Every implementation and evidence requirement is PASS.
- None is FAIL.
- E1 (owner reviews the environment and installations) and E5 (STATUS records v0.0 as
  passed) are INCOMPLETE because they are the owner's action.

**C1–C3:** committed locally as `62887bf26122a0df96a18f8f82ec3e1f148071ba` ("v0.0:
package PatchProof and integrate doctor CLI"). Not pushed or tagged.

**C4 demonstration:**
- The owner ran `uv run --locked --offline patchproof doctor --probe-isolation`
  interactively.
- Run `run-883e1a62b93ced171a8cd9275ceb9a66`: ALL_PLANNED_PROBES_PASSED, 82/82 PASS,
  17/17 positive controls.
  - Timing: 2026-10-12T13:00:56Z to 13:01:40Z, 43.764 s active of 1200 s; no deadline
    expiry.
  - Cleanup COMPLETE; inventory before and after identical.
- **Evidence-consistency review:** 52/52 checks passed. It is a read-only script, not a human audit, and imports no PatchProof code,
  run against the raw evidence. All checks pass:
  - all create argv match run 3 after normalizing per-run tokens;
  - all 10 containers passed the inspect gate before start;
  - only allowlisted operations ran, with no force-removal;
  - all 10 owned containers were removed;
  - NET-01 and FS-05 meet the approved requirements.
- **Not captured:** the shell exit code.
- **Sanitized evidence:** `docs/evidence/v0.0-c4-isolation-demonstration.md` and `.json`.
  Private evidence checksums are recorded there.
- **Historical runs:** runs 1–3 are preserved and their saved manifests still validate.

**Final validation (2026-10-12, pinned 3.13.16, offline):**
- `pytest tests/unit`: 7008 passed, 0 failed, 0 skipped. This includes the verdict
  corpus, 106/106.
- `mypy --strict`: clean, 20 files. `ruff`: clean.
- `uv lock --check --offline`: consistent; `uv.lock` unchanged.
- Offline `patchproof doctor`: READY (v0.0 scope), with 2 advisory warnings (Git 2.42.0,
  `~/.git`).
- `README.md` was corrected: its status still said "pre-implementation, no CLI or
  verdict engine".

## v0.0 closeout C1–C3 — committed `62887bf` (2026-10-12)

**C1 Packaging.**

- uv 0.10.7 could not install CPython 3.13.16; it offers builds only up to 3.13.12. The
  owner chose to upgrade uv, to 0.12.24. The pip `--user` install used a hash-pinned
  wheel.
- `uv python install 3.13.16 --no-bin` installed the managed interpreter. The system
  `python3` is still 3.13.1.
- Added `.python-version` (3.13.16), `pyproject.toml`, and `uv.lock`, and ran
  `uv sync --locked` into the ignored `.venv`.
  - Runtime: typer 0.27.2 and platformdirs 4.12.0.
  - Dev: the exact versions that produced the accepted results (pytest 8.4.2,
    jsonschema 4.25.0, referencing 0.36.2, mypy 1.18.2, ruff 0.14.2).
  - 23 third-party packages are locked with hashes; all are PyPI wheels.
  - `exclude-newer` gives a two-week cooldown.
  - Sources and reasons: `docs/environment.lock.md` §3.1.
- Under the pin, **before any C2/C3 code**, the unchanged suite gave **6923 passed**,
  exactly the accepted baseline.
- Ruff targeting 3.13 newly reports UP017, a style rule, on one line of the accepted
  PP-003 orchestrator. It is suppressed for that file only, leaving the code unchanged.

**C2 `patchproof doctor`, read-only** (`src/patchproof/doctor/`):

- `environment.py` collects observed facts through a closed set of read-only commands:
  - `docker --context desktop-linux` `context inspect`, `version`, `info`, and
    `image inspect` of the approved ID;
  - `git --version` and `uv --version` from allowlisted directories;
  - `sysctl -n hw.memsize`.
- Every command uses argument arrays, deadlines, capped output, and the runner's
  sanitized environment. Doctor has its own executor, which refuses every runner
  operation, so the PP-003 `DockerCli` allowlist is unchanged.
- As in PRE-01, nothing beyond `context inspect` is sent unless the context points at
  the Docker Desktop user socket.
- `assessment.py` is pure. It maps facts to 17 checks: host, Python pin, uv, Git,
  Docker reachability, the Docker Desktop CVE-2025-9074 floor, Linux/x86_64, cgroup v2,
  seccomp, the `none` driver, daemon warnings, approved image identity, and evidence
  directory readiness.
  - A required check that is FAIL or UNKNOWN makes the report `BLOCKED` (exit 21).
  - Observed facts, checks, and assumptions are reported separately.
  - `isolation_verified_by_doctor` is always false.
- Doctor never creates the evidence directory, pulls, or repairs anything.

**C3 `patchproof doctor --probe-isolation`** (`src/patchproof/cli/main.py`):

- It calls the accepted PP-003 entry point unchanged:
  `patchproof.probes.cli.main(["run", "--image-id", <A2 ID from policy code>,
  "--evidence-root", <fixed platformdirs A3 path>])`.
- It accepts no image, path, platform, Docker option, or `--yes`; `--json` is refused.
  All of these exit 2.
- It prints an ACTIVE DOCKER OPERATION banner, then the runner applies its own A2/A3
  checks, interactive A4 phrase, deadlines, exact-ID cleanup, and private evidence.
- Shell-completion installation and rich tracebacks are disabled.

**Results (2026-10-12):**

- `uv run --locked python -I -m pytest tests/unit`: **7008 passed**, 0 failed, 0
  skipped. That is 6923 baseline + 58 doctor + 27 CLI. The system Python 3.13.1 gives
  the same 7008.
- `uv run --locked mypy` (strict, 20 files): clean. `ruff check` on the source and the
  verdict, doctor, and CLI tests: clean.
- **Weakening check:** 8/8 deliberate breakages were caught: image override,
  mutating-op admission, context gate removal, a lowered Docker Desktop floor,
  confirmation bypass, UNKNOWN treated as pass, evidence-directory creation, and an
  isolation claim.
- **Live `patchproof doctor`** (read-only; text and `--json`): `READY`, exit 0.
  - Required checks: all OK.
  - Advisories: Git 2.42.0 < 2.56.0, and `~/.git` present.
  - Observed: Docker Desktop 4.94.0 (241994), server 29.8.2, cgroup v2, seccomp
    builtin, `null` driver present, and the approved image present with the exact ID.
- **Live wrapper refusals** (no Docker call): `--probe-isolation </dev/null` refused at
  A4, exit 21, nothing written. `--image-id` and `--json` give exit 2.
- PP-003 evidence: all 32 files of the three preserved runs still match their saved
  checksum manifests.
- **Owner review fix (2026-10-12):** READY is now explicitly scoped.
  - Text output: "Overall (v0.0 environment readiness): READY, N advisory warning(s)
    unresolved", followed by a scope line.
  - JSON output: a `scope` field.
- **Offline check:** `uv run --locked --offline patchproof doctor` gave exit 0, made no
  registry access in uv's verbose log, and left `uv.lock` and `pyproject.toml`
  byte-identical. Git 2.42.0 and `~/.git` still show as warnings.
- No change to accepted runner, probe, core, container, schema, or architecture files
  (`git diff HEAD` empty for those paths).

**Not done:**

- No probe run, container, pull, or Docker setting change.
- No commit.
- C4 is not started.
- `containers/probes/run_isolation_probes.py` remains as the PP-003 launcher. Its
  docstring and `probes/cli.py`'s still say packaging is pending; they were left
  unchanged as accepted PP-003 files.

## PP-004 — acceptance record (2026-10-12)

**State:** `ACCEPTED` by owner, 2026-10-12. This acceptance covers PP-004 only.

**Acceptance record:**

- **Implementation commit:** `37ec5889fd83795ad771bfa455958647afc22fd8` ("PP-004:
  implement pure verdict engine and negative tests").
- **Tests:** `tests/unit` **6923 passed**, 0 failed, 0 skipped. Re-run at acceptance;
  `mypy --strict` and `ruff` clean.
- **Corpus:** **26/26** approved verdict scenarios reproduced exactly and schema-valid.
  The verdict specification and the corpus are unchanged.
- **Final source-level review (2026-10-12):** no unsafe path to `VERIFIED_FOR_CASES`.
  One defect was fixed before commit: a failed precondition carrying
  `ALL_CONDITIONS_SATISFIED` produced a schema-invalid record. One information loss was
  fixed: `PRECONDITION_NOT_EVALUATED` dropped under a validation failure.
- **Owner-accepted fail-closed clarifications (2026-10-12)**, which leave V-01..V-10 and
  D1–D6 unchanged:
  1. `PRECONDITION_NOT_EVALUATED` is kept whenever a precondition was actually
     unevaluated, even alongside an independent validation failure. Both reasons are kept;
     the verdict stays V-02 `INCONCLUSIVE` with no trusted observations.
  2. Duplicate pack test IDs and duplicate pytest node IDs are invalid input (V-02),
     never deduplicated.
  3. Contradictory precondition reason codes, such as `ALL_CONDITIONS_SATISFIED` on a
     failed precondition, are rejected.
  4. A precondition failed `post_execution` in a run that never started is inconsistent
     evidence (V-02).
- **Integration obligations carried forward:**
  - PP-007: strict duplicate-key loader, full JSON Schema validation before
    `parse_verdict_input`, Pydantic/JSON Schema parity tests (ADR-008), and pack test-ID
    and node-ID uniqueness at pack validation.
  - PP-008: the event collector derives `stream.*` facts and observations from real
    verifier events, with safe encoding and bounding (D6). The engine has so far seen only
    corpus and synthetic input.

## PP-004 — implementation summary (accepted 2026-10-12)

**Implementation:**

- `src/patchproof/core/verdict_input.py`: strict typed frozen records for the
  `verdict-input` 1.0 contract. Shape errors raise `VerdictInputError` before any
  evaluation. Duplicates and other semantic problems are preserved for the engine,
  never normalized.
- `src/patchproof/core/verdicts.py`: `evaluate(VerdictInput, evaluated_at) -> verdict`.
  It is pure: no I/O, no clock (the caller supplies `evaluated_at`), no mutation, and
  no input field for target output.
- It implements the verdict specification literally: validation M1–M7 and G1–G5;
  execution trust E1–E4 (with D6 enforced from the host byte count); cell trust T1–T5;
  the seven independent flags; reason codes, details, and counts in canonical order; and
  V-01..V-10 with D1–D6. `pairs_terminated_normally` and `pairs_with_trusted_evidence`
  are kept separate.
- Six verdicts only; `ENGINE_VERSION` is `0.0.0`, as in the reviewed corpus.

**Results:**

- The 26-scenario corpus is reproduced **exactly** (every field), schema-valid,
  order-independent, and the evaluation never mutates its input.
- `tests/unit`: **6923 passed, 0 failed, 0 skipped**:
  - 757 pre-existing tests;
  - corpus: 106;
  - spec-derived rule tests: 168;
  - parser: 33;
  - properties P-1..P-9: 5859 over 799 generated schema-valid inputs. Generation is
    seeded stdlib randomization, because Hypothesis is not installed and no dependency
    was added. Independent oracles cover P-4, P-5/P-8, and P-6.

  Every rule V-01..V-10 is tested; V-10 by forcing the guard.
- `mypy --strict` and `ruff` are clean.
- 23 weakenings were tried on a scratch copy. 22 made tests fail. The other one,
  dropping V-09's explicit exact-agreement check, is equivalent: the reachability note
  in spec §6 shows that exact agreement is already implied, so the check is defense in
  depth.

**Fail-closed additions, approved by the owner 2026-10-12 (no corpus effect):**

1. Duplicate pack test IDs give `OBSERVATION_MATRIX_INVALID` (V-02) and are never
   deduplicated. Duplicate node IDs are held to the same rule.
2. A precondition `FAILED` with `detected_phase: post_execution` in a run that never
   started gives `EXECUTION_EVIDENCE_INCONSISTENT` (V-02).

**Final source review (2026-10-12) found and fixed two edge cases.** Neither changes the
specification or the corpus:

- **Defect.** A schema-valid input whose FAILED precondition listed
  `ALL_CONDITIONS_SATISFIED` produced a schema-invalid `BLOCKED` record carrying that
  positive code. The parser now refuses such input (`VerdictInputError`), because §8
  reserves the code for V-09. A sweep test now covers every reason code on a failed
  precondition, before and after start: each is refused or yields a schema-valid record.
- **Information loss.** An input `NOT_EVALUATED` precondition whose effective state
  became FAILED, through failed validation, lost `PRECONDITION_NOT_EVALUATED`. The code
  is now emitted when either the input or the effective state is not evaluated,
  satisfying §5.4 ("always") and §8 together. The verdict is unchanged (V-02). **Owner
  confirmation requested.**
- Tests were added for the review situations that lacked a dedicated case: functional
  controls failing on both revisions (V-07, not a regression), and a secure-looking
  candidate with an untested baseline (V-05).

**Not done (outside PP-004 or needing approval):**

- No `pyproject.toml` or `uv.lock`; Python is not pinned (approval item 2).
- No Pydantic models (PP-007) and no CLI (PP-009).
- Real event streams come with PP-008; the engine has only been fed corpus and
  synthetic inputs.

## PP-003 — `ACCEPTED` by owner, 2026-10-12

**State:** `ACCEPTED` by owner, 2026-10-12. This acceptance covers PP-003 only. The v0.0
release gate is **not** complete: PP-004 and the §15.1 exit-gate review and demonstration
remain.

**Acceptance record:**

- **Implementation commit:** `e38d0d1aa51934d00fd06fd58e4ed57b82e1211e` ("PP-003: implement
  and validate container isolation probes").
- **Accepted run:** `run-5c176591e0f793ebdb6c2f07667c4ead`, ALL_PLANNED_PROBES_PASSED. Runtime
  probes: **82/82 PASS**, positive controls 17/17. Docker-free unit tests: **757 passed**.
- **Sanitized evidence:** `docs/evidence/pp-003-isolation-probes.md` and
  `docs/evidence/pp-003-isolation-probes.json`.
- **Pre-acceptance review** of the 4 CONFIGURED_ONLY claims (no-new-privileges,
  no-host-namespaces, no-host-environment, no-published-ports): each narrow claim is
  supported. Every §15.1-named restriction has behavioral evidence. The user namespace is
  shared with the Docker VM; this is a documented residual, mitigated by the non-root UID
  and zero capabilities. See the evidence report's reviewer notes.
- **Accepted limitations:**
  - sleeper stdout not persisted (RES-12 corroborated by the command log);
  - `fb_tunnels_only_for_init_net` unreadable (informational);
  - CPU enforcement is statistical;
  - log retention measured via `docker logs`, not on disk;
  - no-new-privileges not behaviorally exercised;
  - shared user namespace;
  - `--pull=never` refusal of a missing image exercised only in unit tests;
  - `/dev/mqueue` bounded only by the kernel default;
  - results apply to Docker Desktop 4.94.0 / Engine 29.8.2 on 2026-10-12 only.

**Future obligations (tracked; not part of PP-003):**

1. Integrate the standalone probe runner into `patchproof doctor --probe-isolation`
   (§13.1) before v0.0 acceptance. This needs the packaging approval (approval item 2).
2. Persist the sleeper container's stdout in future runs (artifact-retention
   improvement). This must not invalidate or relabel the historical run.
3. Review the container-runtime version and security advisories at every later release
   gate, and re-run the isolation probes after Docker Desktop upgrades.
4. PP-004: implement and test the pure verdict engine (26 reviewed scenarios).

A4 history (all three runs preserved unchanged in private evidence):

| Run | Outcome |
|---|---|
| 1 `run-d109d3606276fd75137241a6a1bc6b92` | **BLOCKED**: Docker inspect representation mismatch (see below) |
| 2 `run-cc1e6383d6893c2afe8ab839cc68a08d` | **ISOLATION_FAILED**: NET-01, FS-05 (see below) |
| 3 `run-5c176591e0f793ebdb6c2f07667c4ead` | **ALL_PLANNED_PROBES_PASSED**: 82 of 82 |

## PP-003 A4 run 3 — `ALL_PLANNED_PROBES_PASSED` (2026-10-12)

Executed by the owner at 04:28:49Z. Active time 36.848 s of 1200 s, no deadline expiry,
not interrupted, cleanup COMPLETE. **82 PASS**, with 0 FAIL, BLOCKED, INCONCLUSIVE,
ERROR, or NOT_RUN.

**Independent read-only verification (2026-10-12)** used the raw container output,
inspect dumps, command log, journal, and snapshots, not the run's own summary:

- **Inspect gate:** all 10 containers passed with 0 mismatches. The restrictions are
  confirmed in each inspect document, and the verifier's `NetworkMode` is
  `container:<exact target ID>`.
- **NET-01:** every non-loopback device was down (no IFF_UP), with no IPv4 or IPv6
  address, an `EINVAL` carrier, and 0/0 bytes. Routes were 0, capability sets zero, and
  every egress attempt blocked.
- **FS-05:** the startup environment was Config.Env plus HOME/HOSTNAME; only
  `LC_CTYPE=C.UTF-8` appeared after start.
- **Docker operations:** 101 commands, all allowlisted. Every removal was
  `container rm -- <id>`, with no force-remove. Every create carried
  `--platform linux/amd64 --pull=never` and the approved image ID.
- **Containers:** 10 created, 8 started, decoys never started, a peak of 2 at once, and
  all 10 removed. The before and after inventory snapshots are identical.
- **Code identity:** the probe-script digest matches (`734aa576…`). The combined code
  hash `6eeb9634…` equals the one reported before the run, and current code regenerates
  all 10 executed create argv exactly.

**Evidence gaps found (not inconsistencies):**

1. The runner does not persist the sleeper container's stdout, so RES-12's "sleeping"
   internal control was judged in memory only. The command log corroborates it: start
   ok, wait timed out at 10.0 s, stop 5.1 s, inspect, removed. A one-line runner fix is
   proposed for later; it was not made, so the reviewed code stays identical to the code
   that ran.
2. `net.core.fb_tunnels_only_for_init_net` was unreadable in the container (ENOENT). It
   is informational, not a pass criterion.

**Sanitized review evidence:** `docs/evidence/pp-003-isolation-probes.md` (report) and
`docs/evidence/pp-003-isolation-probes.json` (machine-readable). The installation ID,
container IDs, paths, raw output, and the script text are excluded.

## PP-003 A4 run 2 — `ISOLATION_FAILED` (2026-10-11; preserved, not relabeled)

Run ID `run-cc1e6383d6893c2afe8ab839cc68a08d`, executed by the owner. Evidence (unchanged)
is in `~/Library/Application Support/PatchProof/probe-runs/run-cc1e6383d6893c2afe8ab839cc68a08d/`.
Active time 35.4 s. All 10 containers passed the corrected inspect gate (including the
verifier, the first real check of its shape). Cleanup was COMPLETE, and preservation
snapshots were identical. Result: **80 PASS, 2 FAIL**.

Before this run, the default `bridge` network ID had changed outside PatchProof, which
points to a Docker engine restart after run 1. The owner accepted the snapshot taken at
the start of run 2 as its baseline.

| Failed | Observed (target and verifier, which share the namespace) | Finding |
|---|---|---|
| NET-01 | `lo` plus `erspan0 gre0 gretap0 ip6_vti0 ip6gre0 ip6tnl0 ip_vti0 sit0 tunl0` | The kernel creates fallback tunnel devices in every new network namespace when `net.core.fb_tunnels_only_for_init_net=0` (the default; kernel docs list tunl0, gre0, gretap0, erspan0, sit0, ip6tnl0, ip6gre0; the vti devices are not named there). Docker's "only loopback" statement covers the devices Docker creates. Complementary evidence all passed: 0 routes (NET-09), every egress attempt `ENETUNREACH` from both containers, all capability sets 0 (no CAP_NET_ADMIN to configure a device), raw and AF_PACKET sockets EPERM. **Not captured:** device state, flags, addresses, counters, sysctl value. Real failure not established; the assertion is broader than the invariant ("no usable path out"). Not proven to be a false positive either. |
| FS-05 | `LC_CTYPE` beyond the image Env keys plus HOME and HOSTNAME | Docker `Config.Env` (keys PATH, GPG_KEY, PYTHON_VERSION, PYTHON_SHA256) contains no `LC_CTYPE`, and the gate verified Env was exactly the image's. The image sets no LANG/LC_*, so CPython starts in the C locale. Per PEP 538 it then sets `LC_CTYPE` (to `C.UTF-8` first) and writes it into its own environment, even under `-I`. The probe read `os.environ` after that. **Not captured:** the exec-time environment (`/proc/self/environ`) and the value. Most likely origin: interpreter coercion, not host inheritance. |

**Diagnostics added (no judgement changed):** the probe script now also records:

- for NET-01: per-interface `operstate`, `flags`, link `type`, `mtu`, `carrier`, IPv4
  address, IPv6 addresses, rx/tx byte counters, and `fb_tunnels_only_for_init_net`;
- for FS-05: `initial_keys` from `/proc/self/environ`, `runtime_only_keys`, and the
  `LC_CTYPE` value (locale names only; anything else withheld).

`tests/unit/test_run2_observations.py` with fixture
`tests/fixtures/docker-29.8.2-run2-observations.json` keeps run 2's real observations
classified as FAIL: the revised checks require evidence that run 2 did not capture.

**Owner decisions (2026-10-11), implemented 2026-10-12** (details in
`docs/architecture/isolation-probes.md` §7):

- **NET-01** is state-based. Fallback tunnel devices may exist but must be down,
  unaddressed, carrier-less, and idle. In the same container, routing must be zero, all
  capabilities zero, and egress blocked. Lists must agree and diagnostics must be
  complete. There is no name allowlist, and unverifiable state never passes.
- **FS-05** checks the startup environment (`/proc/self/environ`) against the image Env
  contract. The only runtime-only addition allowed is CPython's `LC_CTYPE` with value
  `C.UTF-8` or `C.utf8`, absent at startup. Missing or inconsistent evidence fails.
- **Expanded diagnostics are kept.** Only interface facts and environment names are
  collected, plus the `LC_CTYPE` value when it is a locale name.
- **CLN-06** keeps strict network-ID identity.

Tests: `tests/unit/test_net01_fs05_semantics.py`. 13 weakenings of the new rules were
tried on a scratch copy; every one made tests fail.

## PP-003 A4 run 1 — `BLOCKED` (2026-10-11; preserved, not relabeled)

The owner ran `run_isolation_probes.py run` interactively. Run ID
`run-d109d3606276fd75137241a6a1bc6b92`. Evidence (unchanged, 0600) is in
`~/Library/Application Support/PatchProof/probe-runs/run-d109d3606276fd75137241a6a1bc6b92/`:
`run-record.json`, `commands.json`, `inspect.json`, `journal.jsonl`,
`snapshot-before.json`, and `snapshot-after.json`. Active time was 9.004 s.

| Outcome | Probes |
|---|---|
| PASS | PRE-01..03, POL-P1, POL-01..04, CLN-01..06 (9 owned containers removed by exact ID; both decoys refused, then removed; command audit clean; before and after snapshots byte-identical) |
| ERROR | POL-05: the unmutated real inspect did not pass the gate (its internal control) |
| BLOCKED / NOT_RUN | POL-06 BLOCKED; every isolation probe is BLOCKED or NOT_RUN, because no container started and the verifier was never created |

**Root cause:** for all 9 created containers (every role except the verifier), the gate
rejected exactly two fields:

| Field | Gate expected | Docker 29.8.2 returned | Class |
|---|---|---|---|
| `Config.ExposedPorts` | present and empty | key absent (`omitempty`) | representation; incorrect validation assumption |
| `HostConfig.Mounts` | present and empty | key absent (`omitempty`) | representation; incorrect validation assumption |

The real configuration complies. Fields Docker always serializes show both properties:

- **Mounts:** top-level `Mounts` is `[]`; `Binds` and `VolumesFrom` are `null`;
  `Config.Volumes` is `null`; `Tmpfs` holds exactly the two approved tmpfs mounts.
- **Ports:** `PortBindings` is `{}`; `PublishAllPorts` is `false`; `NetworkSettings.Ports` is
  `{}`; `NetworkMode` is `none`.

Every other inspected field matched: platform linux/amd64 through
`ImageManifestDescriptor`, `ShmSize` 16777216, `SecurityOpt`, capabilities, user,
read-only root, limits, and log configuration.

The rejection was **correct fail-closed behavior**. The gate could not establish the
property from the evidence it expected, so it refused to start anything. There was no
security violation.

**Fix** (`src/patchproof/runner/inspect_gate.py`, `_OMITEMPTY_CORROBORATED`): an absent
`HostConfig.Mounts` or `Config.ExposedPorts` is accepted **only** if every
always-serialized corroborating field is present and in its exact empty or false form.
Anything missing, malformed (for example `Mounts: false`), or contradictory still fails
closed. Present non-empty values still fail as before. All other checks are unchanged.

**Regression evidence:** `tests/fixtures/docker-29.8.2-inspect-created.json` holds the real
inspect output for the 9 roles, sanitized: IDs, timestamps, the probe script, the nonce,
and run/installation/digest label values are placeholders; no host paths were present.
`tests/unit/test_inspect_gate_docker29.py` covers: all 9 real representations pass; 17
unsafe or unproven variants of the real output fail; explicitly empty forms are still
accepted; the POL-05 drift mutations are rejected on the real output; other security
fields are still enforced. Re-gating the original captured data with the fixed gate:
all 9 pass, with no other mismatch.

**Still untested on the real runtime:** the verifier's inspect shape (`--network
container:`); post-start behavior; and every isolation probe.

## PP-003 phase A3 — evidence directory created (2026-10-11)

Before anything was created, every path component was checked with `lstat`. There
are no symlinks; `/Users` is root-owned (macOS default); `~`, `~/Library`, and
`~/Library/Application Support` are owned by uid 501; only the two approved leaves were
missing. Each was created with a single-level `mkdir`, mode 0700, refusing if it
already existed. Nothing existing was modified, and nothing was done recursively.

Verified afterwards: `~/Library/Application Support/PatchProof` and `.../probe-runs` are
both real directories, owner 501, mode 0700, with no ACLs. `probe-runs` is empty, and the
runner's own `verify_evidence_root` passes. No installation ID or run evidence was written.

## Global execution deadline and cleanup window (owner-approved 2026-10-11)

- **Active probing:** a monotonic 20-minute budget (`GLOBAL_DEADLINE_SECONDS`). The single
  executor wrapper checks the remaining budget before **every** Docker operation and
  refuses once it is spent. It caps each operation's timeout at the remaining budget.
- **On expiry:** no new probe starts, completed observations are kept, and the expiry
  and its phase are recorded in the record's `execution` block. Unfinished checks become
  NOT_RUN or INCONCLUSIVE. RES-15 is INCONCLUSIVE, so the suite can never be reported as
  passed, and the record builder and schema refuse a "passed" status after expiry or
  interruption.
- **Cleanup:** a separate monotonic 2-minute window (`CLEANUP_WINDOW_SECONDS`), used after
  normal completion, expiry, or interruption. Each tracked, ownership-verified container
  gets one removal attempt (graceful stop, then exact-ID rm, then the verified force
  fallback). The read-only after-snapshot runs in the same window. If the window
  expires, the remaining containers are `FAILED` with `CLEANUP_FAILED` detail, and the
  record shows `cleanup_status: CLEANUP_FAILED`. There is no retry and nothing broader.
- Budgets above 20 min or 2 min are refused in code.
- Tests: `tests/unit/test_probe_deadline.py`, using a synthetic monotonic clock.

## Verifier storage contract and other writable filesystems (2026-10-11)

The owner approved execution-profile contract 1.1 (2026-10-11): verifier 112 MiB
`/scratch` plus 16 MiB `/tmp` (128 MiB of application scratch); target 256 MiB plus
64 MiB; a separate 16 MiB `/dev/shm`.

**Versions are kept side by side, as ADR-008 requires:**

- `schemas/execution-profile.schema.json` is contract **1.0**
  (`urn:patchproof:schema:execution-profile:1.0`). It is byte-identical to the version
  accepted at `682ef63`, pinned by sha256 in `tests/unit/test_schema_versions.py`, and its
  1.0 examples are unchanged.
- `schemas/execution-profile.v1.1.schema.json` is contract **1.1**
  (`urn:patchproof:schema:execution-profile:1.1`), with `schema_version` const `"1.1"` and
  its own `containerLimits`. In it, `scratch_tmpfs_bytes` means `/scratch` only (its
  original meaning), and `tmp_tmpfs_bytes` is a new required field. The examples use the
  `execution-profile.v1.1--` prefix.
- Neither version validates the other's records. The PP-003 runner accepts only 1.1 and
  refuses 1.0 as unsupported, without migrating or reinterpreting it. The shared
  `common:1.0` definition is unchanged.
- Naming rule for later versions: `<record>.v<version>.schema.json`. `test_schemas.py`
  derives the expected `$id` from the file name.

Compatibility: the 1.1 reference profile is `profile_version 0.2.0`, so its hash differs
from any 1.0 profile. Any approval bound to a 1.0 profile hash cannot be reused for 1.1
and needs reapproval. None exists: approval records are PP-007, and the approval
example's `profile_sha256` is a synthetic placeholder.

Writable filesystems for the container user, kept distinct:

| Location | Bound | Part of the 128 MiB budget? |
|---|---|---|
| `/scratch`, `/tmp` | tmpfs size (112 + 16 MiB verifier; 256 + 64 MiB target) | Yes |
| `/dev/shm` | **New fixed `--shm-size 16777216`** (Docker's private-IPC default is 64 MiB). Gate checks `ShmSize`; mount classification requires tmpfs nosuid/nodev/noexec at 16 MiB or less; RES-14 fills it | No |
| `/dev/mqueue` | Kernel `RLIMIT_MSGQUEUE` (not configured by PatchProof) | No |
| `/etc/hosts`, `/etc/hostname`, `/etc/resolv.conf`, `/dev` | Root-owned; FS-08 and FS-10 expect a write to fail | n/a |

The 128 MiB budget does **not** bound every writable filesystem, and it does not bound
total memory. tmpfs pages count against each container's memory limit. The new FS-10
census expects a file to be creatable only under `/scratch`, `/tmp`, `/dev/shm`, or
`/dev/mqueue`.

## PP-003 phase A2 — image identity approved (2026-10-11)

Revalidated read-only by full ID (`docker image inspect sha256:70729b46…c2f`) before the
change. Id, Descriptor digest, and RepoDigest all equal
`sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f`. Os linux,
Architecture amd64, RepoTags `python:3.13-slim`, no Volumes or Entrypoint. All checks
passed. Applied:
`APPROVED_PROBE_IMAGE_ID = "sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f"`
and `APPROVED_PROBE_PLATFORM = "linux/amd64"` in `src/patchproof/runner/policy.py`.
Recorded in `docs/environment.lock.md` §4.6. No pull, no container.

**Owner-approved pre-execution corrections (applied with A2):**

| Decision | Implementation |
|---|---|
| Verifier storage | 112 MiB `/scratch` plus 16 MiB `/tmp`. `check_limits` enforces a combined writable ceiling: verifier 128 MiB, target 320 MiB. For a verifier, a profile's `scratch_tmpfs_bytes` is read as the whole 128 MiB budget, so the accepted PP-002 example remains valid. **Owner confirmation of this mapping is requested; PP-008 owns the final mapping.** |
| PRV-10 | Namespace and mount attempts now run in forked children. Before this, a permitted `unshare` would have contaminated every later probe. PRV-10: namespace operations that need CAP_SYS_ADMIN, plus unshare(NEWUSER\|NEWNS), must fail with EPERM. New PRV-13 records plain unshare(NEWUSER) as permitted or denied (both accepted); if permitted, using it on the container's namespaces must fail. New PRV-P5 is the control for the child channel. |
| Cleanup escalation | Stop with 5 s grace, then ordinary exact-ID rm. Only if the container is still running after a fresh inspect that reconfirms ownership: `ForceRemove` (`rm --force -- <id>`, fixed shape). It is recorded as `FORCE_REMOVED`; otherwise the result is `FAILED` with `CLEANUP_FAILED` detail. Decoys never force. The CLN-05 audit rejects any force without the prior failure and re-inspect. |
| Platform and pull | Every create carries `--platform linux/amd64 --pull=never` and the approved ID. The gate checks the executed argv exactly, `Platform`, and `ImageManifestDescriptor.platform` when present. PRE-03 checks the same. |


## PP-003 phase A1 — image acquired (2026-10-11, owner-approved)

Executed exactly `docker --context desktop-linux pull --platform linux/amd64 python:3.13-slim`.
Exit 0. Docker reported `Digest: sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f`.

| Fact (from `docker image inspect`) | Value |
|---|---|
| Reference | `docker.io/library/python:3.13-slim` (Docker Official Images namespace). Signatures and provenance were **not** verified. |
| Image ID | `sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f` |
| RepoDigests | `python@sha256:70729b46…c2f`, the same value |
| Why ID = digest | The daemon uses the containerd image store (`driver-type io.containerd.snapshotter.v1`). The ID is the digest of the multi-platform OCI **index** (`application/vnd.oci.image.index.v1+json`, 10373 bytes). Only the `linux/amd64` platform content is stored locally; its manifest ID is shown truncated as `8fb4cfa1a261` |
| Os/Architecture | linux/amd64 |
| Size | 176147023 bytes (Docker reports 178 MB disk, 45.3 MB content) |
| Created | 2026-10-06T02:05:24Z |
| Python | `PYTHON_VERSION=3.13.16` |
| Config | No User, Entrypoint, WorkingDir, Volumes, ExposedPorts, or Labels. `Cmd ["python3"]`. Env keys: PATH, GPG_KEY, PYTHON_VERSION, PYTHON_SHA256. 4 layers. |

**Preservation:** before and after the pull, by identity fields: images 9 → 10, with exactly
one added (the image above) and none removed, including dangling `056b54f00419`.
Containers 7 = 7, volumes 10 = 10, networks 5 = 5, build cache 77 = 77. No
PatchProof-labeled containers. No errors.

**Not done:** A2 (`APPROVED_PROBE_IMAGE_ID` is still `None`), A3, and A4. No container was
created.

## PP-003 phase A0 — `READY_FOR_REVIEW` (2026-10-11)

Owner approval of A0 was given in the 2026-10-11 session prompt: implement the runner and
probes, write tests, run Docker-free tests, debug, and update documentation.

**Delivered** (design: `docs/architecture/isolation-probes.md`):

| Area | Files |
|---|---|
| Fixed policy, code-level ceilings, A2 image constant | `src/patchproof/runner/policy.py` |
| Typed Docker CLI wrapper, bounded subprocess execution | `src/patchproof/runner/docker_cli.py` |
| Inspect-before-start gate (55 fields) | `src/patchproof/runner/inspect_gate.py` |
| Exact-ID, label-checked cleanup; write-ahead journal; interrupted-run recovery | `src/patchproof/runner/cleanup.py` |
| 77-probe catalogue with positive controls | `src/patchproof/probes/catalogue.py` |
| In-container probe script (stdlib, emits facts only) | `containers/probes/isolation_probe.py` |
| Pure interpretation | `src/patchproof/probes/interpret.py` |
| Bounded evidence record; honest control claims | `src/patchproof/probes/evidence.py`, `schemas/isolation-probe-run.schema.json` |
| Orchestration, CLI, launcher | `src/patchproof/probes/orchestrator.py`, `src/patchproof/probes/cli.py`, `containers/probes/run_isolation_probes.py` |
| Tests | `tests/conftest.py`, `tests/unit/_fakes.py`, `tests/unit/test_runner_policy.py`, `test_docker_cli.py`, `test_inspect_gate.py`, `test_cleanup.py`, `test_probe_interpret.py`, `test_probe_evidence.py`, `test_probe_orchestrator.py`, `test_probe_script.py` |
| Schema corpus additions | `schemas/examples/valid/isolation-probe-run--not-executed.json`, 6 `schemas/examples/invalid/isolation-probe-run--*.json`; `tests/unit/test_schemas.py` gained 7 table entries and no other change |

The probe catalogue (82, after the RES-15 deadline probe was added): 3 preflight,
12 network, 13 filesystem, 18 privilege, 3 namespace, 20 resource, 7 policy, and
6 cleanup and preservation probes. By kind: 40 negative, 17 positive control,
14 configuration, 5 policy refusal, and 6 cleanup. Every negative
probe has a positive control or an internal control; this is enforced in code.

**Corrections to the earlier execution plan** (details in the design doc, §4):

- The CPU probe used Python threads. The GIL would make it pass without any limit, so it
  now uses forked processes.
- `ptrace` was expected to be blocked, but default seccomp allows it. Replaced by `keyctl`.
- Stdin delivery of the script could hang. The script is now passed as one `-c` argument.
- Root-filesystem writes now include world-writable `/var/tmp` and require EROFS.
- The exact mount allowlist became a classification, so Docker's default masks do not
  fail it falsely.
- The container reports facts only; it never decides PASS or FAIL.

**A0 decisions, as resolved:**

1. A2 as a code constant: applied (see A2 above).
2. Verifier storage: resolved, 112 + 16 MiB.
3. PRV-10: revised. PRV-09 (`keyctl` EPERM) and the PRV-10 expectations still rest on
   Docker's documented default profile. They have not been checked against 29.8.2.
4. The `patchproof doctor --probe-isolation` wrapper still waits for packaging (approval
   item 2).

**Not executed, and only real Docker execution can settle it:** see "Controls still
unverified" below.

## Accepted issues

### PP-008 — `ACCEPTED` by owner, 2026-10-14

**Scope:** the target/verifier runner and typed event transport, with:
- gated execution and pack approval (including supersession);
- the single-use run authorization;
- evidence persistence and inventory reconciliation;
- the limited recovery command;
- evidence hardening (`docker-ops-v2`, separate untrusted output artifacts, real `evaluated_at`);
- the separate interruption-test contract, controller, child and baseline-only driver.

**Commits:** implementation checkpoints `98b5cf8`, `e25f106`, `b2cdedd`, `48e2d8e`; evidence closeout
`c33d580`; this acceptance commit. All local, not pushed, not tagged.

**Live evidence** (owner-executed, each independently audited read-only):
- `run-036553ef7b032f59955cc4a790409931`: r1 against r3, `COMPLETE`/`FINALIZED`, `VERIFIED_FOR_CASES` (V-09),
  16/16 trusted cells, 4 containers created and removed (`docs/evidence/pp-008-first-live-comparison.md`;
  audit 164/164 checks).
- `run-6cee8893b1a0a58690be96bf23fa56b1`: one SIGTERM at `baseline-target-ready`, `INTERRUPTED`/`INCOMPLETE`,
  cleanup `COMPLETE`, `INCONCLUSIVE` (V-05), lifecycle exit 20, controller `EXPECTED_OUTCOME_OBSERVED`, 2
  containers created and removed, verifier and candidate never executed
  (`docs/evidence/pp-008-interruption-demonstration.md`; audit 159/159 checks).

**Gate** (`docs/evidence/pp-008-acceptance-gate.md`): 15 requirements, all PASS.
- At the gate, the accepted `verify_evidence` re-reported both runs and the controller record
  `CONSISTENT`.
- All private evidence, authorization, claim and approval files were identical to the audit
  snapshots.
- Both authorizations are consumed. The current approval `apr-f4b493f9…` is `APPROVED`; the
  superseded `apr-f30bd943…` is unchanged.

**Validation (2026-10-14):**
- 8,667 Docker-free unit tests passed, 0 failed;
- `mypy --strict src`: no issues in 70 files;
- the documented Ruff gate (`--select E,F,W,B,UP --line-length 120 src containers`): clean;
- `ruff check src tests` with project defaults: only the 11 pre-existing E501 findings in unchanged
  test files.

The committed tree was validated separately (see the PP-008 acceptance commit's report).

**Accepted limitations (L1–L12 in the gate report):**
- non-substantive interruption-authorization rationale and scope; the record is kept and no
  signed note is required;
- configuration evidence, not kernel proof;
- structured witnesses without raw responses;
- locally asserted reviewer identity;
- no wall-clock time for the checkpoint;
- journal v1 for the successful run, and the hardened verifier-console path not yet live-demonstrated;
- shell exit codes not captured;
- the preflight's one FAILED auxiliary diagnostic (exit code 1 hidden by `tee`) is preserved;
- network-identity attribution relies on Docker Desktop's external log;
- the deprecated `--time` stop flag is unchanged;
- the host pytest advisory remains separate;
- the claim covers one pair, one fixed fixture and 8 checks.

### PP-002 — `ACCEPTED` by owner, 2026-10-11

Accepted scope:

- the verdict specification, including owner decisions D1–D6;
- ADR-008 (strict schema contracts) and ADR-009 (container security policy as code);
- the reviewed verdict scenarios and the schema-validation requirements.

Accepted at commit `682ef63039df72ecdb3de13d2861c4dea8cda9fd`. Validation evidence at
that commit: 201 passed, 0 failed, 0 skipped, plus the weakening and invariant checks
recorded under "Failed tests, risks, and blockers".

PP-002 was documentation and data-contract work. No software was installed, no container
run, no target executed, and no network used.

PP-002 evidence:

| Artifact | Contents |
|---|---|
| `docs/threat-model.md` | Assets, trust zones, nine trust boundaries (STRIDE), the eight §4.3 abuse cases with planned mitigations and the issue owing evidence, invariant coverage |
| `docs/architecture/verdict-specification.md` | Engine inputs; pytest event grammar and lifecycle derivation; local vs global stream failures; host-confirmed execution trust E1–E4; cell trust T1–T5; input validation M1–M7/G1–G5; execution-start definition; decision table V-01–V-10; independent flags; reason/detail rules; decided D1–D6; 26-scenario truth table; properties P-1–P-9 |
| `docs/adr/ADR-001`–`ADR-007` | The §3.3 decisions, recorded |
| `docs/adr/ADR-008`, `ADR-009` | **Accepted by owner 2026-10-11**, with recorded conditions: schema contracts; container policy is code, not profile data |
| `schemas/*.schema.json` | 9 schemas: `common`, `pack-manifest`, `execution-profile`, `approval-record`, `verifier-event`, `observation`, `execution` (new), `verdict-input` (new), `verdict` |
| `schemas/examples/valid/` | 10 standalone example records |
| `schemas/examples/invalid/` | 52 rejection examples, each pinned to the keyword and location it must fail on |
| `schemas/examples/scenarios/` | 26 engine-input / expected-verdict pairs: the review-controlled truth table PP-004 must reproduce |
| `tests/unit/test_schemas.py` | Machine validation of all of the above, plus a check that the specification's scenario table matches the corpus |
| `PROJECT_SPEC.md` | Amended §5.2 (per-execution result cap enforced from the host byte count, D6), §13.2, §17.3 items 3, 6, 9, 11 |

**Owner decisions** recorded in `verdict-specification.md` §11:

- **D1–D5**, decided in the 2026-10-11 review.
- **D6**, decided in the acceptance-readiness review: a result-cap overflow invalidates
  only the affected `(pair, side)` execution. The engine enforces this from the
  host-observed byte count (scenarios S24–S26).
- **ADR-008 and ADR-009 accepted**, with conditions recorded in each ADR.

PP-002 acceptance is acceptance of that issue only. **It is not the v0.0 release gate.**

**Acceptance-readiness review (2026-10-11) also changed two things:**

- `pairs_completed` was split into `pairs_terminated_normally` (execution only) and
  `pairs_with_trusted_evidence`.
- `EXECUTION_CANCELED` was added, so every suppressed abnormal-termination code has an
  explaining code for the same execution. Raw termination facts stay in the execution
  records.

**Obligations carried forward:**

- PP-004 must implement the engine and reproduce all 26 scenarios.
- PP-007 owes Pydantic/JSON Schema parity tests (ADR-008).
- PP-008 owes safe encoding and bounding of target-derived event content (D6) and
  code-level resource ceilings (ADR-009).

## v0.0 closeout assessment (2026-10-12; C1–C3 since implemented, see above)

Against `PROJECT_SPEC.md` §15.1 and §13.1:

| §15.1 requirement | State |
|---|---|
| Build: environment report, threat model, ADRs, strict schemas, pure verdict prototype, harmless probe suite | Done (PP-001..PP-004 accepted) |
| Build: repository skeleton | **Partial.** No `pyproject.toml`, `uv.lock`, or pinned interpreter; the code runs from `src/` by path |
| Capability: `patchproof doctor` describes the actual Intel Mac and verifies topology, limits, read-only mounts, non-root, no egress, verifier-file and socket invisibility | **Missing as a command.** The verification exists (PP-003 runner), but `patchproof doctor` and `doctor --probe-isolation` (§13.1, "available by v0.0") do not |
| Exit: owner reviews the detected environment and necessary installations | **Pending.** Needs a current report: Docker was upgraded since PP-001; Python 3.13.1 and Git 2.42.0 are still unpatched |
| Exit: every required runtime restriction has a recorded tested result | Done (PP-003 run 3, 82/82) |
| Exit: unit tests cover the verdict truth table, including crash/skip/no-baseline | Done (PP-004) |
| Exit: no probe leaves unrelated changes or containers | Done (CLN-06, all three runs) |
| Exit: STATUS records v0.0 passed only after actual evidence | Pending owner gate review |
| Demo: harmless file-read isolation check, blocked external connection, deliberately invalid policy refused | **Pending.** Recorded evidence exists (FS-06/07, NET-02..07, POL-01..04); a live demonstration needs a separately approved execution |

**Recommended minimal work package: "v0.0 closeout"**, one item tracked in
`docs/backlog.md` under v0.0, in four phases with separate approvals:

1. **C1 Packaging.** `pyproject.toml` (src layout; console script `patchproof`),
   `.python-version`, `uv.lock`; tests via `uv run pytest`.
   - Runtime dependencies: Typer (the CLI framework chosen in §3.1) and platformdirs
     (§5.3 private-state paths).
   - Development dependencies: pytest, jsonschema, referencing, mypy, ruff. Hypothesis is
     optional and deferred.
   - Each dependency's source and version are verified and documented (CLAUDE.md).
2. **C2 `patchproof doctor`**, read-only. It reports: OS and hardware; Git, Python, and uv
   versions; Docker context endpoint, client and server versions, and `docker info`
   security fields; presence and identity of the approved probe image; evidence-root
   state; and outstanding environment approvals. It makes no changes and stays
   Docker-free in unit tests through a fake executor.
3. **C3 `patchproof doctor --probe-isolation`**, a thin Typer wrapper over the existing
   runner. It keeps the same A2/A3/A4 gates, the interactive confirmation, the deadlines,
   and the policy. The probe logic and expectations are unchanged.
4. **C4 Gate review and demonstration.** One owner-approved run of
   `patchproof doctor --probe-isolation`, which also serves as the §15.1 live demo; the
   invalid-policy refusal is shown Docker-free. Then the owner's gate review.

**Approvals the work package needs:**

- **C1:** install the current Python 3.13.x (download), or explicitly accept 3.13.1 for
  v0.0; resolve and lock dependencies from PyPI (`uv lock`, network); create the project
  virtual environment (`uv sync`, installs packages into `.venv`).
- **C2:** read-only Docker queries from `doctor`, the same kind already performed in
  PP-001 and PP-003.
- **C4:** one probe execution (a new A4-type run).
- Separately, and not blocking v0.0 unless the owner decides otherwise: `brew upgrade
  git` (needed by PP-005); removing `~/.git`; committing the owner's ADR-010 work.

## Last completed gate and its evidence

**v0.0 foundation release: `ACCEPTED` by owner, 2026-10-12.** Evidence commit `d1bcbfc`;
gate checklist `docs/evidence/v0.0-release-gate.md`; C4 run
`run-883e1a62b93ced171a8cd9275ceb9a66`. No later release gate has passed.

| Issue | Accepted | Evidence |
|---|---|---|
| PP-001 | 2026-10-11 | `docs/environment.lock.md` |
| PP-002 | 2026-10-11 | commit `682ef63`; see "Accepted issues" above |
| PP-003 | 2026-10-12 | commit `e38d0d1`; run `run-5c176591e0f793ebdb6c2f07667c4ead`; `docs/evidence/pp-003-isolation-probes.md` |
| PP-004 | 2026-10-12 | commit `37ec588`; 6923 unit tests; 26/26 verdict scenarios |
| v0.0-CLOSEOUT | 2026-10-12 | C1–C3 commit `62887bf`; C4 run `run-883e1a62b93ced171a8cd9275ceb9a66` (82/82); evidence commit `d1bcbfc`; 7008 unit tests |
| **v0.0 release** | **2026-10-12** | `docs/evidence/v0.0-release-gate.md` |
| PP-005 | 2026-10-12 | commit `c8128a7`; acceptance `aa3a0a3` (pushed); 7337 unit tests |
| PP-006 | 2026-10-12 | commit `4b8f288`; acceptance `22c43dd` (pushed); 7439 unit tests; `docs/architecture/papertrail-reference.md` |
| PP-007 (implementation) | 2026-10-12 | commit `698e78d`; acceptance `d85b6db` (pushed); 7964 unit tests; parity 160/160 and 223,815 mutations; mutation check 34/35 (M26 equivalent); no pack approved; `docs/architecture/packs-and-approvals.md` |
| PP-008 | 2026-10-14 | checkpoints `98b5cf8`, `e25f106`, `b2cdedd`, `48e2d8e`; evidence `c33d580` (local, not pushed); runs `run-036553ef…` (V-09) and `run-6cee8893…` (V-05); 8,667 unit tests; `docs/evidence/pp-008-acceptance-gate.md` |

## Next permitted issue

**PP-009 — CLI workflow and JSON/Markdown evidence: `IN_PROGRESS`, READY_FOR_REVIEW** (2026-10-14; see the
PP-009 section above). PP-010 has not started. The PP-008 handoff obligations, and where they now stand:
1. general CLI workflow and safe JSON/Markdown reports: implemented (Docker-free; live CLI run still owed);
2. meaningful owner-entered rationale and scope validation for run, interruption and approval authorizations:
   implemented for every owner command (stored records untouched);
3. fail-closed preflight reporting: MANDATORY/DIAGNOSTIC `Preflight` implemented; pipeline exit codes
   documented (`set -o pipefail` or `PIPESTATUS`) and `report --output` avoids `tee`;
4. a controlled end-to-end check of the hardened verifier-console and operation-journal capture in a live
   verifier execution: planned in `docs/architecture/cli-workflow.md`, NOT executed (separate owner approval);
5. safe handling of the accepted response-retention and export limitations: allowlisted reports, documented.
Open separate obligations: host pytest advisory remediation; the deprecated Docker stop flag `--time`
(reviewed policy change). v0.1 is NOT YET ACCEPTED.

## Failed tests, risks, and blockers

**Tests (after the NET-01/FS-05 decisions, 2026-10-12):** `tests/unit`: **757 passed, 0 failed,
0 skipped**. 688 after the run 2 diagnostics, 683 after the run 1 gate fix. Earlier counts: 650 before A4, 620 after A3, 604 after A2, 559 at A0.
Weakening checks on the fix all fail tests: accepting absence without corroboration
(12 failures), accepting `null` as `PublishAllPorts: false` (1), and reverting the fix (14).
None contacts Docker. The bounded-execution tests start a local Python interpreter;
the Docker-free CLI tests replace `subprocess.Popen` with a function that fails the test
if called. Command:

```
env -u PYTEST_ADDOPTS -u PYTEST_PLUGINS -u PYTHONPATH PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  python3 -I -m pytest tests/unit -p no:cacheprovider -q
```

Also clean: `python3 -m mypy --strict src/patchproof`, and
`ruff check --select E,F,W,B,UP --line-length 120 src containers`. These are the host's
existing mypy 1.18.2 and ruff 0.14.2; nothing was installed.

**Failures found and fixed during A0** (no assertion was weakened to pass):

- Code: a memory container that was *not* OOM-killed would have been reported
  INCONCLUSIVE instead of FAIL, because its observation was rejected as foreign. Fixed.
- Code: "0 of 0 decoys removed" was judged FAIL after an interrupted run. It is now NOT_RUN.
- Code: NS-02 reported INCONCLUSIVE when no container ran. It is now NOT_RUN, like every
  other probe.
- Code: `run` wrote the installation-ID file into the evidence directory before the A4
  confirmation. It now writes nothing before confirmation.
- Code: the catalogue validator rejected RES-13, which had no positive control. An
  internal control was added.
- Tests: three test bugs were fixed. A prefix check matched `--pid` inside
  `--pids-limit`; the injection test compared the script-digest label; and an
  assertion expected container IDs on create operations.

**PP-003 weakening checks** were run on a scratch copy outside the repository. Each of
23 deliberate weakenings made at least one test fail:

- argv: drop `--read-only`; drop `--cap-drop ALL`; target network `host`; `rm --force`.
- Inspect gate: ignore `Privileged`; ignore `Binds`.
- Policy: no ceiling check; tags accepted as image IDs; ownership ignores the run label;
  A2 gate bypass; evidence root may be `0755`.
- Interpretation: no control propagation; no stream demotion; nonce not checked; FS-01
  accepts EACCES; TIMEOUT counts as blocked; CPU threshold loosened; unknown errno
  passes; the suite ignores FAIL; 0 decoys counts as a pass.
- Evidence: record completeness check removed; schema allows "passed" with failures;
  claims ignore evidence type.

In the first round, 3 of the 23 were not caught: record completeness, A2 bypass, and
0-decoys. Tests were added for them; then all 23 were caught.

**After the A2 corrections**, 10 further weakenings were tried: drop `--platform`;
`--pull=missing`; the gate skips argv; the gate ignores manifest platform; force without
an ownership recheck; force when not running; the audit ignores force order; PRV-13
ignores post-checks; no combined writable ceiling; verifier scratch back to 128 MiB.
All are caught, along with all 23 earlier ones.

**After the A3 changes**, 8 more weakenings were tried: the initial ownership guard off;
drop `--shm-size`; the gate ignores `ShmSize`; `/dev/shm` size unchecked; the census
allows any location; profile 1.0 accepted; schema `tmp_tmpfs_bytes` optional. The last
one was not caught at first; the rejection example `execution-profile--missing-tmp-size.json`
was added. Disabling either ownership guard fails that guard's dedicated test for a
running container from another run (`test_running_other_run_container_is_refused_without_force`,
`test_escalation_step_itself_refuses_another_runs_container`).

**Final pre-A4 corrections**, 9 more weakenings were tried: the budget check removed;
operation timeouts not bounded; RES-15 passes after expiry; no separate cleanup window;
the record allows a pass after expiry; window expiry reported as removed; budget ceiling
unchecked; the v1.0 schema edited; and (re-run structurally) the schema's pass rule and
the required `tmp_tmpfs_bytes`. All are caught.

One more mutation is not caught: "decoys may force". It is equivalent rather than a gap.
Started decoys are refused before cleanup, and a stopped decoy can never reach the force
step, because force requires a re-inspect showing it still running.

**PP-002 tests (unchanged):** 201 passed at acceptance (2026-10-11, after D6).

Earlier in remediation, one run failed because the scenario-table regex in the test
rejected uppercase directory names. I fixed the regex, not the data.

**D6 weakening checks**, run on a scratch copy outside the repository:

| Weakening | Result |
|---|---|
| S25 expected verdict reverted to global `INCONCLUSIVE` | 2 tests failed |
| S26 `RESULT_CAP_EXCEEDED` detail dropped | 1 test failed |
| `result_cap_bytes` made optional | 1 test failed |

**Independent invariant check** of all 26 scenarios against `PROJECT_SPEC.md`, using
logic separate from the evaluator:

- no false `VERIFIED_FOR_CASES`;
- no `NOT_FIXED` without a clean candidate violation;
- no trusted violation lost outside the deliberate global-failure case S21.

**Earlier weakening checks** (remediation pass, on a scratch copy outside the repository). Each deliberate weakening
must make at least one test fail:

| Weakening | Result |
|---|---|
| S04 expected verdict relabeled `INCONCLUSIVE` | 1 test failed |
| `INCONCLUSIVE` ⇒ no `candidate_violation` guard removed | 1 test failed |
| `verdict-input` `uniqueItems` removed | 1 test failed |
| `COMPLETE` ⇒ `session_end_received` guard removed | 1 test failed |
| S12 row removed from the spec table | 1 test failed |
| S12 expected verdict changed to `NOT_FIXED` | 2 tests failed |
| `PRECONDITION_NOT_EVALUATED` guard removed | 1 test failed |

All seven were caught.

**Limit of these checks:** changing an expected verdict *and* its row in the spec table
together is not detectable by tests. That is what owner review of the corpus is for.

**How the expected verdicts were produced.** A scratch reference evaluator applied the
specification literally. It was kept in the session scratchpad and is **not** committed;
it is not the PP-004 engine. Each scenario's verdict, rule, and key flags were also
specified by hand, and generation fails on any disagreement. All 26 agreed.

**Validation tooling is not pinned.** The tests use `jsonschema` 4.25.0,
`referencing` 0.36.2, and `pytest` 8.4.2. These were already installed in the host
Python 3.13.1 (`/Library/Frameworks/Python.framework/Versions/3.13`); nothing was
installed. There is still no `pyproject.toml` or `uv.lock`. PP-004 packaging must pin
these, or replace them, after source verification (ADR-008).

**Not executed:** no runtime code exists, so no schema is enforced by an application yet.
"PP-002 schema" controls in the threat model are data-shape controls only.

**Blockers and risks, highest first:**

1. **A second Git repository owns the home directory.** `/Users/aliel-asmar/.git`
   exists with 0 tracked files and remotes pointing at unrelated projects. Every
   file in `~` — including `.ssh/`, `.aws/`, `.config/` — reports as untracked
   there, so `git add -A` with that worktree root would stage private credentials.
   This project now shadows it and is contained; the home repository is untouched.
   See `docs/environment.lock.md` §6.1.

2. **No isolation property measured.** The daemon is running on the upgraded runtime
   and its configuration is recorded (`docker info`: server 29.8.2, cgroup v2,
   seccomp builtin, `null` network driver available, 16 CPUs, 7.75 GiB VM). That is
   capability, not enforcement. Invariants INV-01 through INV-03 remain
   **unverified**, because verifying them requires running containers — PP-003. The
   §15.1 exit gate requires a recorded tested result per restriction; none exist.
   v0.0 cannot pass on this report alone. PP-003 is no longer blocked by the runtime
   and needs only approval to run.

3. **Unrelated Docker resources are present and must survive.** The daemon holds 9
   images (~4.4 GiB) and 7 stopped containers from other projects, last used 7–14
   months ago. §5.4 forbids pruning or deleting unrelated resources and PP-014 must
   prove they are preserved. This is now the concrete baseline for that test. No
   PatchProof code path may call `docker system prune` or any unfiltered bulk
   removal. See `docs/environment.lock.md` §4.3.

4. **Git 2.42.0 is roughly three years old** (installed 2023-09-06; current stable
   2.56.0). §9.2 requires a supported patched release, and the snapshot path depends
   directly on Git object reading. Oldest-risk component measured.

5. **Python 3.13.1 is behind on patches.** Pin an approved 3.13.x before generating
   `uv.lock`, so the lockfile is produced once against an approved interpreter.

## Changes requiring owner approval

In the order they block work:

| # | Approval needed | Unblocks |
|---|---|---|
| 1 | ~~Owner review of PP-003~~: **ACCEPTED 2026-10-12** (commit `e38d0d1`) | — |
| 2 | ~~Install current Python 3.13.x and pin it~~: **done 2026-10-12** (3.13.16 via uv 0.12.24; v0.0 closeout C1) | — |
| 3 | ~~`brew upgrade git` (2.42.0 → 2.56.0)~~: **done 2026-10-12** (`environment.lock.md` §3.2) | — |
| 4 | ~~Decide whether to remove `/Users/aliel-asmar/.git`~~: **RETAINED** by owner decision 2026-10-12; the hazard remains | — |
| 5 | ~~Claude Code permissions~~ — closed by the owner's ADR-010 decision (2026-10-11). The ADR-010 file and its `CLAUDE.md`/`PROJECT_SPEC.md`/threat-model edits are uncommitted in the working tree. | — |

### PP-003 operations

**A1, done 2026-10-11:** `docker --context desktop-linux pull --platform linux/amd64 python:3.13-slim`.
**A2, approved and applied 2026-10-11:** image `sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f`.

Proposed for approval (not executed):

**A3, done 2026-10-11:** `~/Library/Application Support/PatchProof/probe-runs`, mode 0700.

**A4 — run the suite.** First review the exact argument arrays (Docker-free):

```
python3 -I containers/probes/run_isolation_probes.py plan --image-id sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f
```

Then run it:

```
python3 -I containers/probes/run_isolation_probes.py run \
  --image-id sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f \
  --evidence-root "$HOME/Library/Application Support/PatchProof/probe-runs"
```

`run` asks you to type `run <12 hex>` interactively. It then runs read-only preflight
(`context inspect`, `version`, `image inspect`, five listings), and creates ten
containers, at most two at a time. Eight are started; two decoys never start. Every
container is gated by inspect before start and removed by exact ID. The run ends with
a second listing and an exact preservation comparison. Every create carries
`--platform linux/amd64 --pull=never` and the approved ID. A container that a graceful
stop cannot stop is force-removed only after its ownership is reconfirmed. The run writes `run-record.json`, `commands.json`, `inspect.json`,
`journal.jsonl`, the per-container stdout, and the snapshots to
`probe-runs/<run-id>/`, all mode 0600. Exit codes: 0 all probes passed, 1 isolation
failed, 20 inconclusive/incomplete/harness invalid, 21 blocked.

Afterwards, sanitized results go to `docs/evidence/` for owner review. That step is not
started.

### Runtime restrictions: status after A4 run 3

Every planned restriction has a recorded tested result on this runtime (Docker Desktop
4.94.0 / Engine 29.8.2, 2026-10-12): 21 controls ENFORCEMENT_EXERCISED and 4
CONFIGURED_ONLY. The four are `no-new-privileges`, `no-host-namespaces`,
`no-host-environment`, and `no-published-ports`; see the reviewer notes in
`docs/evidence/pp-003-isolation-probes.md`. (Corrected 2026-10-12: an earlier version of
this line named the wrong four.) This covers one run on one installation. It is not a guarantee
against container-runtime vulnerabilities (§4.1). Re-verify after Docker Desktop
upgrades.

**Cleared 2026-10-11:** Docker Desktop upgraded 4.42.1 → 4.94.0 (server 29.8.2). The
runtime now meets §5.1 and all advisories listed in `docs/environment.lock.md` §6.5
are patched. Note Docker Desktop on this host is **not** Homebrew-managed; use the
in-app updater or the Intel `.dmg`.

## Is the current release safe to demonstrate?

**Not yet as the v0.0 demonstration.** All three §15.1 demo items now have real
recorded results from A4 run 3: a file-read isolation check (FS-06, FS-07), blocked
external connections (NET-02..07), and invalid policies refused before Docker (POL-01..04).
PP-004 is accepted. The v0.0 gate also needs the closeout work (packaging and
`patchproof doctor`) and the owner's §15.1 review and demonstration.

Per §15.1, a design document alone does not pass this gate.

## Honest claim status

The only claim the evidence supports is the PP-003 statement: "on Docker Desktop 4.94.0
/ Engine 29.8.2, on 2026-10-12, the fixed harmless probe suite recorded all 82 planned
isolation, resource, policy, and cleanup checks as passing". The supporting evidence is in
`docs/evidence/pp-003-isolation-probes.md`. That run does not make Docker escape-proof,
and it does not show that arbitrary hostile repositories are safe to execute. Every other
capability, benchmark, and accuracy figure in `PROJECT_SPEC.md` is still a plan. No §19.1
measurement has been taken.
