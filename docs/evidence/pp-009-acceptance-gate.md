# PP-009 acceptance gate: CLI workflow and JSON/Markdown evidence

**Gate prepared:** 2026-10-14 · **State:** READY_FOR_REVIEW (not accepted) · **Implementation checkpoint:**
`9bc4268f0f360edd339ed3b11f7b27e92d3f15ba` · **Reporting remediation:** the checkpoint commit that adds this
document (U1–U7)

**Completion evidence required (PROJECT_SPEC.md §16):** "Reproducible documented comparison from input to
verdict."

**Live evidence (one owner-executed CLI run, independently audited read-only):**

| Run | Purpose | Recorded result | Review |
|---|---|---|---|
| `run-dd93a78f930812bddca76e025eef5d31` | r1 (vulnerable) against r3 (correct), 1 pair, through `project add`, `plan create`, `plan approve`, `run` | lifecycle `COMPLETE`, evidence `FINALIZED`, cleanup `COMPLETE`, `VERIFIED_FOR_CASES` (V-09), 16/16 trusted cells, both 31-event streams `COMPLETE`, 4 containers created and removed, inventory `CONSISTENT` | `docs/evidence/pp-009-first-live-cli-comparison.md` (110 scripted checks, 0 failed; remediation addendum §11) |

The two accepted PP-008 runs (`run-036553ef…` journal v1, `run-6cee8893…` interrupted) are used read-only
to show historical compatibility.

## Requirement-by-requirement gate

| # | Requirement | Evidence | Status |
|---|---|---|---|
| 1 | **CLI command coverage** (§13.1): `project add\|list`, `profile prepare`, `pack validate\|approve`, `plan create\|show\|approve`, `run`, `report`; `doctor` kept | `src/patchproof/cli/workflow_commands.py`; `docs/architecture/cli-workflow.md` "Commands"; CLI-surface tests (no `--yes`, reviewer, Docker, mount, environment or shell option) | **PASS** |
| 2 | **Project registration**: exact canonical root through the PP-005 boundary, home and parent-repository refusal, scope preview, typed confirmation, write-once 0400 record, duplicate/conflict refusal | registration tests; live record `prj-fc41aa023d78b8c6` loads strictly (live audit §2); final security review F1 | **PASS** |
| 3 | **Immutable plans**: plan bound to exact commits, trees, snapshot manifests, pack, approval, profile, images, fixture and limits; ID derived from its SHA-256; canonical, write-once, re-validated on load; drift refused | plan tests (five drifts after create and after approve); live plan hash reproduces and equals the evidence copy (live audit §2) | **PASS** |
| 4 | **Explicit authorization and single use**: `plan approve` delegates to the accepted run authorization bound to the stored plan hash; typed `AUTHORIZE`; claim before Docker; consumed authorization never reruns; no retry | authorization tests; live `rau-a76fa4d8…` claimed once, byte-equal in evidence, no executable authorization remains (live audit §2) | **PASS** |
| 5 | **Live CLI execution through the accepted PP-008 machinery** | `run` → `execute_once`; live audit §5: four creations, sequential, exact images, `--pull=never`, target `--network none`, verifier joins only its own target, user 10001:10001, read-only root, drop ALL, no-new-privileges, fixed limits, exact-ID cleanup, absence confirmed, inventory identical | **PASS** |
| 6 | **Hardened verifier-console capture** (live) | live audit §4: consoles `CAPTURED` (5,327 B and 569 B), sizes and hashes equal across artifact, revision record and journal; separate from the event channel; absent from operational metadata | **PASS** |
| 7 | **Trusted event transport** | live audit §3: two 31-event streams, contiguous, correct identity, `COMPLETE`; observations re-derived from raw bytes equal the stored ones | **PASS** |
| 8 | **Report integrity and verdict recomputation** | report integrity checks (17 of 17 on the live run); independent audit rebuilt the verdict input from raw records and reproduced `verdict.json` in every field; tamper tests (rewritten verdict, observations, executions, manifest status, missing verdict) | **PASS** |
| 9 | **JSON report readability and accuracy** | one valid document, deterministic, exact identities, separate lifecycle, evidence, verdict, cleanup and `fix_verified_for_selected_cases`; fixed-fixture claim from validated evidence (U3) | **PASS** |
| 10 | **Markdown report readability and safety** | fixed wording literal and proven inert (`safe_text.prose`); values escaped or in code spans; hostile-value tests across every field parsed with the locked `markdown-it-py` (no added heading, table, row, list, link, image, HTML or code block); leading-space indentation closed; regenerated live report: 13 headings, 5 tables, backslashes 202 → 17, all in values (U4, U5) | **PASS** |
| 11 | **Accurate statements at gates and in reports** | authorization review no longer claims PaperTrail never ran (U2); claim label no longer says "seeded" (U3); integrity wording separated from fix verification (U5); `plan create` states it stores a plan (U7) | **PASS** |
| 12 | **Documented, reproducible invocation** | pinned `uv run --locked --offline patchproof …` in README, `cli-workflow.md` and every CLI hint; tests parse each printed hint against the real command tree and pin the `pyproject.toml` entry point (U1) | **PASS** |
| 13 | **Safe report exports** | `--output` tests; live probes: new file 0600; existing file, dangling and live symlinks, data directory and symlinked parent refused with exit 2; nothing overwritten, followed or left behind (live audit §6) | **PASS** |
| 14 | **Exit-code compliance** (§13.2) | `run`/`report` mapping tested for 0, 10, 11, 12, 20, 21, 22 and usage 2; relative paths are usage errors, policy refusals stay 21 (U6); `report` exits 0, 0, 20 for the three recorded runs (captured directly). The shell status of the original live `run` was not observed | **PASS** (limitation recorded) |
| 15 | **Preservation of old evidence** | both PP-008 runs and the live PP-009 run, every approval, authorization and claim: byte-identical (hash, mode, size, mtime, inode) before and after the audit and the remediation | **PASS** |
| 16 | **No weakening of accepted components** | no change to the verdict engine, Git/snapshot boundary, pack, profile, images, runtime policy, cleanup authority, authorization semantics or event grammar; `run_authorization` changed in display text only; accepted tests unchanged | **PASS** |

## Accepted limitations (carried, not resolved by PP-009)

- **L1 Scope.** One supported comparison (PaperTrail r1 → r3, one pair, one fixed synthetic fixture, eight
  selected checks); no general security claim.
- **L2 Release-gate cases.** The §15.2 cases (unchanged, inadequate, deny-all, startup failure, missing
  observation) need a reviewed widening of the plan contract: a separate proposed work item before PP-010
  (`docs/architecture/cli-workflow.md`).
- **L3 Retained data.** Witnesses are structured facts; raw HTTP responses are not retained.
- **L4 Inspection.** Container inspection is configuration evidence, not proof of kernel enforcement.
- **L5 Identity.** Reviewer identities are local assertions; gates are procedural under one OS account.
- **L6 Daemon continuity.** `NO_CHANGE_OBSERVED` does not prove uninterrupted daemon operation.
- **L7 Exit status of the live run.** The shell exit status of the original live `run` was not observed;
  the computed CLI code and the report's own exit code are recorded instead.
- **L8 Console secrets.** The baseline verifier console holds the synthetic fixture's tokens and markers,
  because pytest prints its fixtures on the expected failures. The artifact is private and untrusted, and
  must never be exported. A fix needs a separately reviewed verifier change (C1).
- **L9 Hard links.** `--output` needs a file system with hard links.

## Validation of this gate

See `STATUS.md` (PP-009) for the commands and actual counts: the full Docker-free suite, `mypy --strict`,
Ruff, the remediation mutation check, and the committed-tree validation in a separate offline environment.

**Recommendation:** every PP-009 requirement passes, with the limitations above. PP-009 is ready for the
owner's formal acceptance decision. It is not accepted by this document.
