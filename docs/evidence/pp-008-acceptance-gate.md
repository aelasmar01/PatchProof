# PP-008 acceptance gate — target/verifier runner and typed event transport

**Gate date:** 2026-10-14 · **Owner decision:** ACCEPT, conditional on this documentation review
and committed-tree validation · **Implementation checkpoint:**
`48e2d8e32b09b3d9a607f7682a12d9bfda6deea7` (earlier PP-008 checkpoints `98b5cf8`, `e25f106`,
`b2cdedd`)

**Completion evidence required (PROJECT_SPEC.md §16):** "Source/test separation; successful and
deliberately interrupted runs." The backlog adds that every owned container is labelled with the
installation and run IDs, and that this is the first dynamic reproduction of the PaperTrail
declared expectations. This gate assesses those items, plus the §10 execution requirements and
the verdict specification as they apply to PP-008.

**Live evidence (two owner-executed runs, each independently audited read-only):**

| Run | Purpose | Recorded result | Review |
|---|---|---|---|
| `run-036553ef7b032f59955cc4a790409931` | r1 (vulnerable) against r3 (correct), 1 pair | lifecycle `COMPLETE`, evidence `FINALIZED`, cleanup `COMPLETE`, `VERIFIED_FOR_CASES` (V-09), 16/16 trusted cells, 4 containers created and removed | `docs/evidence/pp-008-first-live-comparison.md` (164 scripted checks, 0 failed) |
| `run-6cee8893b1a0a58690be96bf23fa56b1` | deliberate SIGTERM at `baseline-target-ready`, baseline only | lifecycle `INTERRUPTED`, evidence `INCOMPLETE`, cleanup `COMPLETE`, `INCONCLUSIVE` (V-05), lifecycle exit code 20, controller `EXPECTED_OUTCOME_OBSERVED`, 2 containers created and removed, verifier and candidate never executed | `docs/evidence/pp-008-interruption-demonstration.md` (159 scripted checks, 0 failed) |

## Revalidation at the gate (read-only; no Docker)

- **Evidence verifier:** the accepted `verify_evidence` reports:
  - successful run: `CONSISTENT` / `FINALIZED`;
  - interrupted run: `CONSISTENT` / `INCOMPLETE`;
  - its controller record: `CONSISTENT` / `FINALIZED`.
- **Saved records** were re-read, not assumed:
  - **successful run:** `outcome.json` says `COMPLETE`, `FINALIZED`, cleanup `COMPLETE`, no
    remaining owned containers, termination `normal`; `verdict.json` says
    `VERIFIED_FOR_CASES`, V-09, 16 of 16 trusted cells; the journal has 4 creations and 4
    removals.
  - **interrupted run:** the values in the table above, with both cleanup entries `REMOVED`.
  - The successful run's outcome predates the `lifecycle_exit_code` field, so it records none.
- **Unchanged since the audits:** every private evidence file, controller record, authorization
  record, claim and approval record is identical to the 2026-10-14 audit snapshot (89 hashed
  files and 262 bytes/mode/size/mtime/inode stat entries). The successful run and the ordinary
  run-authorization store are also identical to their 2026-10-13 snapshot.
- **Approvals:** the current approval `apr-f4b493f9…` is `APPROVED` for freshly recomputed
  bindings. The superseded `apr-f30bd943…` is unchanged and reports `APPROVAL_STALE` (superseded),
  as designed. Both are 0400.
- **Authorizations:** both stores hold exactly one record, each `CLAIMED`, and neither has an
  executable authorization (`rau-ed8bb694…`, `iau-92e4f72c…`).
- **Implementation:** the tracked source, tests, profiles, schemas, verifier and container files
  are identical to `48e2d8e`.

## Requirement-by-requirement gate

| # | Requirement | Evidence | Status |
|---|---|---|---|
| 1 | Source and verification-pack separation (§10.2, §16) | both runs: the target mounts only its read-only source snapshot at `/app/source`, the verifier only the read-only approved pack at `/pack`; separate containers; results read from the verifier's attached output only (first-run review §4, §6; interruption review §4) | **PASS** |
| 2 | Real baseline/candidate execution | successful run: r1 then r3, sequential, both verifiers ran to completion with complete streams (first-run review §3–§4, §6) | **PASS** |
| 3 | Exact approved source, pack, profile and image identities | both frozen plans recompute unchanged from current artifacts. Baseline commit `68b2bc0e…` (manifest `1444803c…`); candidate commit `2fb6d093…` (manifest `42d82e22…`); pack tree `529d3cd3…`, manifest `a4c4ce48…`; approval `apr-f4b493f9…`; profile `a1c130c2…`; target image `98548ec4…`, verifier image `e880f609…`; fixture `2cbcf118…` (both reviews §2) | **PASS** |
| 4 | Semantic vulnerability witnesses | AUTH-001 and AUTH-003 on r1: status 200 and the document's own protected marker returned to a caller the hash-checked fixture does not permit; r3: 404, no marker. Structured witnesses only; raw responses not retained (first-run review §3) | **PASS** (accepted witness-depth limit) |
| 5 | Legitimate functional controls | FUNC-001–004 `PASS` on both sides through the reviewed assertions, with assertions active (no `-O`, no `PYTHONOPTIMIZE`); bodies not retained (first-run review §3) | **PASS** (accepted limit) |
| 6 | Complete verifier event transport (§10.3) | successful run: 31 events per side, contiguous, matching run/pair/side/schema, `session_start` … `session_end`, collected list exact; the stream file equals the bytes the host read; target output never reached the channel (first-run review §4). Interrupted run: stream `ABSENT`, 0 bytes, no invented events (interruption review §7) | **PASS** |
| 7 | Deterministic verdict evaluation (verdict specification) | both verdict inputs rebuilt from the underlying records equal the stored inputs. The accepted pure engine reproduces each stored `verdict.json` exactly: V-09 (all conditions) and V-05 (`incomplete_checks`). A counterfactual "normal" termination on the interrupted inputs is still `INCONCLUSIVE` (interruption review §7) | **PASS** |
| 8 | Single-use execution authorization | each run had its own frozen-plan authorization, claimed once and not executable afterwards; claim files byte-identical to their stores; the interruption contract and the ordinary contract refuse each other (both reviews §1) | **PASS** (accepted metadata limitation L1) |
| 9 | Deliberate interruption handling (§10.6, §16) | checkpoint report verified by the controller (stage, run, child PID, exact IDs, deadline); exactly one SIGTERM to that child, 25.0 s before the deadline, observed once by the child; target stopped gracefully; no retry (interruption review §3, §5) | **PASS** |
| 10 | Correct incomplete-evidence classification | interrupted evidence is `INCOMPLETE` in the manifest, outcome, integrity check and verdict reason codes (`RUN_INTERRUPTED`, `EVENT_STREAM_TRUNCATED`, `REPETITION_INCOMPLETE`, `REQUIRED_CHECK_INCOMPLETE`); cleanup `COMPLETE` kept as a separate dimension; lifecycle exit 20 (interruption review §1, §7) | **PASS** |
| 11 | Owned-container lifecycle and cleanup (§10.6) | six containers across both runs, each labelled with installation, run, pair, side, role and purpose; each removed exactly once by full ID after ownership checks, and confirmed absent by a following inspect; no force removal; only owned IDs touched (both reviews §6 / §3) | **PASS** |
| 12 | Docker resource preservation | within each run, the before and after inventories are identical by exact ID and attributes (14 images, 7 containers, 5 networks, 10 volumes); the seven unrelated stopped containers were never touched. The built-in `bridge` ID changed between runs. Docker Desktop's host log, which is outside the frozen evidence, attributes this to idle VM restarts (interruption review §6) | **PASS** |
| 13 | Isolation configuration (§10.1–§10.3) | for all six containers: create argv equals the fixed policy argv; the accepted pre-start gate passes when re-run on the saved inspect. Checked: user 10001:10001, read-only root, `CapDrop ALL`, `no-new-privileges`, default seccomp, private PID/IPC/cgroup namespaces, no devices, image environment only, target `none` and verifier `container:<exact target>`, no ports or bridge, CPU/memory/PID/tmpfs limits, `local` logging 2 × 5 MB, `--pull=never` | **PASS** (configuration evidence, L2) |
| 14 | Evidence integrity and read-only verification | the accepted verifier and an independent re-implementation agree for both runs; private evidence unchanged by both audits and by this gate | **PASS** |
| 15 | Known operating limits documented | listed below and in both reviews | **PASS** |

**Every mandatory requirement is PASS.** No outstanding material security defect is known. The
§10.5 seed list is not met by design: one fixed fixture is an owner decision (D1), and seed
variation is PP-019. Crash reconciliation after a live SIGKILL or host crash (§10.6) is tested
Docker-free only and belongs to PP-014.

## Accepted limitations

- **L1. Interruption authorization metadata.** The consumed authorization's rationale ("testing
  for implementation") and scope ("idk") are not substantive. The frozen plan bound the exact
  baseline, images, approved pack, signal operation, resource limits and two-container budget,
  and the run stayed within it. This is an accepted audit-quality limitation, not a runtime-policy
  failure. The record is not rewritten, deleted, superseded or repaired. The owner does not
  require a signed post-run note, and none was created.
- **L2. Configuration, not kernel proof.** Container inspect records show configuration, not
  comprehensive kernel-enforcement assurance.
- **L3. Witness depth.** Structured witnesses are retained; full raw HTTP responses are not.
- **L4. Reviewer identity.** It is locally asserted; terminal gating and approvals are procedural
  controls under one OS account.
- **L5. Checkpoint time.** The checkpoint and signal order is reconstructable from monotonic times
  and operation order. The checkpoint has no independent wall-clock timestamp.
- **L6. Journal versions.** The successful comparison used the earlier evidence journal (v1). The
  interrupted demonstration used the hardened `docker-ops-v2` journal but never started the
  verifier, so the hardened verifier-console capture path has not been demonstrated in a live
  verifier execution.
- **L7. Shell exit codes.** The actual shell exit codes of the owner-run commands were not
  captured. The controller's harness exit code (0) and the child's lifecycle exit code (20) are
  recorded in its evidence.
- **L8. Preflight discrepancy.** The supplemental interruption preflight ran 46 checks: 45
  passed. One extra diagnostic wrongly required zero Docker containers and **FAILED**, because
  seven unrelated stopped containers existed. The script exited 1; piping its output through
  `tee` hid that. The FAILED check is preserved. The runner's mandatory preconditions passed
  independently, and the reviewed policy permits unrelated stopped containers: cleanup is
  exact-ID only and the inventory is compared by identity.
- **L9. Docker network identity.** The `bridge` network changed identity after a Docker Desktop
  VM restart before the run. That attribution comes from Docker Desktop's own log, external to
  the frozen run evidence. Within the run, the saved before and after inventories match by
  identity. An unchanged network ID does not prove the daemon ran continuously.
- **L10. Deprecated stop flag.** Docker 29.8.2 reports `--time` as deprecated. The stop argv stays
  unchanged pending a separately reviewed policy adjustment.
- **L11. Host pytest advisory.** The host development pytest advisory remediation (pytest 9.0.3
  delta in `docs/environment.lock.md`) remains a separate tracked obligation.
- **L12. Scope of the claim.** One pair, one fixed synthetic fixture, 8 selected checks on the
  synthetic PaperTrail reference application. Not a general security statement.

## PP-009 handoff (recorded, not started)

1. General CLI workflow and safe JSON/Markdown reports.
2. Meaningful owner-entered rationale and scope validation for run, interruption and approval
   authorizations: minimum content, a deny-list of placeholder values, scope naming the run ID,
   and the existing ban on the confirmation phrase.
3. Fail-closed preflight reporting:
   - keep command exit codes through `tee` and other pipelines;
   - label each check as a mandatory gate or an optional diagnostic;
   - fail on any failed mandatory gate.
4. A controlled end-to-end check of the hardened verifier-console and operation-journal capture
   during a live verifier execution, under separate owner approval.
5. Safe handling of the accepted response-retention and export limitations.

## Validation at the gate

Run on the working tree on 2026-10-14. Source and tests were identical to `48e2d8e`; only
documentation differed.

| Check | Command | Actual result |
|---|---|---|
| Docker-free unit suite | `uv run --locked --offline python -I -m pytest -q -p no:cacheprovider` | **8,667 passed**, 0 failed, 0 skipped (334 s) |
| Strict typing | `uv run --locked --offline mypy --strict src` | **no issues** in 70 source files |
| Ruff, documented gate | `ruff check --select E,F,W,B,UP --line-length 120 src containers` | **all checks passed** |
| Ruff, project defaults over `src tests` | `ruff check src tests` | 11 E501 (line too long), all in committed test files unchanged since `48e2d8e` (`_fakes.py` 3, `test_docker_cli.py` 2, `test_inspect_gate.py` 2, `test_schemas.py` 2, `test_net01_fs05_semantics.py` 1, `test_probe_script.py` 1); **no new finding** |

No Python file changed in this closeout. The committed-tree validation is recorded in `STATUS.md`.

## Sanitization

This report and the two run reviews contain run IDs, authorization IDs, short container IDs and
content hashes only. They contain no host paths, installation IDs, process IDs, reviewer names,
synthetic tokens or markers, or raw container output.
