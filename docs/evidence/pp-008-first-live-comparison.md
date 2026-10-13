# PP-008 first live comparison — independent evidence review

**Run:** `run-036553ef7b032f59955cc4a790409931` · **Authorization:** `rau-ed8bb6944af5d7681d52a9947199a37e`
· **Frozen plan:** `sha256:b3b0593a1a6da8f0b04b95cf96cb8c4389358e6e9a3113f5308a509d00f9e47e`

**Audit result (2026-10-13): the evidence is intact and internally consistent, and an
independent recomputation reproduces the stored verdict exactly: `VERIFIED_FOR_CASES`, rule
V-09.** The audit is read-only: no Docker command, no re-execution, no change to the run's
evidence or the authorization store (bytes, modes, mtimes and inodes were compared before
and after). Five evidence-design findings are listed under *Findings*; none of them affects
the trusted event channel or the verdict.

This is a claim about **8 selected checks, one pair, one fixed synthetic fixture**, on the
synthetic PaperTrail reference application (r1 vulnerable against r3 correct). It is not a
statement about application security in general, and not an acceptance of PP-008.

The raw evidence stays private on the owner's Mac (mode 0700 directory, 0600 files). This
report holds only sanitized facts and hashes: no HTTP bodies, synthetic tokens or markers,
installation ID, host paths or container console output.

## 1. Evidence integrity

| Check | Result |
|---|---|
| Accepted `run_evidence.verify_evidence` | `CONSISTENT`, status `FINALIZED`, no problems |
| Manifest | present, strict JSON; lists exactly the 28 files present; every SHA-256, size and mode (0600) matches; no partial (`.tmp-`) file |
| Required artifacts | all 28 present, none unexpected; every JSON file strict-parses; every JSONL line parses and each journal ends with a newline |
| Manifest summary | equal to `outcome.json` |
| Authorization | `authorization.json` byte-identical to the stored record; strict load and `check_authorization` pass; plan hash recomputed = `b3b0593a…`; `plan.json` equals the authorized plan; first-run scope (r1 against r3) holds; reviewer basis `local-assertion-unverified`; supersedes nothing |
| Single use | the store holds exactly one record and one claim (`CLAIMED`, both 0400); `claim.json` byte-identical to the stored claim and names this authorization and run; no executable authorization remains |
| Plan still current | the plan recomputed now from the current private artifacts equals the frozen plan, so no bound input has changed since the run |
| Finalization supported | both revisions present, re-validation passed before each (`revalidation.jsonl`), no exception, no evidence-write failure, both inventories complete, all four containers confirmed absent |

The stored states (`FINALIZED`, `COMPLETE`, cleanup `COMPLETE`, reconciliation `CONSISTENT`)
are each re-derived from the underlying records below, not taken from `outcome.json`.

## 2. Identities

| Item | Bound and verified value |
|---|---|
| Baseline | `refs/tags/authz-r1-vulnerable`, commit `68b2bc0e41cb7e9a074b09f2d97db3e2d2ca288a`, tree `f4a27893dc96e01b42e4b0da27cb2de5977c6063` |
| Candidate | `refs/tags/authz-r3-correct`, commit `2fb6d09378906f1df69ac32b862df4a350e8a56d`, tree `eb22f1bf9e8680971fac0af28c0557b117314803` |
| Source manifests | baseline `sha256:1444803c19d7c826f88243850f44c0590008d5c828f755cd43cf48c997b1a3f7`, candidate `sha256:42d82e22e879969b96b737e42f89b1d7ea65c28e628ec09141e4b33f06604d4f`; the evidence copies are byte-identical to the private snapshot store, re-hashed, and both re-derive byte-for-byte from the durable reference repository |
| Source inclusion | `fixtures/synthetic`, `papertrail`; profile `sha256:2224cc8e1f8bfa336246e3a0ddfbc0bca77913482b5930cd83747e5e3e702c50` |
| Fixture | `synthetic-documents-v1`, `sha256:2cbcf118fddb2cd4e38a9af5e8786911e8f85e292e637102799fd60513129eda` in both snapshots and the pack; one pair; no seed (owner decision D1) |
| Pack | `papertrail-document-access`, tree `sha256:529d3cd3ebf307586dcecef43a0df8ab9b55296849182f8f43c4ad7d6a8a6c31`, manifest `sha256:a4c4ce48d5d2aaa512c746e7ba90d06fd76e879de3a3dea5280079531a8804c8`; the private pack copy re-verified; both verifier sessions report the same tree hash in `session_start` |
| Pack approval | `apr-f4b493f9be53db6b0eff607f79508a65` (current, `APPROVED` for freshly recomputed bindings); the evidence copy is byte-identical to the record; both approval records unchanged (`06f89515…`, superseded `3b6354eb…`) |
| Profile | `papertrail-reference` 1.0.0, `sha256:a1c130c2f8b90c2ada2001ef3bc336b0b8ec29886fd92635dbf5928eb8036835`; the repository file still has this hash |
| Target image | `sha256:98548ec48d8d796fca5adaf4aab3e461bee38210bd1d568281f79190685eac2e` (image-inspect `Id` and every target container's `Image`) |
| Verifier image | `sha256:e880f609a7c4d292441e22d1d0d5d7c876697dd4e1e657a668b2b6266969fecc` (likewise) |
| Repository and pack | the repository pack validates to the same tree and manifest hashes; the durable reference repository keeps all four tags, commits and trees, and `git fsck --strict --full` is clean |

## 3. Observation matrix (actual, from the verifier event streams)

Each cell was re-derived by the accepted collector from the raw verifier stream and equals
the stored observation file. "Event" is the sequence number in that side's stream.

| Test | Baseline (r1) | Event | Candidate (r3) | Event |
|---|---|---|---|---|
| AUTH-001 non-owner reads private document | `VIOLATION_CONFIRMED` | obs 3, call 4 | `SECURE` | obs 3, call 4 |
| AUTH-002 unauthenticated read | `SECURE` | obs 7, call 8 | `SECURE` | obs 7, call 8 |
| AUTH-003 role grant on another document | `VIOLATION_CONFIRMED` | obs 11, call 12 | `SECURE` | obs 11, call 12 |
| AUTH-004 invalid token | `SECURE` | obs 15, call 16 | `SECURE` | obs 15, call 16 |
| FUNC-001 owner reads own document | `PASS` | call 19 | `PASS` | call 19 |
| FUNC-002 granted auditor reads listed document | `PASS` | call 22 | `PASS` | call 22 |
| FUNC-003 second owner reads own document | `PASS` | call 25 | `PASS` | call 25 |
| FUNC-004 caller reads own identity | `PASS` | call 28 | `PASS` | call 28 |

All 16 cells are lifecycle `COMPLETED` with no harness errors. They equal the PP-006 declared
table in every cell, including the declared HTTP status and marker disclosure for all eight
security cells. That comparison was made separately, after the cells were derived.

### Security witnesses

Each security observation carries a structured witness built by the reviewed helper
(`patchproof_verifier.authz`) inside the verifier. A violation requires the document's own
protected marker in the response body and a caller the hash-checked fixture does not permit;
a status code is never enough. A secure result requires a reviewed denial status, no marker
and no document content.

| Test, side | Caller | Document (owner, readers) | Status | Marker in body | Caller permitted |
|---|---|---|---|---|---|
| AUTH-001 baseline | `u-bob` (member) | `doc-alice-private` (`u-alice`; auditor) | 200 | **yes**, this document's marker | no |
| AUTH-003 baseline | `u-carol` (auditor) | `doc-bob-private` (`u-bob`; none) | 200 | **yes**, this document's marker | no |
| AUTH-001 candidate | `u-bob` | `doc-alice-private` | 404 | no | no |
| AUTH-003 candidate | `u-carol` | `doc-bob-private` | 404 | no | no |
| AUTH-002 both | no credential | `doc-alice-private` | 401 | no | — |
| AUTH-004 both | invalid bearer | `doc-alice-private` | 401 | no | — |

Each marker named in the witness is the one belonging to that document's owner. The two
baseline violations ended their call phase as `failed` with failure class
`security_terminal`; every other call phase `passed` with failure class `none`.

### Functional controls

The functional checks emit no observation event. Their `PASS` is the lifecycle of their
reviewed assertions: `expect_document_read` requires status 200 and the exact fixture
`document_id`, `owner_id` and `content`; `expect_identity` requires status 200, the caller's
own `user_id` and `role`, and that the bearer token is not echoed. All eight call phases
`passed`. The verifier ran without `-O` and without `PYTHONOPTIMIZE`, so the assertions were
active. **Limitation:** the response bodies are not retained, so these contents cannot be
re-examined from the evidence; the evidence is that the reviewed assertions passed.

## 4. Event transport

| Check | Baseline | Candidate |
|---|---|---|
| Collector status | `COMPLETE` | `COMPLETE` |
| Events; sequence | 31; contiguous 0–30 | 31; contiguous 0–30 |
| Run, pair, side, schema in every event | match | match |
| First, second, last event | `session_start`, `collected`, `session_end` | same |
| Collected list | exact, in manifest order | exact, in manifest order |
| Lifecycle | setup, call, teardown for each of the 8 tests | same |
| Observations | exactly one per security test, none for functional tests; no unknown test IDs | same |
| `session_end` | 8 tests reported, 4 observations; agrees with host counts | same |
| Bytes received; cap | 8,921 of 10,485,760 | 8,900 of 10,485,760 |
| Stream file equals what the host read | yes (journal SHA-256 and length; not truncated, no timeout) | yes |
| Failed reports; verifier exit | 2; exit 1 (inspect, record and attach agree) | 0; exit 0 |
| Timeout, OOM, crash, runtime errors | none | none |

The target's output never reached the event channel: the trusted stream is only the
verifier's attached standard output, its bytes equal the hash the host recorded, and the
collector parsed nothing else.

## 5. Independently recomputed verdict

The verdict input was rebuilt without reading `verdict-input.json` or `verdict.json`:
- preconditions from the checks above (approval re-checked, pack and session tree hashes,
  source manifests, the pre-start gate re-run on the saved inspects, stream provenance);
- pack tests and expectations from the repository pack and the authorized collection;
- executions from the execution records, cross-checked against Docker's own inspect output;
- observations re-derived from the raw streams by the accepted collector.

The rebuilt input equals the stored `verdict-input.json` field for field. The accepted PP-004
engine on the rebuilt input returns a record equal to the stored `verdict.json` in every
field, given the stored `evaluated_at`:

| Item | Recomputed |
|---|---|
| Verdict, rule | `VERIFIED_FOR_CASES`, **V-09** |
| Reason codes | `ALL_CONDITIONS_SATISFIED` |
| Preconditions | all five `PASSED` |
| Cells | 16 required, 16 trusted; 1 of 1 pair terminated normally with trusted evidence |
| Flags | all seven false: no incomplete checks, candidate violation, regression, harness drift, flakiness, unreproduced baseline or failed baseline control |

## 6. Containers, isolation and cleanup

| Check | Result |
|---|---|
| Containers created | **4** (budget 4): baseline target, baseline verifier, candidate target, candidate verifier, in that order |
| Sequential | both baseline containers were removed before the first candidate create |
| Executed create argv | equal to the fixed policy argv for each container |
| Pre-start gate | re-run by this audit on each container's first saved inspect: **passes** for all four |
| Network | each target `none`; each verifier `container:<its own target>`; no port bindings |
| Mounts | each target: one read-only bind at `/app/source` (its own side's snapshot); each verifier: one read-only bind at `/pack` (the pack copy). No other bind |
| Hardening | read-only root filesystem, user 10001:10001, all capabilities dropped, `no-new-privileges`, not privileged, restart policy `no` |
| Limits | target 1 CPU, 1 GiB memory (no swap), 128 PIDs, tmpfs `/scratch` 256 MiB and `/tmp` 64 MiB; verifier 1 CPU, 512 MiB, 128 PIDs, `/scratch` 112 MiB and `/tmp` 16 MiB; all tmpfs `noexec,nosuid,nodev` |
| Logging | `local` driver, 2 files of 5 MB, no compression |
| Removal | each container removed exactly once by its full registered ID; the next inspect of each reports "no such container"; no force removal was needed |
| Touched resources | only this run's four container IDs were ever inspected, started, stopped or removed |
| Docker operations | 53, all of allowed kinds (9 listings, 4 image inspects, 4 creates, 24 inspects, 2 starts, 2 attached starts, 2 log reads, 2 stops, 4 removals); no network, volume, prune or force operation |
| Inventory | before and after complete and identical by identity (14 images, 7 containers, 5 networks, 10 volumes) |
| Daemon continuity | `NO_CHANGE_OBSERVED`: the network listings before, mid-run and after were identical. **This is an observation, not proof that the daemon never restarted.** |

## 7. Timeline (Docker's own timestamps, UTC)

| Moment | Time | Duration |
|---|---|---|
| Authorization created | 14:35:53 | — |
| Claim | 14:39:41 | — |
| Before-inventory | (first image listing took 4.74 s) | — |
| Baseline target created, started | 14:39:46.568, 46.899 | healthy at 48.278: **1.38 s** after start |
| Baseline verifier | 14:39:48.837 to 50.046 | **1.21 s**, exit 1 (two security failures, as expected) |
| Candidate target created, started | 14:39:51.064, 51.392 | healthy at 52.718: **1.33 s** after start |
| Candidate verifier | 14:39:53.281 to 54.313 | **1.03 s**, exit 0 |
| Evidence finalized | 14:39:55 (file time, 1 s resolution) | — |

- **Active duration:** about 14 s from claim to manifest; 7.75 s from the first create to
  the last verifier exit. The sum of all Docker operation times is 11.05 s.
- **Cleanup:** 0.56 s (baseline) and 0.63 s (candidate), each a graceful stop of the
  target, ordinary removal of both, and absence confirmed.
- **HTTP requests:** not recorded in the evidence. The reviewed pack makes one request per
  test, so 8 per side. The target's health log shows 2 health probes per side. These counts
  come from the code, not from an observed request log.
- **Shell exit code:** **not captured** in the evidence. The command's exit-code rule would
  give 0 for these records, but the actual value was not recorded and is not inferred here.

## 8. Findings

None of these affect the verdict or the trusted channel. All are evidence-design issues for
owner review; nothing was changed in this run's evidence. Corrections for later runs are in
section 10.

1. **The target log is captured from the wrong stream (medium).** Uvicorn writes to standard
   error. `untrusted-target-log-*.log` holds only standard output, so both files are empty.
   The target's standard error, here four uvicorn startup lines, is stored inline in the
   `stderr` field of `docker-ops.jsonl`, capped at 4,096 characters; anything beyond is
   lost. This contradicts the documented rule that the operation journal never stores target
   log content. Proposed fix: store both target streams in the untrusted log file, labeled,
   and keep only their length and hash in the journal.
2. **Verifier console output in the journal (low).** The `start-attached` `stderr` field holds
   pytest's console output. For the baseline failures it includes fixture representations
   with synthetic tokens and markers. It is private and synthetic, but it should be a
   separate, labeled file or a hash only.
3. **`evaluated_at` is the run's start time (low).** `verdict.json` says 14:39:46Z, the moment
   the comparison began, not when the engine evaluated. It is deterministic and harmless for
   the result, but the name misleads.
4. **No wall-clock times in the operation journal (info).** The timeline above relies on
   Docker's own timestamps and file times. Adding a monotonic offset and a UTC time per
   operation would make it complete.
5. **Witness depth (info).** Security witnesses are structured facts attested by the
   reviewed verifier code; `evidence_refs` are empty and raw responses are not retained (spec
   12.2 lists `private/raw-responses/`). Functional controls have no witness record (see
   section 3).

Also noted: pytest warned that the verifier plugin module could not be assertion-rewritten
because it was already imported. This affects only assertion messages, not whether an
assertion raises.

## 9. PP-008 criteria

| Criterion (backlog) | Status |
|---|---|
| Source/test separation | **Met live:** sources and the pack mounted separately and read-only, in separate containers |
| Successful run | **Met:** this run |
| Deliberately interrupted runs | **Not met live.** Only Docker-free tests exist: real SIGINT/SIGTERM/SIGHUP and SIGKILL against the driver with a scripted Docker, and the recovery command. Gate C (C1a, C1b, C2) and the PP-003 probes were collection, protocol and isolation runs, none deliberately interrupted |
| Every owned container labeled with installation and run ID | **Met:** the pre-start gate, re-run on the saved inspects, passes for all four |
| First dynamic reproduction of the declared expectations | **Met** for r1 against r3: 16 of 16 cells, plus statuses and marker disclosure, equal the PP-006 table. Image IDs and the uvicorn pin were resolved at gate B; this audit did not re-inspect the image contents |

**Proposed smallest live interruption demonstration (not executed; needs separate owner
authorization and a new run authorization, since this one is consumed):**
- **Budget:** at most 2 containers (baseline only).
- **Action:** the owner runs `run_papertrail_once` and sends SIGTERM (or Ctrl-C) after the
  baseline containers exist.
- **Expected:** both removed by exact ID, evidence `INCOMPLETE`, lifecycle `INTERRUPTED`, no
  candidate, authorization consumed.
- **Follow-up:** `recover_run` reports nothing to remove.
- **Timing caveat:** the window is short (about 1.4 s readiness plus about 1.2 s verifier).
  A manual signal may land before or after it; the evidence records honestly where it
  landed. For a deterministic signal point, a small reviewed demonstration hook would be
  needed (new code, owner review).
- **Optional second step:** a SIGKILL variant would exercise `recover_run` cleanup (2 more
  containers, typed `CLEANUP`).

## 10. Remediation after this audit (2026-10-13; Docker-free; READY_FOR_REVIEW)

The owner accepted this run's evidence-supported verdict for the eight selected tests and one
pair, and authorized Docker-free corrections. **This run's evidence was not modified**: after
the work, every file is byte-, mode-, mtime- and inode-identical to the audit snapshot, and
the corrected `verify_evidence` still reports it `CONSISTENT`/`FINALIZED` (its journal is
reported as format `v1`, the earlier inline format). The frozen plan still recomputes to
`sha256:b3b0593a…`, so the pack, profile, plugin, images and policy identities are unchanged.

| Finding | Correction for later runs |
|---|---|
| 1. Target stderr in the journal, empty target-log files | Target stdout and stderr are read with separate 5 MiB caps into `untrusted-target-stdout-<tag>.log` and `untrusted-target-stderr-<tag>.log`; capture status, size, hash and truncation in `revision-<tag>.json`; a failed read is `CAPTURE_FAILED` (no file) and makes the evidence `INCOMPLETE` |
| 2. Verifier console in the journal | The verifier's stderr (1 MiB cap) goes to `untrusted-verifier-console-<tag>.log`; the event channel is unchanged |
| 3. `evaluated_at` at the run's start | Read when the engine evaluates; `outcome.json.timestamps` adds execution start and finish and checks their order. This run's `14:39:46Z` stays as recorded and means the comparison's start |
| 4. No wall-clock time per operation | Journal format `docker-ops-v2`: UTC start and end, monotonic duration, exit or `TIMED_OUT`, `interrupted` lines with no invented end, and per stream class, size, hash, cap, truncation and artifact. No raw output in the journal; other Docker output is in bounded `docker-ops-<seq>-<stream>.out` files |
| 5. Witness depth | Unchanged by design. Documented in `docs/architecture/verification-runs.md` ("Retained response evidence"): what the verifier observed, what the stream preserves, what an audit can recompute, and that response bytes cannot be reconstructed. Retaining them would need a plugin, pack or schema change and a new approval; not proposed |

The verifier plugin, pack, profile, runtime images, event grammar and verdict engine were not
changed.

**Interruption demonstration.** The manual-signal proposal in section 9 is replaced by a
deterministic design (`docs/architecture/verification-runs.md`, "Interruption test"): a
controller starts the runner as its own child; the child reports over a private pipe when the
baseline target is healthy and the verifier is created but not started, then waits at most
30 s; the controller checks the exact stage, run ID and child PID and sends one SIGTERM.
Budget: 2 containers created, 1 started; both removed by exact ID; `INCOMPLETE`,
`INTERRUPTED`, no verdict; then `recover_run` should find nothing. The mechanism is tested
Docker-free with real local processes. It needs a new, separately reviewed authorization
contract (the current one fixes four containers and both sides), a new single-use
authorization and separate Docker approval. Nothing was executed.

**Update (owner correction and implementation, 2026-10-13).** The owner corrected the result
contract: once the baseline target has started, the reviewed interruption ends lifecycle
`INTERRUPTED`, evidence `INCOMPLETE`, cleanup `COMPLETE` (both containers confirmed removed),
and the accepted engine's verdict `INCONCLUSIVE` by `V-05`, with lifecycle exit code 20
(PROJECT_SPEC.md 13.2), not "no verdict, exit 4". The separate contract
(`interruption-test-authorization` 1.0), its store, owner command, controller, child and
driver are implemented and tested Docker-free. No real interruption authorization exists and
nothing was executed.

## Limitations

- One pair and one fixed fixture (D1), so no repetition or seed variation; 8 selected checks
  on a synthetic reference application.
- The reviewer identity is a local assertion; terminal gating is procedural.
- Container inspection is configuration evidence, not proof of kernel enforcement.
- Unchanged network identities do not prove daemon continuity.
- HTTP requests, response bodies and the shell exit code are not part of the evidence.
