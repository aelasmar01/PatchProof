# PP-008 deliberate interruption demonstration — independent evidence review

**Run:** `run-6cee8893b1a0a58690be96bf23fa56b1` · **Interruption authorization:**
`iau-92e4f72c5e2b9c251845c13f3e7dde6a` · **Frozen plan:**
`sha256:faa4245d3da979959bfc385fee473423166c8765b1f9b6d3c3e9aa8a40ff9ed9` · **Plan kind:**
`papertrail-interruption-sigterm-baseline-v1`

**Audit result (2026-10-14): the evidence is intact and internally consistent.** The run did
what the reviewed plan says: one baseline target was started and became healthy, one verifier
was created and inspected but never started, and exactly one SIGTERM reached the intended
child at the checkpoint. Both containers were removed by exact ID and confirmed absent. An
independent recomputation reproduces the stored outcome exactly: lifecycle `INTERRUPTED`,
evidence `INCOMPLETE`, cleanup `COMPLETE`, verdict `INCONCLUSIVE` by rule V-05, lifecycle exit
code 20.

The audit is read-only. It ran no Docker command, did not re-execute anything, and did not
change the run's evidence, the controller record, the authorization store, the approval
records or the earlier run. Every private file's bytes, mode, size, modification time and
inode were compared before and after: 89 hashed files and 262 stat entries, identical. 159
scripted checks passed and 0 failed. A script error (a timestamp compared as text) was fixed
before the final pass and is noted in section 10.

This run is a lifecycle and cleanup demonstration. It **cannot** produce a verified-fix
result, and does not: the verifier never ran and no candidate exists in the plan.

The raw evidence stays private on the owner's Mac (0700 directories, 0600 files; the store
records are 0400). This report holds only sanitized facts and hashes. It leaves out host
paths, the installation ID, process IDs, the reviewer's name and container console output.

## 1. Evidence integrity

| Check | Result |
|---|---|
| Accepted `verify_evidence`, child evidence | `CONSISTENT`, status **`INCOMPLETE`**, no problems |
| Accepted `verify_evidence`, controller record | `CONSISTENT`, status `FINALIZED`, no problems |
| Independent re-implementation | for each directory, the manifest lists exactly the files present (child 51, controller 2, plus each manifest); every SHA-256, size and mode (0600) matches; each file is regular, single-link and not partial; the directory is 0700; no temporary files |
| Required artifacts | all 23 required child artifacts present; no file mentions a candidate |
| Manifest summaries | child manifest summary equals `outcome.json`; controller manifest summary equals `controller.json` |
| Honest status | the child manifest says `INCOMPLETE`, with the reason "deliberate interruption: no verifier observation exists and no candidate runs" |
| Authorization | `authorization.json` is byte-identical to the stored record; strict load and the authorization, plan and r1-scope checks pass; the plan hash recomputes to `faa4245d…`, equal to the record and to the value the owner supplied; `plan.json` equals the authorized plan; single use; supersedes nothing |
| Single use, consumed | the store holds exactly this record and its claim (both 0400, single link). The stored claim, the child's `claim.json` and the controller's `claim.json` are byte-identical and name this authorization and run. The store reports no executable authorization, and this one is not superseded |
| Plan still current | the plan recomputed now from the current private artifacts equals the frozen plan, so no bound input changed since the run |
| Approvals | both pack-approval records unchanged (`06f89515…`, superseded `3b6354eb…`), both 0400; `pack-approval.json` is byte-identical to the current record `apr-f4b493f9…`, which is still `APPROVED` for freshly recomputed bindings |
| Earlier run | `run-036553ef…` evidence and the ordinary run-authorization store are byte-, mode-, mtime- and inode-identical to their audit snapshot of 2026-10-13 |
| Order of records | authorization created 04:18:26Z, claimed 04:18:51Z (1 s precision), controller started 04:18:51.904Z |

## 2. Identities

| Item | Bound and verified value |
|---|---|
| Baseline (only source) | `refs/tags/authz-r1-vulnerable`, commit `68b2bc0e41cb7e9a074b09f2d97db3e2d2ca288a`; source manifest `sha256:1444803c19d7c826f88243850f44c0590008d5c828f755cd43cf48c997b1a3f7` (the evidence copy is byte-identical to the snapshot store) |
| Candidate | **none**: the plan's `sources` holds only `baseline`; `candidate_execution` is false |
| Fixture | `sha256:2cbcf118fddb2cd4e38a9af5e8786911e8f85e292e637102799fd60513129eda`; no seed |
| Pack | `papertrail-document-access` 1.0.0, tree `sha256:529d3cd3…6c31`, manifest `sha256:a4c4ce48…a8804c8` |
| Profile | `papertrail-reference` 1.0.0, `sha256:a1c130c2…6835` |
| Target image | `sha256:98548ec48d8d796fca5adaf4aab3e461bee38210bd1d568281f79190685eac2e` (image-inspect `Id` and the container's `Image`) |
| Verifier image | `sha256:e880f609a7c4d292441e22d1d0d5d7c876697dd4e1e657a668b2b6266969fecc` (likewise) |

## 3. Execution sequence (from the operation journal and Docker's own records)

The journal (`docker-ops-v2`, 27 operations) has a requested and a completed line for every
operation, with contiguous sequence numbers. No operation timed out. Times are UTC, from the
journal unless noted.

| # | Operation | Time | Observed fact |
|---|---|---|---|
| 1–4 | before-inventory listings | 04:18:52.450–58.424 | complete; the first listing took 5.59 s because it started Docker Desktop's idle VM (section 6) |
| 5–6 | image inspect ×2 | 58.460–58.649 | exactly the two r2 IDs; `Id` matches |
| 7 | **create target** | 58.657–58.790 | the create output is the journaled ID `fd0f282e8842…` |
| 8 | inspect target (pre-start gate) | 58.793–58.877 | state `created`; the gate passes when re-run on the saved inspect (section 4) |
| 9 | **create verifier** | 58.881–58.996 | ID `8573bf8701d0…`; network `container:<exact target ID>` |
| 10 | inspect verifier (pre-start gate) | 58.999–59.068 | state `created`, start time zero, process ID 0; the gate passes when re-run |
| 11 | **start target** | 59.071–59.363 | Docker `StartedAt` 04:18:59.153 |
| 12–14 | readiness polls | 59.367–00.574 | `running`, health `starting` |
| 15 | readiness poll | 01.080–01.141 | `running`, health **`healthy`**; Docker's health check ran 04:19:00.341–00.812, exit 0 (1.66 s after start) |
| — | **checkpoint → SIGTERM** | between #15 and #16 (inferred from order) | see section 5 |
| 16 | target logs | 01.145–01.206 | stdout 0 B and stderr 194 B, stored as separate untrusted artifacts |
| 17 | inspect verifier | 01.207–01.266 | still `created`, never started |
| 18 | **remove verifier** (`container rm -- <full ID>`) | 01.269–01.348 | exit 0; no force |
| 19 | inspect verifier | 01.350–01.415 | exit 1, "No such container": **confirmed absent** |
| 20 | inspect target | 01.420–01.477 | still `running`, `healthy`, same `StartedAt` |
| 21 | **stop target** (`--time 5`) | 01.479–01.821 | exit 0, graceful |
| 22 | **remove target** (`container rm -- <full ID>`) | 01.823–01.917 | exit 0; no force |
| 23 | inspect target | 01.920–01.990 | exit 1, "No such container": **confirmed absent** |
| 24–27 | after-inventory listings | 02.009–02.581 | complete |

**Counts (independently recounted):** 2 creations, 1 start (the target), 0 attached starts, 1
stop, 2 removals, 10 container inspects, 2 image inspects, 1 log read, 8 listings. No other
kind of operation: no exec, kill, pull, build, network, volume, prune or force removal. Every
container-level operation names one of the two owned full IDs and nothing else. No operation
names a candidate.

**Order versus the owner's audit checklist.** The verifier was created and inspected *before*
the target started (#9–10, then #11), not after the target was ready. This is the accepted
runner's order: the earlier live comparison did the same (operations 7–11 there). The
checkpoint condition still held when the report was sent: target `READY`, verifier created,
inspected and not started.

**Ownership journal:** planned target, created target, planned verifier, created verifier,
then cleanup verifier `REMOVED` and cleanup target `REMOVED`. The IDs equal the create outputs.

## 4. Isolation and resource limits (saved create argv and pre-start inspects)

For each container, the executed create argv equals the fixed policy argv rebuilt by the
accepted code from the frozen plan. The accepted pre-start gate (`check_run_container`), re-run
on each container's saved pre-start inspect, **passes**. An independent field-by-field check
of the same inspects agrees:

| Property | Target | Verifier |
|---|---|---|
| Image | r2 target ID | r2 verifier ID |
| User | `10001:10001` | `10001:10001` |
| Root filesystem | read-only | read-only |
| Capabilities | `CapDrop` `ALL`, no `CapAdd`, not privileged | same |
| `no-new-privileges` | set | set |
| seccomp | default (no seccomp override, nothing unconfined) | same |
| Network | `none` | `container:<exact target ID>` |
| Ports, bridge | no port bindings, no publish-all, not attached to `bridge` | same |
| Mounts | one read-only bind at `/app/source` (the r1 snapshot's source directory) | one read-only bind at `/pack` (the approved pack copy) |
| Docker socket, credentials, volumes | none | none |
| IPC, cgroup namespace, restart | private, private, `no` | same |
| CPU, memory (no swap), PIDs | 1 CPU, 1 GiB, 128 | 1 CPU, 512 MiB, 128 |
| tmpfs (`noexec,nosuid,nodev`) | `/scratch` 256 MiB, `/tmp` 64 MiB | `/scratch` 112 MiB, `/tmp` 16 MiB |
| Logging | `local`, 2 × 5 MB, no compression | same |
| Labels | installation, run, owner `patchproof`, pair 1, side `baseline`, role, purpose `verification-run` | same |
| Environment | no Docker host, credential or agent variables; no `PYTHONOPTIMIZE` | same |

**No security finding.** Inspection is configuration evidence, not proof of kernel
enforcement.

## 5. Checkpoint and signal

| Fact | Source | Value |
|---|---|---|
| Checkpoint report | child (`interruption.json`) and controller (`delivery.report`), equal | stage `baseline-target-ready`, this run ID, the child's PID, both exact container IDs, target `READY`, verifier `CREATED_INSPECTED_NOT_STARTED` |
| Child identity | controller record | the reported PID equals the controller's `child_pid` and the delivery PID; the claim names the controller's own PID (the parent), which the child checks before running |
| Signal | controller | `SIGTERM_SENT`, `signals_sent` 1 |
| Deadline | both | delivered **25.0 s before** the send-by time, inside the 30 s synchronization window |
| Observed by the child | child | exactly one signal, `SIGTERM`; `revision_interruption` `["SIGTERM"]` |
| Timing (shared monotonic clock) | both | report → delivery 0.66 ms; delivery → child observed 0.37 ms; strictly ordered |

Two separate processes recorded these facts and their records agree. The checkpoint's
wall-clock time is not recorded; the table in section 3 places it by operation order.

## 6. Cleanup and resource preservation

| Check | Result |
|---|---|
| Owned containers remaining | none: both confirmed absent by Docker (#19, #23); neither ID appears in the before or after inventory |
| Before vs after (by exact ID and attributes) | identical: 14 images, 7 containers, 5 networks, 10 volumes |
| Listing artifacts | the inventory hashes equal the stored listing outputs |
| Seven unrelated containers | all `exited`, none PatchProof-labelled, all identical before and after; never inspected, stopped or removed |
| Reconciliation | `CONSISTENT`, no findings, `daemon_restart_suspected` false |
| Versus the preflight (2026-10-14 03:59Z) and the earlier run | images, containers and volumes identical by ID. The built-in `bridge` network has a new ID (`a279dd898ec3…`; preflight `3323265a6a33…`; earlier run `4c010519b461…`), with the same name, driver and scope |

**Attribution of the `bridge` ID change (supplementary evidence, outside the saved run
evidence).** Docker Desktop's own host log, read as a file (no Docker command) and treated as
untrusted, records that Docker Desktop stopped its idle VM at 04:04:44Z. The run's first
listing then woke it ("idle → busy … images/json") at 04:18:52.65Z. It was running at
04:18:57.36Z, before the run's first listing returned, and it next stopped at 04:24:03Z. Docker
recreates the built-in networks when its VM restarts. Both inventories therefore come from one
VM session, which is consistent with the identical before and after listings. The target also
ran continuously (unchanged `StartedAt`) from start to stop. Without that log, the saved
evidence alone could not attribute the change: an unchanged network ID does not prove the
daemon never restarted.

## 7. Recomputed lifecycle and verdict

The verdict input was rebuilt from the underlying records, not copied:
- **Execution record:** started true, target `READY`, verifier `NOT_STARTED`, stream
  `ABSENT`, 0 events and 0 bytes.
- **Observations:** the verifier stream and observation files are empty (0 B), and the
  accepted collector yields no cells from them.
- **Pack tests:** taken from the repository pack.
- **Termination:** `interrupted`, from the child's signal record.
- **Preconditions:** from the current approval check and the re-run gates.

The rebuilt input equals `verdict-input.json`. The accepted engine on it returns a record
equal to the whole stored `verdict.json`.

| Field | Recomputed | Saved (outcome, verdict, controller) |
|---|---|---|
| Verdict, rule | `INCONCLUSIVE`, **V-05** | same |
| Reason codes | `RUN_INTERRUPTED`, `EVENT_STREAM_TRUNCATED`, `REPETITION_INCOMPLETE`, `REQUIRED_CHECK_INCOMPLETE` | same |
| Cells | 16 required, 0 trusted; 0 pairs terminated normally | same |
| Flags | `incomplete_checks` true; the other six false | same |
| `execution_started` | true (the baseline target started) | same |
| Run termination | `interrupted` | same |
| Lifecycle | `INTERRUPTED` | same |
| Evidence | `INCOMPLETE` | same |
| Lifecycle exit code | 20 | child 20; controller's `child_lifecycle_exit_code` 20 |
| Cleanup (separate dimension) | `COMPLETE`: both `REMOVED`, none remaining | same |
| Candidate executed, verifier started, verified | false, false, false | same |
| `evaluated_at` | 04:19:02.005054Z, between execution start (52.440) and finish (02.583) | same in `verdict.json` and `outcome.json` |

- **No verified result was possible:** with the same inputs but termination set to
  `normal`, the engine still returns `INCONCLUSIVE` (V-05), because no trusted observation
  exists.
- **Execution timestamps:** `execution_started_at` (04:18:52.440Z) is taken before the first
  Docker operation, as documented. The boolean `execution_started` reflects the target start
  (04:18:59.07Z).

**Controller versus application.** The controller's `EXPECTED_OUTCOME_OBSERVED` and
`harness_exit_code` 0 are the test harness's own status. They say the intended interruption
and cleanup were observed. The interrupted run's status is separate: lifecycle `INTERRUPTED`,
exit 20. The harness exit code is recorded in `controller.json`. The **shell exit code of
either command was not captured** independently and is not inferred here.

## 8. Evidence hardening (compared with `run-036553ef…`, both unchanged)

| Property | Earlier run (journal v1) | This run (`docker-ops-v2`) |
|---|---|---|
| Target output | one log file holding stdout only (empty); stderr inline in the journal | `untrusted-target-stdout-…` (0 B) and `untrusted-target-stderr-…` (194 B), separate; capture status, size, hash and truncation in `revision-…json`, matching the files and the journal descriptor |
| Verifier console | inline in the journal | its own artifact when the verifier runs; here `NOT_ATTEMPTED`, no artifact, because it never started |
| Journal content | inline output strings | descriptors only (class, size, hash, cap, truncation, artifact); no target output appears anywhere in the journal |
| Docker output | inline | bounded `docker-ops-<seq>-<stream>.out` files; every stored file matches its descriptor (hash, size, under cap, not truncated); empty streams `EMPTY` with no file |
| Times | none per operation | UTC start and end and a monotonic duration on every operation |
| `evaluated_at` | the run's start time | read at evaluation, ordered between start and finish (`order` `CONSISTENT`) |
| Integrity check | `CONSISTENT`/`FINALIZED` | `CONSISTENT`/**`INCOMPLETE`**: accepted as intact, not presented as a finalized comparison |

## 9. Findings

1. **Authorization metadata is not substantive (procedural; does not affect the technical
   result).** The consumed authorization's rationale is "testing for implementation" and its
   scope is "idk". The record is intact and was used exactly once. It must not be rewritten,
   deleted, superseded or reused. The technical scope was fixed by the frozen plan, not by
   these fields. Proposals are below.
2. **Deprecated stop flag (low, compatibility).** Docker 29.8.2 printed "Flag --time has been
   deprecated, use --timeout instead" for the stop operation (stored in its output file). The
   stop succeeded. A later Docker release could remove the flag; cleanup would then need its
   force-removal path. Changing the accepted stop argv needs owner review, so it is not changed
   here.
3. **Checkpoint wall-clock time not recorded (info).** The checkpoint and signal carry only
   monotonic times. Their position in the UTC timeline is inferred from operation order.

### Owner decision on finding 1 (2026-10-14)

The owner does not require a separately signed post-run note for PP-008 acceptance. The
deficiency is recorded as an **accepted audit-quality limitation**, not a runtime-policy failure.
The frozen plan bound the exact baseline, images, approved pack, signal operation, resource
limits and two-container budget, and the run stayed within it. The consumed authorization is
not rewritten, deleted, superseded or repaired. No owner signature or attestation was created.
The draft note proposed during the audit is not adopted.

### Proposed validation for future authorizations (carried forward to PP-009; not implemented)

This applies to the rationale and scope fields of the interruption, run and pack-approval
owner commands. It is a procedural quality check, not proof of intent, and it applies only to
new records; stored records stay readable.
- Reject a value shorter than 20 characters, or with fewer than 4 words.
- Reject a value that, case-folded and stripped of punctuation, is in a small deny-list:
  `idk`, `test`, `testing`, `n/a`, `na`, `none`, `todo`, `tbd`, `asdf`, `ok`, `yes`, `?`.
- Reject a scope identical to the rationale.
- For the interruption and run commands, require the scope to contain the displayed run ID.
- Keep the existing rule that neither field may contain the confirmation phrase.
- Show the reason and ask again; never auto-fill.

## 10. Preflight discrepancy (2026-10-14 03:59Z; original output preserved)

The preflight script ran 46 checks: 45 passed and 1 failed. The failed check, written for the
preflight and not part of any accepted gate, was `no containers exist (running or stopped)`,
implemented as "the container listing is empty". It listed the seven unrelated containers.

- **Script exit code:** the script exits 1 on any failed check, so it exited 1. The preflight
  command piped its output through `tee`, so the shell saw `tee`'s 0. This was not noticed or
  reported then.
- **Mandatory or diagnostic:** diagnostic. The owner's requirement was "no foreign or
  unexplained **running** container would interfere". No accepted policy requires an empty
  daemon. The runner needs a complete before-inventory, compares by identity and touches only
  exact owned IDs.
- **Were the seven containers acceptable?** Yes. A separate manual comparison, made after the
  script and not itself scripted, showed all seven stopped, unrelated and identical by ID and
  attributes to the earlier run's inventories. This run confirms it: they were preserved and
  never touched.
- **Did the runner's own preconditions pass?** Yes, independently: the run's own
  preconditions all `PASSED`, both pre-start gates pass on re-run, and both inventories are
  complete.
- **Corrected interpretation:** the preflight result should have read **"PASS on every
  mandatory check; one auxiliary diagnostic FAILED (empty-daemon assertion, stricter than the
  requirement); requirement met by a separate manual comparison; script exit code 1"**. The
  earlier report did disclose 45/46 and named the failed check, but gave the overall result as
  a plain PASS and didn't give the exit code. The failed check stays FAILED; it is not
  relabelled.
- **Also preserved:** the preflight's daemon facts (Docker Desktop 4.94.0, server 29.8.2,
  seccomp, cgroup v2) describe the VM session that started at 03:59:35Z. The run used a later
  session; the saved run evidence does not record the daemon version.
- **Follow-up (owner, 2026-10-14; carried to PP-009):** future preflight workflows must keep
  each command's exit code through pipelines (for example `set -o pipefail` or checking
  `PIPESTATUS`, never only the last command of a `tee` pipeline). They must also label each check
  as a mandatory gate or an optional diagnostic and fail closed on any failed mandatory gate.

**This audit's script** failed one check on its first full pass: a timestamp comparison done
as text, where `…51Z` sorts after `…51.903991Z`. It was corrected to compare times, and the
final pass is 159/159.

## 11. PP-008 completion assessment

| Requirement | Evidence | Status |
|---|---|---|
| Source and verifier separation | both runs: the source is mounted only in the target, the pack only in the verifier, read-only, in separate containers | **PASS** |
| Successful live security comparison | `run-036553ef…`: `VERIFIED_FOR_CASES` (V-09), independently reproduced | **PASS** |
| Semantic vulnerability witnesses | `run-036553ef…`: AUTH-001 and AUTH-003 `VIOLATION_CONFIRMED` on r1 and `SECURE` on r3, from structured witnesses; raw responses not retained (documented design limit) | **PASS** (with the documented witness-depth limit) |
| Positive functional controls | `run-036553ef…`: FUNC-001–004 `PASS` on both sides; no witness record for passes (documented) | **PASS** |
| Complete structured verifier events | `run-036553ef…`: both streams complete with session end; this run: correctly `ABSENT`, never invented | **PASS** |
| Trusted verdict evaluation | both verdicts recomputed by the accepted engine from rebuilt inputs; equal | **PASS** |
| Interrupted execution handling | this run: deterministic checkpoint, one SIGTERM, `INTERRUPTED`, exit 20 | **PASS** |
| Accurate incomplete evidence | this run: `INCOMPLETE` in manifest, outcome and verifier; `V-05` | **PASS** |
| Single-use authorization | both consumed exactly once; no executable authorization remains in either store | **PASS** (procedural metadata deficiency in finding 1, separate) |
| Exact-ID container cleanup | both runs: every removal by full owned ID, confirmed absent, no force | **PASS** |
| Isolation configuration enforcement | both runs: create argv equals policy; gate re-run passes; independent field check agrees | **PASS** (configuration evidence) |
| Preservation of unrelated Docker resources | both runs: before equals after by identity within each run; the bridge recreation between runs is attributed (section 6) | **PASS** |
| Evidence integrity | both runs: accepted verifier and independent re-implementation agree; both unchanged by audits | **PASS** |
| Known limitations | documented here and in the first-run review | **PASS** (documented) |
| Every owned container labelled with installation and run ID (backlog) | all six containers across both runs | **PASS** |

**Required before PP-008 acceptance (owner decisions, no technical blocker):**
1. Owner review of this audit.
2. The owner's decision on finding 1: whether a signed post-run note is wanted before
   acceptance.
3. Owner approval to commit this report and the `STATUS.md`/backlog updates. They are not
   committed.

**Recommended, not required:**
- the authorization-field validation above (new code, owner review);
- the `--time` → `--timeout` stop-flag change (accepted-policy change, owner review);
- a recorded UTC time for the checkpoint;
- optionally, a read-only `recover_run` confirmation that nothing remains. The saved
  after-inventory already shows this; running it needs Docker approval.

At the time of this audit PP-008 remained `IN_PROGRESS`, READY_FOR_REVIEW.

**Owner decisions after this audit (2026-10-14).** The owner accepted PP-008, conditional on a
documentation review and committed-tree validation. The owner does not require a signed
post-run note: finding 1 is an accepted audit-quality limitation. Stronger rationale and scope
validation and fail-closed preflight reporting are carried forward to PP-009. The acceptance gate
is recorded in `docs/evidence/pp-008-acceptance-gate.md`.

## Limitations

- One pair, one fixed fixture (D1), 8 selected checks, a synthetic reference application.
- The reviewer identity is a local assertion; terminal gating and approvals are procedural.
- Container inspection is configuration evidence, not proof of kernel enforcement.
- Daemon continuity rests on Docker Desktop's own log, outside the saved evidence.
- Shell exit codes, the checkpoint's wall-clock time, HTTP traffic and the daemon version at
  run time are not part of the evidence.
- SIGKILL, host crash and daemon-restart recovery paths were not exercised live.
- The hardened verifier-console capture path was not exercised live, because the verifier never
  started here. The successful comparison predates hardening (journal v1).
- The stop flag `--time` remains unchanged pending a separately reviewed policy change.
