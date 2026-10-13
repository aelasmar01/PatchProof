# Verification runs: target/verifier runner and typed event transport (PP-008)

**Spec:** `PROJECT_SPEC.md` §5.2, §7.3–7.5, §8, §10.1–10.6, §15.2 · **ADRs:** ADR-003, ADR-008, ADR-009
**Verdict specification:** §3 (grammar and outcomes), §4 (trust), §5 (preconditions and
validation)

> **State A only: Docker-free implementation and synthetic validation.** No image has been
> pulled or built. No container has run, PaperTrail has not been executed, and no real
> verifier collection exists. Every comparison verdict in the tests comes from **synthetic**
> event streams fed through a **fake** Docker executor, so it shows that the parts compose.
> It is not an application-security result. Images (gate B) and live execution (gate C)
> need separate owner approval: `docs/architecture/run-images.md`.

## Modules

| Module | Responsibility |
|---|---|
| `runner/run_policy.py` | Fixed run-container policy: role commands, labels, typed read-only inputs, the create argv, its exact-shape check, and the `RunCreate`/`StartAttached` operations |
| `runner/run_gate.py` | Inspect-before-start gate for run containers |
| `runner/inputs.py` | Content-addressed pack snapshots (PP-007 R2) and source-snapshot re-verification |
| `runner/run_plan.py` | Typed plan; precondition recomputation; the approved run-image registry (gate-B r2 images); the fixed profile runtime values |
| `runner/profiles.py` | Strict, read-only loader for versioned execution profiles in `profiles/` |
| `pack_approval.py` | Owner-operated PaperTrail pack approval (PP-007 functions; see `packs-and-approvals.md`) |
| `runner/revision.py` | One revision execution: images, inputs, create and gate, readiness, attached verifier, observation, cleanup |
| `runner/collector.py` | Trusted parser and classifier of one verifier event stream |
| `runner/comparison.py` | Pairs × sides, post-run checks, verdict input, the unchanged PP-004 engine; three optional hooks (re-validation before a revision, a stop policy after one, persistence of each result) that default to no effect |
| `core/records/authorization.py`, `schemas/run-authorization.schema.json` | The run-authorization contract 1.0 and its frozen plan document |
| `core/run_authorizations.py` | Semantic checks, the confirmation phrases, creation, the private store, supersession of unused records, and the single-use claim |
| `runner/papertrail_plan.py` | Recomputes the one frozen plan kind `papertrail-authz-r1-r3-one-pair-v1` from the real private artifacts |
| `runner/run_evidence.py` | Exclusive private evidence directory, write-once files, the metadata-only Docker operation journal (`docker-ops-v2`) with bounded output artifacts and the creation budget, inventory capture and reconciliation by identity |
| `runner/interruption_point.py` | Interruption-test synchronization: the child's checkpoint and the controller's single SIGTERM; not reachable from any production driver |
| `core/records/interruption.py`, `schemas/interruption-test-authorization.schema.json` | The separate interruption-test authorization contract 1.0 (baseline only, two containers, one SIGTERM) |
| `core/interruption_authorizations.py` | Its semantic checks, phrases, creation, the separate private store, supersession of unused records, and the single-use claim naming the controller |
| `runner/interruption_plan.py` | Recomputes the one plan kind `papertrail-interruption-sigterm-baseline-v1` (r1 only) from the real private artifacts |
| `runner/interruption_run.py` | Executes one claimed interruption test: baseline only (four guards), the checkpoint, evidence, the lifecycle/verdict/exit-code classification |
| `interruption_authorization.py`, `interruption_test.py`, `interruption_child.py` | Owner-operated: authorize the test once; the controller that runs it once; the runner child only the controller starts |
| `runner/authorized_run.py` | Executes one claimed authorization: per-revision re-validation, the D2 baseline stop, evidence, inventories; separate evidence, lifecycle and cleanup states |
| `runner/interrupts.py` | SIGINT, SIGTERM and SIGHUP become one interrupt so cleanup and finalization run; repeats are ignored |
| `runner/run_recovery.py` | Read-only assessment of one consumed run's containers; exact-ID removal of verified owned ones |
| `run_authorization.py`, `run_papertrail_once.py`, `recover_run.py` | Owner-operated entry points: authorize once; execute once; status and confirmed cleanup after a hard kill |
| `verifier/patchproof_verifier/launch.py` | Fixed verifier entry point; opens the event channel before pytest starts |
| `verifier/patchproof_verifier/plugin.py` | Collection, typed event emission, failure classes, per-test deadline |
| `verifier/patchproof_verifier/events.py` | Event writer; the verifier-side pack-tree hash |
| `verifier/patchproof_verifier/transport.py` | Fixed standard-library HTTP client to 127.0.0.1:8080 |

## Execution topology and policy

One revision execution uses exactly two containers.

| | Target | Verifier |
|---|---|---|
| Network | `--network=none` | `--network=container:<exact target ID>` |
| Input | source snapshot → `/app/source` (read-only bind) | pack snapshot → `/pack` (read-only bind) |
| Command | fixed uvicorn invocation of the profile's `module:callable` | fixed launcher invocation with run, pair and side |
| Never receives | the pack or verifier files | target source |

**Reused unchanged from PP-003:**
- user 10001:10001, read-only rootfs, `--cap-drop ALL`, `no-new-privileges`, default
  seccomp;
- private IPC and cgroup namespaces;
- bounded `/scratch`, `/tmp` and `/dev/shm`;
- the PID, memory, swap and CPU limits under the accepted code-level ceilings;
- rotating `local` logs (2 × 5 MiB);
- `--pull=never`, exact platform, `--restart no`.

**Enforced:**
- **No caller-supplied options:** no Docker argument, mount, environment variable or
  command can be supplied by a caller. `assert_run_create_shape` refuses `--publish`,
  `--env`, `--volume`, `--privileged`, `--network=host` and more.
- **Exactly one input:** each container has exactly one read-only bind, with a fixed
  destination.
- **Input source:** a canonical, owner-only, non-writable directory, without characters that
  could break `--mount` parsing.

**Wrapper admission (gate C, owner-approved 2026-10-13):** `RunCreate` and `StartAttached`
are in `docker_cli.ALLOWED_OP_TYPES`, each only in its single fixed shape
(`docs/evidence/pp-008-gate-c.md`).

## Execution profile and runtime consistency (PP-008)

**Storage:** versioned profiles live in the repository at
`profiles/<profile_id>-<profile_version>.json`. They are review-controlled inputs. The only
one is the **proposed** `profiles/papertrail-reference-1.0.0.json`, with canonical hash
`sha256:a1c130c2f8b90c2ada2001ef3bc336b0b8ec29886fd92635dbf5928eb8036835` (the canonical
JSON of the validated model, as PP-007 binds it). The owner reviews it as one binding of the
pack approval; it is not approved on its own.

**Loader (`runner/profiles.load_profile`)** fails closed. It requires:
- an absolute canonical path, no symlink, a regular file read with `O_NOFOLLOW|O_NONBLOCK`
  and re-checked by identity, at most 16 KiB;
- strict JSON (duplicate keys refused), the execution-profile 1.1 model (unknown fields and
  other versions refused), then the PP-003 `check_profile_document`;
- a file name equal to `<profile_id>-<profile_version>.json`;
- no placeholder text and no placeholder, rejected, unapproved or role-swapped image ID; a
  known fixture contract; a source scope inside the PP-005 grammar;
- every runtime value equal to the enforced one (below);
- a recomputed canonical hash equal to the expected binding.

Nothing is migrated, normalized, defaulted or written. The schema-corpus example (version
0.2.0, placeholder images) and the standalone collection role cannot stand in for this
profile.

**Every runtime value must equal what the runner enforces** (`run_plan.FIXED_PROFILE_RUNTIME`).
A stricter value is refused too, because the runner does not support arbitrary Docker policy
values; the profile must describe what actually runs. `RunPlan` refuses an inconsistent
profile when the plan is built, and the loader refuses it on load.

| Profile value | Required | Where it is enforced |
|---|---|---|
| `resources.target` cpus, memory, pids, scratch, tmp | 1, 1 GiB, 128, 256 MiB, 64 MiB | `limits_from_profile` → `--cpus`, `--memory`/`--memory-swap`, `--pids-limit`, `--tmpfs size=`; confirmed by the pre-start inspect gate |
| `resources.verifier` cpus, memory, pids, scratch, tmp | 1, 512 MiB, 128, 112 MiB, 16 MiB | same |
| `timeouts.readiness_seconds` | 30 | readiness poll in `execute_revision`; equals the target health check's start period |
| `timeouts.request_connect_seconds`, `request_read_seconds` | 5, 5 | `verifier_command` → `--connect-timeout`, `--read-timeout` → verifier HTTP transport |
| `timeouts.revision_deadline_seconds` | 180 | `ResourceLimits.deadline_seconds`, the revision deadline; values above the ceiling are now refused, not clamped |
| `timeouts.cancellation_grace_seconds` | 5 | `--stop-timeout 5` and `docker stop --time 5` (`STOP_GRACE_SECONDS`) |
| `logging.max_file_bytes`, `max_files` | 5242880, 2 | `--log-driver local --log-opt max-size=5m --log-opt max-file=2` |
| `result_cap_bytes` | 10485760 | verifier stdout read bounded at cap + 1; the collector's `OVER_CAP` |
| `network_policy` | `none-shared-loopback-v1` | target `--network=none`; verifier `--network=container:<exact target ID>`; checked by the inspect gate |
| `target_image_id`, `verifier_image_id` | the r2 images | `APPROVED_RUN_IMAGES`; image inspect before each revision |
| `source_scope.include` | `papertrail`, `fixtures/synthetic` | each source snapshot's manifest must record exactly this inclusion scope, before the run (`source_identity`) and before each revision |

## Pack and source integrity (PP-007 R2, closed)

- **Materialization:** `materialize_pack` re-reads each validated file without following
  symlinks or blocking, compares it with its validated size and SHA-256, and writes it with
  `O_EXCL` into `<store>/<pack_tree_sha256 hex>/`. Files are made `0444` and directories
  `0555`; the copy is re-hashed, then renamed into place atomically. A file changed, swapped
  or symlinked after validation is refused, and nothing is copied.
- **Before each revision**, and once more after the run:
  - `verify_pack_snapshot` re-hashes every file, checks the exact file set, the modes and
    ownership, the content address, the pack-tree hash and the manifest hash;
  - the plan's manifest must equal the snapshot's `pack.json`.

  A change found after the run fails `pack_integrity` as post-execution.
- **Source snapshots:** `verify_source_snapshot` re-hashes the PP-005 manifest bytes against
  the planned hash, then every file against the manifest and the source-tree hash.
- **Approval:** `check_preconditions` recomputes every approval binding (manifest, tree,
  collection, verifier image, plugin version, profile hash). A changed, superseded or
  missing approval blocks the run before any container is created. It is never revalidated
  as though it still held.

## Readiness, verifier execution and observation

**Readiness:** the target image carries a fixed exec-form `HEALTHCHECK`, a standard-library
GET of `/health`. The host polls `docker inspect` for `State.Health.Status`:
- `healthy` gives `READY`;
- `unhealthy` or a stopped target gives `STARTUP_FAILED`;
- the readiness deadline gives `READINESS_TIMEOUT`.

A target that never becomes ready means the verifier is never started.

**The verifier** is started attached:
- its standard output is the event channel, read live and bounded at `result_cap_bytes + 1`
  within the remaining revision deadline;
- a verifier still running afterwards is stopped by exact ID;
- the exit code, OOM state, and whether the target exited during the tests come from
  `docker inspect`. Exit codes above 128, after a host stop or an OOM, become `SIGNALED`.

**Target logs** are read bounded (5 MiB), kept separately, labeled untrusted, and never
parsed. A test feeds a target log containing a complete forged event stream; it has no
effect on the verdict.

**Cleanup:** PP-003 `remove_owned`, by exact registered ID, after re-inspecting identity and
the installation and run labels. A container whose labels no longer match is refused and
left in place. Nothing outside the run's own containers is ever touched; a test asserts
this.

## Event transport

**The launcher:** `python3 -I -B -m patchproof_verifier.launch` duplicates the original
standard output to a private descriptor, then points descriptor 1 at standard error,
**before importing pytest**.
- **Why:** an end-to-end test found that pytest keeps its own copy of standard output from
  startup, so a plugin alone cannot keep pytest's output out of the channel.
- **The result:** pytest's report, test prints, and even raw `os.write(1, …)` from a test
  all go to standard error.
- **The plugin** writes compact JSON events, numbered from 0, to the private descriptor
  only. It refuses to run without that descriptor or with plugin autoloading enabled.

**Failure classes:**
- `SecurityTerminal` in the call phase is `security_terminal`;
- `HelperMisuse` is `helper_misuse`;
- the per-test deadline (`SIGALRM`, from the pack's `case_timeout_seconds`) is `timeout`;
- `AssertionError` is `assertion`;
- anything else, including request failures, is `exception`.

`session_end` is emitted only when every collected test has fully reported.

**The host collector** (`collect_stream`) accepts only those bytes. It applies the §3.1
grammar strictly and classifies the stream:

| Status | Scope | When |
|---|---|---|
| `ABSENT` | local | no bytes |
| `OVER_CAP` | local | more than the cap; no cells (D6) |
| `MALFORMED` | global | bad line, sequence gap or duplicate, grammar or window violation, bad `session_end` counts, anything after `session_end` |
| `IDENTITY_MISMATCH` | global | run, pair or side, pack hash, plugin version, or collected list differs from the plan |
| `TRUNCATED` | local | valid prefix without `session_end`; the cut block becomes `INTERRUPTED` |
| `COMPLETE` | — | full grammar and counts, within the cap |

Cells come from the accepted PP-007 `derive_outcome`. The PP-004 engine and its decision
table are unchanged. The engine also re-checks the result cap, exit-code consistency (G3)
and the global stream failures (G1) itself.

## Verifier HTTP transport

`TargetTransport` (standard library):
- **Fixed target:** host `127.0.0.1`, port 8080, GET only.
- **No proxies:** `http.client` never reads proxy variables; a test sets them to a dead
  address.
- **No redirects:** a 302 is returned, and the witnesses treat it as inconclusive.
- **Timeouts:** separate connect and read limits.
- **Size cap:** a declared or streamed body over the cap raises `TargetResponseError`.
- **Request validation:** paths must be plain absolute paths, and bearer tokens short
  printable ASCII.
- **Failures:** a failed request raises `TargetRequestError`, which becomes a test error
  (`exception`), never a vulnerability.

## Run authorization and the first PaperTrail comparison (PP-008)

A pack approval never authorizes a run (spec 7.5). The first live comparison, r1
(vulnerable) against r3 (correct), needs a separate, single-use **run authorization** that
binds one frozen plan. Nothing here is a general workflow; PP-009 replaces it.

**Plan (`papertrail-authz-r1-r3-one-pair-v1`), recomputed by `assemble_run` from the real
artifacts, never from a draft:**
- the run ID and installation ID; the current pack approval, `APPROVED` for freshly
  recomputed bindings, with an unambiguous history;
- the pack (ID, version, manifest, tree), the exact collection in order, the plugin version;
- the profile ID, version and canonical hash; both approved r2 images;
- for each side: tag, full commit and tree IDs, snapshot directory name, manifest SHA-256 and
  source-tree SHA-256. The snapshot is found by commit in the private store (exactly one) and
  re-hashed. The inclusion profile hash and the included paths;
- **fixed-fixture mode (owner decision D1, 2026-10-13):** `synthetic-documents-v1` with its
  exact hash in both snapshots and in the pack, no seed, identical data for both sides, a
  fresh target container per side, exactly one pair. A narrowly scoped v0.1 exception to
  seeded repetition; a pack declaring more pairs is refused. Seed variation is PP-019;
- one pair; baseline then candidate; sequential; no automatic retry; at most four container
  creations, with their exact names;
- **baseline failure policy (owner decision D2):** `stop-before-candidate-on-execution-failure`;
- every runtime value (resources, timeouts, logging, result cap, per-case timeout, response
  cap, network policy, target address) and the evidence destination `evidence/runs/<run-id>`.

The plan hash is the SHA-256 of the plan's canonical JSON. The schema fixes the constant
parts (one pair, four containers, no seed, no retry, single use); `check_authorization` adds
what a schema cannot: the hash, the container names and evidence path derived from the run
ID, placeholder identities, sorted inclusion paths and distinct target and verifier images.
The reusable contract deliberately allows the baseline and candidate to be the same revision
(spec 17.2 compares the unchanged vulnerable revision against itself). Only this driver
restricts revisions: `check_first_run_scope` requires exactly r1 (`68b2bc0e…`) as baseline and
r3 (`2fb6d093…`) as candidate, tag, commit and tree, against module constants. Both commands
apply it: `assemble_run` for every recomputed plan, and the execution command to the stored
plan before anything else.

**Store and claim (`<user data>/run-authorizations/`, 0700).** The PP-007 store discipline:
owner-checked, no symlinks, stable directory identity, `O_EXCL` read-only records, bounded
strict reads, unexpected entries refused. A run ID is never reused. An unused authorization
may be superseded by a new one, never edited; a claimed one can never be superseded.
Execution starts with a **claim**: `rau-<id>.claim`, created with `O_EXCL`, fsynced with its
directory, before the first Docker operation. It is never removed. A claim that is empty or
unreadable (a crash during the claim) is `INDETERMINATE` and counts as consumed. So a crash
before the claim leaves the authorization usable and nothing has run; a crash after it
leaves the authorization consumed.

**Owner commands.** Both use the pack-approval interactive gate: no arguments, no
`PATCHPROOF*` variables, an interactive foreground terminal.
- `python -I -m patchproof.run_authorization`: freezes a fresh run ID, shows the complete
  plan, the four containers, the limits, the declared expectations and the limitations,
  asks for identity, rationale and scope (never containing the phrase), then
  `AUTHORIZE <run-id> <plan-sha256>`; recomputes everything before writing; reads back and
  verifies after. Exit 0 verified; 2 nothing written; 4 written but not verified.
- `python -I -m patchproof.run_papertrail_once`: requires the single unused authorization,
  a plan recomputed now that equals it exactly, and a typed `EXECUTE <run-id>`; then claims
  it, creates the evidence directory exclusively and runs. Exit 0 finalized, lifecycle
  `COMPLETE`, cleanup verified, inventory consistent; 5 finalized but needs attention (a
  stop, unverified cleanup, any inventory change, a suspected daemon restart); 4 incomplete
  evidence; 3 consumed but nothing executed; 2 refused, nothing consumed. An exit code is
  never a verdict.
- `python -I -m patchproof.recover_run`: see *Hard termination and recovery* below.

**Before each revision** the driver re-validates the pack approval, the authorization record
and its claim bytes (and that it is not superseded), and the whole plan recomputed from the
current artifacts. A failure fails the matching precondition (pre-execution before anything
started, post-execution after). `execute_revision` re-checks images, pack and source bytes
itself. Before the candidate, the built-in network identities are listed again: a change
means Docker lost continuity, and the run ends `interrupted`.

**D2 stop.** After the baseline, the candidate is not started if the baseline had a
precondition failure, fails the engine's own execution-trust rule (readiness, termination,
exit code, OOM, deadline, runtime errors, stream status, cap), or did not verify removal of
both containers. The engine's rule is reached through one boundary,
`authorized_run.engine_execution_trust` (the only use of `verdicts._execution_trusted` and
`_execution_reasons`, applied to the engine's own parsed record). The engine is unchanged.
`test_d2_boundary_agrees_with_the_public_engine` pins the boundary to the public `evaluate`
result for 13 execution faults: D2's trust decision must equal the public
`pairs_terminated_normally`, and its codes must equal the public execution reasons for that
baseline. An engine change that moved either would fail that test. The
run ends `interrupted`, so the engine's verdict is incomplete (`INCONCLUSIVE`) and can never
be `VERIFIED_FOR_CASES`. A trusted baseline with unexpected semantic outcomes is not an
execution failure: the candidate runs and the engine classifies it (for example
`BASELINE_NOT_REPRODUCED`).

**Evidence (`<user data>/evidence/runs/<run-id>/`, 0700; files 0600).** Created exclusively
(an existing directory refuses the run). Each file is written to a temporary name with
`O_EXCL`, fsynced, and hard-linked into place, so it is complete or absent and never
overwritten. Journals are append-only and fsynced per line. Contents: the claim, the
authorization bytes, the frozen plan, the pack approval and its history, both source
manifests, the collection, the inventories and their reconciliation, the Docker operation
journal (below), the ownership journal, the re-validation log, per side the execution record,
observation cells, the raw verifier stream (`verifier-stream-…bin`, the only event channel),
the untrusted target stdout and stderr (`untrusted-target-stdout-…log`,
`untrusted-target-stderr-…log`) and verifier console (`untrusted-verifier-console-…log`), never
parsed, cleanup outcomes, the verdict input and verdict, and `outcome.json`. `manifest.json` is
written last with the hash of every file: `FINALIZED`, or `INCOMPLETE` after a handled
failure. No manifest means a crash; the partial files remain. A file above 64 MiB or a
journal line above 1 MiB is refused (above the schema's 50 MiB result-cap maximum).

**Output routing (evidence hardening, 2026-10-13).** The first live run showed two routing
defects: Uvicorn writes to stderr while only the target's stdout was saved (its
`untrusted-target-log-…log` files were empty and the stderr sat inline in the journal), and
the verifier's pytest console (its stderr) was inline in the journal too. That run's evidence
is kept exactly as recorded. For later runs:

| Stream | Cap | Stored as | Parsed |
|---|---|---|---|
| verifier stdout (event channel) | result cap + 1 | `verifier-stream-<tag>.bin` | yes, by the collector only |
| verifier stderr (pytest console, client errors) | 1 MiB | `untrusted-verifier-console-<tag>.log` | never |
| target stdout | 5 MiB | `untrusted-target-stdout-<tag>.log` | never |
| target stderr | 5 MiB | `untrusted-target-stderr-<tag>.log` | never |
| any other Docker CLI output (inspect, listings, client errors) | per operation (64 KiB stderr) | `docker-ops-<seq>-<stream>.out`, 96 MiB total per journal | by the host's own gates only, never as events |

Each stream has its own enforced cap (`run_bounded`; `Logs` and `StartAttached` declare a
`stderr_cap`, bounded and checked). `revision-<tag>.json` records, per untrusted output, the
capture status (`CAPTURED`, `CAPTURE_FAILED`, `NOT_ATTEMPTED`), size, SHA-256, truncation
and artifact name. A failed read is `CAPTURE_FAILED` with no file, never an empty file, and
makes the evidence `INCOMPLETE`.

**Operation journal (`docker-ops-v2`).** Metadata only: per operation a `requested` line, then
a `completed` line (UTC start and end with microseconds, monotonic duration, the client's own
duration, exit code, `EXITED` or `TIMED_OUT`, and per stream its class, byte count, SHA-256,
cap, truncation, storage state and artifact) or an `interrupted` line (`finished_at: null`,
never an invented end). Raw bytes never appear in it. `verify_evidence` checks every v2 line's
keys and every stored artifact's hash and size. Lines without `format` are the earlier inline
format (`v1`, the first live run); they are reported by `journal_format`, not as problems.
A journal or artifact write that fails is collected, never raised: cleanup always proceeds.
After a journal failure, `create`, `start` and `start-attached` are refused, while inspection,
stop and removal continue; the evidence is `INCOMPLETE`.

**Timestamps.** `outcome.json.timestamps` holds `execution_started_at` (before the first
Docker operation), `evaluated_at` (read when the engine evaluates, after the last revision's
cleanup; it equals `verdict.json`), `execution_finished_at` (after the after-inventory) and
`order` (`CONSISTENT` or `INCONSISTENT`; a backward clock is reported, never corrected). In
the first live run `evaluated_at` was read at the comparison's start, so it records when the
comparison began; that record is not rewritten. The engine and its rules are unchanged.

**Three separate states (spec 8.2).** `outcome.json` keeps:
- *evidence status*: `FINALIZED` only when the engine evaluated the run, no exception or
  signal interrupted it, every evidence file was written, and both inventories are complete;
- *lifecycle*: `COMPLETE` only with finalized evidence and a normal termination; otherwise
  `BLOCKED` (the engine's pre-execution `BLOCKED`), `CANCELED` or `INTERRUPTED`;
- *cleanup status*: `COMPLETE` only when every container this run created is absent from a
  complete after-inventory, else `FAILED`.

`verdict` is set only with finalized evidence (`verdict_established`). The engine's
evaluation is always kept as `engine_verdict` and in `verdict.json`: a trusted candidate
violation is never discarded, and incomplete evidence never establishes any verdict,
`VERIFIED_FOR_CASES` included. A failed evidence write does not abort the comparison (the
revision is already cleaned up); after the baseline it stops the run before the candidate.
An incomplete before-inventory fails `environment_identity` before the baseline, so the
engine returns `BLOCKED` and no container is created. `outcome.json` also restates the
fixed-fixture limitation (one pair, no seed, no seed variation).

`run_evidence.verify_evidence` re-checks a directory against its manifest (missing, added,
changed and partial files) and recomputes the verdict from `verdict-input.json` with the
engine. Like spec 12.2 says, it detects inconsistency and corruption, not a local adversary
who rewrites both the manifest and the files.

**Inventory reconciliation by identity.** Images, containers, networks and volumes are listed
before and after (`SnapshotList`, read-only) and compared by ID (volumes by name), never by
count. A built-in network (`bridge`, `host`, `none`) with a new ID under the same name and
driver is classified `DAEMON_MANAGED_BUILTIN_RECREATED`: explained, recorded with both IDs,
and marked as a suspected daemon restart, so continuity is not claimed. Every other change is
`UNEXPLAINED_*` and makes the reconciliation `ATTENTION`; so does any container this run
created that still exists. A failed listing makes it `INCOMPLETE`; before the run, that
creates nothing. Cleanup touches only recorded exact IDs with freshly re-verified ownership
labels, and is verified by their absence from a complete after-inventory.

**Daemon continuity is evidence, not proof.** The built-in network IDs are compared before
the candidate (a change or a failed listing interrupts the run) and after it. A change is
`daemon_continuity: BROKEN_SUSPECTED` and needs attention (exit 5) even when explained; a
failed listing is `UNKNOWN`. Unchanged IDs are reported as `NO_CHANGE_OBSERVED`, never as
proof that the daemon stayed online: a restart that kept the IDs, or a short loss of the
daemon, would not be seen this way. During a revision, a lost daemon shows up as failed
operations, which make the execution untrusted and the cleanup `FAILED`, never assumed
complete.

**Hard termination and recovery.**

| Event | What runs | Result |
|---|---|---|
| SIGINT, SIGTERM, SIGHUP | `runner.interrupts` turns the first into `RunTerminated`; the Docker client in progress is stopped; the revision's `finally` removes its containers by exact ID; evidence is finalized `INCOMPLETE`, lifecycle `INTERRUPTED`; repeats are ignored during cleanup | exit 4; no further revision |
| Unexpected exception (`OSError`, `EvidenceError`, `PolicyViolation`, `ValueError`) | the same cleanup and finalization | exit 4 |
| Any other exception | the revision's `finally` cleanup only; no manifest | not finalized |
| SIGKILL, host shutdown or power loss, interpreter crash | **nothing**: no cleanup, no manifest. Containers of the revision in progress remain (a target keeps running until stopped; Docker Desktop does not restart them, their restart policy is `no`) | consumed claim, journals intact |
| Docker daemon lost mid-revision | operations fail; the execution is untrusted; cleanup is `FAILED` | `INCOMPLETE` or attention |

In every case the claim, fsynced before the first Docker operation, keeps the authorization
consumed, and nothing retries. The ownership journal records each planned name before
`create` and each created ID after it, fsynced. The operation journal records each request
before it is sent. So a hard kill leaves the created IDs on disk.

`python -I -m patchproof.recover_run` (owner-operated, interactive, needs Docker approval
because even the status check runs `docker inspect`) handles what remains, for one consumed
run the owner selects by typing its run ID. It is not the general PP-014 recovery:
- **Read-only first:** the run's journal is read strictly; the four fixed names are resolved
  through the container listing and inspected only by exact full ID. Each is `ABSENT`,
  `OWNED` (journal ID, name and owner, installation and run labels agree, and the journal
  planned it), `FOREIGN`, `AMBIGUOUS` or `UNKNOWN`. Any container with this run's label or
  name prefix outside those four is also ambiguous.
- **Ambiguity refuses everything:** any `FOREIGN`, `AMBIGUOUS`, `UNKNOWN`, unreadable journal
  or failed listing removes nothing.
- **Explicit confirmation:** the exact IDs are shown and the owner types
  `CLEANUP <run-id>`. The assessment is repeated and must name the same IDs. Each is then
  removed with the accepted `remove_owned` (fresh re-inspection of ID, name and labels,
  graceful stop, exact-ID removal, `--force` only while still running).
- **Never resumes:** an allowlist permits only `inspect`, listing, `stop`, `remove` and
  `force-remove`; create, start, attach and logs are refused before Docker.
- **Separate evidence:** `<user data>/evidence/recoveries/<run-id>/rec-<id>/` (subject, every
  assessment, operation journals, cleanup results, manifest). The run's own evidence is only
  read.

## Retained response evidence (what a run can and cannot show)

- **Observed by the trusted verifier, inside its container:** for each security test, the
  status code, whether the protected document's own marker appeared in the body, and the
  caller identity; for each functional test, the pack's assertions (exact IDs, owner,
  content, role, no token echo).
- **Preserved in structured evidence:** the event stream (`verifier-stream-…bin`): per test
  the setup, call and teardown reports with outcome and failure class, and one observation
  per security test with its classification and attested facts. `evidence_refs` are empty:
  the plugin attests the facts, it does not store the response.
- **Recomputable by an independent audit:** the stream's integrity and grammar, every cell
  from the stream, the verdict input from the records, the verdict from the engine, and the
  match with the declared table.
- **Not reconstructible:** the response bodies and headers themselves. Whether a marker was
  really present, or a functional body really matched, rests on the verifier's attested
  observation, not on retained bytes. Raw responses are not retained by default (synthetic
  tokens and markers would otherwise be stored); changing that needs a plugin, pack or event
  schema change and a new approval, and is not proposed here.
- **Scope:** `VERIFIED_FOR_CASES` covers the selected tests on the bound revisions, fixture
  and environment. It is not a claim of comprehensive application security.

## Interruption test (implemented Docker-free; never executed)

PP-008 needs one deliberately interrupted live run. The ordinary run authorization cannot
express it and is not reinterpreted: a separate, versioned contract, store and pair of
commands exist for it alone. None has been used: no real interruption authorization exists
and no interruption run has executed.

**Contract** (`interruption-test-authorization` 1.0; strict JSON, closed Pydantic model and
JSON Schema with model/schema parity tests). The record binds a unique run ID and `iau-` ID,
the current pack approval, pack, profile, approved r2 images, fixture hash and runtime limits
(the pack, profile, image, source and runtime sections reference the `run-authorization` 1.0
definitions unchanged), the r1 commit, tree and snapshot hashes, and the canonical plan hash,
with the locally asserted reviewer, rationale, scope and time. Fixed by the schema, so no
record can authorize more:
- `revision`: pair 1, baseline, `candidate_execution: false`, `automatic_retry: false`; no
  candidate identity exists in the plan (the schema rejects a `sources.candidate` key);
- `containers`: `max_creations: 2`, `max_started: 1`; the target `--network none` with the
  source read-only and started after its inspection gate; the verifier joined to the exact
  target with the pack read-only and `start: never`; exact-ID cleanup;
- `interruption`: stage `baseline-target-ready`, one `SIGTERM`, `escalation: none`, the
  controller-child pipe, a 30 s synchronization wait, 600 s report and cleanup timeouts, no
  retry;
- `expected_outcome`: `INTERRUPTED`, `INCOMPLETE`, cleanup `COMPLETE`, `INCONCLUSIVE` by
  `V-05`, lifecycle exit code 20 (expectations, never results);
- evidence under `evidence/interruption-tests/<run-id>`.

**Store** (`<user data>/interruption-authorizations/`): the accepted run-authorization
discipline, unchanged: 0700, owner check, no symlink traversal, a stable device and inode,
exclusive 0400 records, strict validation, an `O_EXCL`, fsynced claim before any child
exists, no reuse, no retry, supersession only of the single unused record. The claim also
records the claiming controller's PID. The two stores refuse each other's files.

**Commands.**
- `python -I -m patchproof.interruption_authorization` (owner, foreground terminal, no
  arguments or `PATCHPROOF*` variables): recomputes the plan, shows the images, r1 snapshot,
  budget, signal behavior, why no verified-fix result is possible, cleanup and residual
  risks; asks identity, rationale and scope; requires
  `AUTHORIZE INTERRUPTION TEST <run-id> <plan-sha256>`; revalidates; writes and verifies.
- `python -I -m patchproof.interruption_test` (owner, same gate, separate Docker approval):
  revalidates, requires `INTERRUPT <run-id>`, claims, then starts exactly one child
  `python -I -m patchproof.interruption_child <run-id> <fd>` with one inherited pipe, its own
  interpreter, a validated run ID and an explicit environment (`HOME`, `PATH=/usr/bin:/bin`,
  `LC_ALL`/`LANG=C`; nothing inherited). It is the only module besides the reviewed Docker,
  probe and Git wrappers allowed to import `subprocess` (exact path, owner-approved
  2026-10-13), and it has no Docker client.
- The child refuses unless the claim names its parent PID and the recomputed plan equals the
  frozen plan. There is no option, flag or environment variable that selects the test mode,
  and the ordinary driver has no parameter that reaches it.

**Synchronization** (`runner/interruption_point.py`). `execute_revision` calls the checkpoint
with facts it has established itself (`CheckpointState`). The child reports only for pair 1,
baseline, the target started and `READY`, and the verifier created and through its
inspection gate but not started; any other state reports nothing and aborts. The report is
one fixed JSON line (stage, run ID, PID, both container IDs, target readiness, verifier
state, and `send_by_monotonic`: the end of the child's wait minus a margin, on the
system-wide monotonic clock). The controller checks every key and value, including that the
PID is its own unreaped child and that the send-by time has not passed, and sends one SIGTERM
through the process handle; otherwise nothing. The child waits at most 30 s; with no signal
it aborts the same way (fail closed). The send-by time keeps a stalled controller from
signalling a child that has already begun its abort cleanup.

**Container budget and guards.** Four independent guards keep the candidate out, each
tested with the ones before it disabled: `continue_after` stops after the baseline;
`before_revision` refuses any candidate (`interrupt`); the private engine adapter
(`interruption_plan._BaselineOnlyEnginePlan`) has no candidate source or stream and refuses
before anything is created; the recorder refuses a third creation before Docker. Only the
target starts.

**No candidate identity anywhere.** The accepted engine's `RunPlan` dataclass has a
candidate slot; the adapter fills it with the very same baseline object, so the engine's
precondition check re-verifies only the baseline. Nothing is written from that slot: the
authorization, plan, verdict input and outcome name the baseline alone, and a test checks
that no stored byte mentions the candidate's tag, commit or tree.

**Result classification** (owner correction, 2026-10-13; PP-004 decision table unchanged).
`execute_revision` records a signal (or abort) raised at the checkpoint as the revision's
`interruption`, never starts the verifier, removes both containers by exact ID and returns;
`run_comparison` then ends the run `interrupted` and the accepted engine evaluates the
recorded execution:

| | Reviewed interruption | Signal elsewhere (abrupt) |
|---|---|---|
| lifecycle | `INTERRUPTED` | `INTERRUPTED` |
| evidence status | `INCOMPLETE` (always, by design) | `INCOMPLETE` |
| cleanup | `COMPLETE` only if every created ID has a verified removal and is absent from a complete after-inventory | same |
| verdict | `INCONCLUSIVE`, rule `V-05` (required observations missing) | none: the engine did not run |
| lifecycle exit code (13.2) | 20 | 20 |

A precondition failure before anything starts is `BLOCKED` (exit 21). `VERIFIED_FOR_CASES`,
or `BLOCKED` after execution started, is never recorded as the verdict; an engine result like
that is reported as an evidence failure. The controller's own harness exit code is separate:
0 expected outcome observed exactly, 1 deviation, 3 claimed but no child ran, 2 refused.

**Evidence.** The child's directory holds the frozen plan, authorization and claim, the
before and after inventories, the metadata-only operation journal, the ownership journal,
`execution-…`, `revision-…` (with `interruption`), the empty event stream, the target's
untrusted output, `verdict-input.json`, `verdict.json`, `interruption.json` (report, signal
observed, timings) and `outcome.json` (states, exit code, IDs, removals, deviations from the
expected outcome); its manifest status is always `INCOMPLETE`. The controller writes its own
record (`evidence/interruption-controller/<run-id>/controller.json`: delivery, child PID,
lifecycle exit code, durations, the check of the child's evidence). `recover_run` lists
consumed interruption-test authorizations too.

**A child that does not exit** within the cleanup timeout is reported, never killed: no
further signal, no Docker operation (the controller has none), the child's evidence is not
read while it may still be written, cleanup is not confirmed, the controller record stays
`INCOMPLETE`, and the output names the container IDs from the child's report and the
`recover_run` step (recovery finds the containers by their fixed names and the child's
ownership journal). The same recovery note is shown whenever cleanup is not confirmed.

**Not covered.** A SIGKILL of the child (cleanup then needs `recover_run`).

## Docker-free evidence

| Test file | What it shows |
|---|---|
| `test_run_policy.py` | argv golden values, forbidden options, role topology, ceilings, input privacy, every inspect-gate deviation, pack and source integrity (swap, symlink, content, extra, missing, mode, renamed root) |
| `test_run_collector.py` | 14 protocol-violation classes, invalid lines, identity and collection mismatches, truncation, partial lines, forged target-style text, no file access |
| `test_run_execution.py` | the four PP-006 comparisons composed end to end (synthetic); stale approval and unapproved images blocking with zero Docker calls; policy-gate refusal before any start; startup failure, readiness timeout, target OOM, verifier timeout, abnormal exits, OOM with `session_end`, output flood, a trusted violation surviving a local failure, malformed and identity-mismatched streams, untrusted target logs, create and attach failures, cancellation, cleanup refusal, and that unrelated resources are never touched |
| `test_run_transport.py` | redirects, proxies, oversized bodies, timeouts, refused connections, path and header validation |
| `test_run_plugin.py` | **real pytest 8.4.2 in a subprocess on synthetic packs**: event-channel isolation; 11 outcome classes accepted by the host collector; failure classes on the wire; the plugin's pack hash equals the host's; the exact `launch collect … -- <path>` command; refusal of skip/xfail markers and extra tests; autoload enforcement; refusal without the launcher channel; launcher argument shapes |
| `test_run_images.py` | the proposed recipes match the code: base digest, offline wheel-only installs, locks, the health check, the verifier environment |
| `test_profiles.py` | the repository profile loads with its pinned hash and matches the JSON schema and the reference scope; refusal of placeholders, unknown fields, other versions, duplicate keys, wrong names, symlinks, FIFOs, oversize and swapped, rejected or unapproved images; each of 18 runtime values refused when it differs; the values reach the container argv; a different source scope fails `source_identity` |
| `test_pack_approval.py` | refusal of piped stdin, arguments, `PATCHPROOF*` variables and background terminals; acceptance in a foreground pseudo-terminal; every prerequisite failure writes nothing; changes between review and confirmation are detected; the full binding set is shown before the phrase; a synthetic approval is a valid PP-007 record; history is preserved by supersession; the store is never followed through a symlink or repaired; the phrase is refused as rationale or scope |
| `test_run_authorization_store.py` | the schema example is hash-consistent; semantic rules the schema cannot express; strict loading; the exact phrase; the store's save, claim, supersession and run-ID rules; damaged, loose, symlinked or replaced stores refused; all three entry points refuse piped input, arguments and `PATCHPROOF*` variables, and fail closed in a real foreground pseudo-terminal; the reusable contract accepts a revision against itself while `check_first_run_scope` refuses it, swapped sides, another tree and another tag |
| `test_authorized_run.py` | the plan binds every full identity and equals the PP-006 record; refusal of a missing or stale approval, a wrong fixture hash, substituted images, a bad installation ID, a missing pack copy, two pairs, ambiguous or modified snapshots, an invalid run ID and a changed runtime policy; the authorization command's display, phrase, statement and change-detection rules, supersession and run-ID reuse, and distinct post-write failure; drift after authorization blocks before the claim with no Docker operation; single use; two competing claimers; crashes before and after the claim; an indeterminate claim; D2 stops for startup failure, crash, OOM, timeout, truncation, abnormal exit, target exit and malformed, truncated, absent, identity-mismatched and over-cap streams; uncertain cleanup; a trusted baseline with unexpected outcomes still runs the candidate; candidate preparation failure; approval, claim, snapshot and policy drift during the baseline; a daemon restart; target-log text never becomes an event; the complete evidence set, its hashes and modes; no overwrite; incomplete evidence after an exception; an incomplete before-inventory is `BLOCKED` with no container; the four-creation budget; reconciliation by identity. Security review additions: the driver refuses a same-revision authorization; the D2 boundary agrees with the public engine for 13 faults; real SIGINT, SIGTERM and SIGHUP clean up, finalize `INCOMPLETE` and ignore a repeat; a real SIGKILL (child process) leaves a consumed claim, journaled IDs and no manifest; evidence-write failures stop before the candidate or keep the engine verdict without establishing it (`NOT_FIXED` and `VERIFIED_FOR_CASES`); a trusted violation survives a cleanup failure; an incomplete after-inventory; file and line bounds; `verify_evidence` and verdict recomputation; the fixed-fixture limitation; candidate timeout, OOM, crash or absent stream is never a regression; a trusted deny-all is; a restart after the candidate, unchanged IDs as no proof, unexplained changes, Docker unavailable before the candidate, and the daemon vanishing during it |
| `test_run_recovery.py` | confirmed cleanup removes exactly the verified owned containers and never touches others; nothing without the typed phrase; foreign labels, an extra run container, a missing journal or an unreachable daemon refuse all cleanup; a change after confirmation refuses; failed removal is incomplete; nothing to remove after a clean run; no store, no claim, unknown run IDs; never resumes or re-authorizes; an interrupt; the allowlist refuses create, start, attach, logs and wait; recovery after a real SIGKILL |
| `test_run_evidence_hardening.py` | target stdout/stderr and verifier console carrying synthetic tokens, markers and a complete valid event stream never reach the journal or any metadata file and never become events; per-stream caps in `run_bounded` and the Docker client; truncation and failed captures recorded (failed capture is `INCOMPLETE`); journal keys, UTC timestamps, monotonic durations, no invented end for an interrupted operation; the output budget and write failures recorded; a journal failure never blocks cleanup and refuses new containers; `verify_evidence` detects a changed output artifact and smuggled raw keys while v1 lines stay readable; `evaluated_at` read at evaluation and ordered between start and finish, a backward clock reported; the interruption point: configuration refusals, a single stage, single use, a real SIGTERM at the checkpoint removing both baseline containers with no verifier start, fail-closed timeout and broken channel, the two-container budget, unreachability from production, the current contract refusing such a plan; the controller with real child processes: one SIGTERM to its own child, nothing for a wrong run, a foreign PID, a silent or exited child; after an interrupted run the authorization is spent and recovery finds nothing; recovery with a failed journal write finalizes `INCOMPLETE`; a verdict time other than the recorded evaluation time is `INCOMPLETE`; a pipe placed on a standard stream is still refused; the checkpoint reports nothing in any state but the reviewed one; the controller refuses a report that is late, lacks its send-by time, has an extra key, a not-ready target or a started verifier |
| `test_interruption_test.py` | the interruption contract: example hash, the two contracts never accept each other, 13 broader-execution attempts refused by the model, semantic rules; the plan binds only r1 and the approved images; the store's single use, eight simultaneous claimers with one winner, a crash during the claim (consumed, controller and child refuse), partial, corrupt, foreign, stray and mismatched-claim stores refused, the ordinary store refusing interruption records, mode and replaced-directory refusals, supersession of unused records only, strict claim parsing; the owner command's display, wrong phrases (including the ordinary ones), the phrase as rationale, empty identity, input change during review, non-interactive refusal of both commands; the driver: the reviewed SIGTERM gives `INTERRUPTED`/`INCOMPLETE`/`COMPLETE`/`INCONCLUSIVE`/`V-05`/20 with two creations, one start and consistent evidence; a signal before the checkpoint leaves no verdict and nothing finalized; no signal fails closed; an unverified verifier is `BLOCKED` before any start (21); a target that never becomes ready reports nothing; the candidate gate, the engine adapter and the creation budget each hold alone; no stored byte names the candidate's tag, commit or tree; any unverified cleanup outcome fails cleanup; an engine `VERIFIED_FOR_CASES`, `BLOCKED` or `NOT_FIXED` is never presented; cleanup and evidence-write failures are reported; the 13.2 exit-code table; the child's single argument form, refusal of another process's claim, of another run and of stale inputs; the controller refusing stale inputs and a wrong phrase without claiming; **a real controller and real child process end to end** (exit 0, child 20, one SIGTERM, consistent evidence, no retry, recovery finds nothing); a child that does not exit (a real local process ignoring SIGTERM) is reported, never killed or re-signalled, its evidence unread, cleanup unconfirmed and the controller record `INCOMPLETE`, with the recovery step shown; wrong, missing or late reports send nothing; a claim changed before the baseline is `BLOCKED` with no container; the child never runs twice; a failed child start leaves the authorization consumed; harness and lifecycle exit codes kept apart; the ordinary path cannot select the test mode; the fixed child argv, its explicit environment and argument validation; no general process interface in the controller (AST check) |
| `test_pack_approval_supersede.py` | supersession keeps every earlier record byte-for-byte and links the replacement; the current record and its statement are shown before any prompt; one current approval across repeated supersession; refusal of stale bindings, a wrong phrase, the phrase as rationale or scope, empty or ended input, a missing store or current approval, and store or binding changes before the write; a failed write leaves the original current; a failure after the write is exit 4, never success; non-interactive invocation refused |

## Not done and not claimed

- No real verifier collection, image, container, or HTTP request to PaperTrail.
- No PaperTrail pack approval. Every approval in the tests is synthetic, in a temporary
  directory. Only the owner can create one, with `patchproof.pack_approval`.
- Every authorization, claim and evidence directory in the tests is synthetic and
  temporary. The one live comparison (2026-10-13) was created and executed by the owner;
  see `docs/evidence/pp-008-first-live-comparison.md`.
- No live interruption test, and no real interruption-test authorization. The contract,
  store, commands and driver are implemented and tested Docker-free only.
- `APPROVED_RUN_IMAGES` holds only the gate-B r2 images.
- **Docker Desktop specifics are unverified until gate C:** for example, whether
  `Mounts[].Source` is reported as the host path, and the health-state field names. The
  gate fails closed if they differ.
