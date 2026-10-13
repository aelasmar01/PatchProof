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
| `runner/comparison.py` | Pairs × sides, post-run checks, verdict input, the unchanged PP-004 engine |
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
| `test_pack_approval_supersede.py` | supersession keeps every earlier record byte-for-byte and links the replacement; the current record and its statement are shown before any prompt; one current approval across repeated supersession; refusal of stale bindings, a wrong phrase, the phrase as rationale or scope, empty or ended input, a missing store or current approval, and store or binding changes before the write; a failed write leaves the original current; a failure after the write is exit 4, never success; non-interactive invocation refused |

## Not done and not claimed

- No real verifier collection, image, container, or HTTP request to PaperTrail.
- No PaperTrail pack approval. Every approval in the tests is synthetic, in a temporary
  directory. Only the owner can create one, with `patchproof.pack_approval`.
- No run-authorization record (PP-009).
- `APPROVED_RUN_IMAGES` holds only the gate-B r2 images.
- **Docker Desktop specifics are unverified until gate C:** for example, whether
  `Mounts[].Source` is reported as the host path, and the health-state field names. The
  gate fails closed if they differ.
