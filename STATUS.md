# STATUS

**Updated:** 2026-10-12 (PP-004 **`ACCEPTED`** by owner, implementation commit `37ec588`; PP-001..PP-004 accepted; **v0.0 release gate NOT complete**: closeout work and the §15.1 review remain)
**Specification:** `PROJECT_SPEC.md` v1.0

---

## Current release and issue

**Release:** v0.0 — Foundation and execution boundaries
**Issue:** PP-004 — Pure verdict engine and initial negative tests
**State:** `ACCEPTED` by owner, 2026-10-12. This acceptance covers PP-004 only; the v0.0
release gate is not complete.

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

## v0.0 closeout assessment (2026-10-12; assessment only, nothing implemented)

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

**No release gate has passed.** v0.0 is open. PP-001..PP-004 are accepted. The closeout
work and the §15.1 review and demonstration remain; see "v0.0 closeout assessment".

| Issue | Accepted | Evidence |
|---|---|---|
| PP-001 | 2026-10-11 | `docs/environment.lock.md` |
| PP-002 | 2026-10-11 | commit `682ef63`; see "Accepted issues" above |
| PP-003 | 2026-10-12 | commit `e38d0d1`; run `run-5c176591e0f793ebdb6c2f07667c4ead`; `docs/evidence/pp-003-isolation-probes.md` |
| PP-004 | 2026-10-12 | commit `37ec588`; 6923 unit tests; 26/26 verdict scenarios |

## Next permitted issue

**v0.0 closeout work only, once the owner authorizes it.** The v0.0 issues PP-001..PP-004
are all accepted, but the v0.0 gate is not. PP-005 (v0.1) must not start until the v0.0
gate is accepted or the owner explicitly reorders.

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
| 2 | Install current Python 3.13.x and pin it; approve pinning the validation/test dependencies | v0.0 closeout packaging (`pyproject.toml`, `uv.lock`, `patchproof doctor`) |
| 3 | `brew upgrade git` (2.42.0 → 2.56.0) | PP-005 |
| 4 | Decide whether to remove `/Users/aliel-asmar/.git` (nothing is tracked; recommend backing up its config first) | Safe local Git hygiene |
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
