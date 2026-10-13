**Result: LIMITED GATE C COLLECTION/PROTOCOL VALIDATION COMPLETED, WITH A DOCUMENTED C1b
EXCEPTION** (2026-10-13). These are **not** three unconditional PASS results.

| Step | Purpose | Recorded execution result | Owner adjudication |
|---|---|---|---|
| C1a | SYNTHETIC collection under pytest 9.0.3 in the verifier image | **PASS** | — |
| C1b | SYNTHETIC event-protocol run | **FAIL**: an erroneous auxiliary assertion | **ACCEPTED_FOR_C2_PROGRESSION** (see "C1b owner adjudication") |
| C2 | real collection of the PaperTrail pack (collection only) | **PASS** | — |

**Containers created:** 3 of the 3 authorized, one after the other; all were removed by exact
ID after an ownership check. The budget is exhausted.

**Docker state:** no image, container, volume or user network changed. Docker's built-in `bridge` network
was recreated by a Docker Desktop idle restart (see "Correction" below). The target image was never started.
PaperTrail tests were collected but **not executed**. The pack is **NOT_APPROVED**, and no live
comparison took place.

Everything below labeled C1 is **SYNTHETIC**. It verifies the harness only, and it is not a
finding about any application.

Raw records are kept privately on the owner's Mac, mode 0700, and are not part of the
repository: standard output and error, Docker command logs, ownership journals, and inventory
before and after. This report holds only sanitized facts and hashes.

## Authorization and scope

- **Owner instruction:** "PP-008 Gate C: First Isolated Verifier Validation". C1a, C1b and C2
  were authorized, with at most three containers, run sequentially, no external network,
  verifier image only, no retries.
- **Image used:** only the verifier r2 image,
  `sha256:e880f609a7c4d292441e22d1d0d5d7c876697dd4e1e657a668b2b6266969fecc`.
- **Target r2** `sha256:98548ec4…`: approved as an identity only; not started.
- **r1 images:** rejected in code by `run_plan.REJECTED_RUN_IMAGE_IDS`.

## Code changes made for gate C (Docker-free, tested)

1. **`runner/docker_cli.py`:** `ALLOWED_OP_TYPES` gains exactly `RunCreate` and `StartAttached`.
   - A `RunCreate` is accepted only when its argv equals `run_create_argv_tail(spec)` for its
     validated spec, and passes `assert_run_create_shape`: exactly one read-only bind, and no
     forbidden token.
   - A `StartAttached` is accepted only as `container start --attach -- <ID>`, with a bounded
     deadline and output cap.
   - Every other operation, including the PP-003 probe `Create`, still refuses `--mount`
     (tested).
2. **`runner/run_policy.py`:** adds the role `RunRole.STANDALONE`, which is the verifier
   policy with `--network=none` and no target:
   - it accepts only the pack input at `/pack`;
   - its command must equal the fixed `collect_command(...)`, or exactly what `verifier_command`
     builds;
   - the container name ends in `-standalone`;
   - `assert_run_create_shape` no longer imports from `docker_cli`, which avoids an import cycle.
3. **`runner/standalone.py`:** the lifecycle for one standalone container:
   1. image identity;
   2. pack verification;
   3. create, then the inspect gate; a failed gate removes the container unstarted;
   4. attached start with a deadline and output cap;
   5. exit inspection, stopping the container if it is still running;
   6. exact-ID, ownership-checked cleanup;
   7. pack verification again.
4. **`runner/run_plan.py`:**
   - `APPROVED_RUN_IMAGES` holds exactly the two r2 records. Their environment and health check
     are copied from the r2 inspect records, and a test compares them.
   - `REJECTED_RUN_IMAGE_IDS` lists both r1 IDs, and `ApprovedRunImage` refuses them.
5. **`packs/validation.py`:** adds `load_selftest_pack`, which accepts only the pack ID
   `verifier-selftest` and applies the path, layout, size and manifest rules.
   **`core/approvals.py`** refuses to approve `verifier-selftest`.
6. **`examples/packs/verifier-selftest/`:** the SYNTHETIC self-test pack with 11 tests, one
   per outcome class. It makes no network requests, and the strict pack validator rejects it.
7. **Tests:**
   - new: `tests/unit/test_run_standalone.py`;
   - extended: `test_run_policy.py` (standalone role; fixed-shape admission and tamper
     refusal), `test_run_images.py` (approved records equal r2), and `test_run_execution.py`;
   - `test_docker_cli.py`: the allowlist assertion now names the two added operations.

**Docker-free validation before the first container:**
- 8163 passed;
- mypy strict clean (59 files);
- Ruff: no new findings; the 11 pre-existing E501 findings are in untouched lines.

## Pre-execution checks (28/28 passed; no container)

1. Git root, `HEAD` = `origin/main` = `d85b6db`, nothing staged, and the ADR-010 work
   unchanged (`8f1fc685…`/`dd5cad81…`).
2. PP-007 is ACCEPTED.
3. Both r2 images are present, and their `Id`, tags, platform, `Config`, `RootFS`, size and
   creation time equal the gate-B r2 record. Their environment and health check equal the
   approved records.
4. The 11 built verifier files (the package and `pytest.ini`) are byte-identical to the
   repository.
5. Pack snapshots, content-addressed in a private store, with the host tree hash equal to the
   verifier's own:
   - self-test `sha256:09e26b67602ca4448f0a900a4a52df4a397b50fb0dc1cbc70f71fef223c7d5f1`;
   - PaperTrail `sha256:529d3cd3ebf307586dcecef43a0df8ab9b55296849182f8f43c4ad7d6a8a6c31`,
     equal to the PP-007 record.

   Neither contains a `conftest.py` or configuration file.
6–9. Three fixed plans:
   - `--network none`, one read-only bind of the pack snapshot at `/pack`, and the verifier
     image only;
   - no `--volume`, `--device` or `--env-file`, and no published port;
   - the only tmpfs targets are `/scratch` and `/tmp`;
   - the only host path is the pack snapshot.

   The first version of this check matched the in-container `/tmp` tmpfs target and failed.
   It was replaced with the stricter structural check above before any container existed.
10. Inventory: 14 images, 7 containers, 5 networks, 10 volumes. No container uses an r1 or r2
    image.
11. 560 GiB free; the evidence and store directories are `0700`; the container ledger is empty.
12. The Docker-free suite results above.

## C1a: synthetic collection (PASS)

| | |
|---|---|
| Container | `e73d64385d7e419288d48ff339ecd2f518419356375822ec5ef316398b79b0a7` (removed) |
| Image | verifier r2 `sha256:e880f609…` |
| Command | `python3 -I -B -m patchproof_verifier.launch collect --pack /pack -- /pack/tests/test_selftest.py` |
| Create argv SHA-256 | `f63dead8055e882c9aa522d682210d7a2aa0786d2360e3fc7d2c104ab42bdd40` |
| Pre-start inspect gate | **passed**: all 59 inspected fields match the fixed policy |
| Docker operations | image-inspect 1, run-create 1, inspect 2, start-attached 1, remove 1, plus an absence-confirming inspect; no others |
| Exit / termination | 0 / EXITED; no signal, no OOM, no timeout; 1.87 s wall time |
| Standard output | 736 B, not truncated; exactly one compact `collected` line (SHA-256 `a794a92d…`) |
| Standard error | 905 B: pytest `-q` collection listing, `11 tests collected`, and one warning (G-C1) |
| Pack integrity | verified before and after |
| Inventory | unchanged (14/7/5/10) |

**Collected node IDs, exactly the manifest in manifest order** (no missing, extra or
duplicate tests):

| ID | Node ID |
|---|---|
| SEC-001 | `tests/test_selftest.py::test_violation` |
| SEC-002 | `tests/test_selftest.py::test_secure` |
| SEC-003 | `tests/test_selftest.py::test_inconclusive` |
| SEC-004 | `tests/test_selftest.py::test_generic_assertion` |
| SEC-005 | `tests/test_selftest.py::test_suppressed` |
| SEC-006 | `tests/test_selftest.py::test_twice` |
| SEC-007 | `tests/test_selftest.py::test_timeout` |
| FUN-008 | `tests/test_selftest.py::test_pass` |
| FUN-009 | `tests/test_selftest.py::test_fail` |
| FUN-010 | `tests/test_selftest.py::test_crash` |
| FUN-011 | `tests/test_selftest.py::test_skipped` |

**What C1a shows, and how:**
- **The runtime started and the plugin loaded.** The `collected` line is produced only by
  `patchproof_verifier.plugin`, which only the approved `pytest.ini` loads (`-p`).
- **The `--` syntax worked**, and the launcher kept everything except the event line off
  standard output.
- **The pytest version is not self-reported in quiet mode.** It is established by the gate-B
  static audit: the only pytest in the image is 9.0.3.
- **Autoload disabled:** the inspect gate verified `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` in the
  container environment.
- **No conftest:** `--noconftest` is in the approved `pytest.ini`, and the snapshot has no
  `conftest.py`.

## C1b: synthetic event protocol (FAIL on a driver-added criterion; owner criteria met)

| | |
|---|---|
| Container | `24902b34bd2fb72ede23f0773430547477776c140824013c399e2ce5dd30dffb` (removed) |
| Command | the fixed `launch run` form (`--pack /pack`, run ID, pair 1, baseline, connect/read timeout 5 s, then `-- /pack/tests/test_selftest.py`) |
| Create argv SHA-256 | `ac7d30471cb8db2be7bbc89c6bf1fc4bd29c2fdc487cadb9d81e6e3170e322bd` |
| Pre-start inspect gate | **passed**: all 59 fields |
| Docker operations | as in C1a; no others |
| Exit / termination | 1 / EXITED; no signal, no OOM, no timeout; 2.60 s |
| Standard output | 10,364 B of the 10 MiB cap; not truncated (SHA-256 `153ee616…`) |
| Standard error | 4,976 B: pytest's failure reports and `6 failed, 4 passed, 1 skipped, 1 warning`, plus G-C1 |
| Pack integrity | verified before and after |
| Cleanup and inventory | exact-ID removal confirmed; inventory unchanged |

**Event stream, checked by the host collector:**
- `COMPLETE`, 41 events, contiguous `seq`;
- starts with `session_start`, then `collected`; ends with `session_end`;
- `session_start` carries plugin `0.1.0` and the pack tree hash `sha256:09e26b67…`, equal to
  the snapshot;
- every one of the 11 tests reports `setup`, `call` and `teardown` in order;
- failed reports: SEC-001, SEC-004, SEC-006, SEC-007, FUN-009 and FUN-010 (6, all call phase).
  That is consistent with exit 1.

| Test | Lifecycle | Semantic | Harness errors |
|---|---|---|---|
| test_violation | COMPLETED | VIOLATION_CONFIRMED | — |
| test_secure | COMPLETED | SECURE | — |
| test_inconclusive | COMPLETED | INCONCLUSIVE | — |
| test_generic_assertion | CALL_ERROR | NONE | GENERIC_FAILURE_IN_SECURITY_TEST, MISSING_TERMINAL_OBSERVATION |
| test_suppressed | COMPLETED | VIOLATION_CONFIRMED | SUPPRESSED_TERMINAL_EXCEPTION |
| test_twice | CALL_ERROR | SECURE | — |
| test_timeout | TIMED_OUT | NONE | MISSING_TERMINAL_OBSERVATION |
| test_pass | COMPLETED | PASS | — |
| test_fail | COMPLETED | FAIL | — |
| test_crash | CALL_ERROR | NONE | — |
| test_skipped | SKIPPED | NONE | — |

All 11 outcome classes are **identical to the host pytest 8.4.2 baseline**
(`test_run_standalone.py::test_selftest_pack_on_host_pytest_gives_the_expected_outcomes`).
- **Security-terminal observations are distinct from generic assertions:** `test_violation`
  is a confirmed violation, while `test_generic_assertion` is a harness error with no
  observation.
- **Neither test print reached the event channel:** the `print(...)` of a fake `session_end`
  and a raw `os.write(1, ...)` of a forged event are both absent from standard output.

### C1b failure classification

**The failing criterion:** "the test's fd-1 write must appear on standard error". The driver
author (Claude) added this criterion; it is not in the owner's list or in the accepted unit
tests. The write comes from `test_secure`, which **passes**. Pytest's default fd-level capture
holds output a test writes to descriptor 1 and discards it when the test passes. The correct
outcome is therefore "on neither channel", which is what happened.

Host pytest 8.4.2 behaves identically (forged line on stdout: no; on stderr: no; same
summary). The accepted unit test `test_event_channel_carries_only_events` asserts only that
the line is absent from standard output.

**Classification:** a defect in the driver's expectation, not in the verifier, the plugin, the
event stream or cleanup.

**Disposition:** the failure is **not** relabeled. C1b is recorded as FAIL, and as instructed
the sequence stopped before C2. The driver refuses both C2 (C1b has no PASS record) and any C1b
retry. Whether to accept C1b on the owner criteria, or to authorize a corrected re-run (which
would need a fourth container), is the owner's decision.

**What the self-test does not yet show:** that output escaping pytest's capture, such as a
write from a failing test's report section, reaches standard error and not the event
channel. Pytest's failure reports did go to standard error (4,976 B) with nothing on standard
output, which is consistent with the launcher's redirection. A dedicated negative case would
make this explicit.

## C1b owner adjudication (2026-10-13)

**The original C1b result is unchanged.** The private records (`C1b/result.json` SHA-256
`c019ceb5…`, `stdout.bin` `153ee616…`) and the as-executed driver (SHA-256 `889cfd87…`, kept
read-only) are preserved. Their hashes were re-verified after C2 and are byte-identical.

**The adjudication is a separate private record** (`C1b-owner-adjudication.json`), bound to
the C1b result hash:
- **Original execution result:** FAIL, from an erroneous auxiliary assertion.
- **Owner adjudication:** ACCEPTED_FOR_C2_PROGRESSION.
- **The failing assertion** expected a fake event written by a *passing* test to appear on
  standard error. Pytest's normal output capture discards that output, so the expectation
  was incompatible with pytest. It was not an accepted event-protocol security requirement.
- **Satisfied:**
  - 41 structured events with contiguous sequence numbers;
  - valid collection, lifecycle reports and terminal observations;
  - six failed reports, consistent with exit code 1;
  - all 11 outcome classes as expected;
  - no test-generated fake event text on the structured channel;
  - isolation (59/59) and exact-ID cleanup passed.
- **Scope:** this incident only. It does not relax any malformed-stream, collection,
  identity, output-cap or runtime check.
- **Not claimed:** that all of C1b's assertions passed.

**Correction, made without Docker:**
1. **The driver** no longer requires the fake event on standard error. It now checks the real
   invariant: test text never appears on standard output, and every standard-output object
   has exactly the event-schema keys and a known event type. The key set was first written
   with a wrong key name; re-evaluating the *preserved* C1b stream offline caught this before
   C2. The corrected criterion passes on that stream (0 non-event objects in 41).
2. **New unit test**
   `test_run_standalone.py::test_fake_event_write_executes_but_never_enters_the_event_channel`.
   It runs the unchanged self-test pack on the host twice:
   - **with capture disabled** (`-s`, through a copy of the approved ini; host only): the
     forged line appears on standard error, which proves the write executes and that the
     launcher's descriptor 1 is standard error;
   - **with the approved configuration:** the forged line is discarded.

   In both runs the event channel is exactly the plugin's 41 events, the collector reports
   `COMPLETE`, and the 11 outcome classes are as expected.
3. **Unchanged identities:** the verifier image, the self-test pack (`09e26b67…`) and the
   PaperTrail pack (`529d3cd3…`).

## C2: real PaperTrail collection (PASS; collection only)

**C2 revalidation, 31/31 checks** (no container):
- the ledger shows exactly 2 prior creations, both removed and absent;
- the C1b FAIL record is intact and the adjudication is bound to its hash;
- r2 images identical to the gate-B record; verifier files equal the repository;
- PaperTrail snapshot `529d3cd3…`, with the host tree hash equal to the verifier's;
- the plan is the fixed collect form, and the launcher adds `--collect-only`;
- `--network none`, one read-only `/pack` bind, tmpfs only `/scratch` and `/tmp`, no other
  host path, environment variable or credential;
- inventory 14/7/5/10; evidence directories `0700`;
- Docker policy, gate and pack tests: 437 passed.

| | |
|---|---|
| Container | `dc86298ea55681642a6f3ce3663a15c06ac190f2963b07e0838257a690f65624` (removed, confirmed absent) |
| Image | verifier r2 `sha256:e880f609a7c4d292441e22d1d0d5d7c876697dd4e1e657a668b2b6266969fecc` |
| Command | `python3 -I -B -m patchproof_verifier.launch collect --pack /pack -- /pack/tests/test_documents.py` |
| Create argv SHA-256 | `3fd73bfdb3b7fa613a0c3b07e37b65997cd5de48b9f7fbd34fbff4e9e40ada40` |
| Pre-start inspect gate | **passed**: all 59 inspected fields match the fixed policy |
| Docker operations | image-inspect 1, run-create 1, inspect 2, start-attached 1, remove 1, plus an absence-confirming inspect |
| Exit / termination | **0** / EXITED; no signal, no OOM, no timeout; **1.88 s** |
| Standard output | **746 B** of the 256 KiB cap, not truncated; exactly one compact `collected` line (SHA-256 `c9e54895…`) |
| Standard error | 990 B: the 8 node IDs, the G-C1 warning, and `8 tests collected in 0.01s`. No test ran, and there are no pass, fail, skip or xfail lines. |
| Pack | tree `sha256:529d3cd3ebf307586dcecef43a0df8ab9b55296849182f8f43c4ad7d6a8a6c31`, manifest `sha256:a4c4ce48…`; verified before and after |
| pytest | 9.0.3. Established by the gate-B static audit (the only pytest in the image), consistent with the in-image warning location (`_pytest/config/__init__.py:837`, versus `:812` in host 8.4.2). Not self-reported under `-q`. |
| Plugin | `patchproof_verifier` 0.1.0; the 11 built files are byte-identical to the repository (preflight check 4) |
| Inventory | unchanged (14/7/5/10) |

**Collected test IDs and node IDs, exactly the PP-007 manifest in manifest order** (no
missing, extra, duplicate, renamed or reordered tests, and no collection error):

| ID | Node ID |
|---|---|
| AUTH-001 | `tests/test_documents.py::test_nonowner_cannot_read_private_document` |
| AUTH-002 | `tests/test_documents.py::test_unauthenticated_read_is_refused` |
| AUTH-003 | `tests/test_documents.py::test_role_grant_does_not_extend_to_other_documents` |
| AUTH-004 | `tests/test_documents.py::test_invalid_token_is_refused` |
| FUNC-001 | `tests/test_documents.py::test_owner_reads_own_document` |
| FUNC-002 | `tests/test_documents.py::test_granted_auditor_reads_listed_document` |
| FUNC-003 | `tests/test_documents.py::test_second_owner_reads_own_document` |
| FUNC-004 | `tests/test_documents.py::test_caller_reads_own_identity` |

**Prohibited metadata:** none.
- The plugin's `build_collected` refuses skip and xfail markers.
- The approved `pytest.ini` sets `--strict-markers` and `xfail_strict`.
- Only the plugin named in that ini loaded: autoload was disabled (verified by the inspect
  gate) and `--noconftest` was set.

**Record kept:** a private **UNAPPROVED** collection record, `C2/unapproved-collection-record.json`,
for owner review. It is not an approval, and no approval record was created.

**What C2 does not establish:**
- pack approval, or authorization to execute the PaperTrail tests;
- any vulnerability finding or remediation verification;
- authorization to start the target or to run a comparison.

## Observation G-C1: assertion-rewrite warning (pre-existing; not a stop condition)

**The warning**, emitted under pytest 9.0.3 in both C1 steps:

    PytestAssertRewriteWarning: Module already imported so cannot be rewritten; patchproof_verifier.plugin

**Cause:** `patchproof_verifier/__init__.py` imports `.check` and `.plugin`, so the plugin is
imported before pytest registers it through `-p`.

**Effect:**
- pytest's assertion introspection is not applied to the package modules;
- their `assert` statements still execute (the interpreter is not run with `-O`) and still
  raise `AssertionError` with their messages;
- no change in plugin loading or outcome classification was observed.

**Host comparison:** pytest 8.4.2 emits the same warning.

**Recommendation:** a later issue could stop the package `__init__` from importing `.plugin`,
so that pytest's `-p` registration imports it first. Such a change alters the verifier image
contents, so it would need a reviewed rebuild.

## Docker inventory reconciliation

| | Preflight | After C1a | After C1b | Before C2 | After C2 |
|---|---|---|---|---|---|
| Images | 14 | 14 | 14 | 14 | 14 |
| Containers | 7 | 7 | 7 | 7 | 7 |
| Networks | 5 | 5 | 5 | 5 | 5 |
| Volumes | 10 | 10 | 10 | 10 | 10 |

- **Inventory comparison:** within each step, the full inventory lists before and after are
  equal, ignoring only Docker's relative-time text.
- **Correction (readiness review, 2026-10-13):** an earlier version of this report said "the
  listing before C1a equals the one after C2". **That was wrong.**
  - Docker's built-in default `bridge` network was recreated: ID `c5a03b60…` (created
    01:14:11Z) became `c357ca48…` (created 01:23:59Z), between C1b and the C2 revalidation.
  - **Cause**, from Docker Desktop's own log (read as a file; no Docker command): the idle
    manager stopped the VM at 01:20:06Z and restarted it on demand at 01:23:56Z, at the C2
    revalidation's first Docker command. The daemon recreates its default bridge on each
    start; the earlier bridge was itself created by the restart before the first preflight.
  - **Not PatchProof:** PatchProof has no network operation, and every container used
    `--network none`.
  - **Why it was missed:** the C2 revalidation compared counts only.
  - **Unchanged:** images, containers, volumes and the other networks.
- **Before/after identifiers were not completely identical.** The validation containers used
  the fixed isolated network policy (`--network none`), and unrelated images, containers and
  volumes remained intact.
- **Rule for future evidence (owner instruction, 2026-10-13):** reconciliation compares
  actual resource identities (IDs and creation times), not counts, and accounts explicitly
  for Docker daemon or VM restarts between snapshots (Docker Desktop's backend log), rather
  than reporting "unchanged".
- **Ledger:** 3 creations (C1a, C1b, C2) of the 3 authorized. The private
  `container-ledger.jsonl` was written with mode `0644` inside the `0700` evidence directory.
  It is kept unchanged as historical evidence. Future private ledgers and raw evidence files
  use mode `0600`.
- **Leftovers:** no container named `pp-run-…` or using an r1 or r2 image remains.
- **Nothing else:** no prune, filter-based removal, pull, build, tag or exec.

## Remaining before PaperTrail pack approval

1. **Owner review** of the unapproved C2 collection record: 8 tests, pack `529d3cd3…`,
   verifier `e880f609…`, plugin 0.1.0.
2. **Owner review** of the versioned execution profile
   `profiles/papertrail-reference-1.0.0.json` (`sha256:a1c130c2…6835`), which is reviewed as
   one binding of the pack approval.
3. **The owner's typed approval decision**, made by the owner in their own terminal with
   `uv run --locked --offline python -I -m patchproof.pack_approval`. That PP-008 entry point recomputes
   every binding and checks this C2 evidence by its pinned hashes (`stdout.bin` `c9e54895…`,
   `result.json` `9b721cda…`). It then calls the PP-007 `create_approval`, `ApprovalStore`
   and `check_approval`. Nothing in gate C creates or implies this approval.
