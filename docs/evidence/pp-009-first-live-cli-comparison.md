# PP-009 first live CLI comparison: independent read-only audit

**Run:** `run-dd93a78f930812bddca76e025eef5d31` · **Plan:** `plan-89e25ceb9b1a11082e4e053b0d70e07f`
(SHA-256 `sha256:89e25ceb9b1a11082e4e053b0d70e07f4a3d08cd90b9c4bf53a28869ef076e3e`) · **Authorization:**
`rau-a76fa4d83f709d7dd652b7593917c2b0` · **Project:** `prj-fc41aa023d78b8c6` (the PP-006 PaperTrail
reference repository) · **Implementation:** `9bc4268f0f360edd339ed3b11f7b27e92d3f15ba`

**Executed:** by the owner through `patchproof plan approve` and `patchproof run`. Execution ran
2026-10-15T00:14:10Z to 00:14:31Z (UTC); the authorization was created at 00:10:53Z and claimed at 00:14:10Z.

**Audit:** 2026-10-14 (local), read-only. No Docker command was run during the audit, no evidence was
rewritten, and no authorization was created or reused. PP-009 remains READY_FOR_REVIEW.

**Result:** the evidence verifies. The verdict, rebuilt from the raw records without reading the stored
verdict, is `VERIFIED_FOR_CASES` (V-09) and equals the stored verdict in every field. The hardened
verifier-console capture works live. **110 scripted checks, 0 failed.** Four report-accuracy and
documentation defects remain before acceptance (§9); none is a security defect.

## 1. Preservation

- **Before the audit:** every entry under the private data directory was recorded with its SHA-256, mode,
  size, mtime and inode (390 entries).
- **After the audit:** the same snapshot, taken after every read, report and export probe, is identical.
- **Since the PP-009 preflight:** the 225 files recorded then (both accepted PP-008 runs, the interruption
  records, both approvals, the PP-008 authorization and claim, the snapshots, the pack store and the
  reference repository) are byte-identical.
- **New since the preflight (89 files):**
  - one project registration;
  - one plan;
  - one run authorization and its claim;
  - the run's 85 evidence files.
- **Record modes:** the project, plan, authorization, claim and approval records are 0400. The evidence
  directory is 0700 and its files are 0600.

| Record | SHA-256 | Bytes |
|---|---|---|
| plan `plan-89e25ceb…` | `d703ddd78bffbb28a2852f84b8d4882bf7c43e4804763b0c9a9d958324f52dc8` | 4162 |
| authorization `rau-a76fa4d8…` | `8c066f989e8bdd5773bad363395b14f4ab27988b1f2e36e19534bc0688bac91e` | 6571 |
| claim `rau-a76fa4d8….claim` | `c812e63ea3c7d94a54932746afcfb20709a58a4696fa8670f5dc85c18032019f` | 163 |
| project `prj-fc41aa023d78b8c6` | `69b3f21301d661946b7e299baef42f3b0af366edb6798b6aaa2317853a41f071` | 660 |
| pack approval `apr-f4b493f9…` (unchanged) | `06f895153f55b0e1ed1b31c7e8e63d08c102fa64f4f21ccabd08804f82fce0f2` | 2694 |
| run `manifest.json` | `3c49261d92e8aca58e62b4c8c30bfe1827b25028c69bd7f14b59bd625dadcd8a` | 19188 |

## 2. Integrity and bindings (46 checks, 0 failed)

**Evidence integrity**
- **Manifest:** `FINALIZED`, listing 84 files. The directory holds exactly those files plus `manifest.json`.
- **Per-file check:** every file's SHA-256, size and mode (0600) was recomputed independently, and each is a
  regular, non-partial file.
- **Accepted verifier:** `verify_evidence` agrees: `CONSISTENT` / `FINALIZED`, no problems.

**Plan and authorization**
- **Plan:** the stored plan's canonical hash reproduces its ID and SHA-256, and the evidence `plan.json`
  equals it.
- **Authorization and claim:** the evidence `authorization.json` and `claim.json` are byte-equal to the
  stored records. The authorization binds the same plan hash and embeds the identical plan.
- **Authorization store:** both run authorizations are `CLAIMED`, and no authorization is executable.
- **Pack approval:** the evidence `pack-approval.json` is byte-equal to the current approval
  `apr-f4b493f9be53db6b0eff607f79508a65`.
- **Project record:** loads strictly (`project-registration` 1.0). Its ID is derived from its canonical
  path; the reviewer basis is `local-assertion-unverified`; the confirmation is `REGISTER prj-fc41aa023d78b8c6`.

| Input | Identity (verified against the pinned contract and the stored artifacts) |
|---|---|
| Baseline r1 (vulnerable) | `refs/tags/authz-r1-vulnerable` → commit `68b2bc0e41cb7e9a074b09f2d97db3e2d2ca288a`, tree `f4a27893dc96e01b42e4b0da27cb2de5977c6063`; source manifest `sha256:1444803c19d7c826f88243850f44c0590008d5c828f755cd43cf48c997b1a3f7` (evidence copy = snapshot store = plan) |
| Candidate r3 (correct fix) | `refs/tags/authz-r3-correct` → commit `2fb6d09378906f1df69ac32b862df4a350e8a56d`, tree `eb22f1bf9e8680971fac0af28c0557b117314803`; source manifest `sha256:42d82e22e879969b96b737e42f89b1d7ea65c28e628ec09141e4b33f06604d4f` |
| Pack | `papertrail-document-access` 1.0.0, tree `sha256:529d3cd3ebf307586dcecef43a0df8ab9b55296849182f8f43c4ad7d6a8a6c31`, manifest `sha256:a4c4ce48d5d2aaa512c746e7ba90d06fd76e879de3a3dea5280079531a8804c8`, plugin 0.1.0; eight tests; collection equals the plan |
| Profile | `papertrail-reference` 1.0.0, `sha256:a1c130c2f8b90c2ada2001ef3bc336b0b8ec29886fd92635dbf5928eb8036835` |
| Target image | `sha256:98548ec48d8d796fca5adaf4aab3e461bee38210bd1d568281f79190685eac2e` |
| Verifier image | `sha256:e880f609a7c4d292441e22d1d0d5d7c876697dd4e1e657a668b2b6266969fecc` |
| Fixture | `synthetic-documents-v1`, `sha256:2cbcf118fddb2cd4e38a9af5e8786911e8f85e292e637102799fd60513129eda`, in both snapshots; one pair, fixed-fixture exception, no seed |

## 3. Observations and verdict

**Streams.** Each verifier stream was collected from its raw bytes again with the accepted collector and
the plan's identity (run, pair, side, pack tree, plugin, collection).

| Side | Bytes | SHA-256 | Events | Status |
|---|---|---|---|---|
| baseline | 8921 | `92284d15e9d8da4a602969422ea192a69611ff64521fea7ae9611515916c1e41` | 31 (seq 0–30, contiguous) | `COMPLETE` |
| candidate | 8900 | `a49d134b1f4f3fa0a31942c4a81c217d85885ac7cfc1e7246e57dd4bd19d76dc` | 31 (seq 0–30, contiguous) | `COMPLETE` |

- **Stream identity:** every event carries this run, pair 1 and its own side. Each stream runs from
  `session_start` (binding the pack tree and plugin version) to `session_end`.
- **Observations:** the re-derived cells equal `observations-pair-001-*.jsonl` exactly.
- **Execution records:** stream bytes, event count, status and session end in the execution records equal
  the raw streams.

**Observation matrix (16 of 16 cells trusted; none missing, contradictory or untrusted)**

| Test | Kind | Baseline r1 | Candidate r3 | Declared expectation |
|---|---|---|---|---|
| AUTH-001 non-owner reads private document | security | `VIOLATION_CONFIRMED` | `SECURE` | violation → secure |
| AUTH-002 unauthenticated read | security | `SECURE` | `SECURE` | secure → secure |
| AUTH-003 role grant limited to listed documents | security | `VIOLATION_CONFIRMED` | `SECURE` | violation → secure |
| AUTH-004 invalid token | security | `SECURE` | `SECURE` | secure → secure |
| FUNC-001 owner reads own document | functional | `PASS` | `PASS` | pass → pass |
| FUNC-002 granted auditor reads listed document | functional | `PASS` | `PASS` | pass → pass |
| FUNC-003 second owner reads own document | functional | `PASS` | `PASS` | pass → pass |
| FUNC-004 caller reads own identity | functional | `PASS` | `PASS` | pass → pass |

**Witnesses** (structured verifier facts; marker values withheld here):
- **AUTH-001 on r1:** caller `u-bob` (member, not permitted) read `doc-alice-private` with status 200, and
  the document's protected marker was observed. On r3: status 404, marker not observed.
- **AUTH-003 on r1:** caller `u-carol` (auditor, not permitted for that document) read `doc-bob-private` with
  status 200, marker observed. On r3: status 404, marker not observed.
- **AUTH-002 and AUTH-004:** status 401 on both sides (no credential; synthetic invalid bearer), marker not
  observed.

**Verifier exits.**
- **Baseline:** exit 1 (`EXITED`, not OOM). It has two failed reports, the two expected security violations.
- **Candidate:** exit 0 with no failed reports.
- **Cross-check:** both codes match a Docker inspect taken after the attached start, and the attached start's
  own return code.

**Verdict, recomputed independently**
- **Rebuilding the input:** the verdict input was assembled from:
  - the approved pack manifest's tests;
  - the plan's pair count;
  - the two execution records;
  - the 16 re-derived cells.

  Only the five precondition states (all `PASSED`, no reason codes) were taken from the run. The rebuilt
  input equals `verdict-input.json` exactly.
- **Recomputation:** the accepted pure engine gives `VERIFIED_FOR_CASES`, decision rule **V-09**, reason
  `ALL_CONDITIONS_SATISFIED`, termination `normal`. Counts are 4 security and 4 functional tests, 1 pair,
  16 of 16 trusted cells. All seven flags are false: incomplete checks, candidate violation, functional
  regression, harness drift, flaky observations, baseline not reproduced, baseline control failed.
- **Agreement:** the recomputed record equals `verdict.json` in every field. `outcome.json` and the manifest
  summary agree.

## 4. Verifier-console capture and `docker-ops-v2` journal (64 checks, 0 failed)

This is the first live run of the hardened verifier-console capture. The PP-008 successful run predates it,
and the PP-008 interruption run never started a verifier.

| Revision artifact | Capture | Bytes | SHA-256 | Cap | Truncated |
|---|---|---|---|---|---|
| baseline verifier console | `CAPTURED` | 5327 | `d8d651a1f4787010a53d0b56f6777ebdc509d421bd074fc90c54901cd6c7fe16` | 1 MiB | no |
| candidate verifier console | `CAPTURED` | 569 | `56e9f5f69e91788c615a7a0225169f35a286df67301a0b59eac470ad1d061c93` | 1 MiB | no |
| baseline target stdout | `CAPTURED` | 0 | `e3b0c442…` (empty) | 5 MiB | no |
| baseline target stderr | `CAPTURED` | 194 | `7d5a7b3ec08e9a5b97cf11608e8d5a2861c837a09af7aa91807e4f0586d1a097` | 5 MiB | no |
| candidate target stdout | `CAPTURED` | 0 | `e3b0c442…` (empty) | 5 MiB | no |
| candidate target stderr | `CAPTURED` | 194 | `7d5a7b3e…` (same bytes as baseline) | 5 MiB | no |

**Capture accounting**
- **Three-way agreement:** for every row, the artifact's own hash and size equal the revision record and the
  journal descriptor.
- **Labels:** the journal descriptor carries class `untrusted-verifier-console`, `untrusted-target-stdout` or
  `untrusted-target-stderr`, with `stored: REVISION_ARTIFACT`.
- **Empty outputs:** the two empty target-stdout captures are recorded as `CAPTURED` with 0 bytes, not as
  failures. A failed capture would be recorded as `CAPTURE_FAILED` and would make the evidence incomplete.

**Trusted channel kept separate**
- **Event channel:** the attached verifier's stdout is the event channel. Its journal descriptor (class
  `verifier-event-channel`) matches the stream file's hash and size.
- **No mixing:** no console or target-log bytes appear inside either trusted stream.
- **Parsing:** only the stream is parsed (§3).
- **No observation events:** the console logs contain no observation-event JSON.

**Journal shape**
- **Format:** all 106 lines are `docker-ops-v2`, covering 53 operations (seq 1–53). Each has exactly one
  `requested` and one `completed` line; none is interrupted or timed out.
- **Metadata only:** completed lines carry only operation metadata (argv, times, durations, return code,
  termination, timeout). Stream descriptors carry only class, bytes, SHA-256, cap, truncation, storage and
  artifact name. The longest line is 2,493 bytes.
- **Artifact references:** every Docker CLI output file (`docker-ops-NNNN-*.out`) is referenced by exactly one
  descriptor and matches it.

**Secret search**
- **Searched for:** the bound fixture's three synthetic bearer tokens and two protected markers.
- **Searched in:** the journal, every Docker CLI output file, the ownership journal, the revalidation
  journal, both inventories, reconciliation, outcome, manifest, the execution and revision records, and
  the verdict.
- **Result:** none appear.

**Finding C1 (informational): the baseline verifier console holds synthetic secrets.**
- **What it contains:** the synthetic tokens and protected markers of the fixture.
- **Why:** pytest's failure traceback for the two expected security failures prints the fixture objects.
- **Where it stays:** the bytes are confined to the private, untrusted, 0600 console artifact. They appear in
  no operational metadata and no report (§6).
- **Recommendation:** a later, separately reviewed verifier change could keep these out of the console, for
  example by hiding the token in the fixture objects' printed form or by shortening tracebacks. That would
  change the approved verifier image and pack, so it is not a PP-009 change.

## 5. Docker execution, cleanup and inventory (from saved records only)

**Containers**
- **Count and order:** exactly four `container create` operations. The baseline target and verifier are
  created, run, removed and confirmed absent (seq 7–26) before the first candidate create (seq 30).
- **Images:** only the two approved image IDs are inspected (twice each) and used. Every create has
  `--pull=never`; there is no pull, build, exec, copy, prune, force removal, or network or volume creation.

| Container | Network | Read-only root | Capabilities | Privileges | User | Memory, CPU, PIDs | Mount |
|---|---|---|---|---|---|---|---|
| baseline target `c47b4d0ed6c4` | `none` | yes | drop ALL | no-new-privileges, not privileged, no ports | 10001:10001 | 1 GiB, 1 CPU, 128 | `/app/source` read-only |
| baseline verifier `3511c2cb88bf` | `container:` + full ID of `c47b4d0ed6c4` | yes | drop ALL | no-new-privileges, not privileged, no ports | 10001:10001 | 512 MiB, 1 CPU, 128 | pack, read-only |
| candidate target `439b38fce27c` | `none` | yes | drop ALL | no-new-privileges, not privileged, no ports | 10001:10001 | 1 GiB, 1 CPU, 128 | `/app/source` read-only |
| candidate verifier `f53170f7c6a1` | `container:` + full ID of `439b38fce27c` | yes | drop ALL | no-new-privileges, not privileged, no ports | 10001:10001 | 512 MiB, 1 CPU, 128 | pack, read-only |

- **Where these values come from:** both the fixed create argv and Docker's own inspect output saved in the
  evidence.
- **Excluded from every create:** the Docker socket, `--privileged`, host network/PID/IPC, published ports and
  environment options.
- **Pre-start inspections:** each container is inspected after creation and before it starts. Every target
  is also inspected repeatedly until ready, and every verifier again after it exits.

**Operations and return codes**
- **Targets:** every container operation names an owned container by its full 64-character ID.
- **Return codes:** all are 0 except these expected cases:
  - the baseline `start --attach` returns 1, the verifier's own exit code;
  - four inspections after removal return 1 with an empty list and "no such container", which confirms
    absence.

**Cleanup**
- **Removal:** each of the four owned containers was removed exactly once by full ID, then confirmed absent.
  The created IDs equal the manifest's `owned_container_ids`.
- **Result:** cleanup `COMPLETE`, no owned container remaining.

**Inventory**
- **Snapshots:** images, containers, networks and volumes were listed before and after the run. The two
  inventory records are identical (complete, no problems).
- **Reconciliation:** `CONSISTENT`, with no findings and no suspected daemon restart.
- **Daemon continuity:** `NO_CHANGE_OBSERVED` means the built-in network IDs did not change. It does **not**
  prove the daemon stayed online throughout.

## 6. Reports

The reports were captured read-only to a scratchpad, never into the private data directory.

**Exit codes**
- **Markdown and JSON reports:** both exited **0**, matching PROJECT_SPEC.md §13.2 for a complete
  `VERIFIED_FOR_CASES` run. Standard error was empty in both cases.
- **Determinism:** two runs of each format were byte-identical.

**JSON report (19,763 bytes)**
- **Format:** one valid JSON document.
- **Result fields:** run ID, plan hash, authorization, verdict, engine verdict, V-09, `COMPLETE`, `FINALIZED`
  and reason codes are all correct.
- **Integrity:** 17 of 17 checks pass, including "recomputed verdict equals `verdict.json`"; journal
  `docker-ops-v2`; `missing_or_untrusted` is empty.
- **Identities:** the exact source, pack, profile, image and fixture identities are included.
- **Cleanup:** shown as a separate dimension.

**Markdown report (10,404 bytes)**
- **Structure:** parsed with the already-installed `markdown-it-py` 4.2.0 (CommonMark with tables). It has
  13 headings, 5 tables (56 rows), 3 lists (21 items), 51 inline-code spans and bold text.
- **Unsafe content:** no links, images or HTML. No control bytes other than newlines, and no escape sequences.

**Both reports exclude:**
- private paths and installation IDs;
- tokens and marker values (shown as "withheld");
- source, pack code and raw logs;
- console text and raw HTTP responses;
- container IDs.

**Markdown escaping diagnosis**
- **Structure is not escaped.** The renderer emits no escaped structural syntax: no line starts with `\#`,
  `\|`, `\-` or `\*`. Headings, table pipes and delimiters, `**` and backticks are literal. The backslashes
  before structural syntax in the owner's pasted copy came from the copy/paste path, not from PatchProof.
- **Punctuation in text is escaped.** The renderer backslash-escapes 202 ASCII punctuation characters inside
  text (`_` 72, `-` 43, `.` 32, parentheses 28, `;` 13 and others). All of them disappear when the Markdown is
  rendered (0 visible backslashes).
- **Trusted text is escaped too.** This includes report-authored prose and labels, such as
  `**Verified for the selected cases\.**` and `evidence\_status`, not only untrusted interpolated values.
- **Effect:** the report renders correctly, but the raw terminal output (the default `report` destination) is
  hard to read.
- **Classification:** a PP-009 usability defect (U4). It must be corrected before acceptance; it is not a
  security defect.

**Safe export (`--output`)**
- **Tests:** the 49 Docker-free export, report and injection tests pass.
- **Live probes, against temporary files only:**

| Case | Exit | Effect |
|---|---|---|
| New file | 0 | written with mode 0600; content equals stdout |
| Existing file | 2 | not overwritten |
| Dangling symbolic link | 2 | the link's target was not created |
| Link to an existing file | 2 | target unchanged |
| Path inside the private data directory | 2 | refused |
| Path reached through a symbolic link into the data directory | 2 | refused |

No temporary file remained after any case.

## 7. CLI exit-code behaviour

| Dimension | Value | Source |
|---|---|---|
| Semantic verdict | `VERIFIED_FOR_CASES` (V-09) | recomputed (§3) |
| Lifecycle | `COMPLETE`, evidence `FINALIZED`, cleanup `COMPLETE` (separate dimension) | outcome and manifest |
| Exit code computed by the CLI for this run | 0 (§13.2 mapping of `COMPLETE` + `VERIFIED_FOR_CASES`) | the owner's terminal output, and the same mapping recomputed from the record |
| Actual shell exit status of `patchproof run` | **not observed** | the owner's pasted terminal output did not include `$?`, and the evidence does not record it |
| `patchproof report` process exit status | **0**, captured directly in this audit (Markdown and JSON) | this audit |

The shell status of the original `run` invocation is not reconstructed or assumed. The Docker-free suite
pins the CLI path for every §13.2 code: 0, 10, 11, 12, 20, 21, 22 and the usage error 2.

## 8. Known limitations

- **One selected-case comparison.** It covers one pair on one fixed synthetic fixture with eight selected
  checks; it is not a general proof of the fix.
- **Retained data.** Structured witnesses are retained, but raw HTTP responses are not. Container inspection
  is configuration evidence, not proof of kernel enforcement.
- **Reviewer identity.** Identities in the registration, approval and authorization records are local
  assertions, and the approval gates are procedural.
- **Daemon continuity.** `NO_CHANGE_OBSERVED` does not prove uninterrupted daemon operation.
- **Shell exit status.** The original `run` shell exit status was not observed (§7).
- **Console secrets.** The baseline verifier console holds the synthetic fixture secrets (C1). It is private
  and untrusted, and it must never be exported or included in a bundle.
- **Release-gate cases still owed.** The §15.2 cases (unchanged, inadequate, deny-all, startup failure,
  missing observation) are not covered by this run. They remain the separately proposed PP-010 prerequisite.

## 9. PP-009 acceptance checklist

| # | Requirement | Evidence | Status |
|---|---|---|---|
| 1 | CLI commands of §13.1 delegate to accepted PP-005–PP-008 modules | committed `9bc4268`; 8,869 Docker-free tests; final security review F1–F8 | **PASS** |
| 2 | Project registration (canonical path, PP-005 boundary, preview, typed confirmation, write-once) | live record `prj-fc41aa023d78b8c6` loads strictly; 0400 | **PASS** |
| 3 | Immutable plan bound to exact sources, pack, approval, profile, images, fixture | §2; plan hash reproduces; evidence plan identical | **PASS** |
| 4 | Interactive single-use authorization bound to the plan hash | §2; claimed once; no executable authorization remains | **PASS** |
| 5 | Execution only through the accepted PP-008 machinery | §5: four containers, fixed policy, sequential, exact-ID cleanup, consistent inventory | **PASS** |
| 6 | Hardened verifier-console capture, live | §4: captured, bounded, hashed, separate from the trusted channel, absent from metadata | **PASS** |
| 7 | Verdict independently reproducible from saved evidence | §3: rebuilt input equals the stored input; recomputed verdict equals the stored verdict in every field | **PASS** |
| 8 | §13.2 exit codes | `report` 0 observed; mapping verified; `run` shell status not observed (§7) | **PASS** (limitation recorded) |
| 9 | JSON report: valid, accurate, deterministic, safe | §6 | **PASS** |
| 10 | Markdown report: valid structure, safe | §6: structure valid, no unsafe constructs | **PASS** |
| 11 | Markdown report: readable; only untrusted text escaped | §6: trusted prose and labels are escaped (U4) | **INCOMPLETE** at audit; **resolved** (§11) |
| 12 | Report statements accurate | the claim label says "seeded synthetic example" while the same report says the fixture has no seed (U3) | **FAIL** at audit; **resolved** (§11) |
| 13 | Approval-gate statements accurate | the authorization preview says "PaperTrail has never been executed", which has been false since PP-008 (U2) | **FAIL** at audit; **resolved** (§11) |
| 14 | Safe export | §6: no overwrite, no symlink following, data directory refused, evidence unchanged | **PASS** |
| 15 | Completion evidence: reproducible documented comparison from input to verdict | this run and audit. The CLI documentation omits the working invocation `uv run --locked --offline patchproof …`, and the program's next-step hints print bare `patchproof` (U1) | **INCOMPLETE** at audit; **resolved** (§11) |
| 16 | Evidence, approvals and authorizations preserved | §1 | **PASS** |

**Usability and documentation findings** (none is a security defect)

| ID | Finding | Classification | Minimal correction |
|---|---|---|---|
| U1 | Next-step hints print `patchproof report …`, which is not on the shell path here. The working form is `uv run --locked --offline patchproof report …` | documentation | state the invocation in `docs/architecture/cli-workflow.md` and the README. Optionally, have the hints name the uv form when running from the project environment |
| U2 | The `plan approve` review text says "PaperTrail has never been executed" | accuracy defect at an approval gate (**mandatory**) | replace it with neutral text: "Declared expectations (expectations, not results of this run)" |
| U3 | The report claim label says "seeded synthetic example" | accuracy defect in the evidence report (**mandatory**) | label it "fixed synthetic fixture (v0.1 no-seed exception), PaperTrail reference" |
| U4 | The Markdown renderer escapes trusted static prose and labels | usability defect (**mandatory**, per the owner's rule) | escape only interpolated untrusted values; emit fixed labels and prose literally; keep the injection tests |
| U5 | "Verified: yes" in the evidence-integrity section can be misread on incomplete runs | wording (recommended) | rename it to "Integrity checks passed: yes" |
| U6 | A relative path given to `pack validate` or `profile prepare` exits 21 (blocked) instead of 2 (usage error) | §13.2 conformance, minor (recommended) | check that the path is absolute at the argument stage and exit 2 |
| U7 | The `plan create` preview title says "read-only" although the command stores a plan | wording (recommended) | "creates one immutable plan record; approves and executes nothing" |
| C1 | The baseline verifier console holds the synthetic fixture secrets | informational; private artifact only | later verifier hardening, separately reviewed (changes the approved image) |

## 10. Assessment

- **The live result holds.** Integrity, bindings, streams, verdict, console capture, journal hygiene, the
  container policy, cleanup and inventory all pass independent checks.
- **No security boundary was weakened** and no evidence was altered.
- **Not ready for formal acceptance yet.** U1–U4 are small, Docker-free corrections (wording, one renderer
  rule, documentation) with matching tests. U5–U7 are recommended polish. None of them needs a new live run;
  this run's evidence stays valid, and its reports can be regenerated read-only after the fix.

## 11. Remediation addendum (2026-10-14, Docker-free)

The owner approved a narrowly scoped, Docker-free correction of U1–U7. No live run was repeated.

**Unchanged.** The evidence of this run and both PP-008 runs, every approval, authorization and claim, the
verdict engine, the snapshot boundary, the pack, the profile, the images, the runtime policy, cleanup and
the verifier event grammar are untouched.

**Regenerated, read-only.** Only the derived reports were regenerated, by the read-only `report` command.

| Finding | Resolution |
|---|---|
| U1 | Every next-step hint is the pinned `uv run --locked --offline patchproof …` (`workflow.invocation.command`). The README and `docs/architecture/cli-workflow.md` document the invocation and say that a bare `patchproof` works only when installed on PATH. The tests parse each printed hint against the real command tree. The `plan approve` path no longer points at the PP-008 utility. |
| U2 | The authorization review says "Declared EXPECTATIONS, not results. The outcomes below are the expected results for this proposed run; they are not observations from this execution". This is static wording; it reads no run history. |
| U3 | The claim label comes from the validated plan's fixture mode: "Synthetic PaperTrail reference application, one fixed synthetic fixture with no variable seed (the narrow v0.1 fixed-fixture exception)". It is followed by "no statement about untested inputs or the application's overall security". The JSON carries `fixture_mode` and `fixture_seed`. An unknown mode fails the report closed. |
| U4 | PatchProof's fixed wording is emitted literally after `safe_text.prose` proves it inert; every value stays escaped or in a code span. A gap found while testing was closed: a value starting with spaces at the start of a list item could indent it into a code block, and `md` now makes a leading space an entity. |
| U5 | "Evidence integrity checks passed: yes/NO", with a note that integrity is separate from completeness, lifecycle, cleanup and verdict. A new row "Fix verified for the selected cases" (JSON `result.fix_verified_for_selected_cases`) is added. |
| U6 | A relative path to `project add`, `profile prepare` or `pack validate` is a usage error (2) before anything is read. Absolute paths that fail policy (symlink, non-canonical, missing, wrong hash) are still refused (21). |
| U7 | `plan create` titles its output "stored once as an immutable record … approves and executes nothing; approval and execution are separate steps". `plan show` keeps the read-only title. |

**Regenerated reports (actual `report` process exit codes, each format rendered twice, byte-identical):**

| Run | Markdown exit | JSON exit | Verdict (recomputed) | Lifecycle / evidence / cleanup | Backslashes in Markdown (before → after) |
|---|---|---|---|---|---|
| `run-dd93a78f…` (this run) | 0 | 0 | `VERIFIED_FOR_CASES` V-09 | `COMPLETE` / `FINALIZED` / `COMPLETE` | 202 → 17 |
| `run-036553ef…` (PP-008, journal v1) | 0 | 0 | `VERIFIED_FOR_CASES` V-09 | `COMPLETE` / `FINALIZED` / `COMPLETE` | → 17 |
| `run-6cee8893…` (PP-008, interrupted) | 20 | 20 | `INCONCLUSIVE` V-05 | `INTERRUPTED` / `INCOMPLETE` / `COMPLETE` | → 11 |

**What the regenerated reports show:**
- **Escaping:** the remaining backslashes are all in record or evidence values (integrity-check details and the
  approval's scope text), and none is visible once rendered.
- **Structure:** each Markdown report parses with the locked `markdown-it-py` into 13 headings and 5 tables,
  with no link, image or HTML. They contain no control bytes, private paths, installation IDs, tokens,
  markers or console text.
- **Fixed-fixture wording:** present in all three reports; "seeded" appears in none.
- **Interrupted run:** its headline still reads "Not a verification result", and "Fix verified for the
  selected cases" is "no".
- **Older run:** the PP-008 journal-v1 run reports without fields that its historical evidence lacks.

The shell exit status of the original `patchproof run` invocation remains unobserved (§7). The codes above
are the report command's own, captured directly.
