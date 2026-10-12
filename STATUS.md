# STATUS

**Updated:** 2026-10-12 (**PP-007 `READY_FOR_REVIEW`**, uncommitted; Pydantic 2.13.5 added under
owner approval; PP-006 `ACCEPTED` and pushed, `origin/main` = `22c43dd`)
**Specification:** `PROJECT_SPEC.md` v1.0

---

## Current release and issue

**Release:** v0.1 — Useful CLI verification
**Issue:** PP-007 — Pack validation, collection, and approval records
**State:** `READY_FOR_REVIEW`, 2026-10-12. Not committed, pushed or tagged. **No pack is
approved.** Real verifier collection and the verifier image are pending PP-008.
**Previous issue:** PP-006, `ACCEPTED` and pushed (`aa3a0a3..22c43dd`, ordinary
fast-forward, 2026-10-12).
**Safe to demonstrate with synthetic fixtures:** the v0.0 foundation, yes. PP-005 and PP-006
are libraries and fixtures with no CLI workflow yet (PP-009). PaperTrail has **not been
executed**; its expected behavior is declared and checked statically only.

## PP-007 — `READY_FOR_REVIEW` (2026-10-12)

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

## Next permitted issue

**PP-007 is `READY_FOR_REVIEW`** (see above). PP-008 is next. It needs separate owner
authorization, and its verifier image and HTTP client need dependency approval.

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
