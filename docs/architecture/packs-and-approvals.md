# Verification packs, collection, and approvals (PP-007)

**Spec:** `PROJECT_SPEC.md` §7.1–7.5, §8, §10.3 · **ADRs:** ADR-002, ADR-003, ADR-008, ADR-009
**Verdict specification:** §3.1–3.3 (event grammar, lifecycle, semantics), §10 (rules the
schemas do not enforce)

**Code:**
- `src/patchproof/core/strict_json.py` and `core/records/`: strict loader and models;
- `src/patchproof/packs/`: validation and collection;
- `src/patchproof/core/approvals.py` and `core/outcomes.py`;
- `verifier/patchproof_verifier/` and `verifier/pytest.ini`: verifier helpers and plugin.

**Pack:** `examples/packs/papertrail-document-access/`

**Tests:** `test_record_parity.py`, `test_pack_validation.py`, `test_approvals.py`,
`test_outcomes.py`, `test_verifier_helpers.py`.

> **Nothing here has run in a verifier container.** The verifier image, its HTTP
> transport and event channel, the final execution profile and a real collection all belong
> to PP-008. No pack is approved. The PaperTrail pack has never been executed.

## Records: strict loading and Pydantic models (ADR-008)

Loading has two stages.
1. **Strict JSON** (`loads_strict`). It refuses:
   - invalid UTF-8 and a BOM;
   - duplicate keys at any depth;
   - `NaN` and `Infinity`;
   - lone surrogates;
   - nesting deeper than 32 levels (checked before parsing);
   - more than one document;
   - anything over a size limit.
2. **A strict Pydantic v2 model** for the named contract (`load_record`). Every model:
   - is strict (no coercion);
   - is closed (unknown fields rejected);
   - is frozen;
   - never echoes rejected input in its errors.

There is one model per record schema (12 contracts). The models are written by hand, not
generated from the schemas, so the parity tests compare two independent implementations.

**Parity results:**

| Check | Result |
|---|---|
| Corpus: every valid and invalid example, the JSONL event stream, and all 26 scenarios (input and verdict) | 160 records, **0 disagreements** |
| Differential mutation run, 2026-10-12: every corpus record × field deletions, unknown fields, type swaps, bounds, enum swaps and list changes | 223,815 mutations; **0 cases where a model accepts what a schema rejects**; 0 unexplained differences |
| Bounded deterministic sample in the unit suite | up to 400 mutations per valid record, every run |

**The model is stricter in two documented ways:**
- **Trailing newline:** `jsonschema` uses Python's `re.search`, whose `$` also matches before
  a final newline. So the schemas accept `"abc\n"` for `^[a-z0-9-]+$`, and the models
  (`re.fullmatch`) do not.
- **Integral floats:** JSON Schema treats `1.0` as an integer. The strict models reject a
  float for an integer field instead of converting it.

**A fix found by the mutation run:** Pydantic's `Literal[False]` and `Literal[True]` accept
`0` and `1` even in strict mode. The three boolean constants (`uncommitted_changes_included`,
`synthetic`, `declared_expectations_only`) therefore use a strict `bool` with an identity
check. Integer enumerations use strict `int`.

## Pack layout and validation

```
pack.json        manifest (pack-manifest 1.0)
README.md        how the checks establish the expectation
tests/**/test_*.py
fixtures/<fixture_contract>.json
```

`validate_pack` reads bytes and parses Python with `ast`; it never imports pack code. Every
rule fails closed with a stable code: `PACK_PATH_INVALID`, `PACK_TOO_LARGE`, `PACK_INCOMPLETE`,
`PACK_MANIFEST_INVALID`, `PACK_TEST_INVALID` or `PACK_FIXTURE_INVALID`.

- **Paths:**
  - only the layout above, within 64 files, 256 KiB per file and 2 MiB in total;
  - no symlinks, FIFOs or other special files;
  - no hidden names, no `__*` names (so no `__init__.py` or `__pycache__`);
  - no `conftest.py`, `pytest.ini`, `pyproject.toml` or other configuration;
  - an absolute canonical root;
  - each file opened with `O_NOFOLLOW|O_NONBLOCK` and re-checked with `fstat` (regular
    file, same device and inode), so a file swapped for a FIFO or device after `lstat`
    is refused instead of blocking or being read.
- **Manifest:**
  - strict load and model;
  - unique test IDs and unique node IDs;
  - no unresolved placeholders (`{{ }}`, `${}`, `<% %>`, `__NAME__`, `TODO`/`TBD`);
  - parametrized node IDs are refused;
  - every test module is referenced, and every reference exists;
  - each module defines exactly the manifest's tests;
  - at least one security check expects the baseline violation, and at least one functional
    control exists (INV-06, INV-08).
- **Test modules (static):**
  - imports only `__future__` and `patchproof_verifier`;
  - no decorators (so no skip, xfail or parametrize);
  - no `pytest.skip`, `xfail`, `fail`, `exit` or `importorskip`;
  - no `eval`, `exec`, `open`, `getattr`, `__import__` or similar;
  - no `try` or `with` (they could hide a terminal exception);
  - no `Exception`/`BaseException`/`SecurityTerminal` names, no `_private` attributes, no
    lambdas, globals or async tests.
  - A security test takes `check` and makes exactly one terminal call. A functional test does
    neither, and asserts legitimate behavior.
- **Fixture binding:** `fixtures/<contract>.json` must hash to the reviewed contract. For
  `synthetic-documents-v1`, that is the PP-006 `fixture_sha256`. Nothing else may be in
  `fixtures/`.
- **Hashes:**
  - `manifest_sha256` is the SHA-256 of `pack.json`'s bytes.
  - `pack_tree_sha256` is the SHA-256 of the canonical JSON list of `(path, size, sha256)`
    for every file, ordered by path.

These static checks are a policy for v1 packs. They are deliberately narrow, and a richer
pack needs a reviewed policy change.

**They are not a sandbox.** AST rules can be evaded by code written to defeat them, and
they are not a security boundary. They help a reviewer catch mistakes and obvious
misuse before approval. The boundaries are these:
- pack code is never imported on the host;
- it runs only in the isolated verifier container (§10);
- it runs only after an explicit owner approval that binds its exact bytes.

## Exact collection (§7.4)

Collection happens **only in the verifier environment**. `collection_plan` produces the fixed
invocation the PP-008 runner executes in the verifier container:

```
/usr/local/bin/python3 -I -B -m patchproof_verifier.launch collect --pack /pack -- /pack/tests/test_documents.py
  (the launcher runs pytest -c /opt/patchproof/verifier/pytest.ini --rootdir /pack --collect-only ...)
env: PATH, LC_ALL=C.UTF-8, HOME=/nonexistent, PYTEST_DISABLE_PLUGIN_AUTOLOAD=1,
     PYTHONDONTWRITEBYTECODE=1, PYTHONHASHSEED=0       (built from scratch, nothing inherited)
bounds: 30 s, 256 KiB output
```

**Changed in PP-008:** the original `-m pytest ...` form was replaced by the PatchProof
launcher. An end-to-end run under real pytest showed that pytest's own output otherwise
reaches standard output, the event channel. The `--` before the test paths was confirmed with
pytest 8.4.2 on synthetic packs.

**What the invocation guarantees:**
- `-I` ignores `PYTHONPATH` and user site-packages.
- The environment is built from scratch, so `PYTEST_ADDOPTS`, `PYTEST_PLUGINS` and the
  rest cannot be present.
- PatchProof's own `pytest.ini`:
  - loads only `patchproof_verifier.plugin`;
  - disables the cache, doctest, pastebin and stepwise plugins;
  - sets `--noconftest`, `--strict-markers`, `--strict-config` and
    `--import-mode=importlib`;
  - sets `xfail_strict = true`.

**What the plugin does:**
- It maps each collected item to its manifest ID.
- It refuses collection when a test is unknown, missing or duplicated, or carries a
  `skip`/`skipif`/`xfail` marker.
- It emits the `collected` payload.
- It refuses to execute tests until the PP-008 transport exists.

**What the host does:**
- It parses the payload strictly.
- **Review time:** the collection must contain exactly the manifest's tests, each once. Its
  order becomes the approval's `expected_collection`.
- **Run time:** the collection must equal the approved list exactly, in order
  (`PACK_COLLECTION_MISMATCH` otherwise).

**No collection has been performed.** The validators are tested with synthetic,
controlled inputs only.

## Approvals (§7.5, INV-10)

An approval (`approval-record` 1.0) binds:
- the pack ID and version, manifest hash and pack-tree hash;
- the exact expected collection;
- the verifier image ID and plugin version;
- the profile ID and the profile hash (the canonical JSON of the validated profile model);
- a reviewer identity that is only locally asserted (`local-assertion-unverified`), with a
  timestamp, rationale and scope.

**Rules:**
- **Explicit action:** `create_approval` requires the reviewer to type
  `APPROVE <pack_id> <pack_version> <first 12 hex digits of the manifest hash>`. A
  `ReviewDecision` has no default fields; reviewer, rationale and scope are validated text.
  The only caller is the PP-008 owner-operated entry point below; the general PP-009 CLI
  will reuse the same functions.
- **Staleness:** `check_approval` recomputes every binding from current inputs. Any
  difference is `APPROVAL_STALE` and names the fields. The tests change each binding in turn:
  - test content;
  - the manifest;
  - the README;
  - the collection and its order;
  - the verifier image;
  - the plugin version;
  - the profile ID and hash.
- **Immutability:** `ApprovalStore` is a private (0700) directory.
  - Records are written once with `O_EXCL` and mode `0400`. They are never edited or
    deleted.
  - A replacement names the approval it supersedes, and both remain.
  - A superseded approval is stale even when its bindings still match.
  - Forks, dangling links, renamed files, foreign files, FIFOs and tampered records are
    refused. Records are opened non-blocking and re-checked as regular files.
  - Every store operation opens the root as a directory descriptor
    (`O_DIRECTORY|O_NOFOLLOW`) and checks that it is the same private directory, by device
    and inode. Entries are created, listed and read relative to that descriptor, so a
    root swapped for a symlink or another directory is refused, not followed.
- **Pack approval is not run authorization.** A run authorization (PP-009) also binds:
  - the baseline and candidate snapshot hashes;
  - the target image;
  - the resource policy;
  - the repetition plan.

  No approval in this module authorizes a run.

### Owner-operated entry point (PP-008)

`src/patchproof/pack_approval.py` approves exactly one pack, `papertrail-document-access`,
through the functions above. It adds no record format, phrase or store of its own. It is not
the PP-009 CLI. The owner runs it in their own terminal, from the project directory:

```
uv run --locked --offline python -I -m patchproof.pack_approval
```

- **Interactive only:** it refuses any argument, any `PATCHPROOF*` environment variable,
  standard input or output that is not a terminal, and a process that is not in the
  foreground process group of its controlling terminal. A piped confirmation is never read.
- **Fresh bindings:** every binding is recomputed from its source, never from a draft:
  - the pack directory (static validation; nothing is imported);
  - `profiles/papertrail-reference-1.0.0.json` (strict loader, pinned canonical hash);
  - the private gate C2 collection evidence (pinned file hashes; exactly the manifest's eight
    tests, in order; same image, pack tree and manifest; exit 0);
  - the approved r2 verifier image;
  - `PLUGIN_VERSION`, read from the verifier source with `ast`.
- **Review screen:** before any prompt, it shows every binding, the expected collection, the
  security claim, what each check witnesses, the functional controls, the full profile and
  the limits. It states that this is a pack approval, not a run authorization, and that no
  vulnerability has been reproduced.
- **Prompts:** asserted identity, rationale, scope, then the exact PP-007 phrase.
- **Before writing:** all bindings are recomputed and the store is re-read. Any difference
  aborts with nothing written. Re-running with unchanged bindings writes nothing.
- **After writing:** the record is read back; the earlier history must be intact and the file
  `0400`; `check_approval` must report it as the pack's current approval for the recomputed
  bindings. A failure is reported as a failure, never as an approval.
- **Exit codes:** 0 a verified approval was written; 2 not approved, nothing written; 3 an
  approval of exactly these bindings already exists, nothing written; 4 a record was written but
  failed verification (or an error occurred after the write). It is reported as `FAILED
  VERIFICATION`, never as approved, and is not deleted.
- **Statements:** the rationale and scope must not contain the confirmation phrase (case
  and spacing ignored). The phrase is typed only at the confirmation prompt.
- **Pinned, offline environment:** `--locked --offline` refuses a lockfile that is out of date
  and any network access. Verified 2026-10-13 under a pseudo-terminal: `uv run` keeps Python in
  its own foreground process group, so the foreground check passes, and `uv sync --dry-run`
  reports no environment change.
- **Store:** `<platformdirs user data>/PatchProof/approvals/` (macOS:
  `~/Library/Application Support/PatchProof/approvals/`). It is created once with `mkdir(0700)`
  relative to the parent's descriptor; the parent must be owned and not writable by others.
  An existing store must already be exactly `0700`; it is never chmod-repaired. The opened
  `ApprovalStore` must have the same device and inode. Approval records never live in the
  repository.
- **Limit:** the terminal checks are a procedural control, not proof of a human. Software
  running as the same OS account can allocate a pseudo-terminal, and the reviewer identity
  remains `local-assertion-unverified`.

**Correcting a statement by supersession.** A reviewer statement (identity, rationale, scope)
is never edited. To replace it, the owner runs:

```
uv run --locked --offline python -I -m patchproof.pack_approval_supersede
```

- the same interactive gate and fresh binding recomputation as the approval command;
- refused unless the store exists and the pack has a current approval that is `APPROVED` for
  the recomputed bindings. A stale approval is re-approved with the approval command, not
  superseded with a new statement;
- shows the current record with its rationale and scope, then the full review, and states
  that the existing record is kept;
- the new record passes the current approval as `supersedes`;
- after the write, every earlier record must be byte-for-byte and mode-identical, the
  history must be the earlier history plus exactly one record, the new record must be
  `APPROVED` and the original `APPROVAL_STALE (superseded)`;
- exit codes as above. The original is never deleted, renamed or rewritten.

**No PaperTrail approval exists.** Only the owner can make one, with the command above. A
test asserts that no `apr-*.json` file exists in the repository.

## Per-test outcomes (verdict specification §3.2–3.3)

`derive_outcome` implements rules L1–L11 and the harness-error table, as pure code for the
PP-008 collector. It refuses, rather than interprets, a block that is not one of the two
valid shapes.

**Tested integrity cases:**
- A generic assertion in a security test is `CALL_ERROR` with
  `GENERIC_FAILURE_IN_SECURITY_TEST`, never a violation.
- A crash or timeout in a functional test is never `FAIL`.
- A caught terminal exception is flagged `SUPPRESSED_TERMINAL_EXCEPTION`, and the
  observation stays recorded.
- Missing and multiple observations are flagged.
- A security terminal exception without a violation observation is `MALFORMED_EVIDENCE`.
- An observation outside the call window is a grammar error.

## Verifier helpers and the PaperTrail pack

`patchproof_verifier` is PatchProof-owned code installed only in the verifier image. The host
unit-tests it as trusted code; pack modules are never imported.

**`check`** records exactly one terminal observation:
- `violation` records it and then raises `SecurityTerminal`;
- a second call or malformed evidence is `HelperMisuse`;
- requesting `check` in a functional test is refused by the plugin, and by static
  validation before that.

**`Evidence`** is a bounded set of printable facts (at most 32), so target text cannot inject
terminal escapes.

**The authorization witnesses** (`patchproof_verifier.authz`):
- **Violation:** the response body contains the document's synthetic protected marker, and
  the hash-checked fixture shows the caller is neither the owner nor granted a role. The
  evidence names the caller and role, the owner, the document, the reader roles, the status
  and the marker.
- **Secure:** a reviewed denial status (403/404 for authenticated callers, 401 for
  unauthenticated ones), no marker, and no document `content`. A status alone is never
  enough.
- **Inconclusive:** anything else, for example a 200 without the marker, a 500, or a
  redirect.
- **Target text has no authority.** Words like "SECURE" or event-shaped JSON in the body
  change nothing; only the marker test reads the body.
- **Functional helpers:** they assert the actual document ID, owner and content, or the
  caller's own identity and role, and that the bearer token is not echoed.

**The pack:** `papertrail-document-access` 1.0.0 covers PP-006's eight declared checks.

| ID | Node ID (`tests/test_documents.py::…`) | Kind | Baseline → candidate |
|---|---|---|---|
| AUTH-001 | `test_nonowner_cannot_read_private_document` | security | VIOLATION_CONFIRMED → SECURE |
| AUTH-002 | `test_unauthenticated_read_is_refused` | security | SECURE → SECURE |
| AUTH-003 | `test_role_grant_does_not_extend_to_other_documents` | security | VIOLATION_CONFIRMED → SECURE |
| AUTH-004 | `test_invalid_token_is_refused` | security | SECURE → SECURE |
| FUNC-001 | `test_owner_reads_own_document` | functional | PASS → PASS |
| FUNC-002 | `test_granted_auditor_reads_listed_document` | functional | PASS → PASS |
| FUNC-003 | `test_second_owner_reads_own_document` | functional | PASS → PASS |
| FUNC-004 | `test_caller_reads_own_identity` | functional | PASS → PASS |

**Hashes:**
- `manifest_sha256`: `sha256:a4c4ce48d5d2aaa512c746e7ba90d06fd76e879de3a3dea5280079531a8804c8`
- `pack_tree_sha256`: `sha256:529d3cd3ebf307586dcecef43a0df8ab9b55296849182f8f43c4ad7d6a8a6c31`

Both are recomputed by the tests.

**How the pack is checked against PP-006:**
1. An AST test pins each pack test to its helper, caller and path.
2. A second test feeds the helpers **synthetic** responses shaped like PaperTrail's
   documented replies for each PP-006 revision. All 32 check × revision combinations
   produce the declared outcome.

That validates the witness logic. It is **not** an observation of PaperTrail running.

## Obligations for PP-008

- **Images:** build and approve the verifier image, which needs pytest, the
  `patchproof_verifier` package, `pytest.ini` at `/opt/patchproof/verifier/` and an approved
  HTTP client library (§3.1 names HTTPX). This needs owner approval and pinned hashes.
- **Plugin:** implement the `target` client transport (fixed `127.0.0.1:8080`, no redirects,
  no proxies, response size limit) and the verifier event channel, which emits
  `session_start`, `collected`, phase reports with `failure_class`, observations and
  `session_end`.
- **Collector:** enforce the event grammar, then call `derive_outcome`.
- **First collection:** run `collection_plan` in the verifier container, check the result
  with `review_collection`, and only then let the owner approve the pack (done: gate C2;
  owner entry point `patchproof.pack_approval`).
- **Run time:** call `check_run_collection` against the approved list.
- **Bytes approved are bytes run (R2, closed in PP-008 by `runner/inputs.py`):** validation hashes the pack directory as it was read.
  The runner must mount a copy made from exactly those bytes, or re-hash what it mounts
  and refuse a mismatch with the approval's `pack_tree_sha256`. It must never mount the
  live directory unchecked.
- **The collection command has never run.** PP-008 must confirm that pytest 8.4.2 in the
  image accepts it exactly as built (including `--` before the paths), and must record
  any change as a reviewed code change.
