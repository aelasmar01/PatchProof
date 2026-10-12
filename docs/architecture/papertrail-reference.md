# PaperTrail reference application — authorization case (PP-006)

**Spec:** `PROJECT_SPEC.md` §1.3, §6 (primary demonstration), §10.5, §15.2, §17.1, §17.2
**Code:** `src/patchproof/reference/` · **Fixture sources:** `examples/papertrail/`
**Ground truth (machine-readable):** `examples/papertrail/reference-fixture.json`, schema
`schemas/reference-fixture.schema.json` · **Tests:** `tests/unit/test_papertrail_reference.py`

PaperTrail is a small synthetic document API. It exists only so that PatchProof can show the
difference between an unfixed vulnerability, an inadequate fix, a real fix, and a "fix" that
breaks legitimate use. It is a verification fixture, not a product.

> **Nothing here has been executed.** PaperTrail has not been started on any revision and
> no HTTP response has been observed. Every expectation below is **declared** from the
> source-level design and checked statically by the tests. Dynamic reproduction belongs to
> the isolated target/verifier runner (PP-008) and its evidence.

PP-006 covers the **object-level authorization** family only. Path traversal (PP-017) and
mass assignment (PP-018) are not implemented.

## Layout

| Path | Contents |
|---|---|
| `examples/papertrail/template/` | Files identical in every revision: `README.md`, `papertrail/__init__.py`, `papertrail/app.py`, `papertrail/fixtures.py`, `fixtures/synthetic/synthetic-documents-v1.json` |
| `examples/papertrail/revisions/<key>/authz.py` | The one file that differs: `papertrail/authz.py` for `vulnerable`, `inadequate`, `correct`, `deny-all` |
| `examples/papertrail/reference-fixture.json` | Revision identities, callers, profile material, declared expectations, comparisons, limitations |
| `src/patchproof/reference/gitobjects.py` | Deterministic Git object encoding and a write-once loose-object writer |
| `src/patchproof/reference/papertrail.py` | Revision plan, template loading, destination checks, generation |

The generated repository is **not** stored in PatchProof. It is written to a new directory
the operator selects, so no generated Git metadata enters this repository.

## Synthetic authorization model

All identities, tokens, titles and contents are synthetic
(`fixtures/synthetic/synthetic-documents-v1.json`, fixture contract `synthetic-documents-v1`).

| Caller | Fixture user | Role | Authentication |
|---|---|---|---|
| `alice` | `u-alice` | member | synthetic bearer token from the fixture |
| `bob` | `u-bob` | member | synthetic bearer token from the fixture |
| `carol` | `u-carol` | auditor | synthetic bearer token from the fixture |
| `anonymous` | — | — | no `Authorization` header |
| `forged-token` | — | — | `Bearer pt-synthetic-unknown-a86591090626`, which matches no user |

| Document | Owner | `reader_roles` | Protected marker in `content` |
|---|---|---|---|
| `doc-alice-private` | `u-alice` | `["auditor"]` | `PT-PROTECTED-ALICE-dc29518fb491` |
| `doc-bob-private` | `u-bob` | `[]` | `PT-PROTECTED-BOB-f674ae494575` |

**Reviewed policy (what the correct fix enforces):** a document is readable by its owner, and
by a caller whose role is listed in that document's `reader_roles`. Carol's auditor role is an
explicit grant on Alice's document only. Unauthenticated callers are always refused.

Each marker occurs exactly once in the fixture and nowhere in the source code, so a response
that contains it is a semantic witness of disclosure (§7.3), not just a status code.
The schema requires a marker on every security check and on every document read, so a
status code alone can never serve as the witness or as proof of legitimate access.

## HTTP contract (identical in every revision)

`papertrail.app:app` is a plain ASGI 3 callable with no third-party imports. It handles the
`lifespan` protocol and `GET` requests only:

| Route | Behavior |
|---|---|
| `GET /health` | `200 {"status":"ok"}`; no authentication (readiness probe) |
| `GET /me` | `401` without a valid token; otherwise `200` with `user_id`, `display_name`, `role` |
| `GET /documents/{document_id}` | `401` without a valid token, **before** any lookup; `404 {"error":"not_found"}` if the document is missing **or** `authz.can_read_document` refuses; otherwise `200` with `document_id`, `owner_id`, `title`, `content` |
| anything else | `404`; non-`GET` methods `405` |

Other controls are the same in every revision and are not weakened in the baseline: the
bearer token must match exactly (`hmac.compare_digest` against every user, 128-byte cap),
duplicate `Authorization` headers count as unauthenticated, a refused read is
indistinguishable from a missing document, and responses carry `Cache-Control: no-store` and
`X-Content-Type-Options: nosniff`.

## Revisions

Generated with object format **sha1**. `refs/heads/main` points at the baseline. Each
revision has an **annotated** tag; the three candidates are children of the baseline. The IDs
below are the actual output of the generator. The tests regenerate the repository and fail
if any ID differs.

| Tag | Commit ID | Tree ID | Tag object ID | Parent |
|---|---|---|---|---|
| `refs/tags/authz-r1-vulnerable` | `68b2bc0e41cb7e9a074b09f2d97db3e2d2ca288a` | `f4a27893dc96e01b42e4b0da27cb2de5977c6063` | `aac9edf2d273d15e991fd7375fd3b2396a94151a` | — |
| `refs/tags/authz-r2-inadequate` | `38f178748f156d5f39e05ac3f19f1a9f47fea39d` | `a1bb7003a5b4b0644a230c5565b4387f55d4b758` | `905db74a4f8ef0dfece64dee6914fc4f237c80c6` | r1 |
| `refs/tags/authz-r3-correct` | `2fb6d09378906f1df69ac32b862df4a350e8a56d` | `eb22f1bf9e8680971fac0af28c0557b117314803` | `80f59286c86b24bed65372fad277f2cb8bb90eb5` | r1 |
| `refs/tags/authz-r4-deny-all` | `f31cb4b159d1859a3614d97a492389a0f823104e` | `589011d5eabf89bc128690e28ecad8dc83e375f6` | `471eacf5d291cd7908543d32fb9a63760519b95a` | r1 |

Only `papertrail/authz.py` differs between revisions. Every other blob is identical, so the
fixture data, identities, markers, endpoints and response shapes are equivalent across all
four.

### Revision 1 — vulnerable baseline (`authz-r1-vulnerable`)

```python
def can_read_document(user: User | None, document: Document) -> bool:
    return user is not None
```

`app.py` already refuses unauthenticated callers, so this function allows **every**
authenticated caller to read **every** document. The document is never consulted. Bob can
read Alice's private document, and Carol's auditor role reaches Bob's document, which does not
grant it. This is an object-level authorization defect (OWASP API1:2023, broken object level
authorization).

### Revision 2 — inadequate fix (`authz-r2-inadequate`)

```python
READ_ROLES = frozenset({"member", "auditor"})

def can_read_document(user: User | None, document: Document) -> bool:
    if user is None:
        return False
    if not user.user_id:
        return False
    return user.role in READ_ROLES
```

A genuine code change: it adds explicit authentication, identity and role checks. The commit
message says it "requires an identified member account". **It remains vulnerable** because
the decision still does not depend on the requested object: `document.owner_id` and
`document.reader_roles` are never read. Every fixture user is authenticated, has an ID, and
holds `member` or `auditor`, so the cross-owner reads still succeed. The tests prove the
change is real: an account with role `guest` is refused by this revision but allowed by the
baseline. They also prove the decision table for every fixture user is unchanged.

### Revision 3 — correct fix (`authz-r3-correct`)

```python
def can_read_document(user: User | None, document: Document) -> bool:
    if user is None:
        return False
    if user.user_id == document.owner_id:
        return True
    return user.role in document.reader_roles
```

This enforces the reviewed owner/role rule. Alice and Bob keep access to their own documents,
and Carol keeps the explicitly granted read of Alice's document. Bob reading Alice's document
and Carol reading Bob's document both receive the same 404 as a missing document.

### Revision 4 — deny-all (`authz-r4-deny-all`)

```python
def can_read_document(user: User | None, document: Document) -> bool:
    # Document reads are disabled until the access rules have been reviewed.
    return False
```

This blocks the unauthorized reads, but also every legitimate read. The owners and the granted
auditor lose access, which is a **functional regression and not a remediation** (INV-08). `/me`
still works, so the application is up and the failure is in the documents feature only.

## Declared expectations

Cells show the expected semantic outcome and HTTP status. "VIOLATION" means the response
contains the check's protected marker.

| Check | Kind | Caller | Request | vulnerable | inadequate | correct | deny-all |
|---|---|---|---|---|---|---|---|
| AUTH-001 | security | bob | `/documents/doc-alice-private` | VIOLATION 200 | VIOLATION 200 | SECURE 404 | SECURE 404 |
| AUTH-002 | security | anonymous | `/documents/doc-alice-private` | SECURE 401 | SECURE 401 | SECURE 401 | SECURE 401 |
| AUTH-003 | security | carol | `/documents/doc-bob-private` | VIOLATION 200 | VIOLATION 200 | SECURE 404 | SECURE 404 |
| AUTH-004 | security | forged-token | `/documents/doc-alice-private` | SECURE 401 | SECURE 401 | SECURE 401 | SECURE 401 |
| FUNC-001 | functional | alice | `/documents/doc-alice-private` | PASS 200 | PASS 200 | PASS 200 | FAIL 404 |
| FUNC-002 | functional | carol | `/documents/doc-alice-private` | PASS 200 | PASS 200 | PASS 200 | FAIL 404 |
| FUNC-003 | functional | bob | `/documents/doc-bob-private` | PASS 200 | PASS 200 | PASS 200 | FAIL 404 |
| FUNC-004 | functional | alice | `/me` | PASS 200 | PASS 200 | PASS 200 | PASS 200 |

The unauthenticated controls (AUTH-002, AUTH-004) are **secure on the baseline too**. The
baseline's defect is object-level only, and its authentication is not weakened to make the
inadequate fix look different.

Every legitimate read that the reviewed policy permits has a positive control (FUNC-001 to
FUNC-003). The tests check that this set equals the set of reads the correct revision allows.

### Expected comparisons (§17.2)

| Baseline | Candidate | Expected verdict | Basis |
|---|---|---|---|
| `vulnerable` | `vulnerable` | `NOT_FIXED` | AUTH-001 and AUTH-003 still disclose the markers |
| `vulnerable` | `inadequate` | `NOT_FIXED` | the added checks pass for every fixture user; AUTH-001/003 still disclose |
| `vulnerable` | `correct` | `VERIFIED_FOR_CASES` | baseline reproduces AUTH-001/003; candidate secure and every control passes. Only after every runtime gate also passes |
| `vulnerable` | `deny-all` | `REGRESSION_DETECTED` | no violation remains, but FUNC-001 to FUNC-003 pass on the baseline and fail on the candidate |

The tests feed these declared outcomes, as complete and trusted observations, into the
accepted PP-004 verdict engine. It returns exactly these four verdicts. That shows the case
design separates the four outcomes; it is not evidence that the application behaves this way
at runtime.

## How the expectations are verified without running PaperTrail

The test process never imports `papertrail`; a test asserts that it is absent from
`sys.modules`.
- **`authz.py`**
  - Read as bytes and parsed with `ast`.
  - A small interpreter in the test evaluates only the language these files use: constants,
    `user`/`document` field access, `is`, `==`, `in`, `and`, `or`, `not`, `if … return`,
    and a `frozenset` constant.
  - It refuses everything else.
  - The decision table it computes for every caller and document derives each declared
    outcome.
- **`app.py`**
  - Checked structurally: authentication runs before the `/me` and `/documents` branches,
    and the 401 return comes before any lookup.
  - Exactly one `authz.can_read_document` call exists, and a refusal returns 404.
  - The 200 response carries `content`.
- **Imports:** every target module imports only reviewed standard-library modules and
  `papertrail.*`. There is no `eval`, `exec`, `compile`, `__import__` or `open`.

## Fixture generation

```
uv run python -m patchproof.reference /absolute/path/to/new-directory
```

This prints the generation record (tags, commit, tree and tag-object IDs) as JSON, with no
absolute paths. Generation runs no Git process at all. `gitobjects.py` encodes blobs,
trees, commits and annotated tags exactly as Git does and writes them as loose objects. So:
- no hook, filter, template or configuration (host or repository) can affect the result;
- no Git write is ever run against an existing or ambiguous repository root.

**Fixed inputs:**
- the file contents and ordering;
- the identity `PaperTrail Fixture <fixture@papertrail.invalid>` for author, committer and
  tagger;
- the timestamps 2026-01-05 to 2026-01-08, 09:00:00 UTC;
- the messages and tag names;
- the repository config (`repositoryformatversion = 0`, non-bare).

**Destination rules:** the generator refuses, and creates nothing, unless the destination is:
- absolute and canonical;
- new;
- inside an existing directory that the current user owns;
- not the home directory or one of its ancestors;
- not inside the PatchProof source tree;
- not inside any other Git repository. The retained `~/.git`
  (`environment.lock.md` §6.1) is the one documented exception, because every user directory
  sits below it.

**Writes and failure:**
- Every file is created with `O_CREAT|O_EXCL|O_NOFOLLOW` and objects are `0444`.
- Every object is re-read and re-hashed before success is reported.
- Any failure removes the partially created directory.
- A process killed with SIGKILL can leave a partial directory. It is never reported as
  generated; delete it and generate into a new directory.

**Result:** the repository has no index and no checked-out working tree, because PatchProof
consumes committed objects only (ADR-004). `git status` in it will therefore list the tree as
staged deletions. That is expected and does not affect snapshots.

**Evidence in the tests:**
- Two generations are byte-identical, including every file under `.git`.
- The reviewed Git 2.56.0 accepts the repository with `fsck --strict`.
- Rebuilding all four revisions with ordinary `git commit` and `git tag -a`, in a separate
  temporary repository with the same contents, identities, dates and messages, yields the
  same commit and tag-object IDs.
- Changing one template byte changes exactly the affected revision's commit ID.

## Fixture profile material (not an approved profile)

`reference-fixture.json` → `target` holds the material that PP-007 and PP-008 turn into an
execution profile (contract 1.1). It matches the existing schema example
`execution-profile.v1.1--papertrail-reference.json` in `adapter`, `asgi_app`,
`fixture_contract`, `network_policy` and `source_scope`.

| Item | Value |
|---|---|
| Adapter | `python-asgi-http-v1` |
| ASGI module and callable | `papertrail.app:app` |
| Python | 3.13 (the approved probe base image is CPython 3.13.16; the target image is PP-008) |
| Application dependencies | none (standard library only) |
| ASGI server | `uvicorn`, version **UNRESOLVED**: selected and hash-locked during PP-008 preparation with owner approval |
| Bind / readiness | `127.0.0.1:8080` inside the isolated namespace; `GET /health` |
| Network | `none-shared-loopback-v1` (target `--network=none`, verifier joins its namespace) |
| Fixture | `fixtures/synthetic/synthetic-documents-v1.json`, `sha256:2cbcf118fddb2cd4e38a9af5e8786911e8f85e292e637102799fd60513129eda` |
| Initialization | the fixture is read once at import from the snapshot (read-only); there is no database or setup command |
| Data reset | the data is immutable; a fresh process (a fresh container per side and repetition) is the reset |
| Source scope | `papertrail`, `fixtures/synthetic` |
| Unresolved bindings | `target_image_id`, `verifier_image_id`, `server_version`, `dependency_lock` |

`approval_status` is `NOT_APPROVED` by schema: the record cannot represent an approval or a
runtime observation, and it cannot assert a server version.

## PP-005 snapshot compatibility

`register_repository` accepts the generated root, and `create_snapshot` succeeds for each tag
and each full commit ID with the source scope above. Each snapshot contains:
- `fixtures/synthetic/synthetic-documents-v1.json`;
- `papertrail/__init__.py`, `app.py`, `authz.py` and `fixtures.py`.

`README.md` is recorded as an `OUTSIDE_SOURCE_SCOPE` exclusion, so `complete_commit` is
`false`. No file matches the secret-file policy. Two independent generations produce
byte-identical manifests for every tag. The generated repository's fingerprint is unchanged
by registration and snapshotting.

## Limitations and obligations

- **Not executed.** No runtime behavior has been observed. "The vulnerable revision produces a
  semantic witness" (§15.2 exit gate) remains to be shown by PP-008.
- **Fixed data.** Identities and markers do not vary per pair, so the target can know them.
  Seeded variation is PP-019.
- **One case.** One read endpoint and one authorization family. This says nothing about
  PatchProof's accuracy elsewhere.
- **Synthetic authentication.** Static bearer tokens with no expiry. Sessions, CSRF and TLS are
  outside the fixture.
- **Generator location.** The generator reads templates from the source checkout
  (`examples/papertrail/`). Packaging them for an installed release is PP-023.
- **PP-007 owes:** a pack whose tests implement AUTH-001 to AUTH-004 and FUNC-001 to FUNC-004
  with semantic witnesses, so that a status code alone is never the witness. Its fixture copy
  must be bound to `fixture_sha256`. Also the exact collection of test IDs, and approval
  records.
- **PP-008 owes:**
  - the target image (Python 3.13, uvicorn pinned with wheel hashes) and verifier image;
  - snapshot mounting at a read-only path with `papertrail` importable;
  - readiness on `/health`;
  - fresh containers per side;
  - the first dynamic reproduction of these expectations, recorded as evidence and compared
    with this table, not substituted for it.
