# Threat model

**Issue:** PP-002 · **Status:** `READY_FOR_REVIEW` · **Spec basis:** `PROJECT_SPEC.md` §3.2, §4, §10, §11, §12
**Method:** STRIDE applied per trust boundary. Mitigation evidence is organized
around the eight concrete abuse cases in §4.3, not around STRIDE terms.

> **Status of every mitigation below: planned.** No mitigation is implemented or
> verified. Each row names the issue that must produce evidence. Measured host facts
> come from `docs/environment.lock.md`; nothing here is inferred about the host.

---

## 1. Scope and security claim

PatchProof's claim is narrow. For the selected cases, it reports whether a reviewed
check observed the baseline violation, whether the candidate enforces the expectation,
and whether legitimate behavior survives. It reports that only when evidence produced
by an independent verifier is complete. Everything else in this model protects that
claim from being falsified, or protects the host while lower-trust code runs.

**Out of scope for comprehensive protection (§4.1):**

- a compromised host account;
- a malicious author of the approved verifier;
- a hostile Docker administrator;
- container-runtime vulnerabilities (mitigated only by running a supported, patched
  runtime: `docs/environment.lock.md` §6.5);
- a deliberately deceptive target that fingerprints the tests.

Randomized fixtures and process separation reduce these risks; they do not remove them.

## 2. Assets

| ID | Asset | Why it matters |
|---|---|---|
| A1 | Verdict integrity | The product's only claim. A false `VERIFIED_FOR_CASES` is the worst failure. |
| A2 | Approved packs, profiles, and approval records | Define what "verified" means (INV-04, INV-10). |
| A3 | Host account: home directory, credentials, `~/.ssh`, `~/.aws`, Git credential helper | Lower-trust target code must never reach them (INV-01, INV-02). The host has a `gh` credential helper and a stray home-directory Git repository (`environment.lock.md` §5, §6.1). |
| A4 | Original target repositories and uncommitted work | INV-13. |
| A5 | Evidence store and private raw artifacts | Must be complete, bounded, and not exported by default (INV-12, INV-15). |
| A6 | Docker daemon authority | Equivalent to host-file write access [R3]. |
| A7 | Host resources: disk, memory, CPU | Logs, output, and runaway targets must be bounded (§5.2). |
| A8 | Unrelated Docker resources: 9 images and 7 stopped containers | Must survive every PatchProof operation (`environment.lock.md` §4.3). |

## 3. Trust zones

| Zone | Contents | Trust |
|---|---|---|
| Z0 Operator | Ali, terminal, local OS account | Trusted; the only approver |
| Z1 PatchProof host services | CLI, local API, worker, verdict engine, SQLite, evidence store | Trusted code; validates all input |
| Z2 Container runtime | Docker Desktop 4.94.0 VM and daemon | Trusted computing base |
| Z3 Verifier container | Approved verifier image and approved pack | Trusted code processing untrusted HTTP responses |
| Z4 Target container | Approved snapshot of target code and its dependencies | **Lower trust**: executes, and everything it returns is data |
| Z5 Browser | The PatchProof UI tab, plus every other origin and tab | Other origins are hostile |
| Z6 Original repository | Operator-owned Git repo on disk | Content is lower-trust data; the repo itself must not be modified |
| Z7 Coding agent | Claude Code or similar, used at development time | Untrusted for approvals and expectations (§4.3 #8) |

## 4. Data flow and trust boundaries

```text
              Z5 browser (other origins hostile)
                    |  TB-1 loopback HTTP, session + CSRF + Origin + Host checks
                    v
 Z0 operator --> Z1 PatchProof host services ------------------------------+
   terminal       |  CLI / API / worker / verdict engine / SQLite / evidence |
   approval       |                                                           |
                  | TB-2 sanitized read-only git (ls-tree, cat-file)          | TB-7 reports and exports
                  v                                                           v
             Z6 original repo (never written, never mounted)          reviewers (escaped, redacted)
                  |
                  | TB-3 typed Docker CLI wrapper (allowlisted ops, argument arrays)
                  v
 Z2 Docker VM  +-------------------------------------------------------------+
               |  Z4 target  --network=none, read-only snapshot, tmpfs       |
               |     ^   TB-4 shared loopback only (127.0.0.1:8080)          |
               |     |                                                       |
               |  Z3 verifier  joins target's network namespace only;       |
               |     approved pack read-only; no target source              |
               +-------------------------------------------------------------+
                  |  TB-5 verifier structured event stream --> Z1 (trusted channel)
                  |  TB-6 target logs --> Z1 (bounded, labeled untrusted, never parsed as events)
                  |  TB-9 network: no egress, no published ports, no host network
```

| Boundary | Crosses | Principal STRIDE concerns |
|---|---|---|
| TB-1 | Z5 → Z1 | Spoofing (other origins, DNS rebinding); tampering (CSRF); elevation (a request supplying paths, commands, or Docker flags) |
| TB-2 | Z6 → Z1 | Tampering (filters, hooks, text conversion, replacement objects); elevation (option-like refs, path traversal, symlinks); DoS (oversized trees) |
| TB-3 | Z1 → Z2 | Elevation (privileged flags, socket or home mounts, host network); tampering (floating tags, implicit pulls) |
| TB-4 | Z3 ↔ Z4 | Tampering (target fingerprints or deceives tests); information disclosure (target reads verifier files) |
| TB-5 | Z3 → Z1 | Spoofing (forged events); repudiation (missing completion); DoS (output flood) |
| TB-6 | Z4 → Z1 | Tampering and spoofing (result-like text, ANSI, HTML in logs); DoS (log flood) |
| TB-7 | Z1 → readers | Information disclosure (source, secrets, paths); tampering (injection in reports) |
| TB-8 | Z7 → Z1/A2 | Tampering (agent weakens tests or expectations); elevation (agent approves its own patch) |
| TB-9 | Z4 → network | Information disclosure (exfiltration); elevation (reaching host services or the Docker API) |

## 5. Abuse cases (§4.3) with planned mitigations and evidence

### AC-1 A candidate deletes tests, spoofs success text, crashes intentionally, or denies every request

**Boundaries:** TB-4, TB-5, TB-6 · **STRIDE:** Tampering, Spoofing, Repudiation · **Invariants:** INV-04 to INV-09, INV-11

| Planned mitigation | Spec | Evidence issue |
|---|---|---|
| Pack is external to the snapshot. Deleting repository tests cannot remove pack checks. | §7.1, §10.2 | PP-008, PP-020 |
| Exact expected collection; unexpected, missing, skipped, xfail, and xpass results all count as incomplete | §7.4; verdict spec §4 | PP-007, PP-004 |
| Verdict computed from verifier events only; the engine has no input for target output | verdict spec §2 | PP-004 (type), PP-008 (channel) |
| Crash, timeout, or OOM leads to untrusted cells and `INCONCLUSIVE`, never `FAIL` or success | verdict spec §3, V-05 | PP-004, PP-008 |
| A deny-all candidate is caught by functional controls (V-04) | INV-08; pack schema `contains` | PP-004, PP-006 |
| An explicit semantic witness is required; HTTP 500 or a generic assertion is not a violation | INV-05, §7.3 | PP-007 plugin |

**Schema evidence now:** `pack-manifest--no-functional-control.json` and
`pack-manifest--no-baseline-violation-expected.json` are rejected;
`observation--target-stdout-provenance.json` is rejected;
`observation--timeout-recorded-as-fail.json` is rejected.

### AC-2 A repository path, archive entry, Git object name, or manifest field abuses filesystem or command handling

**Boundaries:** TB-2, TB-3, TB-1 · **STRIDE:** Elevation, Tampering · **Invariants:** INV-13, INV-16

| Planned mitigation | Spec | Evidence issue |
|---|---|---|
| Allowlisted Git wrapper; sanitized environment; explicit config disabling filters, hooks, textconv, and replace objects (the host has `filter.lfs.required=true`) | §9.2; `environment.lock.md` §5 | PP-005 |
| Option-like refs and unsupported revision expressions rejected; full object IDs recorded with their object format | §9.1 | PP-005 |
| Symlinks, gitlinks, LFS pointers, special files, traversal, absolute paths, and case-collision paths rejected, never silently omitted | §9.2 | PP-005 |
| Node IDs, relative paths, and ASGI entry points constrained to grammars that cannot express `..`, leading `-`, or shell metacharacters | schemas `common`, `execution-profile` | **PP-002 (schema)**, PP-007 |
| Subprocesses use argument arrays only; no `shell=True` | §10.3 | PP-005, PP-008; Semgrep rule 1 in PP-026 |
| Import of evidence or bundles is inspection-only, with traversal, link, and size checks | §12.4 | PP-024 |

**Schema evidence now:** `pack-manifest--nodeid-path-traversal.json`,
`pack-manifest--nodeid-option-injection.json`,
`execution-profile--asgi-shell-fragment.json`, and
`execution-profile--source-traversal.json` are all rejected.

### AC-3 A malicious webpage attacks the loopback UI (cross-origin requests, DNS rebinding)

**Boundary:** TB-1 · **STRIDE:** Spoofing, Tampering, Elevation · **Invariants:** INV-14, INV-16

| Planned mitigation | Spec | Evidence issue |
|---|---|---|
| Bind to `127.0.0.1:8765` only; exact Host allowlist (defeats DNS rebinding) | §5.4, §11.1 | PP-012 |
| Terminal bootstrap code to HttpOnly SameSite=Strict session; session-bound CSRF token plus exact Origin check | §11.1 | PP-012 |
| No permissive CORS; no state-changing GET | §11.1 | PP-012 |
| Registration and profile approval are terminal-only; the browser selects IDs, never paths, flags, or commands | §11.2 | PP-012 |
| Approval hashes revalidated at dequeue, not only at click time | §11.2 | PP-011 |

**Residual:** loopback HTTP has no transport encryption; documented as an exception (§11.1).

### AC-4 Target responses and logs inject HTML, terminal escapes, report links, or misleading result records

**Boundaries:** TB-6, TB-7 · **STRIDE:** Tampering, Spoofing · **Invariants:** INV-09, INV-12, INV-15

| Planned mitigation | Spec | Evidence issue |
|---|---|---|
| Target logs stored as separately labeled untrusted data and never parsed as events | §10.3 | PP-008 |
| Verifier events travel on a dedicated channel the target cannot write to, under the assumed container boundary | §10.3 | PP-003 (boundary probe), PP-008 |
| Reviewed free-text fields exclude C0 controls (including ESC) and DEL | schema `common.shortText`/`longText` | **PP-002 (schema)** |
| Escaped rendering, no ANSI interpretation, no `dangerouslySetInnerHTML`, strict CSP, script-free static HTML, no remote images | §11.3, §12.3 | PP-013, PP-021 |

**Schema evidence now:** `pack-manifest--ansi-escape-in-title.json` and
`verifier-event--payload-carries-verdict.json` are rejected.

### AC-5 A long-running or memory-hungry application exhausts local resources

**Boundaries:** TB-3, TB-6 · **STRIDE:** Denial of service · **Invariants:** INV-14

| Planned mitigation | Spec | Evidence issue |
|---|---|---|
| A profile cannot omit CPU, memory, PID, or scratch limits; all are required fields | schema `containerLimits` | **PP-002 (schema)** |
| Limits enforced *and probed*. `docker info` capability is not enforcement (`environment.lock.md` §4.5). | §5.2 | **PP-003** |
| Readiness, request, and per-revision deadlines; cancellation grace, then force-remove of only that run's containers | §5.2, §10.6 | PP-008, PP-014 |
| Daemon-side rotating log limit inspected and flood-tested; a profile is blocked if the limit cannot be enforced | §10.3 | PP-003, PP-008 |
| Result cap exceeded leads to `OVER_CAP`, untrusted evidence, and V-02 | §5.2; verdict spec §4 | PP-008 |

**Schema evidence now:** `execution-profile--missing-memory-limit.json` is rejected.
The VM ceiling is 7.75 GiB (`environment.lock.md` §4.4); one comparison needs about
1.5 GiB.

### AC-6 A stale approval or changed image makes a noncomparable run appear valid

**Boundaries:** TB-3, TB-8 · **STRIDE:** Tampering, Repudiation · **Invariants:** INV-04, INV-10

| Planned mitigation | Spec | Evidence issue |
|---|---|---|
| Approval binds pack tree hash, manifest hash, exact collection, verifier image ID, plugin version, and profile hash | §7.5; `approval-record.schema.json` | **PP-002 (schema)**, PP-007 |
| Image identity is a content digest only; tags such as `:latest` cannot be represented | schema `imageId` | **PP-002 (schema)** |
| Same target image for both sides; differing dependency contract leads to `BLOCKED` | ADR-005, §10.4 | PP-007, PP-008 |
| Approvals are immutable; replacement uses `supersedes`; no silent reapproval | §7.5 | PP-007 |
| Pre-execution drift leads to V-01 `BLOCKED`; post-start drift leads to V-02 `INCONCLUSIVE` | verdict spec D5 | PP-004 |

**Schema evidence now:** `execution-profile--floating-image-tag.json`,
`approval-record--abbreviated-hash.json`, and
`approval-record--auto-approved-field.json` are rejected.

**Residual:** approval is workflow accountability, not proof of a separate reviewer
(`reviewer.basis: local-assertion-unverified`). The same OS account can edit every file
(ADR-007).

### AC-7 Cancellation or a crash leaves containers running or evidence half-written

**Boundaries:** TB-3, TB-5 · **STRIDE:** Denial of service, Repudiation · **Invariants:** INV-11, INV-14

| Planned mitigation | Spec | Evidence issue |
|---|---|---|
| Every owned container is labeled with installation ID, run ID, and repetition | §10.6 | PP-008 |
| Reconciliation removes only exact recorded IDs whose labels match; never `docker system prune` or bulk removal | §5.4, §10.6 | PP-014; must preserve A8 |
| Evidence is written to staging and finalized atomically; interruptions produce a structured incomplete record | §12.2 | PP-009 |
| Restart never converts a partial run into success; there is no automatic retry | §8.2, §10.6 | PP-011, PP-014 |
| A stream missing `session_end` leaves the whole side untrusted | verdict spec §4, D3 | PP-004, PP-008 |

### AC-8 A coding agent changes the verification expectations to make its own patch appear successful

**Boundary:** TB-8 · **STRIDE:** Tampering, Elevation · **Invariants:** INV-04, INV-10

| Planned mitigation | Spec | Evidence issue |
|---|---|---|
| Pack and expected-verdict table are review-controlled inputs. Any byte change invalidates approval. | §7.5; CLAUDE.md | PP-007 |
| Approval is interactive and terminal-only; no `--yes`, environment variable, or caller-supplied reviewer can approve | §13.1 | PP-007, PP-009 |
| A security test's candidate expectation can only be `SECURE`, so an agent cannot relabel a remaining violation as expected | pack schema | **PP-002 (schema)** |
| Diffs to tests, test config, lockfiles, and verification files are flagged as review cues | §9.3 | PP-020 |
| The v1.1 MCP interface (optional) is read-only; no approve, run, or modify tools | §15.6 | PP-102 |

**Schema evidence now:** `pack-manifest--security-test-expects-pass.json` and
`pack-manifest--functional-test-expects-secure.json` are rejected.

**Residual:** `CLAUDE.md` is instructions, not an OS sandbox (§23.1). Agent permissions
must be configured and verified separately. The PP-002 session itself ran with Claude
Code's bypass-permissions mode active, which §23.1 advises against on the personal Mac.
**Recorded for owner review.**

## 6. Cross-cutting host-specific threats (measured in PP-001)

| Finding | Threat | Control |
|---|---|---|
| `~/.git` makes the home directory a Git worktree (`environment.lock.md` §6.1) | A Git write with the wrong root stages credentials | Confirm `git rev-parse --show-toplevel` before any Git write; proposed for PP-005: refuse registration of a path whose toplevel is `$HOME`. Owner decision on removing `~/.git` is pending. |
| Global `filter.lfs.*` with `required=true`; `gh` credential helper | Inherited Git config transforms blob bytes or exposes credentials | PP-005 wrapper sanitizes the environment and overrides config explicitly |
| Docker CVE-2025-9074 (fixed in 4.44.3) let containers reach the Engine API without the socket | INV-02 bypassed at the runtime layer | Resolved by the upgrade to 4.94.0; re-check advisories at every release gate |
| No daemon-wide user-namespace remapping | Container root equals VM root | Non-root `--user` per container, tested in PP-003 |
| Unrelated deliberately vulnerable image `bkimminich/juice-shop` present | Confusion with an approved target | Profiles reference image IDs only; juice-shop is not an approved profile |

## 7. Invariant coverage

| Invariant | Abuse cases | First evidence |
|---|---|---|
| INV-01 no target on host | AC-2 | PP-003, PP-008 |
| INV-02 no socket, credentials, repo, or home mount | AC-2, §6 | PP-003 |
| INV-03 no internet, no published port | TB-9 | PP-003 |
| INV-04 identical pack bytes on both sides | AC-1, AC-6, AC-8 | PP-007 |
| INV-05 semantic witness required | AC-1 | PP-002 schema, PP-007 |
| INV-06 baseline reproduction required | AC-1 | PP-002 schema (`contains`), PP-004 (V-08) |
| INV-07 incomplete never verifies | AC-1, AC-7 | PP-004 (T1–T5, V-05) |
| INV-08 legitimate behavior on both sides | AC-1 | PP-002 schema, PP-004 (V-04) |
| INV-09 target output has no verdict authority | AC-1, AC-4 | PP-002 schema (`provenance`), PP-004 input type |
| INV-10 approvals bind hashes | AC-6, AC-8 | PP-002 schema, PP-007 |
| INV-11 failures preserved, no rerun-until-green | AC-7 | PP-004 (D2), PP-019 |
| INV-12 report describes exactly what ran | AC-4 | PP-009, PP-021 |
| INV-13 original repo unchanged | AC-2 | PP-005 |
| INV-14 local, explicit, cancelable | AC-3, AC-5, AC-7 | PP-012, PP-014 |
| INV-15 safe exports by default | AC-4 | PP-024 |
| INV-16 no arbitrary path, command, flag, or executable via web | AC-2, AC-3 | PP-002 schema (profile closed), PP-012 |

"PP-002 schema" means a data-shape control exists and is tested by rejection examples.
It is not evidence that runtime code enforces it; that comes from the named later issue.
