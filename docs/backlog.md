# Implementation backlog

Source of truth for scope: `PROJECT_SPEC.md` Section 16. This file tracks state.

**Rules (PROJECT_SPEC.md §16):** one issue at a time; every issue requires
implementation evidence, relevant tests, updated documentation, and a `STATUS.md`
entry. A release gate is not complete because its files exist.

**Statuses (§20.3):** `NOT_STARTED` · `IN_PROGRESS` · `BLOCKED` · `READY_FOR_REVIEW`
· `ACCEPTED`. Only Ali's recorded review sets `ACCEPTED`.

---

## v0.0 — Foundation and execution boundaries

**Release status: `ACCEPTED` by owner, 2026-10-12.** Covers the v0.0 foundation only;
gate checklist `docs/evidence/v0.0-release-gate.md`. Next planned: v0.1 / PP-005, not
started.

| Issue | Work package | Completion evidence required | Status |
|---|---|---|---|
| PP-001 | Read-only host preflight and project tracking | Actual environment report, approved/unapproved actions, initialized status/backlog | `ACCEPTED` (2026-10-11) |
| PP-002 | Threat model, ADRs, schemas, and verdict specification | Reviewed trust boundaries and machine-validated example records | `ACCEPTED` (2026-10-11, commit `682ef63`) |
| PP-003 | Harmless container isolation probe suite | Saved results for files, network, namespaces, privileges, and resource controls | `ACCEPTED` (2026-10-12, commit `e38d0d1`; run `run-5c176591…`: 82/82 passed; 757 unit tests; evidence `docs/evidence/pp-003-isolation-probes.md`) |
| PP-004 | Pure verdict engine and initial negative tests | Truth-table tests; no Docker dependency for unit tests | `ACCEPTED` (2026-10-12, commit `37ec588`; 26/26 scenarios exact; 6923 Docker-free tests) |
| v0.0-CLOSEOUT | C1 packaging · C2 read-only `patchproof doctor` · C3 `doctor --probe-isolation` integration · C4 demonstration and gate review | Pinned interpreter and lockfile; suite reproduced under the pin; Docker-free doctor and wrapper tests; C4: one approved live run and the owner's §15.1 review | `ACCEPTED` (2026-10-12; C1–C3 commit `62887bf`; C4 run `run-883e1a62…` 82/82; evidence commit `d1bcbfc`; 7008 Docker-free tests) |

PP-002 accepted by owner on 2026-10-11, including decisions D1–D6, ADR-008, ADR-009 and the
reviewed scenarios. Accepted at commit `682ef63039df72ecdb3de13d2861c4dea8cda9fd`, where
`tests/unit/test_schemas.py` gave 201 passed, 0 failed, 0 skipped.

PP-002 evidence: `docs/threat-model.md`, `docs/architecture/verdict-specification.md`,
`docs/adr/`, `schemas/`, `tests/unit/test_schemas.py`. PP-004 must implement decision
table V-01–V-10, input validation M1–M7/G1–G5, per-execution result-cap enforcement (D6), and
properties P-1–P-9 from the verdict specification, and reproduce all 26 expected verdicts in
`schemas/examples/scenarios/`. PP-007 owes Pydantic/JSON Schema parity tests (ADR-008); PP-008
owes safe encoding of target-derived event content (D6) and code-level resource ceilings (ADR-009).

PP-003's runtime blocker is cleared. Docker Desktop was upgraded 4.42.1 → 4.94.0
(server 29.8.2) on 2026-10-11, so the CVE-2025-9074 exposure that bypassed INV-02 at
the runtime layer is patched and §5.1's supported-release requirement is met. See
`docs/environment.lock.md` §6.5.

PP-003 progress, 2026-10-11:

- **A0** (runner, 77-probe catalogue, in-container script, interpretation, evidence
  schema, Docker-free tests) is `READY_FOR_REVIEW`. 559 unit tests pass, and 23
  deliberate weakenings were all caught. Evidence: `STATUS.md` "PP-003 phase A0" and
  `docs/architecture/isolation-probes.md`.
- **A1** (image pulled), **A2** (identity `sha256:70729b46…c2f` approved in code), and
  **A3** (evidence directory created) are done. **A4**: run 1 BLOCKED (inspect
  representation), run 2 ISOLATION_FAILED (NET-01, FS-05), run 3
  ALL_PLANNED_PROBES_PASSED (82 of 82, independently verified). All three are preserved.
- Execution-profile contract 1.1 (`execution-profile.v1.1.schema.json`, explicit `/scratch`
  and `/tmp` sizes) sits beside the unchanged 1.0 contract. PP-007 and PP-008 consume 1.1;
  the runner refuses 1.0 profiles as unsupported.
- A 20-minute global execution deadline and a 2-minute cleanup window bound A4.
- Completion evidence: `docs/evidence/pp-003-isolation-probes.md` and `.json`
  (sanitized). **Accepted by owner 2026-10-12**, for PP-003 only; the v0.0 gate is not passed.
- Follow-ups carried forward, outside PP-003:
  - integrate the runner into `patchproof doctor --probe-isolation` before v0.0
    acceptance: done in v0.0-CLOSEOUT C3 (accepted 2026-10-12);
  - persist sleeper stdout in future runs;
  - review runtime versions and advisories at each release gate, re-probing after
    upgrades;
  - PP-004 verdict engine: **accepted 2026-10-12** (commit `37ec588`). It carries
    PP-007/PP-008 integration obligations; see `STATUS.md`.

## v0.1 — Verification core (useful CLI)

| Issue | Work package | Completion evidence required | Status |
|---|---|---|---|
| PP-005 | Safe repository registration and source snapshots | No original-repo mutation; path/ref/size rejection tests | `ACCEPTED` (2026-10-12, commit `c8128a7`; 7337 Docker-free tests; mutation check 33/34, M11 equivalent; Git 2.56.0; evidence `STATUS.md` PP-005, `docs/architecture/source-snapshots.md`) |
| PP-006 | Reference authorization API and fixture profile | Stable vulnerable/correct/inadequate/deny-all revisions and documented ground truth | `ACCEPTED` (2026-10-12, commit `4b8f288`; 7439 Docker-free tests; mutation check 19/19; tags `authz-r1`..`r4` at commits `68b2bc0`, `38f1787`, `2fb6d09`, `f31cb4b`; not executed; evidence `STATUS.md` PP-006, `docs/architecture/papertrail-reference.md`) |
| PP-007 | Pack validation, collection, and approval records | Exact test IDs and hashes; stale approval rejection; PaperTrail pack for AUTH-001–004/FUNC-001–004 bound to the fixture hash | `ACCEPTED` for the implementation (2026-10-12, commit `698e78d`; pack NOT approved; Pydantic 2.13.5 approved; 7964 Docker-free tests; final mutation 34/35 (M26 equivalent, exhaustively shown); parity 160/160 corpus and 223,815 mutations; no pack approved; real collection pending PP-008; evidence `STATUS.md` PP-007, `docs/architecture/packs-and-approvals.md`) |
| PP-008 | Target/verifier runner and typed event transport | Source/test separation; successful and deliberately interrupted runs; every owned container labelled with installation ID and run ID; first dynamic reproduction of the PaperTrail declared expectations (uvicorn version and image IDs still unresolved) | `IN_PROGRESS` (2026-10-13: gate A complete, 8145 tests, mutation 30/31 with 1 equivalent; gate B COMPLETE (r2 images target `98548ec4…`, verifier `e880f609…`, statically verified; r1 kept and rejected); gate C collection/protocol validation completed with a documented C1b exception (C1a PASS; C1b FAIL from an erroneous auxiliary assertion, owner-adjudicated ACCEPTED_FOR_C2_PROGRESSION; C2 PaperTrail collection PASS, 8/8 in manifest order; 3 of 3 containers used, all removed); approval readiness review done 2026-10-13; profile and approval-infrastructure blockers resolved 2026-10-13 (versioned profile `profiles/papertrail-reference-1.0.0.json` `a1c130c2…`, strict loader, profile/runtime equality, owner-operated `patchproof.pack_approval`; 8246 tests); local pre-approval checkpoint commit 2026-10-13 (8248 tests; not pushed; not acceptance); owner approved the pack (`apr-f30bd943…`) with the phrase as rationale and scope; owner-operated supersession workflow added for the correction (local checkpoint commit; not executed); no live comparison; evidence `STATUS.md` PP-008, `docs/architecture/verification-runs.md`, `docs/architecture/run-images.md`) |
| PP-009 | CLI workflow and JSON/Markdown evidence | Reproducible documented comparison from input to verdict | `NOT_STARTED` |
| PP-010 | Core acceptance demo and tag | Owner-reviewed v0.1 gate report | `NOT_STARTED` |

PP-005 carries a hard requirement from PP-001: the Git subprocess wrapper must run
with a sanitized environment and explicit config overrides. The host has global
`filter.lfs.*` hooks with `filter.lfs.required=true`, so inherited configuration is
not safe to trust. See `docs/environment.lock.md` §5.

PP-005 prerequisites, 2026-10-12:
- Git was upgraded to 2.56.0 (approval item 3, `docs/environment.lock.md` §3.2).
- `~/.git` is retained by owner decision (item 4). The hazard remains, and registration
  refuses the home directory and parent-repository discovery.
- The sanitized-environment requirement is implemented in `src/patchproof/git/command.py`.

## v0.2 — Usable local workbench

| Issue | Work package | Completion evidence required | Status |
|---|---|---|---|
| PP-011 | SQLite models, migrations, durable queue | Atomic claims, idempotency, bounded writes, crash tests | `NOT_STARTED` |
| PP-012 | FastAPI session/origin/CSRF and resource APIs | Unauthorized local-browser request tests fail safely | `NOT_STARTED` |
| PP-013 | React project/case/plan/result views | Accessible end-to-end UI tests and actual screenshots | `NOT_STARTED` |
| PP-014 | Cancellation, interruption, and resource reconciliation | Crash/restart/cancel tests; unrelated resources preserved — the 9 images and 7 stopped containers recorded in `docs/environment.lock.md` §4.3 are the baseline that must survive; reconcile force-killed PP-005 `.staging-*` snapshot leftovers | `NOT_STARTED` |
| PP-015 | Second compatible application onboarding | No core code edits; documented compatibility and truthful case outcome | `NOT_STARTED` |
| PP-016 | Offline workflow and usability review | Completed user journey and identified/fixed usability defects | `NOT_STARTED` |

The Node.js version decision (`docs/environment.lock.md` §6.4) is deferred to PP-013,
where the frontend is first built.

## v0.3 — Verification assurance

| Issue | Work package | Completion evidence required | Status |
|---|---|---|---|
| PP-017 | Path traversal case family | Positive controls and inadequate/correct/deny-all comparisons | `NOT_STARTED` |
| PP-018 | Mass-assignment case family | Unauthorized field and legitimate-update observations | `NOT_STARTED` |
| PP-019 | Repetition and fixture variation | Fresh paired state; recorded seeds; flaky result handling | `NOT_STARTED` |
| PP-020 | Test-integrity and change-review signals | Deletion/skip/configuration drift scenarios and false-positive explanations | `NOT_STARTED` |
| PP-021 | Evidence verification and safe report rendering | Tampering, truncation, HTML/ANSI/path injection tests | `NOT_STARTED` |
| PP-022 | Corpus evaluation and v0.3 gate | Per-scenario expected/actual classification, not invented aggregate accuracy | `NOT_STARTED` |

## v1.0 — Portfolio release (main finish line)

| Issue | Work package | Completion evidence required | Status |
|---|---|---|---|
| PP-023 | Clean install and packaged local release | Fresh install test, frozen versions, no runtime CDN dependencies | `NOT_STARTED` |
| PP-024 | Safe exports, bundle inspection, backup/restore | Corrupt archive, missing artifact, traversal, and recovery tests | `NOT_STARTED` |
| PP-025 | Four secure-code reviews and scoped ASVS map | Findings, fixes, retests, and justified residual risks | `NOT_STARTED` |
| PP-026 | Custom Semgrep rules and local security pipeline | Labeled rule corpus, scan versions/dates, actionable triage | `NOT_STARTED` |
| PP-027 | Measured metrics, case studies, and demo | Reproducible raw measurements and portfolio-ready materials | `NOT_STARTED` |
| PP-028 | Final acceptance and release | Section 21 checklist completed; owner-approved v1.0.0 tag | `NOT_STARTED` |

**Stop here.** §15.5: tag v1.0.0 and use the project in applications and interviews.
Optional integrations are not allowed to delay this release.

## Optional backlog — not prerequisites for the portfolio release

### v1.1 — Coding-agent companion (§15.6)

| Issue | Work package | Status |
|---|---|---|
| PP-101 | Local handoff exporter (`finding.md`, `verified-observations.json`, `constraints.md`, source-change summary) | `NOT_STARTED` |
| PP-102 | Optional read-only local MCP interface; no execution, approval, or patch-application tools | `NOT_STARTED` |
| PP-103 | Boundary tests: no automatic transmission, no model-generated verdicts | `NOT_STARTED` |

Requires separate optional-release approval. A fresh architectural review precedes
the MCP addition.

### v2.0 — Second runtime (§15.7)

| Issue | Work package | Status |
|---|---|---|
| PP-201 | Node.js HTTP application adapter | `NOT_STARTED` |
| PP-202 | Adapter conformance corpus and synthetic reference cases | `NOT_STARTED` |
| PP-203 | Dependency/build-policy review and release review | `NOT_STARTED` |

Separate decision. Identical verdict semantics required in the second runtime.
