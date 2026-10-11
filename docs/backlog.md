# Implementation backlog

Source of truth for scope: `PROJECT_SPEC.md` Section 16. This file tracks state.

**Rules (PROJECT_SPEC.md §16):** one issue at a time; every issue requires
implementation evidence, relevant tests, updated documentation, and a `STATUS.md`
entry. A release gate is not complete because its files exist.

**Statuses (§20.3):** `NOT_STARTED` · `IN_PROGRESS` · `BLOCKED` · `READY_FOR_REVIEW`
· `ACCEPTED`. Only Ali's recorded review sets `ACCEPTED`.

---

## v0.0 — Foundation and execution boundaries

| Issue | Work package | Completion evidence required | Status |
|---|---|---|---|
| PP-001 | Read-only host preflight and project tracking | Actual environment report, approved/unapproved actions, initialized status/backlog | `READY_FOR_REVIEW` |
| PP-002 | Threat model, ADRs, schemas, and verdict specification | Reviewed trust boundaries and machine-validated example records | `NOT_STARTED` |
| PP-003 | Harmless container isolation probe suite | Saved results for files, network, namespaces, privileges, and resource controls | `NOT_STARTED` |
| PP-004 | Pure verdict engine and initial negative tests | Truth-table tests; no Docker dependency for unit tests | `NOT_STARTED` |

PP-003's runtime blocker is cleared. Docker Desktop was upgraded 4.42.1 → 4.94.0
(server 29.8.2) on 2026-10-11, so the CVE-2025-9074 exposure that bypassed INV-02 at
the runtime layer is patched and §5.1's supported-release requirement is met. PP-003
is `NOT_STARTED` and needs only owner approval to run. See
`docs/environment.lock.md` §6.5.

## v0.1 — Verification core (useful CLI)

| Issue | Work package | Completion evidence required | Status |
|---|---|---|---|
| PP-005 | Safe repository registration and source snapshots | No original-repo mutation; path/ref/size rejection tests | `NOT_STARTED` |
| PP-006 | Reference authorization API and fixture profile | Stable vulnerable/correct/inadequate/deny-all revisions and documented ground truth | `NOT_STARTED` |
| PP-007 | Pack validation, collection, and approval records | Exact test IDs and hashes; stale approval rejection | `NOT_STARTED` |
| PP-008 | Target/verifier runner and typed event transport | Source/test separation; successful and deliberately interrupted runs; every owned container labelled with installation ID and run ID | `NOT_STARTED` |
| PP-009 | CLI workflow and JSON/Markdown evidence | Reproducible documented comparison from input to verdict | `NOT_STARTED` |
| PP-010 | Core acceptance demo and tag | Owner-reviewed v0.1 gate report | `NOT_STARTED` |

PP-005 carries a hard requirement from PP-001: the Git subprocess wrapper must run
with a sanitized environment and explicit config overrides. The host has global
`filter.lfs.*` hooks with `filter.lfs.required=true`, so inherited configuration is
not safe to trust. See `docs/environment.lock.md` §5.

## v0.2 — Usable local workbench

| Issue | Work package | Completion evidence required | Status |
|---|---|---|---|
| PP-011 | SQLite models, migrations, durable queue | Atomic claims, idempotency, bounded writes, crash tests | `NOT_STARTED` |
| PP-012 | FastAPI session/origin/CSRF and resource APIs | Unauthorized local-browser request tests fail safely | `NOT_STARTED` |
| PP-013 | React project/case/plan/result views | Accessible end-to-end UI tests and actual screenshots | `NOT_STARTED` |
| PP-014 | Cancellation, interruption, and resource reconciliation | Crash/restart/cancel tests; unrelated resources preserved — the 9 images and 7 stopped containers recorded in `docs/environment.lock.md` §4.3 are the baseline that must survive | `NOT_STARTED` |
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
