# STATUS

**Updated:** 2026-10-11
**Specification:** `PROJECT_SPEC.md` v1.0

---

## Current release and issue

**Release:** v0.0 — Foundation and execution boundaries
**Issue:** PP-001 — Read-only host preflight and project tracking
**State:** `READY_FOR_REVIEW`

PP-001 performed a read-only preflight of the host and initialized project tracking.
No software was installed, no daemon started, no container run, no `sudo` invoked, and
no VM setting changed.

## Last completed gate and its evidence

**None.** No gate has been accepted. This is the first issue of the first release.

PP-001 evidence: `docs/environment.lock.md` — measured host facts with the exact
command used for each value, plus the conflicts found against the specification.

## Next permitted issue

PP-002 — Threat model, ADRs, schemas, and verdict specification.

PP-002 is documentation and schema work with no host dependency, so it can proceed
once PP-001 is reviewed. **PP-003 cannot proceed** until the Docker approvals below
are granted; it is the real v0.0 blocker.

## Failed tests, risks, and blockers

No test suite exists yet. Nothing was executed, so nothing failed. There is no
`pyproject.toml`, no `uv.lock`, and no source tree.

**Blockers and risks, highest first:**

1. **A second Git repository owns the home directory.** `/Users/aliel-asmar/.git`
   exists with 0 tracked files and remotes pointing at unrelated projects. Every
   file in `~` — including `.ssh/`, `.aws/`, `.config/` — reports as untracked
   there, so `git add -A` with that worktree root would stage private credentials.
   This project now shadows it and is contained; the home repository is untouched.
   See `docs/environment.lock.md` §6.1.

2. **Docker daemon not running; no isolation property measured.** Invariants
   INV-01 through INV-03 are unverified on this host. The §15.1 exit gate requires a
   recorded tested result for each runtime restriction; none exist. v0.0 cannot pass
   on this report alone.

3. **Docker Desktop 4.42.1 vs macOS 26.3.1 compatibility is unverified.** §5.1
   requires a currently supported Intel release matched to the actual macOS. Not
   confirmed, and §5.1 forbids a silent fallback to an untested backend.

4. **Git 2.42.0 is roughly three years old** (installed 2023-09-06; current stable
   2.56.0). §9.2 requires a supported patched release, and the snapshot path depends
   directly on Git object reading. Oldest-risk component measured.

5. **Python 3.13.1 is behind on patches.** Pin an approved 3.13.x before generating
   `uv.lock`, so the lockfile is produced once against an approved interpreter.

## Changes requiring owner approval

In the order they block work:

| # | Approval needed | Unblocks |
|---|---|---|
| 1 | Decide whether to remove `/Users/aliel-asmar/.git` (nothing is tracked; recommend backing up its config first) | Safe local Git hygiene |
| 2 | `brew upgrade git` (2.42.0 → current) | PP-005 |
| 3 | Install current Python 3.13.x and pin it | PP-004 packaging |
| 4 | Any Docker Desktop upgrade, after compatibility is checked | PP-003 |
| 5 | Start the Docker daemon and run the PP-003 isolation probe suite | v0.0 exit gate |

Item 4's compatibility check is agent work and needs no approval; only the resulting
upgrade does.

## Is the current release safe to demonstrate?

**No.** There is nothing to demonstrate. No code, no fixtures, no verdict engine, and
no measured isolation. The §15.1 demo requires a live file-read isolation check, a
blocked external connection, and a refused invalid policy — none are implemented.

Per §15.1, a design document alone does not pass this gate.

## Honest claim status

Nothing in this repository may yet be described as a working capability. Every
benchmark, accuracy figure, and isolation guarantee in `PROJECT_SPEC.md` is a plan.
No measurement in §19.1 has been taken.
