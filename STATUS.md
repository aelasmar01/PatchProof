# STATUS

**Updated:** 2026-10-11 (Docker compatibility check completed)
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

2. **Installed Docker Desktop 4.42.1 is unsupported and carries an on-path critical
   container-escape CVE.** Current release is 4.94.0 (2026-10-05); 4.42.1 is ~16
   months old, past Docker's 6-month download and support windows, and predates
   macOS 26. **CVE-2025-9074 (CVSS 9.3, fixed in 4.44.3)** lets a running Linux
   container reach the Docker Engine API unauthenticated and escape to the host, with
   a public proof-of-concept. That bypasses **INV-02** at the runtime layer:
   PatchProof enforces "no Docker socket in a container" by configuration, which the
   CVE routes around. Eleven further advisories post-date 4.42.1.

   macOS 26.3.1 and Intel are both fine — Docker supports the current plus two
   previous macOS majors and still ships an Intel build for 4.94.0. The version is
   the sole problem. See `docs/environment.lock.md` §6.5.

3. **Docker daemon not running; no isolation property measured.** Invariants
   INV-01 through INV-03 are unverified on this host. The §15.1 exit gate requires a
   recorded tested result for each runtime restriction; none exist. v0.0 cannot pass
   on this report alone.

   The daemon must **not** be started on 4.42.1: isolation evidence gathered on a
   runtime with a known-broken escape boundary would be invalid for §15.1.

4. **Git 2.42.0 is roughly three years old** (installed 2023-09-06; current stable
   2.56.0). §9.2 requires a supported patched release, and the snapshot path depends
   directly on Git object reading. Oldest-risk component measured.

5. **Python 3.13.1 is behind on patches.** Pin an approved 3.13.x before generating
   `uv.lock`, so the lockfile is produced once against an approved interpreter.

## Changes requiring owner approval

In the order they block work:

| # | Approval needed | Unblocks |
|---|---|---|
| 1 | **Upgrade Docker Desktop 4.42.1 → 4.94.0 (Intel build).** Unsupported release; CVE-2025-9074 breaks INV-02 at the runtime layer | PP-003 and all container execution |
| 2 | `brew upgrade git` (2.42.0 → current 2.56.0) | PP-005 |
| 3 | Decide whether to remove `/Users/aliel-asmar/.git` (nothing is tracked; recommend backing up its config first) | Safe local Git hygiene |
| 4 | Install current Python 3.13.x and pin it | PP-004 packaging |
| 5 | Start the Docker daemon and run the PP-003 isolation probe suite — **only after item 1** | v0.0 exit gate |

The Docker/macOS compatibility check that was previously listed here as agent work is
**complete** (2026-10-11). Its outcome became item 1.

## Is the current release safe to demonstrate?

**No.** There is nothing to demonstrate. No code, no fixtures, no verdict engine, and
no measured isolation. The §15.1 demo requires a live file-read isolation check, a
blocked external connection, and a refused invalid policy — none are implemented.

Per §15.1, a design document alone does not pass this gate.

## Honest claim status

Nothing in this repository may yet be described as a working capability. Every
benchmark, accuracy figure, and isolation guarantee in `PROJECT_SPEC.md` is a plan.
No measurement in §19.1 has been taken.
