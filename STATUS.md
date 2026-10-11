# STATUS

**Updated:** 2026-10-11 (Docker Desktop upgraded to 4.94.0; runtime blocker cleared)
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
| 1 | Run the PP-003 isolation probe suite (harmless probes only; no target code) | v0.0 exit gate |
| 2 | `brew upgrade git` (2.42.0 → 2.56.0) | PP-005 |
| 3 | Decide whether to remove `/Users/aliel-asmar/.git` (nothing is tracked; recommend backing up its config first) | Safe local Git hygiene |
| 4 | Install current Python 3.13.x and pin it | PP-004 packaging |

**Cleared 2026-10-11:** Docker Desktop upgraded 4.42.1 → 4.94.0 (server 29.8.2). The
runtime now meets §5.1 and all advisories listed in `docs/environment.lock.md` §6.5
are patched. Note Docker Desktop on this host is **not** Homebrew-managed; use the
in-app updater or the Intel `.dmg`.

## Is the current release safe to demonstrate?

**No.** There is nothing to demonstrate. No code, no fixtures, no verdict engine, and
no measured isolation. The §15.1 demo requires a live file-read isolation check, a
blocked external connection, and a refused invalid policy — none are implemented.

Per §15.1, a design document alone does not pass this gate.

## Honest claim status

Nothing in this repository may yet be described as a working capability. Every
benchmark, accuracy figure, and isolation guarantee in `PROJECT_SPEC.md` is a plan.
No measurement in §19.1 has been taken.
