# ADR-004 — Committed snapshots, not mutable worktrees

**Status:** Accepted (locked in `PROJECT_SPEC.md` §3.3; recorded here in PP-002)
**Date:** 2026-10-11
**Source:** §3.3, §9

## Context
Checking out revisions in the operator's repository would run hooks and filters,
touch uncommitted work, and expose `.git` metadata to containers.

## Decision
Execution consumes validated read-only snapshots built from Git objects
(`ls-tree`/`cat-file`) of resolved full commit IDs. The original repository is never
checked out, reset, cleaned, stashed, modified, or mounted. Uncommitted changes are
excluded, and the UI states this.

## Consequences
- On this host the Git wrapper must override the global `filter.lfs.*` configuration
  and avoid the `gh` credential helper (`environment.lock.md` §5).
- Symlinks, submodules, LFS pointers, and special files are rejected in v1.0 rather
  than silently omitted.

## Verification
PP-005: tests showing no original-repo mutation, plus path, ref, and size rejection
tests.
