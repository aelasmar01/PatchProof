# ADR-002 — Shared core; no CLI/web duplication

**Status:** Accepted (locked in `PROJECT_SPEC.md` §3.3; recorded here in PP-002)
**Date:** 2026-10-11
**Source:** §3.3, §3.2

## Context
If the CLI and the browser validated or judged differently, the same evidence could
yield two verdicts.

## Decision
Validation, plan resolution, verdict evaluation, and evidence serialization live in one
core package, `src/patchproof/core`. The CLI and API are thin clients over it.

## Consequences
- The schemas in `schemas/` and the strict Pydantic models introduced in PP-007 must
  describe the same contract, and a test must check the two against each other.
- The verdict engine has a single implementation (PP-004).

## Verification
PP-009 and PP-012 call the same services; PP-021 recomputes verdicts from evidence
through the same engine.
