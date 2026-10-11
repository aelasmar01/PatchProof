# ADR-006 — No remote model adjudication

**Status:** Accepted (locked in `PROJECT_SPEC.md` §3.3; recorded here in PP-002)
**Date:** 2026-10-11
**Source:** §3.3, §1.5

## Context
A language model's narrative is not an execution observation, and it can be steered by
target content.

## Decision
No model produces, influences, or approves a verdict, an observation, or an approval.
The verdict engine's inputs are typed observations and precondition results only.

## Consequences
- The optional v1.1 handoff and MCP interfaces are read-only and export reviewed data
  only (§15.6).
- Agent-authored packs still require human approval (threat model AC-8).

## Verification
PP-004 input type; PP-103 boundary tests (optional release).
