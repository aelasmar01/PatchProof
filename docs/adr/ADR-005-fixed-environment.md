# ADR-005 — Fixed environment for code-fix comparisons

**Status:** Accepted (locked in `PROJECT_SPEC.md` §3.3; recorded here in PP-002)
**Date:** 2026-10-11
**Source:** §3.3, §10.4

## Context
If baseline and candidate ran on different dependency sets, a verdict could reflect the
environment rather than the code change.

## Decision
Baseline and candidate use the same approved target image, identified by its content
digest. A dependency or infrastructure change is a different kind of comparison and is
out of scope until after v1.0.

## Consequences
- An execution profile carries image IDs only; tags cannot be represented
  (`common.imageId`).
- A differing dependency contract makes the comparison `BLOCKED` as noncomparable
  (verdict spec V-01/V-02, D5).

## Verification
PP-007/PP-008 identity checks; §17.3 scenario 9 in PP-022.
