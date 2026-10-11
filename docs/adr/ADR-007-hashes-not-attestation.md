# ADR-007 — Hashes support consistency, not independent attestation

**Status:** Accepted (locked in `PROJECT_SPEC.md` §3.3; recorded here in PP-002)
**Date:** 2026-10-11
**Source:** §3.3, §7.5, §12.2

## Context
The operator controls this machine. Anyone with that account can rewrite both an
artifact and its manifest.

## Decision
SHA-256 manifests detect corruption and inconsistency relative to the manifest. They
are never described as tamper-proof, signed, or nonrepudiable. Approval records state
`reviewer.basis: local-assertion-unverified`.

## Consequences
- The schema makes the honest basis the only representable value
  (`approval-record--claims-verified-reviewer.json` is rejected).
- Reports must not use attestation language (§22).

## Verification
PP-021 tamper and truncation tests; report wording review in PP-025.
