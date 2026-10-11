# ADR-001 — Local first; no hosted service

**Status:** Accepted (locked in `PROJECT_SPEC.md` §3.3; recorded here in PP-002)
**Date:** 2026-10-11
**Source:** §3.3, §1.5

## Context
PatchProof handles private target source, raw responses, and evidence. A hosted
component would add transmission, tenancy, and account surfaces that the product does
not need.

## Decision
Every required user journey works without a hosted service. There is no telemetry, no
cloud database, and no runtime LLM. The network is used only for installation and
explicitly approved preparation (§1.5, §10.4).

## Consequences
- Verification runs must work offline once images are cached (§15.3 exit gate).
- Evidence and backups stay on the host, so host disk encryption becomes the
  operator's responsibility (§12.5).

## Verification
PP-016 (offline workflow); PP-023 (no runtime CDN dependencies).
