# ADR-008 — Versioned JSON Schema contracts with a strict loader

**Status:** Proposed — awaiting owner review (PP-002)
**Date:** 2026-10-11
**Source:** §7.1, §12.2; new in PP-002

## Context
§7.1 requires strict manifests that reject unknown fields, duplicate keys, unsupported
versions, oversized values, invalid paths, and placeholders, and requires a published,
versioned JSON Schema. Records cross trust boundaries (verifier to host, evidence to
reviewer), so every consumer needs the same contract.

## Decision
- Every persisted or exchanged record has a JSON Schema (draft 2020-12) in `schemas/`,
  with `$id` `urn:patchproof:schema:<name>:<version>`. Shared bounded types live in
  `common.schema.json`.
- Every record schema is closed (`additionalProperties: false`), bounds every string
  and array, and pins `schema_version` with `const`. A new version is a new schema file;
  a v1.0 reader rejects every other version.
- Free text excludes C0 control characters and DEL, so terminal escapes cannot enter
  reviewed records.
- Loading happens in two stages. First, a strict JSON parser rejects duplicate keys and
  non-finite numbers. Then the schema is validated. Cross-field rules JSON Schema cannot
  express (uniqueness, staleness, stream completeness) live in code and are listed in
  `docs/architecture/verdict-specification.md` §9.
- Where a security rule can be expressed in the schema, it is, as a second line of
  defense behind the code. For example, `VERIFIED_FOR_CASES` with any flag set is
  schema-invalid.
- Each rejection example names the exact keyword and location it must fail on, so an
  example cannot pass by failing for an unrelated reason.
- PP-007 adds strict Pydantic v2 models. A test must show the models and the schemas
  accept and reject the same example corpus (ADR-002).

## Consequences
- Validation in PP-002 uses `jsonschema` 4.25.0 and `referencing` 0.36.2, which were
  already installed in the host Python 3.13.1. They are not yet pinned project
  dependencies. PP-004 packaging must add them to `pyproject.toml` and `uv.lock`, or
  replace them, after source verification.
- Schema bounds are sanity limits, not approvals. Reviewed limits are bound by profile
  and pack hashes (§7.5).

## Verification
`tests/unit/test_schemas.py`: schema meta-validation, valid examples, reason-pinned
rejection examples, and strict-loader tests.
