# ADR-003 — Independent verifier process

**Status:** Accepted (locked in `PROJECT_SPEC.md` §3.3; recorded here in PP-002)
**Date:** 2026-10-11
**Source:** §3.3, §7.4, §10

## Context
If target code were imported into the pytest interpreter, it could monkeypatch the
helpers, the plugin, or the reporter that produce the result.

## Decision
Target code runs only in the target container. The verifier is a separate container
running an approved image and pack. It tests behavior across HTTP over a shared
loopback namespace and never receives target source.

## Consequences
- Supported targets are limited to HTTP applications under the approved ASGI profile
  (§1.3).
- Observations come from a structured verifier event stream. Target output is labeled
  untrusted data (INV-09; `verifier-event.schema.json`, `observation.schema.json`).

## Verification
PP-003 boundary probes (the target cannot see verifier files); PP-008 source/test
separation tests.
