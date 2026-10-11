# ADR-009 — Container security policy is code, not profile data

**Status:** Proposed — awaiting owner review (PP-002)
**Date:** 2026-10-11
**Source:** §10.2, §11.2, INV-16; new in PP-002

## Context
§10.2 fixes the container security policy: non-root, read-only root filesystem, all
capabilities dropped, no-new-privileges, default seccomp, private namespaces, no socket
or host mounts, and no host environment. If any of these were a field in an execution
profile, a profile edit (by a person, an agent, or a web request) could relax it, and
the relaxation would only be caught at review.

## Decision
The execution profile schema has **no field** for container user, capabilities,
privilege, seccomp, mounts, devices, network mode, environment variables, entry
command, or raw Docker arguments. These are constants in the runner (PP-008).
A profile can choose only the following:

- image IDs;
- the ASGI entry point, restricted by a grammar;
- the fixture contract;
- source include paths;
- resource limits and timeouts, all required and bounded.

`network_policy` has exactly one representable value.

## Consequences
- Relaxing policy requires a code change and an ADR, never a configuration change
  (§22).
- `execution-profile--privileged-flag.json`, `--docker-args.json`, and
  `--bridge-network.json` are rejected by the schema.
- The runner must still inspect each created container and probe enforcement. Absence
  of a field is not proof the runtime enforced the policy (§10.2; PP-003).

## Verification
PP-002 rejection examples; PP-008 container inspection tests; Semgrep rule 2 in PP-026.
