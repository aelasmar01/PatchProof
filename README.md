# PatchProof

**Local application security fix verification workbench.**

Compare a vulnerable application revision with a proposed fix, run the same
human-reviewed security checks against each in separate disposable environments, and
preserve evidence of what was — and was not — demonstrated.

> **Project status: v0.0 foundation, release gate awaiting owner review.** This repository
> contains:
> - the specification, threat model, and verdict specification;
> - versioned record schemas;
> - a pure verdict engine that reproduces 26 reviewed scenarios;
> - a container isolation probe suite;
> - the `patchproof doctor` command.
>
> The suite has recorded all 82 planned checks as passing twice on Docker Desktop 4.94.0
> (`docs/evidence/`). That is evidence for one runtime and date, not an escape-proof
> guarantee. PatchProof cannot yet compare revisions; everything in the Roadmap below is
> planned, not achieved.

---

## The problem

A developer changes code to address a security finding. A passing test suite or a
plausible explanation does not establish that the particular vulnerability was
reproduced, corrected, and prevented from recurring without breaking legitimate
behavior.

PatchProof keeps those questions separate:

1. Did the selected original revision exhibit the reported security failure?
2. Does the proposed revision enforce the reviewed security expectation?
3. Does legitimate behavior still work?
4. Did the verification environment actually run the expected checks?
5. Can another reviewer inspect the evidence and repeat the assessment?

The engineering contribution is **trustworthy interpretation of before-and-after
evidence** — not scanner aggregation or automatic vulnerability discovery.

## What a verdict means

A verified result is reported as **"Verified for the selected cases"**, always
followed by the test count and repetition count. It does not mean the application is
secure, that the patch has no bypasses, or that an arbitrary hostile repository is
safe to execute.

Two guarantees shape the design:

- A passing candidate alone is never a verified fix. The baseline must first
  reproduce the intended failure.
- A missing, skipped, crashed, or timed-out required check can never contribute to a
  verified verdict.

## Implemented

| Capability | State |
|---|---|
| Measured host environment report | Done — `docs/environment.lock.md` |
| Project specification | Done — `PROJECT_SPEC.md` |
| Agent working agreement | Done — `CLAUDE.md` |
| Issue tracking | Done — `STATUS.md`, `docs/backlog.md` |
| Threat model and verdict specification | Accepted (PP-002) — `docs/threat-model.md`, `docs/architecture/verdict-specification.md` |
| Record schemas with validated examples | Accepted (PP-002) — `schemas/`, `tests/unit/test_schemas.py` |
| Container isolation probe suite (PP-003) | Accepted. On Docker Desktop 4.94.0 / Engine 29.8.2, 82 of 82 probes passed in run 3 and again in the v0.0 C4 demonstration. Runs 1 and 2 failed and are documented — `src/patchproof/`, `containers/probes/`, `docs/architecture/isolation-probes.md`, `docs/evidence/pp-003-isolation-probes.md`, `docs/evidence/v0.0-c4-isolation-demonstration.md` |
| Pure verdict engine (PP-004) | Accepted. Reproduces all 26 reviewed scenarios — `src/patchproof/core/`, `docs/architecture/verdict-specification.md` |
| `patchproof doctor` / `doctor --probe-isolation` | v0.0 closeout. A read-only environment report, and an interactive, separately authorized run of the isolation probe suite — `src/patchproof/doctor/`, `src/patchproof/cli/` |

Nothing else. No API, no verification runner, and no comparison of revisions yet.

## Roadmap

Planned releases, in order. Each must leave a runnable tagged product or a documented
foundation gate.

| Release | Goal |
|---|---|
| v0.0 | Verify the host, establish threat boundaries, freeze schemas, demonstrate isolation with harmless probes |
| v0.1 | CLI compares two committed revisions with one approved verification pack; JSON and Markdown evidence |
| v0.2 | Local web workbench: register a repository, manage cases, run and cancel comparisons, inspect results |
| v0.3 | Verification assurance: more security families, repeated runs, test-integrity checks, negative testing of the verifier itself |
| **v1.0** | **Portfolio release** — reproducible install, safe exports, tested backup/restore, AppSec assessment, measured evidence |
| v1.1 | Optional: reviewed context handoff for coding agents |
| v2.0 | Optional: a second runtime adapter (Node.js HTTP) |

## Scope boundaries

**Not goals:** cloud deployment, hosted backend, telemetry, runtime LLM, automatic
patch generation, internet target scanning, Kubernetes, or required hosted CI.

**No claim of safe execution of arbitrary malicious repositories.** The operator must
approve a repository before it runs. PatchProof does not automatically execute
uploaded archives, unreviewed verification packs, repository Dockerfiles, dependency
build scripts, or arbitrary shell commands.

**Internet use:** installation, approved dependency and image preparation, and
optional security database refreshes may require network access. Once dependencies
and images are cached, core operation and verification runs must work offline.

## Target compatibility

The initial target is an owner-approved, locally available Git repository containing a
Python HTTP application that runs under the approved ASGI/Uvicorn profile with
synthetic fixtures and no required external services. FastAPI and Starlette are the
first compatibility target.

The verifier uses pytest and HTTPX and **does not import the target application into
the verifier process** — target code runs in a separate container and is tested across
an HTTP boundary.

An application that requires Redis, PostgreSQL, cloud credentials, or a proprietary
service may be unsupported. That will be stated explicitly rather than papered over
with mocks.

## Documentation

| File | Contents |
|---|---|
| `PROJECT_SPEC.md` | Full specification: architecture, trust model, invariants, iteration gates |
| `STATUS.md` | Current issue, last accepted gate, blockers, pending approvals |
| `CLAUDE.md` | Working agreement for agent-assisted implementation |
| `docs/backlog.md` | PP-001 through PP-028 and the optional backlog |
| `docs/environment.lock.md` | Measured host facts and conflicts against the specification |
| `docs/threat-model.md` | Trust boundaries, abuse cases, planned mitigations and their evidence issues |
| `docs/architecture/verdict-specification.md` | Verdict inputs, trust predicate, ordered decision table |
| `docs/adr/` | Architecture decision records |
| `schemas/` | Versioned JSON Schemas and valid/invalid example records |

## Setup

Development setup only. The pinned interpreter is CPython 3.13.16, managed by uv 0.12.24;
dependencies are locked in `uv.lock`.

```
uv sync --locked                                # create .venv from the lockfile
uv run --locked --offline patchproof doctor     # read-only environment report
uv run --locked pytest tests/unit               # Docker-free unit tests
```

Every `patchproof` command runs this way from the project directory, with absolute path arguments. A bare
`patchproof` works only where the package is installed on the shell's PATH, which v0.1 does not do. The v0.1
workflow is in `docs/architecture/cli-workflow.md`.

`patchproof doctor --probe-isolation` creates and removes probe containers. It needs the
approved probe image, a private evidence directory, and interactive confirmation; see
`STATUS.md` before running it. Release setup, the one-command reference demo, and the
command that validates its evidence arrive with v1.0 (PP-023).

## License

Apache-2.0. See `LICENSE`.
