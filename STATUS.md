# STATUS

**Updated:** 2026-10-11 (PP-002 ACCEPTED by owner; PP-003 execution plan awaiting owner approval)
**Specification:** `PROJECT_SPEC.md` v1.0

---

## Current release and issue

**Release:** v0.0 — Foundation and execution boundaries
**Issue:** PP-003 — Harmless container isolation probe suite
**State:** `NOT_STARTED`

The PP-003 execution plan was prepared through read-only inspection only. It is waiting
for owner approval. No container has been created or run, no image pulled, and no
Docker setting changed.

## Accepted issues

### PP-002 — `ACCEPTED` by owner, 2026-10-11

Accepted scope:

- the verdict specification, including owner decisions D1–D6;
- ADR-008 (strict schema contracts) and ADR-009 (container security policy as code);
- the reviewed verdict scenarios and the schema-validation requirements.

Accepted at commit `682ef63039df72ecdb3de13d2861c4dea8cda9fd`. Validation evidence at
that commit: 201 passed, 0 failed, 0 skipped, plus the weakening and invariant checks
recorded under "Failed tests, risks, and blockers".

PP-002 was documentation and data-contract work. No software was installed, no container
run, no target executed, and no network used.

PP-002 evidence:

| Artifact | Contents |
|---|---|
| `docs/threat-model.md` | Assets, trust zones, nine trust boundaries (STRIDE), the eight §4.3 abuse cases with planned mitigations and the issue owing evidence, invariant coverage |
| `docs/architecture/verdict-specification.md` | Engine inputs; pytest event grammar and lifecycle derivation; local vs global stream failures; host-confirmed execution trust E1–E4; cell trust T1–T5; input validation M1–M7/G1–G5; execution-start definition; decision table V-01–V-10; independent flags; reason/detail rules; decided D1–D6; 26-scenario truth table; properties P-1–P-9 |
| `docs/adr/ADR-001`–`ADR-007` | The §3.3 decisions, recorded |
| `docs/adr/ADR-008`, `ADR-009` | **Accepted by owner 2026-10-11**, with recorded conditions: schema contracts; container policy is code, not profile data |
| `schemas/*.schema.json` | 9 schemas: `common`, `pack-manifest`, `execution-profile`, `approval-record`, `verifier-event`, `observation`, `execution` (new), `verdict-input` (new), `verdict` |
| `schemas/examples/valid/` | 10 standalone example records |
| `schemas/examples/invalid/` | 52 rejection examples, each pinned to the keyword and location it must fail on |
| `schemas/examples/scenarios/` | 26 engine-input / expected-verdict pairs: the review-controlled truth table PP-004 must reproduce |
| `tests/unit/test_schemas.py` | Machine validation of all of the above, plus a check that the specification's scenario table matches the corpus |
| `PROJECT_SPEC.md` | Amended §5.2 (per-execution result cap enforced from the host byte count, D6), §13.2, §17.3 items 3, 6, 9, 11 |

**Owner decisions** recorded in `verdict-specification.md` §11:

- **D1–D5**, decided in the 2026-10-11 review.
- **D6**, decided in the acceptance-readiness review: a result-cap overflow invalidates
  only the affected `(pair, side)` execution. The engine enforces this from the
  host-observed byte count (scenarios S24–S26).
- **ADR-008 and ADR-009 accepted**, with conditions recorded in each ADR.

PP-002 acceptance is acceptance of that issue only. **It is not the v0.0 release gate.**

**Acceptance-readiness review (2026-10-11) also changed two things:**

- `pairs_completed` was split into `pairs_terminated_normally` (execution only) and
  `pairs_with_trusted_evidence`.
- `EXECUTION_CANCELED` was added, so every suppressed abnormal-termination code has an
  explaining code for the same execution. Raw termination facts stay in the execution
  records.

**Obligations carried forward:**

- PP-004 must implement the engine and reproduce all 26 scenarios.
- PP-007 owes Pydantic/JSON Schema parity tests (ADR-008).
- PP-008 owes safe encoding and bounding of target-derived event content (D6) and
  code-level resource ceilings (ADR-009).

## Last completed gate and its evidence

**No release gate has passed.** v0.0 is open. It needs PP-003 and PP-004 plus the §15.1
demonstration.

| Issue | Accepted | Evidence |
|---|---|---|
| PP-001 | 2026-10-11 | `docs/environment.lock.md` |
| PP-002 | 2026-10-11 | commit `682ef63`; see "Accepted issues" above |

## Next permitted issue

**PP-003**, the harmless container isolation probes, is next in backlog order. It is
permitted to start only after the owner approves its execution plan. Execution needs
explicit approval to:

- pull one pinned base image (network access);
- create, run, and remove probe containers.

PP-004, the pure verdict engine, follows. It needs a pinned Python and a
`pyproject.toml` (approval item 3). Taking PP-004 before PP-003 would need an explicit
owner decision to reorder.

## Failed tests, risks, and blockers

**Tests:** `tests/unit/test_schemas.py`: 201 passed, 0 failed, 0 skipped (2026-10-11, after
D6). Command:

```
env -u PYTEST_ADDOPTS -u PYTEST_PLUGINS -u PYTHONPATH PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  python3 -I -m pytest tests/unit -p no:cacheprovider -q
```

Earlier in remediation, one run failed because the scenario-table regex in the test
rejected uppercase directory names. I fixed the regex, not the data.

**D6 weakening checks**, run on a scratch copy outside the repository:

| Weakening | Result |
|---|---|
| S25 expected verdict reverted to global `INCONCLUSIVE` | 2 tests failed |
| S26 `RESULT_CAP_EXCEEDED` detail dropped | 1 test failed |
| `result_cap_bytes` made optional | 1 test failed |

**Independent invariant check** of all 26 scenarios against `PROJECT_SPEC.md`, using
logic separate from the evaluator:

- no false `VERIFIED_FOR_CASES`;
- no `NOT_FIXED` without a clean candidate violation;
- no trusted violation lost outside the deliberate global-failure case S21.

**Earlier weakening checks** (remediation pass, on a scratch copy outside the repository). Each deliberate weakening
must make at least one test fail:

| Weakening | Result |
|---|---|
| S04 expected verdict relabeled `INCONCLUSIVE` | 1 test failed |
| `INCONCLUSIVE` ⇒ no `candidate_violation` guard removed | 1 test failed |
| `verdict-input` `uniqueItems` removed | 1 test failed |
| `COMPLETE` ⇒ `session_end_received` guard removed | 1 test failed |
| S12 row removed from the spec table | 1 test failed |
| S12 expected verdict changed to `NOT_FIXED` | 2 tests failed |
| `PRECONDITION_NOT_EVALUATED` guard removed | 1 test failed |

All seven were caught.

**Limit of these checks:** changing an expected verdict *and* its row in the spec table
together is not detectable by tests. That is what owner review of the corpus is for.

**How the expected verdicts were produced.** A scratch reference evaluator applied the
specification literally. It was kept in the session scratchpad and is **not** committed;
it is not the PP-004 engine. Each scenario's verdict, rule, and key flags were also
specified by hand, and generation fails on any disagreement. All 26 agreed.

**Validation tooling is not pinned.** The tests use `jsonschema` 4.25.0,
`referencing` 0.36.2, and `pytest` 8.4.2. These were already installed in the host
Python 3.13.1 (`/Library/Frameworks/Python.framework/Versions/3.13`); nothing was
installed. There is still no `pyproject.toml` or `uv.lock`. PP-004 packaging must pin
these, or replace them, after source verification (ADR-008).

**Not executed:** no runtime code exists, so no schema is enforced by an application yet.
"PP-002 schema" controls in the threat model are data-shape controls only.

**Blockers and risks, highest first:**

1. **A second Git repository owns the home directory.** `/Users/aliel-asmar/.git`
   exists with 0 tracked files and remotes pointing at unrelated projects. Every
   file in `~` — including `.ssh/`, `.aws/`, `.config/` — reports as untracked
   there, so `git add -A` with that worktree root would stage private credentials.
   This project now shadows it and is contained; the home repository is untouched.
   See `docs/environment.lock.md` §6.1.

2. **No isolation property measured.** The daemon is running on the upgraded runtime
   and its configuration is recorded (`docker info`: server 29.8.2, cgroup v2,
   seccomp builtin, `null` network driver available, 16 CPUs, 7.75 GiB VM). That is
   capability, not enforcement. Invariants INV-01 through INV-03 remain
   **unverified**, because verifying them requires running containers — PP-003. The
   §15.1 exit gate requires a recorded tested result per restriction; none exist.
   v0.0 cannot pass on this report alone. PP-003 is no longer blocked by the runtime
   and needs only approval to run.

3. **Unrelated Docker resources are present and must survive.** The daemon holds 9
   images (~4.4 GiB) and 7 stopped containers from other projects, last used 7–14
   months ago. §5.4 forbids pruning or deleting unrelated resources and PP-014 must
   prove they are preserved. This is now the concrete baseline for that test. No
   PatchProof code path may call `docker system prune` or any unfiltered bulk
   removal. See `docs/environment.lock.md` §4.3.

4. **Git 2.42.0 is roughly three years old** (installed 2023-09-06; current stable
   2.56.0). §9.2 requires a supported patched release, and the snapshot path depends
   directly on Git object reading. Oldest-risk component measured.

5. **Python 3.13.1 is behind on patches.** Pin an approved 3.13.x before generating
   `uv.lock`, so the lockfile is produced once against an approved interpreter.

## Changes requiring owner approval

In the order they block work:

| # | Approval needed | Unblocks |
|---|---|---|
| 1 | Approve the PP-003 execution plan: one pinned image pull, then harmless probe containers with labeled, ID-scoped cleanup | v0.0 exit gate |
| 2 | Install current Python 3.13.x and pin it; approve pinning the validation/test dependencies | PP-004 packaging |
| 3 | `brew upgrade git` (2.42.0 → 2.56.0) | PP-005 |
| 4 | Decide whether to remove `/Users/aliel-asmar/.git` (nothing is tracked; recommend backing up its config first) | Safe local Git hygiene |
| 5 | Claude Code permissions: §23.1 advises against broad bypass mode on this Mac; PP-002 ran with it active (`docs/threat-model.md` AC-8) | Agent-boundary hygiene |

**Cleared 2026-10-11:** Docker Desktop upgraded 4.42.1 → 4.94.0 (server 29.8.2). The
runtime now meets §5.1 and all advisories listed in `docs/environment.lock.md` §6.5
are patched. Note Docker Desktop on this host is **not** Homebrew-managed; use the
in-app updater or the Intel `.dmg`.

## Is the current release safe to demonstrate?

**No.** The §15.1 demo requires a live file-read isolation check, a blocked external
connection, and a refused invalid policy. None is implemented. The schema test showing
`execution-profile--privileged-flag.json` rejected is a data-shape check, not the
runtime policy refusal the demo requires.

Per §15.1, a design document alone does not pass this gate.

## Honest claim status

Nothing in this repository may yet be described as a working capability. Every
benchmark, accuracy figure, and isolation guarantee in `PROJECT_SPEC.md` is a plan.
No measurement in §19.1 has been taken.
