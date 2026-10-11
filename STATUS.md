# STATUS

**Updated:** 2026-10-11 (PP-001 accepted by owner; PP-002 ready for review)
**Specification:** `PROJECT_SPEC.md` v1.0

---

## Current release and issue

**Release:** v0.0 — Foundation and execution boundaries
**Issue:** PP-002 — Threat model, ADRs, schemas, and verdict specification
**State:** `READY_FOR_REVIEW`

PP-002 is documentation and data-contract work. No software was installed, no
container run, no target executed, and no network used.

PP-002 evidence:

| Artifact | Contents |
|---|---|
| `docs/threat-model.md` | Assets, trust zones, nine trust boundaries (STRIDE), the eight §4.3 abuse cases with planned mitigations and the issue owing evidence, invariant coverage |
| `docs/architecture/verdict-specification.md` | Engine inputs, trust predicate, ordered decision table V-01–V-10, flags, §8.5/§17.3 mapping, properties PP-004 must test |
| `docs/adr/ADR-001`–`ADR-007` | The §3.3 decisions, recorded |
| `docs/adr/ADR-008`, `ADR-009` | **Proposed**: schema contract conventions; container policy is code, not profile data |
| `schemas/*.schema.json` | `common`, `pack-manifest`, `execution-profile`, `approval-record`, `verifier-event`, `observation`, `verdict` (JSON Schema 2020-12) |
| `schemas/examples/valid/` | 13 example records, including the §7.2 manifest verbatim and a full baseline event stream |
| `schemas/examples/invalid/` | 37 rejection examples, each pinned to the keyword and location it must fail on |
| `tests/unit/test_schemas.py` | Machine validation of all of the above |

**Owner decisions requested in PP-002** (`verdict-specification.md` §10). Each chosen
reading is the conservative one:

- D1: a timeout or crash makes that side's cells untrusted (V-05), not a provenance
  failure.
- D2: a trusted candidate violation in any pair gives `NOT_FIXED`, even if another pair
  was secure.
- D3: a violation from a truncated stream is untrusted, so the result is `INCONCLUSIVE`.
- D4: partial baseline reproduction gives `NOT_REPRODUCED`.
- D5: environment drift found after start gives `INCONCLUSIVE`; found before start, it
  gives `BLOCKED`.
- ADR-008 and ADR-009 accept or amend.

## Last completed gate and its evidence

**No release gate has passed.** v0.0 is open.

**PP-001 ACCEPTED** by owner on 2026-10-11. Evidence: `docs/environment.lock.md`.

## Next permitted issue

After PP-002 review: **PP-003** (isolation probes; needs owner approval to run
containers) or **PP-004** (pure verdict engine; needs a pinned Python and `pyproject.toml`,
approval item 3). PP-004 has no Docker dependency, so it can proceed in parallel with
the PP-003 approval.

## Failed tests, risks, and blockers

**Tests:** `tests/unit/test_schemas.py`: 78 passed, 0 failed, 0 skipped (2026-10-11).
Command:

```
env -u PYTEST_ADDOPTS -u PYTEST_PLUGINS -u PYTHONPATH PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  python3 -I -m pytest tests/unit -p no:cacheprovider -q
```

The suite was also checked against deliberately weakened schemas, on a scratch copy
outside the repository:

| Weakening | Result |
|---|---|
| Node-ID pattern loosened to `.*` | 2 tests failed |
| `VERIFIED_FOR_CASES` flag guard removed | 1 test failed |
| Profile opened to extra fields | 3 tests failed |

All three weakenings were caught.

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
| 1 | Review PP-002, including decisions D1–D5 and proposed ADR-008/ADR-009 | PP-004 rule set |
| 2 | Run the PP-003 isolation probe suite (harmless probes only; no target code) | v0.0 exit gate |
| 3 | Install current Python 3.13.x and pin it; approve pinning the validation/test dependencies | PP-004 packaging |
| 4 | `brew upgrade git` (2.42.0 → 2.56.0) | PP-005 |
| 5 | Decide whether to remove `/Users/aliel-asmar/.git` (nothing is tracked; recommend backing up its config first) | Safe local Git hygiene |
| 6 | Claude Code permissions: §23.1 advises against broad bypass mode on this Mac; PP-002 ran with it active (`docs/threat-model.md` AC-8) | Agent-boundary hygiene |

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
