# CLI workflow and safe reports (PP-009)

PP-009 adds the v0.1 command-line workflow of PROJECT_SPEC.md 13.1 on top of the accepted PP-005
to PP-008 components. It adds no execution engine, approval system, Docker policy or verdict logic.
Each command delegates to the module that already owns its step.

## Commands

| Command | What it does | Delegates to | Writes |
|---|---|---|---|
| `patchproof doctor [--json]`, `doctor --probe-isolation` | unchanged (PP-003, v0.0) | `doctor`, `probes.cli` | unchanged |
| `patchproof project add <path>` | validate an exact canonical repository root, preview what will and will not be read, record the owner's typed approval (interactive) | `git.repository.register_repository` | one `project-registration` record (0400) |
| `patchproof project list` | list registered projects | — | nothing |
| `patchproof profile prepare <profile-file> [--check-images]` | strict, hash-pinned profile preview; images, limits, deadlines. `--check-images` looks the two approved image IDs up locally (read-only `image inspect`) | `runner.profiles.load_profile`, `DockerCli` (`ImageInspect` only) | nothing; never pulls, builds or installs |
| `patchproof pack validate <pack-dir>` | static pack validation; expected collection and declared observations; approval state for the PaperTrail pack | `packs.validation.validate_pack`, `pack_approval.assemble_review`, `core.approvals.check_approval` | nothing; never approves |
| `patchproof pack approve <pack-id>` | the owner-operated pack approval (interactive); only `papertrail-document-access` | `pack_approval.run_approval` | one approval record |
| `patchproof plan create --project P --baseline R --candidate R [--create-snapshots]` | resolve revisions in the project, check them against the plan contract, recompute the frozen plan, store it, preview it with a preflight | `register_repository`, `resolve_revision`, `git.snapshot.create_snapshot` (only after a typed `SNAPSHOT <project>`), `papertrail_plan.assemble_run` | one plan record (0400); snapshots only when confirmed |
| `patchproof plan show <plan-id>` | the stored plan, its authorization state, and whether it still equals the plan recomputed now | `assemble_run` | nothing |
| `patchproof plan approve <plan-id>` | the owner-operated run authorization, bound to the stored plan's run ID and hash (interactive) | `run_authorization.run_authorization(expected_plan_sha256=…)` | one run authorization |
| `patchproof run <plan-id> [--json]` | execute the approved, unchanged plan once, after typed `EXECUTE <run-id>` (interactive). With `--json`, the conversation is on standard error and standard output carries only the JSON result | `run_papertrail_once.execute_once(expected_plan_sha256=…)` | the run's evidence; consumes the authorization |
| `patchproof report <run-id> [--format markdown\|json] [--output FILE]` | verify the evidence, recompute the verdict, print a safe review report | `run_evidence.verify_evidence`, `core.verdicts.evaluate`, `runner.collector.collect_stream` | nothing, or one new report file |

**Not accepted anywhere:**
- a Docker option, image, mount, network, environment variable or shell command;
- a reviewer name;
- `--yes` or `--force`.

A test scans every command's options for these.

**Gates:** `project add`, `pack approve`, `plan approve`, `run` and `plan create --create-snapshots` refuse
unless standard input and output (standard error for `run --json`) are a foreground terminal and no
`PATCHPROOF*` variable is set
(`pack_approval.require_terminal`, the gate the owner commands already use, minus its no-argument rule;
the arguments only select an object). Every approval and execution phrase is typed. Creating a plan
approves nothing, approving a plan executes nothing, and nothing runs automatically after either.

## Supported workflow (v0.1)

The only executable contract is the accepted `papertrail-authz-r1-r3-one-pair-v1`:
- the PaperTrail reference profile;
- baseline r1 (`authz-r1-vulnerable`) against candidate r3 (`authz-r3-correct`);
- one pair, the fixed synthetic fixture, at most four containers.

This is a deliberate supported-case restriction, not a shortcut around validation:
- `plan create` resolves both revisions to full commit and tree IDs through the PP-005 wrapper and compares
  them with the commit and tree IDs the accepted contract pins (`papertrail_plan.PAPERTRAIL_REVISIONS`). A
  tag is only a way to name a revision; a moved or re-created tag resolves to a different commit and is
  refused.
- Any other pair is refused before a snapshot, plan, approval or Docker operation exists.
- Approval and execution recompute the same contract, so nothing the CLI stores can widen it.

PatchProof makes no general runtime compatibility claim.

**Release-gate evidence this scope cannot produce (PROJECT_SPEC.md 15.2).** The v0.1 exit gate also needs
live evidence that:
- an unchanged vulnerable revision is not verified;
- an inadequate fix (r2) is not verified;
- a deny-all revision (r4) is classified as a functional regression;
- a startup failure, no-tests condition or missing observation never yields a verified result.

The Docker-free tests drive the accepted engine through the CLI for these shapes (`NOT_FIXED` 10,
`REGRESSION_DETECTED` 11, `NOT_REPRODUCED` 12, interrupted 20), but only with the fake Docker. Live
evidence needs comparisons the current contract refuses.

**Proposed separate work item (not started; needs owner review before PP-010 can use it):**
1. A reviewed widening of the plan contract to name each additional comparison exactly (for example
   r1 → r1, r1 → r2, r1 → r4), each with pinned commit and tree IDs and the same one-pair, four-container
   scope. Nothing generic, no caller-chosen revisions.
2. Read-only snapshots of r2 and r4 through `plan create --create-snapshots` (typed confirmation).
3. One new single-use run authorization per comparison (`plan approve`), with separate Docker approval for
   each run. No retry.
4. The startup-failure and missing-observation cases need a reviewed way to provoke them live (for example
   a profile or fixture variant). That is a further security-contract decision, not a CLI option.

```
patchproof project add /absolute/path/to/papertrail-reference
patchproof profile prepare profiles/papertrail-reference-1.0.0.json --check-images
patchproof pack validate examples/packs/papertrail-document-access
patchproof pack approve papertrail-document-access        # only if no current approval exists
patchproof plan create --project prj-… --baseline refs/tags/authz-r1-vulnerable \
                       --candidate refs/tags/authz-r3-correct
patchproof plan show plan-…
patchproof plan approve plan-…                            # typed AUTHORIZE <run-id> <plan-sha256>
patchproof run plan-…                                     # typed EXECUTE <run-id>; Docker
patchproof report run-… --format markdown --output report.md
```

## Records

- **Project registration** (`schemas/project-registration.schema.json` 1.0, `core.records.project`):
  - the canonical path, object format and supported profiles;
  - the owner's asserted identity (`local-assertion-unverified`), rationale and scope;
  - the typed `REGISTER <project-id>`.
  The project ID is the first 16 hex digits of the SHA-256 of the canonical path. PP-005 refuses any
  non-canonical spelling of a root (case variants and firmlinked aliases were checked on this host). An
  existing ID whose stored path differs is refused as a conflict. A directory already registered under
  another path (same device and inode) is refused as a duplicate. Cross-field rules are in
  `workflow.projects.check_registration`. Model/schema parity is covered by the existing corpus and
  differential tests (one valid and seven invalid examples).
- **Plan:** the canonical JSON of the accepted `RunPlanDocument` (no new contract). The plan ID is
  `plan-` plus the first 32 hex digits of its SHA-256. On load the bytes must be canonical, validate against
  the contract and its semantics, and hash to the ID.
- **Stores** (`workflow.store.PrivateStore`, under `<user data>/projects` and `<user data>/plans`):
  - the directory is created once with mode 0700 inside a private parent, never followed through a
    symlink and never repaired;
  - each record is written exclusively, read-only (0400) and fsynced;
  - reads are bounded and accept only regular single-link 0400 files.

## Preflight (PP-008 follow-up)

`workflow.preflight.Preflight` labels every check MANDATORY (a gate) or DIAGNOSTIC (information).
- The result is computed only from mandatory checks, and a report with no mandatory check is never a pass.
- Diagnostics never block and never turn a refusal into a success.
- `plan create` and `plan show` print their preflight.

**Exit codes through pipelines.** A shell reports the exit code of a pipeline's *last* command, so
`patchproof report … | tee report.md` reports `tee`'s 0. Use `--output FILE` instead of `tee`, or run with
`set -o pipefail` (or check `PIPESTATUS`). Scripts for future preflights must do the same.

## Exit codes (PROJECT_SPEC.md 13.2)

`workflow.exit_codes.run_exit_code(lifecycle, verdict, evidence_status)` is pure.

**Lifecycle comes first:**

| Lifecycle | Exit code |
|---|---|
| `CANCELED` | 22 |
| `INTERRUPTED` | 20 |
| `BLOCKED` | 21 |
| anything but `COMPLETE` with `FINALIZED` evidence and a verdict | 20 |

**Then the verdict:**

| Verdict | Exit code |
|---|---|
| `VERIFIED_FOR_CASES` | 0 |
| `NOT_FIXED` | 10 |
| `REGRESSION_DETECTED` | 11 |
| `NOT_REPRODUCED` | 12 |
| `INCONCLUSIVE` | 20 |
| `BLOCKED` | 21 |
| unknown | 20 |

**`run`:**
- refused before the claim: 21;
- claimed but nothing executed, or incomplete evidence without a record: 20;
- otherwise the record's own lifecycle and verdict.
`--json` prints the semantic verdict, the engine verdict, the lifecycle and the exit code separately.

**`report`:** the run's code, but 20 whenever the evidence does not verify. The PP-008 interruption
demonstration's controller (harness) exit code is never used as a run's exit code.

**Other commands:** 0 for success (or already done, unchanged), 21 for refused, 2 for a usage error.
For `report`, an unknown run ID and a refused or unwritable `--output` are usage errors (2), and evidence
that cannot be read or verified is 20.

**`run --json`** prints one JSON document on standard output:
- the run ID, the stage, the lifecycle, the evidence status;
- the semantic verdict, the engine verdict, the reason codes;
- the exit code and the contract it follows;
- cleanup, inventory reconciliation, daemon continuity and any stop reason, as separate fields.

Cleanup never changes the exit code. A `VERIFIED_FOR_CASES` run whose cleanup failed exits 0 and says so
in `cleanup_complete`. Callers must read the document, not infer it from the code (PROJECT_SPEC.md 13.2).

**The PP-008 utility is a different contract.** `python -I -m patchproof.run_papertrail_once` keeps its
accepted exit codes:

| Code | Meaning |
|---|---|
| 0 | finalized and clean, *whatever the verdict* (a `NOT_FIXED` run exits 0) |
| 5 | finalized but needs attention |
| 4 | incomplete evidence |
| 3 | claimed but not executed |
| 2 | refused |

These are operational codes, not PROJECT_SPEC.md 13.2 codes. `patchproof run` never passes them through:
it maps the run's own record with `exit_codes.run_exit_code` (tests pin a utility 0 with a `NOT_FIXED`
record to CLI 10). Scripts must use `patchproof run`, never the utility's code, as a verdict signal.

## Reports

`workflow.reports` builds a report only from persisted evidence, after:
1. **Accepted evidence verifier** (`verify_evidence`): manifest, every artifact's hash, size and mode, the
   operation journal (`docker-ops-v1` inline and the hardened `docker-ops-v2` are both accepted).
2. **Strict loading** of every record used: plan, authorization, outcome, manifest, verdict, verdict input,
   executions, observations, pack approval.
3. **Verdict recomputation** with the accepted engine from the stored verdict input, compared with the whole
   `verdict.json`. The recorded engine verdict and reason codes must equal it.
4. **Cross-checks:**
   - verdict-input executions against the execution records;
   - verdict-input observations against the observation files;
   - each side's observations against the cells the accepted collector re-derives from the raw verifier
     stream;
   - per-cell trust (the engine's own E1–E4 and T1–T5 rules) against the engine's trusted-cell count;
   - the plan against the authorization; the manifest summary against the outcome;
   - the manifest status against the outcome's evidence status;
   - the established verdict, which must be absent or equal to the recomputed engine verdict (and present
     and equal for a `COMPLETE` run);
   - for the interruption demonstration, the recorded lifecycle exit code against the run record.

If any check fails, the report says EVIDENCE NOT VERIFIED first and exits 20; nothing is presented as
established. A consistent incomplete run without a verdict (a signal before any revision finished) verifies
and is reported as such. The evidence is opened read-only and never modified.

**Contents** (PROJECT_SPEC.md 12.3):
- the run ID and lifecycle; the semantic verdict, engine verdict, decision rule, reason codes and flags;
- the narrow security claim and the legitimate behavior tested, labelled as a seeded synthetic example;
- baseline and candidate commits, trees and snapshot manifest hashes; source inclusion;
- pack, profile, verifier plugin and image identities; the fixture;
- the pack approval ID, basis and scope;
- planned and actual pairs; required tests with declared and observed outcomes per side and per-cell trust;
- security witnesses; executions; missing or untrusted cells with reason codes;
- cleanup and inventory reconciliation as a separate dimension;
- a fixed remediation summary per verdict; reproducibility prerequisites; limitations.

An interrupted run stays `INTERRUPTED`/`INCOMPLETE`/`INCONCLUSIVE` (or "no verdict") in the headline,
whatever its cleanup status.

**Report security:**

- **Allowlist.** Every field is chosen explicitly. Never included: raw target or verifier output, response
  bodies, source, pack test code, host paths, installation IDs, process IDs, reviewer names, fixture tokens or
  protected markers.
- **Witnesses.** The verifier's structured facts pass a per-key allowlist (`caller_id`, `caller_role`,
  `caller_permitted`, `credential`, `document_id`, `owner_id`, `reader_roles`, `status`, `marker_observed`).
  The `marker` value is always withheld. Other keys and unexpected values are withheld. A claim must be one of
  the four reviewed verifier claims.
- **Escaping:**
  - control, C1, bidirectional and zero-width characters become visible `\u{XXXX}`;
  - `&`, `<` and `>` become entities and other Markdown-significant characters are backslash-escaped, so no
    link, image (remote or `file:`), HTML, table break or heading can be injected;
  - JSON output is `ensure_ascii`.
- **Defence in depth:**
  - every value is truncated with a visible marker; the whole report is limited to 512 KiB;
  - known secret shapes are redacted, and a rendered report still containing one is refused;
  - the private data directory and home paths are replaced in every string.
- **Output.** `--output` writes a new 0600 file atomically:
  1. the text goes to a hidden temporary file in the destination directory (exclusive create, fsynced);
  2. that file is hard-linked to the requested name; the link fails if anything already has that name,
     a dangling symlink included, so nothing is overwritten or followed;
  3. the temporary name is always removed.

  The directory is opened once and must be the directory its resolved path names. A destination inside
  the private data directory, including through a symlinked parent, is refused. A failure leaves nothing at
  the destination, and the evidence is never opened for writing. A file system without hard links cannot
  receive `--output`; use standard output there.

A report is a **review report, not a reproduction bundle** (PROJECT_SPEC.md 12.4). It names the hashes
needed to reproduce a run and contains no source, pack, image or credential.

**Witness depth and response retention (accepted limitations).**
- Security witnesses are structured facts that the reviewed verifier helpers establish and the trusted
  event stream carries.
- Raw HTTP responses are not retained (PROJECT_SPEC.md 12.2 lists `private/raw-responses/` as future work),
  so a report cannot re-examine them and never claims to contain them.
- Functional controls pass or fail through reviewed assertions; their bodies are not retained either.
- Retaining responses would need a plugin, pack or schema change and a new approval.

## Rationale and scope validation (PP-008 follow-up)

`pack_approval.statement_problem` is used for every rationale and scope typed into project registration,
pack approval and supersession, run authorization and interruption authorization. It refuses:
- a statement under 20 characters, or with fewer than 4 different words;
- fewer than 3 meaningful (non-placeholder) words;
- placeholders such as `idk` or `test`;
- the confirmation phrase, or any 40-plus-digit hash from it;
- a scope identical to the rationale.

It checks effort, not truth, and applies only when a statement is typed. Stored records, including the
consumed PP-008 interruption authorization, are never revalidated, rewritten or repaired.

## Live validation still owed (not executed)

1. **A real run through the CLI.** `plan approve` and `run` delegate to the flows already used live in
   PP-008, but the CLI path itself has run only against the fake Docker. Running it needs a new plan, owner
   authorization and Docker approval.
2. **The hardened verifier-console capture in a live verifier execution.** PP-008 hardening is proven
   Docker-free; the live interruption run never started its verifier. Proposed check, for separate owner
   approval:
   1. Use the existing r1 → r3 plan contract (four containers, one pair) through `plan create`,
      `plan approve` and `run`.
   2. **Expected:** `docker-ops-v2` journal; `untrusted-target-stdout/stderr-*` and
      `untrusted-verifier-console-*` artifacts with capture status, size, hash and truncation recorded;
      no raw output in the journal; a real `evaluated_at`.
   3. **Expected:** `patchproof report` verifies and reproduces `VERIFIED_FOR_CASES` (V-09), and
      `recover_run` finds nothing.
   4. **Budget:** at most four container creations. **Retry:** none.
