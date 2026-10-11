# Verdict specification

**Issue:** PP-002 (revised in review remediation, 2026-10-11) · **Status:** `READY_FOR_REVIEW`
**Spec basis:** `PROJECT_SPEC.md` §5.2, §7.3–§7.5, §8, §10.3, §13.2, §17.3
**Implemented in:** PP-004, the pure engine and its truth-table tests. Nothing here is implemented yet.

This document fixes the verdict engine's inputs, its validation, its trust rules, its
evaluation order, and its outputs. It is a review-controlled input. PP-004 must
reproduce every expected verdict in the scenario corpus (section 12) exactly, and
changing any rule needs owner review (CLAUDE.md, "Verification integrity").

**The governing invariant.** Trustworthy evidence of a remaining vulnerability is
preserved. Missing, incomplete, inconsistent, or untrusted evidence never produces
`VERIFIED_FOR_CASES`.

Machine-checkable contracts live in `schemas/` (JSON Schema draft 2020-12). Example
records use placeholder digests made of one repeated hex digit; they are not real
hashes.

---

## 1. Three dimensions, never merged (§8.1)

| Dimension | Values | Contract |
|---|---|---|
| Run lifecycle | `DRAFT → PREFLIGHT → AWAITING_APPROVAL → QUEUED → RUNNING → FINALIZING → COMPLETE`; terminal alternatives `BLOCKED`, `CANCELED`, `INTERRUPTED`; separate cleanup status `PENDING`/`COMPLETE`/`FAILED` | §8.2; persisted in PP-011 |
| Per-test observation | stream status × lifecycle outcome × semantic outcome (sections 3–4) | `observation.schema.json` |
| Comparison verdict | the six verdicts (section 6) | `verdict.schema.json` |

Every run that reaches evaluation gets a verdict record, including canceled and
interrupted runs. The engine is told how the run ended through `run_termination`
(`normal`, `canceled`, `interrupted`), never through the lifecycle state itself.

### 1.1 CLI exit code (§13.2)

The exit code is chosen **first by lifecycle, then by verdict**:

| Run state | Exit code |
|---|---|
| Lifecycle `CANCELED` | 22 |
| Lifecycle `INTERRUPTED` | 20 |
| Lifecycle `BLOCKED` (never executed) | 21 |
| Otherwise, by verdict | `VERIFIED_FOR_CASES` 0 · `NOT_FIXED` 10 · `REGRESSION_DETECTED` 11 · `NOT_REPRODUCED` 12 · `INCONCLUSIVE` 20 · `BLOCKED` 21 |

The lifecycle-based codes do not replace the semantic verdict. A canceled run whose
completed executions already established a trusted candidate violation still records
`NOT_FIXED` (scenario S17), and its JSON output reports that verdict alongside exit
code 22.

## 2. Engine inputs (`verdict-input.schema.json`)

The engine is a pure function `evaluate(VerdictInput) → Verdict`. It never calls
Docker, reads files, or parses logs. Its input contains **only** the following:

| Field | Source |
|---|---|
| `pack_tests` | the approved pack's required-test table: ID, node ID, kind, baseline expectation, candidate expectation |
| `pairs_planned` | the approved plan |
| `result_cap_bytes` | the approved profile's per-execution structured result cap (§5.2) |
| `preconditions` | five results, each `{state, detected_phase, reason_codes}` (section 5) |
| `run_termination` | `normal`, `canceled`, or `interrupted` |
| `executions` | host-observed execution records, one per started or attempted pair/side (`execution.schema.json`) |
| `observations` | per-test cells derived from verifier events only (`observation.schema.json`) |

There is no input field for target stdout, target logs, target-created files, target
HTTP status text, or any target-supplied status (INV-09). This is a type-level control:
the engine cannot be handed those values. `verdict-input--target-log-field.json` is
rejected by the schema.

## 3. Pytest lifecycle and per-test outcomes

### 3.1 Valid event grammar for one verifier stream (protocol)

The approved verifier plugin emits events with `seq` starting at 0 and incrementing by
exactly 1. A **complete** stream has this shape:

```text
session_start
collected                      (exactly the approved collection, in order)
block(test_1) ... block(test_n) (one block per collected test, in collection order, never interleaved)
session_end                    (tests_reported = n, observations_emitted = number of observation events)

block(t) :=
    test_report(t, setup, passed)
    observation(t, ...)*          (zero or more, only inside the call window)
    test_report(t, call, any outcome)
    test_report(t, teardown, passed | failed)
  | test_report(t, setup, failed | skipped)
    test_report(t, teardown, passed | failed)     (no call report when setup did not pass)
```

The second form is how pytest itself behaves. When setup fails or skips, pytest emits
no call report but still runs and reports teardown. A setup failure is therefore a
**valid** sequence. It makes only that test untrusted (section 3.2) and does not
corrupt the stream.

**Protocol violations** make the stream `MALFORMED`, which is a global provenance
failure (section 4.1):

- a missing report;
- a duplicated report;
- a call report after a setup that did not pass;
- reports out of order or for the wrong test;
- interleaved blocks;
- an observation outside its test's call window;
- events after `session_end`;
- a gap or duplicate in `seq`;
- a schema-invalid event;
- `session_end` counts that differ from what the host actually received.

The plugin, not the test author, controls this grammar, so a violation means the result
channel cannot be trusted.

A stream that ends early, without `session_end`, is `TRUNCATED` if everything received
is a valid prefix of the grammar. That is a **local** failure: only that execution is
affected. The block that was cut off yields lifecycle `INTERRUPTED`. Tests with no block
at all yield `NOT_RUN`, and their cells may be omitted.

### 3.2 Lifecycle outcome of one valid block

Apply these rules in order and stop at the first match.

| # | Condition | `lifecycle_outcome` | Harness error added |
|---|---|---|---|
| L1 | Block cut off by truncation | `INTERRUPTED` | — |
| L2 | Any report in the block has `xfail: true`, and the call reports passed or failed | `XPASSED` | — |
| L3 | Any report in the block has `xfail: true`, otherwise | `XFAILED` | — |
| L4 | Setup failed | `SETUP_ERROR` | — |
| L5 | Setup or call skipped | `SKIPPED` | — |
| L6 | Call failed with `failure_class: timeout` | `TIMED_OUT` | — |
| L7 | Call failed with `exception` or `helper_misuse` | `CALL_ERROR` | — |
| L8 | Security test; call failed with `assertion` | `CALL_ERROR` | `GENERIC_FAILURE_IN_SECURITY_TEST` |
| L9 | Functional test; call failed with `security_terminal` | `CALL_ERROR` | `OBSERVATION_ON_FUNCTIONAL_TEST` |
| L10 | Teardown failed | `TEARDOWN_ERROR` | `ERROR_AFTER_OBSERVATION` if an observation was emitted |
| L11 | Otherwise | `COMPLETED` | — |

So `COMPLETED` means exactly this: setup passed, teardown passed, and the call ended in
one of these ways:

- a pass;
- a functional assertion failure;
- a security test's controlled `security_terminal` exception.

A generic `AssertionError` in a security test is **never** a violation witness (L8;
§7.3, INV-05).

### 3.3 Semantic outcome and harness errors

**Functional test.**

| Lifecycle and call | `semantic_outcome` |
|---|---|
| `COMPLETED`, call passed | `PASS` |
| `COMPLETED`, call failed with `assertion` | `FAIL` |
| Any other lifecycle | `NONE` (schema-enforced: a timeout or crash is never a `FAIL`) |

An observation event on a functional test adds `OBSERVATION_ON_FUNCTIONAL_TEST`.

**Security test.** The semantic outcome is the outcome of its single observation event:
`VIOLATION_CONFIRMED`, `SECURE`, or `INCONCLUSIVE`. It is `NONE` when there is no single
observation. The plugin adds these harness errors:

| Harness error | When |
|---|---|
| `MISSING_TERMINAL_OBSERVATION` | the call ran but emitted no observation |
| `MULTIPLE_TERMINAL_OBSERVATIONS` | more than one observation (semantic `NONE`) |
| `SUPPRESSED_TERMINAL_EXCEPTION` | a `VIOLATION_CONFIRMED` observation, but the call passed (the helper's exception was caught) |
| `MALFORMED_EVIDENCE` | evidence failed the helper's validation, or a `security_terminal` failure has no matching `VIOLATION_CONFIRMED` observation |

`SETUP_ERROR`, `NOT_RUN`, and `NOT_COLLECTED` always have semantic `NONE`
(schema-enforced).

## 4. Trust

### 4.1 Stream status: local versus global

| `stream.status` | Meaning | Scope |
|---|---|---|
| `COMPLETE` | full grammar satisfied, within the cap, identity matched | — |
| `TRUNCATED` | valid prefix, no `session_end` | **local**: this execution is untrusted |
| `ABSENT` | no events received | **local** |
| `MALFORMED` | protocol violation (section 3.1) | **global** provenance failure |
| `IDENTITY_MISMATCH` | run/pair/side, pack hash, or collected set differs from the plan | **global** |
| `OVER_CAP` | exceeded `result_cap_bytes` | **local** (owner decision D6) |

**The engine enforces the cap itself (D6).** An execution is over the cap if its
`stream.status` is `OVER_CAP` **or** its host-observed `stream.bytes_received` exceeds
`result_cap_bytes`, whatever status was supplied (S26). Every observation from an
over-cap execution is untrusted, including any apparent violation (S24, S26). The
execution is reported with `RESULT_CAP_EXCEEDED` for its pair and side. Other complete,
normally finalized, integrity-valid executions remain trustworthy, so a trusted candidate
violation elsewhere still gives `NOT_FIXED` (S25).

### 4.2 Execution trust: host-confirmed finalization

A `session_end` event alone never makes an execution trustworthy. An execution record
is **trusted** if and only if all of these hold:

| # | Condition |
|---|---|
| E1 | `started` and `target.readiness == READY` |
| E2 | `verifier.termination == EXITED` and `exit_code ∈ {0, 1}` |
| E3 | no verifier OOM, no target OOM, target did not exit during tests, no deadline exceeded, not canceled, no runtime errors |
| E4 | `stream.status == COMPLETE` and `stream.bytes_received ≤ result_cap_bytes` |

Pytest exit code 1 is expected whenever any report failed. A controlled
`security_terminal` exception, a functional assertion failure, and a setup error all
produce 1. The engine therefore does not require exit code 0. Exit codes 2–5 (pytest
interrupted, internal error, usage error, no tests collected), a signal, or an
unobserved termination fail E2, giving `VERIFIER_TERMINATED_ABNORMALLY` unless a
deadline, OOM, or cancellation already explains it.

Whether exit 0 or 1 is *consistent* with the reports is a separate check, G3 in
section 5.2. A contradiction there is a global failure, not a local one.

An untrusted execution affects only its own cells (D1, D6). Other trusted executions
remain usable.

### 4.3 Cell trust

One cell is `(pair, side, test_id)`. The required cell set has exactly `2 × P × T`
keys. A cell is **trusted** if and only if all of these hold:

| # | Condition |
|---|---|
| T1 | Every effective precondition is `PASSED`: no input precondition failed or was left unevaluated, and input validation (section 5.2) passed. |
| T2 | Its pair/side execution is trusted (E1–E4). |
| T3 | The cell exists and `lifecycle_outcome == COMPLETED`. |
| T4 | `harness_errors` is empty. |
| T5 | `semantic_outcome ∈ {VIOLATION_CONFIRMED, SECURE}` for security, or `∈ {PASS, FAIL}` for functional. |

Untrusted cells are preserved in the evidence matrix and displayed. They are never
verdict evidence.

## 5. Preconditions and input validation

### 5.1 Preconditions

| Precondition | Fails when (examples) | Typical reason codes |
|---|---|---|
| `authorization` | approval missing, superseded, or stale; plan hash changed | `APPROVAL_MISSING`, `APPROVAL_STALE` |
| `pack_integrity` | pack tree hash ≠ approved; manifest invalid; pack lacks a functional control or an expected violation; collected set ≠ approved | `PACK_INTEGRITY_FAILED`, `PACK_INCOMPLETE_FOR_FIX_VERIFICATION`, `PACK_COLLECTION_MISMATCH` |
| `source_identity` | resolved commit or snapshot hash ≠ plan | `SOURCE_IDENTITY_MISMATCH` |
| `environment_identity` | image IDs, profile hash, or dependency contract differ; runtime policy inspection failed | `ENVIRONMENT_NONCOMPARABLE`, `UNSUPPORTED_TARGET_PROFILE`, `RUNTIME_POLICY_FAILED` |
| `result_provenance` | result evidence is malformed, identity-mismatched, corrupted, or inconsistent with its manifest | `EVENT_STREAM_MALFORMED`, `EVENT_STREAM_IDENTITY_MISMATCH`, `EVIDENCE_INCOMPLETE` |

An execution failure (startup failure, timeout, OOM, abnormal exit, cancellation,
truncation, result-cap overflow) is **not** a precondition failure. It is local (sections 4.1–4.2).

A `FAILED` precondition carries `detected_phase` (section 5.3) and at least one reason
code. `PASSED` and `NOT_EVALUATED` carry neither (schema-enforced).

### 5.2 Input validation (fail closed, never normalize)

Before any rule is applied, the engine checks the input. A failure sets the
**effective** `result_provenance` to `FAILED`, adds the listed reason, and makes every
cell untrusted (T1). The engine never deduplicates, merges, or drops records to make
input valid. In particular it must not build a dictionary by assignment, because a
second record would silently overwrite the first.

| # | Check | Reason on failure |
|---|---|---|
| M1 | Every record's `run_id` equals the input's `run_id`. | `OBSERVATION_MATRIX_INVALID` |
| M2 | Every observation's `test_id` is in `pack_tests`, and its `kind` and `nodeid` match that test. | `OBSERVATION_MATRIX_INVALID` |
| M3 | Every `pair` is ≤ `pairs_planned`. (`side` and pair ≥ 1 are schema-enforced.) | `OBSERVATION_MATRIX_INVALID` |
| M4 | No two observations share a `(pair, side, test_id)` key, whether identical or conflicting. Byte-identical duplicates are also rejected by the schema (`uniqueItems`). | `OBSERVATION_MATRIX_INVALID` |
| M5 | No two execution records share a `(pair, side)` key. | `OBSERVATION_MATRIX_INVALID` |
| M6 | Every observation belongs to a started execution, and its `stream_status` equals that execution's `stream.status`. Stream trust therefore applies identically to every cell of the stream. | `OBSERVATION_MATRIX_INVALID` |
| M7 | A `COMPLETE` stream has a cell for every required test. | `OBSERVATION_MATRIX_INVALID` |
| G1 | No execution has `stream.status` `MALFORMED` or `IDENTITY_MISMATCH`. Enforced by the engine even if the caller passed `result_provenance: PASSED`. (`OVER_CAP` is local: section 4.1, D6.) | the stream's reason (section 4.1) |
| G2 | No execution has events (`stream.status ≠ ABSENT`) while `verifier.termination == NOT_STARTED`. | `EXECUTION_EVIDENCE_INCONSISTENT` |
| G3 | For a `COMPLETE` stream whose verifier `EXITED` with 0 or 1: `exit_code == 1` if and only if `stream.failed_reports > 0`. | `EXECUTION_EVIDENCE_INCONSISTENT` |
| G4 | For a `COMPLETE` stream: the number of its cells that imply a failed report (lifecycle `SETUP_ERROR`, `CALL_ERROR`, `TEARDOWN_ERROR`, `TIMED_OUT`, or `COMPLETED` with `FAIL`/`VIOLATION_CONFIRMED`) is ≤ `failed_reports`, and `failed_reports ≤ 2T`. | `EXECUTION_EVIDENCE_INCONSISTENT` |
| G5 | No precondition `FAILED` with `detected_phase: pre_execution` while execution started. | `EXECUTION_EVIDENCE_INCONSISTENT` |

Counts are computed from the validated records. `stream.failed_reports`,
`events_received`, and `bytes_received` are facts the host collector computed from
the bytes it received. They are never copied from `session_end`, which is checked
against them (section 3.1).

Missing cells are **not** a validation failure unless M7 applies. A missing cell is
untrusted (T3), which leads to incompleteness and V-05.

### 5.3 When comparison execution begins (D5)

Comparison execution begins at the first `docker start` of any container belonging to
the run. That is the earliest moment at which target or verifier code can run.

| Before that instant (`pre_execution`) | After it (`post_execution`) |
|---|---|
| Plan approval, dequeue revalidation (§11.2), preflight, image presence checks, and container **creation and inspection**. A policy-inspection failure on a created but never-started container is `pre_execution`. | Every later detection, including failures found while preparing a later pair. |

`execution_started` is true if any execution record has `started: true`, **or** any
observation exists. Evidence exists only if something ran, so a run with observations
can never be reported as `BLOCKED`.

### 5.4 Unevaluated preconditions

A `NOT_EVALUATED` precondition is never treated as passing. It always adds
`PRECONDITION_NOT_EVALUATED` (schema-enforced) and leads to:

- V-01 `BLOCKED` if execution never started;
- V-02 `INCONCLUSIVE` if it did.

## 6. Decision table

First compute validation (section 5.2), trust (section 4), flags (section 7), and reason
codes (section 8) from all of the evidence. Then apply the rules in order; the first
match sets `verdict` and `decision_rule`. Every flag and reason code stays in the
output whichever rule matches.

| Rule | Condition (no earlier rule matched) | Verdict |
|---|---|---|
| **V-01** | Execution never started, input validation passed, and some precondition is not `PASSED`. | `BLOCKED` |
| **V-02** | Some effective precondition is not `PASSED`: a post-execution failure, an unevaluated precondition after start, or failed input validation. **No observation is trusted (T1)**, so earlier observations cannot establish any verdict, positive or negative. | `INCONCLUSIVE` |
| **V-03** | `candidate_violation` | `NOT_FIXED` |
| **V-04** | `functional_regression` | `REGRESSION_DETECTED` |
| **V-05** | `incomplete_checks` | `INCONCLUSIVE` |
| **V-06** | `flaky_observations` | `INCONCLUSIVE` |
| **V-07** | `baseline_control_failed` | `INCONCLUSIVE` |
| **V-08** | `baseline_not_reproduced` | `NOT_REPRODUCED` |
| **V-09** | Execution started; `run_termination == normal`; `pairs_terminated_normally == pairs_with_trusted_evidence == pairs_planned`; exactly `2 × P × T` trusted cells; each equals its pack expectation for its side; and no flag is set. | `VERIFIED_FOR_CASES` |
| **V-10** | Fallthrough. Unreachable by construction (see the reachability note below); exists so the engine can never default to a positive verdict. | `INCONCLUSIVE` + `UNCLASSIFIED_EVIDENCE` |

**Reachability.** Suppose V-08 does not match. Then every cell is trusted (no V-05),
consistent across pairs (no V-06), and the baseline controls hold (no V-07). Each
candidate security cell is therefore `SECURE` (no V-03). Each candidate functional cell
is `PASS`: a `FAIL` would have triggered V-04 or V-07. Each baseline expected-violation
cell is `VIOLATION_CONFIRMED` (no V-08). Together those are exactly the conditions of
V-09.

**Notes.**

- **V-03 needs no baseline reproduction** (§8.4). One trusted candidate violation is
  proof on its own. It is not hidden by:
  - incomplete repetitions (S03);
  - flakiness (S04, D2);
  - a setup failure elsewhere (S11);
  - cancellation (S17).
- **V-04 requires a same-pair trusted baseline `PASS`.** A candidate timeout is not a
  `FAIL` (S08). A baseline that did not run cannot anchor a regression.
- **V-05 precedes V-06 to V-08.** Repetition, control, and reproduction judgments are
  made only on complete evidence. S05 has a trusted baseline disagreement *and* a
  not-reproduced pair. It is `INCONCLUSIVE` by V-06, with both flags set.
- **V-09 is defined as exact agreement**, not as the absence of failures.

## 7. Flags: independent evidence

Each flag states what the evidence demonstrates. None depends on the selected rule.
All except `incomplete_checks` and `harness_drift` are computed over **trusted** cells
only. Under a global failure (T1) no cell is trusted, so those flags are false. The
untrusted observations remain visible in the evidence matrix.

| Flag | Set when |
|---|---|
| `candidate_violation` | any trusted candidate security cell is `VIOLATION_CONFIRMED` |
| `functional_regression` | for some pair *p* and functional test *f*, the trusted candidate cell `(p, f)` is `FAIL` and the trusted baseline cell `(p, f)` is `PASS` |
| `flaky_observations` | for some side and test, two trusted cells in different pairs have different semantic outcomes, even if another pair is incomplete |
| `baseline_not_reproduced` | some trusted baseline cell of an expected-violation test is `SECURE` |
| `baseline_control_failed` | a trusted baseline functional cell is `FAIL`, or a trusted baseline security cell whose expectation is `SECURE` is `VIOLATION_CONFIRMED` |
| `incomplete_checks` | any required cell is missing or untrusted, or `run_termination ≠ normal` |
| `harness_drift` | `environment_identity` or `pack_integrity` `FAILED` with `detected_phase: post_execution`, or any cell (trusted or not) records a harness error |

`verdict.schema.json` cross-checks verdicts against flags. For example:

- `VERIFIED_FOR_CASES` with any flag set is rejected;
- `INCONCLUSIVE` with `candidate_violation` or `functional_regression` set is rejected,
  because those flags always select V-03 or V-04 first;
- `BLOCKED` requires `execution_started: false` and `incomplete_checks: true`.

## 8. Reason codes, details, and counts

**Reason codes** are the union of every applicable code below, emitted in the canonical
order of `common.reasonCode`. `ALL_CONDITIONS_SATISFIED` appears only with V-09, and as
the only code.

| Scope | Code | Emitted when | Detail entries |
|---|---|---|---|
| Run | each failed precondition's `reason_codes` | input precondition `FAILED` | none |
| Run | `PRECONDITION_NOT_EVALUATED` | any effective precondition `NOT_EVALUATED` | none |
| Run | `OBSERVATION_MATRIX_INVALID`, `EXECUTION_EVIDENCE_INCONSISTENT` | M1–M7 / G2–G5 failed | none |
| Run | `RUN_CANCELED`, `RUN_INTERRUPTED` | `run_termination` | none |
| Run | `REPETITION_INCOMPLETE` | execution started and `pairs_terminated_normally < pairs_planned` | none |
| Execution | `EVENT_STREAM_MALFORMED`, `EVENT_STREAM_IDENTITY_MISMATCH` | G1 | per pair/side |
| Execution | `TARGET_STARTUP_FAILED` | readiness `STARTUP_FAILED` or `READINESS_TIMEOUT` | per pair/side |
| Execution | `EXECUTION_TIMED_OUT` | `deadline_exceeded` | per pair/side |
| Execution | `EXECUTION_OOM_KILLED` | verifier or target OOM | per pair/side |
| Execution | `TARGET_EXITED_DURING_TESTS` | target exited during tests | per pair/side |
| Execution | `RUNTIME_ERROR` | any runtime error | per pair/side |
| Execution | `EXECUTION_CANCELED` | this execution's `canceled` is true | per pair/side |
| Execution | `RESULT_CAP_EXCEEDED` | `stream.status == OVER_CAP` or `bytes_received > result_cap_bytes` | per pair/side |
| Execution | `VERIFIER_TERMINATED_ABNORMALLY` | signal, unobserved termination, or exit ∉ {0, 1}, not explained by deadline, OOM, cancellation, or result-cap overflow (each of which has its own code above) | per pair/side |
| Execution | `EVENT_STREAM_TRUNCATED` | target ready, stream `TRUNCATED` or `ABSENT` | per pair/side |
| Cell | `REQUIRED_CHECK_INCOMPLETE` | execution started and a required cell is untrusted or missing | per cell |
| Cell | `CHECK_INCONCLUSIVE` | any cell with semantic `INCONCLUSIVE` | per cell |
| Cell | `HARNESS_ERROR` | any cell with harness errors | per cell |
| Cell | `CANDIDATE_VIOLATION_CONFIRMED` | each trusted candidate security `VIOLATION_CONFIRMED` | per cell |
| Cell | `NEW_SECURITY_VIOLATION` | as above, **and** the trusted baseline cell for the same pair and test is `SECURE` | per cell |
| Cell | `FUNCTIONAL_REGRESSION` | the `functional_regression` condition | per candidate cell |
| Cell | `BASELINE_CONTROL_FAILED` | trusted baseline functional `FAIL` | per cell |
| Cell | `BASELINE_SECURITY_UNEXPECTED` | trusted baseline security cell expected `SECURE` that observed `VIOLATION_CONFIRMED` | per cell |
| Test | `INCONSISTENT_REPETITIONS` | the `flaky_observations` condition | per side/test (pair null) |
| Test | `BASELINE_NOT_REPRODUCED` / `BASELINE_PARTIALLY_REPRODUCED` | see below | per not-reproduced test (side baseline, pair null) |
| Run | `UNCLASSIFIED_EVIDENCE` | V-10 | none |

**`NEW_SECURITY_VIOLATION` needs comparative evidence.** A baseline *expectation* of
`SECURE` is not enough; a trusted baseline observation of `SECURE` in the same pair is
required. Otherwise only `CANDIDATE_VIOLATION_CONFIRMED` is emitted.

**Baseline reproduction (D4).** Classify each expected-violation test from its trusted
baseline cells:

- **not reproduced:** any of them is `SECURE`;
- **reproduced:** at least one is `VIOLATION_CONFIRMED` and none is `SECURE`.

Then:

- `BASELINE_PARTIALLY_REPRODUCED` if some tests are reproduced and others are not;
- `BASELINE_NOT_REPRODUCED` if none is reproduced.

The affected test IDs appear in `details` (S09).

**Termination evidence is never discarded.** Suppressing `VERIFIER_TERMINATED_ABNORMALLY` only
removes a redundant summary code. The explaining cause always has its own reason for the same
pair/side (`EXECUTION_TIMED_OUT`, `EXECUTION_OOM_KILLED`, `EXECUTION_CANCELED`, or `RESULT_CAP_EXCEEDED`). The raw
host-observed facts are retained unchanged in that execution's record, `executions/pair-NNN-<side>.json`
in the evidence bundle (§12.2) and in `verdict-input.json`. Those facts are exit status, signal,
OOM flags, deadline, cancellation, and runtime errors. Reason codes summarize; the execution
records are the authoritative termination evidence.

**Details** are sorted by the following keys, in order:

1. reason-code order;
2. pair (null first);
3. side (null, then baseline, then candidate);
4. test ID.

Together with the canonical reason order, this makes the output independent of input
order (P-2).

**Counts** are computed from validated input, never taken from the caller.

| Count | Meaning |
|---|---|
| `required_cells` | `2 × P × T` |
| `trusted_cells` | cells satisfying T1–T5 |
| `pairs_terminated_normally` | pairs whose two executions both satisfy E1–E4. This is **execution completion only**; it says nothing about whether the evidence is trusted. |
| `pairs_with_trusted_evidence` | pairs in which all `2 × T` cells are trusted (T1–T5) |

The two pair counts are deliberately separate. Under a global failure,
`pairs_terminated_normally` can be 1 while `pairs_with_trusted_evidence` and `trusted_cells`
are 0 (S12, S21). Any display of "repetitions completed" or "checks completed" **must** use
`pairs_with_trusted_evidence` and `trusted_cells`. It must never use
`pairs_terminated_normally`, which may be shown only labeled as execution status, for example
"executions ended normally".

## 9. Display (§8.3, §14)

| Verdict | `display_label` | Always shown with |
|---|---|---|
| `VERIFIED_FOR_CASES` | Verified for the selected cases | test count and repetition count (`pairs_with_trusted_evidence` of `pairs_planned`), immediately |
| `NOT_FIXED` | Not fixed | the violating cells and every incomplete check |
| `REGRESSION_DETECTED` | Regression detected | the failing control and its same-pair baseline pass |
| `NOT_REPRODUCED` | Not reproduced | which expected violations did not reproduce |
| `INCONCLUSIVE` | Inconclusive | every reason code and detail, and trusted checks as `trusted_cells` of `required_cells` |
| `BLOCKED` | Blocked | the precondition and the specific input requiring attention |

## 10. What the schemas do not enforce

| Rule | Owner |
|---|---|
| Duplicate JSON keys and `NaN`/`Infinity` rejected before validation | strict loader, PP-007 (reference behavior tested in `tests/unit/test_schemas.py`) |
| Pack test IDs and node IDs unique; files exist; collection matches | pack validation, PP-007 |
| Approval bindings equal current hashes (staleness) | approval check, PP-007 |
| Event grammar and stream status (section 3.1); `failed_reports` and `bytes_received` counted from received events | event collector, PP-008 |
| Target-derived content safely encoded, escaped, and bounded before it enters an event | verifier event producer and collector, PP-008 (D6) |
| Lifecycle and semantic derivation (sections 3.2–3.3) | verifier plugin and collector, PP-007/PP-008 |
| Input validation M1–M7 and G1–G5 (section 5.2), except byte-identical duplicates | verdict engine, PP-004 |
| Trust, flags, reasons, details, counts, and the decision table | verdict engine, PP-004 |

Records not yet specified: run authorization / execution plan (PP-007/PP-009), evidence
bundle manifest (PP-009), and source snapshot manifest (PP-005). Each gets a schema in
the issue that first produces it.

## 11. Owner decisions (decided 2026-10-11 in PP-002 review)

| ID | Decision |
|---|---|
| D1 | A startup failure, timeout, OOM, abnormal termination, or cancellation makes **only that execution's** observations untrusted. The result is normally `INCONCLUSIVE`, unless independent trustworthy evidence from other completed executions establishes `NOT_FIXED` or `REGRESSION_DETECTED`. Malformed, identity-mismatched, corrupted, or inconsistent result evidence is a **global** provenance failure (V-02). Over-cap was originally listed here; D6 superseded that, and over-cap is now local. *Correction to the earlier draft:* it claimed the alternative reading ("every incomplete stream is a provenance failure") gave the same verdict. It does not. Under that reading, one timed-out repetition would turn a `NOT_FIXED` established by other repetitions (S03) into `INCONCLUSIVE`, hiding a demonstrated vulnerability. |
| D2 | A trusted candidate `VIOLATION_CONFIRMED` in one repetition and a trusted `SECURE` in another give `NOT_FIXED` with `flaky_observations: true` (S04). A demonstrated violation does not disappear because a later repetition passed (INV-11). |
| D3 | Observations from a truncated, unfinalized, or otherwise untrusted stream are preserved for review but excluded from verdict evidence. An apparent violation there does not by itself establish `NOT_FIXED` (S06). Other trustworthy completed executions may (S03). |
| D4 | Partial baseline reproduction gives `NOT_REPRODUCED` with `BASELINE_PARTIALLY_REPRODUCED`, provided all required evidence is complete, trustworthy, and consistent and no higher rule applies. The affected tests are listed in `details` (S09). |
| D5 | Validation failures detected before comparison execution begins (section 5.3) give `BLOCKED` (S14, S22). Failures detected afterward give `INCONCLUSIVE`, with the affected precondition and execution history preserved (S15). A global validation failure prevents every earlier observation from establishing a verified or authoritative negative verdict. `PROJECT_SPEC.md` §17.3 items 3, 6, and 9 were amended to match. |
| D6 | A structured result-cap overflow invalidates **only the affected execution** `(pair, side)`, restoring the intent of §5.2. All of its observations are untrusted, including any apparent violation. It is reported with `RESULT_CAP_EXCEEDED` for that pair and side. Other complete, normally finalized, integrity-valid executions stay trustworthy, so an existing trusted candidate violation still gives `NOT_FIXED` with `candidate_violation` and `incomplete_checks` (S25). No incomplete or over-cap execution can contribute to `VERIFIED_FOR_CASES`. The engine checks the host-observed byte count against the cap itself (S26). Malformed, identity-mismatched, and structurally corrupted streams remain **global** provenance failures under the conservative v1.0 policy. PP-008's event producer and collector must safely encode, escape, and bound target-derived content. They must not silently discard or rewrite material evidence to make it validate; invalid data is handled explicitly, with recorded limitations. |

Related accepted ADRs (2026-10-11): **ADR-008** (schema contracts) and **ADR-009**
(container security policy is code).

## 12. Scenario corpus (review-controlled truth table)

Each directory under `schemas/examples/scenarios/` holds a `verdict-input.json` and the
reviewed expected `verdict.json`. `tests/unit/test_schemas.py` checks four things:

- both records are schema-valid;
- they are mutually consistent;
- this table matches the directories;
- duplicate cells occur only where V-02 is expected.

PP-004 must reproduce each `verdict.json` exactly. The expected records were generated
by a scratch evaluator applying this document literally, kept outside the repository.
Each verdict, rule, and key flag was also specified by hand, and generation failed on
any disagreement. None did.

| ID | Directory | Situation | Expected verdict | Rule |
|---|---|---|---|---|
| S01 | `S01-verified-fix` | Fully verified fix | `VERIFIED_FOR_CASES` | V-09 |
| S02 | `S02-remaining-candidate-violation` | Trusted remaining candidate violation (inadequate patch) | `NOT_FIXED` | V-03 |
| S03 | `S03-violation-plus-incomplete-repetition` | Candidate violation plus incomplete repetition | `NOT_FIXED` | V-03 |
| S04 | `S04-candidate-violation-flaky` | Trusted candidate violation in one pair, secure in another (D2) | `NOT_FIXED` | V-03 |
| S05 | `S05-baseline-security-disagreement` | Trusted baseline security outcome disagrees across repetitions | `INCONCLUSIVE` | V-06 |
| S06 | `S06-truncated-stream-apparent-violation` | Truncated stream containing an apparent violation (D3) | `INCONCLUSIVE` | V-05 |
| S07 | `S07-functional-regression-deny-all` | Functional regression with a same-pair baseline pass (deny-all) | `REGRESSION_DETECTED` | V-04 |
| S08 | `S08-candidate-timeout-no-failure` | Candidate per-test timeout without a valid failure observation | `INCONCLUSIVE` | V-05 |
| S09 | `S09-partial-baseline-reproduction` | Partial baseline reproduction (D4) | `NOT_REPRODUCED` | V-08 |
| S10 | `S10-baseline-functional-control-failed` | Baseline functional-control failure | `INCONCLUSIVE` | V-07 |
| S11 | `S11-setup-error-with-completed-violation` | Valid pytest setup failure alongside another completed violation | `NOT_FIXED` | V-03 |
| S12 | `S12-duplicate-observation-cell` | Duplicate observation cell with conflicting content | `INCONCLUSIVE` | V-02 |
| S13 | `S13-abnormal-termination-after-session-end` | Abnormal verifier termination after apparent session completion | `INCONCLUSIVE` | V-05 |
| S14 | `S14-pre-execution-policy-failure` | Runtime policy refused before execution began | `BLOCKED` | V-01 |
| S15 | `S15-post-execution-environment-drift` | Environment drift found after execution began (D5) | `INCONCLUSIVE` | V-02 |
| S16 | `S16-precondition-not-evaluated` | Required precondition not evaluated | `INCONCLUSIVE` | V-02 |
| S17 | `S17-canceled-with-established-violation` | Canceled run with previously established trustworthy violation | `NOT_FIXED` | V-03 |
| S18 | `S18-interrupted-after-clean-pair` | Interrupted run after one clean pair | `INCONCLUSIVE` | V-05 |
| S19 | `S19-baseline-already-secure` | Baseline already secure | `NOT_REPRODUCED` | V-08 |
| S20 | `S20-baseline-startup-failure` | Baseline startup failure, candidate passes | `INCONCLUSIVE` | V-05 |
| S21 | `S21-exit-code-contradicts-reports` | Verifier exit status contradicts its reports | `INCONCLUSIVE` | V-02 |
| S22 | `S22-stale-approval` | Approved pack changed before execution (stale approval) | `BLOCKED` | V-01 |
| S23 | `S23-generic-assertion-in-security-test` | Generic assertion failure in a security test is not a witness | `INCONCLUSIVE` | V-05 |
| S24 | `S24-over-cap-stream-with-apparent-violation` | Over-cap result stream with an apparent violation | `INCONCLUSIVE` | V-05 |
| S25 | `S25-trusted-violation-with-other-pair-over-cap` | Trusted candidate violation in pair 1; pair 2 exceeds its result cap (D6) | `NOT_FIXED` | V-03 |
| S26 | `S26-byte-count-over-cap-despite-complete-status` | Only apparent violation is in a stream whose host byte count exceeds the cap, although its status says COMPLETE (D6) | `INCONCLUSIVE` | V-05 |

## 13. Mapping to `PROJECT_SPEC.md` §8.5 and §17.3

| Spec scenario | Verdict and rule | Corpus |
|---|---|---|
| §8.5 disclosed → blocked, owner works | `VERIFIED_FOR_CASES`, V-09 | S01 |
| §8.5 / §17.2 still disclosed (unchanged or inadequate patch) | `NOT_FIXED`, V-03 | S02 |
| §8.5 / §17.2 every request denied | `REGRESSION_DETECTED`, V-04 | S07 |
| §8.5, §17.3 #2 baseline startup failure | `INCONCLUSIVE`, V-05 | S20 |
| §8.5, §17.3 #1 baseline already secure | `NOT_REPRODUCED`, V-08 | S19 |
| §8.5, §17.3 #7 target prints PASS but the verifier sees disclosure | `NOT_FIXED`, V-03. Target output is not an engine input (section 2). | S02 |
| §8.5, §17.3 #5 required check skipped, xfailed, or xpassed | `INCONCLUSIVE`, V-05 (L2–L5, T3); never verified | — (lifecycle rule) |
| §8.5, §17.3 #10 repetitions disagree | never verified: `INCONCLUSIVE` V-06, or `NOT_FIXED` V-03 when a trusted candidate violation exists | S05, S04 |
| §17.3 #3 candidate timeout or OOM | `INCONCLUSIVE`, V-05, unless other trusted executions establish V-03/V-04; the failed execution's observations are preserved | S08, S03 |
| §17.3 #4 required test not collected | before execution (pack validation): `BLOCKED`, V-01. During the run: collection mismatch makes the stream `IDENTITY_MISMATCH` → `INCONCLUSIVE`, V-02 | S14 pattern, S24 pattern |
| §17.3 #6 approved pack changed | before execution: `BLOCKED`, V-01. After start: `INCONCLUSIVE`, V-02 | S22, S15 pattern |
| §17.3 #8 candidate deletes repository tests | no effect: the pack is external to the snapshot (runner, PP-008) | — |
| §17.3 #9 image or dependency drift | before execution: `BLOCKED`, V-01. After start: `INCONCLUSIVE`, V-02 | S14, S15 |
| §17.3 #11 truncated output or missing completion | `INCONCLUSIVE`, V-05 (local; D3). Malformed: V-02 | S06, S13 |
| §5.2 structured result cap exceeded | that execution untrusted (local; D6): `INCONCLUSIVE`, V-05, unless other trusted executions establish V-03/V-04 | S24, S25, S26 |
| §17.3 #12 evidence changed after creation | integrity verification fails (`evidence verify`, PP-021) | — |

## 14. Properties PP-004 must test

These are in addition to one test per rule and per scenario:

- **P-1 Monotonic safety.** Removing any observation or execution record, or degrading
  any input toward less trust, never changes a non-`VERIFIED_FOR_CASES` result into
  `VERIFIED_FOR_CASES`. Degrading means:
  - a trusted cell becomes untrusted;
  - a stream status becomes non-`COMPLETE`;
  - a precondition becomes non-`PASSED`;
  - termination becomes non-normal.
- **P-2 Order independence.** Permuting `executions` or `observations` does not change
  any field of the output.
- **P-3 Precondition dominance.** If any effective precondition is not `PASSED`, the
  verdict is `BLOCKED` or `INCONCLUSIVE`, and `trusted_cells == 0`.
- **P-4 Verified implies exact completeness.** `VERIFIED_FOR_CASES` implies all of the
  following:
  - the validated matrix contains exactly the `2 × P × T` required keys, with no
    duplicate, unknown, or extra key;
  - every execution is trusted (E1–E4), and
    `pairs_terminated_normally == pairs_with_trusted_evidence == pairs_planned`;
  - every cell is trusted and equals its expectation;
  - every precondition is `PASSED`;
  - `run_termination == normal`;
  - no flag is set.

  Adding any duplicate cell, even a byte-identical one that bypasses the schema in a
  property test, yields V-02.
- **P-5 Trusted candidate violation dominates, and only trusted ones do.** With every
  effective precondition `PASSED`, any input containing at least one trusted candidate
  `VIOLATION_CONFIRMED` cell yields `NOT_FIXED`. That holds regardless of untrusted,
  missing, flaky, or canceled evidence elsewhere. Conversely, a `VIOLATION_CONFIRMED`
  cell that is untrusted never yields `NOT_FIXED` and never sets `candidate_violation`.
  Untrusted includes a truncated, abnormally terminated, or global-failure execution,
  and a non-`COMPLETED` lifecycle.
- **P-6 No baseline, no positive or reproduction verdict.** If every baseline cell is
  untrusted, the verdict is never `VERIFIED_FOR_CASES` or `NOT_REPRODUCED`.
- **P-7 Schema conformance.** Every engine output validates against
  `verdict.schema.json`.
- **P-8 Generic failures are not witnesses.** No sequence of assertion, exception,
  timeout, or setup failures can produce `candidate_violation` without a trusted
  `VIOLATION_CONFIRMED` observation.
- **P-9 Result-cap overflow is local and enforced.** Raising any execution's
  `bytes_received` above `result_cap_bytes` makes exactly that execution's cells
  untrusted. It never changes a verdict to `VERIFIED_FOR_CASES`, never removes a trusted
  violation from another execution, and always yields `RESULT_CAP_EXCEEDED` for that
  pair and side.
