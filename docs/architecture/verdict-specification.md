# Verdict specification

**Issue:** PP-002 · **Status:** `READY_FOR_REVIEW` · **Spec basis:** `PROJECT_SPEC.md` §7.3–§7.5, §8, §10.3, §17.3
**Implements in:** PP-004 (pure engine and truth-table tests). Nothing here is implemented yet.

This document fixes the inputs, the order of evaluation, and the decision table for the
comparison verdict. It is a review-controlled input: PP-004's tests are derived from
the rule IDs below, and changing a rule needs owner review (CLAUDE.md, "Verification
integrity").

Machine-checkable contracts live in `schemas/` (JSON Schema draft 2020-12). Example
records in `schemas/examples/` use placeholder digests made of a repeated hex digit;
they are not real hashes.

---

## 1. Three dimensions, never merged (§8.1)

| Dimension | Values | Defined in |
|---|---|---|
| Run lifecycle | `DRAFT → PREFLIGHT → AWAITING_APPROVAL → QUEUED → RUNNING → FINALIZING → COMPLETE`; terminal alternates `BLOCKED`, `CANCELED`, `INTERRUPTED`; separate cleanup status `PENDING`/`COMPLETE`/`FAILED` | §8.2; persisted in PP-011 |
| Per-test observation | stream status × lifecycle outcome × semantic outcome (section 3) | `observation.schema.json` |
| Comparison verdict | six verdicts (section 6) | `verdict.schema.json` |

A run's lifecycle can be `COMPLETE` with an `INCONCLUSIVE` verdict. A canceled run still
gets a verdict record (normally `INCONCLUSIVE` with `RUN_CANCELED`). The CLI exit code
follows §13.2 and uses the lifecycle for 22 (canceled) and the verdict otherwise.

## 2. Engine inputs

The engine is a pure function. Its input type contains **only**:

1. The approved pack manifest's required-test table (ID, kind, baseline/candidate expectation).
2. The planned pair count from the approved plan.
3. Precondition results (section 5), each `PASSED`, `FAILED`, or `NOT_EVALUATED`, with
   the phase in which any failure was detected (`pre_execution` or `post_execution`).
4. Observation records (section 3), each from `provenance: verifier-event-stream`.
5. Run termination: `normal`, `canceled`, or `interrupted`.

There is no input field for target stdout, target logs, target-created files, target
HTTP status text, or any target-supplied status (INV-09). This is a type-level control:
the engine cannot be handed those values, so it cannot be influenced by them.

## 3. Observation cell

One cell is identified by `(pair, side, test_id)`. For a plan with *P* pairs and *T*
required tests there are exactly `2 × P × T` required cells. A missing cell is treated
as a cell with `stream_status: ABSENT`, `lifecycle_outcome: NOT_RUN`,
`semantic_outcome: NONE`.

**Stream status** (whole pair/side): `COMPLETE`, `TRUNCATED`, `MALFORMED`,
`IDENTITY_MISMATCH`, `OVER_CAP`, `ABSENT`.

**Lifecycle outcome** (pytest cross-check, §7.3): `COMPLETED`, `SETUP_ERROR`,
`CALL_ERROR`, `TEARDOWN_ERROR`, `SKIPPED`, `XFAILED`, `XPASSED`, `TIMED_OUT`, `NOT_RUN`,
`NOT_COLLECTED`.

`COMPLETED` means that setup passed, teardown passed, and the call phase ended in one of
these ways:

- a security test emitted exactly one terminal observation, and the only call-phase
  failure was the helper's own controlled exception (`failure_class: security_terminal`);
- a functional test passed, or failed with `failure_class: assertion`.

Any other exception, timeout, or crash is a different lifecycle outcome.

**Semantic outcome:** security `VIOLATION_CONFIRMED`, `SECURE`, `INCONCLUSIVE`, `NONE`;
functional `PASS`, `FAIL`, `NONE`. A functional cell whose lifecycle is not `COMPLETED`
is always `NONE`, because a timeout is not a failure (enforced by the observation schema).

**Harness errors** (§7.3): missing, multiple, or suppressed terminal observations,
malformed evidence, an error after an observation, an observation on a functional test,
and duplicate reports.

## 4. Trust predicate

A cell is **trusted** if and only if all of the following hold:

| # | Condition |
|---|---|
| T1 | All five preconditions are `PASSED`. |
| T2 | `stream_status == COMPLETE` for that pair/side. |
| T3 | `lifecycle_outcome == COMPLETED`. |
| T4 | `harness_errors` is empty. |
| T5 | `semantic_outcome` ∈ {`VIOLATION_CONFIRMED`, `SECURE`} for security, or ∈ {`PASS`, `FAIL`} for functional. |

**Stream completeness (T2), checked by the host collector in PP-008.** A stream is
`COMPLETE` when it meets all of these:

- `seq` starts at 0 and has no gaps or duplicates;
- there is exactly one `session_start` (first) and one `session_end` (last);
- every event's `run_id`/`pair`/`side` matches the plan;
- `session_start.pack_tree_sha256` equals the approved pack hash;
- the `collected` set equals the approved expected collection exactly;
- every collected test has exactly one setup, call, and teardown report;
- the `session_end` counts match what was received;
- the stream stayed within `result_cap_bytes`.

Anything else marks **the whole pair/side** as untrusted. A terminated verifier
therefore cannot contribute a trustworthy observation from a partial prefix of its
output (§10.3), and that includes a violation (see decision D3 in section 10).

Untrusted cells are preserved and displayed. They are never verdict evidence.

## 5. Preconditions (§8.4, first bullet)

| Precondition | Fails when (examples) | Typical reason codes |
|---|---|---|
| `authorization` | no approval, approval superseded or stale, plan hash changed since approval | `APPROVAL_MISSING`, `APPROVAL_STALE` |
| `pack_integrity` | pack tree hash ≠ approved hash; manifest invalid; pack lacks a functional control or an expected baseline violation | `PACK_INTEGRITY_FAILED`, `PACK_INCOMPLETE_FOR_FIX_VERIFICATION`, `PACK_COLLECTION_MISMATCH` |
| `source_identity` | resolved commit or snapshot hash ≠ plan | `SOURCE_IDENTITY_MISMATCH` |
| `environment_identity` | image IDs, profile hash, or dependency contract differ between sides or from the plan; runtime policy inspection failed | `ENVIRONMENT_NONCOMPARABLE`, `UNSUPPORTED_TARGET_PROFILE`, `RUNTIME_POLICY_FAILED` |
| `result_provenance` | any required stream not `COMPLETE`; evidence artifacts missing or hash mismatch | `EVENT_STREAM_TRUNCATED`, `EVENT_STREAM_MALFORMED`, `EVENT_STREAM_IDENTITY_MISMATCH`, `RESULT_CAP_EXCEEDED`, `EVIDENCE_INCOMPLETE` |

**Exception for `result_provenance`.** A stream that is incomplete because its
execution failed (startup failure, OOM, timeout, cancellation) does not fail the
`result_provenance` precondition. It makes that pair/side's cells untrusted (T2) and is
handled by V-05. `result_provenance` fails only when evidence is malformed,
identity-mismatched, over the cap, or inconsistent with its manifest; those conditions
indicate the result channel itself cannot be trusted. **Owner decision D1.**

## 6. Decision table

Evaluate the rules in order; the first match sets the primary verdict and
`decision_rule`. Flags (section 7) and reason codes are computed independently of the
match, from all evidence, so a later problem is never hidden by an earlier rule
(§8.4, last paragraph).

"Required security expectation" means a pack test with `kind: security`. "Expected
violation test" means a security test with `baseline_expected: VIOLATION_CONFIRMED`.

| Rule | Condition (all previous rules did not match) | Verdict |
|---|---|---|
| **V-01** | A precondition `FAILED`, and the failure was detected **before any container started** (at plan approval, dequeue revalidation, or preflight). | `BLOCKED` |
| **V-02** | A precondition `FAILED` after execution began, for example image or environment drift found on post-start inspection, collection mismatch, malformed or over-cap stream, or an evidence hash mismatch. All observations are untrusted (T1). | `INCONCLUSIVE` |
| **V-03** | At least one **trusted candidate** security cell is `VIOLATION_CONFIRMED` (any pair). | `NOT_FIXED` |
| **V-04** | For some pair *p* and functional test *f*: the trusted candidate cell is `FAIL` and the trusted baseline cell for the same *p*, *f* is `PASS`. | `REGRESSION_DETECTED` |
| **V-05** | Any required cell is untrusted, fewer than the planned pairs completed, or the run was canceled or interrupted. | `INCONCLUSIVE` |
| **V-06** | All cells are trusted, but some `(side, test)` has different semantic outcomes across pairs. | `INCONCLUSIVE` |
| **V-07** | All cells trusted and consistent, but a baseline control is not as expected: a baseline functional cell is `FAIL`, or a baseline security test with `baseline_expected: SECURE` observed `VIOLATION_CONFIRMED`. | `INCONCLUSIVE` |
| **V-08** | All cells trusted and consistent, and baseline controls are as expected, but at least one expected-violation test observed `SECURE` on the baseline. | `NOT_REPRODUCED` |
| **V-09** | Every required cell is trusted and equals its pack expectation on its side, in every planned pair, with all preconditions `PASSED` and no flag set. | `VERIFIED_FOR_CASES` |
| **V-10** | Fallthrough. Unreachable by construction; exists so the engine can never default to a positive verdict. | `INCONCLUSIVE` (`UNCLASSIFIED_EVIDENCE`) |

Notes:

- **V-03 needs no baseline reproduction.** A trusted candidate violation is proof on its
  own (§8.4, second bullet). A violation on a test whose baseline expectation was
  `SECURE` adds the reason `NEW_SECURITY_VIOLATION`. A violation on an expected-violation
  test adds `CANDIDATE_VIOLATION_CONFIRMED`.
- **V-03 beats flakiness.** A violation observed in one pair and `SECURE` in another is
  `NOT_FIXED` with `flaky_observations` set. A demonstrated violation is not erased by a
  later secure run, and rerun-until-green is forbidden (INV-11). **Owner decision D2.**
- **V-04 requires a same-pair trusted baseline `PASS`.** A candidate timeout is not a
  `FAIL` (section 3), and a baseline that did not run cannot anchor a regression, so
  both fall through to V-05.
- **V-08 covers partial reproduction.** If one expected-violation test reproduces and
  another does not, the verdict is `NOT_REPRODUCED` with reason
  `BASELINE_PARTIALLY_REPRODUCED`, and the per-test matrix shows which test did not
  reproduce. **Owner decision D4.**
- **V-09 is the only path to `VERIFIED_FOR_CASES`.** It is defined as exact agreement
  with the pack table, not as the absence of failures.

## 7. Flags (§8.4)

All flags are computed from **trusted** cells only. The exceptions are
`incomplete_checks`, which reflects untrusted cells, and `harness_drift`.

| Flag | Set when |
|---|---|
| `incomplete_checks` | any required cell is untrusted, or pairs completed < pairs planned |
| `candidate_violation` | any trusted candidate security cell is `VIOLATION_CONFIRMED` |
| `functional_regression` | the V-04 condition holds |
| `harness_drift` | the `environment_identity` or `pack_integrity` precondition failed after execution began, or a harness error was recorded |
| `flaky_observations` | the V-06 condition holds for any `(side, test)`, irrespective of the primary verdict |
| `baseline_not_reproduced` | the V-08 condition holds for any expected-violation test |
| `baseline_control_failed` | the V-07 condition holds |

`verdict.schema.json` cross-checks the verdict against its flags. For example, it
rejects `VERIFIED_FOR_CASES` with any flag set, and `INCONCLUSIVE` with
`candidate_violation` set (a trusted violation is always V-03).

## 8. Display (§8.3, §14)

| Verdict | `display_label` | Always shown with |
|---|---|---|
| `VERIFIED_FOR_CASES` | Verified for the selected cases | test count and repetition count, immediately |
| `NOT_FIXED` | Not fixed | the violating test(s) and any incomplete checks |
| `REGRESSION_DETECTED` | Regression detected | the failing control and its baseline pass |
| `NOT_REPRODUCED` | Not reproduced | which expected violation did not reproduce |
| `INCONCLUSIVE` | Inconclusive | every reason code |
| `BLOCKED` | Blocked | the precondition and the specific input requiring attention |

## 9. What the schemas do not enforce

JSON Schema cannot express the following, so they are assigned to code:

| Rule | Owner |
|---|---|
| Duplicate JSON keys and `NaN`/`Infinity` rejected before validation | strict loader, PP-007 (reference behavior tested in `tests/unit/test_schemas.py`) |
| Test IDs and node IDs unique within a pack | pack validation, PP-007 |
| Pack files exist, are bounded, and collection matches the manifest | pack validation, PP-007 |
| Approval bindings equal the current hashes (staleness) | approval check, PP-007 |
| Stream completeness (section 4) | event collector, PP-008 |
| `pairs_completed ≤ pairs_planned`; `VERIFIED_FOR_CASES` requires equality | verdict engine, PP-004 |
| The decision table itself | verdict engine, PP-004 |

Records not yet specified: run authorization / execution plan (PP-007/PP-009), evidence
bundle manifest (PP-009), and source snapshot manifest (PP-005). Each gets a schema in
the issue that first produces it.

## 10. Owner decisions in this specification

These are interpretations where `PROJECT_SPEC.md` admits more than one reading. Each
chosen reading is the conservative one: it can never produce a `VERIFIED_FOR_CASES`
that the alternative would refuse.

| ID | Question | Chosen reading | Alternative |
|---|---|---|---|
| D1 | Does a timeout or crash fail `result_provenance`? | No. It makes that pair/side's cells untrusted, leading to V-05 `INCONCLUSIVE`, and keeps `BLOCKED` for permission failures only. | Treat any incomplete stream as a provenance failure (V-02). Same verdict, but a less specific reason. |
| D2 | A trusted candidate violation in one pair, `SECURE` in another? | `NOT_FIXED` plus `flaky_observations`. | `INCONCLUSIVE`. This would let flakiness mask a demonstrated violation. |
| D3 | A violation observed before the verifier stream was cut off? | Untrusted; the result is `INCONCLUSIVE`, and the observation is preserved and displayed (§17.3 #3, #11). | Count it as `NOT_FIXED` from the partial prefix. Rejected under §10.3. |
| D4 | One expected violation reproduced, another not? | `NOT_REPRODUCED` with `BASELINE_PARTIALLY_REPRODUCED`. | `INCONCLUSIVE`. |
| D5 | Environment drift found after containers started? | V-02 `INCONCLUSIVE`; `BLOCKED` is reserved for "not permitted to run". | `BLOCKED` regardless of phase (§17.3 #9 says `BLOCKED`). Pre-execution drift, the normal case, is `BLOCKED` under both readings. |

## 11. Mapping to §8.5 and §17.3

| Scenario | Expected | Rule |
|---|---|---|
| §8.5 disclosed → blocked, owner works | `VERIFIED_FOR_CASES` once all gates pass | V-09 |
| §8.5 disclosed → still disclosed (§17.2 unchanged / inadequate) | `NOT_FIXED` | V-03 |
| §8.5 disclosed → every request denied | `REGRESSION_DETECTED` | V-04 |
| §8.5 baseline startup failure, candidate passes | `INCONCLUSIVE` | V-05 |
| §8.5 baseline already secure (§17.3 #1) | `NOT_REPRODUCED` | V-08 |
| §8.5 target logs "PASS", independent check sees disclosure (§17.3 #7) | `NOT_FIXED` (logs are not an input) | V-03 |
| §8.5 required candidate test skipped (§17.3 #5) | `INCONCLUSIVE` | V-05 (T3) |
| §8.5 outcomes differ across repetitions (§17.3 #10) | never verified | V-06, or V-03 per D2 |
| §17.3 #2 baseline startup failure | `INCONCLUSIVE` | V-05 |
| §17.3 #3 candidate timeout or OOM | `INCONCLUSIVE`; prior observations preserved | V-05 (D3) |
| §17.3 #4 required test not collected | `BLOCKED` if found at pack validation; else `INCONCLUSIVE` | V-01 / V-02 |
| §17.3 #6 approved pack changed | `BLOCKED` | V-01 |
| §17.3 #8 candidate deletes repository tests | no effect: the pack is external to the snapshot | — (runner, PP-008) |
| §17.3 #9 image or dependency drift | `BLOCKED` | V-01 (V-02 if post-start, D5) |
| §17.3 #11 truncated stream or no completion event | `INCONCLUSIVE` | V-02 / V-05 (D1) |
| §17.3 #12 evidence changed after creation | integrity verification fails | `evidence verify`, PP-021 |

## 12. Properties PP-004 must test

In addition to one test per rule and per row in section 11:

- **P-1 Monotonic safety.** Removing any observation, or downgrading any trusted cell to
  untrusted, never changes a non-`VERIFIED_FOR_CASES` result into `VERIFIED_FOR_CASES`.
- **P-2 Order independence.** Permuting observation order does not change the verdict,
  flags, or reason codes.
- **P-3 Precondition dominance.** If any precondition is `FAILED`, the verdict is
  `BLOCKED` or `INCONCLUSIVE`.
- **P-4 Verified implies complete.** `VERIFIED_FOR_CASES` implies exactly `2 × P × T`
  trusted cells, each matching its expectation.
- **P-5 Candidate violation dominates.** Given passing preconditions, adding one trusted
  candidate `VIOLATION_CONFIRMED` cell yields `NOT_FIXED`.
- **P-6 No-baseline cannot verify.** If every baseline cell is untrusted, the verdict
  is never `VERIFIED_FOR_CASES` or `NOT_REPRODUCED`.
- **P-7 Schema conformance.** Every engine output validates against
  `verdict.schema.json`.
