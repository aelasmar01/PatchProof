"""Execute one claimed interruption-test authorization and persist its evidence (PP-008).

Called only by the dedicated child `patchproof.interruption_child`, after the controller has
claimed the authorization. It uses the accepted runner unchanged (`run_comparison`,
`execute_revision`, the pre-start gate, exact-ID cleanup and the PP-004 verdict engine), with:

- **Baseline only, four independent guards.** `continue_after` stops after the baseline;
  `before_revision` refuses any candidate (`interrupt`); the plan's private engine adapter
  has no candidate source and refuses before anything is created
  (`interruption_plan._BaselineOnlyEnginePlan`); the recorder's container budget is two, so
  a third creation is refused before it reaches Docker.
- **Re-validation before the baseline:** the pack approval, the stored interruption
  authorization and its claim, and the complete recomputed plan must be unchanged.
- **The checkpoint** (`runner.interruption_point`) at `baseline-target-ready`. The SIGTERM it
  waits for is recorded as the revision's interruption; the verifier is never started; both
  containers are removed by exact ID; the run is evaluated by the accepted engine as
  `interrupted`.

**Result contract (PROJECT_SPEC.md 8.2, 8.3, 13.2; owner correction 2026-10-13):**
- *lifecycle* `INTERRUPTED` once execution has started (`BLOCKED` only when a precondition
  failed before anything started; `CANCELED` never arises here);
- *evidence status* always `INCOMPLETE`: by design no verifier observation exists and the
  candidate never runs, so this evidence can never be `FINALIZED`;
- *cleanup status* `COMPLETE` only when both containers are confirmed absent from a complete
  after-inventory and no cleanup outcome is a refusal or failure; otherwise `FAILED`;
- *verdict*: the accepted engine's evaluation of the recorded execution, which for the
  reviewed interruption is `INCONCLUSIVE` by rule `V-05` (missing required observations).
  `VERIFIED_FOR_CASES`, and `BLOCKED` after execution started, are never recorded as the
  verdict: either would be an engine contradiction and is reported as an evidence failure;
- *lifecycle exit code* `lifecycle_exit_code`: 20 for `INTERRUPTED` (lifecycle takes
  precedence), 21 `BLOCKED`, 22 `CANCELED`.

A signal anywhere other than the checkpoint, or any other exception, still cleans up the
revision in progress, but stops before the engine runs: then there is no verdict, the
evidence is `INCOMPLETE` and the lifecycle `INTERRUPTED`. Nothing is ever retried.
"""

from __future__ import annotations

import hashlib
import json
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Final

from ..core.approvals import ApprovalError, ApprovalStore, check_approval
from ..core.interruption_authorizations import (
    InterruptionAuthorizationError,
    InterruptionAuthorizationStore,
    is_superseded,
)
from ..core.records.interruption import InterruptionTestAuthorization
from .authorized_run import CLEANUP_VERIFIED, execution_failure_reasons, timestamp_order
from .cleanup import CleanupResult, OwnershipRegistry
from .comparison import ComparisonResult, RevisionGate, run_comparison
from .docker_cli import Executor
from .interruption_plan import (
    AssembledInterruption,
    assemble_interruption,
    interruption_plan_differences,
)
from .interruption_point import InterruptionPoint
from .papertrail_plan import PlanError, RunEnvironment, difference_precondition
from .policy import PolicyViolation
from .revision import Clock, RevisionResult
from .run_evidence import (
    EvidenceError,
    Inventory,
    RecordingExecutor,
    RunEvidence,
    capture_inventory,
    reconcile,
    utc_stamp,
)

MAX_CONTAINERS: Final = 2
_LIFECYCLE_EXIT: Final = {"INTERRUPTED": 20, "BLOCKED": 21, "CANCELED": 22}
_VERDICT_EXIT: Final = {"VERIFIED_FOR_CASES": 0, "NOT_FIXED": 10, "REGRESSION_DETECTED": 11, "NOT_REPRODUCED": 12,
                        "INCONCLUSIVE": 20, "BLOCKED": 21}


def lifecycle_exit_code(lifecycle: str, verdict: str | None) -> int:
    """PROJECT_SPEC.md 13.2. Lifecycle takes precedence; a COMPLETE run maps its verdict."""
    if lifecycle in _LIFECYCLE_EXIT:
        return _LIFECYCLE_EXIT[lifecycle]
    if lifecycle == "COMPLETE" and verdict in _VERDICT_EXIT:
        return _VERDICT_EXIT[verdict]
    raise ValueError(f"no exit code for lifecycle {lifecycle!r} with verdict {verdict!r}")


@dataclass
class InterruptionOutcome:
    lifecycle: str
    evidence_status: str  # always INCOMPLETE for this plan kind
    cleanup_status: str  # COMPLETE or FAILED
    verdict: str | None
    decision_rule: str | None
    reason_codes: list[str]
    checkpoint_reached: bool
    signal_observed: str | None
    lifecycle_exit_code: int
    matches_expected: bool
    deviations: list[str]
    evidence_dir: str
    notes: list[str] = field(default_factory=list)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass
class OutcomeRegistry(OwnershipRegistry):
    """The accepted registry, also keeping each cleanup outcome in memory.

    Cleanup runs in `execute_revision`'s `finally`, so its outcomes exist even when a signal
    outside the checkpoint means no `RevisionResult` is ever returned.
    """

    outcomes: list[CleanupResult] = field(default_factory=list)

    def record_outcome(self, result: CleanupResult) -> None:
        self.outcomes.append(result)
        super().record_outcome(result)


def write_revision_evidence(evidence: RunEvidence, result: RevisionResult, result_cap_bytes: int) -> list[str]:
    """The revision's files, as `authorized_run` writes them. Returns capture failures (never raises for them)."""
    tag = f"pair-{result.pair:03d}-{result.side}"
    evidence.write_json(f"execution-{tag}.json", result.execution.model_dump(mode="json"))
    evidence.write(f"observations-{tag}.jsonl",
                   b"".join(_canonical(c.model_dump(mode="json")) + b"\n" for c in result.stream.cells))
    evidence.write(f"verifier-stream-{tag}.bin", result.raw_stream)
    outputs: dict[str, Any] = {}
    for prefix, captured in (("untrusted-target-stdout", result.target_stdout),
                             ("untrusted-target-stderr", result.target_stderr),
                             ("untrusted-verifier-console", result.verifier_console)):
        name = f"{prefix}-{tag}.log" if captured.capture == "CAPTURED" else None
        if name is not None:
            evidence.write(name, captured.data)
        outputs[prefix] = {"capture": captured.capture, "detail": captured.detail, "artifact": name,
                           "bytes": len(captured.data), "truncated": captured.truncated,
                           "sha256": "sha256:" + hashlib.sha256(captured.data).hexdigest()}
    failed = [p for p, o in outputs.items() if o["capture"] == "CAPTURE_FAILED"]
    evidence.write_json(f"revision-{tag}.json", {
        "pair": result.pair, "side": result.side, "notes": list(result.notes),
        "precondition_failure": list(result.precondition_failure) if result.precondition_failure else None,
        "interruption": result.interruption,
        "stream_status": result.stream.status, "verifier_stream_bytes": len(result.raw_stream),
        "verifier_stream_sha256": "sha256:" + hashlib.sha256(result.raw_stream).hexdigest(),
        "untrusted_outputs": outputs,
        "cleanup": [{"name": c.name, "container_id": c.container_id, "status": c.status.value,
                     "detail": c.detail} for c in result.cleanup],
        "execution_failure_reasons": execution_failure_reasons(result, result_cap_bytes),
    })
    return [f"pair {result.pair} {result.side}: output capture failed: {failed}"] if failed else []


def execute_interruption_test(env: RunEnvironment, stored: InterruptionTestAuthorization, stored_raw: bytes,
                              claim_raw: bytes, assembled: AssembledInterruption, evidence: RunEvidence,
                              executor: Executor, point: InterruptionPoint, *, clock: Clock,
                              now: Callable[[], datetime]) -> InterruptionOutcome:
    plan_doc = stored.plan
    run_id = plan_doc.run_id
    notes: list[str] = []
    timestamps: dict[str, str | None] = {"execution_started_at": utc_stamp(now()), "evaluated_at": None}
    evidence.write("claim.json", claim_raw)
    evidence.write("authorization.json", stored_raw)
    evidence.write("plan.json", _canonical(plan_doc.model_dump(mode="json")) + b"\n")
    evidence.write("pack-approval.json", assembled.approval_raw)
    evidence.write_json("pack-approval-history.json", {
        aid: {"supersedes": r.supersedes, "created_at": r.created_at}
        for aid, r in sorted(assembled.approvals.items())})
    evidence.write("source-manifest-baseline.json", assembled.source_manifest)
    evidence.write_json("collection.json", [c.model_dump() for c in assembled.plan.collection])

    recorder = RecordingExecutor(executor, evidence, max_creations=MAX_CONTAINERS, wall_clock=now)
    before = capture_inventory(recorder)
    evidence.write_json("inventory-before.json", before.document())
    registry = OutcomeRegistry(assembled.plan.ownership, journal_path=evidence.path("ownership-journal.jsonl"))
    stop: dict[str, str] = {}
    evidence_failures: list[str] = []
    cap = assembled.plan.profile.result_cap_bytes
    candidate_refused: list[bool] = []

    def revalidate(side: str) -> RevisionGate | None:
        if side != "baseline":  # guard 2 of 4: never reached while continue_after stops the run
            candidate_refused.append(True)
            return RevisionGate(interrupt=True, note="the interruption test never executes a candidate")
        if not before.complete:
            return RevisionGate(failure=("environment_identity", "RUNTIME_POLICY_FAILED"),
                                note="the before-inventory is incomplete; no container is created")
        try:
            check = check_approval(ApprovalStore(env.approval_store).records().values(),
                                   assembled.plan.binding_inputs(), approval_id=plan_doc.pack_approval_id)
        except ApprovalError as exc:
            return RevisionGate(failure=("authorization", "APPROVAL_MISSING"), note=f"approval store: {exc}")
        if check.status != "APPROVED":
            return RevisionGate(failure=("authorization", check.status), note=f"pack approval is {check.status}")
        try:
            records, claims = InterruptionAuthorizationStore(env.authorization_store).scan()
        except InterruptionAuthorizationError as exc:
            return RevisionGate(failure=("authorization", "APPROVAL_STALE"), note=f"authorization store: {exc}")
        current, claim = records.get(stored.authorization_id), claims.get(stored.authorization_id)
        if (current is None or current.raw != stored_raw or claim is None or claim.raw != claim_raw
                or is_superseded(records, stored.authorization_id)):
            return RevisionGate(failure=("authorization", "APPROVAL_STALE"),
                                note="the interruption authorization or its claim changed, or it was superseded")
        try:
            fresh = assemble_interruption(env, run_id)
        except PlanError as exc:
            return RevisionGate(failure=(exc.precondition, exc.code), note=f"plan inputs: {exc}")
        if fresh.document != plan_doc:
            sections = interruption_plan_differences(plan_doc, fresh.document)
            return RevisionGate(failure=difference_precondition(sections), note=f"plan drift in {sections}")
        return None

    def before_revision(pair: int, side: str, started: bool) -> RevisionGate | None:
        gate = revalidate(side)
        evidence.append_line("revalidation.jsonl", {"pair": pair, "side": side, "started": started,
                                                    "passed": gate is None, "note": gate.note if gate else "",
                                                    "failure": list(gate.failure) if gate and gate.failure else None,
                                                    "interrupt": bool(gate and gate.interrupt)})
        if gate is not None:
            stop.setdefault("reason", f"REVALIDATION_FAILED before {side}: {gate.note}")
        return gate

    def on_revision(result: RevisionResult) -> None:
        try:
            evidence_failures.extend(write_revision_evidence(evidence, result, cap))
        except (EvidenceError, OSError) as exc:
            evidence_failures.append(f"pair {result.pair} {result.side}: {type(exc).__name__}: {exc}")

    def continue_after(result: RevisionResult) -> bool:  # guard 1 of 4
        stop.setdefault("reason", "BASELINE_ONLY: the interruption test never executes a candidate")
        return False

    def evaluation_time() -> str:
        stamp = utc_stamp(now())
        timestamps["evaluated_at"] = stamp
        return stamp

    comparison: ComparisonResult | None = None
    exception: str | None = None
    try:
        comparison = run_comparison(recorder, assembled.plan, assembled.approvals.values(), registry, clock=clock,
                                    evaluated_at=evaluation_time, approved_images=env.approved_images,
                                    before_revision=before_revision, continue_after=continue_after,
                                    on_revision=on_revision, checkpoint=point)
    except KeyboardInterrupt as exc:  # a signal outside the checkpoint: cleaned up, not evaluable
        exception = f"INTERRUPTED_BY_{getattr(exc, 'signal_name', 'SIGINT')}"
        notes.append(f"{exception} outside the checkpoint: the engine did not evaluate the run")
    except (PolicyViolation, EvidenceError, OSError, ValueError) as exc:
        exception = f"{type(exc).__name__}: {exc}"
        notes.append("".join(traceback.format_exception_only(exc)).strip())
    finally:
        point.close()
    if comparison is not None:
        for name, value in (("verdict-input.json", comparison.verdict_input.model_dump(mode="json")),
                            ("verdict.json", comparison.verdict)):
            try:
                evidence.write_json(name, value)
            except (EvidenceError, OSError) as exc:
                evidence_failures.append(f"{name}: {type(exc).__name__}: {exc}")
    interruption = {
        "stage": plan_doc.interruption.stage, "checkpoint_reached": point.report is not None,
        "report": point.report, "signal_observed": point.observed,
        "reported_at_monotonic": point.reported_at_monotonic, "observed_at_monotonic": point.observed_at_monotonic,
        "synchronization_wait_seconds": point.wait_seconds,
        "revision_interruption": [r.interruption for r in comparison.revisions] if comparison else None,
        "candidate_refused_by_gate": bool(candidate_refused),
    }
    try:
        evidence.write_json("interruption.json", interruption)
    except (EvidenceError, OSError) as exc:
        evidence_failures.append(f"interruption.json: {type(exc).__name__}: {exc}")
    return _finish(evidence, recorder, before, comparison, registry, point, stored=stored,
                   stop_reason=stop.get("reason"), notes=notes, exception=exception,
                   evidence_failures=evidence_failures, timestamps=timestamps, now=now)


def _finish(evidence: RunEvidence, recorder: RecordingExecutor, before: Inventory,
            comparison: ComparisonResult | None, registry: OutcomeRegistry, point: InterruptionPoint, *,
            stored: InterruptionTestAuthorization, stop_reason: str | None, notes: list[str], exception: str | None,
            evidence_failures: list[str], timestamps: dict[str, str | None],
            now: Callable[[], datetime]) -> InterruptionOutcome:
    after = capture_inventory(recorder)
    failures = list(evidence_failures)
    finished_at = utc_stamp(now())
    times = {**timestamps, "execution_finished_at": finished_at}
    times["order"] = timestamp_order(times["execution_started_at"], times["evaluated_at"], finished_at)
    if comparison is not None and comparison.verdict["evaluated_at"] != times["evaluated_at"]:
        failures.append("the verdict's evaluated_at is not the recorded evaluation time")
    try:
        evidence.write_json("inventory-after.json", after.document())
    except (EvidenceError, OSError) as exc:
        failures.append(f"inventory-after.json: {type(exc).__name__}: {exc}")
    owned = [e.container_id.value for e in registry.entries.values() if e.container_id is not None]
    reconciliation = reconcile(before, after, owned)
    try:
        evidence.write_json("reconciliation.json", reconciliation)
    except (EvidenceError, OSError) as exc:
        failures.append(f"reconciliation.json: {type(exc).__name__}: {exc}")
    # Every container this run created must have a verified removal of its own exact ID, and
    # be absent from a complete after-inventory.
    cleanup = list(registry.outcomes)
    remaining = [cid for cid in owned if cid in after.resources.get("containers", {})]
    removed = {c.container_id for c in cleanup if c.status in CLEANUP_VERIFIED}
    cleanup_complete = (after.complete and not remaining and set(owned) <= removed
                        and all(c.status in CLEANUP_VERIFIED for c in cleanup))
    failures.extend(recorder.failures)

    engine = comparison.verdict if comparison else None
    termination = comparison.verdict_input.run_termination if comparison else None
    started = bool(engine and engine["execution_started"]) or any(
        r.op_name == "start" for r in recorder.results)
    verdict: str | None = None
    if engine is not None:
        allowed = {"INCONCLUSIVE"} if engine["execution_started"] else {"INCONCLUSIVE", "BLOCKED"}
        if engine["verdict"] in allowed:
            verdict = engine["verdict"]
        else:  # an engine contradiction: kept in verdict.json, never presented as this run's verdict
            failures.append(f"the engine evaluated {engine['verdict']} for an interruption test; not recorded "
                            "as the verdict")
    if engine is not None and engine["verdict"] == "BLOCKED" and not started:
        lifecycle = "BLOCKED"
    elif termination == "canceled":
        lifecycle = "CANCELED"
    else:
        lifecycle = "INTERRUPTED"
    exit_code = lifecycle_exit_code(lifecycle, verdict)
    revisions = [f"{r.pair}-{r.side}" for r in comparison.revisions] if comparison else []
    started_ops = [r.op_name for r in recorder.results if r.op_name in ("start", "start-attached")]
    expected = stored.plan.expected_outcome
    cleanup_status = "COMPLETE" if cleanup_complete else "FAILED"
    decision_rule: str | None = engine["decision_rule"] if engine and verdict else None
    observed: dict[str, Any] = {"lifecycle": lifecycle, "evidence_status": "INCOMPLETE",
                                "cleanup_status": cleanup_status, "verdict": verdict, "decision_rule": decision_rule,
                                "lifecycle_exit_code": exit_code}
    deviations = [f"{k}: expected {v}, observed {observed[k]}" for k, v in expected.model_dump().items()
                  if observed[k] != v]
    if point.observed != stored.plan.interruption.signal:
        deviations.append(f"signal: expected {stored.plan.interruption.signal} at the checkpoint, observed "
                          f"{point.observed}")
    if started_ops != ["start"] or recorder.creations != MAX_CONTAINERS or revisions != ["1-baseline"]:
        deviations.append(f"execution: expected one baseline revision, two creations and one start; observed "
                          f"{revisions}, {recorder.creations} creations, starts {started_ops}")
    if failures or exception:
        deviations.append("evidence capture or execution raised; see evidence_failures and exception")

    outcome = InterruptionOutcome(
        lifecycle=lifecycle, evidence_status="INCOMPLETE", cleanup_status=cleanup_status,
        verdict=verdict, decision_rule=decision_rule,
        reason_codes=list(engine["reason_codes"]) if engine else [], checkpoint_reached=point.report is not None,
        signal_observed=point.observed, lifecycle_exit_code=exit_code, matches_expected=not deviations,
        deviations=deviations, evidence_dir=str(evidence.directory), notes=notes)
    summary = {
        "run_id": stored.plan.run_id, "authorization_kind": stored.kind, "authorization_id": stored.authorization_id,
        "plan_kind": stored.plan.plan_kind, "plan_sha256": stored.plan_sha256,
        "pack_approval_id": stored.plan.pack_approval_id,
        "evidence_status": "INCOMPLETE",
        "evidence_status_reason": "deliberate interruption: no verifier observation exists and no candidate runs",
        "lifecycle": lifecycle, "lifecycle_exit_code": exit_code,
        "cleanup_status": cleanup_status, "cleanup_complete": cleanup_complete,
        "verdict": verdict, "verdict_source": "accepted PP-004 engine, evaluated on the recorded execution"
        if verdict else None, "verified": False,
        "decision_rule": decision_rule, "engine_verdict": engine["verdict"] if engine else None,
        "reason_codes": outcome.reason_codes, "execution_started": started, "run_termination": termination,
        "checkpoint_reached": outcome.checkpoint_reached, "signal_observed": point.observed,
        "revisions_executed": revisions, "candidate_executed": any(r.endswith("candidate") for r in revisions),
        "containers_created": recorder.creations, "start_operations": started_ops, "verifier_started": any(
            op == "start-attached" for op in started_ops),
        "owned_container_ids": owned, "remaining_owned_container_ids": remaining,
        "cleanup": [{"name": c.name, "container_id": c.container_id, "status": c.status.value} for c in cleanup],
        "reconciliation": reconciliation["status"],
        "daemon_restart_suspected": reconciliation["daemon_restart_suspected"],
        "stop_reason": stop_reason, "exception": exception, "evidence_failures": failures,
        "expected_outcome": expected.model_dump(), "matches_expected": outcome.matches_expected,
        "deviations": deviations, "timestamps": times, "notes": notes,
    }
    evidence.write_json("outcome.json", summary)
    evidence.finalize(status="INCOMPLETE", summary=summary)
    return outcome
