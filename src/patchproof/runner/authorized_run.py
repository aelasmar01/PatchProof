"""Execute one claimed run authorization and persist its evidence (PP-008).

Called only by `patchproof.run_papertrail_once`, after the authorization has been claimed and
the evidence directory created. Everything here uses the accepted runner unchanged
(`run_comparison`, `execute_revision`, the pre-start gate, exact-ID cleanup and the PP-004
verdict engine), through three hooks:

- **Before each revision:** the pack approval, the stored authorization and its claim, and
  the complete plan are re-validated; the plan is recomputed from the current artifacts and
  must equal the frozen plan. Images, pack and source bytes are re-checked again by
  `execute_revision` itself. Before the candidate, the built-in network identities are
  re-listed: if they changed, the container runtime lost continuity (for example a Docker
  Desktop restart) and the run ends `interrupted`.
- **After each revision:** its execution record, observation cells, the verifier's raw
  stream, the untrusted target log and cleanup outcomes are written immediately.
- **Baseline failure policy (owner decision D2, 2026-10-13):** after a baseline
  execution-level failure the candidate is not started. Execution-level failure means the
  engine's own trust rule fails for the execution (readiness, termination, OOM, deadline,
  runtime errors, stream status or cap), a precondition failed, or cleanup did not verify
  removal of both containers. A trusted baseline with unexpected semantic outcomes is not an
  execution-level failure: the candidate runs and the engine classifies the evidence.

The verdict is always the accepted engine's evaluation of host-collected facts. A run that
stops early ends `interrupted`, so it can never be `VERIFIED_FOR_CASES`.

**Three separate states (PROJECT_SPEC.md 8.2, 12.2).** `outcome.json` and the manifest keep:
- *evidence status*: `FINALIZED` only when the engine evaluated the run, no exception or
  signal interrupted it, every evidence file was written, and both inventories are complete;
  otherwise `INCOMPLETE`. A missing manifest (hard kill) is also incomplete.
- *lifecycle*: `COMPLETE` only with finalized evidence and a normal termination; otherwise
  `BLOCKED`, `CANCELED` or `INTERRUPTED`.
- *cleanup status*: `COMPLETE` only when every container this run created is absent from a
  complete after-inventory; otherwise `FAILED`, which needs `patchproof.recover_run`.

`verdict` is set only when the evidence is finalized (`verdict_established`). The engine's
evaluation is always kept as `engine_verdict` and in `verdict.json`, so a trusted candidate
violation is never discarded, while incomplete evidence never establishes any verdict,
`VERIFIED_FOR_CASES` included.
"""

from __future__ import annotations

import hashlib
import json
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final

from ..core.approvals import ApprovalError, ApprovalStore, check_approval
from ..core.records.authorization import RunAuthorization
from ..core.run_authorizations import RunAuthorizationError, RunAuthorizationStore, is_superseded
# The ONLY use of engine internals: D2 must classify an execution exactly as the engine does.
# `engine_execution_trust` below is the boundary, and
# `test_d2_boundary_agrees_with_the_public_engine` pins it to the public `evaluate` result.
from ..core.verdict_input import _execution as engine_execution
from ..core.verdicts import _execution_reasons, _execution_trusted
from .cleanup import CleanupStatus, OwnershipRegistry
from .comparison import ComparisonResult, RevisionGate, run_comparison
from .docker_cli import Executor
from .papertrail_plan import (
    AssembledRun,
    PlanError,
    RunEnvironment,
    assemble_run,
    difference_precondition,
    plan_differences,
)
from .policy import PolicyViolation
from .revision import Clock, RevisionResult
from .run_evidence import EvidenceError, Inventory, RecordingExecutor, RunEvidence, capture_inventory, reconcile

CLEANUP_VERIFIED: Final = frozenset({CleanupStatus.REMOVED, CleanupStatus.FORCE_REMOVED})


def engine_execution_trust(execution_record: Any, result_cap_bytes: int) -> tuple[bool, list[str]]:
    """The accepted engine's execution trust (E1-E4) and execution reason codes, unchanged.

    `execution_record` is an `Execution` record; it is parsed by the engine's own strict
    parser, exactly as `evaluate` sees it.
    """
    execution = engine_execution(execution_record.model_dump(mode="json"), "execution")
    return _execution_trusted(execution, result_cap_bytes), sorted(_execution_reasons(execution, result_cap_bytes))


def execution_failure_reasons(result: RevisionResult, result_cap_bytes: int) -> list[str]:
    """Why a revision is an execution-level failure (D2). Empty: trusted and fully cleaned up."""
    reasons: list[str] = []
    if result.precondition_failure is not None:
        reasons.append(f"PRECONDITION:{result.precondition_failure[0]}:{result.precondition_failure[1]}")
    trusted, codes = engine_execution_trust(result.execution, result_cap_bytes)
    if not trusted:
        reasons.extend(codes or ["EXECUTION_NOT_TRUSTED"])
        if result.execution.stream.status != "COMPLETE":
            reasons.append(f"STREAM_{result.execution.stream.status}")
    if len(result.cleanup) != 2 or any(c.status not in CLEANUP_VERIFIED for c in result.cleanup):
        reasons.append("CLEANUP_INCOMPLETE")
    return list(dict.fromkeys(reasons))


FIXTURE_LIMITATION: Final = ("v0.1 fixed-fixture exception (owner decision D1): one pair, the bound "
                              "synthetic-documents-v1 bytes for both sides, no seed and no seed variation; "
                              "seeded repetition is PP-019")
CONTINUITY_NOTE: Final = ("Built-in network identities are compared before the candidate and after the run. A "
                          "changed ID shows the daemon or its VM restarted; an unchanged ID does NOT prove the "
                          "daemon stayed online.")


@dataclass
class RunOutcome:
    status: str  # evidence: FINALIZED or INCOMPLETE
    lifecycle: str  # COMPLETE, BLOCKED, CANCELED or INTERRUPTED
    verdict: str | None  # established verdict: only with FINALIZED evidence
    engine_verdict: str | None  # the engine's evaluation, whenever it ran
    reason_codes: list[str]
    stop_reason: str | None
    reconciliation: str
    cleanup_complete: bool
    daemon_continuity: str
    evidence_dir: str
    notes: list[str] = field(default_factory=list)


def _stamp(now: datetime) -> str:
    return now.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def execute_authorized_run(env: RunEnvironment, stored: RunAuthorization, stored_raw: bytes, claim_raw: bytes,
                           assembled: AssembledRun, evidence: RunEvidence, executor: Executor, *, clock: Clock,
                           now: Callable[[], datetime]) -> RunOutcome:
    plan_doc = stored.plan
    run_id = plan_doc.run_id
    notes: list[str] = []
    evidence.write("claim.json", claim_raw)
    evidence.write("authorization.json", stored_raw)
    evidence.write("plan.json", _canonical(plan_doc.model_dump(mode="json")) + b"\n")
    evidence.write("pack-approval.json", assembled.approval_raw)
    evidence.write_json("pack-approval-history.json", {
        aid: {"supersedes": r.supersedes, "created_at": r.created_at}
        for aid, r in sorted(assembled.approvals.items())})
    for side, raw in assembled.source_manifests.items():
        evidence.write(f"source-manifest-{side}.json", raw)
    evidence.write_json("collection.json", [c.model_dump() for c in assembled.plan.collection])

    recorder = RecordingExecutor(executor, evidence)
    before = capture_inventory(recorder)
    evidence.write_json("inventory-before.json", before.document())

    registry = OwnershipRegistry(assembled.plan.ownership, journal_path=evidence.path("ownership-journal.jsonl"))
    stop: dict[str, str] = {}
    evidence_failures: list[str] = []
    continuity: dict[str, str] = {}
    cap = assembled.plan.profile.result_cap_bytes

    def revalidate(side: str) -> RevisionGate | None:
        if not before.complete:  # Docker unavailable or unreadable before anything was created
            return RevisionGate(failure=("environment_identity", "RUNTIME_POLICY_FAILED"),
                                note="the before-inventory is incomplete; no container is created")
        try:
            store = ApprovalStore(env.approval_store)
            check = check_approval(store.records().values(), assembled.plan.binding_inputs(),
                                   approval_id=plan_doc.pack_approval_id)
        except ApprovalError as exc:
            return RevisionGate(failure=("authorization", "APPROVAL_MISSING"), note=f"approval store: {exc}")
        if check.status != "APPROVED":
            return RevisionGate(failure=("authorization", check.status), note=f"pack approval is {check.status}")
        try:
            records, claims = RunAuthorizationStore(env.authorization_store).scan()
        except RunAuthorizationError as exc:
            return RevisionGate(failure=("authorization", "APPROVAL_STALE"), note=f"authorization store: {exc}")
        current = records.get(stored.authorization_id)
        claim = claims.get(stored.authorization_id)
        if (current is None or current.raw != stored_raw or claim is None or claim.raw != claim_raw
                or is_superseded(records, stored.authorization_id)):
            return RevisionGate(failure=("authorization", "APPROVAL_STALE"),
                                note="the run authorization or its claim changed, or it was superseded")
        try:
            fresh = assemble_run(env, run_id)
        except PlanError as exc:
            return RevisionGate(failure=(exc.precondition, exc.code), note=f"plan inputs: {exc}")
        if fresh.document != plan_doc:
            sections = plan_differences(plan_doc, fresh.document)
            return RevisionGate(failure=difference_precondition(sections), note=f"plan drift in {sections}")
        if side == "candidate":
            networks = capture_inventory(recorder, ("networks",))
            if not networks.complete or networks.builtin_networks() != before.builtin_networks():
                continuity["before_candidate"] = "BROKEN" if networks.complete else "UNKNOWN"
                return RevisionGate(interrupt=True, note="Docker continuity lost: built-in network identities "
                                                         "changed or could not be listed before the candidate")
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
        # A failed evidence write never aborts the comparison: the containers are already
        # cleaned up, the result stays in memory for the engine, the run is marked
        # incomplete, and `continue_after` stops before the next revision.
        try:
            persist_revision(result)
        except (EvidenceError, OSError) as exc:
            evidence_failures.append(f"pair {result.pair} {result.side}: {type(exc).__name__}: {exc}")

    def persist_revision(result: RevisionResult) -> None:
        tag = f"pair-{result.pair:03d}-{result.side}"
        evidence.write_json(f"execution-{tag}.json", result.execution.model_dump(mode="json"))
        evidence.write(f"observations-{tag}.jsonl",
                       b"".join(_canonical(c.model_dump(mode="json")) + b"\n" for c in result.stream.cells))
        evidence.write(f"verifier-stream-{tag}.bin", result.raw_stream)
        evidence.write(f"untrusted-target-log-{tag}.log", result.target_log)
        evidence.write_json(f"revision-{tag}.json", {
            "pair": result.pair, "side": result.side, "notes": list(result.notes),
            "precondition_failure": list(result.precondition_failure) if result.precondition_failure else None,
            "stream_status": result.stream.status, "verifier_stream_bytes": len(result.raw_stream),
            "verifier_stream_sha256": "sha256:" + hashlib.sha256(result.raw_stream).hexdigest(),
            "target_log_truncated": result.target_log_truncated,
            "cleanup": [{"name": c.name, "container_id": c.container_id, "status": c.status.value,
                         "detail": c.detail} for c in result.cleanup],
            "execution_failure_reasons": execution_failure_reasons(result, cap),
        })

    def continue_after(result: RevisionResult) -> bool:
        if result.side != "baseline":
            return True  # nothing follows the candidate; its evidence state is judged in `_finish`
        if evidence_failures:
            stop.setdefault("reason", "EVIDENCE_WRITE_FAILED: " + "; ".join(evidence_failures))
            return False
        reasons = execution_failure_reasons(result, cap)
        if reasons:
            stop.setdefault("reason", "D2_BASELINE_EXECUTION_FAILURE: " + ", ".join(reasons))
        return not reasons

    comparison: ComparisonResult | None = None
    exception: str | None = None
    try:
        comparison = run_comparison(recorder, assembled.plan, assembled.approvals.values(), registry, clock=clock,
                                    evaluated_at=_stamp(now()), approved_images=env.approved_images,
                                    before_revision=before_revision, continue_after=continue_after,
                                    on_revision=on_revision)
    except KeyboardInterrupt as exc:  # Ctrl-C, or SIGTERM/SIGHUP via runner.interrupts
        # The interrupted revision's own `finally` has already attempted exact-ID cleanup.
        exception = f"INTERRUPTED_BY_{getattr(exc, 'signal_name', 'SIGINT')}"
        notes.append(f"{exception}: the run stopped; no further revision was started")
    except (PolicyViolation, EvidenceError, OSError, ValueError) as exc:
        exception = f"{type(exc).__name__}: {exc}"
        notes.append("".join(traceback.format_exception_only(exc)).strip())
    if comparison is not None:
        for name, value in (("verdict-input.json", comparison.verdict_input.model_dump(mode="json")),
                            ("verdict.json", comparison.verdict)):
            try:
                evidence.write_json(name, value)
            except (EvidenceError, OSError) as exc:
                evidence_failures.append(f"{name}: {type(exc).__name__}: {exc}")
    return _finish(evidence, recorder, before, comparison, registry, stop_reason=stop.get("reason"),
                   notes=notes, exception=exception, evidence_failures=evidence_failures,
                   continuity=continuity, run_id=run_id, stored=stored)


def _finish(evidence: RunEvidence, recorder: RecordingExecutor, before: Inventory,
            comparison: ComparisonResult | None, registry: OwnershipRegistry, *,
            stop_reason: str | None, notes: list[str], exception: str | None, evidence_failures: list[str],
            continuity: dict[str, str], run_id: str, stored: RunAuthorization) -> RunOutcome:
    after = capture_inventory(recorder)
    evidence_failures = list(evidence_failures)
    try:
        evidence.write_json("inventory-after.json", after.document())
    except (EvidenceError, OSError) as exc:
        evidence_failures.append(f"inventory-after.json: {type(exc).__name__}: {exc}")
    owned = [e.container_id.value for e in registry.entries.values() if e.container_id is not None]
    reconciliation = reconcile(before, after, owned)
    try:
        evidence.write_json("reconciliation.json", reconciliation)
    except (EvidenceError, OSError) as exc:
        evidence_failures.append(f"reconciliation.json: {type(exc).__name__}: {exc}")
    # Cleanup is verified by identity: every container this run created must be absent from a
    # complete after-inventory, and no known cleanup outcome may be a refusal or failure.
    cleanup = [c for r in (comparison.revisions if comparison else ()) for c in r.cleanup]
    remaining = [cid for cid in owned if cid in after.resources.get("containers", {})]
    known = [c for c in cleanup if c.status is not CleanupStatus.NOT_CREATED]
    cleanup_complete = after.complete and not remaining and all(c.status in CLEANUP_VERIFIED for c in known)
    engine = comparison.verdict if comparison else None
    termination = comparison.verdict_input.run_termination if comparison else None
    complete = (engine is not None and exception is None and not evidence_failures
                and before.complete and after.complete)
    if engine is not None and engine["verdict"] == "BLOCKED":
        lifecycle = "BLOCKED"
    elif complete and termination == "normal":
        lifecycle = "COMPLETE"
    else:
        lifecycle = "CANCELED" if termination == "canceled" else "INTERRUPTED"
    if continuity.get("before_candidate") == "BROKEN" or reconciliation["daemon_restart_suspected"]:
        daemon_continuity = "BROKEN_SUSPECTED"
    elif continuity.get("before_candidate") == "UNKNOWN" or not (before.complete and after.complete):
        daemon_continuity = "UNKNOWN"
    else:
        daemon_continuity = "NO_CHANGE_OBSERVED"
    outcome = RunOutcome(
        status="FINALIZED" if complete else "INCOMPLETE", lifecycle=lifecycle,
        verdict=engine["verdict"] if engine and complete else None,
        engine_verdict=engine["verdict"] if engine else None,
        reason_codes=list(engine["reason_codes"]) if engine else [],
        stop_reason=stop_reason, reconciliation=reconciliation["status"], cleanup_complete=cleanup_complete,
        daemon_continuity=daemon_continuity, evidence_dir=str(evidence.directory), notes=notes)
    summary = {"run_id": run_id, "authorization_id": stored.authorization_id, "plan_sha256": stored.plan_sha256,
               "pack_approval_id": stored.plan.pack_approval_id,
               "evidence_status": outcome.status, "lifecycle": lifecycle,
               "verdict": outcome.verdict, "verdict_established": outcome.verdict is not None,
               "engine_verdict": outcome.engine_verdict, "reason_codes": outcome.reason_codes,
               "run_termination": termination,
               "revisions_executed": [f"{r.pair}-{r.side}" for r in comparison.revisions] if comparison else [],
               "stop_reason": stop_reason, "exception": exception, "evidence_failures": evidence_failures,
               "containers_created": recorder.creations, "owned_container_ids": owned,
               "remaining_owned_container_ids": remaining,
               "cleanup_status": "COMPLETE" if cleanup_complete else "FAILED", "cleanup_complete": cleanup_complete,
               "reconciliation": reconciliation["status"],
               "daemon_restart_suspected": reconciliation["daemon_restart_suspected"],
               "daemon_continuity": daemon_continuity, "daemon_continuity_note": CONTINUITY_NOTE,
               "fixture": {"mode": stored.plan.fixture.mode, "fixture_sha256": stored.plan.fixture.fixture_sha256,
                           "seed": None, "pairs": stored.plan.repetitions.pairs, "limitation": FIXTURE_LIMITATION},
               "notes": notes}
    evidence.write_json("outcome.json", summary)
    evidence.finalize(status="FINALIZED" if complete else "INCOMPLETE", summary=summary)
    return outcome
