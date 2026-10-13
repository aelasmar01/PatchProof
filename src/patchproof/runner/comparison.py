"""One comparison run: preconditions, revision executions, and the verdict (PROJECT_SPEC.md 8; PP-008).

**Steps:**
1. **Preconditions.** Compute them before anything is created (verdict specification 5.1).
   If any fails, nothing is created or started and the verdict is `BLOCKED`.
2. **Executions.** Execute pairs 1..P, baseline then candidate, each with a fresh target and
   verifier.
   - **First pre-execution failure:** detected before anything in the run started, it stops
     the run as `pre_execution`.
   - **Later failures:** detected after the first start, a failure is `post_execution`
     (D5).
3. **After the run.** Re-verify the pack snapshot. A change during the run fails
   `pack_integrity` post-execution. Streams that are MALFORMED or IDENTITY_MISMATCH fail
   `result_provenance`; the engine enforces this as well (G1).
4. **Verdict.** Assemble the verdict input from host-collected facts only, and evaluate it
   with the accepted PP-004 engine, which is unchanged. `evaluated_at` may be a function: it
   is then called immediately before the engine evaluates, so the record carries the real
   evaluation time rather than the comparison's start.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, Literal

from ..core.records import validate_record
from ..core.records.pack import ApprovalRecord
from ..core.records.run import Precondition, VerdictInput
from ..core.verdict_input import parse_verdict_input
from ..core.verdicts import evaluate
from .cleanup import OwnershipRegistry
from .docker_cli import Executor
from .inputs import InputIntegrityError, verify_pack_snapshot
from .revision import Checkpoint, Clock, RevisionResult, execute_revision
from .run_plan import APPROVED_RUN_IMAGES, ApprovedRunImage, RunPlan, check_preconditions

PRECONDITIONS = ("authorization", "pack_integrity", "source_identity", "environment_identity", "result_provenance")


@dataclass(frozen=True)
class ComparisonResult:
    verdict_input: VerdictInput
    verdict: dict[str, Any]
    revisions: tuple[RevisionResult, ...]


def _failed(phase: Literal["pre_execution", "post_execution"], code: str) -> Precondition:
    return Precondition.model_validate({"state": "FAILED", "detected_phase": phase, "reason_codes": [code]})


def build_verdict_input(plan: RunPlan, preconditions: dict[str, Precondition], revisions: Iterable[RevisionResult],
                        run_termination: Literal["normal", "canceled", "interrupted"]) -> VerdictInput:
    revisions = list(revisions)
    return validate_record(VerdictInput, {
        "schema_version": "1.0", "run_id": plan.ownership.run_id,
        "pack_tests": [t.model_dump() for t in plan.manifest.tests], "pairs_planned": plan.pairs,
        "result_cap_bytes": plan.profile.result_cap_bytes,
        "preconditions": {name: preconditions[name].model_dump() for name in PRECONDITIONS},
        "run_termination": run_termination,
        "executions": [r.execution.model_dump() for r in revisions],
        "observations": [cell.model_dump() for r in revisions for cell in r.stream.cells],
    }, "verdict-input")


@dataclass(frozen=True)
class RevisionGate:
    """A caller's re-validation result before a revision starts (PP-008 authorized runs).

    `failure` fails the named precondition (pre- or post-execution, as for any other
    precondition failure). `interrupt` ends the run as `interrupted` without a precondition
    failure, for example when the container runtime lost continuity.
    """

    failure: tuple[str, str] | None = None
    interrupt: bool = False
    note: str = ""


def _no_gate(pair: int, side: str, started: bool) -> RevisionGate | None:
    return None


def run_comparison(executor: Executor, plan: RunPlan, approvals: Iterable[ApprovalRecord],
                   registry: OwnershipRegistry, *, clock: Clock, evaluated_at: str | Callable[[], str],
                   approved_images: Iterable[ApprovedRunImage] = APPROVED_RUN_IMAGES,
                   cancel: Callable[[], bool] = lambda: False,
                   before_revision: Callable[[int, str, bool], RevisionGate | None] = _no_gate,
                   continue_after: Callable[[RevisionResult], bool] = lambda result: True,
                   on_revision: Callable[[RevisionResult], None] = lambda result: None,
                   checkpoint: Checkpoint | None = None) -> ComparisonResult:
    """Run preconditions, revisions and the verdict.

    The three optional hooks default to no effect. `before_revision` re-validates inputs
    immediately before each revision; `continue_after` lets a scheduling policy stop before
    the next revision (the run then ends `interrupted`, so its evidence is incomplete and can
    never be `VERIFIED_FOR_CASES`); `on_revision` receives each result as soon as it exists,
    so it can be persisted before the next revision starts. `checkpoint` is for the
    interruption test only (`execute_revision`); no production caller passes it.
    """
    preconditions = check_preconditions(plan, approvals, approved_images)
    preconditions["result_provenance"] = Precondition(state="PASSED", detected_phase=None, reason_codes=[])
    revisions: list[RevisionResult] = []
    termination: Literal["normal", "canceled", "interrupted"] = "normal"
    if all(p.state == "PASSED" for p in preconditions.values()):
        started = False
        for pair in range(1, plan.pairs + 1):
            for side in ("baseline", "candidate"):
                if cancel():
                    termination = "canceled"
                    break
                gate = before_revision(pair, side, started)
                if gate is not None and gate.interrupt:
                    termination = "interrupted"
                    break
                if gate is not None and gate.failure is not None:
                    name, code = gate.failure
                    preconditions[name] = _failed("post_execution" if started else "pre_execution", code)
                    break
                result = execute_revision(executor, plan, pair, side, registry, clock=clock, cancel=cancel,
                                          checkpoint=checkpoint)
                revisions.append(result)
                on_revision(result)
                started = started or result.execution.started
                if result.execution.canceled:
                    termination = "canceled"
                if result.interruption is not None:  # interruption test only: never set in production
                    termination = "interrupted"
                    break
                if result.precondition_failure is not None:
                    name, code = result.precondition_failure
                    preconditions[name] = _failed("post_execution" if started else "pre_execution", code)
                    break
                if termination == "normal" and not continue_after(result):
                    termination = "interrupted"
                    break
            if termination != "normal" or any(p.state != "PASSED" for p in preconditions.values()):
                break
        if started:
            try:
                verify_pack_snapshot(plan.pack)
            except InputIntegrityError:
                preconditions["pack_integrity"] = _failed("post_execution", "PACK_INTEGRITY_FAILED")
        for result in revisions:
            status = result.stream.status
            if status in ("MALFORMED", "IDENTITY_MISMATCH") and preconditions["result_provenance"].state == "PASSED":
                code = "EVENT_STREAM_MALFORMED" if status == "MALFORMED" else "EVENT_STREAM_IDENTITY_MISMATCH"
                preconditions["result_provenance"] = _failed("post_execution", code)
    else:
        preconditions["result_provenance"] = Precondition(state="NOT_EVALUATED", detected_phase=None,
                                                          reason_codes=[])
    verdict_input = build_verdict_input(plan, preconditions, revisions, termination)
    parsed = parse_verdict_input(verdict_input.model_dump())
    verdict = evaluate(parsed, evaluated_at() if callable(evaluated_at) else evaluated_at)
    return ComparisonResult(verdict_input=verdict_input, verdict=verdict, revisions=tuple(revisions))
