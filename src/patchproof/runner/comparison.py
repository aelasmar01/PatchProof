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
   with the accepted PP-004 engine, which is unchanged.
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
from .revision import Clock, RevisionResult, execute_revision
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


def run_comparison(executor: Executor, plan: RunPlan, approvals: Iterable[ApprovalRecord],
                   registry: OwnershipRegistry, *, clock: Clock, evaluated_at: str,
                   approved_images: Iterable[ApprovedRunImage] = APPROVED_RUN_IMAGES,
                   cancel: Callable[[], bool] = lambda: False) -> ComparisonResult:
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
                result = execute_revision(executor, plan, pair, side, registry, clock=clock, cancel=cancel)
                revisions.append(result)
                started = started or result.execution.started
                if result.execution.canceled:
                    termination = "canceled"
                if result.precondition_failure is not None:
                    name, code = result.precondition_failure
                    preconditions[name] = _failed("post_execution" if started else "pre_execution", code)
                    break
            if termination == "canceled" or any(p.state != "PASSED" for p in preconditions.values()):
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
    verdict = evaluate(parse_verdict_input(verdict_input.model_dump()), evaluated_at)
    return ComparisonResult(verdict_input=verdict_input, verdict=verdict, revisions=tuple(revisions))
