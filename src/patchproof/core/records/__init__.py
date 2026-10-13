"""Strict Pydantic v2 models for every PatchProof record contract (ADR-008, ADR-002).

`load_record` is the production loader: strict JSON parsing (`patchproof.core.strict_json`)
followed by validation against the model for the named contract. The JSON Schema files in
`schemas/` describe the same contracts; `tests/unit/test_record_parity.py` checks that
both accept and reject the same documents.
"""

from __future__ import annotations

from typing import Any, Final

from pydantic import BaseModel, ValidationError

from ..strict_json import DEFAULT_MAX_BYTES, StrictJsonError, loads_strict
from .authorization import RunAuthorization
from .evidence import IsolationProbeRun, ReferenceFixture, SourceManifest
from .pack import ApprovalRecord, ExecutionProfileV10, ExecutionProfileV11, PackManifest
from .run import Execution, Observation, VerdictInput, VerdictRecord, VerifierEvent

RECORD_MODELS: Final[dict[str, type[BaseModel]]] = {
    "pack-manifest": PackManifest,
    "execution-profile": ExecutionProfileV10,
    "execution-profile.v1.1": ExecutionProfileV11,
    "approval-record": ApprovalRecord,
    "verifier-event": VerifierEvent,
    "observation": Observation,
    "execution": Execution,
    "verdict-input": VerdictInput,
    "verdict": VerdictRecord,
    "isolation-probe-run": IsolationProbeRun,
    "source-manifest": SourceManifest,
    "reference-fixture": ReferenceFixture,
    "run-authorization": RunAuthorization,
}


class RecordError(ValueError):
    """A record failed strict loading or contract validation. The message never echoes input."""

    def __init__(self, contract: str, problems: list[str]) -> None:
        self.contract = contract
        self.problems = problems
        super().__init__(f"{contract}: " + "; ".join(problems[:5]))


def _problems(exc: ValidationError) -> list[str]:
    return [f"{'/'.join(str(p) for p in e['loc']) or '<root>'}: {e['msg']}" for e in exc.errors()]


def validate_record[M: BaseModel](model: type[M], data: Any, contract: str = "record") -> M:
    try:
        return model.model_validate(data, strict=True)
    except ValidationError as exc:
        raise RecordError(contract, _problems(exc)) from None


def load_record[M: BaseModel](model: type[M], raw: bytes, *, contract: str = "record",
                              max_bytes: int = DEFAULT_MAX_BYTES) -> M:
    try:
        data = loads_strict(raw, max_bytes=max_bytes)
    except StrictJsonError as exc:
        raise RecordError(contract, [str(exc)]) from None
    return validate_record(model, data, contract)
