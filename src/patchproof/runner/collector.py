"""Trusted host collector for one verifier event stream (verdict specification 3.1, 4.1; PP-008).

**Input.** The input is only the bytes the host read from the exact verifier container's
attached standard output, bounded at `result_cap_bytes + 1`. Target output, target logs,
HTTP bodies and files are never passed here. The collector:
- parses each line strictly (`VerifierEvent` model, duplicate keys refused);
- enforces the event grammar;
- checks identity against the plan;
- counts what it actually received.

It never repairs, reorders, deduplicates or synthesizes an event or an observation.

**Status classification:**
- `ABSENT`: no bytes at all.
- `OVER_CAP`: more bytes than the cap. Local; no cells are produced, since every cell would
  be untrusted (D6).
- `MALFORMED`: a bad line, a sequence gap or duplicate, a grammar violation, a
  `session_end` whose counts differ from what was received, or anything after
  `session_end`. Global.
- `IDENTITY_MISMATCH`: run, pair or side, the pack hash, the plugin version, or the
  collected list differs from the plan. Global.
- `TRUNCATED`: a valid prefix without `session_end`, including a final partial line.
  Local; the cut-off block becomes `INTERRUPTED`.
- `COMPLETE`: the full grammar, `session_end` counts equal to what was received, and
  within the cap.

Per-test cells come from the accepted PP-007 rules (`core.outcomes.derive_outcome`).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Literal

from ..core.outcomes import BlockGrammarError, derive_outcome
from ..core.records import RecordError, load_record, validate_record
from ..core.records.common import EvidenceRef
from ..core.records.pack import CollectedTest
from ..core.records.run import (
    CollectedPayload,
    Observation,
    ObservationPayload,
    SessionEndPayload,
    SessionStartPayload,
    StreamStatus,
    TestReportPayload,
    VerifierEvent,
)

MAX_EVENT_LINE: Final = 65536


@dataclass(frozen=True)
class StreamIdentity:
    run_id: str
    pair: int
    side: Literal["baseline", "candidate"]
    pack_tree_sha256: str
    plugin_version: str
    collection: tuple[CollectedTest, ...]
    kinds: Mapping[str, Literal["security", "functional"]]


@dataclass(frozen=True)
class CollectedStream:
    status: StreamStatus
    session_end_received: bool
    events_received: int
    bytes_received: int
    failed_reports: int
    cells: tuple[Observation, ...]
    detail: str


class _Stop(Exception):
    def __init__(self, status: StreamStatus, detail: str) -> None:
        self.status = status
        self.detail = detail


def _cell(identity: StreamIdentity, test: CollectedTest, status: StreamStatus,
          events: Sequence[TestReportPayload | ObservationPayload], truncated: bool) -> Observation:
    kind = identity.kinds[test.id]
    derived = derive_outcome(kind, test.id, events, truncated=truncated)
    observations = [e for e in events if isinstance(e, ObservationPayload)]
    refs: list[EvidenceRef] = list(observations[0].evidence_refs) if len(observations) == 1 else []
    return validate_record(Observation, {
        "schema_version": "1.0", "run_id": identity.run_id, "pair": identity.pair, "side": identity.side,
        "test_id": test.id, "nodeid": test.nodeid, "kind": kind, "stream_status": status,
        "lifecycle_outcome": derived.lifecycle_outcome, "semantic_outcome": derived.semantic_outcome,
        "harness_errors": list(derived.harness_errors), "evidence_refs": [r.model_dump() for r in refs],
        "provenance": "verifier-event-stream"}, "observation")


def collect_stream(raw: bytes, identity: StreamIdentity, *, result_cap_bytes: int) -> CollectedStream:
    received = len(raw)
    if received == 0:
        return CollectedStream("ABSENT", False, 0, 0, 0, (), "no events received")
    lines = raw.split(b"\n")
    complete, tail = lines[:-1], lines[-1]
    if received > result_cap_bytes:
        return CollectedStream("OVER_CAP", False, min(len(complete), 100001), min(received, result_cap_bytes + 1),
                               0, (), f"stream exceeded the {result_cap_bytes}-byte result cap")

    tests = list(identity.collection)
    blocks: list[list[TestReportPayload | ObservationPayload]] = []
    current: list[TestReportPayload | ObservationPayload] = []
    failed = observations = events = 0
    session_end = False

    def block_state() -> str:
        reports = [e for e in current if isinstance(e, TestReportPayload)]
        if not reports:
            return "need-setup"
        if reports[0].outcome != "passed":
            return "need-teardown"
        return "need-call-or-observation" if len(reports) == 1 else "need-teardown"

    try:
        for index, line in enumerate(complete):
            if len(line) > MAX_EVENT_LINE:
                raise _Stop("MALFORMED", f"event {index} exceeds the line limit")
            try:
                event = load_record(VerifierEvent, line, contract="verifier-event", max_bytes=MAX_EVENT_LINE)
            except RecordError:
                raise _Stop("MALFORMED", f"event {index} is not a valid verifier event") from None
            if event.seq != index:
                raise _Stop("MALFORMED", f"sequence gap or duplicate at event {index}")
            if (event.run_id, event.pair, event.side) != (identity.run_id, identity.pair, identity.side):
                raise _Stop("IDENTITY_MISMATCH", f"event {index} carries another run, pair or side")
            if session_end:
                raise _Stop("MALFORMED", "event after session_end")
            events += 1
            payload = event.payload
            if index == 0:
                if not isinstance(payload, SessionStartPayload):
                    raise _Stop("MALFORMED", "the stream does not begin with session_start")
                if (payload.pack_tree_sha256, payload.verifier_plugin_version) != (
                        identity.pack_tree_sha256, identity.plugin_version):
                    raise _Stop("IDENTITY_MISMATCH", "pack or plugin identity differs from the plan")
                continue
            if index == 1:
                if not isinstance(payload, CollectedPayload):
                    raise _Stop("MALFORMED", "collected must follow session_start")
                if [(t.id, t.nodeid) for t in payload.tests] != [(t.id, t.nodeid) for t in tests]:
                    raise _Stop("IDENTITY_MISMATCH", "collected tests differ from the approved collection")
                continue
            if isinstance(payload, (SessionStartPayload, CollectedPayload)):
                raise _Stop("MALFORMED", f"repeated {event.type}")
            if isinstance(payload, SessionEndPayload):
                if current or len(blocks) != len(tests):
                    raise _Stop("MALFORMED", "session_end before every collected test reported")
                if (payload.tests_reported, payload.observations_emitted) != (len(tests), observations):
                    raise _Stop("MALFORMED", "session_end counts differ from what was received")
                session_end = True
                continue
            if len(blocks) >= len(tests):
                raise _Stop("MALFORMED", "event for a test after every block completed")
            assert isinstance(payload, (TestReportPayload, ObservationPayload))
            if payload.test_id != tests[len(blocks)].id:
                raise _Stop("MALFORMED", f"event {index} is for the wrong test or out of order")
            state = block_state()
            if isinstance(payload, ObservationPayload):
                if state != "need-call-or-observation":
                    raise _Stop("MALFORMED", f"observation outside the call window at event {index}")
                observations += 1
                current.append(payload)
                continue
            expected = {"need-setup": ("setup",), "need-call-or-observation": ("call",),
                        "need-teardown": ("teardown",)}[state]
            if payload.phase not in expected:
                raise _Stop("MALFORMED", f"unexpected {payload.phase} report at event {index}")
            if payload.outcome == "failed":
                failed += 1
            current.append(payload)
            if payload.phase == "teardown":
                blocks.append(current)
                current = []
        if session_end and tail:
            raise _Stop("MALFORMED", "bytes after session_end")
    except _Stop as stop:
        return CollectedStream(stop.status, session_end, events, received, failed, (), stop.detail)

    status: StreamStatus = "COMPLETE" if session_end else "TRUNCATED"
    try:
        cells = [_cell(identity, tests[i], status, block, False) for i, block in enumerate(blocks)]
        if not session_end and current:
            cells.append(_cell(identity, tests[len(blocks)], status, current, True))
    except BlockGrammarError as exc:
        return CollectedStream("MALFORMED", session_end, events, received, failed, (), str(exc))
    detail = "complete stream" if session_end else f"stream ended without session_end after {events} event(s)"
    return CollectedStream(status, session_end, events, received, failed, tuple(cells), detail)

