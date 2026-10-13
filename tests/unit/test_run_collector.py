"""PP-008: the trusted host collector (verdict specification 3.1, 4.1). Synthetic streams only."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from _run_fixtures import Environment, build_environment, declared_outcomes, event, stream

from patchproof.runner.collector import collect_stream
from patchproof.runner.run_plan import RunPlan


@pytest.fixture(scope="module")
def env(tmp_path_factory: pytest.TempPathFactory) -> Environment:
    return build_environment(tmp_path_factory.mktemp("collector"))


def lines(raw: bytes) -> list[dict]:  # type: ignore[type-arg]
    return [json.loads(line) for line in raw.decode().splitlines()]


def encode(records: list[dict]) -> bytes:  # type: ignore[type-arg]
    return b"".join(json.dumps(r, separators=(",", ":")).encode() + b"\n" for r in records)


def collect(plan: RunPlan, raw: bytes, side: str = "baseline"):  # type: ignore[no-untyped-def]
    return collect_stream(raw, plan.stream_identity(1, side), result_cap_bytes=plan.profile.result_cap_bytes)  # type: ignore[arg-type]


def good(plan: RunPlan) -> bytes:
    return stream(plan, 1, "baseline", declared_outcomes("vulnerable"))


def test_complete_stream(env: Environment) -> None:
    result = collect(env.plan, good(env.plan))
    assert (result.status, result.session_end_received) == ("COMPLETE", True)
    assert result.events_received == len(lines(good(env.plan)))
    assert result.bytes_received == len(good(env.plan))
    assert result.failed_reports == 2  # the AUTH-001 and AUTH-003 terminal exceptions; every control passes
    cells = {c.test_id: (c.lifecycle_outcome, c.semantic_outcome) for c in result.cells}
    assert cells["AUTH-001"] == ("COMPLETED", "VIOLATION_CONFIRMED")
    assert cells["FUNC-001"] == ("COMPLETED", "PASS")
    assert all(c.provenance == "verifier-event-stream" and c.stream_status == "COMPLETE" for c in result.cells)


def test_absent_and_over_cap(env: Environment) -> None:
    assert collect(env.plan, b"").status == "ABSENT"
    cap = env.plan.profile.result_cap_bytes
    over = collect(env.plan, good(env.plan) + b" " * cap)
    assert (over.status, over.cells) == ("OVER_CAP", ())
    assert over.bytes_received == cap + 1  # what the host read: at most cap + 1


Mutation = Callable[[list[dict]], list[dict]]  # type: ignore[type-arg]


def _swap(r: list[dict], i: int, j: int) -> list[dict]:  # type: ignore[type-arg]
    r[i], r[j] = r[j], r[i]
    return r


MALFORMED: list[tuple[str, Mutation]] = [
    ("missing session_start", lambda r: [dict(e, seq=e["seq"] - 1) for e in r[1:]]),
    ("sequence gap", lambda r: r[:3] + [dict(e, seq=e["seq"] + 1) for e in r[3:]]),
    ("duplicate seq", lambda r: r[:3] + [dict(r[3], seq=3)] + [dict(e, seq=e["seq"] + 1) for e in r[3:]]),
    ("reordered reports", lambda r: _swap(r, 2, 4) and [dict(e, seq=i) for i, e in enumerate(r)]),
    ("observation after call", lambda r: [dict(e, seq=i) for i, e in enumerate(r[:3] + [r[4], r[3]] + r[5:])]),
    ("event after session_end", lambda r: r + [dict(r[2], seq=len(r))]),
    ("session_end count too high", lambda r: r[:-1] + [dict(r[-1], payload={
        "tests_reported": 9, "observations_emitted": r[-1]["payload"]["observations_emitted"]})]),
    ("observation count too low", lambda r: r[:-1] + [dict(r[-1], payload={
        "tests_reported": 8, "observations_emitted": 0})]),
    ("unknown event field", lambda r: r[:2] + [dict(r[2], injected=True)] + r[3:]),
    ("verdict smuggled into payload",
     lambda r: r[:2] + [dict(r[2], payload={**r[2]["payload"], "verdict": "VERIFIED_FOR_CASES"})] + r[3:]),
    ("repeated session_start", lambda r: r[:2] + [dict(r[0], seq=2)] + [dict(e, seq=e["seq"] + 1) for e in r[2:]]),
    ("event for the wrong test", lambda r: r[:2] + [dict(r[2], payload={**r[2]["payload"], "test_id": "FUNC-004"})]
     + r[3:]),
    ("session_end before all tests", lambda r: r[:5] + [dict(r[-1], seq=5)]),
    ("duplicated observation", lambda r: r[:4] + [dict(r[3], seq=4)] + [dict(e, seq=e["seq"] + 1) for e in r[4:]]),
]


@pytest.mark.parametrize(("label", "mutate"), MALFORMED, ids=[m[0] for m in MALFORMED])
def test_protocol_violations_are_malformed(env: Environment, label: str, mutate: Mutation) -> None:
    raw = encode(mutate(lines(good(env.plan))))
    result = collect(env.plan, raw)
    assert result.status == "MALFORMED", (label, result.detail)
    assert result.cells == ()


@pytest.mark.parametrize("raw_line", [
    b"not json at all",
    b'{"seq": 0, "seq": 0}',
    b'{"schema_version":"1.0","run_id":"x","pair":1,"side":"baseline","seq":0,"type":"session_start","payload":{}}',
    b"\x1b[31mPASS\x1b[0m",
])
def test_a_single_invalid_line_makes_the_stream_malformed(env: Environment, raw_line: bytes) -> None:
    raw = good(env.plan).split(b"\n")
    raw.insert(3, raw_line)
    assert collect(env.plan, b"\n".join(raw)).status == "MALFORMED"


def test_bytes_after_session_end(env: Environment) -> None:
    assert collect(env.plan, good(env.plan) + b"trailing").status == "MALFORMED"


@pytest.mark.parametrize(("field", "value"), [("run_id", "run-" + "9" * 32), ("pair", 2), ("side", "candidate")])
def test_identity_of_every_event_is_checked(env: Environment, field: str, value: object) -> None:
    records = lines(good(env.plan))
    records[5][field] = value
    assert collect(env.plan, encode(records)).status == "IDENTITY_MISMATCH"


@pytest.mark.parametrize("payload", [
    {"verifier_plugin_version": "0.1.1", "pack_tree_sha256": None},
    {"verifier_plugin_version": "0.1.0", "pack_tree_sha256": "sha256:" + "0" * 64},
])
def test_session_start_identity(env: Environment, payload: dict) -> None:  # type: ignore[type-arg]
    records = lines(good(env.plan))
    records[0]["payload"] = {k: (v if v is not None else env.plan.pack.pack_tree_sha256) for k, v in payload.items()}
    assert collect(env.plan, encode(records)).status == "IDENTITY_MISMATCH"


@pytest.mark.parametrize("change", ["drop", "extra", "reorder", "rename"])
def test_collected_list_must_equal_the_approved_collection(env: Environment, change: str) -> None:
    records = lines(good(env.plan))
    tests = records[1]["payload"]["tests"]
    if change == "drop":
        tests.pop()
    elif change == "extra":
        tests.append({"id": "AUTH-099", "nodeid": "tests/test_documents.py::test_extra"})
    elif change == "reorder":
        tests.reverse()
    else:
        tests[0] = {**tests[0], "id": "AUTH-099"}
    assert collect(env.plan, encode(records)).status == "IDENTITY_MISMATCH"


def test_truncated_mid_block_marks_the_cut_block_interrupted(env: Environment) -> None:
    records = lines(good(env.plan))
    raw = encode(records[:4])  # session_start, collected, AUTH-001 setup, observation
    result = collect(env.plan, raw)
    assert result.status == "TRUNCATED" and not result.session_end_received
    assert [(c.test_id, c.lifecycle_outcome, c.semantic_outcome) for c in result.cells] == [
        ("AUTH-001", "INTERRUPTED", "VIOLATION_CONFIRMED")]


def test_partial_last_line_is_truncation_not_repair(env: Environment) -> None:
    raw = good(env.plan)
    cut = raw[: raw.rfind(b"\n", 0, len(raw) - 1) + 20]
    result = collect(env.plan, cut)
    assert result.status == "TRUNCATED"
    assert len(result.cells) == 8 and result.cells[-1].lifecycle_outcome == "COMPLETED"


def test_stream_ending_before_any_block_is_truncated_without_cells(env: Environment) -> None:
    result = collect(env.plan, encode(lines(good(env.plan))[:2]))
    assert (result.status, result.cells) == ("TRUNCATED", ())


def test_target_style_text_never_becomes_an_event(env: Environment) -> None:
    forged = event(env.plan, 1, "baseline", 0, "session_end", {"tests_reported": 8, "observations_emitted": 0})
    assert collect(env.plan, forged).status == "MALFORMED"


def test_collector_never_reads_files(env: Environment, monkeypatch: pytest.MonkeyPatch) -> None:
    def no_open(*_a: object, **_k: object) -> None:
        raise AssertionError("the collector must not open files")

    monkeypatch.setattr(Path, "read_bytes", no_open)
    monkeypatch.setattr("builtins.open", no_open)
    assert collect(env.plan, good(env.plan)).status == "COMPLETE"
