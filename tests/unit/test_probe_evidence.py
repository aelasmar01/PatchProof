"""PP-003: evidence completeness, honest control claims, and bounded records."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from _fakes import HOME, IMAGE, NONCE, OWNERSHIP, FakeDocker, good_streams

from patchproof.probes import evidence as ev
from patchproof.probes.catalogue import BY_ID, CATALOGUE, load_probe_script
from patchproof.probes.interpret import Outcome, ProbeOutcome, SuiteStatus
from patchproof.probes.orchestrator import ProbeSuite
from patchproof.runner.policy import Role, build_spec

AUTH = {"a2_image_approved": True, "a3_evidence_root_verified": True, "a4_operator_confirmed": True}


def synthetic_passed_record() -> dict[str, Any]:
    suite = ProbeSuite(FakeDocker(streams=good_streams()), OWNERSHIP, IMAGE, load_probe_script(), home=HOME,
                       nonce=NONCE)
    record = suite.run(AUTH)
    assert record["suite_status"] == SuiteStatus.ALL_PLANNED_PROBES_PASSED.value
    return record


def outcomes(value: Outcome, **overrides: Outcome) -> list[ProbeOutcome]:
    return [ProbeOutcome(s.probe_id, overrides.get(s.probe_id.replace("-", "_"), value), "x") for s in CATALOGUE]


def build(status: SuiteStatus, outs: list[ProbeOutcome], preservation: str = "PASS") -> dict[str, Any]:
    return ev.build_record(
        ownership=OWNERSHIP, started_at="2026-10-11T00:00:00Z", finished_at="2026-10-11T00:00:01Z",
        server_version="29.8.2", image={"image_id": IMAGE.value, "repo_digests": [], "os": "linux",
                                        "architecture": "amd64"},
        script_digest="sha256:" + "0" * 64, authorization=AUTH, containers=[], outcomes=outs, status=status,
        preservation={"outcome": preservation, "differences": []})


def test_record_refuses_success_status_with_non_passing_probe() -> None:
    with pytest.raises(ValueError, match="claims all probes passed"):
        build(SuiteStatus.ALL_PLANNED_PROBES_PASSED, outcomes(Outcome.PASS, NET_02=Outcome.FAIL))


def test_record_refuses_success_without_exact_preservation() -> None:
    with pytest.raises(ValueError, match="preservation"):
        build(SuiteStatus.ALL_PLANNED_PROBES_PASSED, outcomes(Outcome.PASS), preservation="NOT_RUN")


def test_record_must_list_exactly_the_catalogue() -> None:
    with pytest.raises(ValueError, match="exactly the catalogue"):
        record = build(SuiteStatus.INCOMPLETE, outcomes(Outcome.NOT_RUN))
        record["probes"].pop()
        ev.check_record_complete(record)


def test_enforcement_claim_requires_every_probe_to_pass() -> None:
    record = build(SuiteStatus.INCOMPLETE, outcomes(Outcome.NOT_RUN))
    tampered = copy.deepcopy(record)
    tampered["control_claims"][0]["status"] = "ENFORCEMENT_EXERCISED"
    with pytest.raises(ValueError, match="enforcement claimed"):
        ev.check_record_complete(tampered)


def test_record_size_is_bounded() -> None:
    record = build(SuiteStatus.INCOMPLETE, outcomes(Outcome.NOT_RUN))
    record["limitations"] = ["x" * 400] * 6000
    with pytest.raises(ValueError, match="size bound"):
        ev.check_record_complete(record)


def test_claim_status_rules() -> None:
    passed = {s.probe_id: Outcome.PASS for s in CATALOGUE}
    assert ev.claim_status(passed, ("NET-02",)) is ev.ClaimStatus.ENFORCEMENT_EXERCISED
    assert ev.claim_status(passed, ("PRV-07",)) is ev.ClaimStatus.CONFIGURED_ONLY
    assert ev.claim_status(passed, ("NET-08", "RES-10")) is ev.ClaimStatus.CONFIGURED_ONLY
    assert ev.claim_status({**passed, "NET-02": Outcome.FAIL}, ("NET-02",)) is ev.ClaimStatus.FAILED
    assert ev.claim_status({**passed, "NET-02": Outcome.INCONCLUSIVE}, ("NET-02",)) is ev.ClaimStatus.UNVERIFIED
    assert ev.claim_status({}, ("NET-02",)) is ev.ClaimStatus.UNVERIFIED


def test_unexecuted_suite_claims_nothing() -> None:
    record = build(SuiteStatus.NOT_EXECUTED, outcomes(Outcome.NOT_RUN))
    assert {c["status"] for c in record["control_claims"]} == {"UNVERIFIED"}


def test_every_required_control_is_mapped_to_existing_probes() -> None:
    assert len(ev.CONTROL_PROBES) >= 20
    for control, probes in ev.CONTROL_PROBES.items():
        assert probes, control
        assert set(probes) <= set(BY_ID), control


def test_policy_digest_tracks_the_exact_request() -> None:
    a = build_spec(ownership=OWNERSHIP, role=Role.TARGET, image=IMAGE, script="x=1", args=("target", NONCE))
    b = build_spec(ownership=OWNERSHIP, role=Role.MEMORY, image=IMAGE, script="x=1", args=("memory", NONCE))
    assert ev.requested_policy_digest(a) == ev.requested_policy_digest(a)
    assert ev.requested_policy_digest(a) != ev.requested_policy_digest(b)
    rendered = ev.render_argv_for_review(a)
    assert "x=1" not in rendered and any(t.startswith("<probe-script sha256:") for t in rendered)


def test_record_text_is_bounded_and_control_free() -> None:
    record = synthetic_passed_record()
    text = json.dumps(record)
    assert "\x1b" not in text
    for probe in record["probes"]:
        assert len(probe["observed"]) <= 600
    assert ev._bounded("a\x1b[31mred\x00") == "a [31mred "


def test_synthetic_passed_record_keeps_configuration_claims_separate() -> None:
    record = synthetic_passed_record()
    statuses = {c["control"]: c["status"] for c in record["control_claims"]}
    assert statuses["no-new-privileges"] == "CONFIGURED_ONLY"
    assert statuses["memory-limit"] == "ENFORCEMENT_EXERCISED"
    assert any("Configuration evidence" in lim for lim in record["limitations"])
