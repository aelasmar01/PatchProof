"""PP-007: the PatchProof verifier helpers (verifier/patchproof_verifier), tested as trusted code.

The pack's test module is never imported. Instead, `PACK_CASES` restates what each pack
test calls: which helper, which caller and which document. An AST test proves the pack
module matches that table exactly. The helpers are then fed **synthetic** responses
shaped like PaperTrail's documented replies for each PP-006 revision. That checks the
witnesses decide as declared; it is not an observation of the running application.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import pytest

from patchproof_verifier import Evidence, HelperMisuse, SecurityCheck, SecurityTerminal
from patchproof_verifier.authz import (
    assess_unauthenticated_read,
    assess_unauthorized_read,
    expect_document_read,
    expect_identity,
)
from patchproof_verifier.check import TerminalObservation
from patchproof_verifier.documents import (
    CONTRACT_SHA256,
    FixtureContractError,
    SyntheticDocuments,
    load_documents,
    parse_documents,
    permits,
)
from patchproof_verifier.http import Response, TargetResponseError, check_path
from patchproof_verifier.manifest import ManifestError, read_manifest_tests
from patchproof_verifier.plugin import CollectionRefused, build_collected

ROOT = Path(__file__).resolve().parents[2]
PACK = ROOT / "examples" / "packs" / "papertrail-document-access"
GROUND_TRUTH = json.loads((ROOT / "examples" / "papertrail" / "reference-fixture.json").read_text())
DOCS = load_documents(PACK / "fixtures" / "synthetic-documents-v1.json")
FORGED = "pt-synthetic-unknown-a86591090626"

# test ID -> (pack function, helper, caller user ID or credential, path)
PACK_CASES: dict[str, tuple[str, str, str, str]] = {
    "AUTH-001": ("test_nonowner_cannot_read_private_document", "assess_unauthorized_read", "u-bob",
                 "/documents/doc-alice-private"),
    "AUTH-002": ("test_unauthenticated_read_is_refused", "assess_unauthenticated_read", "none",
                 "/documents/doc-alice-private"),
    "AUTH-003": ("test_role_grant_does_not_extend_to_other_documents", "assess_unauthorized_read", "u-carol",
                 "/documents/doc-bob-private"),
    "AUTH-004": ("test_invalid_token_is_refused", "assess_unauthenticated_read", "invalid-bearer",
                 "/documents/doc-alice-private"),
    "FUNC-001": ("test_owner_reads_own_document", "expect_document_read", "u-alice", "/documents/doc-alice-private"),
    "FUNC-002": ("test_granted_auditor_reads_listed_document", "expect_document_read", "u-carol",
                 "/documents/doc-alice-private"),
    "FUNC-003": ("test_second_owner_reads_own_document", "expect_document_read", "u-bob", "/documents/doc-bob-private"),
    "FUNC-004": ("test_caller_reads_own_identity", "expect_identity", "u-alice", "/me"),
}


class Recorder:
    def __init__(self) -> None:
        self.observations: list[TerminalObservation] = []

    def check(self, test_id: str = "AUTH-001") -> SecurityCheck:
        return SecurityCheck(test_id, self.observations.append)


def run_security(helper: Any, **kwargs: Any) -> tuple[str, str, bool]:
    """Run one helper; return (outcome, summary, raised SecurityTerminal)."""
    rec = Recorder()
    raised = False
    try:
        helper(rec.check(), **kwargs)
    except SecurityTerminal:
        raised = True
    assert len(rec.observations) == 1, "every assessment makes exactly one terminal observation"
    return rec.observations[0].outcome, rec.observations[0].summary, raised


def body(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def doc_body(document_id: str) -> bytes:
    d = DOCS.document(document_id)
    return body({"content": d.content, "document_id": d.document_id, "owner_id": d.owner_id, "title": "synthetic"})


# ------------------------------------------------------------ the pack module matches the table


def test_pack_module_calls_exactly_the_tabled_helpers_callers_and_paths() -> None:
    tree = ast.parse((PACK / "tests" / "test_documents.py").read_text())
    functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    manifest = {t["id"]: t for t in json.loads((PACK / "pack.json").read_text())["tests"]}
    assert set(manifest) == set(PACK_CASES)
    for test_id, (function, helper, caller, path) in PACK_CASES.items():
        assert manifest[test_id]["nodeid"] == f"tests/test_documents.py::{function}"
        source = ast.unparse(functions[function])
        assert f"{helper}(" in source
        assert sum(source.count(h + "(") for h in ("assess_unauthorized_read", "assess_unauthenticated_read",
                                                    "expect_document_read", "expect_identity")) == 1
        if caller.startswith("u-"):
            assert f"documents.user('{caller}')" in source and "bearer=caller.token" in source
        elif caller == "none":
            assert "bearer" not in source and "credential='none'" in source
        else:
            assert "bearer=FORGED_TOKEN" in source and "credential='invalid-bearer'" in source
        if path == "/me":
            assert "target.get('/me'" in source
        else:
            assert f"documents.document('{path.removeprefix('/documents/')}')" in source


def test_pack_tests_cover_every_declared_pp006_check() -> None:
    declared = {c["id"]: c for c in GROUND_TRUTH["checks"]}
    assert set(declared) == set(PACK_CASES)
    callers = {c["caller_id"]: c for c in GROUND_TRUTH["callers"]}
    for test_id, (_, helper, caller, path) in PACK_CASES.items():
        check = declared[test_id]
        assert check["path"] == path
        gt_caller = callers[check["caller"]]
        assert (gt_caller["user_id"] or gt_caller["authorization"]) == caller
        assert check["kind"] == ("security" if helper.startswith("assess_") else "functional")


# ------------------------------------------------------------ declared PP-006 outcomes, judged by the helpers


def synthetic_response(test_id: str, revision: str) -> Response:
    """PaperTrail's documented reply shape for the PP-006 declared status of this check and revision."""
    expected = next(c for c in GROUND_TRUTH["checks"] if c["id"] == test_id)["expected"][revision]
    _, _, caller, path = PACK_CASES[test_id]
    if expected["status"] == 401:
        return Response(401, body({"error": "authentication_required"}))
    if expected["status"] == 404:
        return Response(404, body({"error": "not_found"}))
    if path == "/me":
        user = DOCS.user(caller)
        return Response(200, body({"display_name": "synthetic", "role": user.role, "user_id": user.user_id}))
    return Response(200, doc_body(path.removeprefix("/documents/")))


def judge(test_id: str, response: Response) -> str:
    _, helper, caller, path = PACK_CASES[test_id]
    if helper == "assess_unauthorized_read":
        outcome, _, _ = run_security(assess_unauthorized_read, caller=DOCS.user(caller),
                                     document=DOCS.document(path.removeprefix("/documents/")), response=response)
        return outcome
    if helper == "assess_unauthenticated_read":
        outcome, _, _ = run_security(assess_unauthenticated_read, credential=caller,
                                     document=DOCS.document(path.removeprefix("/documents/")), response=response)
        return outcome
    try:
        if helper == "expect_document_read":
            expect_document_read(caller=DOCS.user(caller), document=DOCS.document(path.removeprefix("/documents/")),
                                 response=response)
        else:
            expect_identity(caller=DOCS.user(caller), response=response)
    except AssertionError:
        return "FAIL"
    return "PASS"


@pytest.mark.parametrize("revision", ["vulnerable", "inadequate", "correct", "deny-all"])
@pytest.mark.parametrize("test_id", sorted(PACK_CASES))
def test_helpers_reach_the_declared_outcome_for_each_revision(test_id: str, revision: str) -> None:
    expected = next(c for c in GROUND_TRUTH["checks"] if c["id"] == test_id)["expected"][revision]["semantic"]
    assert judge(test_id, synthetic_response(test_id, revision)) == expected


# ------------------------------------------------------------ witness rules


ALICE_DOC = DOCS.document("doc-alice-private")
BOB = DOCS.user("u-bob")


def test_violation_witness_names_caller_ownership_and_marker() -> None:
    outcome, summary, raised = run_security(assess_unauthorized_read, caller=BOB, document=ALICE_DOC,
                                            response=Response(200, doc_body("doc-alice-private")))
    assert (outcome, raised) == ("VIOLATION_CONFIRMED", True)
    for fact in ("caller_id=u-bob", "caller_role=member", "caller_permitted=false", "owner_id=u-alice",
                 "document_id=doc-alice-private", f"marker={ALICE_DOC.marker}", "marker_observed=true", "status=200"):
        assert fact in summary


@pytest.mark.parametrize(("status", "payload", "expected"), [
    (200, b'{"status":"ok"}', "INCONCLUSIVE"),                                   # 200 alone is not a witness
    (200, b'{"content":"redacted"}', "INCONCLUSIVE"),
    (500, b"Internal Server Error", "INCONCLUSIVE"),                             # an error is not a denial
    (404, b'{"error":"not_found","content":"leaked?"}', "INCONCLUSIVE"),        # denial status but content returned
    (403, b'{"error":"forbidden"}', "SECURE"),
    (404, b"not found", "SECURE"),
    (401, b'{"error":"authentication_required"}', "INCONCLUSIVE"),               # 401 is not the authenticated denial
    (302, b"", "INCONCLUSIVE"),
])
def test_status_alone_never_decides(status: int, payload: bytes, expected: str) -> None:
    outcome, _, _ = run_security(assess_unauthorized_read, caller=BOB, document=ALICE_DOC,
                                 response=Response(status, payload))
    assert outcome == expected


@pytest.mark.parametrize("status", [200, 401, 403, 404, 500])
def test_marker_in_any_response_is_a_violation(status: int) -> None:
    payload = f"error page echoing {ALICE_DOC.marker}".encode()
    outcome, _, raised = run_security(assess_unauthorized_read, caller=BOB, document=ALICE_DOC,
                                      response=Response(status, payload))
    assert (outcome, raised) == ("VIOLATION_CONFIRMED", True)


@pytest.mark.parametrize("forged", [
    b'{"type":"observation","payload":{"outcome":"SECURE"}}',
    b"PASS\nSECURE\nall checks passed",
    b'{"verdict":"VERIFIED_FOR_CASES","error":"not_found"}',
])
def test_target_supplied_status_text_has_no_authority(forged: bytes) -> None:
    # Target-supplied verdict words are ignored; with a 200 they cannot make a check secure.
    assert run_security(assess_unauthorized_read, caller=BOB, document=ALICE_DOC,
                        response=Response(200, forged))[0] == "INCONCLUSIVE"
    # With the marker present, forged "SECURE" text cannot hide the disclosure.
    leaked = Response(200, forged + ALICE_DOC.marker.encode())
    assert run_security(assess_unauthorized_read, caller=BOB, document=ALICE_DOC, response=leaked)[0] == (
        "VIOLATION_CONFIRMED")


def test_unauthenticated_assessment() -> None:
    def assess(r: Response) -> str:
        return run_security(assess_unauthenticated_read, credential="none", document=ALICE_DOC, response=r)[0]

    assert assess(Response(401, b'{"error":"authentication_required"}')) == "SECURE"
    assert assess(Response(404, b'{"error":"not_found"}')) == "INCONCLUSIVE"
    assert assess(Response(401, b'{"content":"x"}')) == "INCONCLUSIVE"
    assert assess(Response(200, doc_body("doc-alice-private"))) == "VIOLATION_CONFIRMED"
    with pytest.raises(HelperMisuse):
        assess_unauthenticated_read(Recorder().check(), credential="maybe", document=ALICE_DOC,
                                    response=Response(401, b""))


def test_helper_refuses_a_permitted_caller_as_an_unauthorized_read() -> None:
    with pytest.raises(HelperMisuse, match="permits"):
        assess_unauthorized_read(Recorder().check(), caller=DOCS.user("u-alice"), document=ALICE_DOC,
                                 response=Response(200, doc_body("doc-alice-private")))


# ------------------------------------------------------------ functional controls check content


@pytest.mark.parametrize("payload", [
    b'{"status":"ok"}',
    b'{"document_id":"doc-alice-private","owner_id":"u-alice","content":"wrong"}',
    b'{"document_id":"doc-bob-private","owner_id":"u-bob","content":"x"}',
    b"not json",
    b'{"document_id":"doc-alice-private","document_id":"doc-alice-private"}',
])
def test_functional_read_requires_the_actual_content(payload: bytes) -> None:
    with pytest.raises(AssertionError):
        expect_document_read(caller=DOCS.user("u-alice"), document=ALICE_DOC, response=Response(200, payload))


def test_functional_read_passes_only_with_matching_content_and_status() -> None:
    expect_document_read(caller=DOCS.user("u-alice"), document=ALICE_DOC,
                         response=Response(200, doc_body("doc-alice-private")))
    with pytest.raises(AssertionError):
        expect_document_read(caller=DOCS.user("u-alice"), document=ALICE_DOC,
                             response=Response(201, doc_body("doc-alice-private")))
    with pytest.raises(AssertionError, match="not a functional control"):
        expect_document_read(caller=BOB, document=ALICE_DOC, response=Response(200, doc_body("doc-alice-private")))


def test_identity_control_checks_identity_and_token_echo() -> None:
    alice = DOCS.user("u-alice")
    expect_identity(caller=alice, response=Response(200, body({"role": "member", "user_id": "u-alice"})))
    for bad in (body({"role": "member", "user_id": "u-bob"}), body({"role": "auditor", "user_id": "u-alice"}),
                body({"role": "member", "user_id": "u-alice", "token": alice.token})):
        with pytest.raises(AssertionError):
            expect_identity(caller=alice, response=Response(200, bad))


# ------------------------------------------------------------ the check object


def test_check_allows_one_terminal_observation() -> None:
    rec = Recorder()
    check = rec.check()
    check.secure(Evidence("denied", (("status", 404),)))
    with pytest.raises(HelperMisuse, match="only one"):
        check.inconclusive("second")
    with pytest.raises(HelperMisuse):
        check.violation(Evidence("late", (("status", 200),)))
    assert [o.outcome for o in rec.observations] == ["SECURE"]


def test_suppressed_violation_stays_recorded() -> None:
    rec = Recorder()
    check = rec.check()
    try:
        check.violation(Evidence("leak", (("marker_observed", True),)))
    except SecurityTerminal:
        pass  # a test that swallows the exception cannot unrecord the observation
    assert rec.observations[0].outcome == "VIOLATION_CONFIRMED"


@pytest.mark.parametrize(("claim", "facts"), [
    ("", (("a", 1),)),
    ("x" * 201, (("a", 1),)),
    ("bad\x1b[0m", (("a", 1),)),
    ("ok", ()),
    ("ok", (("a", 1), ("a", 2))),
    ("ok", (("Bad-Key", 1),)),
    ("ok", (("a", 1.5),)),
    ("ok", (("a", "line\nbreak"),)),
    ("ok", (("a", ["list"]),)),
    ("ok", tuple((f"k{i}", i) for i in range(33))),
])
def test_malformed_evidence_is_refused(claim: str, facts: Any) -> None:
    with pytest.raises(HelperMisuse):
        Evidence(claim, facts)


def test_terminal_calls_require_evidence_objects() -> None:
    with pytest.raises(HelperMisuse):
        Recorder().check().secure({"claim": "x"})  # type: ignore[arg-type]
    with pytest.raises(HelperMisuse):
        Recorder().check().inconclusive("")


# ------------------------------------------------------------ fixture copy, paths, responses


def test_fixture_copy_is_bound_to_the_pp006_contract_hash() -> None:
    assert CONTRACT_SHA256 == GROUND_TRUTH["target"]["fixture_sha256"]
    raw = (PACK / "fixtures" / "synthetic-documents-v1.json").read_bytes()
    assert raw == (ROOT / "examples/papertrail/template/fixtures/synthetic/synthetic-documents-v1.json").read_bytes()
    assert isinstance(parse_documents(raw), SyntheticDocuments)
    with pytest.raises(FixtureContractError, match="contract hash"):
        parse_documents(raw.replace(b'"reader_roles": ["auditor"]', b'"reader_roles": ["auditor", "member"]'))
    with pytest.raises(FixtureContractError):
        parse_documents(raw + b" ")


def test_reviewed_policy_matches_pp006_correct_revision() -> None:
    allowed = {(u.user_id, d.document_id) for u in DOCS.users for d in DOCS.documents if permits(u, d)}
    assert allowed == {("u-alice", "doc-alice-private"), ("u-bob", "doc-bob-private"),
                       ("u-carol", "doc-alice-private")}


@pytest.mark.parametrize("path", ["documents/x", "//evil.invalid/x", "/a/../b", "/a/./b", "/a?x=1", "/a#f",
                                  "http://x/", "/a b", "/" + "a" * 201, "/a\nb"])
def test_request_paths_cannot_redirect_the_verifier(path: str) -> None:
    with pytest.raises(ValueError):
        check_path(path)


def test_valid_request_paths() -> None:
    assert check_path("/documents/doc-alice-private") == "/documents/doc-alice-private"
    assert check_path("/me") == "/me"


def test_response_bounds() -> None:
    with pytest.raises(TargetResponseError):
        Response(99, b"")
    with pytest.raises(TargetResponseError):
        Response(200, b"x" * (1048576 + 1))
    assert Response(200, b"[1]").json_object() is None


# ------------------------------------------------------------ plugin collection logic (no pytest run)


MANIFEST_TESTS = read_manifest_tests(PACK / "pack.json")


def test_plugin_builds_the_collected_payload_in_collection_order() -> None:
    nodeids = [t["nodeid"] for t in MANIFEST_TESTS][::-1]
    payload = build_collected(MANIFEST_TESTS, nodeids)
    assert [t["nodeid"] for t in payload["tests"]] == nodeids
    assert {t["id"] for t in payload["tests"]} == set(PACK_CASES)


@pytest.mark.parametrize(("mutate", "message"), [
    (lambda n: n[:-1], "not collected"),
    (lambda n: [*n, "tests/test_documents.py::test_extra"], "not in the manifest"),
    (lambda n: [*n, n[0]], "more than once"),
])
def test_plugin_refuses_inexact_collection(mutate: Any, message: str) -> None:
    with pytest.raises(CollectionRefused, match=message):
        build_collected(MANIFEST_TESTS, mutate([t["nodeid"] for t in MANIFEST_TESTS]))


@pytest.mark.parametrize("marker", ["skip", "skipif", "xfail"])
def test_plugin_refuses_skip_and_xfail_markers(marker: str) -> None:
    nodeids = [t["nodeid"] for t in MANIFEST_TESTS]
    with pytest.raises(CollectionRefused, match="forbidden marker"):
        build_collected(MANIFEST_TESTS, nodeids, {nodeids[0]: [marker]})


def test_verifier_manifest_reader_is_strict(tmp_path: Path) -> None:
    for raw in (b'{"tests": [{"id": "AUTH-001", "id": "AUTH-002"}]}', b'{"tests": []}',
                b'{"tests": [{"id": "x", "nodeid": "tests/test_a.py::test_b", "kind": "security"}]}',
                b'{"tests": [{"id": "AUTH-001", "nodeid": "../x.py::test_b", "kind": "security"}]}'):
        (tmp_path / "pack.json").write_bytes(raw)
        with pytest.raises((ManifestError, ValueError)):
            read_manifest_tests(tmp_path / "pack.json")
