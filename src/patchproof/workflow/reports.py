"""`patchproof report <run-id>`: safe JSON and Markdown review reports (PROJECT_SPEC.md 12.2-12.4; PP-009).

**Verify before reporting.** A report is built only from a run's persisted evidence, after:
1. the accepted `run_evidence.verify_evidence` (manifest, every artifact's hash, size and mode,
   the operation journal in either accepted format, `docker-ops-v1` inline or `docker-ops-v2`);
2. strict loading of every record it uses against its contract;
3. recomputing the verdict with the accepted PP-004 engine from the stored verdict input, and
   cross-checking that input against the execution records, the observation files and the
   observations re-derived by the accepted collector from the raw verifier streams.
Any failure or disagreement is shown first, the result is labelled EVIDENCE NOT VERIFIED and the
exit code is 20. The evidence is opened read-only and never changed.

**Allowlist, not redaction.** The report is assembled field by field from a fixed allowlist.
It never includes raw target or verifier output, response bodies, source code, the pack's test
code, host paths, installation IDs, process IDs, reviewer names, fixture tokens or protected
markers. Witness facts pass a per-key allowlist (the `marker` value is withheld; only whether it
was observed is shown) and witness claims must be one of the reviewed verifier claims. Known
secret shapes are redacted on top, and the rendered text is checked for private paths.

**Not a reproduction bundle.** A report names the hashes needed to reproduce a run; it contains
no source, pack, image or credential and cannot reproduce anything on its own.

**Exit code** (PROJECT_SPEC.md 13.2): the run's own lifecycle and verdict, lifecycle first. A
controller-test harness result (the PP-008 interruption demonstration) is reported separately and
never used as the run's exit code.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal

from ..core.records import RecordError, load_record, validate_record
from ..core.records.authorization import RunPlanDocument
from ..core.records.interruption import InterruptionPlanDocument
from ..core.records.pack import ApprovalRecord, CollectedTest
from ..core.records.run import Execution, Observation, VerdictRecord, VerifierEvent
from ..core.strict_json import StrictJsonError, loads_strict
from ..core.verdict_input import VerdictInputError, parse_verdict_input
from ..core.verdicts import EvaluationError, _cell_semantic_if_trusted, _execution_trusted, evaluate
from ..runner.collector import StreamIdentity, collect_stream
from ..runner.run_evidence import journal_format, verify_evidence
from . import exit_codes
from .invocation import command
from .safe_text import UnsafeProse, code, contains_secret, md, plain, prose

REPORT_FORMAT: Final = "patchproof-review-report-v1"
RUN_ID_RE: Final = re.compile(r"run-[0-9a-f]{32}")
MAX_JSON_BYTES: Final = 4 * 1024 * 1024
MAX_STREAM_BYTES: Final = 64 * 1024 * 1024
MAX_REPORT_BYTES: Final = 512 * 1024
MAX_LIST: Final = 400
Kind = Literal["comparison", "interruption-demonstration"]

# Witness facts emitted by the reviewed verifier helpers (verifier/patchproof_verifier/authz.py).
WITNESS_FACTS: Final = ("caller_id", "caller_role", "caller_permitted", "credential", "document_id", "owner_id",
                        "reader_roles", "status", "marker_observed")
WITHHELD_FACTS: Final = {"marker": "withheld (synthetic protected value; see marker_observed)"}
REVIEWED_CLAIMS: Final = frozenset({
    "A caller the fixture does not permit received the document's protected marker",
    "The read was denied and neither the marker nor document content was returned",
    "An unauthenticated caller received the document's protected marker",
    "Authentication was required and no protected content was returned",
})
_FACT_VALUE_RE: Final = re.compile(r"[A-Za-z0-9_,.-]{1,64}")
_SUMMARY_RE: Final = re.compile(r"(?P<claim>[^\n]{1,300}?)\. (?P<facts>[a-z_]+=[^\n]*)")

REMEDIATION: Final[Mapping[str, str]] = {
    "VERIFIED_FOR_CASES": "For the selected checks only, the candidate blocked the violations reproduced on the "
                          "baseline and kept every functional control passing. Review authorization paths these "
                          "checks do not cover before relying on the fix; this is not a statement about the "
                          "application's overall security.",
    "NOT_FIXED": "At least one selected security check still observed a violation on the candidate. Do not treat "
                 "the candidate as a fix; start from the failing checks listed above.",
    "REGRESSION_DETECTED": "No candidate violation was observed, but a functional control that passed on the "
                           "baseline failed on the candidate (legitimate behavior was lost). This is not a "
                           "successful remediation.",
    "NOT_REPRODUCED": "The baseline did not show the expected violation, so a secure candidate proves nothing. "
                      "Check the baseline selection and the pack before drawing any conclusion.",
    "INCONCLUSIVE": "No conclusion is supported. Address the listed reasons and run a new, separately authorized "
                    "plan; do not read this result as a pass or a fail.",
    "BLOCKED": "Verification was not permitted (approval, policy or preflight). Nothing about the fix was observed.",
}
# The claim label for each fixture mode a validated plan can carry (the plan contracts allow only
# the v0.1 exception today). An unknown mode has no label and fails the report closed.
FIXTURE_LABELS: Final[Mapping[str, str]] = {
    "fixed-fixture-v0.1-exception": "Synthetic PaperTrail reference application, one fixed synthetic fixture with no "
                                    "variable seed (the narrow v0.1 fixed-fixture exception)",
}
CLAIM_SCOPE: Final = ("The claim covers only the selected checks on this fixture and makes no statement about "
                      "untested inputs or the application's overall security.")
BASE_LIMITATIONS: Final = (
    "Synthetic reference application (PaperTrail) with one fixed synthetic fixture and no variable seed: not a "
    "finding in a real project.",
    "The claim covers only the selected checks, the planned number of pairs and the fixed fixture.",
    "Security witnesses are structured facts recorded by the reviewed verifier helpers; raw HTTP responses are not "
    "retained and cannot be re-examined.",
    "Functional controls pass or fail through reviewed assertions; their response bodies are not retained.",
    "Container inspection is configuration evidence, not proof that the kernel enforced the policy.",
    "Reviewer identities are local assertions; approvals and authorizations are procedural controls under one OS "
    "account.",
    "Evidence verification detects inconsistency with the manifest, not a local adversary who rewrites both.",
    "This review report is not a runnable reproduction bundle.",
)


class ReportError(Exception):
    """The run cannot be located or read safely. Nothing was reported."""


class RunNotFound(ReportError):
    """No evidence exists for the run ID (a usage error: exit 2)."""


class OutputError(ReportError):
    """The `--output` destination was refused or could not be written. Nothing was left there (exit 2)."""


# ------------------------------------------------------------------ reading


def locate_run(data_root: Path, run_id: str) -> tuple[Path, Kind]:
    if not RUN_ID_RE.fullmatch(run_id):
        raise ReportError("a run ID is 'run-' followed by 32 lower-case hex digits")
    found: list[tuple[Path, Kind]] = []
    for sub, kind in (("runs", "comparison"), ("interruption-tests", "interruption-demonstration")):
        path = data_root / "evidence" / sub / run_id
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077:
            raise ReportError("the run's evidence is not a private directory owned by you")
        found.append((path, kind))  # type: ignore[arg-type]
    if len(found) != 1:
        if not found:
            raise RunNotFound("no evidence exists for this run ID")
        raise ReportError("the run ID is ambiguous")
    return found[0]


def _read(directory: Path, name: str, limit: int) -> bytes:
    fd = os.open(directory / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        st = os.fstat(handle.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise ReportError(f"{name} is not a regular file")
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ReportError(f"{name} exceeds its size limit")
    return data


def _json(directory: Path, name: str) -> Any:
    return loads_strict(_read(directory, name, MAX_JSON_BYTES), max_bytes=MAX_JSON_BYTES)


def _jsonl(directory: Path, name: str) -> list[Any]:
    raw = _read(directory, name, MAX_JSON_BYTES)
    return [loads_strict(line, max_bytes=MAX_JSON_BYTES) for line in raw.splitlines() if line.strip()]


# ------------------------------------------------------------------ witnesses


def parse_witness(summary: str) -> tuple[str, dict[str, str]]:
    """(claim, allowlisted facts) from a verifier observation summary. Unknown shapes are withheld."""
    m = _SUMMARY_RE.fullmatch(summary)
    if m is None:
        return "[unparsed witness withheld]", {}
    claim = m.group("claim") if m.group("claim") in REVIEWED_CLAIMS else "[unreviewed claim text withheld]"
    facts: dict[str, str] = {}
    for item in m.group("facts").split("; "):
        key, sep, value = item.partition("=")
        if not sep:
            continue
        if key in WITHHELD_FACTS:
            facts[key] = WITHHELD_FACTS[key]
        elif key in WITNESS_FACTS:
            facts[key] = value if _FACT_VALUE_RE.fullmatch(value) and not contains_secret(value) else \
                "[withheld: unexpected value]"
        else:
            facts[key] = "[withheld: not in the report allowlist]"
    return claim, facts


def _witnesses(raw: bytes, run_id: str, side: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for line in raw.splitlines():
        try:
            event = load_record(VerifierEvent, line, contract="verifier-event")
        except RecordError:
            continue  # the collector cross-check reports malformed streams; witnesses come only from valid events
        if event.type != "observation" or event.run_id != run_id or event.side != side:
            continue
        payload = event.payload
        claim, facts = parse_witness(payload.summary)  # type: ignore[union-attr]
        out.append({"test_id": payload.test_id, "side": side, "pair": event.pair,  # type: ignore[union-attr]
                    "outcome": payload.outcome, "claim": claim, "facts": facts})  # type: ignore[union-attr]
    return out[:MAX_LIST]


# ------------------------------------------------------------------ building


@dataclass(frozen=True)
class Report:
    document: dict[str, Any]
    exit_code: int


def _check(checks: list[dict[str, Any]], name: str, passed: bool, detail: str = "") -> bool:
    checks.append({"name": name, "passed": bool(passed), "detail": plain(detail, 300)})
    return passed


def build_report(data_root: Path, run_id: str, *, home: Path | None = None) -> Report:
    directory, kind = locate_run(data_root, run_id)
    checks: list[dict[str, Any]] = []
    integrity = verify_evidence(directory)
    verified = _check(checks, "accepted evidence verifier: manifest, hashes, sizes, modes, journal",
                      integrity.get("state") == "CONSISTENT" and not integrity.get("problems"),
                      f"{integrity.get('state')} {integrity.get('status')}")
    try:
        fmt = journal_format(directory)
    except (OSError, ValueError):
        fmt = "unreadable"
    try:
        doc = _assemble(directory, kind, run_id, checks)
    except (ReportError, RecordError, StrictJsonError, VerdictInputError, EvaluationError, OSError, KeyError,
            TypeError, ValueError) as exc:
        _check(checks, "evidence records strictly loaded", False, f"{type(exc).__name__}: {exc}")
        doc = {"run": {"run_id": run_id, "kind": kind}}
    all_ok = verified and all(c["passed"] for c in checks)
    result = doc.get("result", {})
    code_ = exit_codes.run_exit_code(result.get("lifecycle"), result.get("verdict"), result.get("evidence_status"))
    if not all_ok:
        code_ = exit_codes.INCONCLUSIVE
    if "result" in doc:
        result["fix_verified_for_selected_cases"] = (all_ok and code_ == exit_codes.OK
                                                     and result.get("verdict") == "VERIFIED_FOR_CASES")
    headline = _headline(result, all_ok)
    document: dict[str, Any] = {
        "report_format": REPORT_FORMAT,
        "notice": "Review report generated from verified local evidence. It is not a runnable reproduction bundle "
                  "and contains no source, pack code, raw output, response bodies, host paths or credentials.",
        "headline": headline,
        "exit_code": code_,
        "integrity": {"verified": all_ok, "manifest_status": integrity.get("status"),
                      "verifier_state": integrity.get("state"),
                      "problems": [plain(p, 300) for p in list(integrity.get("problems") or [])[:50]],
                      "journal_format": fmt, "checks": checks},
        **doc,
    }
    document["limitations"] = _limitations(kind, fmt)
    _scrub(document, data_root, home or Path.home())
    return Report(document, code_)


HEADLINE_NOT_VERIFIED: Final = "EVIDENCE NOT VERIFIED: no result is reported as established (exit 20)."
HEADLINE_VERIFIED: Final = "Verified for the selected cases."
HEADLINE_NOT_A_RESULT: Final = "Not a verification result, whatever the cleanup status."
INTEGRITY_NOTE: Final = ("These checks show only that the saved evidence is consistent with its manifest and with "
                         "itself. Completeness, lifecycle, cleanup and the comparison verdict are reported "
                         "separately, and a passing integrity check never means a fix was verified.")


def _headline(result: Mapping[str, Any], verified: bool) -> str:
    if not verified:
        return HEADLINE_NOT_VERIFIED
    lifecycle, status, verdict = result.get("lifecycle"), result.get("evidence_status"), result.get("verdict")
    if lifecycle == "COMPLETE" and status == "FINALIZED" and verdict == "VERIFIED_FOR_CASES":
        return HEADLINE_VERIFIED
    if lifecycle != "COMPLETE" or status != "FINALIZED":
        return (f"{lifecycle}: evidence {status}; verdict {verdict} ({result.get('decision_rule')}). "
                f"{HEADLINE_NOT_A_RESULT}")
    return f"{verdict} ({result.get('decision_rule')})."


def _trusted_cells(raw_input: Mapping[str, Any], recomputed: Mapping[str, Any]) -> set[tuple[int, str, str]]:
    """Which cells the accepted engine trusts, by its own rules (E1-E4 per execution, T1-T5 per cell)."""
    inp = parse_verdict_input(raw_input)
    states = recomputed["preconditions"]
    if not all((v["state"] if isinstance(v, Mapping) else v) == "PASSED" for v in states.values()):
        return set()  # T1
    keys = [e.key for e in inp.executions]
    trusted_executions = {e.key for e in inp.executions
                          if keys.count(e.key) == 1 and _execution_trusted(e, inp.result_cap_bytes)}
    return {o.key for o in inp.observations
            if (o.pair, o.side) in trusted_executions and _cell_semantic_if_trusted(o) is not None}


def _exists(directory: Path, name: str) -> bool:
    return os.path.lexists(directory / name)


def _assemble(directory: Path, kind: Kind, run_id: str, checks: list[dict[str, Any]]) -> dict[str, Any]:
    plan: RunPlanDocument | InterruptionPlanDocument
    if kind == "comparison":
        plan = validate_record(RunPlanDocument, _json(directory, "plan.json"), "run-plan")
    else:
        plan = validate_record(InterruptionPlanDocument, _json(directory, "plan.json"), "interruption-plan")
    _check(checks, "plan names this run", plan.run_id == run_id)
    authorization = _json(directory, "authorization.json")
    _check(checks, "plan.json equals the authorized plan", authorization.get("plan") == plan.model_dump(mode="json"))
    outcome = _json(directory, "outcome.json")
    manifest = _json(directory, "manifest.json")
    _check(checks, "manifest summary equals outcome.json", manifest.get("summary") == outcome)
    _check(checks, "manifest status equals the outcome's evidence status",
           manifest.get("status") == outcome.get("evidence_status"), f"{manifest.get('status')}")
    _check(checks, "outcome names this run and plan", outcome.get("run_id") == run_id and
           outcome.get("plan_sha256") == authorization.get("plan_sha256"))
    planned = ["baseline", "candidate"] if kind == "comparison" else ["baseline"]
    sides = [s for s in planned if _exists(directory, f"execution-pair-001-{s}.json")]
    _check(checks, "executed sides are a prefix of the planned order", sides == planned[:len(sides)],
           ", ".join(sides) or "none")
    executions = [validate_record(Execution, _json(directory, f"execution-pair-001-{s}.json"), "execution")
                  for s in sides]

    has_verdict = _exists(directory, "verdict.json"), _exists(directory, "verdict-input.json")
    recomputed: dict[str, Any] | None = None
    raw_input: dict[str, Any] = {}
    if any(has_verdict):
        stored_verdict = _json(directory, "verdict.json")
        validate_record(VerdictRecord, stored_verdict, "verdict")
        raw_input = _json(directory, "verdict-input.json")
        recomputed = evaluate(parse_verdict_input(raw_input), stored_verdict["evaluated_at"])
        _check(checks, "verdict recomputed by the accepted engine equals verdict.json", recomputed == stored_verdict,
               f"recomputed {recomputed.get('verdict')} {recomputed.get('decision_rule')}")
        _check(checks, "outcome's engine verdict equals the recomputed verdict",
               outcome.get("engine_verdict") == recomputed["verdict"] and
               outcome.get("reason_codes") == recomputed["reason_codes"])
        _check(checks, "verdict input executions equal the execution records",
               raw_input.get("executions") == [e.model_dump(mode="json") for e in executions])
    else:
        _check(checks, "no verdict files only for incomplete evidence without an engine verdict",
               manifest.get("status") == "INCOMPLETE" and outcome.get("engine_verdict") is None
               and outcome.get("verdict") is None, "the engine did not evaluate this run")

    expected: dict[str, dict[str, Any]] = {t["id"]: dict(t) for t in raw_input.get("pack_tests", [])}
    kinds = {i: t["kind"] for i, t in expected.items()}
    collection = tuple(CollectedTest(id=t.id, nodeid=t.nodeid) for t in plan.pack.expected_collection)
    observations: list[Observation] = []
    witnesses: list[dict[str, Any]] = []
    for side in sides:
        side_obs = [validate_record(Observation, o, "observation")
                    for o in _jsonl(directory, f"observations-pair-001-{side}.jsonl")]
        observations += side_obs
        stream = _read(directory, f"verifier-stream-pair-001-{side}.bin", MAX_STREAM_BYTES)
        if kinds:
            identity = StreamIdentity(run_id=run_id, pair=1, side=side,  # type: ignore[arg-type]
                                      pack_tree_sha256=plan.pack.pack_tree_sha256,
                                      plugin_version=plan.pack.verifier_plugin_version, collection=collection,
                                      kinds=kinds)
            derived = collect_stream(stream, identity, result_cap_bytes=plan.runtime.result_cap_bytes).cells
            _check(checks, f"{side} observations re-derived from the raw verifier stream equal the stored ones",
                   [c.model_dump(mode="json") for c in derived] == [o.model_dump(mode="json") for o in side_obs])
        witnesses += _witnesses(stream, run_id, side)
    if recomputed is not None:
        _check(checks, "verdict input observations equal the observation files",
               raw_input.get("observations") == [o.model_dump(mode="json") for o in observations])
    established, engine_now = outcome.get("verdict"), recomputed["verdict"] if recomputed else None
    _check(checks, "the established verdict is absent or the recomputed engine verdict",
           established is None or established == engine_now, f"{established} vs {engine_now}")
    if outcome.get("lifecycle") == "COMPLETE":
        _check(checks, "a COMPLETE run has finalized evidence and an established, recomputed verdict",
               outcome.get("evidence_status") == "FINALIZED" and established is not None
               and established == engine_now)
    if kind == "interruption-demonstration":
        _check(checks, "recorded lifecycle exit code agrees with the run record",
               outcome.get("lifecycle_exit_code") == exit_codes.run_exit_code(
                   outcome.get("lifecycle"), outcome.get("verdict"), outcome.get("evidence_status")))
    approval = load_record(ApprovalRecord, _read(directory, "pack-approval.json", 65536), contract="approval-record")
    _check(checks, "pack approval in evidence is the plan's approval", approval.approval_id == plan.pack_approval_id)

    details = recomputed["details"] if recomputed else []
    trusted_cells = _trusted_cells(raw_input, recomputed) if recomputed else set()
    by_cell: dict[tuple[str, str], Observation] = {(o.side, o.test_id): o for o in observations}
    tests = []
    for t in plan.pack.expected_collection[:MAX_LIST]:
        e = expected.get(t.id)
        row: dict[str, Any] = {"id": t.id, "nodeid": t.nodeid, "kind": e["kind"] if e else None,
                               "expected": {s: (e[f"{s}_expected"] if e else None) for s in planned},
                               "observed": {}}
        for s in planned:
            o = by_cell.get((s, t.id))
            row["observed"][s] = None if o is None else {
                "semantic": o.semantic_outcome, "lifecycle": o.lifecycle_outcome, "stream": o.stream_status,
                "harness_errors": list(o.harness_errors),
                "trusted": (1, s, t.id) in trusted_cells}
        tests.append(row)
    trusted = sum(1 for r in tests for s in planned if r["observed"][s] and r["observed"][s]["trusted"])
    counts = recomputed["counts"] if recomputed else None
    if counts is not None:
        _check(checks, "per-cell trust agrees with the engine's trusted-cell count",
               trusted == counts["trusted_cells"], f"{trusted} of {counts['required_cells']}")
    p = plan
    inputs: dict[str, Any] = {
        "sources": {s: {"tag": getattr(p.sources, s).tag, "commit_id": getattr(p.sources, s).commit_id,
                        "tree_id": getattr(p.sources, s).tree_id,
                        "snapshot_manifest_sha256": getattr(p.sources, s).source_manifest_sha256,
                        "source_tree_sha256": getattr(p.sources, s).source_tree_sha256} for s in planned},
        "source_inclusion": {"include": list(p.source_inclusion.include),
                             "inclusion_profile_sha256": p.source_inclusion.inclusion_profile_sha256},
        "pack": {"pack_id": p.pack.pack_id, "pack_version": p.pack.pack_version,
                 "manifest_sha256": p.pack.manifest_sha256, "pack_tree_sha256": p.pack.pack_tree_sha256,
                 "verifier_plugin_version": p.pack.verifier_plugin_version},
        "profile": {"profile_id": p.profile.profile_id, "profile_version": p.profile.profile_version,
                    "profile_sha256": p.profile.profile_sha256},
        "images": {"target_image_id": p.images.target_image_id, "verifier_image_id": p.images.verifier_image_id},
        "fixture": {"contract": p.fixture.fixture_contract, "sha256": p.fixture.fixture_sha256,
                    "mode": p.fixture.mode, "seed": p.fixture.seed},
        "pack_approval": {"approval_id": approval.approval_id, "created_at": approval.created_at,
                          "reviewer_basis": approval.reviewer.basis, "scope": plain(approval.scope, 600)},
    }
    revision_cleanup = [c for s in sides for c in _json(directory, f"revision-pair-001-{s}.json").get("cleanup", [])
                        if isinstance(c, dict)] if all(_exists(directory, f"revision-pair-001-{s}.json")
                                                       for s in sides) else []
    verdict = outcome.get("verdict")
    result = {
        "lifecycle": outcome.get("lifecycle"), "evidence_status": outcome.get("evidence_status"),
        "verdict": verdict, "engine_verdict": recomputed["verdict"] if recomputed else None,
        "decision_rule": recomputed["decision_rule"] if recomputed else None,
        "reason_codes": list(recomputed["reason_codes"]) if recomputed else [],
        "flags": dict(recomputed["flags"]) if recomputed else {},
        "run_termination": recomputed["run_termination"] if recomputed else outcome.get("run_termination"),
        "execution_started": recomputed["execution_started"] if recomputed else bool(sides),
        "sides_executed": sides,
    }
    n_tests = len(tests)
    n_security = sum(1 for t in tests if t["kind"] == "security")
    return {
        "run": {"run_id": run_id, "kind": kind, "plan_kind": p.plan_kind,
                "plan_sha256": authorization.get("plan_sha256"),
                "authorization_id": authorization.get("authorization_id"),
                "authorization_kind": authorization.get("kind"),
                "evaluated_at": recomputed["evaluated_at"] if recomputed else None},
        "result": result,
        "claim": {"label": FIXTURE_LABELS[p.fixture.mode], "fixture_mode": p.fixture.mode,
                  "fixture_seed": p.fixture.seed, "scope": CLAIM_SCOPE, "selected_checks": n_tests,
                  "security_checks": n_security, "functional_controls": n_tests - n_security,
                  "pairs_planned": 1,
                  "security_claim": "Each security check expects the baseline outcome shown (a violation where "
                                    "declared) and SECURE on the candidate, judged by the reviewed witness rules.",
                  "legitimate_behavior": "Each functional control expects PASS on both revisions: permitted callers "
                                         "keep receiving exactly their documents and identity."},
        "inputs": inputs,
        "repetitions": {"pairs_planned": 1,
                        "pairs_terminated_normally": counts["pairs_terminated_normally"] if counts else 0,
                        "pairs_with_trusted_evidence": counts["pairs_with_trusted_evidence"] if counts else 0},
        "observations": {"required_cells": counts["required_cells"] if counts else n_tests * len(planned),
                         "trusted_cells": counts["trusted_cells"] if counts else 0,
                         "untrusted_or_missing_cells": (counts["required_cells"] - counts["trusted_cells"]) if counts
                         else n_tests * len(planned)},
        "tests": tests,
        "witnesses": witnesses,
        "executions": [{"side": e.side, "started": e.started, "target_readiness": e.target.readiness,
                        "target_oom_killed": e.target.oom_killed, "verifier_termination": e.verifier.termination,
                        "verifier_exit_code": e.verifier.exit_code, "verifier_oom_killed": e.verifier.oom_killed,
                        "stream_status": e.stream.status, "events_received": e.stream.events_received,
                        "deadline_exceeded": e.deadline_exceeded, "runtime_errors": list(e.runtime_errors)}
                       for e in executions],
        "missing_or_untrusted": [{"side": d["side"], "pair": d["pair"], "test_id": d.get("test_id"),
                                  "reason_code": d["reason_code"]} for d in details[:MAX_LIST]],
        "cleanup": {"status": outcome.get("cleanup_status"), "containers_created": outcome.get("containers_created"),
                    "removed": sum(1 for c in revision_cleanup if c.get("status") == "REMOVED"),
                    "remaining_owned_containers": len(outcome.get("remaining_owned_container_ids") or []),
                    "inventory_reconciliation": outcome.get("reconciliation"),
                    "daemon_restart_suspected": outcome.get("daemon_restart_suspected"),
                    "note": "Cleanup is a separate dimension: complete cleanup never makes a run successful."},
        "remediation": REMEDIATION.get(str(verdict or (recomputed or {}).get("verdict")), REMEDIATION["INCONCLUSIVE"]),
        "reproducibility": [
            "The same approved pack (tree above) under a current approval, and the same profile hash.",
            "Local copies of both images with exactly the IDs above (never pulled during a run).",
            "Source snapshots of the commits above whose manifests have the hashes above.",
            "A new plan and a new single-use run authorization; a consumed authorization never runs again.",
            f"A Docker environment that passes the read-only doctor check ({command('doctor')}).",
        ],
    }


def _limitations(kind: Kind, fmt: str) -> list[str]:
    out = list(BASE_LIMITATIONS)
    if fmt == "v1":
        out.append("This run predates evidence hardening (operation journal v1): per-operation times and separate "
                   "target stdout/stderr artifacts are not available.")
    if kind == "interruption-demonstration":
        out.append("Deliberate interruption demonstration: the verifier never started and no candidate exists, so no "
                   "verification result is possible. The demonstration harness result is not this run's result.")
    return out


def _scrub(value: Any, data_root: Path, home: Path) -> Any:
    """Replace private path prefixes in every string (defence in depth; fields are already allowlisted)."""
    if isinstance(value, dict):
        for k in list(value):
            value[k] = _scrub(value[k], data_root, home)
        return value
    if isinstance(value, list):
        return [_scrub(v, data_root, home) for v in value]
    if isinstance(value, str):
        for prefix, label in ((str(data_root), "<user data>"), (str(home), "<home>")):
            if prefix and prefix != "/":
                value = value.replace(prefix, label)
        return value
    return value


# ------------------------------------------------------------------ rendering


def render_json(report: Report) -> str:
    text = json.dumps(report.document, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    return _bounded(text)


def _bounded(text: str) -> str:
    if len(text.encode("utf-8")) > MAX_REPORT_BYTES:
        raise ReportError("the report exceeds its size bound; it was not produced")
    if contains_secret(text):
        raise ReportError("the report would contain a secret-shaped value; it was not produced")
    return text


def _row(cells: Sequence[object]) -> str:
    return "| " + " | ".join(str(c) for c in cells) + " |"


def _num(value: object) -> str:
    """A count: plain digits are inert inline; anything else is a value and is escaped."""
    return str(value) if type(value) is int else code(value)


def _headline_markdown(d: Mapping[str, Any]) -> str:
    """The headline with every evidence-derived value in a code span and the fixed wording literal.
    Mirrors `_headline` (the JSON text); a test pins that the two agree."""
    result = d.get("result", {})
    if not d["integrity"]["verified"]:
        return prose(HEADLINE_NOT_VERIFIED)
    lifecycle, status, verdict = result.get("lifecycle"), result.get("evidence_status"), result.get("verdict")
    if lifecycle == "COMPLETE" and status == "FINALIZED" and verdict == "VERIFIED_FOR_CASES":
        return prose(HEADLINE_VERIFIED)
    rule = code(result.get("decision_rule"))
    if lifecycle != "COMPLETE" or status != "FINALIZED":
        return (f"{code(lifecycle)}: evidence {code(status)}; verdict {code(verdict)} ({rule}). "
                f"{prose(HEADLINE_NOT_A_RESULT)}")
    return f"{code(verdict)} ({rule})."


def render_markdown(report: Report) -> str:
    """Markdown with a fixed structure. PatchProof's own wording is literal (`prose` proves it inert);
    every value from evidence, records or the target is a code span (`code`) or escaped (`md`)."""
    try:
        return _bounded(_markdown(report.document))
    except UnsafeProse as exc:
        raise ReportError(str(exc)) from None


def _markdown(d: Mapping[str, Any]) -> str:
    run, result = d.get("run", {}), d.get("result", {})
    integrity = d["integrity"]
    out = [f"# PatchProof review report: {code(run.get('run_id'))}", "",
           f"**{_headline_markdown(d)}**", "", prose(d["notice"]), "",
           "## Result", "",
           _row(["Field", "Value"]), _row(["---", "---"])]
    for key in ("lifecycle", "evidence_status", "verdict", "engine_verdict", "decision_rule", "run_termination",
                "execution_started"):
        out.append(_row([code(key), code(result.get(key))]))
    out.append(_row([prose("Fix verified for the selected cases"),
                     "yes" if result.get("fix_verified_for_selected_cases") else "no"]))
    out.append(_row([prose("CLI exit code (PROJECT_SPEC.md 13.2)"), code(d["exit_code"])]))
    out.append(_row(["reason codes", ", ".join(code(r) for r in result.get("reason_codes", [])) or "none"]))
    out += ["", "## Evidence integrity", "",
            f"Evidence integrity checks passed: **{'yes' if integrity['verified'] else 'NO'}**. "
            f"Evidence completeness (manifest status): {code(integrity['manifest_status'])}. Operation journal: "
            f"{code(integrity['journal_format'])}.", "",
            prose(INTEGRITY_NOTE), "",
            _row(["Check", "Passed", "Detail"]), _row(["---", "---", "---"])]
    out += [_row([prose(c["name"]), "yes" if c["passed"] else "NO", md(c["detail"])]) for c in integrity["checks"]]
    for p in integrity["problems"]:
        out.append(f"- Problem: {md(p)}")
    if "inputs" in d:
        i = d["inputs"]
        fixture = i["fixture"]
        seed = prose("no variable seed") if fixture.get("seed") is None else f"seed {code(fixture['seed'])}"
        out += ["", "## Run and inputs", "", _row(["Item", "Value"]), _row(["---", "---"]),
                _row(["kind", code(run.get("kind"))]), _row(["plan", code(run.get("plan_sha256"))]),
                _row(["authorization", code(run.get("authorization_id"))]),
                _row(["evaluated at", code(run.get("evaluated_at"))])]
        for side, s in i["sources"].items():
            out.append(_row([f"{code(side)} source", f"{code(s['tag'])} commit {code(s['commit_id'])} tree "
                                                     f"{code(s['tree_id'])} snapshot manifest "
                                                     f"{code(s['snapshot_manifest_sha256'])}"]))
        out += [_row(["source inclusion", ", ".join(code(x) for x in i["source_inclusion"]["include"])]),
                _row(["pack", f"{code(i['pack']['pack_id'])} {code(i['pack']['pack_version'])} tree "
                              f"{code(i['pack']['pack_tree_sha256'])}"]),
                _row(["verifier plugin", code(i["pack"]["verifier_plugin_version"])]),
                _row(["profile", f"{code(i['profile']['profile_id'])} {code(i['profile']['profile_sha256'])}"]),
                _row(["target image", code(i["images"]["target_image_id"])]),
                _row(["verifier image", code(i["images"]["verifier_image_id"])]),
                _row(["fixture", f"{code(fixture['contract'])} {code(fixture['sha256'])}, mode "
                                 f"{code(fixture.get('mode'))}, {seed}"]),
                _row(["pack approval", f"{code(i['pack_approval']['approval_id'])} "
                                       f"({code(i['pack_approval']['reviewer_basis'])})"]),
                _row(["approval scope", md(i["pack_approval"]["scope"], 600)])]
        c = d["claim"]
        out += ["", "## Claim", "",
                f"{prose(c['label'])}: {_num(c['selected_checks'])} selected checks ({_num(c['security_checks'])} "
                f"security, {_num(c['functional_controls'])} functional controls), {_num(c['pairs_planned'])} "
                f"pair. Repetitions terminated normally: {_num(d['repetitions']['pairs_terminated_normally'])}; "
                f"with trusted evidence: {_num(d['repetitions']['pairs_with_trusted_evidence'])}.", "",
                prose(c["scope"]), "",
                f"Security claim: {prose(c['security_claim'])}", "",
                f"Legitimate behavior: {prose(c['legitimate_behavior'])}", "",
                "## Required tests and observations", "",
                f"Trusted cells: {_num(d['observations']['trusted_cells'])} of "
                f"{_num(d['observations']['required_cells'])}.", ""]
        sides = list(i["sources"])
        out += [_row(["Test", "Kind", *[f"{code(s)} expected" for s in sides],
                      *[f"{code(s)} observed" for s in sides]]),
                _row(["---"] * (2 + 2 * len(sides)))]
        for t in d["tests"]:
            observed = []
            for s in sides:
                o = t["observed"].get(s)
                observed.append("not executed" if o is None else f"{code(o['semantic'])} / {code(o['lifecycle'])}"
                                + ("" if o["trusted"] else " (untrusted)"))
            out.append(_row([code(t["id"]), code(t["kind"]), *[code(t["expected"].get(s)) for s in sides],
                             *observed]))
        out += ["", "## Security witnesses (structured facts; raw responses are not retained)", ""]
        if not d["witnesses"]:
            out.append("No security witness was recorded.")
        for w in d["witnesses"]:
            claim = prose(w["claim"]) if w["claim"] in REVIEWED_CLAIMS else md(w["claim"])
            facts = "; ".join(f"{code(k)} {prose(v)}" if WITHHELD_FACTS.get(k) == v else code(f"{k}={v}")
                              for k, v in w["facts"].items())
            out.append(f"- {code(w['test_id'])} {code(w['side'])}: {code(w['outcome'])}. {claim}. {facts}")
        out += ["", "## Executions", "", _row(["Side", "Started", "Target", "Verifier", "Exit", "Stream", "Events"]),
                _row(["---"] * 7)]
        for e in d["executions"]:
            out.append(_row([code(e["side"]), code(e["started"]), code(e["target_readiness"]),
                             code(e["verifier_termination"]), code(e["verifier_exit_code"]),
                             code(e["stream_status"]), _num(e["events_received"])]))
        out += ["", "## Missing checks, harness errors and uncertainty", ""]
        if not d["missing_or_untrusted"]:
            out.append("None reported by the engine.")
        for m in d["missing_or_untrusted"]:
            out.append(f"- {code(m['side'])} pair {_num(m['pair'])} {code(m['test_id'] or 'whole-side')}: "
                       f"{code(m['reason_code'])}")
        cl = d["cleanup"]
        out += ["", "## Cleanup and resource preservation", "",
                f"Cleanup {code(cl['status'])}; containers created {_num(cl['containers_created'])}, removed "
                f"{_num(cl['removed'])}, owned remaining {_num(cl['remaining_owned_containers'])}; inventory "
                f"{code(cl['inventory_reconciliation'])}; daemon restart suspected "
                f"{code(cl['daemon_restart_suspected'])}. {prose(cl['note'])}",
                "", "## Remediation summary", "", prose(d["remediation"]),
                "", "## Reproducibility prerequisites", ""]
        out += [f"- {prose(r)}" for r in d["reproducibility"]]
    out += ["", "## Limitations", ""]
    out += [f"- {prose(x)}" for x in d["limitations"]]
    return "\n".join(out) + "\n"


def write_output(path: Path, text: str, data_root: Path) -> Path:
    """Write a new 0600 report file atomically. Never overwrites, never follows a symlink at the
    destination and never writes inside the private data directory.

    The text goes to a hidden temporary file in the destination directory (exclusive create,
    fsynced), which is then hard-linked to the requested name; the link fails if anything already
    has that name, a dangling symlink included. The temporary name is always removed, so a failure
    leaves nothing at the destination. The evidence is never opened for writing.
    """
    target = Path(os.path.abspath(path))
    name = target.name
    if not name or name in (".", "..") or "/" in name:
        raise OutputError("--output must name a file")
    data = text.encode("utf-8")
    try:
        dir_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
    except OSError as exc:
        raise OutputError(f"the output directory cannot be opened: {exc.strerror}") from None
    try:
        parent = os.path.realpath(target.parent)
        private = os.path.realpath(data_root)
        opened, resolved = os.fstat(dir_fd), os.stat(parent)
        if (opened.st_dev, opened.st_ino) != (resolved.st_dev, resolved.st_ino):
            raise OutputError("the output directory changed while it was being checked")
        if parent == private or Path(parent).is_relative_to(private):
            raise OutputError("reports are never written inside the private data directory")
        temporary = f".{name[:64]}.{secrets.token_hex(8)}.tmp"
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dir_fd)
        except OSError as exc:
            raise OutputError(f"the output directory is not writable: {exc.strerror}") from None
        try:
            try:
                view = memoryview(data)
                while view:
                    view = view[os.write(fd, view):]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.link(temporary, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd, follow_symlinks=False)
        except FileExistsError:
            raise OutputError(f"{plain(name, 200)} already exists; reports never overwrite a file") from None
        except OSError as exc:
            raise OutputError(f"the report could not be written: {exc.strerror}") from None
        finally:
            try:
                os.unlink(temporary, dir_fd=dir_fd)
            except FileNotFoundError:
                pass
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    return Path(parent) / name
