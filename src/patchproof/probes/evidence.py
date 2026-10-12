"""Bounded, structured evidence for one probe-suite run (schema: isolation-probe-run 1.0).

The record separates what was requested, what Docker reported, what the kernel reported,
and what a probe actually exercised. `control_claims` is computed from probe outcomes,
so a control is described as enforced only when a behavioral probe for it passed in
this run. Nothing here performs I/O except `write_private`, which writes only inside an
already-existing, owner-only evidence directory (the A3 gate).
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Final

from ..runner.docker_cli import create_argv_tail
from ..runner.policy import DOCKER_CONTEXT, ContainerSpec, Ownership, PolicyViolation, script_sha256
from .catalogue import BY_ID, CATALOGUE, SUITE_VERSION, EvidenceType
from .interpret import ContainerFacts, Outcome, ProbeOutcome, SuiteStatus

SCHEMA_VERSION: Final = "1.0"
RECORD_TYPE: Final = "isolation-probe-run"
MAX_RECORD_BYTES: Final = 2 * 1024 * 1024


class ClaimStatus(str, Enum):
    ENFORCEMENT_EXERCISED = "ENFORCEMENT_EXERCISED"
    CONFIGURED_ONLY = "CONFIGURED_ONLY"
    FAILED = "FAILED"
    UNVERIFIED = "UNVERIFIED"


# Each required control (PP-003 assignment §4.A) and the probes that bear on it.
CONTROL_PROBES: Final[Mapping[str, tuple[str, ...]]] = {
    "explicit-docker-context": ("PRE-01",),
    "fixed-non-root-identity": ("PRV-01", "PRV-02"),
    "read-only-root-filesystem": ("FS-01",),
    "all-capabilities-dropped": ("PRV-03", "PRV-04", "PRV-05", "PRV-06"),
    "no-new-privileges": ("PRV-07",),
    "default-seccomp": ("PRV-08", "PRV-09", "PRV-10"),
    "not-privileged": ("PRV-10", "PRV-11", "PRV-12", "PRV-13", "POL-06"),
    "no-host-namespaces": ("NS-01", "NS-02", "NS-03", "NET-01"),
    "no-docker-socket-or-engine-api": ("FS-02", "NET-06"),
    "no-host-credential-home-or-repo-mounts": ("FS-03", "FS-04", "FS-09"),
    "no-host-environment": ("FS-05",),
    "no-published-ports": ("NET-08",),
    "no-external-connectivity": ("NET-02", "NET-03", "NET-04", "NET-05", "NET-07", "NET-09"),
    "approved-loopback-topology": ("NET-P1", "NS-02"),
    "target-verifier-file-separation": ("FS-06", "FS-07"),
    "cpu-limit": ("RES-05", "RES-06"),
    "memory-limit": ("RES-01", "RES-02"),
    "process-limit": ("RES-03", "RES-04"),
    "bounded-scratch-storage": ("FS-08", "FS-10", "RES-07", "RES-08", "RES-09", "RES-14"),
    "bounded-logs-and-output": ("RES-10", "RES-11", "RES-13"),
    "deadline-and-forced-termination": ("RES-12", "RES-15"),
    "immutable-image-no-implicit-pull": ("PRE-02", "PRE-03"),
    "policy-refusal-before-start": ("POL-01", "POL-02", "POL-03", "POL-04", "POL-05"),
    "exact-id-ownership-cleanup": ("CLN-01", "CLN-02", "CLN-03", "CLN-04", "CLN-05"),
    "unrelated-resources-preserved": ("CLN-06",),
}

EXERCISING: Final = frozenset({EvidenceType.BEHAVIORAL, EvidenceType.HOST_CHECK})

STANDING_LIMITATIONS: Final = (
    "Results describe this Docker Desktop installation on the recorded date only; they are not a "
    "guarantee against container-runtime vulnerabilities (PROJECT_SPEC.md 4.1).",
    "Configuration evidence (inspect, kernel-reported state) is not enforcement evidence; see control_claims.",
    "Network negatives sample representative destinations; the structural evidence is NET-01 and NET-09.",
    "CPU enforcement (RES-06) is statistical and sensitive to host load.",
    "Daemon log retention (RES-11) is measured through docker logs, not on-disk size inside the VM.",
    "no-new-privileges is kernel-reported (NoNewPrivs); no setuid binary is executed to exercise it.",
    "Root-only writable mounts (/dev tmpfs, /dev/mqueue) are classified, not write-exercised beyond /etc bind files.",
    "Interrupted-run recovery is covered by unit tests; the probe run does not deliberately crash itself.",
)


def claim_status(outcomes: Mapping[str, Outcome], probe_ids: Sequence[str]) -> ClaimStatus:
    results = [outcomes.get(p, Outcome.NOT_RUN) for p in probe_ids]
    if any(r is Outcome.FAIL for r in results):
        return ClaimStatus.FAILED
    if not results or any(r is not Outcome.PASS for r in results):
        return ClaimStatus.UNVERIFIED
    if any(BY_ID[p].evidence in EXERCISING for p in probe_ids):
        return ClaimStatus.ENFORCEMENT_EXERCISED
    return ClaimStatus.CONFIGURED_ONLY


def control_claims(outcomes: Sequence[ProbeOutcome]) -> list[dict[str, Any]]:
    by_id = {o.probe_id: o.outcome for o in outcomes}
    return [
        {"control": control, "status": claim_status(by_id, probes).value, "probes": list(probes)}
        for control, probes in CONTROL_PROBES.items()
    ]


def requested_policy_digest(spec: ContainerSpec) -> str:
    """Hash of the exact create argv, with the script replaced by its digest."""
    tail = create_argv_tail(spec)
    digest = script_sha256(spec.script)
    rendered = [digest if token == spec.script else token for token in tail]
    return "sha256:" + hashlib.sha256(json.dumps(rendered).encode()).hexdigest()


def render_argv_for_review(spec: ContainerSpec) -> list[str]:
    """The create argv with the probe script shown as its digest, for plans and logs."""
    digest = script_sha256(spec.script)
    return ["docker", "--context", DOCKER_CONTEXT] + [
        f"<probe-script {digest}>" if token == spec.script else token for token in create_argv_tail(spec)
    ]


def _bounded(text: str, limit: int = 600) -> str:
    cleaned = "".join(ch if ch >= " " and ch != "\x7f" else " " for ch in text)
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 3] + "..."


@dataclass
class ContainerRecord:
    facts: ContainerFacts
    name: str
    container_id: str | None
    policy_digest: str
    gate_mismatches: list[dict[str, str]]
    cleanup_status: str
    cleanup_detail: str

    def to_json(self) -> dict[str, Any]:
        stream = self.facts.stream
        return {
            "role": self.facts.role.value,
            "name": self.name,
            "container_id": self.container_id,
            "requested_policy_sha256": self.policy_digest,
            "gate": {"passed": self.facts.gate_passed, "mismatches": self.gate_mismatches[:64]},
            "started": self.facts.started,
            "exit_code": self.facts.exit_code,
            "oom_killed": self.facts.oom_killed,
            "wait_timed_out": self.facts.wait_timed_out,
            "stream": None if stream is None else {
                "observations": len(stream.observations),
                "ended": stream.ended,
                "truncated": stream.truncated,
                "malformed_lines": stream.malformed_lines,
                "foreign_records": stream.foreign_records,
                "duplicates": sorted(stream.duplicates)[:32],
            },
            "error": _bounded(self.facts.error, 400) or None,
            "cleanup": {"status": self.cleanup_status, "detail": _bounded(self.cleanup_detail, 400)},
        }


def build_record(
    *,
    ownership: Ownership,
    started_at: str,
    finished_at: str,
    server_version: str | None,
    image: Mapping[str, Any] | None,
    script_digest: str,
    authorization: Mapping[str, bool],
    containers: Sequence[ContainerRecord],
    outcomes: Sequence[ProbeOutcome],
    status: SuiteStatus,
    preservation: Mapping[str, Any],
    execution: Mapping[str, Any] | None = None,
    extra_limitations: Sequence[str] = (),
) -> dict[str, Any]:
    by_id = {o.probe_id: o for o in outcomes}
    probes = []
    for spec in CATALOGUE:
        result = by_id.get(spec.probe_id)
        probes.append({
            "probe_id": spec.probe_id,
            "title": spec.title,
            "category": spec.category.value,
            "kind": spec.kind.value,
            "evidence_type": spec.evidence.value,
            "critical": spec.critical,
            "controls": list(spec.controls),
            "internal_control": spec.internal_control or None,
            "expected": spec.expected,
            "outcome": (result.outcome if result else Outcome.NOT_RUN).value,
            "observed": _bounded(result.summary if result else "not executed"),
            "roles": [r.value for r in spec.roles],
        })
    record = {
        "schema_version": SCHEMA_VERSION,
        "record_type": RECORD_TYPE,
        "suite_version": SUITE_VERSION,
        "run_id": ownership.run_id,
        "installation_id": ownership.installation_id,
        "started_at": started_at,
        "finished_at": finished_at,
        "docker": {"context": DOCKER_CONTEXT, "server_version": server_version},
        "image": dict(image) if image else None,
        "probe_script_sha256": script_digest,
        "authorization": dict(authorization),
        "containers": [c.to_json() for c in containers],
        "probes": probes,
        "control_claims": control_claims(outcomes),
        "preservation": dict(preservation),
        "execution": dict(execution) if execution is not None else {
            "global_deadline_seconds": 1200, "cleanup_window_seconds": 120, "active_elapsed_seconds": 0.0,
            "deadline_expired": False, "expired_during_phase": None, "interrupted": False,
            "cleanup_window_expired": False, "cleanup_status": "NOT_NEEDED"},
        "suite_status": status.value,
        "limitations": [_bounded(t, 400) for t in (*STANDING_LIMITATIONS, *extra_limitations)][:32],
    }
    check_record_complete(record)
    return record


def check_record_complete(record: Mapping[str, Any]) -> None:
    """Code-level completeness rules the schema cannot express."""
    ids = [p["probe_id"] for p in record["probes"]]
    if sorted(ids) != sorted(BY_ID):
        raise ValueError("record does not list exactly the catalogue probes")
    passed_status = record["suite_status"] == SuiteStatus.ALL_PLANNED_PROBES_PASSED.value
    if passed_status and any(p["outcome"] != "PASS" for p in record["probes"]):
        raise ValueError("suite status claims all probes passed while some did not")
    if passed_status and record["preservation"].get("outcome") != "PASS":
        raise ValueError("suite status claims success without an exact preservation check")
    execution = record["execution"]
    if passed_status and (execution["deadline_expired"] or execution["interrupted"]):
        raise ValueError("suite status claims success after the deadline expired or the run was interrupted")
    if passed_status and execution["cleanup_status"] != "COMPLETE":
        raise ValueError("suite status claims success without complete cleanup")
    for claim in record["control_claims"]:
        if claim["status"] == ClaimStatus.ENFORCEMENT_EXERCISED.value:
            outcomes = {p["probe_id"]: p["outcome"] for p in record["probes"]}
            if any(outcomes[pid] != "PASS" for pid in claim["probes"]):
                raise ValueError("enforcement claimed for a control whose probes did not all pass")
    if len(json.dumps(record).encode()) > MAX_RECORD_BYTES:
        raise ValueError("record exceeds its size bound")


# --- Private evidence directory (A3) -----------------------------------------------------


def verify_evidence_root(root: Path) -> None:
    """The A3 directory must already exist, be a real directory, owned by us, mode 0700.

    This module never creates it: creating the permanent evidence location is a
    separately approved step.
    """
    try:
        info = os.lstat(root)
    except FileNotFoundError as exc:
        raise PolicyViolation(f"evidence root {root} does not exist (A3 not completed)") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise PolicyViolation("evidence root is not a directory (symlinks are refused)")
    if info.st_uid != os.getuid():
        raise PolicyViolation("evidence root is not owned by the current user")
    if stat.S_IMODE(info.st_mode) != 0o700:
        raise PolicyViolation("evidence root must have mode 0700")


def create_run_dir(root: Path, ownership: Ownership) -> Path:
    verify_evidence_root(root)
    run_dir = root / ownership.run_id
    os.mkdir(run_dir, 0o700)  # fails if it already exists: no reuse of a run directory
    return run_dir


def write_private(run_dir: Path, name: str, data: bytes) -> None:
    if "/" in name or name.startswith("."):
        raise PolicyViolation("evidence file names are flat")
    fd = os.open(run_dir / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
