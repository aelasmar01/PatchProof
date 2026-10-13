"""Single-use run authorizations: creation, semantic checks, private storage and the claim (PP-008).

**What an authorization binds:** one frozen `RunPlanDocument` (schemas/run-authorization
1.0), identified by `plan_sha256`, the SHA-256 of its canonical JSON. The plan names the
current pack approval, the run and installation IDs, every input identity, the runtime
limits and the evidence destination. A pack approval never authorizes a run.

**Single use.** Executing an authorization starts with a *claim*: a `rau-<id>.claim` file
created with `O_CREAT|O_EXCL`, fsynced together with its directory, before the first Docker
operation. A claim is never removed or reset. An authorization with a claim file is
consumed. A claim file that is empty or unreadable (a crash during the claim) is
`INDETERMINATE`, which is treated as consumed. There is no retry, no reset and no
re-authorization of the same run ID.

**Supersession.** An unused authorization can be replaced by a new one that names it in
`supersedes`. A claimed authorization can never be superseded, and each authorization can
be superseded at most once. The executable authorization is the single record that is
neither claimed nor superseded.

**Storage rules (reusing the PP-007 `ApprovalStore` discipline):** a private (0700)
directory owned by the current user, opened as a directory descriptor without following
symlinks and re-checked by device and inode on every operation. Records and claims are
created exclusively and read-only (0400), read with a size bound, and strictly validated.
Unexpected entries, corrupted records and ambiguous history refuse the whole store.

**Limits:** like approvals, this is workflow accountability, not proof of who authorized:
the same OS account can write these files (`reviewer.basis = local-assertion-unverified`).
"""

from __future__ import annotations

import json
import os
import re
import secrets
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal

from .approvals import canonical_sha256
from .records import RecordError, load_record, validate_record
from .records.authorization import RunAuthorization, RunPlanDocument

MAX_AUTHORIZATION_BYTES: Final = 65536
MAX_CLAIM_BYTES: Final = 4096
_RECORD_RE: Final = re.compile(r"rau-[0-9a-f]{32}\.json")
_CLAIM_RE: Final = re.compile(r"rau-[0-9a-f]{32}\.claim")
_REPEATED_HEX_RE: Final = re.compile(r"(?:sha256:)?([0-9a-f])\1{39,63}")


class RunAuthorizationError(ValueError):
    """A run authorization could not be created, stored, read or claimed as specified."""


def plan_sha256(plan: RunPlanDocument) -> str:
    return canonical_sha256(plan)


def container_names(run_id: str) -> list[tuple[str, str, str]]:
    """(side, role, name) of the four containers, in execution order."""
    short = run_id[4:16]
    return [(side, role, f"pp-run-{short}-p1-{side}-{role}")
            for side in ("baseline", "candidate") for role in ("target", "verifier")]


def _hex_values(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _hex_values(v)]
    if isinstance(value, list):
        return [s for v in value for s in _hex_values(v)]
    return []


def check_plan_semantics(plan: RunPlanDocument) -> None:
    """Rules the schema cannot express. Raises RunAuthorizationError."""
    if any(_REPEATED_HEX_RE.fullmatch(s) for s in _hex_values(plan.model_dump(mode="json"))):
        raise RunAuthorizationError("the plan contains a placeholder identity (one repeated hex digit)")
    expected = container_names(plan.run_id)
    observed = [(c.side, c.role, c.name) for c in plan.containers.sequence]
    if observed != expected:
        raise RunAuthorizationError("the container sequence does not match the run ID and the fixed order")
    if plan.evidence.destination != f"evidence/runs/{plan.run_id}":
        raise RunAuthorizationError("the evidence destination does not match the run ID")
    if plan.source_inclusion.include != sorted(plan.source_inclusion.include):
        raise RunAuthorizationError("the source inclusion list is not in canonical (sorted) order")
    # Baseline and candidate may be the same revision: PROJECT_SPEC.md 17.2 compares the
    # unchanged vulnerable revision against itself. Which revisions a particular driver may
    # run is that driver's rule (`papertrail_plan.check_first_run_scope`), not this contract's.
    if plan.images.target_image_id == plan.images.verifier_image_id:
        raise RunAuthorizationError("target and verifier images must differ")


def check_authorization(record: RunAuthorization) -> None:
    check_plan_semantics(record.plan)
    if record.plan_sha256 != plan_sha256(record.plan):
        raise RunAuthorizationError("plan_sha256 is not the hash of the plan")
    if record.supersedes == record.authorization_id:
        raise RunAuthorizationError("an authorization cannot supersede itself")


def authorization_phrase(plan: RunPlanDocument) -> str:
    """The exact text the owner types: it names the run and the full plan identity."""
    return f"AUTHORIZE {plan.run_id} {plan_sha256(plan)}"


def execution_phrase(plan: RunPlanDocument) -> str:
    return f"EXECUTE {plan.run_id}"


@dataclass(frozen=True)
class AuthorizationDecision:
    """The owner's explicit action. Every field is required; nothing has a default."""

    asserted_identity: str
    rationale: str
    scope: str
    typed_confirmation: str


def create_authorization(plan: RunPlanDocument, decision: AuthorizationDecision, *,
                         supersedes: RunAuthorization | None, now: datetime) -> RunAuthorization:
    check_plan_semantics(plan)
    if decision.typed_confirmation != authorization_phrase(plan):
        raise RunAuthorizationError("the typed confirmation does not match this plan; nothing was authorized")
    if now.tzinfo is None:
        raise RunAuthorizationError("the authorization time must be timezone-aware")
    record = validate_record(RunAuthorization, {
        "schema_version": "1.0", "kind": "run-authorization", "authorization_id": f"rau-{secrets.token_hex(16)}",
        "created_at": now.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "supersedes": supersedes.authorization_id if supersedes else None, "single_use": True,
        "plan_sha256": plan_sha256(plan), "plan": plan.model_dump(mode="json"),
        "reviewer": {"asserted_identity": decision.asserted_identity, "basis": "local-assertion-unverified"},
        "rationale": decision.rationale, "scope": decision.scope,
    }, "run-authorization")
    check_authorization(record)
    return record


ClaimState = Literal["CLAIMED", "INDETERMINATE"]


@dataclass(frozen=True)
class Claim:
    authorization_id: str
    state: ClaimState
    raw: bytes


@dataclass(frozen=True)
class StoredAuthorization:
    record: RunAuthorization
    raw: bytes


class RunAuthorizationStore:
    """Append-only private directory of run authorizations and their single-use claims."""

    def __init__(self, root: Path) -> None:
        raw = str(root)
        if not os.path.isabs(raw) or os.path.realpath(raw) != raw:
            raise RunAuthorizationError("run-authorization store must be an absolute canonical directory")
        self.root = root
        fd = self._open_root(identity=None)
        try:
            st = os.fstat(fd)
            self._identity = (st.st_dev, st.st_ino)
        finally:
            os.close(fd)

    @property
    def identity(self) -> tuple[int, int]:
        return self._identity

    def _open_root(self, identity: tuple[int, int] | None) -> int:
        try:
            fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as exc:
            raise RunAuthorizationError("run-authorization store is missing, not a directory, or a symlink") from exc
        st = os.fstat(fd)
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700
                or (identity is not None and (st.st_dev, st.st_ino) != identity)):
            os.close(fd)
            raise RunAuthorizationError("run-authorization store must be the same 0700 directory owned by you")
        return fd

    def _read(self, dir_fd: int, name: str, limit: int) -> bytes:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
        with os.fdopen(fd, "rb") as handle:
            st = os.fstat(handle.fileno())
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
                raise RunAuthorizationError(f"{name} is not a regular file owned by you")
            return handle.read(limit + 1)

    def _scan(self, dir_fd: int) -> tuple[dict[str, StoredAuthorization], dict[str, Claim]]:
        records: dict[str, StoredAuthorization] = {}
        claims: dict[str, Claim] = {}
        for name in sorted(os.listdir(dir_fd)):
            is_record, is_claim = _RECORD_RE.fullmatch(name), _CLAIM_RE.fullmatch(name)
            if not (is_record or is_claim) or not stat.S_ISREG(
                    os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode):
                raise RunAuthorizationError(f"unexpected entry {name!r} in the run-authorization store")
            data = self._read(dir_fd, name, MAX_AUTHORIZATION_BYTES if is_record else MAX_CLAIM_BYTES)
            ident = name.rsplit(".", 1)[0]
            if is_claim:
                claims[ident] = Claim(ident, _claim_state(data, ident), data)
                continue
            try:
                record = load_record(RunAuthorization, data, contract="run-authorization",
                                     max_bytes=MAX_AUTHORIZATION_BYTES)
                check_authorization(record)
            except (RecordError, RunAuthorizationError) as exc:
                raise RunAuthorizationError(f"{name} is not a valid run authorization") from exc
            if record.authorization_id != ident:
                raise RunAuthorizationError(f"{name} does not match its authorization ID")
            records[ident] = StoredAuthorization(record, data)
        _check_history(records, claims)
        return records, claims

    def scan(self) -> tuple[dict[str, StoredAuthorization], dict[str, Claim]]:
        dir_fd = self._open_root(self._identity)
        try:
            return self._scan(dir_fd)
        finally:
            os.close(dir_fd)

    def executable(self) -> StoredAuthorization | None:
        """The single authorization that is neither claimed nor superseded, or None."""
        records, claims = self.scan()
        return _executable(records, claims)

    def save(self, record: RunAuthorization) -> Path:
        check_authorization(record)
        dir_fd = self._open_root(self._identity)
        try:
            records, claims = self._scan(dir_fd)
            if any(r.record.plan.run_id == record.plan.run_id for r in records.values()):
                raise RunAuthorizationError("that run ID already has an authorization; a run ID is never reused")
            current = _executable(records, claims)
            expected = current.record.authorization_id if current else None
            if record.supersedes != expected:
                raise RunAuthorizationError(
                    "a new authorization must supersede exactly the current unused authorization"
                    if expected else "there is no unused authorization to supersede")
            name = f"{record.authorization_id}.json"
            data = json.dumps(record.model_dump(mode="json"), indent=2, sort_keys=True).encode("utf-8") + b"\n"
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=dir_fd)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        return self.root / name

    def claim(self, authorization_id: str, *, run_id: str, now: datetime) -> bytes:
        """Consume an authorization, durably and exclusively. Raises if it is already claimed.

        The claim file is created with O_EXCL, written, fsynced and its directory fsynced
        before this returns. Nothing ever removes it.
        """
        if not re.fullmatch(r"rau-[0-9a-f]{32}", authorization_id):
            raise RunAuthorizationError("invalid authorization ID")
        data = json.dumps({"authorization_id": authorization_id, "run_id": run_id, "pid": os.getpid(),
                           "claimed_at": now.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")},
                          sort_keys=True).encode("utf-8") + b"\n"
        dir_fd = self._open_root(self._identity)
        try:
            try:
                fd = os.open(f"{authorization_id}.claim", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o400, dir_fd=dir_fd)
            except FileExistsError:
                raise RunAuthorizationError("this authorization has already been claimed; it is consumed") from None
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        return data


def _claim_state(data: bytes, ident: str) -> ClaimState:
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "INDETERMINATE"
    if not isinstance(doc, dict) or doc.get("authorization_id") != ident:
        return "INDETERMINATE"
    return "CLAIMED"


def _check_history(records: dict[str, StoredAuthorization], claims: dict[str, Claim]) -> None:
    if any(ident not in records for ident in claims):
        raise RunAuthorizationError("a claim names an authorization that is not in the store")
    superseded = [r.record.supersedes for r in records.values() if r.record.supersedes is not None]
    if any(s not in records for s in superseded):
        raise RunAuthorizationError("an authorization supersedes a record that is missing")
    if len(superseded) != len(set(superseded)):
        raise RunAuthorizationError("an authorization was superseded twice; the history is ambiguous")
    run_ids = [r.record.plan.run_id for r in records.values()]
    if len(run_ids) != len(set(run_ids)):
        raise RunAuthorizationError("two authorizations name the same run ID")
    # A record can be both claimed and superseded only through a race between a driver's
    # claim and a new authorization. It is never executable either way, and the driver
    # re-checks supersession after claiming and before every revision.


def _executable(records: dict[str, StoredAuthorization], claims: dict[str, Claim]) -> StoredAuthorization | None:
    superseded = {r.record.supersedes for r in records.values()}
    open_ = [r for ident, r in records.items() if ident not in claims and ident not in superseded]
    if len(open_) > 1:
        raise RunAuthorizationError("more than one unused authorization; the history is ambiguous")
    return open_[0] if open_ else None


def is_superseded(records: dict[str, StoredAuthorization], authorization_id: str) -> bool:
    return any(r.record.supersedes == authorization_id for r in records.values())
