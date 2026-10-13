"""Single-use interruption-test authorizations: creation, semantic checks, private storage and the claim (PP-008).

This mirrors `core.run_authorizations` for a separate contract
(`interruption-test-authorization` 1.0) in a separate store
(`<user data>/interruption-authorizations/`). Neither store accepts the other's files, and
nothing here reads, writes or reinterprets a run authorization.

**Storage rules (the accepted `RunAuthorizationStore` discipline, applied unchanged):** a
private (0700) directory owned by the current user, opened without following symlinks and
re-checked by device and inode on every operation. Records and claims are created
exclusively and read-only (0400), fsynced with their directory, read with a size bound and
strictly validated. Unexpected entries, corrupted or partial records and ambiguous history
refuse the whole store.

**Single use.** Executing starts with a claim (`iau-<id>.claim`, `O_CREAT|O_EXCL`, fsynced
before the runner child exists). A claim is never removed. A claim file that is empty or
unreadable (a crash during the claim) is `INDETERMINATE` and counts as consumed. There is no
retry, no reset, and a consumed authorization can never be superseded: supersession applies
only to the single unused, unclaimed record.

**The claim names the controller.** It records the PID of the process that claimed it. The
runner child refuses to execute unless that PID is its own parent, so the child cannot be
started from a shell against someone else's claim.

**Limits:** workflow accountability, not proof of who authorized
(`reviewer.basis = local-assertion-unverified`); the same OS account can write these files.
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
from .records.interruption import InterruptionPlanDocument, InterruptionTestAuthorization
from .run_authorizations import AuthorizationDecision

MAX_AUTHORIZATION_BYTES: Final = 65536
MAX_CLAIM_BYTES: Final = 4096
_ID_RE: Final = re.compile(r"iau-[0-9a-f]{32}")
_RECORD_RE: Final = re.compile(r"iau-[0-9a-f]{32}\.json")
_CLAIM_RE: Final = re.compile(r"iau-[0-9a-f]{32}\.claim")
_RUN_RE: Final = re.compile(r"run-[0-9a-f]{32}")
_STAMP_RE: Final = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_REPEATED_HEX_RE: Final = re.compile(r"(?:sha256:)?([0-9a-f])\1{39,63}")


class InterruptionAuthorizationError(ValueError):
    """An interruption-test authorization could not be created, stored, read or claimed as specified."""


def interruption_plan_sha256(plan: InterruptionPlanDocument) -> str:
    return canonical_sha256(plan)


def interruption_container_names(run_id: str) -> tuple[str, str]:
    """(target, verifier): the baseline names of the ordinary naming scheme, nothing else."""
    short = run_id[4:16]
    return f"pp-run-{short}-p1-baseline-target", f"pp-run-{short}-p1-baseline-verifier"


def interruption_evidence_destination(run_id: str) -> str:
    return f"evidence/interruption-tests/{run_id}"


def _hex_values(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _hex_values(v)]
    if isinstance(value, list):
        return [s for v in value for s in _hex_values(v)]
    return []


def check_interruption_plan(plan: InterruptionPlanDocument) -> None:
    """Rules the schema cannot express. Raises InterruptionAuthorizationError."""
    if any(_REPEATED_HEX_RE.fullmatch(s) for s in _hex_values(plan.model_dump(mode="json"))):
        raise InterruptionAuthorizationError("the plan contains a placeholder identity (one repeated hex digit)")
    if (plan.containers.target.name, plan.containers.verifier.name) != interruption_container_names(plan.run_id):
        raise InterruptionAuthorizationError("the container names do not match the run ID")
    if plan.evidence.destination != interruption_evidence_destination(plan.run_id):
        raise InterruptionAuthorizationError("the evidence destination does not match the run ID")
    if plan.source_inclusion.include != sorted(plan.source_inclusion.include):
        raise InterruptionAuthorizationError("the source inclusion list is not in canonical (sorted) order")
    if plan.images.target_image_id == plan.images.verifier_image_id:
        raise InterruptionAuthorizationError("target and verifier images must differ")


def check_interruption_authorization(record: InterruptionTestAuthorization) -> None:
    check_interruption_plan(record.plan)
    if record.plan_sha256 != interruption_plan_sha256(record.plan):
        raise InterruptionAuthorizationError("plan_sha256 is not the hash of the plan")
    if record.supersedes == record.authorization_id:
        raise InterruptionAuthorizationError("an authorization cannot supersede itself")


def interruption_authorization_phrase(plan: InterruptionPlanDocument) -> str:
    """The exact text the owner types to authorize: it names the test, the run and the plan hash."""
    return f"AUTHORIZE INTERRUPTION TEST {plan.run_id} {interruption_plan_sha256(plan)}"


def interruption_execution_phrase(plan: InterruptionPlanDocument) -> str:
    return f"INTERRUPT {plan.run_id}"


def create_interruption_authorization(plan: InterruptionPlanDocument, decision: AuthorizationDecision, *,
                                      supersedes: InterruptionTestAuthorization | None,
                                      now: datetime) -> InterruptionTestAuthorization:
    check_interruption_plan(plan)
    if decision.typed_confirmation != interruption_authorization_phrase(plan):
        raise InterruptionAuthorizationError("the typed confirmation does not match this plan; nothing was authorized")
    if now.tzinfo is None:
        raise InterruptionAuthorizationError("the authorization time must be timezone-aware")
    try:
        record = validate_record(InterruptionTestAuthorization, {
            "schema_version": "1.0", "kind": "interruption-test-authorization",
            "authorization_id": f"iau-{secrets.token_hex(16)}",
            "created_at": now.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "supersedes": supersedes.authorization_id if supersedes else None, "single_use": True,
            "plan_sha256": interruption_plan_sha256(plan), "plan": plan.model_dump(mode="json"),
            "reviewer": {"asserted_identity": decision.asserted_identity, "basis": "local-assertion-unverified"},
            "rationale": decision.rationale, "scope": decision.scope,
        }, "interruption-test-authorization")
    except RecordError as exc:
        raise InterruptionAuthorizationError(str(exc)) from None
    check_interruption_authorization(record)
    return record


ClaimState = Literal["CLAIMED", "INDETERMINATE"]


@dataclass(frozen=True)
class InterruptionClaim:
    authorization_id: str
    state: ClaimState
    raw: bytes
    run_id: str | None = None
    pid: int | None = None


@dataclass(frozen=True)
class StoredInterruptionAuthorization:
    record: InterruptionTestAuthorization
    raw: bytes


def parse_claim(data: bytes, ident: str) -> InterruptionClaim:
    """Strict: exactly the four keys the claim writes. Anything else is INDETERMINATE (consumed)."""
    indeterminate = InterruptionClaim(ident, "INDETERMINATE", data)
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return indeterminate
    if not isinstance(doc, dict) or set(doc) != {"authorization_id", "run_id", "pid", "claimed_at"}:
        return indeterminate
    pid, run_id, claimed_at = doc["pid"], doc["run_id"], doc["claimed_at"]
    if (doc["authorization_id"] != ident or not isinstance(run_id, str) or not _RUN_RE.fullmatch(run_id)
            or not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1
            or not isinstance(claimed_at, str) or not _STAMP_RE.fullmatch(claimed_at)):
        return indeterminate
    return InterruptionClaim(ident, "CLAIMED", data, run_id, pid)


class InterruptionAuthorizationStore:
    """Append-only private directory of interruption-test authorizations and their claims."""

    def __init__(self, root: Path) -> None:
        raw = str(root)
        if not os.path.isabs(raw) or os.path.realpath(raw) != raw:
            raise InterruptionAuthorizationError("interruption-authorization store must be an absolute canonical "
                                                 "directory")
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
            raise InterruptionAuthorizationError("interruption-authorization store is missing, not a directory, "
                                                 "or a symlink") from exc
        st = os.fstat(fd)
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700
                or (identity is not None and (st.st_dev, st.st_ino) != identity)):
            os.close(fd)
            raise InterruptionAuthorizationError("interruption-authorization store must be the same 0700 directory "
                                                 "owned by you")
        return fd

    def _read(self, dir_fd: int, name: str, limit: int) -> bytes:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
        with os.fdopen(fd, "rb") as handle:
            st = os.fstat(handle.fileno())
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
                raise InterruptionAuthorizationError(f"{name} is not a regular file owned by you")
            return handle.read(limit + 1)

    def _scan(self, dir_fd: int) -> tuple[dict[str, StoredInterruptionAuthorization], dict[str, InterruptionClaim]]:
        records: dict[str, StoredInterruptionAuthorization] = {}
        claims: dict[str, InterruptionClaim] = {}
        for name in sorted(os.listdir(dir_fd)):
            is_record, is_claim = _RECORD_RE.fullmatch(name), _CLAIM_RE.fullmatch(name)
            if not (is_record or is_claim) or not stat.S_ISREG(
                    os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode):
                raise InterruptionAuthorizationError(f"unexpected entry {name!r} in the interruption-authorization "
                                                     "store")
            data = self._read(dir_fd, name, MAX_AUTHORIZATION_BYTES if is_record else MAX_CLAIM_BYTES)
            ident = name.rsplit(".", 1)[0]
            if is_claim:
                claims[ident] = parse_claim(data, ident)
                continue
            try:
                record = load_record(InterruptionTestAuthorization, data, contract="interruption-test-authorization",
                                     max_bytes=MAX_AUTHORIZATION_BYTES)
                check_interruption_authorization(record)
            except (RecordError, InterruptionAuthorizationError) as exc:
                raise InterruptionAuthorizationError(f"{name} is not a valid interruption-test authorization") \
                    from exc
            if record.authorization_id != ident:
                raise InterruptionAuthorizationError(f"{name} does not match its authorization ID")
            records[ident] = StoredInterruptionAuthorization(record, data)
        _check_history(records, claims)
        return records, claims

    def scan(self) -> tuple[dict[str, StoredInterruptionAuthorization], dict[str, InterruptionClaim]]:
        dir_fd = self._open_root(self._identity)
        try:
            return self._scan(dir_fd)
        finally:
            os.close(dir_fd)

    def executable(self) -> StoredInterruptionAuthorization | None:
        """The single authorization that is neither claimed nor superseded, or None."""
        records, claims = self.scan()
        return _executable(records, claims)

    def save(self, record: InterruptionTestAuthorization) -> Path:
        check_interruption_authorization(record)
        dir_fd = self._open_root(self._identity)
        try:
            records, claims = self._scan(dir_fd)
            if any(r.record.plan.run_id == record.plan.run_id for r in records.values()):
                raise InterruptionAuthorizationError("that run ID already has an authorization; a run ID is never "
                                                     "reused")
            current = _executable(records, claims)
            expected = current.record.authorization_id if current else None
            if record.supersedes != expected:
                raise InterruptionAuthorizationError(
                    "a new authorization must supersede exactly the current unused authorization"
                    if expected else "there is no unused authorization to supersede (a consumed one never is)")
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
        """Consume an authorization, durably and exclusively, naming this process. Raises if already claimed.

        The claim file is created with O_EXCL, written, fsynced and its directory fsynced
        before this returns. Nothing ever removes it.
        """
        if not _ID_RE.fullmatch(authorization_id) or not _RUN_RE.fullmatch(run_id):
            raise InterruptionAuthorizationError("invalid authorization or run ID")
        data = json.dumps({"authorization_id": authorization_id, "run_id": run_id, "pid": os.getpid(),
                           "claimed_at": now.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")},
                          sort_keys=True).encode("utf-8") + b"\n"
        dir_fd = self._open_root(self._identity)
        try:
            try:
                fd = os.open(f"{authorization_id}.claim", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o400, dir_fd=dir_fd)
            except FileExistsError:
                raise InterruptionAuthorizationError("this authorization has already been claimed; it is consumed") \
                    from None
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        return data


def _check_history(records: dict[str, StoredInterruptionAuthorization],
                   claims: dict[str, InterruptionClaim]) -> None:
    if any(ident not in records for ident in claims):
        raise InterruptionAuthorizationError("a claim names an authorization that is not in the store")
    superseded = [r.record.supersedes for r in records.values() if r.record.supersedes is not None]
    if any(s not in records for s in superseded):
        raise InterruptionAuthorizationError("an authorization supersedes a record that is missing")
    if len(superseded) != len(set(superseded)):
        raise InterruptionAuthorizationError("an authorization was superseded twice; the history is ambiguous")
    run_ids = [r.record.plan.run_id for r in records.values()]
    if len(run_ids) != len(set(run_ids)):
        raise InterruptionAuthorizationError("two authorizations name the same run ID")
    for ident, claim in claims.items():
        if claim.state == "CLAIMED" and claim.run_id != records[ident].record.plan.run_id:
            raise InterruptionAuthorizationError("a claim names a different run than its authorization")


def _executable(records: dict[str, StoredInterruptionAuthorization],
                claims: dict[str, InterruptionClaim]) -> StoredInterruptionAuthorization | None:
    superseded = {r.record.supersedes for r in records.values()}
    open_ = [r for ident, r in records.items() if ident not in claims and ident not in superseded]
    if len(open_) > 1:
        raise InterruptionAuthorizationError("more than one unused authorization; the history is ambiguous")
    return open_[0] if open_ else None


def is_superseded(records: dict[str, StoredInterruptionAuthorization], authorization_id: str) -> bool:
    return any(r.record.supersedes == authorization_id for r in records.values())
