"""Pack approval records (PROJECT_SPEC.md 7.5, INV-10; schemas/approval-record.schema.json).

**What an approval binds:**
- the exact pack (ID, version, manifest hash and pack-tree hash);
- the exact collection observed in the verifier environment;
- the verifier image and plugin version;
- the execution profile;
- a locally asserted reviewer, with a timestamp, scope and rationale.

**Rules:**
- **Staleness:** changing any bound input makes the approval stale (`APPROVAL_STALE`). A
  stale approval is never silently refreshed.
- **Immutability:** records are written once (`O_EXCL`, read-only) and never edited or
  deleted. A replacement names the record it supersedes, and history is preserved.
- **Explicit owner action:** creation requires a phrase the reviewer must type exactly; it
  names the pack, version and manifest hash. There is no default reviewer, rationale or
  phrase anywhere in this module, so an approval cannot be produced by omission.

**Limits:**
- This is workflow accountability, not proof of who reviewed: the same OS account can
  write these files (`reviewer.basis = local-assertion-unverified`).
- Run authorization is a separate, later record (PP-009). It also binds the source
  snapshots, target image, resource policy and repetition plan; nothing here authorizes a
  run.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal

from pydantic import BaseModel

from .records import RecordError, load_record, validate_record
from .records.pack import ApprovalBindings, ApprovalRecord, CollectedTest

MAX_RECORD_BYTES: Final = 65536
_FILE_RE: Final = re.compile(r"apr-[0-9a-f]{32}\.json")


class ApprovalError(ValueError):
    """An approval could not be created, stored or read as specified."""


def canonical_sha256(record: BaseModel) -> str:
    """SHA-256 of a record's canonical JSON (sorted keys, no whitespace, field aliases)."""
    data = json.dumps(record.model_dump(mode="json", by_alias=True), sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(data.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class BindingInputs:
    """Current values of everything an approval binds. Computed fresh; never read from the approval."""

    pack_id: str
    pack_version: str
    manifest_sha256: str
    pack_tree_sha256: str
    collection: tuple[CollectedTest, ...]
    verifier_image_id: str
    verifier_plugin_version: str
    profile_id: str
    profile_sha256: str

    def bindings(self) -> ApprovalBindings:
        return validate_record(ApprovalBindings, {
            "pack_id": self.pack_id, "pack_version": self.pack_version, "pack_schema_version": "1.0",
            "manifest_sha256": self.manifest_sha256, "pack_tree_sha256": self.pack_tree_sha256,
            "expected_collection": [c.model_dump() for c in self.collection],
            "verifier_image_id": self.verifier_image_id, "verifier_plugin_version": self.verifier_plugin_version,
            "profile_id": self.profile_id, "profile_sha256": self.profile_sha256,
        }, "approval-bindings")


def confirmation_phrase(bindings: ApprovalBindings) -> str:
    """The exact text the reviewer types to approve these bindings."""
    return f"APPROVE {bindings.pack_id} {bindings.pack_version} {bindings.manifest_sha256[7:19]}"


@dataclass(frozen=True)
class ReviewDecision:
    """The reviewer's explicit action. Every field is required; nothing has a default."""

    asserted_identity: str
    rationale: str
    scope: str
    typed_confirmation: str


def create_approval(bindings: ApprovalBindings, decision: ReviewDecision, *, supersedes: ApprovalRecord | None,
                    now: datetime) -> ApprovalRecord:
    if bindings.pack_id == "verifier-selftest":
        raise ApprovalError("the synthetic verifier self-test pack can never be approved")
    if decision.typed_confirmation != confirmation_phrase(bindings):
        raise ApprovalError("the typed confirmation does not match these bindings; nothing was approved")
    if supersedes is not None and supersedes.bindings.pack_id != bindings.pack_id:
        raise ApprovalError("an approval can only supersede an approval of the same pack")
    if now.tzinfo is None:
        raise ApprovalError("the review time must be timezone-aware")
    stamp = now.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return validate_record(ApprovalRecord, {
        "schema_version": "1.0", "approval_id": f"apr-{secrets.token_hex(16)}", "kind": "pack-approval",
        "created_at": stamp, "supersedes": supersedes.approval_id if supersedes else None,
        "bindings": bindings.model_dump(),
        "reviewer": {"asserted_identity": decision.asserted_identity, "basis": "local-assertion-unverified"},
        "rationale": decision.rationale, "scope": decision.scope,
    }, "approval-record")


class ApprovalStore:
    """Append-only directory of approval records. Never overwrites, edits or deletes.

    Every operation opens the root as a directory descriptor (`O_DIRECTORY|O_NOFOLLOW`) and
    checks that it is still the same private directory, by device and inode. Entries are
    then created, listed and read relative to that descriptor. So a root swapped for a
    symlink or for another directory after construction is refused, never followed.
    """

    def __init__(self, root: Path) -> None:
        raw = str(root)
        if not os.path.isabs(raw) or os.path.realpath(raw) != raw:
            raise ApprovalError("approval store must be an absolute canonical directory")
        self.root = root
        fd = self._open_root(identity=None)
        try:
            st = os.fstat(fd)
            self._identity = (st.st_dev, st.st_ino)
        finally:
            os.close(fd)

    @property
    def identity(self) -> tuple[int, int]:
        """(device, inode) of the directory pinned at construction."""
        return self._identity

    def _open_root(self, identity: tuple[int, int] | None) -> int:
        try:
            fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as exc:
            raise ApprovalError("approval store is missing, not a directory, or a symlink") from exc
        st = os.fstat(fd)
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077
                or (identity is not None and (st.st_dev, st.st_ino) != identity)):
            os.close(fd)
            raise ApprovalError("approval store must be the same private (0700) directory owned by the current user")
        return fd

    def save(self, record: ApprovalRecord) -> Path:
        dir_fd = self._open_root(self._identity)
        try:
            records = self._records(dir_fd)
            if record.supersedes is not None:
                previous = records.get(record.supersedes)
                if previous is None:
                    raise ApprovalError("the superseded approval is not in this store")
                if previous.bindings.pack_id != record.bindings.pack_id:
                    raise ApprovalError("an approval can only supersede an approval of the same pack")
                if any(r.supersedes == record.supersedes for r in records.values()):
                    raise ApprovalError("that approval has already been superseded")
            name = f"{record.approval_id}.json"
            data = json.dumps(record.model_dump(mode="json"), indent=2, sort_keys=True).encode("utf-8") + b"\n"
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=dir_fd)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
        finally:
            os.close(dir_fd)
        return self.root / name

    def records(self) -> dict[str, ApprovalRecord]:
        dir_fd = self._open_root(self._identity)
        try:
            return self._records(dir_fd)
        finally:
            os.close(dir_fd)

    def _records(self, dir_fd: int) -> dict[str, ApprovalRecord]:
        found: dict[str, ApprovalRecord] = {}
        for name in sorted(os.listdir(dir_fd)):
            if (not _FILE_RE.fullmatch(name)
                    or not stat.S_ISREG(os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode)):
                raise ApprovalError(f"unexpected entry {name!r} in the approval store")
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
            with os.fdopen(fd, "rb") as handle:
                if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                    raise ApprovalError(f"{name} is not a regular file")
                raw = handle.read(MAX_RECORD_BYTES + 1)
            try:
                record = load_record(ApprovalRecord, raw, contract="approval-record", max_bytes=MAX_RECORD_BYTES)
            except RecordError as exc:
                raise ApprovalError(f"{name} is not a valid approval record") from exc
            if f"{record.approval_id}.json" != name:
                raise ApprovalError(f"{name} does not match its approval ID")
            found[record.approval_id] = record
        return found

    def current(self, pack_id: str) -> ApprovalRecord | None:
        """The single unsuperseded approval for a pack, or None. Forks and dangling links fail."""
        return current_approval(self.records().values(), pack_id)


def current_approval(records: Iterable[ApprovalRecord], pack_id: str) -> ApprovalRecord | None:
    chain = [r for r in records if r.bindings.pack_id == pack_id]
    ids = {r.approval_id for r in chain}
    superseded = [r.supersedes for r in chain if r.supersedes is not None]
    if any(s not in ids for s in superseded):
        raise ApprovalError("an approval supersedes a record that is missing")
    if len(superseded) != len(set(superseded)):
        raise ApprovalError("an approval was superseded twice; the history is ambiguous")
    leaves = [r for r in chain if r.approval_id not in superseded]
    if len(leaves) > 1:
        raise ApprovalError("more than one current approval; the history is ambiguous")
    if chain and not leaves:
        raise ApprovalError("the approval history is circular")
    return leaves[0] if leaves else None


@dataclass(frozen=True)
class ApprovalCheck:
    status: Literal["APPROVED", "APPROVAL_MISSING", "APPROVAL_STALE"]
    approval_id: str | None
    stale_fields: tuple[str, ...]


def check_approval(records: Iterable[ApprovalRecord], inputs: BindingInputs, *,
                   approval_id: str | None = None) -> ApprovalCheck:
    """Compare the pack's current approval with freshly computed bindings.

    Any difference is stale. A named approval that has since been superseded is stale too,
    even when its bindings still match.
    """
    history = list(records)
    current = current_approval(history, inputs.pack_id)
    if approval_id is not None and (current is None or current.approval_id != approval_id):
        if any(r.approval_id == approval_id for r in history):
            return ApprovalCheck("APPROVAL_STALE", approval_id, ("superseded",))
        return ApprovalCheck("APPROVAL_MISSING", None, ())
    if current is None:
        return ApprovalCheck("APPROVAL_MISSING", None, ())
    now = inputs.bindings().model_dump()
    then = current.bindings.model_dump()
    stale = tuple(sorted(k for k in now if now[k] != then[k]))
    return ApprovalCheck("APPROVAL_STALE" if stale else "APPROVED", current.approval_id, stale)
