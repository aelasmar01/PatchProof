"""Verifier copy of fixture contract synthetic-documents-v1 (PP-006 PaperTrail).

The pack carries its own copy of the fixture file. It is loaded here only after its
SHA-256 matches the reviewed contract hash, so the verifier's notion of users, owners,
grants and markers cannot silently drift from the data the target serves.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

CONTRACT: Final = "synthetic-documents-v1"
CONTRACT_SHA256: Final = "sha256:2cbcf118fddb2cd4e38a9af5e8786911e8f85e292e637102799fd60513129eda"
MAX_FIXTURE_BYTES: Final = 65536
MARKER_RE: Final = re.compile(r"PT-PROTECTED-[A-Z]{1,16}-[0-9a-f]{12}")


class FixtureContractError(Exception):
    """The fixture copy does not match the reviewed contract."""


@dataclass(frozen=True)
class User:
    user_id: str
    role: str
    token: str


@dataclass(frozen=True)
class Document:
    document_id: str
    owner_id: str
    reader_roles: tuple[str, ...]
    content: str
    marker: str


@dataclass(frozen=True)
class SyntheticDocuments:
    users: tuple[User, ...]
    documents: tuple[Document, ...]

    def user(self, user_id: str) -> User:
        matches = [u for u in self.users if u.user_id == user_id]
        if len(matches) != 1:
            raise FixtureContractError(f"no unique fixture user {user_id!r}")
        return matches[0]

    def document(self, document_id: str) -> Document:
        matches = [d for d in self.documents if d.document_id == document_id]
        if len(matches) != 1:
            raise FixtureContractError(f"no unique fixture document {document_id!r}")
        return matches[0]


def permits(user: User, document: Document) -> bool:
    """The reviewed read policy: the owner, or a role the document explicitly lists."""
    return user.user_id == document.owner_id or user.role in document.reader_roles


def _field(record: dict[str, Any], key: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value:
        raise FixtureContractError(f"fixture field {key} must be a non-empty string")
    return value


def parse_documents(raw: bytes) -> SyntheticDocuments:
    if len(raw) > MAX_FIXTURE_BYTES:
        raise FixtureContractError("fixture file is too large")
    if "sha256:" + hashlib.sha256(raw).hexdigest() != CONTRACT_SHA256:
        raise FixtureContractError("fixture copy does not match the reviewed contract hash")
    data = json.loads(raw)
    if data.get("fixture_contract") != CONTRACT or data.get("synthetic") is not True:
        raise FixtureContractError("unexpected fixture contract")
    users = tuple(User(_field(u, "user_id"), _field(u, "role"), _field(u, "token")) for u in data["users"])
    documents = []
    for d in data["documents"]:
        content = _field(d, "content")
        markers = MARKER_RE.findall(content)
        if len(markers) != 1:
            raise FixtureContractError("each document carries exactly one protected marker")
        documents.append(Document(_field(d, "document_id"), _field(d, "owner_id"), tuple(d["reader_roles"]),
                                  content, markers[0]))
    return SyntheticDocuments(users, tuple(documents))


def load_documents(path: Path) -> SyntheticDocuments:
    return parse_documents(path.read_bytes())
