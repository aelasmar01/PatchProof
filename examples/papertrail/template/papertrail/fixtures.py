"""Synthetic fixture data for PaperTrail (fixture contract synthetic-documents-v1).

Every identity, bearer token and document is synthetic. The data is read once when the
module is imported, validated strictly, and never modified afterwards, so a fresh process
always starts from the same state.
"""

from __future__ import annotations

import hmac
import json
from dataclasses import dataclass
from pathlib import Path

FIXTURE_CONTRACT = "synthetic-documents-v1"
FIXTURE_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "synthetic" / "synthetic-documents-v1.json"
MAX_FIXTURE_BYTES = 65536
MAX_TOKEN_BYTES = 128
BEARER_PREFIX = b"Bearer "

_USER_KEYS = frozenset({"user_id", "display_name", "role", "token"})
_DOCUMENT_KEYS = frozenset({"document_id", "owner_id", "title", "reader_roles", "content"})


@dataclass(frozen=True)
class User:
    user_id: str
    display_name: str
    role: str
    token: str


@dataclass(frozen=True)
class Document:
    document_id: str
    owner_id: str
    title: str
    reader_roles: tuple[str, ...]
    content: str


@dataclass(frozen=True)
class Fixture:
    users: tuple[User, ...]
    documents: tuple[Document, ...]

    def document(self, document_id: str) -> Document | None:
        for document in self.documents:
            if document.document_id == document_id:
                return document
        return None


def _text(record: dict[str, object], key: str) -> str:
    value = record[key]
    if not isinstance(value, str) or not value:
        raise ValueError(f"fixture field {key} must be a non-empty string")
    return value


def load_fixture(path: Path = FIXTURE_PATH) -> Fixture:
    raw = path.read_bytes()
    if len(raw) > MAX_FIXTURE_BYTES:
        raise ValueError("fixture file is too large")
    data = json.loads(raw)
    if data.get("fixture_contract") != FIXTURE_CONTRACT or data.get("synthetic") is not True:
        raise ValueError("unsupported fixture contract")
    users = []
    for record in data["users"]:
        if set(record) != _USER_KEYS:
            raise ValueError("unexpected user fields")
        users.append(User(_text(record, "user_id"), _text(record, "display_name"),
                          _text(record, "role"), _text(record, "token")))
    documents = []
    for record in data["documents"]:
        if set(record) != _DOCUMENT_KEYS:
            raise ValueError("unexpected document fields")
        roles = record["reader_roles"]
        if not isinstance(roles, list) or not all(isinstance(role, str) and role for role in roles):
            raise ValueError("reader_roles must be a list of role names")
        documents.append(Document(_text(record, "document_id"), _text(record, "owner_id"),
                                  _text(record, "title"), tuple(roles), _text(record, "content")))
    if not all(user.token.isascii() for user in users):
        raise ValueError("tokens must be ASCII")
    user_ids = {user.user_id for user in users}
    if len(user_ids) != len(users) or len({user.token for user in users}) != len(users):
        raise ValueError("duplicate user ID or token")
    if len({document.document_id for document in documents}) != len(documents):
        raise ValueError("duplicate document ID")
    if any(document.owner_id not in user_ids for document in documents):
        raise ValueError("document owner is not a fixture user")
    return Fixture(tuple(users), tuple(documents))


def authenticate(fixture: Fixture, authorization: bytes | None) -> User | None:
    """Return the user whose synthetic bearer token was presented, or None."""
    if authorization is None or not authorization.startswith(BEARER_PREFIX):
        return None
    presented = authorization.removeprefix(BEARER_PREFIX)
    if not presented or len(presented) > MAX_TOKEN_BYTES:
        return None
    match = None
    for user in fixture.users:
        if hmac.compare_digest(presented, user.token.encode("ascii")):
            match = user
    return match


FIXTURE = load_fixture()
