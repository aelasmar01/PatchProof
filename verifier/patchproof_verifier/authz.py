"""Reviewed object-level authorization witnesses (PROJECT_SPEC.md 7.3, 17.1).

Each `assess_*` helper makes exactly one terminal call on `check`, and decides it only from
facts it establishes itself:
- **Violation:** the response body contains the document's synthetic protected marker,
  and the fixture shows that the caller is not permitted. A status code alone is never a
  witness.
- **Secure:** the response has a reviewed denial status, does not contain the marker, and
  does not return document content. A denial status alone is not enough.
- **Inconclusive:** anything else, for example a 200 without the marker, a server error,
  or a body that is not interpretable.

Target-supplied text such as "SECURE", "PASS" or JSON that looks like an event is just
bytes in the body; only the marker test reads the body.

The functional `expect_*` helpers use ordinary assertions and check actual content and
identity, not just a status code.
"""

from __future__ import annotations

from typing import Final

from .check import Evidence, HelperMisuse, SecurityCheck
from .documents import Document, User, permits
from .http import Response

AUTHENTICATED_DENIALS: Final = (403, 404)
UNAUTHENTICATED_DENIALS: Final = (401,)
_CONTENT_KEYS: Final = ("content",)


def _discloses(document: Document, response: Response) -> bool:
    return document.marker.encode("ascii") in response.body


def _returns_content(response: Response) -> bool:
    body = response.json_object()
    return body is not None and any(k in body for k in _CONTENT_KEYS)


def _facts(document: Document, response: Response, **extra: str | int | bool | None
           ) -> tuple[tuple[str, str | int | bool | None], ...]:
    return (*extra.items(), ("document_id", document.document_id), ("owner_id", document.owner_id),
            ("reader_roles", ",".join(document.reader_roles) or "none"), ("status", response.status),
            ("marker", document.marker), ("marker_observed", _discloses(document, response)))


def assess_unauthorized_read(check: SecurityCheck, *, caller: User, document: Document, response: Response) -> None:
    """An authenticated caller whom the reviewed policy does not permit to read `document`."""
    if permits(caller, document):
        raise HelperMisuse("the fixture permits this caller; this is not an unauthorized read")
    facts = _facts(document, response, caller_id=caller.user_id, caller_role=caller.role, caller_permitted=False)
    if _discloses(document, response):
        check.violation(Evidence("A caller the fixture does not permit received the document's protected marker",
                                 facts))
    if response.status in AUTHENTICATED_DENIALS and not _returns_content(response):
        check.secure(Evidence("The read was denied and neither the marker nor document content was returned",
                              facts))
        return
    check.inconclusive(f"status {response.status} without the marker is neither a disclosure nor a reviewed denial")


def assess_unauthenticated_read(check: SecurityCheck, *, credential: str, document: Document,
                                response: Response) -> None:
    """A caller with no valid credential. `credential` describes what was presented."""
    if credential not in ("none", "invalid-bearer"):
        raise HelperMisuse("credential must be 'none' or 'invalid-bearer'")
    facts = _facts(document, response, credential=credential)
    if _discloses(document, response):
        check.violation(Evidence("An unauthenticated caller received the document's protected marker", facts))
    if response.status in UNAUTHENTICATED_DENIALS and not _returns_content(response):
        check.secure(Evidence("Authentication was required and no protected content was returned", facts))
        return
    check.inconclusive(f"status {response.status} is not the reviewed authentication denial")


def expect_document_read(*, caller: User, document: Document, response: Response) -> None:
    """Legitimate read: the permitted caller receives exactly this document's content."""
    assert permits(caller, document), "the fixture does not permit this read; it is not a functional control"
    assert response.status == 200, f"expected 200, got {response.status}"
    body = response.json_object()
    assert body is not None, "the response is not a JSON object"
    assert body.get("document_id") == document.document_id, "a different document was returned"
    assert body.get("owner_id") == document.owner_id, "the owner does not match the fixture"
    assert body.get("content") == document.content, "the content does not match the fixture"


def expect_identity(*, caller: User, response: Response) -> None:
    """Legitimate identity read: the caller sees their own identity and nothing secret."""
    assert response.status == 200, f"expected 200, got {response.status}"
    body = response.json_object()
    assert body is not None, "the response is not a JSON object"
    assert body.get("user_id") == caller.user_id, "the identity does not match the caller"
    assert body.get("role") == caller.role, "the role does not match the fixture"
    assert caller.token.encode("ascii") not in response.body, "the response echoes the bearer token"
