"""Document read authorization for PaperTrail."""

from __future__ import annotations

from papertrail.fixtures import Document, User


def can_read_document(user: User | None, document: Document) -> bool:
    """Return whether the authenticated caller may read the document."""
    return user is not None
