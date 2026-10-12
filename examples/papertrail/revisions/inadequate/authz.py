"""Document read authorization for PaperTrail."""

from __future__ import annotations

from papertrail.fixtures import Document, User

# Roles whose accounts may read documents.
READ_ROLES = frozenset({"member", "auditor"})


def can_read_document(user: User | None, document: Document) -> bool:
    """Return whether the authenticated caller may read the document."""
    if user is None:
        return False
    if not user.user_id:
        return False
    return user.role in READ_ROLES
