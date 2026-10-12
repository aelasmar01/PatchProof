"""Typed rejection reasons for repository registration and snapshot creation.

Every refusal carries a stable reason code so callers and tests can tell *why* an input
was rejected, not only that it was. Detail text is bounded and escaped because it may
quote untrusted repository data (paths, Git stderr).
"""

from __future__ import annotations

import unicodedata
from enum import StrEnum
from typing import Final

DETAIL_LIMIT: Final = 300


class Reason(StrEnum):
    # Git executable and environment
    GIT_BINARY_UNAVAILABLE = "GIT_BINARY_UNAVAILABLE"
    GIT_VERSION_UNSUPPORTED = "GIT_VERSION_UNSUPPORTED"
    GIT_COMMAND_FAILED = "GIT_COMMAND_FAILED"
    GIT_TIMEOUT = "GIT_TIMEOUT"
    GIT_OUTPUT_LIMIT = "GIT_OUTPUT_LIMIT"
    MALFORMED_GIT_OUTPUT = "MALFORMED_GIT_OUTPUT"
    OPERATION_NOT_ALLOWED = "OPERATION_NOT_ALLOWED"
    # Registration
    PATH_NOT_ABSOLUTE = "PATH_NOT_ABSOLUTE"
    PATH_NOT_CANONICAL = "PATH_NOT_CANONICAL"
    NOT_A_DIRECTORY = "NOT_A_DIRECTORY"
    NOT_OWNED_BY_USER = "NOT_OWNED_BY_USER"
    HOME_DIRECTORY_REPOSITORY = "HOME_DIRECTORY_REPOSITORY"
    NOT_A_REPOSITORY_ROOT = "NOT_A_REPOSITORY_ROOT"
    AMBIGUOUS_REPOSITORY = "AMBIGUOUS_REPOSITORY"
    UNSUPPORTED_REPOSITORY_LAYOUT = "UNSUPPORTED_REPOSITORY_LAYOUT"
    UNSUPPORTED_OBJECT_FORMAT = "UNSUPPORTED_OBJECT_FORMAT"
    # Revisions and objects
    UNSUPPORTED_REVISION = "UNSUPPORTED_REVISION"
    ABBREVIATED_OBJECT_ID = "ABBREVIATED_OBJECT_ID"
    REF_NOT_FOUND = "REF_NOT_FOUND"
    MISSING_OBJECT = "MISSING_OBJECT"
    NOT_A_COMMIT = "NOT_A_COMMIT"
    OBJECT_TYPE_MISMATCH = "OBJECT_TYPE_MISMATCH"
    OBJECT_HASH_MISMATCH = "OBJECT_HASH_MISMATCH"
    # Tree entries and paths
    UNSAFE_PATH = "UNSAFE_PATH"
    PATH_COLLISION = "PATH_COLLISION"
    SYMLINK_ENTRY = "SYMLINK_ENTRY"
    GITLINK_ENTRY = "GITLINK_ENTRY"
    SPECIAL_ENTRY = "SPECIAL_ENTRY"
    LFS_POINTER = "LFS_POINTER"
    # Source scope and limits
    INVALID_SOURCE_SCOPE = "INVALID_SOURCE_SCOPE"
    REQUIRED_PATH_MISSING = "REQUIRED_PATH_MISSING"
    SECRET_PATH_REQUIRED = "SECRET_PATH_REQUIRED"
    TREE_ENTRY_LIMIT = "TREE_ENTRY_LIMIT"
    ENTRY_LIMIT = "ENTRY_LIMIT"
    FILE_SIZE_LIMIT = "FILE_SIZE_LIMIT"
    TOTAL_SIZE_LIMIT = "TOTAL_SIZE_LIMIT"
    # Snapshot destination
    DESTINATION_INVALID = "DESTINATION_INVALID"
    SNAPSHOT_VERIFICATION_FAILED = "SNAPSHOT_VERIFICATION_FAILED"


class SourceError(Exception):
    """A registration, resolution, or snapshot request was refused. Nothing was produced."""

    def __init__(self, reason: Reason, detail: str = "") -> None:
        self.reason = reason
        self.detail = safe_text(detail)
        super().__init__(f"{reason.value}: {self.detail}" if self.detail else reason.value)


def safe_text(value: str | bytes, limit: int = DETAIL_LIMIT) -> str:
    """Printable, bounded rendering of untrusted text: control and format characters escaped."""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="backslashreplace")
    out: list[str] = []
    for ch in value:
        code = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif code < 0x20 or code == 0x7F or 0x80 <= code < 0xA0 or _is_format(ch):
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
        if len(out) >= limit:
            out.append("...")
            break
    return "".join(out)


def _is_format(ch: str) -> bool:
    return unicodedata.category(ch) in {"Cf", "Zl", "Zp", "Cs"}
