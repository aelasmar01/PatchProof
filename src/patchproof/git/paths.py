"""Tree path validation, reviewed source scope, and the built-in secret-file policy (9.2).

Pure functions over untrusted path bytes from Git trees. Nothing here touches the
filesystem.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Final

from .errors import Reason, SourceError, safe_text

MAX_PATH_BYTES: Final = 4096
MAX_SEGMENT_BYTES: Final = 255

# Same grammar as schemas/common.schema.json#/$defs/relativePath: source_scope.include items.
INCLUDE_RE: Final = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}(/[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}){0,15}")
MAX_INCLUDE_ITEMS: Final = 64

# Unicode categories refused anywhere in a path: controls, format characters (zero-width
# and bidirectional controls, which also hide '.git' variants on HFS+), separators, surrogates.
FORBIDDEN_CATEGORIES: Final = frozenset({"Cc", "Cf", "Zl", "Zp", "Cs"})

# Built-in secret-file policy (not profile data; execution-profile schema source_scope).
# Matched case-insensitively against each path's final segment and directory segments.
SECRET_POLICY_VERSION: Final = "secret-files-1"
SECRET_FILE_PATTERNS: Final = (
    ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore", "*.kdbx",
    "id_rsa", "id_rsa.*", "id_dsa", "id_dsa.*", "id_ecdsa", "id_ecdsa.*", "id_ed25519", "id_ed25519.*",
    ".netrc", "_netrc", ".npmrc", ".pypirc", ".git-credentials", ".htpasswd", ".pgpass",
    "credentials", "credentials.json", "secrets.json", "secrets.yml", "secrets.yaml", "secrets.toml",
    "*.tfvars", "terraform.tfstate", "terraform.tfstate.*",
)
SECRET_DIR_PATTERNS: Final = (".ssh", ".aws", ".gnupg", ".docker", ".kube", ".azure", ".gcloud")


def validate_tree_path(raw: bytes) -> str:
    """Decode and validate one path from a Git tree. Rejects rather than repairs."""
    if not raw:
        raise SourceError(Reason.UNSAFE_PATH, "empty path")
    if len(raw) > MAX_PATH_BYTES:
        raise SourceError(Reason.UNSAFE_PATH, f"path longer than {MAX_PATH_BYTES} bytes")
    try:
        path = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise SourceError(Reason.UNSAFE_PATH, f"path is not valid UTF-8: {safe_text(raw)}") from exc
    if path.startswith("/"):
        raise SourceError(Reason.UNSAFE_PATH, f"absolute path {safe_text(path)}")
    if "\\" in path:
        raise SourceError(Reason.UNSAFE_PATH, f"backslash in path {safe_text(path)}")
    for ch in path:
        if unicodedata.category(ch) in FORBIDDEN_CATEGORIES:
            raise SourceError(Reason.UNSAFE_PATH, f"control or format character in {safe_text(path)}")
    for segment in path.split("/"):
        if segment in ("", ".", ".."):
            raise SourceError(Reason.UNSAFE_PATH, f"empty, '.' or '..' segment in {safe_text(path)}")
        if len(segment.encode("utf-8")) > MAX_SEGMENT_BYTES:
            raise SourceError(Reason.UNSAFE_PATH, "path segment longer than 255 bytes")
        if _is_git_dir_name(segment):
            raise SourceError(Reason.UNSAFE_PATH, f"Git metadata name in {safe_text(path)}")
    return path


def _is_git_dir_name(segment: str) -> bool:
    folded = unicodedata.normalize("NFC", segment).casefold().rstrip(". ")
    return folded == ".git" or folded == "git~1"


def collision_key(path: str) -> str:
    """Key under which two paths name the same file on a case-insensitive, normalizing filesystem."""
    return unicodedata.normalize("NFC", unicodedata.normalize("NFD", path)).casefold()


def check_collisions(paths: Iterable[str]) -> None:
    """Refuse paths that collide by case or Unicode normalization, including file/directory clashes."""
    seen: dict[str, str] = {}
    dirs: dict[str, str] = {}
    files: list[tuple[str, str]] = []
    for path in paths:
        key = collision_key(path)
        if key in seen and seen[key] != path:
            raise SourceError(Reason.PATH_COLLISION, f"{safe_text(seen[key])} and {safe_text(path)} collide")
        seen[key] = path
        files.append((key, path))
        parts = path.split("/")
        for i in range(1, len(parts)):
            raw_dir = "/".join(parts[:i])
            dkey = collision_key(raw_dir)
            if dkey in dirs and dirs[dkey] != raw_dir:
                raise SourceError(Reason.PATH_COLLISION,
                                  f"directories {safe_text(dirs[dkey])} and {safe_text(raw_dir)} collide")
            dirs[dkey] = raw_dir
    for key, path in files:
        if key in dirs:
            raise SourceError(Reason.PATH_COLLISION, f"file {safe_text(path)} collides with a directory")


def is_secret_path(path: str) -> bool:
    segments = [unicodedata.normalize("NFC", s).casefold() for s in path.split("/")]
    if any(fnmatchcase(s, p) for s in segments[:-1] for p in SECRET_DIR_PATTERNS):
        return True
    name = segments[-1]
    return any(fnmatchcase(name, p) for p in (*SECRET_FILE_PATTERNS, *SECRET_DIR_PATTERNS))


@dataclass(frozen=True)
class SourceScope:
    """Reviewed application/fixture paths to export (execution profile `source_scope.include`)."""

    include: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.include, tuple) or not 1 <= len(self.include) <= MAX_INCLUDE_ITEMS:
            raise SourceError(Reason.INVALID_SOURCE_SCOPE, f"include must list 1..{MAX_INCLUDE_ITEMS} paths")
        if len(set(self.include)) != len(self.include):
            raise SourceError(Reason.INVALID_SOURCE_SCOPE, "duplicate include path")
        for item in self.include:
            if not isinstance(item, str) or len(item) > 255 or not INCLUDE_RE.fullmatch(item):
                raise SourceError(Reason.INVALID_SOURCE_SCOPE, f"include path {safe_text(str(item))} is not allowed")
            if is_secret_path(item):
                raise SourceError(Reason.SECRET_PATH_REQUIRED,
                                  f"required path {safe_text(item)} matches the secret-file policy")

    @classmethod
    def of(cls, include: Sequence[str]) -> SourceScope:
        return cls(tuple(include))

    def matching_prefix(self, path: str) -> str | None:
        for prefix in self.include:
            if path == prefix or path.startswith(prefix + "/"):
                return prefix
        return None
