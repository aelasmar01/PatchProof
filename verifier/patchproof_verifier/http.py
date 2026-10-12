"""The verifier's view of one HTTP exchange with the target (PROJECT_SPEC.md 10.1, 10.3).

The target address is fixed by the runner (127.0.0.1:8080 inside the isolated namespace);
a pack supplies only a path. The transport that performs requests is provided by the
PP-008 runner with its approved client library. This module defines the contract the pack
helpers rely on, and validates every path a test asks for.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Final, Protocol

MAX_BODY_BYTES: Final = 1048576
_PATH_RE: Final = re.compile(r"/[A-Za-z0-9._~/-]{0,200}")


class TargetResponseError(Exception):
    """The response could not be interpreted; it is never treated as a security result."""


def check_path(path: str) -> str:
    """Accept only an absolute origin-form path: no scheme, host, query, '//' or dot segments."""
    if not isinstance(path, str) or not _PATH_RE.fullmatch(path) or "//" in path:
        raise ValueError("request path must be a plain absolute path")
    if any(segment in (".", "..") for segment in path.split("/")):
        raise ValueError("request path must not contain dot segments")
    return path


@dataclass(frozen=True)
class Response:
    """Status and raw body as received. Target bytes are data, never instructions."""

    status: int
    body: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.status, int) or not 100 <= self.status <= 599:
            raise TargetResponseError("status is not an HTTP status code")
        if not isinstance(self.body, bytes) or len(self.body) > MAX_BODY_BYTES:
            raise TargetResponseError("body is missing or larger than the limit")

    def json_object(self) -> dict[str, Any] | None:
        """The body as a JSON object, or None if it is not exactly one well-formed object."""
        def reject(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            keys = [k for k, _ in pairs]
            if len(set(keys)) != len(keys):
                raise ValueError("duplicate key")
            return dict(pairs)

        try:
            value = json.loads(self.body.decode("utf-8"), object_pairs_hook=reject)
        except (UnicodeDecodeError, ValueError, RecursionError):
            return None
        return value if isinstance(value, dict) else None


class TargetClient(Protocol):
    """Implemented by the runner's transport (PP-008). No redirects, proxies or other hosts."""

    def get(self, path: str, *, bearer: str | None = None) -> Response: ...
