"""Strict JSON loading: the first of the two loading stages in ADR-008.

Record bytes are untrusted. Loading fails closed and never repairs input:
- the bytes must be valid UTF-8, with no byte-order mark, within a size limit;
- duplicate object keys are rejected (the last-wins rule of `json.loads` would hide them);
- `NaN`, `Infinity` and `-Infinity` are rejected;
- lone UTF-16 surrogates, which cannot be re-encoded, are rejected;
- nesting deeper than a fixed limit is rejected before it can exhaust the stack.

Schema and model validation (the second stage) happen afterwards in `patchproof.core.records`.
"""

from __future__ import annotations

import json
from typing import Any, Final

DEFAULT_MAX_BYTES: Final = 1048576
MAX_DEPTH: Final = 32


class StrictJsonError(ValueError):
    """The bytes are not one strictly well-formed JSON document within the limits."""


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJsonError("duplicate object key")
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    raise StrictJsonError(f"non-finite number {name} is not permitted")


def _check_tree(value: Any, depth: int) -> None:
    if depth > MAX_DEPTH:
        raise StrictJsonError(f"nesting deeper than {MAX_DEPTH} levels")
    if isinstance(value, str):
        _check_text(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            _check_text(key)
            _check_tree(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _check_tree(item, depth + 1)


def _check_text(text: str) -> None:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise StrictJsonError("lone surrogate in string") from exc


def _bracket_depth(text: str) -> int:
    """Upper bound on nesting, computed before parsing so a deep document cannot recurse."""
    depth = deepest = 0
    in_string = escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif ch in "]}":
            depth -= 1
    return deepest


def loads_strict(raw: bytes, *, max_bytes: int = DEFAULT_MAX_BYTES) -> Any:
    """Parse exactly one JSON document from `raw` or raise StrictJsonError."""
    if not isinstance(raw, bytes):
        raise StrictJsonError("input must be bytes")
    if len(raw) > max_bytes:
        raise StrictJsonError(f"document larger than {max_bytes} bytes")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise StrictJsonError("byte-order mark is not permitted")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise StrictJsonError("document is not valid UTF-8") from exc
    if _bracket_depth(text) > MAX_DEPTH:
        raise StrictJsonError(f"nesting deeper than {MAX_DEPTH} levels")
    try:
        value = json.loads(text, object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant)
    except StrictJsonError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise StrictJsonError("document is not well-formed JSON") from exc
    _check_tree(value, 0)
    return value
