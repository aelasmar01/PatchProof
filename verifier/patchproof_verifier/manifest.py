"""Minimal, strict reading of the approved pack manifest inside the verifier image.

The host has already validated the pack fully (`patchproof.packs`) and the approval binds
its hash. The verifier only needs the test table, so it reads that with a duplicate-key-
rejecting parser and fails closed on anything unexpected.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Final

MAX_MANIFEST_BYTES: Final = 65536
_ID_RE: Final = re.compile(r"[A-Z][A-Z0-9]{1,15}-[0-9]{3}")
_NODEID_RE: Final = re.compile(r"tests/([A-Za-z0-9_][A-Za-z0-9_-]{0,63}/){0,4}test_[A-Za-z0-9_]{1,64}\.py::"
                               r"([A-Z][A-Za-z0-9_]{0,63}::)?test_[A-Za-z0-9_]{1,64}")


class ManifestError(Exception):
    pass


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ManifestError("duplicate key in pack.json")
    return dict(pairs)


def read_manifest_tests(path: Path) -> list[dict[str, str]]:
    raw = path.read_bytes()
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ManifestError("pack.json is too large")
    data = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
    tests = data.get("tests") if isinstance(data, dict) else None
    if not isinstance(tests, list) or not tests:
        raise ManifestError("pack.json has no test table")
    result = []
    for test in tests:
        if not isinstance(test, dict):
            raise ManifestError("malformed test entry")
        tid, nodeid, kind = test.get("id"), test.get("nodeid"), test.get("kind")
        if (not isinstance(tid, str) or not _ID_RE.fullmatch(tid) or not isinstance(nodeid, str)
                or not _NODEID_RE.fullmatch(nodeid) or kind not in ("security", "functional")):
            raise ManifestError("malformed test entry")
        result.append({"id": tid, "nodeid": nodeid, "kind": kind})
    return result


def read_manifest_limits(path: Path) -> tuple[int, int]:
    """(max_response_bytes, case_timeout_seconds) from the approved manifest."""
    raw = path.read_bytes()
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ManifestError("pack.json is too large")
    data = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
    limits = data.get("limits") if isinstance(data, dict) else None
    if not isinstance(limits, dict):
        raise ManifestError("pack.json has no limits")
    size, timeout = limits.get("max_response_bytes"), limits.get("case_timeout_seconds")
    if (type(size) is not int or not 1 <= size <= 1048576 or type(timeout) is not int
            or not 1 <= timeout <= 120):
        raise ManifestError("malformed limits")
    return size, timeout
