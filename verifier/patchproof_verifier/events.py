"""Verifier event emission (schemas/verifier-event.schema.json 1.0; verdict specification 3.1).

Each event is one line of compact JSON written to a private duplicate of the original
standard output. The plugin redirects the process's file descriptor 1 to standard error
before any test runs. Pytest's own output and anything a test prints therefore cannot
reach the event channel. Sequence numbers start at 0 and increase by exactly 1. The host
collector, not this module, decides whether the stream is trustworthy.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Final

RUN_ID_RE: Final = re.compile(r"run-[0-9a-f]{32}")
MAX_LINE_BYTES: Final = 65536


class EventChannelError(Exception):
    pass


class EventWriter:
    def __init__(self, fd: int, *, run_id: str, pair: int, side: str) -> None:
        if not RUN_ID_RE.fullmatch(run_id) or not 1 <= pair <= 10 or side not in ("baseline", "candidate"):
            raise EventChannelError("invalid run identity")
        self._fd = fd
        self._identity = {"run_id": run_id, "pair": pair, "side": side}
        self._seq = 0

    @property
    def emitted(self) -> int:
        return self._seq

    def emit(self, event_type: str, payload: dict[str, Any]) -> None:
        record = {"schema_version": "1.0", **self._identity, "seq": self._seq, "type": event_type,
                  "payload": payload}
        line = (json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
        if len(line) > MAX_LINE_BYTES:
            raise EventChannelError("event line exceeds the size limit")
        view = memoryview(line)
        while view:
            written = os.write(self._fd, view)
            view = view[written:]
        self._seq += 1


def write_line(fd: int, payload: dict[str, Any]) -> None:
    """One compact JSON line (used for the review-time `collected` record)."""
    data = (json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def pack_tree_sha256(root: Path) -> str:
    """The same canonical pack-tree hash the host computes (patchproof.packs.validation).

    It is the SHA-256 of the canonical JSON list of (path, size, sha256), ordered by path,
    over every regular file. A symlink or special file is refused.
    """
    entries = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in [*dirnames, *filenames]:
            full = Path(dirpath) / name
            st = os.lstat(full)
            if stat.S_ISDIR(st.st_mode):
                continue
            if not stat.S_ISREG(st.st_mode):
                raise EventChannelError(f"pack contains a non-regular file: {full.relative_to(root)}")
            data = full.read_bytes()
            entries.append({"path": full.relative_to(root).as_posix(), "sha256": "sha256:" + hashlib.sha256(
                data).hexdigest(), "size": len(data)})
    entries.sort(key=lambda e: str(e["path"]).encode("utf-8"))
    canonical = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()
