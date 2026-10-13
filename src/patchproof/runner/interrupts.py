"""Graceful termination for the authorized-run driver (PP-008).

Python's default SIGTERM and SIGHUP actions end the process at once, skipping every
`finally` block, including exact-ID container cleanup. While the driver runs, these
handlers turn SIGINT, SIGTERM and SIGHUP into `RunTerminated` (a `KeyboardInterrupt`), so
the in-progress revision's cleanup and the evidence finalization still run.

- **First signal:** raised once, in the main thread, at the next bytecode boundary.
- **Further signals:** recorded and ignored, so a second Ctrl-C cannot abort cleanup that is
  already running. Only SIGKILL (which no process can catch) ends the driver then.

**Not covered, by design of the OS:** SIGKILL, a host shutdown or power loss, an
interpreter crash. Nothing runs in those cases; the containers of the revision in progress
remain until `patchproof.recover_run` removes them (exact IDs, ownership re-verified, after
a typed confirmation).
"""

from __future__ import annotations

import os
import signal
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from types import FrameType
from typing import Any, Final

HANDLED_SIGNALS: Final = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


class RunTerminated(KeyboardInterrupt):
    """A termination signal arrived while the driver was running."""

    def __init__(self, signal_name: str) -> None:
        self.signal_name = signal_name
        super().__init__(signal_name)


@dataclass
class SignalLog:
    received: list[str] = field(default_factory=list)


@contextmanager
def graceful_termination() -> Iterator[SignalLog]:
    """Install the handlers for the duration of the block; restore the previous ones after."""
    log = SignalLog()

    def handler(signum: int, frame: FrameType | None) -> None:
        name = signal.Signals(signum).name
        log.received.append(name)
        if len(log.received) == 1:
            raise RunTerminated(name)
        os.write(2, f"\n{name} received again: ignored while cleanup and evidence finalization run.\n".encode())

    previous: dict[signal.Signals, Any] = {}
    try:
        for handled in HANDLED_SIGNALS:
            previous[handled] = signal.signal(handled, handler)
        yield log
    finally:
        for handled, old in previous.items():
            signal.signal(handled, old)
