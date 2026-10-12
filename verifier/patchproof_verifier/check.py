"""Terminal security observations (PROJECT_SPEC.md 7.3).

A security test ends with exactly one of:
- `check.secure(evidence)`: the declared protection was observed;
- `check.violation(evidence)`: the declared violation was observed. It records the
  observation and then raises `SecurityTerminal`, the controlled exception that the plugin
  reports as `failure_class: security_terminal`;
- `check.inconclusive(reason)`: neither could be established.

A second terminal call, malformed evidence, or use outside a security test raises
`HelperMisuse` (`failure_class: helper_misuse`). The plugin, not the test, derives the
outcome. Catching `SecurityTerminal` inside a test does not hide the violation: the
observation is already recorded, and the plugin reports `SUPPRESSED_TERMINAL_EXCEPTION`.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final, Literal, NoReturn

Outcome = Literal["VIOLATION_CONFIRMED", "SECURE", "INCONCLUSIVE"]
FactValue = str | int | bool | None

MAX_FACTS: Final = 32
MAX_TEXT: Final = 200
_KEY_RE: Final = re.compile(r"[a-z][a-z0-9_]{0,39}")
_TEXT_RE: Final = re.compile(r"[^\x00-\x1f\x7f]*")


class SecurityTerminal(Exception):  # noqa: N818 - the protocol name for this terminal exception
    """Ends a security test after a VIOLATION_CONFIRMED observation has been recorded."""


class HelperMisuse(Exception):  # noqa: N818 - the protocol name for helper misuse
    """The security helpers were used incorrectly; the test cannot produce trusted evidence."""


def _text(value: str, what: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_TEXT or not _TEXT_RE.fullmatch(value):
        raise HelperMisuse(f"{what} must be 1-{MAX_TEXT} printable characters")
    return value


@dataclass(frozen=True)
class Evidence:
    """A bounded, structured witness. Values are facts the helper itself established."""

    claim: str
    facts: tuple[tuple[str, FactValue], ...]

    def __post_init__(self) -> None:
        _text(self.claim, "claim")
        if not isinstance(self.facts, tuple) or not 1 <= len(self.facts) <= MAX_FACTS:
            raise HelperMisuse(f"evidence needs 1-{MAX_FACTS} facts")
        keys = [k for k, _ in self.facts]
        if len(set(keys)) != len(keys):
            raise HelperMisuse("evidence fact names must be unique")
        for key, value in self.facts:
            if not isinstance(key, str) or not _KEY_RE.fullmatch(key):
                raise HelperMisuse("evidence fact names are lower-case identifiers")
            if isinstance(value, str):
                _text(value, f"fact {key}")
            elif value is not None and not isinstance(value, (bool, int)):
                raise HelperMisuse(f"fact {key} must be text, an integer, a boolean or null")

    def summary(self) -> str:
        rendered = "; ".join(f"{k}={'null' if v is None else str(v).lower() if isinstance(v, bool) else v}"
                             for k, v in self.facts)
        return f"{self.claim}. {rendered}"


@dataclass(frozen=True)
class TerminalObservation:
    test_id: str
    outcome: Outcome
    summary: str


ObservationSink = Callable[[TerminalObservation], None]


class SecurityCheck:
    """The `check` object given to one security test. Records at most one terminal observation."""

    def __init__(self, test_id: str, sink: ObservationSink) -> None:
        self._test_id = test_id
        self._sink = sink
        self._terminal: TerminalObservation | None = None

    @property
    def terminal(self) -> TerminalObservation | None:
        return self._terminal

    def _record(self, outcome: Outcome, summary: str) -> None:
        if self._terminal is not None:
            raise HelperMisuse("a security test may record only one terminal observation")
        self._terminal = TerminalObservation(self._test_id, outcome, summary)
        self._sink(self._terminal)

    def secure(self, evidence: Evidence) -> None:
        if not isinstance(evidence, Evidence):
            raise HelperMisuse("check.secure requires Evidence")
        self._record("SECURE", evidence.summary())

    def violation(self, evidence: Evidence) -> NoReturn:
        if not isinstance(evidence, Evidence):
            raise HelperMisuse("check.violation requires Evidence")
        self._record("VIOLATION_CONFIRMED", evidence.summary())
        raise SecurityTerminal(f"{self._test_id}: security violation confirmed")

    def inconclusive(self, reason: str) -> None:
        self._record("INCONCLUSIVE", f"Inconclusive. {_text(reason, 'reason')}")
