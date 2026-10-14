"""Fail-closed preflight reports (PP-008 follow-up, owner 2026-10-14).

Every check is labelled MANDATORY (a gate: any failure refuses the operation) or DIAGNOSTIC
(information: it never refuses and never turns a refusal into success). The overall result is
computed only from mandatory checks, and a report with no mandatory check is not a pass.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from .safe_text import plain

Kind = Literal["MANDATORY", "DIAGNOSTIC"]


@dataclass(frozen=True)
class Check:
    name: str
    kind: Kind
    passed: bool
    detail: str = ""


@dataclass
class Preflight:
    checks: list[Check] = field(default_factory=list)

    def mandatory(self, name: str, passed: bool, detail: str = "") -> bool:
        self.checks.append(Check(name, "MANDATORY", passed, detail))
        return passed

    def diagnostic(self, name: str, passed: bool, detail: str = "") -> None:
        self.checks.append(Check(name, "DIAGNOSTIC", passed, detail))

    @property
    def passed(self) -> bool:
        gates = [c for c in self.checks if c.kind == "MANDATORY"]
        return bool(gates) and all(c.passed for c in gates)

    def failed_mandatory(self) -> list[Check]:
        return [c for c in self.checks if c.kind == "MANDATORY" and not c.passed]

    def render(self) -> str:
        lines = ["Preflight (MANDATORY checks gate the operation; DIAGNOSTIC checks never do):"]
        for c in self.checks:
            state = "PASS" if c.passed else ("FAIL" if c.kind == "MANDATORY" else "NOTE")
            lines.append(f"  [{c.kind:10}] {state:4} {plain(c.name, 120)}" + (f": {plain(c.detail, 400)}"
                                                                                if c.detail else ""))
        failed = self.failed_mandatory()
        verdict = ("PASS: every mandatory check passed" if self.passed else
                   f"BLOCKED: {len(failed)} mandatory check(s) failed" if failed else "BLOCKED: no mandatory check ran")
        lines.append(f"  Result: {verdict}.")
        return "\n".join(lines) + "\n"

    def document(self) -> dict[str, object]:
        return {"passed": self.passed,
                "checks": [{"name": c.name, "kind": c.kind, "passed": c.passed, "detail": plain(c.detail, 400)}
                           for c in self.checks]}
