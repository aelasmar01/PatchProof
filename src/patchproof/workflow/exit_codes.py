"""PROJECT_SPEC.md 13.2 exit codes for the `patchproof` CLI. Pure.

Lifecycle takes precedence over verdict: a `CANCELED` run exits 22 and an `INTERRUPTED` run
exits 20 whatever semantic verdict its record preserves. Evidence that is not finalized never
yields a verdict exit code. The controller-test harness exit code of the PP-008 interruption
demonstration is never used here: only the interrupted application run's own record counts.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

OK: Final = 0
USAGE: Final = 2
NOT_FIXED: Final = 10
REGRESSION_DETECTED: Final = 11
NOT_REPRODUCED: Final = 12
INCONCLUSIVE: Final = 20
BLOCKED: Final = 21
CANCELED: Final = 22

VERDICT_EXIT: Final[Mapping[str, int]] = {
    "VERIFIED_FOR_CASES": OK,
    "NOT_FIXED": NOT_FIXED,
    "REGRESSION_DETECTED": REGRESSION_DETECTED,
    "NOT_REPRODUCED": NOT_REPRODUCED,
    "INCONCLUSIVE": INCONCLUSIVE,
    "BLOCKED": BLOCKED,
}


def run_exit_code(lifecycle: str | None, verdict: str | None, evidence_status: str | None) -> int:
    """The exit code for a run record. Unknown or missing values never map to success."""
    if lifecycle == "CANCELED":
        return CANCELED
    if lifecycle == "INTERRUPTED":
        return INCONCLUSIVE
    if lifecycle == "BLOCKED":
        return BLOCKED
    if lifecycle != "COMPLETE" or evidence_status != "FINALIZED" or verdict is None:
        return INCONCLUSIVE
    return VERDICT_EXIT.get(verdict, INCONCLUSIVE)
