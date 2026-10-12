"""PatchProof verifier helpers and pytest plugin (PROJECT_SPEC.md 7.3, 7.4).

This package is PatchProof-owned, reviewed code that is installed only in the approved
verifier image. Verification packs import it; they never import target code, and the
verifier never receives target source (ADR-003).
"""

from .check import Evidence, HelperMisuse, SecurityCheck, SecurityTerminal
from .plugin import PLUGIN_VERSION

__all__ = ["PLUGIN_VERSION", "Evidence", "HelperMisuse", "SecurityCheck", "SecurityTerminal"]
