"""How the v0.1 workflow tells the owner which command to run next (PROJECT_SPEC.md 13.1; PP-009 U1).

v0.1 runs from a development checkout, not from an installed package: the pinned, offline
invocation is `uv run --locked --offline patchproof ...` from the project directory (the same
form the README and `docs/architecture/cli-workflow.md` document). A bare `patchproof` works
only where the package is installed on the shell's PATH, which v0.1 does not do, so every
next-step hint is printed in the pinned form. Hints never contain host paths.

This builds display text only: nothing here runs a command, and an argument that would need
shell quoting is refused rather than quoted.
"""

from __future__ import annotations

import re
from typing import Final

INVOCATION: Final = ("uv", "run", "--locked", "--offline", "patchproof")
_PLAIN_ARGUMENT: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@=-]{0,127}")


def command(*args: str) -> str:
    """The exact command line for `patchproof <args>` in the documented development environment."""
    for arg in args:
        if not _PLAIN_ARGUMENT.fullmatch(arg):
            raise ValueError("a next-step hint takes only plain identifiers")
    return " ".join((*INVOCATION, *args))
