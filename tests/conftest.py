"""Test configuration: make the `src/` tree importable.

`uv run pytest` uses the editable install from pyproject.toml. Adding `src/` here as
well keeps the tests runnable from an exported tree or another interpreter without
relying on PYTHONPATH.
"""

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
# PP-007: the PatchProof-owned verifier helpers (installed only in the verifier image) are
# unit-tested here as trusted code. Pack test modules are never imported.
VERIFIER = Path(__file__).resolve().parents[1] / "verifier"
if str(VERIFIER) not in sys.path:
    sys.path.insert(0, str(VERIFIER))
