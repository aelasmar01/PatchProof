"""Test configuration: make the not-yet-packaged `src/` tree importable.

Packaging (pyproject.toml, approval item 2) is still unapproved, so tests add `src/`
explicitly instead of relying on an installed package or PYTHONPATH.
"""

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
