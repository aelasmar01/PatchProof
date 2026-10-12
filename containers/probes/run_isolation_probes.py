"""Launcher for the PP-003 probe suite until `patchproof doctor --probe-isolation` is packaged.

Usage (from any directory; -I keeps the host environment and cwd out of sys.path):

    python3 -I containers/probes/run_isolation_probes.py plan --image-id sha256:<id>
    python3 -I containers/probes/run_isolation_probes.py run --image-id sha256:<id> \
        --evidence-root "$HOME/Library/Application Support/PatchProof/probe-runs"

`run` requires the A2, A3, and A4 approvals; see STATUS.md.
"""

import sys
from pathlib import Path

sys.dont_write_bytecode = True  # `plan` must have no filesystem side effects
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from patchproof.probes.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
