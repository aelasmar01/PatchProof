"""``python -m patchproof.reference <new-directory>``: generate the PaperTrail reference repository.

Prints the deterministic generation record (tags, commit and tree IDs) as JSON. The
destination must be a new directory; nothing existing is modified.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from .gitobjects import FixtureGenerationError
from .papertrail import generate_reference_repository


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: python -m patchproof.reference <new-absolute-directory>", file=sys.stderr)
        return 2
    try:
        generated = generate_reference_repository(Path(argv[0]))
    except (FixtureGenerationError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(generated.as_record(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
