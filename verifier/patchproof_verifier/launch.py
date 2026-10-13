"""Fixed verifier entry point: `python3 -I -B -m patchproof_verifier.launch <mode> ...`.

**Why this exists.** Pytest saves its own copy of standard output while it is starting up,
before any plugin can act, and its terminal reporter writes through that copy. A plugin
therefore cannot keep pytest's output out of standard output. This launcher instead:
1. moves the original standard output to a private descriptor (the event channel), and
   points descriptor 1 at standard error, **before pytest is imported**;
2. calls `pytest.main` with arguments it builds itself;
3. passes the event descriptor to the PatchProof plugin.

Everything except PatchProof events then leaves the container on standard error.

**Accepted argument shapes** (anything else is refused with exit code 2):

    collect --pack /pack -- tests/...py ...
    run --pack /pack --run RUN --pair N --side SIDE --connect-timeout S --read-timeout S -- tests/...py ...

Paths after `--` must be the pack's test modules, under the pack root.
"""

from __future__ import annotations

import os
import re
import sys
from typing import Final

PYTEST_INI: Final = "/opt/patchproof/verifier/pytest.ini"
_PATH_RE: Final = re.compile(r"/[A-Za-z0-9_][A-Za-z0-9_/.-]{0,250}\.py")


class LaunchError(Exception):
    pass


def build_pytest_args(argv: list[str], event_fd: int, *, ini: str = PYTEST_INI) -> list[str]:
    """Translate the launcher's fixed argument shape into pytest arguments, or refuse."""
    if "--" not in argv:
        raise LaunchError("test paths must follow --")
    split = argv.index("--")
    head, paths = argv[:split], argv[split + 1:]
    if not head or head[0] not in ("collect", "run"):
        raise LaunchError("mode must be collect or run")
    mode, options = head[0], head[1:]
    expected = ["--pack"] if mode == "collect" else ["--pack", "--run", "--pair", "--side", "--connect-timeout",
                                                     "--read-timeout"]
    if len(options) != 2 * len(expected) or options[0::2] != expected:
        raise LaunchError(f"{mode} takes exactly {' '.join(expected)}")
    values = dict(zip(options[0::2], options[1::2], strict=True))
    pack = values["--pack"]
    if not pack.startswith("/") or "\x00" in pack:
        raise LaunchError("--pack must be an absolute path")
    if not paths or len(set(paths)) != len(paths):
        raise LaunchError("at least one distinct test path is required")
    for path in paths:
        if not _PATH_RE.fullmatch(path) or ".." in path.split("/") or not path.startswith(pack.rstrip("/") + "/tests/"):
            raise LaunchError("test paths must be .py files under the pack's tests/ directory")
    args = ["-c", ini, "--rootdir", pack, "-q", "--patchproof-pack", pack, "--patchproof-event-fd", str(event_fd)]
    if mode == "collect":
        args.append("--collect-only")
    else:
        args += ["--patchproof-run", values["--run"], "--patchproof-pair", values["--pair"],
                 "--patchproof-side", values["--side"], "--patchproof-connect-timeout", values["--connect-timeout"],
                 "--patchproof-read-timeout", values["--read-timeout"]]
    return [*args, "--", *paths]


def main(argv: list[str], *, ini: str = PYTEST_INI) -> int:
    event_fd = os.dup(1)
    os.dup2(2, 1)
    os.set_inheritable(event_fd, False)
    try:
        args = build_pytest_args(argv, event_fd, ini=ini)
    except LaunchError as exc:
        print(f"patchproof launch: {exc}", file=sys.stderr)
        return 2
    import pytest  # imported only after descriptor 1 points at standard error

    return int(pytest.main(args))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
