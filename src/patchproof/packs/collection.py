"""Exact test collection (PROJECT_SPEC.md 7.4).

Collection runs **only in the verifier environment**, never in this process: pack modules
are untrusted until approved, and importing them would execute their code. This module:
1. builds the fixed collection invocation the runner executes inside the verifier container
   (PP-008), through `patchproof_verifier.launch`, which runs pytest with PatchProof's own
   `pytest.ini`. It uses explicit test paths, no plugin autoloading, no inherited
   environment and no `conftest.py`, and it is bounded in time and output;
2. strictly parses the `collected` payload that the approved plugin emits;
3. checks that the collection matches the manifest exactly. At review time the collection
   becomes the approval's expected collection. In a run, the collection must equal that
   approved list, in order.

No collection has been performed yet: the verifier image does not exist until PP-008.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from ..core.records import RecordError, load_record
from ..core.records.pack import CollectedTest, RequiredTest
from ..core.records.run import CollectedPayload
from .validation import ValidatedPack

VERIFIER_PYTHON: Final = "/usr/local/bin/python3"
VERIFIER_PYTEST_INI: Final = "/opt/patchproof/verifier/pytest.ini"
PACK_MOUNT: Final = "/pack"
COLLECTION_TIMEOUT_SECONDS: Final = 30
COLLECTION_OUTPUT_CAP: Final = 262144
# Variables that change how Python or pytest load code. The environment is built from
# scratch, so none can be present; tests assert it.
FORBIDDEN_ENV: Final = frozenset({"PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME",
                                  "PYTHONUSERBASE", "PYTHONINSPECT", "PYTHONBREAKPOINT", "PYTHONWARNINGS",
                                  "PYTHONSAFEPATH", "PY_COLORS", "PYTEST_DEBUG", "PYTEST_THEME"})


class CollectionMismatch(ValueError):
    """Collected tests differ from the manifest or the approval (PACK_COLLECTION_MISMATCH)."""


@dataclass(frozen=True)
class CollectionPlan:
    """The exact, fixed invocation the PP-008 runner executes inside the verifier container."""

    argv: tuple[str, ...]
    env: tuple[tuple[str, str], ...]
    cwd: str
    timeout_seconds: int
    output_cap_bytes: int


def collection_plan(pack: ValidatedPack) -> CollectionPlan:
    paths = tuple(f"{PACK_MOUNT}/{rel}" for rel in pack.test_files)
    # PP-008: pytest is started through the PatchProof launcher, which opens the private event
    # channel before pytest starts (pytest keeps its own copy of stdout from startup onwards).
    argv = (VERIFIER_PYTHON, "-I", "-B", "-m", "patchproof_verifier.launch", "collect", "--pack", PACK_MOUNT,
            "--", *paths)
    env = (("PATH", "/usr/local/bin:/usr/bin:/bin"), ("LC_ALL", "C.UTF-8"), ("HOME", "/nonexistent"),
           ("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1"), ("PYTHONDONTWRITEBYTECODE", "1"), ("PYTHONHASHSEED", "0"))
    return CollectionPlan(argv=argv, env=env, cwd=PACK_MOUNT, timeout_seconds=COLLECTION_TIMEOUT_SECONDS,
                          output_cap_bytes=COLLECTION_OUTPUT_CAP)


def parse_collected(raw: bytes) -> list[CollectedTest]:
    """Strictly parse the plugin's `collected` payload (bounded; duplicate keys rejected)."""
    if len(raw) > COLLECTION_OUTPUT_CAP:
        raise CollectionMismatch("collection output exceeds the cap")
    try:
        payload = load_record(CollectedPayload, raw, contract="collected", max_bytes=COLLECTION_OUTPUT_CAP)
    except RecordError as exc:
        raise CollectionMismatch(f"malformed collection record: {'; '.join(exc.problems[:3])}") from None
    return list(payload.tests)


def review_collection(manifest_tests: Sequence[RequiredTest], collected: Sequence[CollectedTest]
                      ) -> tuple[CollectedTest, ...]:
    """Review time: the collection must contain exactly the manifest's tests, each once.

    Returns the collection in collection order. That order becomes the approval's
    `expected_collection`.
    """
    expected = {(t.id, t.nodeid) for t in manifest_tests}
    got = [(c.id, c.nodeid) for c in collected]
    if len(set(got)) != len(got) or len({i for i, _ in got}) != len(got) or len({n for _, n in got}) != len(got):
        raise CollectionMismatch("a test was collected more than once")
    missing, extra = expected - set(got), set(got) - expected
    if missing or extra:
        raise CollectionMismatch(f"{len(missing)} missing and {len(extra)} unexpected test(s)")
    return tuple(collected)


def check_run_collection(approved: Sequence[CollectedTest], collected: Sequence[CollectedTest]) -> None:
    """Run time: the collection must equal the approved expected collection exactly, in order."""
    if [(c.id, c.nodeid) for c in collected] != [(a.id, a.nodeid) for a in approved]:
        raise CollectionMismatch("the collected tests differ from the approved collection")
