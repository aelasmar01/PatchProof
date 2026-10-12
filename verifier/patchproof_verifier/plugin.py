"""The approved PatchProof pytest plugin (PROJECT_SPEC.md 7.3, 7.4). Runs only in the verifier image.

It is loaded explicitly through `verifier/pytest.ini`, with entry-point autoloading
disabled, so a pack cannot add plugins.
- **Collection (PP-007):** maps every collected item to its manifest test ID. It refuses
  unknown tests, duplicate node IDs and skip/xfail markers before any test runs, and builds
  the `collected` payload.
- **Fixtures:**
  - `check`: the per-test terminal-observation object, for security tests only;
  - `documents`: the hash-checked synthetic fixture copy from the pack;
  - `target`: the HTTP client, supplied by the PP-008 runner.

Event emission over the verifier channel and per-phase reports belong to the PP-008
transport. Until then a run (as opposed to collection) refuses to start, so no partial
result can be mistaken for a run.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, Final

import pytest

from .check import SecurityCheck, TerminalObservation
from .documents import SyntheticDocuments, load_documents
from .http import TargetClient
from .manifest import read_manifest_tests

PLUGIN_VERSION: Final = "0.1.0"
FORBIDDEN_MARKERS: Final = frozenset({"skip", "skipif", "xfail"})


class CollectionRefused(Exception):  # noqa: N818 - protocol name
    """Collection does not match the pack manifest exactly; nothing may run."""


def build_collected(manifest_tests: Sequence[dict[str, str]], nodeids: Sequence[str],
                    markers: Mapping[str, Iterable[str]] | None = None) -> dict[str, list[dict[str, str]]]:
    """The `collected` payload: every collected node ID with its manifest test ID, in collection order."""
    by_nodeid = {t["nodeid"]: t["id"] for t in manifest_tests}
    if len(by_nodeid) != len(manifest_tests) or len({t["id"] for t in manifest_tests}) != len(manifest_tests):
        raise CollectionRefused("the manifest repeats a test ID or node ID")
    if len(set(nodeids)) != len(nodeids):
        raise CollectionRefused("a node ID was collected more than once")
    unknown = [n for n in nodeids if n not in by_nodeid]
    if unknown:
        raise CollectionRefused(f"{len(unknown)} collected test(s) are not in the manifest")
    missing = [n for n in by_nodeid if n not in nodeids]
    if missing:
        raise CollectionRefused(f"{len(missing)} manifest test(s) were not collected")
    for nodeid, names in (markers or {}).items():
        refused = FORBIDDEN_MARKERS.intersection(names)
        if refused:
            raise CollectionRefused(f"{nodeid} carries forbidden marker(s) {sorted(refused)}")
    return {"tests": [{"id": by_nodeid[n], "nodeid": n} for n in nodeids]}


class _State:
    def __init__(self, pack_root: Path, manifest_tests: list[dict[str, str]]) -> None:
        self.pack_root = pack_root
        self.manifest_tests = manifest_tests
        self.kinds = {t["nodeid"]: t["kind"] for t in manifest_tests}
        self.ids = {t["nodeid"]: t["id"] for t in manifest_tests}
        self.collected: dict[str, list[dict[str, str]]] | None = None
        self.observations: list[TerminalObservation] = []


_STATE_KEY = pytest.StashKey[_State]()


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("patchproof")
    group.addoption("--patchproof-pack", default=None, help="approved pack root (read-only)")


def pytest_configure(config: pytest.Config) -> None:
    root = config.getoption("--patchproof-pack")
    if root is None:
        raise pytest.UsageError("--patchproof-pack is required")
    pack_root = Path(root)
    config.stash[_STATE_KEY] = _State(pack_root, read_manifest_tests(pack_root / "pack.json"))


def pytest_collection_modifyitems(session: pytest.Session, config: pytest.Config, items: list[pytest.Item]) -> None:
    state = config.stash[_STATE_KEY]
    markers = {item.nodeid: [m.name for m in item.iter_markers()] for item in items}
    try:
        state.collected = build_collected(state.manifest_tests, [item.nodeid for item in items], markers)
    except CollectionRefused as exc:
        raise pytest.UsageError(f"PatchProof collection refused: {exc}") from None


def pytest_runtestloop(session: pytest.Session) -> Any:
    if session.config.option.collectonly:
        return None
    raise pytest.UsageError("test execution requires the PP-008 verifier transport; collection only")


@pytest.fixture
def check(request: pytest.FixtureRequest) -> SecurityCheck:
    state = request.config.stash[_STATE_KEY]
    nodeid = request.node.nodeid
    if state.kinds.get(nodeid) != "security":
        raise pytest.UsageError(f"{nodeid}: the check fixture is only for security tests")
    return SecurityCheck(state.ids[nodeid], state.observations.append)


@pytest.fixture
def documents(request: pytest.FixtureRequest) -> SyntheticDocuments:
    state = request.config.stash[_STATE_KEY]
    return load_documents(state.pack_root / "fixtures" / "synthetic-documents-v1.json")


@pytest.fixture
def target() -> TargetClient:
    raise pytest.UsageError("the target client is provided by the PP-008 runner")
