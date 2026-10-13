"""The approved PatchProof pytest plugin (PROJECT_SPEC.md 7.3, 7.4, 10.3). Runs only in the verifier image.

It is loaded explicitly through `verifier/pytest.ini`, with entry-point autoloading
disabled (the plugin refuses to run otherwise), so a pack cannot add plugins.

**Two modes, both writing to a private event channel:**
- **Collection only** (`--collect-only`): maps every collected item to its manifest test
  ID. It refuses unknown, missing or duplicated tests and skip/xfail markers, then writes
  one `collected` record.
- **Run** (`--patchproof-run/--patchproof-pair/--patchproof-side`): emits the typed
  verifier-event stream: `session_start`, `collected`, a `test_report` per phase with its
  `failure_class`, one `observation` per terminal security call, and `session_end`. The
  plugin emits `session_end` only when every collected test has fully reported; an
  incomplete run ends without it, and the host classifies it as TRUNCATED.

**The event channel:** a private descriptor opened by `patchproof_verifier.launch` before
pytest starts, passed as `--patchproof-event-fd`. Pytest's own output and anything a test
prints go to standard error. The plugin refuses to run without the descriptor. The host, not
this plugin, decides whether the stream is trustworthy.

**Failure classes:** `SecurityTerminal` in the call phase is `security_terminal`;
`HelperMisuse` is `helper_misuse`; the per-test deadline is `timeout`; `AssertionError` is
`assertion`; anything else, including request failures, is `exception`.
"""

from __future__ import annotations

import os
import re
import signal
from collections.abc import Generator, Iterable, Mapping, Sequence
from pathlib import Path
from types import FrameType
from typing import Any, Final

import pytest

from .check import HelperMisuse, SecurityCheck, SecurityTerminal, TerminalObservation
from .documents import SyntheticDocuments, load_documents
from .events import EventWriter, pack_tree_sha256, write_line
from .http import TargetClient
from .manifest import read_manifest_limits, read_manifest_tests
from .transport import TargetTransport

PLUGIN_VERSION: Final = "0.1.0"
FORBIDDEN_MARKERS: Final = frozenset({"skip", "skipif", "xfail"})
_RUN_ID_RE: Final = re.compile(r"run-[0-9a-f]{32}")


class CollectionRefused(Exception):  # noqa: N818 - protocol name
    """Collection does not match the pack manifest exactly; nothing may run."""


class CaseTimeout(Exception):  # noqa: N818 - protocol name
    """The per-test deadline from the pack manifest expired (failure_class: timeout)."""


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


def failure_class(when: str, outcome: str, exc: BaseException | None) -> str:
    """The plugin's classification of one phase report (verdict specification 3.2)."""
    if outcome != "failed":
        return "none"
    if isinstance(exc, SecurityTerminal):
        return "security_terminal" if when == "call" else "exception"
    if isinstance(exc, HelperMisuse):
        return "helper_misuse"
    if isinstance(exc, CaseTimeout):
        return "timeout"
    if isinstance(exc, AssertionError):
        return "assertion"
    return "exception"


class _State:
    def __init__(self, pack_root: Path, manifest_tests: list[dict[str, str]], case_timeout: int,
                 max_response_bytes: int) -> None:
        self.pack_root = pack_root
        self.manifest_tests = manifest_tests
        self.kinds = {t["nodeid"]: t["kind"] for t in manifest_tests}
        self.ids = {t["nodeid"]: t["id"] for t in manifest_tests}
        self.case_timeout = case_timeout
        self.max_response_bytes = max_response_bytes
        self.collected: dict[str, list[dict[str, str]]] | None = None
        self.observations: list[TerminalObservation] = []
        self.writer: EventWriter | None = None
        self.event_fd: int | None = None
        self.collect_only = False
        self.torn_down: set[str] = set()
        self.timeouts: tuple[float, float] = (5.0, 5.0)


_STATE_KEY = pytest.StashKey[_State]()


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("patchproof")
    group.addoption("--patchproof-pack", default=None, help="approved pack root (read-only)")
    group.addoption("--patchproof-run", default=None, help="run ID (run mode)")
    group.addoption("--patchproof-pair", default=None, help="pair index (run mode)")
    group.addoption("--patchproof-side", default=None, help="baseline or candidate (run mode)")
    group.addoption("--patchproof-connect-timeout", default="5", help="target connect timeout, seconds")
    group.addoption("--patchproof-read-timeout", default="5", help="target read timeout, seconds")
    group.addoption("--patchproof-event-fd", default=None, help="event descriptor from patchproof_verifier.launch")


def _event_channel(config: pytest.Config) -> int:
    """The private event descriptor the launcher opened before pytest started."""
    raw = config.getoption("--patchproof-event-fd")
    if raw is None or not str(raw).isdigit() or int(raw) < 3:
        raise pytest.UsageError("start the verifier through patchproof_verifier.launch (no event descriptor)")
    fd = int(raw)
    try:
        os.fstat(fd)
    except OSError:
        raise pytest.UsageError("the event descriptor is not open") from None
    return fd


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config: pytest.Config) -> None:
    if os.environ.get("PYTEST_DISABLE_PLUGIN_AUTOLOAD") != "1":
        raise pytest.UsageError("PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 is required")
    root = config.getoption("--patchproof-pack")
    if root is None:
        raise pytest.UsageError("--patchproof-pack is required")
    pack_root = Path(root)
    max_bytes, case_timeout = read_manifest_limits(pack_root / "pack.json")
    state = _State(pack_root, read_manifest_tests(pack_root / "pack.json"), case_timeout, max_bytes)
    state.collect_only = bool(config.option.collectonly)
    run, pair, side = (config.getoption(o) for o in ("--patchproof-run", "--patchproof-pair", "--patchproof-side"))
    if state.collect_only:
        if any(v is not None for v in (run, pair, side)):
            raise pytest.UsageError("collection mode takes no run identity")
        state.event_fd = _event_channel(config)
    else:
        if (run is None or not _RUN_ID_RE.fullmatch(run) or pair is None or not str(pair).isdigit()
                or not 1 <= int(pair) <= 10 or side not in ("baseline", "candidate")):
            raise pytest.UsageError("run mode needs a valid --patchproof-run, --patchproof-pair and --patchproof-side")
        try:
            timeouts = (float(config.getoption("--patchproof-connect-timeout")),
                        float(config.getoption("--patchproof-read-timeout")))
        except ValueError:
            raise pytest.UsageError("timeouts must be numbers") from None
        if not all(0 < t <= 30 for t in timeouts):
            raise pytest.UsageError("timeouts must be within (0, 30] seconds")
        state.timeouts = timeouts
        state.event_fd = _event_channel(config)
        state.writer = EventWriter(state.event_fd, run_id=run, pair=int(pair), side=side)
    config.stash[_STATE_KEY] = state
    config.pluginmanager.register(_Reporter(state), "patchproof-reporter")


def pytest_sessionstart(session: pytest.Session) -> None:
    state = session.config.stash[_STATE_KEY]
    if state.writer is not None:
        state.writer.emit("session_start", {"verifier_plugin_version": PLUGIN_VERSION,
                                            "pack_tree_sha256": pack_tree_sha256(state.pack_root)})


def pytest_collection_modifyitems(session: pytest.Session, config: pytest.Config, items: list[pytest.Item]) -> None:
    state = config.stash[_STATE_KEY]
    markers = {item.nodeid: [m.name for m in item.iter_markers()] for item in items}
    try:
        state.collected = build_collected(state.manifest_tests, [item.nodeid for item in items], markers)
    except CollectionRefused as exc:
        raise pytest.UsageError(f"PatchProof collection refused: {exc}") from None
    if state.collect_only and state.event_fd is not None:
        write_line(state.event_fd, state.collected)
    elif state.writer is not None:
        state.writer.emit("collected", state.collected)


@pytest.hookimpl(wrapper=True)
def pytest_runtest_call(item: pytest.Item) -> Generator[None, Any, Any]:
    state = item.config.stash[_STATE_KEY]

    def expire(signum: int, frame: FrameType | None) -> None:
        raise CaseTimeout(f"test exceeded {state.case_timeout} s")

    previous = signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, float(state.case_timeout))
    try:
        return (yield)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[None]) -> Generator[None, Any, Any]:
    report = yield
    exc = call.excinfo.value if call.excinfo is not None else None
    report.patchproof_failure_class = failure_class(report.when, report.outcome, exc)
    return report


class _Reporter:
    """Registered per session: turns each phase report into a `test_report` event."""

    def __init__(self, state: _State) -> None:
        self.state = state

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        state = self.state
        test_id = state.ids.get(report.nodeid)
        if state.writer is None or test_id is None:
            return
        state.writer.emit("test_report", {
            "test_id": test_id, "phase": report.when, "outcome": report.outcome,
            "failure_class": getattr(report, "patchproof_failure_class", "exception" if report.failed else "none"),
            "xfail": hasattr(report, "wasxfail"),
        })
        if report.when == "teardown":
            state.torn_down.add(report.nodeid)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    state = session.config.stash.get(_STATE_KEY, None)
    if state is None or state.writer is None or state.collected is None:
        return
    collected = [t["nodeid"] for t in state.collected["tests"]]
    if set(collected) == state.torn_down:
        state.writer.emit("session_end", {"tests_reported": len(collected),
                                          "observations_emitted": len(state.observations)})


@pytest.fixture
def check(request: pytest.FixtureRequest) -> SecurityCheck:
    state = request.config.stash[_STATE_KEY]
    nodeid = request.node.nodeid
    if state.kinds.get(nodeid) != "security":
        raise pytest.UsageError(f"{nodeid}: the check fixture is only for security tests")

    def sink(observation: TerminalObservation) -> None:
        state.observations.append(observation)
        if state.writer is not None:
            state.writer.emit("observation", {"test_id": observation.test_id, "outcome": observation.outcome,
                                              "summary": observation.summary, "evidence_refs": []})

    return SecurityCheck(state.ids[nodeid], sink)


@pytest.fixture
def documents(request: pytest.FixtureRequest) -> SyntheticDocuments:
    state = request.config.stash[_STATE_KEY]
    return load_documents(state.pack_root / "fixtures" / "synthetic-documents-v1.json")


@pytest.fixture
def target(request: pytest.FixtureRequest) -> TargetClient:
    state = request.config.stash[_STATE_KEY]
    connect, read = state.timeouts
    return TargetTransport(connect_timeout=connect, read_timeout=read, max_body_bytes=state.max_response_bytes)
