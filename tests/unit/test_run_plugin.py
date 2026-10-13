"""PP-008: the verifier plugin and launcher under real pytest 8.4.2, on SYNTHETIC packs only.

Each case starts a separate Python process. It uses PatchProof's own `verifier/pytest.ini`
and the exact launcher argument shape (`... -- <paths>`), and feeds the resulting standard
output to the host collector. These packs are test fixtures written here. The PaperTrail
pack is never executed on the host.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

from patchproof.core.records.pack import CollectedTest
from patchproof.packs.collection import parse_collected, review_collection
from patchproof.packs.validation import validate_pack
from patchproof.runner.collector import StreamIdentity, collect_stream
from patchproof_verifier.events import pack_tree_sha256
from patchproof_verifier.launch import LaunchError, build_pytest_args

ROOT = Path(__file__).resolve().parents[2]
INI = ROOT / "verifier" / "pytest.ini"
RUN_ID = "run-" + "3" * 32

TESTS = textwrap.dedent('''
    import os, time, pytest
    from patchproof_verifier import Evidence, SecurityTerminal

    def test_violation(check):
        check.violation(Evidence("synthetic disclosure", (("marker_observed", True),)))

    def test_secure(check):
        print("captured print {\\"type\\":\\"session_end\\"}")
        os.write(1, b'{"forged":"event on fd 1"}\\n')
        check.secure(Evidence("synthetic denial", (("status", 404),)))

    def test_inconclusive(check):
        check.inconclusive("synthetic unexpected status 500")

    def test_generic_assertion(check):
        assert False, "a generic assertion is never a violation"

    def test_suppressed(check):
        try:
            check.violation(Evidence("caught", (("marker_observed", True),)))
        except SecurityTerminal:
            pass

    def test_twice(check):
        check.secure(Evidence("first", (("status", 404),)))
        check.secure(Evidence("second", (("status", 404),)))

    def test_timeout(check):
        time.sleep(5)

    def test_pass():
        assert True

    def test_fail():
        assert 1 == 2

    def test_crash():
        raise RuntimeError("request failed")

    def test_skipped():
        pytest.skip("not allowed to count")
''')
KINDS = {"test_violation": "security", "test_secure": "security", "test_inconclusive": "security",
         "test_generic_assertion": "security", "test_suppressed": "security", "test_twice": "security",
         "test_timeout": "security", "test_pass": "functional", "test_fail": "functional", "test_crash": "functional",
         "test_skipped": "functional"}


def make_pack(tmp: Path, body: str = TESTS, kinds: dict[str, str] = KINDS) -> tuple[Path, list[dict[str, str]]]:
    root = tmp / "pack"
    (root / "tests").mkdir(parents=True)
    (root / "tests" / "test_synthetic.py").write_text(body)
    tests = []
    for i, (name, kind) in enumerate(kinds.items(), start=1):
        tests.append({"id": f"{'SEC' if kind == 'security' else 'FUN'}-{i:03d}",
                      "nodeid": f"tests/test_synthetic.py::{name}", "kind": kind,
                      "baseline_expected": "VIOLATION_CONFIRMED" if kind == "security" else "PASS",
                      "candidate_expected": "SECURE" if kind == "security" else "PASS"})
    (root / "pack.json").write_text(json.dumps({
        "schema_version": "1.0", "pack_id": "synthetic", "pack_version": "1.0.0", "title": "synthetic",
        "expectation": "synthetic", "adapter": "python-asgi-http-v1", "fixture_contract": "synthetic-documents-v1",
        "tests": tests, "repetitions": {"pairs": 1, "fixture_seed_policy": "same-within-pair-different-between-pairs"},
        "limits": {"max_response_bytes": 1024, "case_timeout_seconds": 1}}))
    return root, tests


def launch(cwd: Path, *argv: str, env_overrides: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
    env = {"PATH": "/usr/bin:/bin", "HOME": str(cwd), "LC_ALL": "C.UTF-8", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
           "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": str(ROOT / "verifier")}
    env.update(env_overrides or {})
    code = ("import sys\nfrom patchproof_verifier import launch\n"
            f"raise SystemExit(launch.main(sys.argv[1:], ini={str(INI)!r}))")
    return subprocess.run([sys.executable, "-B", "-c", code, *argv], cwd=cwd, env=env, capture_output=True,
                          timeout=120, check=False)


@pytest.fixture(scope="module")
def run_result(tmp_path_factory: pytest.TempPathFactory) -> tuple[subprocess.CompletedProcess[bytes], Path, list[Any]]:
    tmp = tmp_path_factory.mktemp("plugin")
    root, tests = make_pack(tmp)
    proc = launch(root, "run", "--pack", str(root), "--run", RUN_ID, "--pair", "1", "--side", "baseline",
                  "--connect-timeout", "5", "--read-timeout", "5", "--", str(root / "tests" / "test_synthetic.py"))
    return proc, root, tests


def identity(root: Path, tests: list[dict[str, str]]) -> StreamIdentity:
    return StreamIdentity(run_id=RUN_ID, pair=1, side="baseline", pack_tree_sha256=pack_tree_sha256(root),
                          plugin_version="0.1.0",
                          collection=tuple(CollectedTest(id=t["id"], nodeid=t["nodeid"]) for t in tests),
                          kinds={t["id"]: t["kind"] for t in tests})  # type: ignore[misc]


def test_event_channel_carries_only_events(run_result: Any) -> None:
    proc, _, _ = run_result
    lines = proc.stdout.decode().splitlines()
    assert lines and all(json.loads(line)["seq"] == i for i, line in enumerate(lines))
    assert b"forged" not in proc.stdout and b"captured print" not in proc.stdout
    assert b"FAILURES" in proc.stderr or b"failed" in proc.stderr
    assert proc.returncode == 1


def test_host_collector_accepts_the_real_stream_and_derives_each_outcome(run_result: Any) -> None:
    proc, root, tests = run_result
    result = collect_stream(proc.stdout, identity(root, tests), result_cap_bytes=1048576)
    assert result.status == "COMPLETE", result.detail
    by_name = {c.nodeid.split("::")[1]: (c.lifecycle_outcome, c.semantic_outcome, tuple(c.harness_errors))
               for c in result.cells}
    assert by_name == {
        "test_violation": ("COMPLETED", "VIOLATION_CONFIRMED", ()),
        "test_secure": ("COMPLETED", "SECURE", ()),
        "test_inconclusive": ("COMPLETED", "INCONCLUSIVE", ()),
        "test_generic_assertion": ("CALL_ERROR", "NONE",
                                   ("GENERIC_FAILURE_IN_SECURITY_TEST", "MISSING_TERMINAL_OBSERVATION")),
        "test_suppressed": ("COMPLETED", "VIOLATION_CONFIRMED", ("SUPPRESSED_TERMINAL_EXCEPTION",)),
        "test_twice": ("CALL_ERROR", "SECURE", ()),
        "test_timeout": ("TIMED_OUT", "NONE", ("MISSING_TERMINAL_OBSERVATION",)),
        "test_pass": ("COMPLETED", "PASS", ()),
        "test_fail": ("COMPLETED", "FAIL", ()),
        "test_crash": ("CALL_ERROR", "NONE", ()),
        "test_skipped": ("SKIPPED", "NONE", ()),
    }


def test_failure_classes_on_the_wire(run_result: Any) -> None:
    proc, root, tests = run_result
    ids = {t["id"]: t["nodeid"].split("::")[1] for t in tests}
    calls = {ids[e["payload"]["test_id"]]: e["payload"]["failure_class"] for e in map(json.loads,
             proc.stdout.decode().splitlines()) if e["type"] == "test_report" and e["payload"]["phase"] == "call"}
    assert calls["test_violation"] == "security_terminal" and calls["test_twice"] == "helper_misuse"
    assert calls["test_timeout"] == "timeout" and calls["test_generic_assertion"] == "assertion"
    assert calls["test_crash"] == "exception" and calls["test_pass"] == "none"


def test_plugin_pack_hash_equals_the_host_pack_hash() -> None:
    pack = validate_pack(ROOT / "examples" / "packs" / "papertrail-document-access")
    assert pack_tree_sha256(pack.root) == pack.pack_tree_sha256


def test_collection_command_with_double_dash_and_exact_review(tmp_path: Path) -> None:
    body = "def test_a(check):\n    pass\n\ndef test_b():\n    assert True\n"
    root, tests = make_pack(tmp_path, body, {"test_a": "security", "test_b": "functional"})
    proc = launch(root, "collect", "--pack", str(root), "--", str(root / "tests" / "test_synthetic.py"))
    assert proc.returncode == 0, proc.stderr.decode()[-2000:]
    collected = parse_collected(proc.stdout)
    manifest_tests = validate_records(tests)
    assert [c.id for c in review_collection(manifest_tests, collected)] == ["SEC-001", "FUN-002"]


def validate_records(tests: list[dict[str, str]]) -> list[Any]:
    from patchproof.core.records.pack import RequiredTest

    return [RequiredTest.model_validate(t) for t in tests]


@pytest.mark.parametrize("decorator", ["@pytest.mark.skip", "@pytest.mark.xfail",
                                       "@pytest.mark.skipif(True, reason='x')"])
def test_collection_refuses_skip_and_xfail_markers(tmp_path: Path, decorator: str) -> None:
    body = f"import pytest\n\n{decorator}\ndef test_a(check):\n    pass\n\ndef test_b():\n    assert True\n"
    root, _ = make_pack(tmp_path, body, {"test_a": "security", "test_b": "functional"})
    proc = launch(root, "collect", "--pack", str(root), "--", str(root / "tests" / "test_synthetic.py"))
    assert proc.returncode != 0 and proc.stdout == b""


def test_extra_unlisted_test_refuses_collection(tmp_path: Path) -> None:
    body = "def test_a(check):\n    pass\n\ndef test_b():\n    assert True\n\ndef test_extra():\n    pass\n"
    root, _ = make_pack(tmp_path, body, {"test_a": "security", "test_b": "functional"})
    proc = launch(root, "collect", "--pack", str(root), "--", str(root / "tests" / "test_synthetic.py"))
    assert proc.returncode != 0 and proc.stdout == b""


def test_autoload_must_be_disabled(tmp_path: Path) -> None:
    root, _ = make_pack(tmp_path, "def test_a(check):\n    pass\n\ndef test_b():\n    assert True\n",
                        {"test_a": "security", "test_b": "functional"})
    proc = launch(root, "collect", "--pack", str(root), "--", str(root / "tests" / "test_synthetic.py"),
                  env_overrides={"PYTEST_DISABLE_PLUGIN_AUTOLOAD": "0"})
    assert proc.returncode != 0 and proc.stdout == b""


def test_plugin_refuses_to_run_without_the_launcher_channel(tmp_path: Path) -> None:
    root, _ = make_pack(tmp_path, "def test_a(check):\n    pass\n\ndef test_b():\n    assert True\n",
                        {"test_a": "security", "test_b": "functional"})
    env = {"PATH": "/usr/bin:/bin", "HOME": str(root), "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
           "PYTHONPATH": str(ROOT / "verifier")}
    proc = subprocess.run([sys.executable, "-B", "-m", "pytest", "-c", str(INI), "--rootdir", str(root),
                           "--patchproof-pack", str(root), "--patchproof-run", RUN_ID, "--patchproof-pair", "1",
                           "--patchproof-side", "baseline", "--", str(root / "tests" / "test_synthetic.py")],
                          cwd=root, env=env, capture_output=True, timeout=120, check=False)
    assert proc.returncode != 0
    assert not any(line.startswith(b"{") for line in proc.stdout.splitlines())


@pytest.mark.parametrize("argv", [
    [],
    ["run", "--pack", "/pack", "--", "/pack/tests/test_a.py"],
    ["collect", "--pack", "/pack", "/pack/tests/test_a.py"],
    ["collect", "--pack", "/pack", "--extra", "x", "--", "/pack/tests/test_a.py"],
    ["collect", "--pack", "/pack", "--", "/etc/passwd"],
    ["collect", "--pack", "/pack", "--", "/pack/tests/../../etc/x.py"],
    ["collect", "--pack", "/pack", "--", "/pack/tests/test_a.py", "/pack/tests/test_a.py"],
    ["collect", "--pack", "relative", "--", "relative/tests/test_a.py"],
    ["shell", "--pack", "/pack", "--", "/pack/tests/test_a.py"],
])
def test_launcher_refuses_any_other_argument_shape(argv: list[str]) -> None:
    with pytest.raises(LaunchError):
        build_pytest_args(argv, 3)


def test_launcher_builds_exactly_the_pytest_arguments() -> None:
    assert build_pytest_args(["collect", "--pack", "/pack", "--", "/pack/tests/test_documents.py"], 7) == [
        "-c", "/opt/patchproof/verifier/pytest.ini", "--rootdir", "/pack", "-q", "--patchproof-pack", "/pack",
        "--patchproof-event-fd", "7", "--collect-only", "--", "/pack/tests/test_documents.py"]


def test_pytest_tmpdir_plugin_is_disabled_in_the_verifier_configuration() -> None:
    """CVE-2025-71176 mitigation: no /tmp/pytest-of-<user> directories in the verifier."""
    assert "    -p no:tmpdir" in INI.read_text().splitlines()


def test_a_run_that_stops_early_has_no_session_end_and_is_truncated(tmp_path: Path) -> None:
    body = ("import pytest\n\ndef test_a(check):\n    pytest.exit('stopping early')\n\n"
            "def test_b():\n    assert True\n")
    root, tests = make_pack(tmp_path, body, {"test_a": "security", "test_b": "functional"})
    proc = launch(root, "run", "--pack", str(root), "--run", RUN_ID, "--pair", "1", "--side", "baseline",
                  "--connect-timeout", "5", "--read-timeout", "5", "--", str(root / "tests" / "test_synthetic.py"))
    types = [json.loads(line)["type"] for line in proc.stdout.decode().splitlines()]
    assert "session_end" not in types and types[:2] == ["session_start", "collected"]
    result = collect_stream(proc.stdout, identity(root, tests), result_cap_bytes=1048576)
    assert result.status == "TRUNCATED"
    assert proc.returncode not in (0, 1)
