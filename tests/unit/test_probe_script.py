"""PP-003: static checks of the in-container probe script and the CLI gates.

The probe script is parsed, never executed, on the host: several of its probes attempt
outbound connections that are expected to fail only inside a no-network container.
"""

from __future__ import annotations

import ast
import json
import re
import subprocess
from pathlib import Path

import pytest

from patchproof.probes import cli
from patchproof.probes.catalogue import CATALOGUE, PROBE_SCRIPT_PATH, load_probe_script, probe_script_digest
from patchproof.probes.interpret import HOST_JUDGED_OBSERVATIONS, STREAM_KINDS
from patchproof.runner.policy import MAX_SCRIPT_BYTES, Role

SCRIPT = load_probe_script()
TREE = ast.parse(SCRIPT)
STDLIB_ALLOWED = {"ctypes", "errno", "fcntl", "http.server", "json", "os", "socket", "stat", "struct", "subprocess",
                  "sys", "threading", "time", "urllib.request"}


def test_script_fits_in_one_argument() -> None:
    assert len(SCRIPT.encode()) <= MAX_SCRIPT_BYTES
    assert "\x00" not in SCRIPT


def test_script_imports_only_the_standard_library() -> None:
    imported = set()
    for node in ast.walk(TREE):
        if isinstance(node, ast.Import):
            imported |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    assert imported <= STDLIB_ALLOWED, imported - STDLIB_ALLOWED


def _emitted_probe_ids() -> set[str]:
    ids = set()
    for node in ast.walk(TREE):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("emit", "guarded"):
            first = node.args[0] if node.args else None
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                ids.add(first.value)
    return ids


def test_script_emits_only_catalogue_probe_ids() -> None:
    catalogue = {s.probe_id for s in CATALOGUE}
    host_judged = set().union(*HOST_JUDGED_OBSERVATIONS.values())
    assert _emitted_probe_ids() <= catalogue | host_judged


def test_every_container_emitted_probe_is_in_the_script() -> None:
    emitted = _emitted_probe_ids()
    for spec in CATALOGUE:
        if spec.roles:
            assert spec.probe_id in emitted, spec.probe_id


def test_markers_are_known_stream_kinds() -> None:
    kinds = set()
    for node in ast.walk(TREE):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "marker":
            kinds.add(node.args[0].value)  # type: ignore[attr-defined]
    assert kinds <= STREAM_KINDS


def test_script_modes_match_roles() -> None:
    modes = re.search(r"MODES = \{(.*?)\}", SCRIPT, re.S)
    assert modes is not None
    names = set(re.findall(r'"([a-z]+)":', modes.group(1)))
    assert names == {r.value for r in Role if not r.is_decoy}


def test_script_never_emits_a_verdict_word() -> None:
    for node in ast.walk(TREE):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            assert node.value not in ("PASS", "FAIL", "VERIFIED", "SECURE"), node.value


def test_script_has_main_guard_and_no_host_side_effects_at_import() -> None:
    top_level_calls = [n for n in TREE.body if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)]
    assert top_level_calls == []
    assert any(isinstance(n, ast.If) and "__main__" in ast.unparse(n.test) for n in TREE.body)


def test_digest_is_stable_and_matches_file() -> None:
    import hashlib

    assert probe_script_digest() == "sha256:" + hashlib.sha256(PROBE_SCRIPT_PATH.read_bytes()).hexdigest()


# ------------------------------------------------------------------- CLI gates (no Docker)


def _forbid_spawn(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_spawn(*a: object, **k: object) -> None:
        raise AssertionError("Docker must not be invoked")

    monkeypatch.setattr(subprocess, "Popen", no_spawn)


def test_plan_is_docker_free(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    _forbid_spawn(monkeypatch)
    assert cli.main(["plan", "--image-id", "sha256:" + "1" * 64, "--json"]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert len(plan["containers"]) == 10
    assert plan["gates"]["A2_approved_image_id"] == "sha256:" + "70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f"
    assert plan["gates"]["A2_matches_requested"] is False
    for c in plan["containers"]:
        assert "--pull=never" in c["argv"] and "--platform" in c["argv"] and "linux/amd64" in c["argv"]
        assert not any(SCRIPT in a for a in c["argv"])
    assert [c["started"] for c in plan["containers"]].count(False) == 2


def test_plan_refuses_floating_image(monkeypatch: pytest.MonkeyPatch) -> None:
    _forbid_spawn(monkeypatch)
    assert cli.main(["plan", "--image-id", "python:3.13-slim"]) == cli.EXIT_BLOCKED


def test_run_refuses_without_a2_before_touching_docker(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _forbid_spawn(monkeypatch)
    root = tmp_path / "probe-runs"
    root.mkdir(mode=0o700)
    assert cli.main(["run", "--image-id", "sha256:" + "1" * 64, "--evidence-root", str(root)]) == cli.EXIT_BLOCKED
    assert list(root.iterdir()) == [], "nothing written when the A2 gate is closed"


def test_run_refuses_missing_evidence_root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _forbid_spawn(monkeypatch)
    monkeypatch.setattr(cli, "check_execution_gates", lambda *a, **k: __import__(
        "patchproof.probes.orchestrator", fromlist=["x"]).check_execution_gates(
        *a, **k, approved_image_id="sha256:" + "1" * 64))
    missing = tmp_path / "absent"
    assert cli.main(["run", "--image-id", "sha256:" + "1" * 64, "--evidence-root", str(missing)]) == cli.EXIT_BLOCKED
    assert not missing.exists()


def test_run_requires_interactive_confirmation(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _forbid_spawn(monkeypatch)
    monkeypatch.setattr(cli, "check_execution_gates", lambda *a, **k: None)
    root = tmp_path / "probe-runs"
    root.mkdir(mode=0o700)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert cli.main(["run", "--image-id", "sha256:" + "1" * 64, "--evidence-root", str(root)]) == cli.EXIT_BLOCKED
    assert list(root.iterdir()) == [], "nothing is written before A4 confirmation"
