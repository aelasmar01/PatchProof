"""PP-008: run-container policy, create argv, inspect gate, and immutable inputs (PP-007 R2)."""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

import pytest
from _run_fixtures import (
    OWNERSHIP,
    PACK_DIR,
    TARGET_ENV,
    VERIFIER_ENV,
    Environment,
    build_environment,
    container_inspect,
    private,
)

from patchproof.packs.validation import validate_pack
from patchproof.runner import policy
from patchproof.runner.docker_cli import ALLOWED_OP_TYPES
from patchproof.runner.inputs import (
    InputIntegrityError,
    PackSnapshot,
    SourceSnapshot,
    materialize_pack,
    verify_pack_snapshot,
    verify_source_snapshot,
)
from patchproof.runner.policy import ContainerId, ImageId, PolicyViolation
from patchproof.runner.run_gate import check_run_container
from patchproof.runner.run_policy import (
    RunCreate,
    RunRole,
    StartAttached,
    assert_run_create_shape,
    build_run_spec,
    run_create_argv_tail,
    target_command,
    verifier_command,
)

TID = "c" * 64


@pytest.fixture(scope="module")
def env(tmp_path_factory: pytest.TempPathFactory) -> Environment:
    return build_environment(tmp_path_factory.mktemp("policy"))


def specs(env: Environment) -> tuple[Any, Any]:
    plan = env.plan
    target = build_run_spec(ownership=OWNERSHIP, pair=1, side="baseline", role=RunRole.TARGET,
                            image=plan.target_image.image, limits=plan.limits(RunRole.TARGET),
                            input_dir=plan.baseline.source_dir, command=target_command("papertrail.app:app"))
    verifier = build_run_spec(ownership=OWNERSHIP, pair=1, side="baseline", role=RunRole.VERIFIER,
                              image=plan.verifier_image.image, limits=plan.limits(RunRole.VERIFIER),
                              input_dir=plan.pack.root, join_target=ContainerId(TID),
                              command=verifier_command(run_id=OWNERSHIP.run_id, pair=1, side="baseline",
                                                       test_paths=plan.test_paths, connect_timeout=5, read_timeout=5))
    return target, verifier


# ------------------------------------------------------------ fixed commands and argv


def test_fixed_commands(env: Environment) -> None:
    assert target_command("papertrail.app:app") == (
        "-I", "-B", "-m", "uvicorn", "papertrail.app:app", "--app-dir", "/app/source", "--host", "127.0.0.1",
        "--port", "8080", "--workers", "1", "--loop", "asyncio", "--http", "h11", "--ws", "none", "--interface",
        "asgi3", "--lifespan", "on", "--no-access-log", "--no-proxy-headers", "--no-server-header",
        "--timeout-graceful-shutdown", "3")
    assert verifier_command(run_id=OWNERSHIP.run_id, pair=1, side="candidate", test_paths=env.plan.test_paths,
                            connect_timeout=5, read_timeout=2.5) == (
        "-I", "-B", "-m", "patchproof_verifier.launch", "run", "--pack", "/pack", "--run", OWNERSHIP.run_id,
        "--pair", "1", "--side", "candidate", "--connect-timeout", "5", "--read-timeout", "2.5", "--",
        "/pack/tests/test_documents.py")


@pytest.mark.parametrize("app", ["papertrail.app:app; rm -rf /", "--reload", "a:b:c", "../x:app", ""])
def test_asgi_app_grammar(app: str) -> None:
    with pytest.raises(PolicyViolation):
        target_command(app)


@pytest.mark.parametrize("paths", [(), ("/etc/passwd",), ("/pack/tests/../x.py",), ("/pack/tests/a.py",),
                                   ("/pack/tests/test_a.py", "/pack/tests/test_a.py")])
def test_verifier_test_paths(paths: tuple[str, ...]) -> None:
    with pytest.raises(PolicyViolation):
        verifier_command(run_id=OWNERSHIP.run_id, pair=1, side="baseline", test_paths=paths, connect_timeout=5,
                         read_timeout=5)


def test_create_argv_reuses_the_probe_security_settings(env: Environment) -> None:
    target, verifier = specs(env)
    for spec in (target, verifier):
        argv = run_create_argv_tail(spec)
        for option, value in (("--user", "10001:10001"), ("--cap-drop", "ALL"),
                              ("--security-opt", "no-new-privileges=true"), ("--ipc", "private"),
                              ("--cgroupns", "private"), ("--restart", "no"), ("--log-driver", "local"),
                              ("--platform", "linux/amd64"), ("--entrypoint", "/usr/local/bin/python3")):
            assert argv[argv.index(option) + 1] == value
        assert "--read-only" in argv and "--pull=never" in argv
        assert argv.count("--mount") == 1
        assert_run_create_shape(argv)
    assert run_create_argv_tail(target)[run_create_argv_tail(target).index("--network") + 1] == "none"
    assert run_create_argv_tail(verifier)[run_create_argv_tail(verifier).index("--network") + 1] == f"container:{TID}"


@pytest.mark.parametrize("extra", [["--publish", "8080:8080"], ["-p", "8080"], ["--env", "X=1"],
                                   ["--privileged"], ["--cap-add", "SYS_ADMIN"], ["--volume", "/:/host"],
                                   ["--mount", "type=bind,source=/,target=/host"], ["--network=host"],
                                   ["--security-opt", "seccomp=unconfined"], ["--pid", "host"]])
def test_shape_check_refuses_extra_options(env: Environment, extra: list[str]) -> None:
    target, _ = specs(env)
    argv = run_create_argv_tail(target)
    tampered = argv[:4] + extra + argv[4:]
    with pytest.raises(PolicyViolation):
        assert_run_create_shape(tampered)


def test_role_topology_cannot_be_inverted(env: Environment) -> None:
    plan = env.plan
    with pytest.raises(PolicyViolation, match="no network"):
        build_run_spec(ownership=OWNERSHIP, pair=1, side="baseline", role=RunRole.TARGET, image=plan.target_image.image,
                       limits=plan.limits(RunRole.TARGET), input_dir=plan.baseline.source_dir,
                       command=target_command("papertrail.app:app"), join_target=ContainerId(TID))
    with pytest.raises(PolicyViolation, match="join"):
        build_run_spec(ownership=OWNERSHIP, pair=1, side="baseline", role=RunRole.VERIFIER,
                       image=plan.verifier_image.image, limits=plan.limits(RunRole.VERIFIER), input_dir=plan.pack.root,
                       command=verifier_command(run_id=OWNERSHIP.run_id, pair=1, side="baseline",
                                                test_paths=plan.test_paths, connect_timeout=5, read_timeout=5))


def test_limits_cannot_exceed_the_accepted_ceilings(env: Environment) -> None:
    plan = env.plan
    loose = policy.ResourceLimits(nano_cpus=2_000_000_000, memory_bytes=policy.GIB, pids=128,
                                  scratch_bytes=policy.MIB, tmp_bytes=policy.MIB, deadline_seconds=60)
    with pytest.raises(PolicyViolation, match="ceiling"):
        build_run_spec(ownership=OWNERSHIP, pair=1, side="baseline", role=RunRole.TARGET, image=plan.target_image.image,
                       limits=loose, input_dir=plan.baseline.source_dir, command=target_command("papertrail.app:app"))


def test_target_receives_only_the_source_and_the_verifier_only_the_pack(env: Environment) -> None:
    target, verifier = specs(env)
    assert target.input.destination == "/app/source" and target.input.source == env.plan.baseline.source_dir
    assert verifier.input.destination == "/pack" and verifier.input.source == env.plan.pack.root
    assert "/pack" not in " ".join(run_create_argv_tail(target))
    assert str(env.plan.baseline.source_dir) not in " ".join(run_create_argv_tail(verifier))


def test_read_only_input_must_be_private_canonical_and_unwritable(tmp_path: Path, env: Environment) -> None:
    from patchproof.runner.run_policy import ReadOnlyInput

    writable = private(tmp_path / "w")
    with pytest.raises(PolicyViolation, match="no write permission"):
        ReadOnlyInput(writable, "/pack")
    (tmp_path / "link").symlink_to(env.plan.pack.root)
    with pytest.raises(PolicyViolation, match="canonical"):
        ReadOnlyInput(tmp_path / "link", "/pack")
    with pytest.raises(PolicyViolation, match="mount only"):
        ReadOnlyInput(env.plan.pack.root, "/etc")
    comma = tmp_path / "a,b"
    comma.mkdir(mode=0o555)
    with pytest.raises(PolicyViolation):
        ReadOnlyInput(Path(os.path.realpath(comma)), "/pack")


def test_run_operations_are_admitted_only_in_their_fixed_shapes(env: Environment) -> None:
    import dataclasses

    from patchproof.runner.docker_cli import Create, assert_no_forbidden_tokens

    assert RunCreate in ALLOWED_OP_TYPES and StartAttached in ALLOWED_OP_TYPES
    target, _ = specs(env)
    assert_no_forbidden_tokens(RunCreate(target))
    assert_no_forbidden_tokens(StartAttached(ContainerId(TID), timeout_seconds=30, stdout_cap=262145))

    class TamperedCreate(RunCreate):
        def argv_tail(self) -> list[str]:
            argv = run_create_argv_tail(self.spec)
            return argv[:4] + ["--publish", "8080:8080"] + argv[4:]

    with pytest.raises(PolicyViolation):
        assert_no_forbidden_tokens(TamperedCreate(target))

    @dataclasses.dataclass(frozen=True)
    class TamperedStart(StartAttached):
        def argv_tail(self) -> list[str]:
            return ["container", "start", "--attach", "--interactive", "--", self.container.value]

    with pytest.raises(PolicyViolation):
        assert_no_forbidden_tokens(TamperedStart(ContainerId(TID), timeout_seconds=30, stdout_cap=10))
    with pytest.raises(PolicyViolation):
        assert_no_forbidden_tokens(StartAttached(ContainerId(TID), timeout_seconds=0.5, stdout_cap=10))
    # The accepted PP-003 probe create still refuses --mount.
    from patchproof.runner.policy import Role, build_spec

    probe = build_spec(ownership=OWNERSHIP, role=Role.TARGET, image=ImageId("sha256:" + "a" * 64),
                       script="print(1)", args=("probe",))

    class MountedProbe(Create):
        def argv_tail(self) -> list[str]:
            argv = super().argv_tail()
            return argv[:4] + ["--mount", "type=bind,source=/,target=/host,readonly"] + argv[4:]

    with pytest.raises(PolicyViolation, match="forbidden"):
        assert_no_forbidden_tokens(MountedProbe(probe))


def standalone_spec(env: Environment, command: tuple[str, ...] | None = None) -> Any:
    from patchproof.runner.run_policy import collect_command

    plan = env.plan
    return build_run_spec(ownership=OWNERSHIP, pair=1, side="baseline", role=RunRole.STANDALONE,
                          image=plan.verifier_image.image, limits=plan.limits(RunRole.VERIFIER),
                          input_dir=plan.pack.root, command=command or collect_command(plan.test_paths))


def test_standalone_collection_spec_is_the_pp007_collection_plan(env: Environment) -> None:
    from patchproof.packs.collection import collection_plan

    spec = standalone_spec(env)
    pack = validate_pack(PACK_DIR)
    assert ("/usr/local/bin/python3", *spec.command) == collection_plan(pack).argv
    argv = run_create_argv_tail(spec)
    assert argv[argv.index("--network") + 1] == "none"
    assert argv[argv.index("--mount") + 1].endswith("target=/pack,readonly")
    assert spec.name.endswith("-p1-baseline-standalone")
    result = check_run_container(container_inspect(spec, "d" * 64, VERIFIER_ENV), spec, ContainerId("d" * 64),
                                 VERIFIER_ENV, create_argv=argv)
    assert result.passed, result.summary()


def test_standalone_role_refuses_network_target_input_and_other_commands(env: Environment) -> None:
    import dataclasses

    from patchproof.runner.run_policy import ReadOnlyInput, RunContainerSpec

    spec = standalone_spec(env)
    fields = {f.name: getattr(spec, f.name) for f in dataclasses.fields(RunContainerSpec)}
    from patchproof.runner.policy import Network

    with pytest.raises(PolicyViolation, match="no network"):
        RunContainerSpec(**{**fields, "network": Network(ContainerId(TID))})
    with pytest.raises(PolicyViolation, match="only the source snapshot"):
        RunContainerSpec(**{**fields, "input": ReadOnlyInput(env.plan.baseline.source_dir, "/app/source")})
    for command in (("-I", "-B", "-m", "pytest", "--collect-only"),
                    ("-I", "-B", "-m", "patchproof_verifier.launch", "shell"),
                    ("-I", "-B", "-m", "patchproof_verifier.launch", "collect", "--pack", "/pack", "--",
                     "/etc/passwd.py"),
                    ("-I", "-B", "-m", "patchproof_verifier.launch", "run", "--pack", "/pack", "--run",
                     "run-" + "3" * 32, "--pair", "1", "--side", "baseline", "--connect-timeout", "5",
                     "--read-timeout", "5", "--extra", "--", "/pack/tests/test_documents.py"),
                    ("-I", "-B", "-m", "patchproof_verifier.launch", "run", "--pack", "/tmp", "--run",
                     "run-" + "3" * 32, "--pair", "1", "--side", "baseline", "--connect-timeout", "5",
                     "--read-timeout", "5", "--", "/pack/tests/test_documents.py")):
        with pytest.raises(PolicyViolation):
            RunContainerSpec(**{**fields, "command": command})


# ------------------------------------------------------------ inspect gate


def test_gate_passes_the_fixed_policy(env: Environment) -> None:
    target, verifier = specs(env)
    for spec, env_list, cid in ((target, TARGET_ENV, TID), (verifier, VERIFIER_ENV, "d" * 64)):
        result = check_run_container(container_inspect(spec, cid, env_list), spec, ContainerId(cid), env_list,
                                     create_argv=run_create_argv_tail(spec))
        assert result.passed, result.summary()


GATE_TAMPERS: list[tuple[str, Any]] = [
    ("privileged", lambda o: o["HostConfig"].update(Privileged=True)),
    ("caps", lambda o: o["HostConfig"].update(CapDrop=[])),
    ("rootfs", lambda o: o["HostConfig"].update(ReadonlyRootfs=False)),
    ("seccomp", lambda o: o["HostConfig"].update(SecurityOpt=["seccomp=unconfined"])),
    ("bridge", lambda o: o["HostConfig"].update(NetworkMode="bridge")),
    ("ports", lambda o: o["HostConfig"].update(PortBindings={"8080/tcp": [{"HostPort": "8080"}]})),
    ("publish all", lambda o: o["HostConfig"].update(PublishAllPorts=True)),
    ("binds", lambda o: o["HostConfig"].update(Binds=["/:/host"])),
    ("rw mount", lambda o: o["HostConfig"]["Mounts"][0].update(ReadOnly=False)),
    ("rw effective", lambda o: o["Mounts"][0].update(RW=True)),
    ("second mount", lambda o: o["Mounts"].append({"Type": "bind", "Source": "/", "Destination": "/host",
                                                   "RW": False})),
    ("other source", lambda o: o["HostConfig"]["Mounts"][0].update(Source="/Users")),
    ("socket", lambda o: o["HostConfig"]["Mounts"][0].update(Source="/var/run/docker.sock")),
    ("user", lambda o: o["Config"].update(User="0")),
    ("env", lambda o: o["Config"].update(Env=[*o["Config"]["Env"], "PYTHONPATH=/x"])),
    ("cmd", lambda o: o["Config"].update(Cmd=["-c", "import os"])),
    ("memory", lambda o: o["HostConfig"].update(Memory=0)),
    ("pids", lambda o: o["HostConfig"].update(PidsLimit=-1)),
    ("pid host", lambda o: o["HostConfig"].update(PidMode="host")),
    ("logs", lambda o: o["HostConfig"].update(LogConfig={"Type": "json-file", "Config": {}})),
    ("devices", lambda o: o["HostConfig"].update(Devices=[{"PathOnHost": "/dev/kvm"}])),
    ("labels", lambda o: o["Config"].update(Labels={})),
    ("health", lambda o: o["Config"].update(Healthcheck={"Test": ["CMD-SHELL", "curl x"]})),
    ("tty", lambda o: o["Config"].update(OpenStdin=True)),
]


@pytest.mark.parametrize(("label", "tamper"), GATE_TAMPERS, ids=[t[0] for t in GATE_TAMPERS])
def test_gate_refuses_every_deviation(env: Environment, label: str, tamper: Any) -> None:
    target, _ = specs(env)
    obj = container_inspect(target, TID, TARGET_ENV)
    tamper(obj)
    assert not check_run_container(obj, target, ContainerId(TID), TARGET_ENV,
                                   create_argv=run_create_argv_tail(target)).passed


def test_gate_refuses_a_verifier_with_a_health_check_or_a_different_argv(env: Environment) -> None:
    _, verifier = specs(env)
    obj = container_inspect(verifier, "d" * 64, VERIFIER_ENV)
    obj["Config"]["Healthcheck"] = {"Test": ["NONE"]}
    assert not check_run_container(obj, verifier, ContainerId("d" * 64), VERIFIER_ENV,
                                   create_argv=run_create_argv_tail(verifier)).passed
    clean = container_inspect(verifier, "d" * 64, VERIFIER_ENV)
    assert not check_run_container(clean, verifier, ContainerId("d" * 64), VERIFIER_ENV, create_argv=None).passed


# ------------------------------------------------------------ pack snapshot integrity (PP-007 R2)


def copy_pack(tmp: Path) -> Path:
    dest = tmp / "pack"
    shutil.copytree(PACK_DIR, dest)
    return Path(os.path.realpath(dest))


def test_materialized_pack_equals_the_validated_bytes(tmp_path: Path) -> None:
    pack = validate_pack(copy_pack(tmp_path))
    snapshot = materialize_pack(pack, private(tmp_path / "store"))
    assert snapshot.root.name == pack.pack_tree_sha256.removeprefix("sha256:")
    for f in pack.files:
        assert (snapshot.root / f.path).read_bytes() == (pack.root / f.path).read_bytes()
        assert (snapshot.root / f.path).stat().st_mode & 0o777 == 0o444
    assert materialize_pack(pack, private(tmp_path / "store")) == snapshot  # idempotent, re-verified


def test_pack_changed_after_validation_is_not_copied(tmp_path: Path) -> None:
    root = copy_pack(tmp_path)
    pack = validate_pack(root)
    test = root / "tests" / "test_documents.py"
    test.write_text(test.read_text().replace("u-bob", "u-alice", 1))
    store = private(tmp_path / "store")
    with pytest.raises(InputIntegrityError, match="changed after validation"):
        materialize_pack(pack, store)
    assert [p.name for p in store.iterdir()] == []


def test_pack_file_swapped_for_a_symlink_after_validation(tmp_path: Path) -> None:
    root = copy_pack(tmp_path)
    pack = validate_pack(root)
    readme = root / "README.md"
    real = tmp_path / "readme"
    shutil.copy(readme, real)
    readme.unlink()
    readme.symlink_to(real)
    with pytest.raises(InputIntegrityError):
        materialize_pack(pack, private(tmp_path / "store"))


@pytest.mark.parametrize("tamper", ["content", "extra", "missing", "mode", "rename-root"])
def test_tampered_snapshot_fails_verification(tmp_path: Path, tamper: str) -> None:
    pack = validate_pack(copy_pack(tmp_path))
    snapshot = materialize_pack(pack, private(tmp_path / "store"))
    root = snapshot.root
    os.chmod(root, 0o755)
    os.chmod(root / "tests", 0o755)
    if tamper == "content":
        target = root / "tests" / "test_documents.py"
        os.chmod(target, 0o644)
        target.write_text(target.read_text().replace("u-bob", "u-alice", 1))
        os.chmod(target, 0o444)
    elif tamper == "extra":
        (root / "tests" / "test_extra.py").write_text("x = 1\n")
        os.chmod(root / "tests" / "test_extra.py", 0o444)
    elif tamper == "missing":
        os.chmod(root / "README.md", 0o644)
        (root / "README.md").unlink()
    elif tamper == "mode":
        os.chmod(root / "pack.json", 0o644)
    os.chmod(root / "tests", 0o555)
    os.chmod(root, 0o555)
    if tamper == "rename-root":
        os.chmod(root.parent, 0o700)
        moved = root.parent / ("0" * 64)
        os.chmod(root, 0o755)
        os.rename(root, moved)
        os.chmod(moved, 0o555)
        snapshot = PackSnapshot(moved, snapshot.pack_tree_sha256, snapshot.manifest_sha256, snapshot.files)
    with pytest.raises(InputIntegrityError):
        verify_pack_snapshot(snapshot)


def test_source_snapshot_is_reverified(env: Environment, tmp_path: Path) -> None:
    manifest = verify_source_snapshot(env.plan.baseline)
    assert manifest.commit_id == "68b2bc0e41cb7e9a074b09f2d97db3e2d2ca288a"
    copy = tmp_path / "snap"
    shutil.copytree(env.plan.baseline.snapshot_dir, copy)
    for dirpath, _d, _f in os.walk(copy):
        os.chmod(dirpath, 0o755)
    app = copy / "source" / "papertrail" / "authz.py"
    os.chmod(app, 0o644)
    app.write_text("def can_read_document(user, document):\n    return True\n")
    os.chmod(app, 0o444)
    with pytest.raises(InputIntegrityError, match="differs from the source manifest"):
        verify_source_snapshot(SourceSnapshot(Path(os.path.realpath(copy)), env.plan.baseline.manifest_sha256))
    with pytest.raises(InputIntegrityError, match="manifest hash"):
        verify_source_snapshot(SourceSnapshot(env.plan.baseline.snapshot_dir, "sha256:" + "0" * 64))


def test_images_are_identities_not_tags() -> None:
    with pytest.raises(PolicyViolation):
        ImageId("python:3.13-slim")


def test_directly_constructed_spec_cannot_swap_role_inputs(env: Environment) -> None:
    import dataclasses

    from patchproof.runner.run_policy import ReadOnlyInput, RunContainerSpec

    target, verifier = specs(env)
    fields = {f.name: getattr(target, f.name) for f in dataclasses.fields(RunContainerSpec)}
    with pytest.raises(PolicyViolation, match="only the source snapshot"):
        RunContainerSpec(**{**fields, "input": ReadOnlyInput(env.plan.pack.root, "/pack")})
    vfields = {f.name: getattr(verifier, f.name) for f in dataclasses.fields(RunContainerSpec)}
    with pytest.raises(PolicyViolation, match="only the source snapshot"):
        RunContainerSpec(**{**vfields, "input": ReadOnlyInput(env.plan.baseline.source_dir, "/app/source")})


@pytest.mark.parametrize(("role", "image_id"), [
    (RunRole.TARGET, "sha256:e5d1ad51ecfcf50c3f0835e3d801c76d591396474f13179070a32a1233b1b102"),
    (RunRole.VERIFIER, "sha256:e57f61f8f8a8e8757935159dfaaeb1e891f50b0e44dcfe1eece7528377eef972"),
])
def test_gate_b_r1_images_can_never_be_approved_run_images(role: RunRole, image_id: str) -> None:
    from patchproof.runner.run_plan import APPROVED_RUN_IMAGES, ApprovedRunImage
    from patchproof.runner.run_policy import TARGET_HEALTHCHECK

    with pytest.raises(PolicyViolation, match="rejected"):
        ApprovedRunImage(role, ImageId(image_id), TARGET_ENV if role is RunRole.TARGET else VERIFIER_ENV,
                         TARGET_HEALTHCHECK if role is RunRole.TARGET else None)
    assert all(i.image.value != image_id for i in APPROVED_RUN_IMAGES)
