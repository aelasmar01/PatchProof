"""PP-008: the versioned execution profile, its strict loader, and profile/runtime consistency.

Docker-free. Profiles under test are copies in temporary `profiles/` directories; the
repository profile is only read.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

import pytest
from _run_fixtures import OWNERSHIP, Environment, build_environment
from test_schemas import validator_for

from patchproof.core.approvals import canonical_sha256
from patchproof.core.records import load_record
from patchproof.core.records.evidence import SourceManifest
from patchproof.core.records.pack import ExecutionProfileV11
from patchproof.runner import policy
from patchproof.runner.docker_cli import Stop
from patchproof.runner.inputs import InputIntegrityError, verify_source_snapshot
from patchproof.runner.policy import ContainerId, PolicyViolation
from patchproof.runner.profiles import (
    MAX_PROFILE_BYTES,
    PAPERTRAIL_PROFILE_ID,
    PAPERTRAIL_PROFILE_SHA256,
    PAPERTRAIL_PROFILE_VERSION,
    ProfileError,
    load_profile,
    profile_path,
)
from patchproof.runner.run_plan import (
    APPROVED_RUN_IMAGES,
    FIXED_PROFILE_RUNTIME,
    READINESS_SECONDS,
    REJECTED_RUN_IMAGE_IDS,
    RunPlan,
    check_preconditions,
    check_source_scope,
    limits_from_profile,
    runtime_differences,
)
from patchproof.runner.run_policy import (
    TARGET_HEALTHCHECK,
    RunCreate,
    RunRole,
    build_run_spec,
    target_command,
    verifier_command,
)

ROOT = Path(__file__).resolve().parents[2]
REPO_PROFILE = profile_path(ROOT, PAPERTRAIL_PROFILE_ID, PAPERTRAIL_PROFILE_VERSION)
SCHEMA_EXAMPLE = ROOT / "schemas/examples/valid/execution-profile.v1.1--papertrail-reference.json"


def _doc() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(REPO_PROFILE.read_text())
    return data


def _write(tmp: Path, doc: dict[str, Any] | bytes, name: str | None = None) -> Path:
    directory = tmp / "profiles"
    directory.mkdir(exist_ok=True)
    if isinstance(doc, dict):
        name = name or f"{doc['profile_id']}-{doc['profile_version']}.json"
        data = json.dumps(doc, indent=2).encode()
    else:
        data = doc
    path = Path(os.path.realpath(directory)) / (name or "papertrail-reference-1.0.0.json")
    path.write_bytes(data)
    return path


def _set(doc: dict[str, Any], dotted: str, value: Any) -> dict[str, Any]:
    node = doc
    *parents, leaf = dotted.split(".")
    for key in parents:
        node = node[key]
    node[leaf] = value
    return doc


# ------------------------------------------------------------------ the repository profile


def test_repository_profile_loads_with_the_pinned_canonical_hash() -> None:
    loaded = load_profile(REPO_PROFILE, expected_sha256=PAPERTRAIL_PROFILE_SHA256)
    assert loaded.sha256 == PAPERTRAIL_PROFILE_SHA256 == canonical_sha256(loaded.profile)
    assert loaded.profile.profile_id == "papertrail-reference" and loaded.profile.profile_version == "1.0.0"
    target, verifier = APPROVED_RUN_IMAGES
    assert (loaded.profile.target_image_id, loaded.profile.verifier_image_id) == (target.image.value,
                                                                                 verifier.image.value)
    assert loaded.profile.asgi_app == "papertrail.app:app"
    assert loaded.profile.fixture_contract == "synthetic-documents-v1"
    assert loaded.profile.source_scope.include == ["papertrail", "fixtures/synthetic"]
    assert runtime_differences(loaded.profile) == []


def test_repository_profile_matches_the_json_schema_and_the_reference_scope() -> None:
    doc = _doc()
    assert validator_for("execution-profile.v1.1").is_valid(doc)
    ground = json.loads((ROOT / "examples/papertrail/reference-fixture.json").read_text())["target"]
    assert doc["source_scope"] == ground["source_scope"]
    assert (doc["asgi_app"], doc["fixture_contract"], doc["network_policy"]) == (
        ground["asgi_app"], ground["fixture_contract"], ground["network_policy"])


def test_profiles_directory_holds_only_versioned_profiles() -> None:
    names = sorted(p.name for p in (ROOT / "profiles").iterdir())
    assert names == ["papertrail-reference-1.0.0.json"]


def test_hash_is_of_the_model_not_the_file_formatting(tmp_path: Path) -> None:
    compact = _write(tmp_path, json.dumps(_doc(), separators=(",", ":")).encode())
    assert load_profile(compact, expected_sha256=PAPERTRAIL_PROFILE_SHA256).sha256 == PAPERTRAIL_PROFILE_SHA256


# ------------------------------------------------------------------ fail-closed loading


def test_expected_binding_mismatch_is_refused() -> None:
    with pytest.raises(ProfileError, match="differs from the expected binding"):
        load_profile(REPO_PROFILE, expected_sha256="sha256:" + "0" * 64)


def test_changed_profile_contents_change_the_hash_and_are_refused(tmp_path: Path) -> None:
    doc = _set(_doc(), "profile_version", "1.0.1")
    path = _write(tmp_path, doc)
    with pytest.raises(ProfileError, match="differs from the expected binding"):
        load_profile(path, expected_sha256=PAPERTRAIL_PROFILE_SHA256)


def test_collection_example_with_placeholder_images_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path, json.loads(SCHEMA_EXAMPLE.read_text()))
    with pytest.raises(ProfileError, match="placeholder"):
        load_profile(path, expected_sha256=canonical_sha256(
            load_record(ExecutionProfileV11, SCHEMA_EXAMPLE.read_bytes())))


@pytest.mark.parametrize("mutation, message", [
    (lambda d: d.update(privileged=True), "not a valid execution-profile"),
    (lambda d: d.update(schema_version="1.0"), "not a valid execution-profile"),
    (lambda d: d["resources"]["target"].update(network_mode="host"), "not a valid execution-profile"),
    (lambda d: d.update(asgi_app="TODO"), "not a valid|placeholder"),
    (lambda d: d.update(fixture_contract="other-contract-v1"), "unknown fixture contract"),
    (lambda d: d.update(target_image_id=d["verifier_image_id"], verifier_image_id=d["target_image_id"]),
     "not the approved target run image"),
    (lambda d: d.update(verifier_image_id=sorted(REJECTED_RUN_IMAGE_IDS)[0]), "rejected image"),
    (lambda d: d.update(target_image_id="sha256:" + "c" * 64), "placeholder"),
    (lambda d: d.update(target_image_id="sha256:" + "0123456789abcdef" * 4), "not the approved target"),
])
def test_invalid_profiles_are_refused(tmp_path: Path, mutation: Any, message: str) -> None:
    doc = _doc()
    mutation(doc)
    path = _write(tmp_path, json.dumps(doc).encode(), "papertrail-reference-1.0.0.json")
    with pytest.raises(ProfileError, match=message):
        load_profile(path, expected_sha256=PAPERTRAIL_PROFILE_SHA256)


def test_duplicate_keys_are_refused(tmp_path: Path) -> None:
    raw = REPO_PROFILE.read_bytes().replace(b'"profile_id": "papertrail-reference",',
                                            b'"profile_id": "papertrail-reference", "profile_id": "x",', 1)
    path = _write(tmp_path, raw)
    with pytest.raises(ProfileError, match="not a valid"):
        load_profile(path, expected_sha256=PAPERTRAIL_PROFILE_SHA256)


def test_file_name_must_name_the_profile(tmp_path: Path) -> None:
    path = _write(tmp_path, REPO_PROFILE.read_bytes(), "papertrail-reference-9.9.9.json")
    with pytest.raises(ProfileError, match="file name differs"):
        load_profile(path, expected_sha256=PAPERTRAIL_PROFILE_SHA256)


def test_profile_must_live_in_a_profiles_directory(tmp_path: Path) -> None:
    other = Path(os.path.realpath(tmp_path)) / "papertrail-reference-1.0.0.json"
    other.write_bytes(REPO_PROFILE.read_bytes())
    with pytest.raises(ProfileError, match="profiles/"):
        load_profile(other, expected_sha256=PAPERTRAIL_PROFILE_SHA256)


def test_symlinks_are_refused(tmp_path: Path) -> None:
    real = _write(tmp_path, REPO_PROFILE.read_bytes(), "papertrail-reference-1.0.0.json")
    link_dir = Path(os.path.realpath(tmp_path)) / "links" / "profiles"
    link_dir.mkdir(parents=True)
    link = link_dir / "papertrail-reference-1.0.0.json"
    link.symlink_to(real)
    with pytest.raises(ProfileError, match="canonical"):
        load_profile(link, expected_sha256=PAPERTRAIL_PROFILE_SHA256)
    dir_link = Path(os.path.realpath(tmp_path)) / "alias"
    dir_link.symlink_to(real.parent.parent)
    with pytest.raises(ProfileError, match="canonical"):
        load_profile(dir_link / "profiles" / real.name, expected_sha256=PAPERTRAIL_PROFILE_SHA256)


def test_special_and_missing_files_are_refused(tmp_path: Path) -> None:
    directory = Path(os.path.realpath(tmp_path)) / "profiles"
    directory.mkdir()
    fifo = directory / "papertrail-reference-1.0.0.json"
    os.mkfifo(fifo)
    with pytest.raises(ProfileError, match="not a regular file"):
        load_profile(fifo, expected_sha256=PAPERTRAIL_PROFILE_SHA256)
    with pytest.raises(ProfileError, match="missing"):
        load_profile(directory / "papertrail-reference-2.0.0.json", expected_sha256=PAPERTRAIL_PROFILE_SHA256)


def test_oversized_profiles_are_refused(tmp_path: Path) -> None:
    path = _write(tmp_path, REPO_PROFILE.read_bytes() + b" " * MAX_PROFILE_BYTES)
    with pytest.raises(ProfileError, match="size limit"):
        load_profile(path, expected_sha256=PAPERTRAIL_PROFILE_SHA256)


def test_loading_never_writes(tmp_path: Path) -> None:
    path = _write(tmp_path, REPO_PROFILE.read_bytes())
    before = (path.read_bytes(), os.stat(path).st_mtime_ns, sorted(os.listdir(path.parent)))
    load_profile(path, expected_sha256=PAPERTRAIL_PROFILE_SHA256)
    assert (path.read_bytes(), os.stat(path).st_mtime_ns, sorted(os.listdir(path.parent))) == before


# ------------------------------------------------------------------ profile/runtime consistency

RUNTIME_MUTATIONS = [
    ("logging.max_file_bytes", 4 * 1024 * 1024),
    ("logging.max_files", 1),
    ("timeouts.cancellation_grace_seconds", 10),
    ("timeouts.readiness_seconds", 29),
    ("timeouts.request_connect_seconds", 2),
    ("timeouts.request_read_seconds", 10),
    ("timeouts.revision_deadline_seconds", 120),
    ("result_cap_bytes", 1048576),
    ("resources.target.cpus", 0.5),
    ("resources.target.memory_bytes", 536870912),
    ("resources.target.pids", 64),
    ("resources.target.scratch_tmpfs_bytes", 134217728),
    ("resources.target.tmp_tmpfs_bytes", 33554432),
    ("resources.verifier.cpus", 0.5),
    ("resources.verifier.memory_bytes", 268435456),
    ("resources.verifier.pids", 64),
    ("resources.verifier.scratch_tmpfs_bytes", 67108864),
    ("resources.verifier.tmp_tmpfs_bytes", 8388608),
]


@pytest.mark.parametrize("field, value", RUNTIME_MUTATIONS)
def test_values_that_differ_from_the_enforced_policy_are_refused(tmp_path: Path, field: str, value: Any) -> None:
    """Stricter values are refused too: the profile must describe what actually runs."""
    doc = _set(_doc(), field, value)
    profile = load_record(ExecutionProfileV11, json.dumps(doc).encode())
    assert runtime_differences(profile) == [field]
    path = _write(tmp_path, doc)
    with pytest.raises(ProfileError, match=re.escape(field)):
        load_profile(path, expected_sha256=canonical_sha256(profile))


def test_fixed_runtime_values_are_the_enforced_constants() -> None:
    timeouts: Any = FIXED_PROFILE_RUNTIME["timeouts"]
    logging: Any = FIXED_PROFILE_RUNTIME["logging"]
    # Docker's local log driver reads max-size "5m" as 5 MiB.
    size = re.fullmatch(r"(\d+)m", policy.LOG_MAX_SIZE)
    assert size is not None and int(size.group(1)) * 1024 * 1024 == policy.LOG_MAX_SIZE_BYTES
    assert logging == {"max_file_bytes": policy.LOG_MAX_SIZE_BYTES, "max_files": policy.LOG_MAX_FILE}
    assert timeouts["cancellation_grace_seconds"] == policy.STOP_GRACE_SECONDS
    assert Stop(ContainerId("f" * 64)).argv_tail()[2:4] == ["--time", str(policy.STOP_GRACE_SECONDS)]
    assert READINESS_SECONDS * 1_000_000_000 == TARGET_HEALTHCHECK["StartPeriod"]
    assert timeouts["revision_deadline_seconds"] == policy.CEILINGS[policy.LimitClass.TARGET].deadline_seconds
    assert FIXED_PROFILE_RUNTIME["network_policy"] == policy.NETWORK_POLICY_VALUE


def test_the_profile_values_reach_the_container_argv(tmp_path: Path) -> None:
    profile = load_profile(REPO_PROFILE, expected_sha256=PAPERTRAIL_PROFILE_SHA256).profile
    source = Path(os.path.realpath(tmp_path)) / "src"
    source.mkdir(mode=0o555)
    target_id = ContainerId("e" * 64)
    for role, block, network in ((RunRole.TARGET, profile.resources.target, "none"),
                                 (RunRole.VERIFIER, profile.resources.verifier, f"container:{target_id.value}")):
        limits = limits_from_profile(profile, role)
        assert limits.deadline_seconds == profile.timeouts.revision_deadline_seconds
        mount = "/app/source" if role is RunRole.TARGET else "/pack"
        command = target_command(profile.asgi_app) if role is RunRole.TARGET else verifier_command(
            run_id=OWNERSHIP.run_id, pair=1, side="baseline", test_paths=("/pack/tests/test_documents.py",),
            connect_timeout=profile.timeouts.request_connect_seconds,
            read_timeout=profile.timeouts.request_read_seconds)
        spec = build_run_spec(ownership=OWNERSHIP, pair=1, side="baseline", role=role,
                              image=policy.ImageId(profile.target_image_id if role is RunRole.TARGET
                                                   else profile.verifier_image_id),
                              limits=limits, input_dir=source, command=command,
                              join_target=target_id if role is RunRole.VERIFIER else None)
        assert spec.input.destination == mount
        argv = RunCreate(spec).argv_tail()

        def value(flag: str, argv: list[str] = argv) -> str:
            return argv[argv.index(flag) + 1]

        assert value("--network") == network
        assert value("--cpus") == f"{block.cpus:g}"
        assert value("--memory") == value("--memory-swap") == str(block.memory_bytes)
        assert value("--pids-limit") == str(block.pids)
        assert f"/scratch:rw,noexec,nosuid,nodev,size={block.scratch_tmpfs_bytes},mode=1777" in argv
        assert f"/tmp:rw,noexec,nosuid,nodev,size={block.tmp_tmpfs_bytes},mode=1777" in argv
        assert "max-size=5m" in argv and "max-file=2" in argv
        assert value("--stop-timeout") == str(profile.timeouts.cancellation_grace_seconds)
        if role is RunRole.VERIFIER:
            assert value("--connect-timeout") == "5" and value("--read-timeout") == "5"


def test_deadlines_above_the_ceiling_are_refused_not_clamped() -> None:
    profile = load_profile(REPO_PROFILE, expected_sha256=PAPERTRAIL_PROFILE_SHA256).profile
    longer = profile.model_copy(update={"timeouts": profile.timeouts.model_copy(
        update={"revision_deadline_seconds": 300})})
    with pytest.raises(PolicyViolation, match="deadline_seconds=300"):
        limits_from_profile(longer, RunRole.TARGET)


# ------------------------------------------------------------------ source scope


@pytest.fixture(scope="module")
def env(tmp_path_factory: pytest.TempPathFactory) -> Environment:
    return build_environment(tmp_path_factory.mktemp("profiles"))


def test_snapshot_scope_must_equal_the_profile_scope(env: Environment) -> None:
    manifest: SourceManifest = verify_source_snapshot(env.plan.baseline)
    assert manifest.inclusion_profile.include == sorted(env.plan.profile.source_scope.include)
    check_source_scope(env.plan.profile, manifest)
    narrower = env.plan.profile.model_copy(update={"source_scope": env.plan.profile.source_scope.model_copy(
        update={"include": ["papertrail"]})})
    with pytest.raises(InputIntegrityError, match="source_scope"):
        check_source_scope(narrower, manifest)


def test_a_different_source_scope_fails_source_identity(env: Environment) -> None:
    profile = env.plan.profile.model_copy(update={"source_scope": env.plan.profile.source_scope.model_copy(
        update={"include": ["papertrail"]})})
    plan = RunPlan(**{**env.plan.__dict__, "profile": profile})
    result = check_preconditions(plan, env.approvals, (plan.target_image, plan.verifier_image))
    assert result["source_identity"].state == "FAILED"
    assert result["source_identity"].reason_codes == ["SOURCE_IDENTITY_MISMATCH"]
    assert result["authorization"].reason_codes == ["APPROVAL_STALE"]  # the profile hash changed too


def test_plans_refuse_profiles_inconsistent_with_the_runtime(env: Environment) -> None:
    for field, value in RUNTIME_MUTATIONS:
        doc = _set(env.plan.profile.model_dump(mode="json"), field, value)
        profile = load_record(ExecutionProfileV11, json.dumps(doc).encode())
        with pytest.raises(PolicyViolation, match=re.escape(field)):
            RunPlan(**{**env.plan.__dict__, "profile": profile})
