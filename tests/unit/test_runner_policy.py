"""PP-003 / ADR-009: the fixed container policy refuses anything it does not represent."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

import pytest
from _fakes import IMAGE, OWNERSHIP

from patchproof.runner import policy as pol
from patchproof.runner.policy import (
    CEILINGS,
    ContainerId,
    ImageId,
    LimitClass,
    Ownership,
    PolicyViolation,
    ResourceLimits,
    Role,
    build_spec,
    check_limits,
    check_profile_document,
)

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "schemas" / "examples"
SCRIPT = "print('probe')"
NONCE = "c" * 32


def spec(role: Role = Role.TARGET, **kw: Any) -> pol.ContainerSpec:
    defaults: dict[str, Any] = {"ownership": OWNERSHIP, "role": role, "image": IMAGE, "script": SCRIPT,
                                "args": (role.value if not role.is_decoy else "sleeper", NONCE)}
    if role is Role.VERIFIER:
        defaults["join_target"] = ContainerId("f" * 64)
    defaults.update(kw)
    return build_spec(**defaults)


# ------------------------------------------------------------------- identities


@pytest.mark.parametrize("ref", [
    "python:latest", "python:3.13-slim", "python", "python@sha256:" + "a" * 64, "docker.io/library/python:3.13",
    "sha256:" + "a" * 63, "sha256:" + "A" * 64, "a" * 64, "sha256:" + "a" * 64 + "\n", " sha256:" + "a" * 64,
    "--privileged", "", "sha512:" + "a" * 128,
])
def test_floating_or_malformed_image_references_refused(ref: str) -> None:
    with pytest.raises(PolicyViolation):
        ImageId(ref)


def test_full_image_id_accepted() -> None:
    assert ImageId("sha256:" + "0123456789abcdef" * 4).value.startswith("sha256:")


@pytest.mark.parametrize("cid", ["abc", "F" * 64, "f" * 63, "--all", "f" * 64 + " "])
def test_container_id_must_be_full_hex(cid: str) -> None:
    with pytest.raises(PolicyViolation):
        ContainerId(cid)


@pytest.mark.parametrize("inst,run", [("inst-x", "run-" + "a" * 32), ("inst-" + "a" * 32, "run-1"),
                                      ("../etc", "run-" + "a" * 32)])
def test_ownership_identities_validated(inst: str, run: str) -> None:
    with pytest.raises(PolicyViolation):
        Ownership(installation_id=inst, run_id=run)


# ------------------------------------------------------------------- limits and ceilings


@pytest.mark.parametrize("limit_class", list(LimitClass))
def test_ceilings_themselves_are_accepted(limit_class: LimitClass) -> None:
    check_limits(CEILINGS[limit_class], limit_class)


@pytest.mark.parametrize("limit_class", list(LimitClass))
@pytest.mark.parametrize("field", [f.name for f in dataclasses.fields(ResourceLimits)])
def test_every_limit_above_its_ceiling_is_refused(limit_class: LimitClass, field: str) -> None:
    ceiling = CEILINGS[limit_class]
    over = dataclasses.replace(ceiling, **{field: getattr(ceiling, field) * 2})
    with pytest.raises(PolicyViolation, match="exceeds"):
        check_limits(over, limit_class)


@pytest.mark.parametrize("field", [f.name for f in dataclasses.fields(ResourceLimits)])
@pytest.mark.parametrize("value", [0, -1])
def test_zero_or_negative_limits_refused(field: str, value: int) -> None:
    bad = dataclasses.replace(CEILINGS[LimitClass.TARGET], **{field: value})
    with pytest.raises(PolicyViolation):
        check_limits(bad, LimitClass.TARGET)


def test_non_integer_limits_refused() -> None:
    bad = dataclasses.replace(CEILINGS[LimitClass.TARGET], memory_bytes=True)
    with pytest.raises(PolicyViolation):
        check_limits(bad, LimitClass.TARGET)
    with pytest.raises(PolicyViolation):
        check_limits(dataclasses.replace(CEILINGS[LimitClass.TARGET], pids=64.0), LimitClass.TARGET)  # type: ignore[arg-type]


def test_verifier_writable_storage_totals_128_mib() -> None:
    v = CEILINGS[LimitClass.VERIFIER]
    assert (v.scratch_bytes, v.tmp_bytes) == (112 * pol.MIB, 16 * pol.MIB)
    assert pol.WRITABLE_CEILINGS[LimitClass.VERIFIER] == 128 * pol.MIB
    assert v.scratch_bytes + v.tmp_bytes == pol.WRITABLE_CEILINGS[LimitClass.VERIFIER]
    assert spec(Role.VERIFIER).tmpfs() == {
        "/scratch": "rw,noexec,nosuid,nodev,size=117440512,mode=1777",
        "/tmp": "rw,noexec,nosuid,nodev,size=16777216,mode=1777",
    }


def test_combined_writable_ceiling_is_enforced_independently(monkeypatch: pytest.MonkeyPatch) -> None:
    loose = dict(CEILINGS)
    loose[LimitClass.VERIFIER] = dataclasses.replace(CEILINGS[LimitClass.VERIFIER], scratch_bytes=256 * pol.MIB)
    monkeypatch.setattr(pol, "CEILINGS", loose)
    over = dataclasses.replace(CEILINGS[LimitClass.VERIFIER], scratch_bytes=120 * pol.MIB)
    with pytest.raises(PolicyViolation, match="combined writable"):
        check_limits(over, LimitClass.VERIFIER)


def test_profile_contract_1_1_uses_explicit_tmpfs_sizes() -> None:
    doc = load("execution-profile.v1.1--papertrail-reference.json")
    assert doc["schema_version"] == "1.1"
    v = doc["resources"]["verifier"]
    assert (v["scratch_tmpfs_bytes"], v["tmp_tmpfs_bytes"]) == (112 * pol.MIB, 16 * pol.MIB)
    check_profile_document(doc)


def test_legacy_1_0_profile_is_refused_not_reinterpreted() -> None:
    legacy = load("execution-profile--papertrail-reference.json")  # historical 1.0 record, still valid as 1.0
    assert legacy["schema_version"] == "1.0"
    with pytest.raises(PolicyViolation, match="never reinterpreted"):
        check_profile_document(legacy)
    upgraded_without_tmp = load("execution-profile.v1.1--papertrail-reference.json")
    del upgraded_without_tmp["resources"]["verifier"]["tmp_tmpfs_bytes"]
    with pytest.raises(PolicyViolation):
        check_profile_document(upgraded_without_tmp)


@pytest.mark.parametrize("side,scratch,tmp", [
    ("verifier", 128 * pol.MIB, 16 * pol.MIB),   # the old reading: 128 MiB scratch + /tmp = 144 MiB
    ("verifier", 112 * pol.MIB, 32 * pol.MIB),   # /tmp above its ceiling
    ("target", 256 * pol.MIB, 128 * pol.MIB),
])
def test_profile_scratch_budget_violations_refused(side: str, scratch: int, tmp: int) -> None:
    doc = load("execution-profile.v1.1--papertrail-reference.json")
    doc["resources"][side].update(scratch_tmpfs_bytes=scratch, tmp_tmpfs_bytes=tmp)
    with pytest.raises(PolicyViolation):
        check_profile_document(doc)


def test_shm_is_fixed_and_outside_the_scratch_budget() -> None:
    from patchproof.runner.docker_cli import create_argv_tail

    argv = create_argv_tail(spec(Role.VERIFIER))
    assert argv[argv.index("--shm-size") + 1] == str(16 * pol.MIB)
    assert pol.SHM_SIZE_BYTES not in (pol.WRITABLE_CEILINGS[LimitClass.VERIFIER],)
    assert "shm" not in {f.name for f in dataclasses.fields(ResourceLimits)}


def test_verifier_cannot_take_target_sized_limits() -> None:
    with pytest.raises(PolicyViolation, match="verifier ceiling"):
        spec(Role.VERIFIER, limits=CEILINGS[LimitClass.TARGET])


def test_stricter_limits_are_allowed() -> None:
    stricter = dataclasses.replace(CEILINGS[LimitClass.TARGET], memory_bytes=256 * pol.MIB)
    assert spec(limits=stricter).limits.memory_bytes == 256 * pol.MIB


def test_cpus_argument_rendering() -> None:
    assert dataclasses.replace(CEILINGS[LimitClass.TARGET], nano_cpus=1_000_000_000).cpus_arg == "1"
    assert dataclasses.replace(CEILINGS[LimitClass.TARGET], nano_cpus=500_000_000).cpus_arg == "0.5"
    assert dataclasses.replace(CEILINGS[LimitClass.TARGET], nano_cpus=250_000_000).cpus_arg == "0.25"


# ------------------------------------------------------------------- topology and command shape


def test_spec_has_no_field_for_security_options() -> None:
    fields = {f.name for f in dataclasses.fields(pol.ContainerSpec)}
    assert fields == {"name", "role", "image", "network", "limits", "labels", "script", "args"}
    network_fields = {f.name for f in dataclasses.fields(pol.Network)}
    assert network_fields == {"join_target"}


def test_only_verifier_joins_and_must_join() -> None:
    with pytest.raises(PolicyViolation, match="verifier must join"):
        build_spec(ownership=OWNERSHIP, role=Role.VERIFIER, image=IMAGE, script=SCRIPT, args=("verifier", NONCE))
    for role in (Role.TARGET, Role.MEMORY, Role.DECOY_FOREIGN):
        with pytest.raises(PolicyViolation, match="only the verifier"):
            spec(role, join_target=ContainerId("f" * 64))
    assert spec(Role.VERIFIER).network.mode == "container:" + "f" * 64
    assert spec(Role.TARGET).network.mode == "none"


@pytest.mark.parametrize("args", [
    ("--privileged",), ("-v",), ("target", "--network=host"), ("a b",), ("Target",), ("x;rm",), ("$(id)",),
    (), ("a", "b", "c", "d", "e"), ("target", "../../etc"),
])
def test_probe_arguments_cannot_carry_options_or_shell(args: tuple[str, ...]) -> None:
    with pytest.raises(PolicyViolation):
        spec(args=args)


def test_script_bounds() -> None:
    with pytest.raises(PolicyViolation):
        spec(script="")
    with pytest.raises(PolicyViolation):
        spec(script="print(1)\x00")
    with pytest.raises(PolicyViolation):
        spec(script="#" * (pol.MAX_SCRIPT_BYTES + 1))


def test_command_is_fixed_interpreter_flags_then_script_then_tokens() -> None:
    s = spec()
    assert s.command == ("-I", "-S", "-B", "-c", SCRIPT, "target", NONCE)


# ------------------------------------------------------------------- labels and names


def test_owned_container_labels() -> None:
    labels = spec().label_map
    assert labels[pol.LABEL_OWNER] == "patchproof"
    assert labels[pol.LABEL_INSTALLATION] == OWNERSHIP.installation_id
    assert labels[pol.LABEL_RUN] == OWNERSHIP.run_id
    assert labels[pol.LABEL_ROLE] == "target"


def test_decoy_labels() -> None:
    other = spec(Role.DECOY_OTHER_RUN).label_map
    assert other[pol.LABEL_RUN] != OWNERSHIP.run_id and other[pol.LABEL_DECOY_OF] == OWNERSHIP.run_id
    foreign = spec(Role.DECOY_FOREIGN).label_map
    assert foreign == {pol.LABEL_DECOY_OF: OWNERSHIP.run_id}


def test_labels_and_names_validated() -> None:
    good = spec()
    with pytest.raises(PolicyViolation):
        dataclasses.replace(good, labels=(*good.labels, ("com.example.x", "1")))
    with pytest.raises(PolicyViolation):
        dataclasses.replace(good, labels=tuple((k, "a b") if k == pol.LABEL_ROLE else (k, v) for k, v in good.labels))
    with pytest.raises(PolicyViolation):
        dataclasses.replace(good, labels=tuple((k, v) for k, v in good.labels if k != pol.LABEL_RUN))
    with pytest.raises(PolicyViolation):
        dataclasses.replace(good, name="unrelated_db")
    with pytest.raises(PolicyViolation):
        dataclasses.replace(good, name="pp-probe-000000000000-target --privileged")


# ------------------------------------------------------------------- profile documents


def load(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(next(EXAMPLES.glob(f"*/{name}")).read_text())
    return data


def test_reviewed_profile_example_accepted() -> None:
    check_profile_document(load("execution-profile.v1.1--papertrail-reference.json"))


@pytest.mark.parametrize("name", [
    "execution-profile.v1.1--privileged-flag.json", "execution-profile.v1.1--docker-args.json",
    "execution-profile.v1.1--bridge-network.json", "execution-profile.v1.1--floating-image-tag.json",
    "execution-profile.v1.1--missing-memory-limit.json", "execution-profile.v1.1--missing-tmp-size.json",
    "execution-profile.v1.1--v1-0-record.json",
])
def test_rejected_profile_examples_refused_by_code(name: str) -> None:
    with pytest.raises(PolicyViolation):
        check_profile_document(load(name))


@pytest.mark.parametrize("mutation", [
    lambda d: d["resources"]["target"].__setitem__("memory_bytes", 2 * pol.GIB),
    lambda d: d["resources"]["verifier"].__setitem__("memory_bytes", pol.GIB),
    lambda d: d["resources"]["target"].__setitem__("cpus", 4),
    lambda d: d["resources"]["target"].__setitem__("pids", 100000),
    lambda d: d["resources"]["verifier"].__setitem__("scratch_tmpfs_bytes", 512 * pol.MIB),
    lambda d: d["resources"]["target"].__setitem__("cpus", True),
    lambda d: d["resources"]["target"].__setitem__("mounts", ["/:/host"]),
    lambda d: d["logging"].__setitem__("max_file_bytes", 50 * pol.MIB),
    lambda d: d["logging"].__setitem__("max_files", 5),
    lambda d: d.pop("logging"),
    lambda d: d.__setitem__("devices", ["/dev/kvm"]),
    lambda d: d.__setitem__("user", "0:0"),
])
def test_profile_limit_and_field_violations_refused(mutation: Any) -> None:
    doc = load("execution-profile.v1.1--papertrail-reference.json")
    mutation(doc)
    with pytest.raises(PolicyViolation):
        check_profile_document(doc)
