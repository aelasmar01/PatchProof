"""Fixed container security policy (PROJECT_SPEC.md 5.2, 10.1, 10.2; ADR-009).

Every security-relevant container setting is a constant here. The only inputs a caller
controls are typed, validated values: an image ID, the container role, resource limits
that must sit at or below a code-level ceiling, and a probe command whose shape is
fixed. There is deliberately no way to pass a mount, capability, security option,
network name, environment variable, device, or raw Docker argument.

Nothing in this module contacts Docker.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Final

# --- Fixed policy constants ------------------------------------------------------------

DOCKER_CONTEXT: Final = "desktop-linux"
CONTAINER_UID: Final = 10001
CONTAINER_GID: Final = 10001
CONTAINER_USER: Final = f"{CONTAINER_UID}:{CONTAINER_GID}"
ENTRYPOINT: Final = "/usr/local/bin/python3"
PYTHON_FLAGS: Final = ("-I", "-S", "-B")
WORKDIR: Final = "/scratch"
TMPFS_OPTIONS: Final = "rw,noexec,nosuid,nodev"
TMPFS_MODE: Final = "1777"
LOG_DRIVER: Final = "local"
LOG_MAX_SIZE: Final = "5m"
LOG_MAX_SIZE_BYTES: Final = 5 * 1024 * 1024
LOG_MAX_FILE: Final = 2
LOG_COMPRESS: Final = "false"
STOP_GRACE_SECONDS: Final = 5
# /dev/shm: with --ipc private Docker mounts a private, world-writable tmpfs sized by
# ShmSize (default 64 MiB). Fixed small bound, separate from the application scratch budget.
SHM_SIZE_BYTES: Final = 16 * 1024 * 1024
# Writable filesystems the container's user may legitimately write to (FS-10).
ALLOWED_WRITABLE_MOUNTS: Final = frozenset({"/scratch", "/tmp", "/dev/shm", "/dev/mqueue"})
SECURITY_OPTS: Final = ("no-new-privileges=true",)
IPC_MODE: Final = "private"
CGROUPNS_MODE: Final = "private"
RESTART_POLICY: Final = "no"
EXPECTED_RUNTIME: Final = "runc"
TARGET_LOOPBACK_HOST: Final = "127.0.0.1"
TARGET_LOOPBACK_PORT: Final = 8080

LABEL_PREFIX: Final = "io.patchproof."
LABEL_OWNER: Final = "io.patchproof.owner"
LABEL_INSTALLATION: Final = "io.patchproof.installation"
LABEL_RUN: Final = "io.patchproof.run"
LABEL_ROLE: Final = "io.patchproof.role"
LABEL_PURPOSE: Final = "io.patchproof.purpose"
LABEL_SCRIPT: Final = "io.patchproof.script-sha256"
LABEL_DECOY_OF: Final = "io.patchproof.decoy-of"
OWNER_VALUE: Final = "patchproof"
PURPOSE_VALUE: Final = "isolation-probe"

MAX_SCRIPT_BYTES: Final = 96 * 1024  # below Linux MAX_ARG_STRLEN (128 KiB)

MIB: Final = 1024 * 1024
GIB: Final = 1024 * MIB
NANO_CPUS_PER_CPU: Final = 1_000_000_000

# A2 gate. The probe image identity is review-controlled code, not configuration.
# Owner-approved 2026-10-11 (A2): python:3.13-slim, linux/amd64, pulled in A1. Under the
# containerd image store this local ID is the digest of the OCI image index; RepoDigest
# python@<same digest>. Changing it requires a new owner review.
APPROVED_PROBE_IMAGE_ID: Final[str | None] = (
    "sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f"
)
APPROVED_PROBE_PLATFORM: Final = "linux/amd64"

IMAGE_ID_RE: Final = re.compile(r"^sha256:[0-9a-f]{64}$")
CONTAINER_ID_RE: Final = re.compile(r"^[0-9a-f]{64}$")
RUN_ID_RE: Final = re.compile(r"^run-[0-9a-f]{32}$")
INSTALLATION_ID_RE: Final = re.compile(r"^inst-[0-9a-f]{32}$")
CONTAINER_NAME_RE: Final = re.compile(r"^pp-(probe|decoy)-[0-9a-f]{12}-[a-z][a-z0-9-]{0,23}$")
COMMAND_ARG_RE: Final = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
LABEL_VALUE_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._-]{0,127}$")


class PolicyViolation(ValueError):
    """A request would weaken or step outside the fixed policy. Raised before Docker is called."""


# --- Typed identities ------------------------------------------------------------------


@dataclass(frozen=True)
class ImageId:
    """Full local image content ID. Tags, repository names, and short IDs are rejected."""

    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or not IMAGE_ID_RE.fullmatch(self.value):
            raise PolicyViolation(
                "image reference must be a full 'sha256:<64 hex>' image ID; "
                "tags, repository names, digests-by-name, and short IDs are not identities"
            )


@dataclass(frozen=True)
class ContainerId:
    """Full 64-hex container ID as returned by `docker create`."""

    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or not CONTAINER_ID_RE.fullmatch(self.value):
            raise PolicyViolation("container ID must be the full 64-hex ID")


@dataclass(frozen=True)
class Ownership:
    """Installation and run identity stamped on every owned container (10.6)."""

    installation_id: str
    run_id: str

    def __post_init__(self) -> None:
        if not INSTALLATION_ID_RE.fullmatch(self.installation_id):
            raise PolicyViolation("installation ID must match inst-<32 hex>")
        if not RUN_ID_RE.fullmatch(self.run_id):
            raise PolicyViolation("run ID must match run-<32 hex>")

    @property
    def short(self) -> str:
        return self.run_id[4:16]


class Role(str, Enum):
    """Probe container roles. The role fixes the network topology and the limit class."""

    TARGET = "target"
    VERIFIER = "verifier"
    MEMORY = "memory"
    PIDS = "pids"
    CPU = "cpu"
    STORAGE = "storage"
    LOGFLOOD = "logflood"
    SLEEPER = "sleeper"
    DECOY_OTHER_RUN = "decoy-other-run"
    DECOY_FOREIGN = "decoy-foreign"

    @property
    def is_decoy(self) -> bool:
        return self in (Role.DECOY_OTHER_RUN, Role.DECOY_FOREIGN)

    @property
    def limit_class(self) -> LimitClass:
        return LimitClass.VERIFIER if self is Role.VERIFIER else LimitClass.TARGET


class LimitClass(str, Enum):
    TARGET = "target"
    VERIFIER = "verifier"


# --- Resource limits and code-level ceilings (ADR-009 owner condition) -----------------


@dataclass(frozen=True)
class ResourceLimits:
    nano_cpus: int
    memory_bytes: int
    pids: int
    scratch_bytes: int
    tmp_bytes: int
    deadline_seconds: int

    @property
    def cpus_arg(self) -> str:
        whole, frac = divmod(self.nano_cpus, NANO_CPUS_PER_CPU)
        if frac == 0:
            return str(whole)
        return f"{whole}.{frac:09d}".rstrip("0")


# §5.2 design envelope. These are ceilings: a request may be stricter, never looser.
CEILINGS: Final[Mapping[LimitClass, ResourceLimits]] = {
    LimitClass.TARGET: ResourceLimits(
        nano_cpus=1 * NANO_CPUS_PER_CPU,
        memory_bytes=1 * GIB,
        pids=128,
        scratch_bytes=256 * MIB,
        tmp_bytes=64 * MIB,
        deadline_seconds=180,
    ),
    LimitClass.VERIFIER: ResourceLimits(
        nano_cpus=1 * NANO_CPUS_PER_CPU,
        memory_bytes=512 * MIB,
        pids=128,
        scratch_bytes=112 * MIB,
        tmp_bytes=16 * MIB,
        deadline_seconds=180,
    ),
}

# Application scratch budget (/scratch + /tmp) per container. §5.2: verifier 128 MiB in total
# (owner decision 2026-10-11: 112 MiB /scratch + 16 MiB /tmp); target 256 MiB scratch plus a
# separate bounded 64 MiB /tmp. This budget does NOT cover /dev/shm (SHM_SIZE_BYTES below),
# /dev/mqueue (kernel RLIMIT_MSGQUEUE), or total memory.
WRITABLE_CEILINGS: Final[Mapping[LimitClass, int]] = {
    LimitClass.TARGET: 320 * MIB,
    LimitClass.VERIFIER: 128 * MIB,
}

# Lower bounds: a zero or negative value would mean "unlimited" to Docker for some flags.
FLOORS: Final = ResourceLimits(
    nano_cpus=10_000_000,
    memory_bytes=64 * MIB,
    pids=16,
    scratch_bytes=1 * MIB,
    tmp_bytes=1 * MIB,
    deadline_seconds=1,
)


def check_limits(limits: ResourceLimits, limit_class: LimitClass) -> None:
    """Refuse limits above the code-level ceiling or below the floor."""
    ceiling = CEILINGS[limit_class]
    for name in ResourceLimits.__dataclass_fields__:
        value = getattr(limits, name)
        if type(value) is not int:
            raise PolicyViolation(f"{name} must be an integer")
        if value < getattr(FLOORS, name):
            raise PolicyViolation(f"{name}={value} is below the minimum {getattr(FLOORS, name)}")
        if value > getattr(ceiling, name):
            raise PolicyViolation(
                f"{name}={value} exceeds the {limit_class.value} ceiling {getattr(ceiling, name)}"
            )
    if limits.nano_cpus % 10_000_000:
        raise PolicyViolation("nano_cpus must be a multiple of 0.01 CPU")
    writable = limits.scratch_bytes + limits.tmp_bytes
    if writable > WRITABLE_CEILINGS[limit_class]:
        raise PolicyViolation(
            f"combined writable tmpfs {writable} exceeds the {limit_class.value} ceiling "
            f"{WRITABLE_CEILINGS[limit_class]}"
        )


# --- Network topology (10.1) -----------------------------------------------------------


@dataclass(frozen=True)
class Network:
    """Only two topologies are representable: no network, or joining one exact target."""

    join_target: ContainerId | None = None

    @property
    def mode(self) -> str:
        if self.join_target is None:
            return "none"
        return f"container:{self.join_target.value}"


NO_NETWORK: Final = Network()


# --- Container specification ------------------------------------------------------------


def script_sha256(script: str) -> str:
    return "sha256:" + hashlib.sha256(script.encode("utf-8")).hexdigest()


def ownership_labels(ownership: Ownership, role: Role, script: str) -> dict[str, str]:
    if role is Role.DECOY_FOREIGN:
        # A container PatchProof's ownership check must treat as not-ours. It carries
        # only a decoy marker so its separately logged teardown can identify it.
        return {LABEL_DECOY_OF: ownership.run_id}
    labels = {
        LABEL_OWNER: OWNER_VALUE,
        LABEL_INSTALLATION: ownership.installation_id,
        LABEL_RUN: ownership.run_id,
        LABEL_ROLE: role.value,
        LABEL_PURPOSE: PURPOSE_VALUE,
        LABEL_SCRIPT: script_sha256(script),
    }
    if role is Role.DECOY_OTHER_RUN:
        # Same installation, deliberately different run: cleanup for this run must refuse it.
        decoy_run = "run-" + hashlib.sha256(ownership.run_id.encode()).hexdigest()[:32]
        labels[LABEL_RUN] = decoy_run
        labels[LABEL_DECOY_OF] = ownership.run_id
    return labels


def container_name(ownership: Ownership, role: Role) -> str:
    kind = "decoy" if role.is_decoy else "probe"
    return f"pp-{kind}-{ownership.short}-{role.value}"


@dataclass(frozen=True)
class ContainerSpec:
    """A fully validated request for one probe container."""

    name: str
    role: Role
    image: ImageId
    network: Network
    limits: ResourceLimits
    labels: tuple[tuple[str, str], ...]
    script: str
    args: tuple[str, ...]

    def __post_init__(self) -> None:
        if not CONTAINER_NAME_RE.fullmatch(self.name):
            raise PolicyViolation("container name is outside the PatchProof naming scheme")
        check_limits(self.limits, self.role.limit_class)
        if self.role is Role.VERIFIER:
            if self.network.join_target is None:
                raise PolicyViolation("the verifier must join the exact target's namespace")
        elif self.network.join_target is not None:
            raise PolicyViolation("only the verifier may join another container's namespace")
        if not isinstance(self.script, str) or not self.script:
            raise PolicyViolation("probe script is required")
        if "\x00" in self.script or len(self.script.encode("utf-8")) > MAX_SCRIPT_BYTES:
            raise PolicyViolation("probe script contains NUL or exceeds the argument size bound")
        if not 1 <= len(self.args) <= 4:
            raise PolicyViolation("probe arguments must be 1-4 fixed tokens")
        for arg in self.args:
            if not COMMAND_ARG_RE.fullmatch(arg):
                raise PolicyViolation("probe arguments must be lower-case tokens, not options")
        keys = [k for k, _ in self.labels]
        if len(keys) != len(set(keys)):
            raise PolicyViolation("duplicate label key")
        for key, value in self.labels:
            if not key.startswith(LABEL_PREFIX) or not LABEL_VALUE_RE.fullmatch(value):
                raise PolicyViolation("labels must be io.patchproof.* with bounded values")
        label_map = dict(self.labels)
        if self.role is Role.DECOY_FOREIGN:
            if set(label_map) != {LABEL_DECOY_OF}:
                raise PolicyViolation("the foreign decoy carries only the decoy marker label")
        else:
            for required in (LABEL_OWNER, LABEL_INSTALLATION, LABEL_RUN, LABEL_ROLE):
                if required not in label_map:
                    raise PolicyViolation(f"owned containers must carry {required}")
            if label_map[LABEL_ROLE] != self.role.value:
                raise PolicyViolation("role label does not match the container role")

    @property
    def label_map(self) -> dict[str, str]:
        return dict(self.labels)

    @property
    def command(self) -> tuple[str, ...]:
        """Arguments after the image: fixed interpreter flags, the probe script, tokens."""
        return (*PYTHON_FLAGS, "-c", self.script, *self.args)

    def tmpfs(self) -> dict[str, str]:
        return {
            WORKDIR: f"{TMPFS_OPTIONS},size={self.limits.scratch_bytes},mode={TMPFS_MODE}",
            "/tmp": f"{TMPFS_OPTIONS},size={self.limits.tmp_bytes},mode={TMPFS_MODE}",
        }


def build_spec(
    *,
    ownership: Ownership,
    role: Role,
    image: ImageId,
    script: str,
    args: tuple[str, ...],
    limits: ResourceLimits | None = None,
    join_target: ContainerId | None = None,
) -> ContainerSpec:
    """The single constructor for probe container specs. Defaults to the role's ceiling."""
    chosen = limits if limits is not None else CEILINGS[role.limit_class]
    return ContainerSpec(
        name=container_name(ownership, role),
        role=role,
        image=image,
        network=Network(join_target) if join_target is not None else NO_NETWORK,
        limits=chosen,
        labels=tuple(sorted(ownership_labels(ownership, role, script).items())),
        script=script,
        args=args,
    )


# --- Code-level refusal of security-relevant profile content (ADR-009) -----------------

PROFILE_ALLOWED_KEYS: Final = frozenset(
    {
        "schema_version", "profile_id", "profile_version", "adapter", "target_image_id",
        "verifier_image_id", "asgi_app", "fixture_contract", "network_policy",
        "source_scope", "resources", "timeouts", "logging", "result_cap_bytes",
    }
)
CONTAINER_LIMIT_KEYS: Final = frozenset({"cpus", "memory_bytes", "pids", "scratch_tmpfs_bytes", "tmp_tmpfs_bytes"})
PROFILE_SCHEMA_VERSION: Final = "1.1"
NETWORK_POLICY_VALUE: Final = "none-shared-loopback-v1"


def check_profile_document(doc: Mapping[str, object]) -> None:
    """Refuse a profile document that tries to carry policy, before any Docker call.

    This is the code-level second line behind `execution-profile.schema.json`: unknown
    keys (privileged, mounts, docker_args, network_mode, ...) are refused, image
    references must be IDs, the network policy has one value, and limits must sit
    inside the code ceilings. Full profile semantics belong to PP-007/PP-008.
    """
    if not isinstance(doc, Mapping):
        raise PolicyViolation("profile must be an object")
    unknown = sorted(set(doc) - PROFILE_ALLOWED_KEYS)
    if unknown:
        raise PolicyViolation(f"profile carries fields the policy does not allow: {unknown}")
    if doc.get("schema_version") != PROFILE_SCHEMA_VERSION:
        raise PolicyViolation(
            f"execution-profile contract {doc.get('schema_version')!r} is not {PROFILE_SCHEMA_VERSION}; "
            "older profiles are refused, never reinterpreted")
    for key in ("target_image_id", "verifier_image_id"):
        value = doc.get(key)
        if not isinstance(value, str):
            raise PolicyViolation(f"{key} is required")
        ImageId(value)
    if doc.get("network_policy") != NETWORK_POLICY_VALUE:
        raise PolicyViolation("network_policy has exactly one permitted value")
    resources = doc.get("resources")
    if not isinstance(resources, Mapping) or set(resources) != {"target", "verifier"}:
        raise PolicyViolation("resources must define exactly target and verifier limits")
    for side, limit_class in (("target", LimitClass.TARGET), ("verifier", LimitClass.VERIFIER)):
        block = resources[side]
        if not isinstance(block, Mapping) or set(block) != CONTAINER_LIMIT_KEYS:
            raise PolicyViolation(f"resources.{side} must contain exactly {sorted(CONTAINER_LIMIT_KEYS)}")
        cpus = block["cpus"]
        if type(cpus) not in (int, float) or isinstance(cpus, bool):
            raise PolicyViolation(f"resources.{side}.cpus must be a number")
        ceiling = CEILINGS[limit_class]
        for key in ("memory_bytes", "pids", "scratch_tmpfs_bytes", "tmp_tmpfs_bytes"):
            if type(block[key]) is not int:
                raise PolicyViolation(f"resources.{side}.{key} must be an integer")
        # Explicit sizes (contract 1.1): /scratch and /tmp each within their ceiling, and
        # their sum within the class's application scratch budget (check_limits).
        check_limits(
            ResourceLimits(
                nano_cpus=round(float(cpus) * NANO_CPUS_PER_CPU),
                memory_bytes=block["memory_bytes"],
                pids=block["pids"],
                scratch_bytes=block["scratch_tmpfs_bytes"],
                tmp_bytes=block["tmp_tmpfs_bytes"],
                deadline_seconds=ceiling.deadline_seconds,
            ),
            limit_class,
        )
    logging_block = doc.get("logging")
    if isinstance(logging_block, Mapping):
        size = logging_block.get("max_file_bytes")
        files = logging_block.get("max_files")
        if type(size) is not int or type(files) is not int:
            raise PolicyViolation("logging limits must be integers")
        if size > LOG_MAX_SIZE_BYTES or files > LOG_MAX_FILE or size < 1 or files < 1:
            raise PolicyViolation("logging limits exceed the code-level log ceiling")
    else:
        raise PolicyViolation("logging limits are required")
