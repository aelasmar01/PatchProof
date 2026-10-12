"""The fixed PP-003 probe catalogue.

Each probe has a kind. A NEGATIVE probe expects something to be impossible; it is only
interpretable when every positive control it names passed in the same run, because a
broken harness also "cannot connect" or "cannot write". CONFIGURATION probes read what
the runtime or kernel reports; they are never presented as enforcement.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Final

from ..runner.policy import Role, script_sha256

SUITE_VERSION: Final = "pp-003-probes-1.0"
PROBE_SCRIPT_PATH: Final = Path(__file__).resolve().parents[3] / "containers" / "probes" / "isolation_probe.py"


def load_probe_script() -> str:
    return PROBE_SCRIPT_PATH.read_text("utf-8")


def probe_script_digest() -> str:
    return script_sha256(load_probe_script())


class Category(str, Enum):
    PREFLIGHT = "preflight"
    NETWORK = "network"
    FILESYSTEM = "filesystem"
    PRIVILEGE = "privilege"
    NAMESPACE = "namespace"
    RESOURCE = "resource"
    POLICY = "policy"
    CLEANUP = "cleanup"


class Kind(str, Enum):
    NEGATIVE = "negative"
    POSITIVE_CONTROL = "positive_control"
    CONFIGURATION = "configuration"
    POLICY_REFUSAL = "policy_refusal"
    CLEANUP = "cleanup"


class EvidenceType(str, Enum):
    BEHAVIORAL = "behavioral"  # the restriction was exercised and held
    KERNEL_STATE = "kernel_state"  # the kernel reports the restriction from inside the container
    INSPECT = "inspect"  # Docker reports the configuration
    HOST_CHECK = "host_check"  # host-side logic over recorded facts, no container involved


@dataclass(frozen=True)
class ProbeSpec:
    probe_id: str
    title: str
    category: Category
    kind: Kind
    evidence: EvidenceType
    roles: tuple[Role, ...]  # containers that must emit an observation; () for host probes
    controls: tuple[str, ...]
    expected: str
    critical: bool = False
    # For a negative probe without a separate control: the control carried inside the
    # same observation. The interpreter returns ERROR when it is absent or false.
    internal_control: str = ""


T, V = Role.TARGET, Role.VERIFIER
TV = (T, V)
N, P, C, Q, K = Kind.NEGATIVE, Kind.POSITIVE_CONTROL, Kind.CONFIGURATION, Kind.POLICY_REFUSAL, Kind.CLEANUP
B, KS, INS, H = EvidenceType.BEHAVIORAL, EvidenceType.KERNEL_STATE, EvidenceType.INSPECT, EvidenceType.HOST_CHECK
NET, FS, PRV, NS, RES, POL, CLN, PRE = (
    Category.NETWORK, Category.FILESYSTEM, Category.PRIVILEGE, Category.NAMESPACE,
    Category.RESOURCE, Category.POLICY, Category.CLEANUP, Category.PREFLIGHT,
)

CATALOGUE: Final[tuple[ProbeSpec, ...]] = (
    # Preflight (read-only daemon queries)
    ProbeSpec("PRE-01", "Docker context is desktop-linux on the expected socket", PRE, C, H, (), (),
              "context endpoint is unix://$HOME/.docker/run/docker.sock"),
    ProbeSpec("PRE-02", "Approved image identity present locally", PRE, C, INS, (), (),
              "image inspect Id equals the approved ID; linux/amd64; Config.Volumes empty"),
    ProbeSpec("PRE-03", "No implicit pull", PRE, C, H, (), (),
              "every create argv carries --pull never and the image ID, never a tag"),
    # Network
    ProbeSpec("NET-P1", "Verifier reaches target over the shared loopback", NET, P, B, (V,), (),
              "HTTP 200 from 127.0.0.1:8080 with the run nonce"),
    ProbeSpec("NET-P2", "UDP loopback round trip works", NET, P, B, (T,), (), "datagram echoed on 127.0.0.1"),
    ProbeSpec("NET-P3", "Resolver answers for localhost", NET, P, B, (T,), (), "localhost resolves to loopback"),
    ProbeSpec("NET-01", "No usable network interface besides loopback", NET, N, KS, TV, ("NET-P1",),
              "lo UP with 127.0.0.1; every other interface (any name) administratively down, operstate down, "
              "no IPv4/IPv6 address, no carrier, zero traffic; 0 routes; no capabilities; egress blocked",
              critical=True),
    ProbeSpec("NET-09", "No routes beyond loopback", NET, N, KS, TV, ("NET-P1",),
              "0 IPv4 routes; 0 non-lo IPv6 routes", critical=True),
    ProbeSpec("NET-02", "No IPv4 TCP egress", NET, N, B, (T,), ("NET-P1",),
              "every connect fails with ENETUNREACH/EHOSTUNREACH/EADDRNOTAVAIL", critical=True),
    ProbeSpec("NET-03", "No IPv6 TCP egress", NET, N, B, (T,), ("NET-P1",),
              "every connect fails with an unreachable errno", critical=True),
    ProbeSpec("NET-04", "No DNS resolution of external names", NET, N, B, (T,), ("NET-P3",),
              "getaddrinfo fails for every external name", critical=True),
    ProbeSpec("NET-05", "No UDP egress", NET, N, B, (T,), ("NET-P2",),
              "sendto fails with an unreachable errno", critical=True),
    ProbeSpec("NET-06", "Docker Engine API and host gateway unreachable", NET, N, B, (T,), ("NET-P1",),
              "no TCP connection to gateway/engine addresses; gateway names do not resolve", critical=True),
    ProbeSpec("NET-07", "Joining the target namespace adds no egress", NET, N, B, (V,), ("NET-P1",),
              "NET-02..06 attempts from the verifier all fail", critical=True),
    ProbeSpec("NET-08", "No published or exposed ports", NET, C, INS, (), (),
              "PortBindings/Ports/ExposedPorts empty and PublishAllPorts false for target and verifier"),
    # Filesystem
    ProbeSpec("FS-P1", "Approved scratch locations are writable", FS, P, B, (T, V, Role.STORAGE), (),
              "1 MiB write and read-back succeed in /scratch and /tmp"),
    ProbeSpec("FS-P2", "Marker search finds the container's own marker", FS, P, B, TV, (),
              "own marker found by the same walk used for the cross-container check"),
    ProbeSpec("FS-P3", "Socket scan detects a known socket", FS, P, B, TV, (),
              "the probe's own AF_UNIX socket in /scratch is detected"),
    ProbeSpec("FS-01", "Root filesystem is read-only", FS, N, B, TV, ("FS-P1",),
              "creating files on the image filesystem fails with EROFS, including world-writable /var/tmp",
              critical=True),
    ProbeSpec("FS-02", "Docker socket inaccessible", FS, N, B, TV, ("FS-P3",),
              "no socket paths exist, none found by scan, connects fail, mountinfo has no docker.sock",
              critical=True),
    ProbeSpec("FS-03", "Host home, repository, and credential paths absent", FS, N, B, TV, (),
              "none of the host path names exist", critical=True,
              internal_control="the same existence check reports /etc/passwd as present"),
    ProbeSpec("FS-04", "Mount table contains only expected mounts", FS, N, KS, TV, (),
              "every mount matches the classified allowlist; no host-path source; / is read-only overlay",
              critical=True, internal_control="the parser finds the root mount and the /scratch tmpfs"),
    ProbeSpec("FS-05", "No host environment inherited", FS, N, KS, TV, (),
              "startup environment (/proc/self/environ) = image Env keys plus HOSTNAME/HOME; the only "
              "runtime-only variable allowed is CPython's LC_CTYPE=C.UTF-8 or C.utf8, absent at startup",
              internal_control="PATH from the image Env is visible"),
    ProbeSpec("FS-06", "Target cannot see verifier files", FS, N, B, (T,), ("FS-P2",),
              "verifier marker not found by walk or via /proc/*/root", critical=True),
    ProbeSpec("FS-07", "Verifier cannot see target files", FS, N, B, (V,), ("FS-P2",),
              "target marker not found by walk or via /proc/*/root"),
    ProbeSpec("FS-10", "Writable locations are only the approved tmpfs mounts", FS, N, B, TV, (),
              "a file can be created only under /scratch, /tmp, /dev/shm or /dev/mqueue", critical=True,
              internal_control="the census finds /scratch and /tmp writable"),
    ProbeSpec("FS-08", "Kernel tunables and cgroup files not writable", FS, N, B, TV, ("FS-P1",),
              "open for write fails with EROFS/EACCES/EPERM on every existing path, including the "
              "/etc/hosts, /etc/hostname and /etc/resolv.conf bind mounts"),
    ProbeSpec("FS-09", "No credential or repository files on the container filesystem", FS, N, B, TV,
              ("FS-P2",), "no sensitive names found and the walk was not truncated", critical=True),
    # Privileges
    ProbeSpec("PRV-01", "Fixed non-root identity", PRV, N, KS, TV, (),
              "uid/euid/gid/egid 10001; no supplementary group 0", critical=True,
              internal_control="all four IDs are reported as integers"),
    ProbeSpec("PRV-P1", "setuid to own uid works", PRV, P, B, TV, (), "setuid(own uid) succeeds"),
    ProbeSpec("PRV-02", "Cannot become root", PRV, N, B, TV, ("PRV-P1",),
              "setuid(0), setgid(0), setgroups([0]) fail with EPERM", critical=True),
    ProbeSpec("PRV-03", "All capability sets empty", PRV, C, KS, TV, (),
              "CapInh/CapPrm/CapEff/CapBnd/CapAmb all zero"),
    ProbeSpec("PRV-P2", "chown to own uid works", PRV, P, B, TV, (), "chown(own uid, own gid) succeeds"),
    ProbeSpec("PRV-04", "CAP_CHOWN not usable", PRV, N, B, TV, ("PRV-P2",), "chown to 0:0 fails with EPERM"),
    ProbeSpec("PRV-05", "CAP_MKNOD not usable", PRV, N, B, TV, ("PRV-P2",), "mknod char device fails with EPERM"),
    ProbeSpec("PRV-P3", "Ordinary TCP socket creation works", PRV, P, B, TV, (), "AF_INET stream socket created"),
    ProbeSpec("PRV-06", "CAP_NET_RAW not usable", PRV, N, B, TV, ("PRV-P3",),
              "raw ICMP and AF_PACKET sockets fail with EPERM/EACCES"),
    ProbeSpec("PRV-07", "no-new-privileges set", PRV, C, KS, TV, (), "NoNewPrivs: 1"),
    ProbeSpec("PRV-08", "seccomp filter active", PRV, C, KS, TV, (), "Seccomp: 2 and Seccomp_filters >= 1"),
    ProbeSpec("PRV-P4", "ctypes syscall path works", PRV, P, B, TV, (), "libc getpid via ctypes equals os.getpid"),
    ProbeSpec("PRV-09", "seccomp blocks keyctl (needs no capability)", PRV, N, B, TV, ("PRV-P4",),
              "keyctl fails with EPERM", critical=True),
    ProbeSpec("PRV-P5", "Forked-child result channel works", PRV, P, B, TV, (),
              "a forked child reports its result through the pipe"),
    ProbeSpec("PRV-10", "Namespace operations needing CAP_SYS_ADMIN refused", PRV, N, B, TV, ("PRV-P4", "PRV-P5"),
              "unshare(NEWNS), unshare(NEWNET), unshare(NEWPID), unshare(NEWUSER|NEWNS) and setns(mnt) each "
              "fail with EPERM, each in its own forked child", critical=True),
    ProbeSpec("PRV-11", "Cannot mount", PRV, N, B, TV, ("PRV-P4", "PRV-P5"),
              "mount tmpfs fails with EPERM (forked child)", critical=True),
    ProbeSpec("PRV-12", "Only default devices", PRV, N, KS, TV, (), "/dev entries are a subset of the default set",
              internal_control="/dev/null is listed"),
    ProbeSpec("PRV-13", "A user namespace, if the default profile permits one, grants no container privilege",
              PRV, N, B, TV, ("PRV-P4", "PRV-P5"),
              "unshare(CLONE_NEWUSER) outcome recorded (permitted or EPERM both accepted); if permitted, "
              "sethostname, mount tmpfs and unshare(NEWNS) from inside it all fail with EPERM", critical=True),
    # Namespaces
    ProbeSpec("NS-01", "Private PID namespace", NS, N, KS, TV, (),
              "the probe is PID 1 and the only process visible", critical=True,
              internal_control="the probe's own PID appears in the /proc listing"),
    ProbeSpec("NS-02", "Namespace topology matches 10.1", NS, N, KS, TV, (),
              "net shared between target and verifier; pid, mnt, ipc differ", critical=True,
              internal_control="the shared net namespace is the positive half of the same comparison"),
    ProbeSpec("NS-03", "No host namespaces configured", NS, C, INS, (), (),
              "PidMode/UTSMode/UsernsMode empty, IpcMode private, CgroupnsMode private, NetworkMode as planned"),
    # Resources
    ProbeSpec("RES-01", "Memory limit configured, no swap", RES, C, KS, TV, (),
              "memory.max equals the limit; memory.swap.max is 0"),
    ProbeSpec("RES-P1", "Allocation below the limit works", RES, P, B, (Role.MEMORY,), (),
              "256 MiB allocated and touched"),
    ProbeSpec("RES-02", "Memory limit enforced", RES, N, B, (), ("RES-P1",),
              "OOM-killed (exit 137, OOMKilled true) before progress reaches the limit", critical=True),
    ProbeSpec("RES-03", "PID limit configured", RES, C, KS, TV, (), "pids.max equals 128"),
    ProbeSpec("RES-P2", "Thread creation below the limit works", RES, P, B, (Role.PIDS,), (), "16 threads started"),
    ProbeSpec("RES-04", "PID limit enforced", RES, N, B, (Role.PIDS,), ("RES-P2",),
              "thread creation fails with at most 128 tasks"),
    ProbeSpec("RES-05", "CPU limit configured", RES, C, KS, TV, (), "cpu.max equals '100000 100000'"),
    ProbeSpec("RES-P3", "CPU measurement works", RES, P, B, (Role.CPU,), (), "one busy process reaches ratio >= 0.5"),
    ProbeSpec("RES-06", "CPU limit enforced", RES, N, B, (Role.CPU,), ("RES-P3",),
              "four busy processes reach CPU/wall <= 1.25"),
    ProbeSpec("RES-P4", "Exec from the image filesystem works", RES, P, B, (Role.STORAGE,), (),
              "interpreter subprocess exits 0"),
    ProbeSpec("RES-07", "Scratch tmpfs bounded", RES, N, B, (Role.STORAGE,), ("FS-P1",),
              "ENOSPC after at least half and at most the scratch limit"),
    ProbeSpec("RES-08", "/tmp tmpfs bounded", RES, N, B, (Role.STORAGE,), ("FS-P1",),
              "ENOSPC after at least half and at most the /tmp limit"),
    ProbeSpec("RES-14", "/dev/shm bounded separately from the scratch budget", RES, N, B, (Role.STORAGE,),
              ("FS-P1",), "if /dev/shm is mounted, ENOSPC at or below 16 MiB; if absent, recorded as absent"),
    ProbeSpec("RES-09", "/tmp is noexec", RES, N, B, (Role.STORAGE,), ("RES-P4",),
              "executing a script in /tmp fails with EACCES"),
    ProbeSpec("RES-10", "Daemon log rotation configured", RES, C, INS, (), (),
              "LogConfig local, max-size 5m, max-file 2, compress false"),
    ProbeSpec("RES-P5", "Log flood ran to completion", RES, P, B, (), (),
              "flood-end marker retained; at least 30 MiB written"),
    ProbeSpec("RES-11", "Daemon-side log volume bounded", RES, N, B, (), ("RES-P5",),
              "retained log bytes <= 2 x 5 MiB + slack; flood-start marker rotated away", critical=True),
    ProbeSpec("RES-12", "Deadline and forced termination", RES, N, B, (), (),
              "runner deadline expires, stop escalates within grace, container stopped and removed",
              internal_control="the sleeping marker shows the container was running when the deadline hit"),
    ProbeSpec("RES-15", "Suite finished within the 20-minute global execution deadline", RES, C, H, (), (),
              "active probing completed before the monotonic deadline; on expiry or interruption the result is "
              "INCONCLUSIVE, so the suite can never be reported as passed", critical=True),
    ProbeSpec("RES-13", "Collector output cap holds", RES, N, H, (), (),
              "a 1 MiB-capped read of the flood log returns <= 1 MiB and is marked truncated",
              internal_control="the uncapped read of the same log returned more than 1 MiB"),
    # Policy refusal (no Docker call may happen)
    ProbeSpec("POL-P1", "Valid fixed-policy request accepted", POL, P, H, (), (),
              "default target and verifier specs build and the profile example is accepted"),
    ProbeSpec("POL-01", "Privileged profile refused", POL, Q, H, (), ("POL-P1",),
              "refused before any Docker invocation"),
    ProbeSpec("POL-02", "Forbidden mount, network, and Docker-argument fields refused", POL, Q, H, (), ("POL-P1",),
              "refused before any Docker invocation"),
    ProbeSpec("POL-03", "Floating image references refused", POL, Q, H, (), ("POL-P1",),
              "tags, name@digest, and short IDs refused before any Docker invocation"),
    ProbeSpec("POL-04", "Limits above code ceilings refused", POL, Q, H, (), ("POL-P1",),
              "refused before any Docker invocation"),
    ProbeSpec("POL-05", "Inspect gate rejects drifted configuration", POL, Q, H, (), (),
              "real target inspect passes; every mutated copy (privileged, cap-add, socket bind, bridge, "
              "unconfined seccomp, unlimited memory) is rejected"),
    ProbeSpec("POL-06", "Every created container passed the inspect gate before start", POL, C, INS, (), (),
              "gate passed for every started container; none started after a mismatch"),
    # Cleanup and preservation
    ProbeSpec("CLN-01", "Owned containers removed by exact ID", CLN, K, H, (), (),
              "every owned container removed and confirmed absent"),
    ProbeSpec("CLN-02", "Container from another run refused", CLN, K, H, (), ("CLN-01",),
              "cleanup refuses the other-run decoy; it still exists afterwards"),
    ProbeSpec("CLN-03", "Container without PatchProof ownership refused", CLN, K, H, (), ("CLN-01",),
              "cleanup refuses the foreign decoy; it still exists afterwards"),
    ProbeSpec("CLN-04", "Decoys torn down by their separate path", CLN, K, H, (), (),
              "both decoys removed by exact ID and confirmed absent"),
    ProbeSpec("CLN-05", "Only allowlisted Docker operations executed", CLN, K, H, (), (),
              "command log contains only allowlisted operations; no prune, filter, force, or bulk removal"),
    ProbeSpec("CLN-06", "Unrelated resources preserved", CLN, K, H, (), (),
              "image, container, volume, network, and build-cache snapshots identical before and after",
              critical=True),
)

BY_ID: Final = {spec.probe_id: spec for spec in CATALOGUE}


def validate_catalogue() -> None:
    """Structural invariants of the catalogue itself (also unit-tested)."""
    if len(BY_ID) != len(CATALOGUE):
        raise ValueError("duplicate probe ID")
    for spec in CATALOGUE:
        for control in spec.controls:
            ctrl = BY_ID.get(control)
            if ctrl is None:
                raise ValueError(f"{spec.probe_id} names unknown control {control}")
            if ctrl.kind not in (Kind.POSITIVE_CONTROL, Kind.CLEANUP):
                raise ValueError(f"{spec.probe_id} control {control} is not a positive control")
        if spec.kind is Kind.POSITIVE_CONTROL and spec.controls:
            raise ValueError("positive controls do not themselves depend on controls")
        if spec.kind is Kind.NEGATIVE and not spec.controls and not spec.internal_control:
            raise ValueError(f"negative probe {spec.probe_id} has no positive control")


validate_catalogue()
