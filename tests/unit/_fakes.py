"""Synthetic Docker responses for Docker-free tests (SYNTHETIC FIXTURES, not measurements).

`FakeDocker` implements the runner's `Executor` protocol over an in-memory model. It
never starts a process and never contacts a daemon. Its inspect documents follow the
shape of `docker container inspect` closely enough to exercise the gate; they were not
captured from a real daemon, so the first real run (A4) remains the test of the gate's
field expectations against Docker 29.8.2.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from patchproof.runner.docker_cli import (
    CommandResult,
    ContextInspect,
    Create,
    ImageInspect,
    Inspect,
    Logs,
    ForceRemove,
    Remove,
    SnapshotList,
    Start,
    Stop,
    Version,
    Wait,
    create_argv_tail,
)
from patchproof.runner.policy import (
    CONTAINER_USER,
    ENTRYPOINT,
    MIB,
    ContainerSpec,
    ImageId,
    Ownership,
    Role,
)

HOME = "/Users/synthetic"
IMAGE = ImageId("sha256:" + "1" * 64)
IMAGE_ENV = ["PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "PYTHON_VERSION=3.13.0"]
OWNERSHIP = Ownership(installation_id="inst-" + "a" * 32, run_id="run-" + "b" * 32)
NONCE = "c" * 32
ZERO = "0" * 16


def good_inspect(spec: ContainerSpec, cid: str, env: list[str] | None = None, state: str = "created") -> dict[str, Any]:
    limits = spec.limits
    return {
        "Id": cid,
        "Name": "/" + spec.name,
        "Image": spec.image.value,
        "Platform": "linux",
        "ImageManifestDescriptor": {"mediaType": "application/vnd.oci.image.manifest.v1+json",
                                    "digest": "sha256:" + "8" * 64, "size": 1000,
                                    "platform": {"architecture": "amd64", "os": "linux"}},
        "State": {"Status": state, "Running": state == "running", "ExitCode": 0, "OOMKilled": False},
        "Config": {
            "Image": spec.image.value, "User": CONTAINER_USER, "Entrypoint": [ENTRYPOINT], "Cmd": list(spec.command),
            "Labels": spec.label_map, "Env": list(env if env is not None else IMAGE_ENV), "WorkingDir": "/scratch",
            "Tty": False, "OpenStdin": False, "AttachStdin": False, "ExposedPorts": None, "Volumes": None,
        },
        "HostConfig": {
            "Privileged": False, "CapDrop": ["ALL"], "CapAdd": None, "ReadonlyRootfs": True,
            "SecurityOpt": ["no-new-privileges=true"], "NetworkMode": spec.network.mode, "PortBindings": {},
            "PublishAllPorts": False, "Binds": None, "Mounts": None, "VolumesFrom": None, "Links": None,
            "Devices": [], "DeviceRequests": None, "DeviceCgroupRules": None, "ExtraHosts": None, "GroupAdd": None,
            "CgroupParent": "", "Tmpfs": spec.tmpfs(), "Memory": limits.memory_bytes,
            "MemorySwap": limits.memory_bytes, "NanoCpus": limits.nano_cpus, "PidsLimit": limits.pids,
            "OomKillDisable": False, "PidMode": "", "IpcMode": "private", "ShmSize": 16777216, "UTSMode": "", "UsernsMode": "",
            "CgroupnsMode": "private", "Runtime": "runc", "AutoRemove": False,
            "LogConfig": {"Type": "local", "Config": {"max-size": "5m", "max-file": "2", "compress": "false"}},
            "MaskedPaths": ["/proc/asound", "/proc/acpi", "/proc/kcore", "/sys/firmware"],
            "ReadonlyPaths": ["/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"],
            "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
        },
        "Mounts": [],
        "NetworkSettings": {"Ports": {}},
    }


def sample_mountinfo(cid: str = "f" * 64) -> list[str]:
    return [
        "600 500 0:50 / / ro,relatime master:1 - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/l/A",
        "601 600 0:52 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw",
        "602 600 0:53 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755",
        "603 602 0:54 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw,gid=5,mode=620,ptmxmode=666",
        "604 600 0:55 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs ro",
        "605 604 0:30 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw",
        "606 602 0:51 / /dev/mqueue rw,nosuid,nodev,noexec,relatime - mqueue mqueue rw",
        "617 602 0:62 / /dev/shm rw,nosuid,nodev,noexec,relatime - tmpfs shm rw,size=16384k",
        f"607 600 254:1 /docker/containers/{cid}/resolv.conf /etc/resolv.conf rw,relatime - ext4 /dev/vda1 rw",
        f"608 600 254:1 /docker/containers/{cid}/hostname /etc/hostname rw,relatime - ext4 /dev/vda1 rw",
        f"609 600 254:1 /docker/containers/{cid}/hosts /etc/hosts rw,relatime - ext4 /dev/vda1 rw",
        "610 600 0:56 / /scratch rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=262144k,mode=1777",
        "611 600 0:57 / /tmp rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=65536k,mode=1777",
        "612 601 0:52 /bus /proc/bus ro,nosuid,nodev,noexec,relatime - proc proc rw",
        "613 601 0:52 /sys /proc/sys ro,nosuid,nodev,noexec,relatime - proc proc rw",
        "614 601 0:53 /null /proc/kcore rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755",
        "615 601 0:58 / /proc/acpi ro,relatime - tmpfs tmpfs ro",
        "616 604 0:59 / /sys/firmware ro,relatime - tmpfs tmpfs ro",
    ]


FALLBACK_TUNNELS = ("erspan0", "gre0", "gretap0", "ip6_vti0", "ip6gre0", "ip6tnl0", "ip_vti0", "sit0", "tunl0")


def down_interface(link_type: str = "778") -> dict[str, Any]:
    return {"operstate": "down", "flags": "0x80", "type": link_type, "mtu": "1476", "carrier": "error:EINVAL",
            "ipv4": "none:EADDRNOTAVAIL", "ipv6": [], "rx_bytes": 0, "tx_bytes": 0}


def net01_observation(others: tuple[str, ...] = FALLBACK_TUNNELS) -> dict[str, Any]:
    """Shape of the expanded NET-01 diagnostics: loopback plus kernel fallback tunnels, down and idle."""
    names = sorted(("lo", *others))
    details = {n: down_interface() for n in others}
    details["lo"] = {"operstate": "unknown", "flags": "0x9", "type": "772", "mtu": "65536", "carrier": "1",
                     "ipv4": "127.0.0.1", "ipv6": [], "rx_bytes": 1024, "tx_bytes": 1024}
    return {"proc_net_dev": names, "if_nameindex": names, "details": details, "fb_tunnels_only_for_init_net": "0"}


def fs05_observation(coerced: str | None = "C.UTF-8") -> dict[str, Any]:
    """Startup env = image Env keys + HOME/HOSTNAME; CPython (PEP 538) adds LC_CTYPE after start."""
    initial = sorted([k.split("=", 1)[0] for k in IMAGE_ENV] + ["HOME", "HOSTNAME"])
    runtime_only = ["LC_CTYPE"] if coerced else []
    return {"keys": sorted(initial + runtime_only), "initial_keys": initial, "runtime_only_keys": runtime_only,
            "lc_ctype_value": coerced}


def blocked(dest: str, err: str = "ENETUNREACH") -> dict[str, Any]:
    return {"dest": dest, "ok": False, "errno": err}


def common_observations(role: Role) -> dict[str, dict[str, Any]]:
    limits_mem = {Role.TARGET: 1024 * MIB, Role.VERIFIER: 512 * MIB}[role]
    ns_suffix = "1" if role is Role.TARGET else "2"
    obs: dict[str, dict[str, Any]] = {
        "NET-01": net01_observation(),
        "NET-09": {"ipv4_routes": 0, "ipv6_routes_non_lo": 0},
        "FS-P1": {"targets": {"/scratch": {"ok": True, "match": True}, "/tmp": {"ok": True, "match": True}}},
        "FS-P3": {"own_socket_detected": True},
        "FS-01": {"attempts": [{"path": "/pp-probe", "ok": False, "errno": "EROFS"},
                               {"path": "/var/tmp/pp-probe", "ok": False, "errno": "EROFS"},
                               {"path": "/home/pp-probe", "ok": False, "errno": "ENOENT"}]},
        "FS-02": {"paths": [{"path": "/var/run/docker.sock", "exists": False}], "sockets_found": [],
                  "connects": [{"path": "/var/run/docker.sock", "ok": False, "errno": "ENOENT"}],
                  "mountinfo_mentions_docker_sock": False},
        "FS-03": {"paths": [{"path": "/Users", "exists": False}, {"path": "/host_mnt", "exists": False}],
                  "control_etc_passwd_exists": True},
        "FS-04": {"lines": sample_mountinfo(), "total": len(sample_mountinfo())},
        "FS-05": fs05_observation(),
        "FS-10": {"writable": ["/dev/mqueue", "/dev/shm", "/scratch", "/tmp"],
                  "refused": {"/": "EROFS", "/dev": "EACCES", "/dev/pts": "EACCES"}},
        "FS-P2": {"own_marker_found": 2, "scanned": 1234},
        "FS-08": {"attempts": [{"path": "/proc/sys/kernel/hostname", "ok": False, "errno": "EROFS"},
                               {"path": "/etc/hosts", "ok": False, "errno": "EACCES"}]},
        "FS-09": {"found": [], "scanned": 12000, "denied": 5, "truncated": False},
        "PRV-01": {"uid": 10001, "euid": 10001, "gid": 10001, "egid": 10001, "groups": [10001]},
        "PRV-P1": {"setuid_self": {"ok": True}},
        "PRV-02": {k: {"ok": False, "errno": "EPERM"} for k in ("setuid0", "setgid0", "setgroups0")},
        "PRV-03": {k: ZERO for k in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")},
        "PRV-P2": {"chown_self": {"ok": True}},
        "PRV-04": {"chown_root": {"ok": False, "errno": "EPERM"}},
        "PRV-05": {"mknod_char": {"ok": False, "errno": "EPERM"}},
        "PRV-P3": {"tcp_socket": {"ok": True}},
        "PRV-06": {"raw_icmp": {"ok": False, "errno": "EPERM"}, "af_packet": {"ok": False, "errno": "EPERM"}},
        "PRV-07": {"NoNewPrivs": "1"},
        "PRV-08": {"Seccomp": "2", "Seccomp_filters": "1"},
        "PRV-P4": {"ctypes_getpid": 1, "os_getpid": 1, "arch": "x86_64"},
        "PRV-09": {"keyctl": {"ok": False, "errno": "EPERM"}},
        "PRV-P5": {"child_ok": True, "pid_differs": True},
        "PRV-10": {k: {"ok": False, "errno": "EPERM"} for k in (
            "unshare_newns", "unshare_newnet", "unshare_newpid", "unshare_newuser_newns", "setns_mnt")},
        "PRV-11": {"mount_tmpfs": {"ok": False, "errno": "EPERM"}},
        # Docker documents that its default profile permits unprivileged user namespaces;
        # the synthetic baseline models that case, which must still PASS.
        "PRV-13": {"newuser": {"ok": True, "result": 0},
                   "post": {"sethostname": {"ok": False, "errno": "EPERM"},
                            "mount_tmpfs": {"ok": False, "errno": "EPERM"},
                            "unshare_newns": {"ok": False, "errno": "EPERM"},
                            "cap_eff_in_new_userns": "000001ffffffffff"}},
        "PRV-12": {"entries": ["fd", "full", "mqueue", "null", "ptmx", "pts", "random", "stderr", "stdin",
                               "stdout", "tty", "urandom", "zero"]},
        "NS-01": {"pids": [1], "self_pid": 1, "process_count": 1},
        "NS-02": {"net": "net:[4026531840]", "pid": f"pid:[40265320{ns_suffix}]",
                  "mnt": f"mnt:[40265321{ns_suffix}]", "ipc": f"ipc:[40265322{ns_suffix}]",
                  "uts": f"uts:[40265323{ns_suffix}]", "cgroup": f"cgroup:[40265324{ns_suffix}]",
                  "user": "user:[4026531837]"},
        "RES-01": {"memory_max": str(limits_mem), "memory_swap_max": "0"},
        "RES-03": {"pids_max": "128"},
        "RES-05": {"cpu_max": "100000 100000"},
    }
    egress = [blocked("1.1.1.1:443"), blocked("8.8.8.8:53")]
    egress6 = [blocked("[2606:4700:4700::1111]:443")]
    dns = [{"name": "example.com", "ok": False, "gai": "-3"}]
    udp = [blocked("8.8.8.8:53")]
    engine = [blocked("192.168.65.7:2375"), {"dest": "127.0.0.1:2375", "loopback": True, "ok": False,
                                              "errno": "ECONNREFUSED"},
              {"name": "host.docker.internal", "ok": False, "gai": "-2"}]
    if role is Role.TARGET:
        obs.update({
            "NET-P2": {"ok": True, "echo_match": True},
            "NET-P3": {"ok": True, "addresses": ["127.0.0.1", "::1"]},
            "NET-02": {"attempts": egress}, "NET-03": {"attempts": egress6}, "NET-04": {"attempts": dns},
            "NET-05": {"attempts": udp}, "NET-06": {"attempts": engine},
            "FS-06": {"other_marker_paths": [], "other_marker_via_proc": [], "scanned": 1234, "denied": 3,
                      "truncated": False},
        })
    else:
        obs.update({
            "NET-P1": {"status": 200, "nonce_match": True, "tries": 3},
            "NET-07": {"tcp4": egress, "tcp6": egress6, "dns": dns, "udp": udp, "engine": engine},
            "FS-07": {"other_marker_paths": [], "other_marker_via_proc": [], "scanned": 1234, "denied": 3,
                      "truncated": False},
        })
    return obs


def standalone_observations(role: Role) -> dict[str, dict[str, Any]]:
    if role is Role.MEMORY:
        return {"RES-P1": {"allocated_mib": 256, "ok": True}}
    if role is Role.PIDS:
        return {"RES-P2": {"started": 16, "ok": True}, "RES-04": {"started_threads": 120, "error": "can't start"}}
    if role is Role.CPU:
        return {"RES-P3": {"workers": 1, "ratio": 0.98}, "RES-06": {"workers": 4, "ratio": 1.01}}
    if role is Role.STORAGE:
        return {"FS-P1": {"targets": {"/scratch": {"ok": True, "match": True}, "/tmp": {"ok": True, "match": True}}},
                "RES-P4": {"returncode": 0}, "RES-09": {"exec_tmp": {"ok": False, "errno": "EACCES"}},
                "RES-07": {"bytes_written": 250 * MIB, "errno": "ENOSPC"},
                "RES-08": {"bytes_written": 60 * MIB, "errno": "ENOSPC"},
                "RES-14": {"present": True, "bytes_written": 16 * MIB, "errno": "ENOSPC"}}
    return {}


def record_line(role: Role, kind: str = "obs", nonce: str = NONCE, **extra: Any) -> bytes:
    return json.dumps({"pp": kind, "v": 1, "nonce": nonce, "role": role.value, **extra}, sort_keys=True).encode()


def obs_stream(role: Role, observations: dict[str, dict[str, Any]], *, end: bool = True, nonce: str = NONCE,
               extra_markers: list[bytes] | None = None) -> bytes:
    lines = [record_line(role, "start", nonce, pid=1)]
    lines += [record_line(role, "obs", nonce, probe=p, obs=o) for p, o in observations.items()]
    lines += extra_markers or []
    if end:
        lines.append(record_line(role, "end", nonce, count=len(observations)))
    return b"\n".join(lines) + b"\n"


def logflood_stream(nonce: str = NONCE, retained_mib: int = 10, include_start: bool = False) -> bytes:
    filler = (b"f" * 1023 + b"\n") * 1024 * retained_mib
    head = record_line(Role.LOGFLOOD, "flood-start", nonce) + b"\n" if include_start else b""
    return head + filler + record_line(Role.LOGFLOOD, "flood-end", nonce, bytes=30 * MIB) + b"\n"


SNAPSHOT_ROWS: dict[str, list[dict[str, Any]]] = {
    "images": [{"ID": "sha256:" + "1" * 64, "Repository": "python", "Tag": "3.13-slim", "Digest": "<none>"},
               {"ID": "sha256:" + "9" * 64, "Repository": "<none>", "Tag": "<none>", "Digest": "<none>"}],
    "containers": [{"ID": "e" * 64, "Names": "unrelated_db", "Image": "postgres:16", "State": "exited",
                    "Status": "Exited (0) 7 months ago"}],
    "volumes": [{"Name": "unrelated_data", "Driver": "local"}],
    "networks": [{"ID": "n" * 12, "Name": "bridge", "Driver": "bridge"}],
    "system-df": [{"Type": "Images", "TotalCount": "2"}, {"Type": "Build Cache", "TotalCount": "77"}],
}


def _result(op_name: str, argv: list[str], rc: int | None = 0, out: bytes = b"", err: bytes = b"",
            truncated: bool = False, timed_out: bool = False) -> CommandResult:
    return CommandResult(op_name=op_name, argv=tuple(argv), returncode=rc, stdout=out, stderr=err,
                         stdout_truncated=truncated, stderr_truncated=False, timed_out=timed_out,
                         duration_seconds=0.01)


@dataclass
class FakeContainer:
    spec: ContainerSpec
    cid: str
    state: str = "created"
    exit_code: int = 0
    oom: bool = False


@dataclass
class FakeDocker:
    """In-memory Docker model. Scenario hooks customize behaviour per test."""

    context_host: str = f"unix://{HOME}/.docker/run/docker.sock"
    image_present: bool = True
    image_env: list[str] = field(default_factory=lambda: list(IMAGE_ENV))
    image_volumes: dict[str, Any] | None = None
    streams: dict[Role, bytes] = field(default_factory=dict)
    exits: dict[Role, tuple[int, bool]] = field(default_factory=dict)  # role -> (exit code, oom)
    hang_roles: set[Role] = field(default_factory=lambda: {Role.SLEEPER})
    inspect_mutator: Callable[[Role, dict[str, Any]], None] | None = None
    fail_remove_roles: set[Role] = field(default_factory=set)
    fail_stop_roles: set[Role] = field(default_factory=set)  # stop "times out"; container keeps running
    fail_force_roles: set[Role] = field(default_factory=set)
    snapshot_after_mutator: Callable[[dict[str, list[dict[str, Any]]]], None] | None = None
    interrupt_on: tuple[str, Role] | None = None
    # Simulated monotonic time: each op costs op_cost[op_name] (or wait_cost[role] for Wait).
    # An op whose cost exceeds its (budget-capped) timeout times out after exactly that timeout.
    clock: list[float] = field(default_factory=lambda: [0.0])
    op_cost: dict[str, float] = field(default_factory=dict)
    wait_cost: dict[Role, float] = field(default_factory=dict)
    timeline: list[tuple[str, float, float]] = field(default_factory=list)  # (op, start time, timeout)
    containers: dict[str, FakeContainer] = field(default_factory=dict)
    ops: list[tuple[str, str]] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    _counter: int = 0
    _snapshots_taken: int = 0

    def _role_of(self, cid: str) -> Role | None:
        c = self.containers.get(cid)
        return c.spec.role if c else None

    def run(self, op: Any) -> CommandResult:
        argv = ["docker", "--context", "desktop-linux", *op.argv_tail()]
        target = getattr(getattr(op, "container", None), "value", None) or getattr(getattr(op, "ref", None), "value", "")
        self.ops.append((op.op_name, target or ""))
        role = self._role_of(target) if target else None
        self.timeline.append((op.op_name, self.clock[0], op.timeout_seconds))
        cost = self.wait_cost.get(role, 0.0) if isinstance(op, Wait) and role is not None else \
            self.op_cost.get(op.op_name, 0.0)
        if isinstance(op, Wait) and role in self.hang_roles:
            cost = op.timeout_seconds
        if cost > op.timeout_seconds:
            self.clock[0] += op.timeout_seconds
            return _result(op.op_name, argv, rc=None, timed_out=True)
        self.clock[0] += cost
        if self.interrupt_on and role is not None and self.interrupt_on == (op.op_name, role):
            raise KeyboardInterrupt
        if isinstance(op, ContextInspect):
            return _result(op.op_name, argv, out=json.dumps([{"Name": "desktop-linux",
                                                               "Endpoints": {"docker": {"Host": self.context_host}}}]).encode())
        if isinstance(op, Version):
            return _result(op.op_name, argv, out=json.dumps({"Server": {"Version": "29.8.2"}}).encode())
        if isinstance(op, ImageInspect):
            if not self.image_present:
                return _result(op.op_name, argv, rc=1, out=b"[]", err=b"Error: No such image")
            return _result(op.op_name, argv, out=json.dumps([{
                "Id": op.image.value, "RepoDigests": ["python@sha256:" + "2" * 64], "Os": "linux",
                "Architecture": "amd64", "Config": {"Env": self.image_env, "Volumes": self.image_volumes}}]).encode())
        if isinstance(op, Create):
            assert create_argv_tail(op.spec) == op.argv_tail()
            self._counter += 1
            cid = f"{self._counter:064x}"
            self.containers[cid] = FakeContainer(op.spec, cid)
            return _result(op.op_name, argv, out=(cid + "\n").encode())
        if isinstance(op, Inspect):
            ref = op.ref.value
            match = self.containers.get(ref) or next(
                (c for c in self.containers.values() if c.spec.name == ref), None)
            if match is None:
                return _result(op.op_name, argv, rc=1, out=b"[]", err=b"Error: No such container: x")
            obj = good_inspect(match.spec, match.cid, self.image_env, match.state)
            obj["State"].update({"ExitCode": match.exit_code, "OOMKilled": match.oom,
                                 "Running": match.state == "running"})
            if self.inspect_mutator:
                self.inspect_mutator(match.spec.role, obj)
            return _result(op.op_name, argv, out=json.dumps([obj]).encode())
        if isinstance(op, Start):
            c = self.containers[op.container.value]
            c.state = "running"
            return _result(op.op_name, argv)
        if isinstance(op, Wait):
            c = self.containers[op.container.value]
            if c.spec.role in self.hang_roles:
                return _result(op.op_name, argv, rc=None, timed_out=True)
            code, oom = self.exits.get(c.spec.role, (137, True) if c.spec.role is Role.MEMORY else (0, False))
            c.state, c.exit_code, c.oom = "exited", code, oom
            return _result(op.op_name, argv, out=f"{code}\n".encode())
        if isinstance(op, Logs):
            c = self.containers[op.container.value]
            data = self.streams.get(c.spec.role, b"")
            if len(data) > op.stdout_cap:
                return _result(op.op_name, argv, rc=None, out=data[: op.stdout_cap], truncated=True)
            return _result(op.op_name, argv, out=data)
        if isinstance(op, Stop):
            c = self.containers[op.container.value]
            if c.spec.role in self.fail_stop_roles:
                return _result(op.op_name, argv, rc=None, timed_out=True)
            c.state, c.exit_code = "exited", 137
            return _result(op.op_name, argv)
        if isinstance(op, ForceRemove):
            c = self.containers[op.container.value]
            if c.spec.role in self.fail_force_roles:
                return _result(op.op_name, argv, rc=1, err=b"Error: daemon unavailable")
            del self.containers[op.container.value]
            self.removed.append(op.container.value)
            return _result(op.op_name, argv)
        if isinstance(op, Remove):
            c = self.containers[op.container.value]
            if c.spec.role in self.fail_remove_roles:
                return _result(op.op_name, argv, rc=1, err=b"Error: removal failed")
            if c.state == "running":
                return _result(op.op_name, argv, rc=1, err=b"cannot remove running container")
            del self.containers[op.container.value]
            self.removed.append(op.container.value)
            return _result(op.op_name, argv)
        if isinstance(op, SnapshotList):
            self._snapshots_taken += 1
            rows = json.loads(json.dumps(SNAPSHOT_ROWS))
            if self._snapshots_taken > len(SNAPSHOT_ROWS) and self.snapshot_after_mutator:
                self.snapshot_after_mutator(rows)
            return _result(op.op_name, argv, out=b"\n".join(json.dumps(r).encode() for r in rows[op.kind]))
        raise AssertionError(f"unexpected op {op}")


def good_streams(nonce: str = NONCE) -> dict[Role, bytes]:
    progress = [record_line(Role.MEMORY, "progress", nonce, allocated_mib=m) for m in range(320, 1024, 64)]
    return {
        Role.TARGET: obs_stream(Role.TARGET, common_observations(Role.TARGET), nonce=nonce),
        Role.VERIFIER: obs_stream(Role.VERIFIER, common_observations(Role.VERIFIER), nonce=nonce),
        Role.MEMORY: obs_stream(Role.MEMORY, standalone_observations(Role.MEMORY), end=False, nonce=nonce,
                                extra_markers=progress),
        Role.PIDS: obs_stream(Role.PIDS, standalone_observations(Role.PIDS), nonce=nonce),
        Role.CPU: obs_stream(Role.CPU, standalone_observations(Role.CPU), nonce=nonce),
        Role.STORAGE: obs_stream(Role.STORAGE, standalone_observations(Role.STORAGE), nonce=nonce),
        Role.LOGFLOOD: logflood_stream(nonce),
        Role.SLEEPER: record_line(Role.SLEEPER, "start", nonce, pid=1) + b"\n"
        + record_line(Role.SLEEPER, "sleeping", nonce) + b"\n",
    }
