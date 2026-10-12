"""PatchProof PP-003 in-container isolation probe.

THIS SCRIPT RUNS ONLY INSIDE A PATCHPROOF PROBE CONTAINER. Do not run it on a host:
several probes attempt outbound connections that are expected to fail only because the
container has no network.

The host passes this file's text as `python3 -I -S -B -c <script> <mode> <nonce>`, so no
host path is mounted. It uses the standard library only.

It emits one JSON observation per line on stdout and never decides PASS or FAIL. The
host interprets observations against the fixed expectations (patchproof.probes.interpret).
A missing or malformed observation is therefore never success.
"""

import ctypes
import errno
import fcntl
import http.server
import json
import os
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import urllib.request

SCHEMA = 1
LOOPBACK = ("127.0.0.1", 8080)
WALK_LIMIT = 60000
MAX_TEXT = 256
SENSITIVE_NAMES = frozenset(
    {".git", ".ssh", ".aws", ".docker", ".claude", ".gnupg", ".kube", ".netrc",
     ".git-credentials", "id_rsa", "id_ed25519", "id_ecdsa", "docker.sock", "PatchProof"}
)
HOST_PATHS = ("/Users", "/host_mnt", "/Volumes", "/private", "/mnt/host", "/run/host-services",
              "/root/.ssh", "/root/.aws", "/root/.docker", "/.docker", "/home/user", "/workspace")
SOCKET_PATHS = ("/var/run/docker.sock", "/run/docker.sock", "/run/host-services/docker.proxy.sock",
                "/run/host-services/backend.sock", "/var/run/docker.raw.sock",
                "/run/guest-services/docker.sock")
SOCKET_SCAN_DIRS = ("/run", "/var/run", "/tmp", "/scratch", "/var/tmp")
ROOTFS_WRITE_TARGETS = ("/pp-probe", "/etc/pp-probe", "/usr/pp-probe", "/usr/local/lib/pp-probe",
                        "/var/tmp/pp-probe", "/home/pp-probe", "/opt/pp-probe")
TUNABLES = ("/proc/sys/kernel/hostname", "/proc/sys/net/ipv4/ip_forward", "/proc/sysrq-trigger",
            "/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/pids.max", "/sys/kernel/mm/transparent_hugepage/enabled",
            "/etc/hosts", "/etc/hostname", "/etc/resolv.conf")
TCP_V4 = (("1.1.1.1", 443), ("8.8.8.8", 53), ("9.9.9.9", 443))
TCP_V6 = (("2606:4700:4700::1111", 443), ("2001:4860:4860::8888", 53))
UDP_DESTS = (("8.8.8.8", 53), ("1.1.1.1", 53))
DNS_NAMES = ("example.com", "docker.com")
ENGINE_ADDRS = (("192.168.65.1", 2375), ("192.168.65.7", 2375), ("192.168.65.254", 2375),
                ("172.17.0.1", 2375), ("172.17.0.1", 2376), ("127.0.0.1", 2375))
ENGINE_NAMES = ("host.docker.internal", "gateway.docker.internal", "kubernetes.docker.internal")
CLONE_NEWUSER = 0x10000000
CLONE_NEWNS = 0x00020000
CLONE_NEWNET = 0x40000000
CLONE_NEWPID = 0x20000000
SYS_KEYCTL_X86_64 = 250
KEYCTL_GET_KEYRING_ID = 0
KEY_SPEC_SESSION_KEYRING = -3
MIB = 1024 * 1024

MODE = sys.argv[1] if len(sys.argv) > 1 else ""
NONCE = sys.argv[2] if len(sys.argv) > 2 else ""
_COUNT = 0
_LOCK = threading.Lock()


def emit(probe, **obs):
    global _COUNT
    record = {"pp": "obs", "v": SCHEMA, "nonce": NONCE, "role": MODE, "probe": probe, "obs": obs}
    line = json.dumps(record, sort_keys=True, separators=(",", ":"))
    with _LOCK:
        _COUNT += 1
        sys.stdout.write(line + "\n")
        sys.stdout.flush()


def marker(kind, **extra):
    record = {"pp": kind, "v": SCHEMA, "nonce": NONCE, "role": MODE, **extra}
    with _LOCK:
        sys.stdout.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        sys.stdout.flush()


def clip(text):
    text = str(text)
    return text if len(text) <= MAX_TEXT else text[:MAX_TEXT]


def errname(exc):
    code = getattr(exc, "errno", None)
    if isinstance(code, int):
        return errno.errorcode.get(code, str(code))
    return type(exc).__name__


def attempt(fn):
    try:
        fn()
        return {"ok": True}
    except socket.gaierror as exc:
        return {"ok": False, "gai": clip(exc.args[0] if exc.args else exc)}
    except TimeoutError:
        return {"ok": False, "errno": "TIMEOUT"}
    except OSError as exc:
        return {"ok": False, "errno": errname(exc)}


def guarded(probe, fn):
    """Run one probe; an unexpected exception becomes an error observation, not a pass."""
    try:
        fn()
    except BaseException as exc:  # noqa: BLE001 - report every failure
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        emit(probe, probe_error=type(exc).__name__, detail=clip(exc))


def read_text(path, limit=65536):
    with open(path, "rb") as handle:
        return handle.read(limit).decode("utf-8", "replace")


# --- Network -----------------------------------------------------------------------------


def tcp_connect(host, port, family=socket.AF_INET, timeout=3.0):
    def go():
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
    return go


SIOCGIFADDR = 0x8915
LOCALE_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-@")


def ipv4_address(name):
    """IPv4 address of an interface, or the errno (EADDRNOTAVAIL = no address)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            raw = fcntl.ioctl(sock.fileno(), SIOCGIFADDR, struct.pack("256s", name.encode()[:15]))
            return socket.inet_ntoa(raw[20:24])
        except OSError as exc:
            return "none:" + errname(exc)


def interface_details(names, counters):
    """Diagnostics only (no judgement): state, flags, link type, addresses, traffic counters."""
    ipv6 = {}
    try:
        for line in read_text("/proc/net/if_inet6").splitlines():
            fields = line.split()
            if len(fields) == 6:
                ipv6.setdefault(fields[5], []).append(fields[0])
    except OSError:
        pass
    details = {}
    for name in names[:32]:
        entry = {}
        for attr in ("operstate", "flags", "type", "mtu", "carrier"):
            try:
                entry[attr] = read_text(f"/sys/class/net/{name}/{attr}", 64).strip()
            except OSError as exc:
                entry[attr] = "error:" + errname(exc)
        entry["ipv4"] = ipv4_address(name)
        entry["ipv6"] = ipv6.get(name, [])[:8]
        entry["rx_bytes"], entry["tx_bytes"] = counters.get(name, (None, None))
        details[name] = entry
    return details


def probe_interfaces():
    names, counters = [], {}
    for line in read_text("/proc/net/dev").splitlines()[2:]:
        if ":" in line:
            name, _, rest = line.partition(":")
            name = name.strip()
            names.append(name)
            fields = rest.split()
            if len(fields) >= 9:
                counters[name] = (int(fields[0]), int(fields[8]))
    try:
        fb = read_text("/proc/sys/net/core/fb_tunnels_only_for_init_net", 16).strip()
    except OSError as exc:
        fb = "error:" + errname(exc)
    emit("NET-01", proc_net_dev=sorted(names), if_nameindex=sorted(n for _, n in socket.if_nameindex()),
         details=interface_details(sorted(names), counters), fb_tunnels_only_for_init_net=fb)


def probe_routes():
    v4 = [ln for ln in read_text("/proc/net/route").splitlines()[1:] if ln.strip()]
    v6_non_lo = 0
    try:
        for line in read_text("/proc/net/ipv6_route").splitlines():
            fields = line.split()
            if fields and fields[-1] != "lo":
                v6_non_lo += 1
    except FileNotFoundError:
        pass
    emit("NET-09", ipv4_routes=len(v4), ipv6_routes_non_lo=v6_non_lo)


def probe_udp_loopback():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rx, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as tx:
        rx.bind(("127.0.0.1", 0))
        rx.settimeout(3)
        payload = ("pp-" + NONCE).encode()
        tx.sendto(payload, rx.getsockname())
        data, _ = rx.recvfrom(256)
        emit("NET-P2", ok=True, echo_match=data == payload)


def probe_resolver_localhost():
    try:
        infos = socket.getaddrinfo("localhost", 80, proto=socket.IPPROTO_TCP)
        emit("NET-P3", ok=True, addresses=sorted({i[4][0] for i in infos})[:8])
    except OSError as exc:
        emit("NET-P3", ok=False, errno=errname(exc))


def tcp4_attempts():
    return [{"dest": f"{h}:{p}", **attempt(tcp_connect(h, p))} for h, p in TCP_V4]


def tcp6_attempts():
    return [{"dest": f"[{h}]:{p}", **attempt(tcp_connect(h, p, socket.AF_INET6))} for h, p in TCP_V6]


def dns_attempts():
    out = []
    for name in DNS_NAMES:
        out.append({"name": name, **attempt(lambda n=name: socket.getaddrinfo(n, 443))})
    return out


def udp_attempts():
    out = []
    for host, port in UDP_DESTS:
        def go(h=host, p=port):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(3)
                sock.sendto(b"pp", (h, p))
        out.append({"dest": f"{host}:{port}", **attempt(go)})
    return out


def engine_attempts():
    out = []
    for host, port in ENGINE_ADDRS:
        if host == "127.0.0.1":
            # Loopback here is the container's own namespace; nothing listens on 2375.
            # A refused connection is expected and proves only that the port is closed.
            out.append({"dest": f"{host}:{port}", "loopback": True, **attempt(tcp_connect(host, port))})
            continue
        out.append({"dest": f"{host}:{port}", **attempt(tcp_connect(host, port))})
    for name in ENGINE_NAMES:
        out.append({"name": name, **attempt(lambda n=name: socket.getaddrinfo(n, 2375))})
    return out


def network_suite(prefix_repeat=False):
    guarded("NET-01", probe_interfaces)
    guarded("NET-09", probe_routes)
    if prefix_repeat:
        guarded("NET-07", lambda: emit("NET-07", tcp4=tcp4_attempts(), tcp6=tcp6_attempts(),
                                       dns=dns_attempts(), udp=udp_attempts(), engine=engine_attempts()))
        return
    guarded("NET-P2", probe_udp_loopback)
    guarded("NET-P3", probe_resolver_localhost)
    guarded("NET-02", lambda: emit("NET-02", attempts=tcp4_attempts()))
    guarded("NET-03", lambda: emit("NET-03", attempts=tcp6_attempts()))
    guarded("NET-04", lambda: emit("NET-04", attempts=dns_attempts()))
    guarded("NET-05", lambda: emit("NET-05", attempts=udp_attempts()))
    guarded("NET-06", lambda: emit("NET-06", attempts=engine_attempts()))


# --- Filesystem --------------------------------------------------------------------------


def write_readback(directory, size):
    path = os.path.join(directory, f"pp-rw-{NONCE}")
    payload = os.urandom(size)
    with open(path, "wb") as handle:
        handle.write(payload)
    with open(path, "rb") as handle:
        match = handle.read() == payload
    os.unlink(path)
    return {"ok": True, "match": match}


def probe_scratch_writable():
    results = {}
    for directory in ("/scratch", "/tmp"):
        try:
            results[directory] = write_readback(directory, MIB)
        except OSError as exc:
            results[directory] = {"ok": False, "errno": errname(exc)}
    emit("FS-P1", targets=results)


def probe_rootfs_readonly():
    out = []
    for path in ROOTFS_WRITE_TARGETS:
        def go(p=path):
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
            os.unlink(p)
        out.append({"path": path, **attempt(go)})
    emit("FS-01", attempts=out)


def scan_sockets(dirs, depth=3):
    found = []
    for base in dirs:
        stack = [(base, 0)]
        while stack:
            current, level = stack.pop()
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        try:
                            mode = entry.stat(follow_symlinks=False).st_mode
                        except OSError:
                            continue
                        if stat.S_ISSOCK(mode):
                            found.append(entry.path)
                        elif stat.S_ISDIR(mode) and level < depth:
                            stack.append((entry.path, level + 1))
            except OSError:
                continue
    return sorted(set(found))[:64]


def probe_docker_socket():
    own = f"/scratch/pp-own-{NONCE}.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(own)
        found = scan_sockets(SOCKET_SCAN_DIRS)
        emit("FS-P3", own_socket_detected=own in found)
        foreign = [p for p in found if p != own]
    finally:
        server.close()
        try:
            os.unlink(own)
        except OSError:
            pass
    paths = [{"path": p, "exists": os.path.lexists(p)} for p in SOCKET_PATHS]
    connects = []
    for path in SOCKET_PATHS:
        def go(p=path):
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(2)
                client.connect(p)
        connects.append({"path": path, **attempt(go)})
    mountinfo = read_text("/proc/self/mountinfo")
    emit("FS-02", paths=paths, sockets_found=foreign, connects=connects,
         mountinfo_mentions_docker_sock="docker.sock" in mountinfo)


def probe_host_paths():
    emit("FS-03", paths=[{"path": p, "exists": os.path.lexists(p)} for p in HOST_PATHS],
         control_etc_passwd_exists=os.path.exists("/etc/passwd"))


def probe_mountinfo():
    lines = read_text("/proc/self/mountinfo", 262144).splitlines()
    emit("FS-04", lines=[clip(ln) for ln in lines[:300]], total=len(lines))


def probe_writable_census():
    """Try to create a file at every directory mount point; report where it succeeded."""
    points = set()
    for line in read_text("/proc/self/mountinfo", 262144).splitlines():
        fields = line.split()
        if len(fields) > 4:
            points.add(fields[4].replace("\\040", " "))
    writable, refused = [], {}
    for point in sorted(points):
        if not os.path.isdir(point) or point.startswith(("/proc", "/sys")):
            continue
        path = os.path.join(point, f"pp-census-{NONCE}")
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
            os.unlink(path)
            writable.append(point)
        except OSError as exc:
            refused[point] = errname(exc)
    emit("FS-10", writable=writable, refused=refused)


def probe_env_keys():
    """Keys only. initial_keys is the environment the kernel recorded at exec
    (/proc/self/environ), before interpreter startup could change os.environ (PEP 538)."""
    try:
        with open("/proc/self/environ", "rb") as handle:
            raw = handle.read(65536)
        initial = sorted({e.split(b"=", 1)[0].decode("utf-8", "replace") for e in raw.split(b"\0") if e})
    except OSError as exc:
        initial = ["error:" + errname(exc)]
    runtime = sorted(os.environ.keys())
    lc_ctype = os.environ.get("LC_CTYPE")
    # A locale name is not sensitive; anything else is withheld.
    lc_value = lc_ctype if lc_ctype and len(lc_ctype) <= 32 and set(lc_ctype) <= LOCALE_CHARS else None
    emit("FS-05", keys=runtime[:128], initial_keys=initial[:128],
         runtime_only_keys=sorted(set(runtime) - set(initial))[:32], lc_ctype_value=lc_value)


def probe_tunables():
    out = []
    for path in TUNABLES:
        def go(p=path):
            fd = os.open(p, os.O_WRONLY)  # opened for write only; nothing is written
            os.close(fd)
        out.append({"path": path, **attempt(go)})
    emit("FS-08", attempts=out)


def walk(root, want_names, skip=("/proc", "/sys", "/dev")):
    found, scanned, denied, truncated = [], 0, 0, False
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    scanned += 1
                    if scanned > WALK_LIMIT:
                        truncated = True
                        return found, scanned, denied, truncated
                    if entry.name in want_names:
                        found.append(entry.path)
                    try:
                        if entry.is_dir(follow_symlinks=False) and entry.path not in skip:
                            stack.append(entry.path)
                    except OSError:
                        continue
        except PermissionError:
            denied += 1
        except OSError:
            continue
    return found, scanned, denied, truncated


def probe_sensitive_files():
    found, scanned, denied, truncated = walk("/", SENSITIVE_NAMES)
    emit("FS-09", found=sorted(found)[:50], scanned=scanned, denied=denied, truncated=truncated)


def marker_name(role):
    return f"pp-marker-{role}-{NONCE}"


def write_markers(role):
    for directory in ("/scratch", "/tmp"):
        with open(os.path.join(directory, marker_name(role)), "w") as handle:
            handle.write(NONCE)


def cross_check(own_role, other_role, probe_id):
    own, other = marker_name(own_role), marker_name(other_role)
    found, scanned, denied, truncated = walk("/", {own, other})
    proc_roots = []
    for pid in os.listdir("/proc"):
        if pid.isdigit():
            for sub in ("root", "cwd"):
                try:
                    proc_roots.append(os.path.join("/proc", pid, sub))
                except OSError:
                    pass
    via_proc = []
    for base in proc_roots:
        for directory in ("scratch", "tmp"):
            candidate = os.path.join(base, directory, other)
            try:
                if os.path.lexists(candidate):
                    via_proc.append(candidate)
            except OSError:
                pass
    emit("FS-P2", own_marker_found=sum(1 for p in found if p.endswith(own)), scanned=scanned)
    emit(probe_id, other_marker_paths=sorted(p for p in found if p.endswith(other))[:16],
         other_marker_via_proc=sorted(via_proc)[:16], scanned=scanned, denied=denied, truncated=truncated)


# --- Privileges and namespaces -----------------------------------------------------------


def probe_identity():
    emit("PRV-01", uid=os.getuid(), euid=os.geteuid(), gid=os.getgid(), egid=os.getegid(),
         groups=sorted(os.getgroups()))


def probe_setuid():
    emit("PRV-P1", setuid_self=attempt(lambda: os.setuid(os.getuid())))
    emit("PRV-02", setuid0=attempt(lambda: os.setuid(0)), setgid0=attempt(lambda: os.setgid(0)),
         setgroups0=attempt(lambda: os.setgroups([0])))


def probe_status_fields():
    fields = {}
    for line in read_text("/proc/self/status").splitlines():
        key, _, value = line.partition(":")
        if key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp",
                   "Seccomp_filters"):
            fields[key] = value.strip()
    emit("PRV-03", **{k: fields.get(k) for k in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")})
    emit("PRV-07", NoNewPrivs=fields.get("NoNewPrivs"))
    emit("PRV-08", Seccomp=fields.get("Seccomp"), Seccomp_filters=fields.get("Seccomp_filters"))


def probe_capability_exercise():
    path = f"/scratch/pp-cap-{NONCE}"
    with open(path, "w") as handle:
        handle.write("x")
    emit("PRV-P2", chown_self=attempt(lambda: os.chown(path, os.getuid(), os.getgid())))
    emit("PRV-04", chown_root=attempt(lambda: os.chown(path, 0, 0)))
    os.unlink(path)
    emit("PRV-05", mknod_char=attempt(
        lambda: os.mknod(f"/scratch/pp-dev-{NONCE}", 0o600 | stat.S_IFCHR, os.makedev(1, 3))))
    emit("PRV-P3", tcp_socket=attempt(lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM).close()))
    raw = attempt(lambda: socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP).close())
    packet = attempt(lambda: socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0).close())
    emit("PRV-06", raw_icmp=raw, af_packet=packet)


def libc_call(fn):
    ctypes.set_errno(0)
    result = fn()
    if result == -1:
        code = ctypes.get_errno()
        return {"ok": False, "errno": errno.errorcode.get(code, str(code))}
    return {"ok": True, "result": int(result)}


def in_child(fn):
    """Run fn in a forked child and return its JSON-able result through a pipe."""
    read_end, write_end = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_end)
        try:
            data = json.dumps(fn()).encode()
        except BaseException as exc:  # noqa: BLE001 - report every failure
            data = json.dumps({"child_error": type(exc).__name__, "detail": clip(exc)}).encode()
        try:
            os.write(write_end, data[:60000])
        finally:
            os._exit(0)
    os.close(write_end)
    with os.fdopen(read_end, "rb") as handle:
        raw = handle.read(65536)
    os.waitpid(pid, 0)
    try:
        value = json.loads(raw.decode("utf-8"))
        return value if isinstance(value, dict) else {"child_error": "non-object result"}
    except ValueError:
        return {"child_error": "no result from child"}


def probe_syscalls():
    libc = ctypes.CDLL(None, use_errno=True)
    arch = os.uname().machine
    emit("PRV-P4", ctypes_getpid=int(libc.getpid()), os_getpid=os.getpid(), arch=arch)
    if arch == "x86_64":
        libc.syscall.restype = ctypes.c_long
        emit("PRV-09", keyctl=libc_call(lambda: libc.syscall(
            ctypes.c_long(SYS_KEYCTL_X86_64), ctypes.c_long(KEYCTL_GET_KEYRING_ID),
            ctypes.c_long(KEY_SPEC_SESSION_KEYRING), ctypes.c_long(0))))
    else:
        emit("PRV-09", unsupported_arch=arch)
    parent = os.getpid()
    emit("PRV-P5", **in_child(lambda: {"child_ok": True, "pid_differs": os.getpid() != parent}))

    def unshare(flags):
        return lambda: libc.unshare(ctypes.c_int(flags))

    def setns_mnt():
        fd = os.open("/proc/self/ns/mnt", os.O_RDONLY)
        try:
            return libc.setns(ctypes.c_int(fd), ctypes.c_int(CLONE_NEWNS))
        finally:
            os.close(fd)

    # Each attempt runs in its own forked child, so a permitted namespace change can never
    # alter the probe process or a later probe.
    forbidden = {}
    for name, call in (("unshare_newns", unshare(CLONE_NEWNS)), ("unshare_newnet", unshare(CLONE_NEWNET)),
                       ("unshare_newpid", unshare(CLONE_NEWPID)),
                       ("unshare_newuser_newns", unshare(CLONE_NEWUSER | CLONE_NEWNS)),
                       ("setns_mnt", setns_mnt)):
        forbidden[name] = in_child(lambda c=call: libc_call(c))
    emit("PRV-10", **forbidden)

    target = f"/scratch/pp-mnt-{NONCE}"
    os.mkdir(target)
    try:
        def mount_tmpfs():
            return libc.mount(b"none", target.encode(), b"tmpfs", ctypes.c_ulong(0), None)

        emit("PRV-11", mount_tmpfs=in_child(lambda: libc_call(mount_tmpfs)))

        def userns_then_use_it():
            created = libc_call(unshare(CLONE_NEWUSER))
            result = {"newuser": created}
            if created.get("ok"):
                # Capabilities now exist only inside the new user namespace. They must not
                # act on the container's own UTS or mount namespaces, and seccomp must still
                # refuse new namespaces that need CAP_SYS_ADMIN.
                status = read_text("/proc/self/status")
                cap_eff = next((ln.split(":", 1)[1].strip() for ln in status.splitlines()
                                if ln.startswith("CapEff:")), None)
                result["post"] = {
                    "sethostname": libc_call(lambda: libc.sethostname(b"pp-probe", ctypes.c_size_t(8))),
                    "mount_tmpfs": libc_call(mount_tmpfs),
                    "unshare_newns": libc_call(unshare(CLONE_NEWNS)),
                    "cap_eff_in_new_userns": cap_eff,
                }
            return result

        emit("PRV-13", **in_child(userns_then_use_it))
    finally:
        try:
            os.rmdir(target)
        except OSError:
            pass


def probe_devices():
    emit("PRV-12", entries=sorted(os.listdir("/dev"))[:128])


def probe_processes():
    pids = sorted(int(p) for p in os.listdir("/proc") if p.isdigit())
    emit("NS-01", pids=pids[:64], self_pid=os.getpid(), process_count=len(pids))


def probe_namespaces():
    out = {}
    for name in ("net", "pid", "mnt", "ipc", "uts", "cgroup", "user"):
        try:
            out[name] = os.readlink(f"/proc/self/ns/{name}")
        except OSError as exc:
            out[name] = "error:" + errname(exc)
    emit("NS-02", **out)


def probe_cgroup_config():
    values = {}
    for name in ("memory.max", "memory.swap.max", "pids.max", "cpu.max"):
        try:
            values[name] = read_text(f"/sys/fs/cgroup/{name}", 256).strip()
        except OSError as exc:
            values[name] = "error:" + errname(exc)
    emit("RES-01", memory_max=values["memory.max"], memory_swap_max=values["memory.swap.max"])
    emit("RES-03", pids_max=values["pids.max"])
    emit("RES-05", cpu_max=values["cpu.max"])


def common_suite(network_repeat):
    network_suite(prefix_repeat=network_repeat)
    guarded("FS-P1", probe_scratch_writable)
    guarded("FS-01", probe_rootfs_readonly)
    guarded("FS-02", probe_docker_socket)
    guarded("FS-03", probe_host_paths)
    guarded("FS-04", probe_mountinfo)
    guarded("FS-05", probe_env_keys)
    guarded("FS-10", probe_writable_census)
    guarded("FS-08", probe_tunables)
    guarded("FS-09", probe_sensitive_files)
    guarded("PRV-01", probe_identity)
    guarded("PRV-02", probe_setuid)
    guarded("PRV-03", probe_status_fields)
    guarded("PRV-04", probe_capability_exercise)
    guarded("PRV-09", probe_syscalls)
    guarded("PRV-12", probe_devices)
    guarded("NS-01", probe_processes)
    guarded("NS-02", probe_namespaces)
    guarded("RES-01", probe_cgroup_config)


# --- Modes -------------------------------------------------------------------------------


def mode_target():
    common_suite(network_repeat=False)
    write_markers("target")
    done = threading.Event()

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):  # keep stdout reserved for observations
            pass

        def reply(self, body):
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):  # noqa: N802 - http.server API
            if self.path == "/nonce":
                self.reply("target-" + NONCE)
            elif self.path == "/cross-check":
                guarded("FS-06", lambda: cross_check("target", "verifier", "FS-06"))
                self.reply("checked")
            elif self.path == "/shutdown":
                self.reply("bye")
                done.set()
            else:
                self.send_response(404)
                self.end_headers()

    server = http.server.HTTPServer(LOOPBACK, Handler)
    server.timeout = 0.5
    marker("serving")
    deadline = time.monotonic() + 120
    while not done.is_set() and time.monotonic() < deadline:
        server.handle_request()
    server.server_close()
    marker("end", count=_COUNT, shutdown_requested=done.is_set())


def aux_step(step, fn):
    """Verifier coordination steps. A failure is a diagnostic marker, never an observation."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        marker("aux-error", step=step, detail=clip(exc))


def http_get(path, timeout=5):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(f"http://{LOOPBACK[0]}:{LOOPBACK[1]}{path}", timeout=timeout) as response:
        return response.status, response.read(4096).decode("utf-8", "replace")


def mode_verifier():
    common_suite(network_repeat=True)
    write_markers("verifier")
    status, body, tries = None, "", 0
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        tries += 1
        try:
            status, body = http_get("/nonce")
            break
        except OSError:
            time.sleep(0.5)
    emit("NET-P1", status=status, nonce_match=body == "target-" + NONCE, tries=tries)
    if status == 200:
        aux_step("cross-check-request", lambda: http_get("/cross-check", timeout=60))
    guarded("FS-07", lambda: cross_check("verifier", "target", "FS-07"))
    if status == 200:
        aux_step("shutdown-request", lambda: http_get("/shutdown"))
    marker("end", count=_COUNT)


def mode_memory():
    held = []
    held.append(b"\x01" * (256 * MIB))  # bytes multiplication writes every page
    emit("RES-P1", allocated_mib=256, ok=True)
    held.clear()
    allocated = 0
    while allocated < 1536:
        held.append(b"\x01" * (64 * MIB))
        allocated += 64
        marker("progress", allocated_mib=allocated)
    emit("RES-02", not_killed=True, allocated_mib=allocated)
    marker("end", count=_COUNT)


def mode_pids():
    stop = threading.Event()
    threads = []
    try:
        for _ in range(16):
            thread = threading.Thread(target=stop.wait, daemon=True)
            thread.start()
            threads.append(thread)
        emit("RES-P2", started=16, ok=True)
        error = None
        for _ in range(512):
            try:
                thread = threading.Thread(target=stop.wait, daemon=True)
                thread.start()
                threads.append(thread)
            except RuntimeError as exc:
                error = clip(exc)
                break
        emit("RES-04", started_threads=len(threads), error=error)
    finally:
        stop.set()
        for thread in threads:
            thread.join(timeout=5)
    marker("end", count=_COUNT)


def busy_children(count, seconds):
    children = []
    start = time.monotonic()
    for _ in range(count):
        pid = os.fork()
        if pid == 0:
            end = time.monotonic() + seconds
            x = 0
            while time.monotonic() < end:
                x += 1
            os._exit(0)
        children.append(pid)
    cpu = 0.0
    for pid in children:
        _, _, usage = os.wait4(pid, 0)
        cpu += usage.ru_utime + usage.ru_stime
    wall = time.monotonic() - start
    return {"workers": count, "cpu_seconds": round(cpu, 3), "wall_seconds": round(wall, 3),
            "ratio": round(cpu / wall, 3) if wall > 0 else None}


def mode_cpu():
    guarded("RES-P3", lambda: emit("RES-P3", **busy_children(1, 2.0)))
    guarded("RES-06", lambda: emit("RES-06", **busy_children(4, 3.0)))
    marker("end", count=_COUNT)


def fill(directory):
    written, err = 0, None
    paths = []
    block = b"\x01" * MIB
    try:
        index = 0
        while written < 2048 * MIB:
            path = os.path.join(directory, f"pp-fill-{index}")
            with open(path, "wb") as handle:
                for _ in range(16):
                    handle.write(block)
                    handle.flush()
                    written += MIB
            paths.append(path)
            index += 1
    except OSError as exc:
        err = errname(exc)
    finally:
        for path in paths + [os.path.join(directory, f"pp-fill-{len(paths)}")]:
            try:
                os.unlink(path)
            except OSError:
                pass
    return {"bytes_written": written, "errno": err}


def mode_storage():
    guarded("FS-P1", probe_scratch_writable)
    guarded("RES-P4", lambda: emit("RES-P4", returncode=subprocess.run(
        [sys.executable, "-I", "-S", "-c", "pass"], check=False, timeout=20).returncode))

    def noexec():
        path = f"/tmp/pp-exec-{NONCE}.sh"
        with open(path, "w") as handle:
            handle.write("#!/bin/sh\nexit 0\n")
        os.chmod(path, 0o700)
        try:
            emit("RES-09", exec_tmp=attempt(lambda: subprocess.run([path], check=False, timeout=20)))
        finally:
            os.unlink(path)
    guarded("RES-09", noexec)
    guarded("RES-07", lambda: emit("RES-07", **fill("/scratch")))
    guarded("RES-08", lambda: emit("RES-08", **fill("/tmp")))
    if os.path.isdir("/dev/shm"):
        guarded("RES-14", lambda: emit("RES-14", present=True, **fill("/dev/shm")))
    else:
        emit("RES-14", present=False)
    marker("end", count=_COUNT)


def mode_logflood():
    marker("flood-start")
    line = b"f" * 1023 + b"\n"
    chunk = line * 1024  # 1 MiB
    written = 0
    out = sys.stdout.buffer
    for _ in range(30):
        out.write(chunk)
        written += len(chunk)
    out.flush()
    marker("flood-end", bytes=written)


def mode_sleeper():
    marker("sleeping")
    time.sleep(3600)


MODES = {
    "target": mode_target,
    "verifier": mode_verifier,
    "memory": mode_memory,
    "pids": mode_pids,
    "cpu": mode_cpu,
    "storage": mode_storage,
    "logflood": mode_logflood,
    "sleeper": mode_sleeper,
}


def main():
    if MODE not in MODES or len(NONCE) != 32:
        sys.stderr.write("usage: <mode> <nonce>\n")
        return 2
    marker("start", pid=os.getpid())
    MODES[MODE]()
    return 0


if __name__ == "__main__":
    sys.exit(main())
