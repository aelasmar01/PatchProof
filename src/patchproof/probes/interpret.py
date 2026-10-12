"""Pure interpretation of probe observations (no I/O, no Docker).

Rules that keep a broken harness from looking like isolation:

1. The container reports raw facts; only this module decides PASS or FAIL.
2. A missing, malformed, duplicated, or wrong-nonce observation is never PASS.
3. A container stream without its end marker, cut by the collector cap, or ended by an
   unexpected exit demotes that container's PASS results to INCONCLUSIVE.
4. A NEGATIVE probe whose positive control did not PASS is INCONCLUSIVE, unless it
   observed a failure itself: an observed escape stays FAIL.
5. Unknown errno values are INCONCLUSIVE, not PASS.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Final

from ..runner.policy import (
    ALLOWED_WRITABLE_MOUNTS,
    CEILINGS,
    SHM_SIZE_BYTES,
    CONTAINER_GID,
    CONTAINER_UID,
    LOG_MAX_FILE,
    LOG_MAX_SIZE_BYTES,
    MIB,
    STOP_GRACE_SECONDS,
    Role,
)
from .catalogue import BY_ID, CATALOGUE, Kind, ProbeSpec

MAX_LINE_BYTES: Final = 64 * 1024
MAX_RECORDS_PER_STREAM: Final = 400
STREAM_KINDS: Final = frozenset(
    {"obs", "start", "end", "serving", "sleeping", "flood-start", "flood-end", "progress", "aux-error"}
)
# EAFNOSUPPORT: the address family (e.g. IPv6) does not exist in the namespace at all.
UNREACHABLE: Final = frozenset({"ENETUNREACH", "EHOSTUNREACH", "EADDRNOTAVAIL", "EAFNOSUPPORT"})
ROUTE_EXISTS: Final = frozenset({"ECONNREFUSED", "TIMEOUT", "ECONNRESET", "ECONNABORTED"})
NOT_WRITABLE: Final = frozenset({"EROFS", "EACCES", "EPERM"})
DEFAULT_DEVICES: Final = frozenset(
    {"null", "zero", "full", "random", "urandom", "tty", "console", "pts", "shm", "mqueue", "fd",
     "stdin", "stdout", "stderr", "ptmx", "core"}
)
ZERO_CAPS: Final = "0000000000000000"
# "/" is root-owned (EROFS is returned before EACCES on a read-only mount); /var/tmp is
# world-writable in the image, so only a read-only mount can refuse the write there.
RO_DISCRIMINATING_PATHS: Final = frozenset({"/pp-probe", "/var/tmp/pp-probe"})
LOG_SLACK_BYTES: Final = 256 * 1024
SLEEPER_STOP_SLACK_SECONDS: Final = 15.0
# Observations a container may emit for probes judged host-side from Docker facts.
# The memory container reports RES-02 only when its allocation loop was NOT killed.
HOST_JUDGED_OBSERVATIONS: Final[Mapping[Role, frozenset[str]]] = {Role.MEMORY: frozenset({"RES-02"})}


class Outcome(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"
    BLOCKED = "BLOCKED"
    NOT_RUN = "NOT_RUN"


_SEVERITY: Final = {
    Outcome.PASS: 0, Outcome.NOT_RUN: 1, Outcome.INCONCLUSIVE: 2, Outcome.BLOCKED: 3,
    Outcome.ERROR: 4, Outcome.FAIL: 5,
}


def worst(outcomes: Iterable[Outcome]) -> Outcome:
    items = list(outcomes)
    if not items:
        return Outcome.NOT_RUN
    return max(items, key=lambda o: _SEVERITY[o])


class SuiteStatus(str, Enum):
    ALL_PLANNED_PROBES_PASSED = "ALL_PLANNED_PROBES_PASSED"
    ISOLATION_FAILED = "ISOLATION_FAILED"
    HARNESS_INVALID = "HARNESS_INVALID"
    BLOCKED = "BLOCKED"
    INCOMPLETE = "INCOMPLETE"
    NOT_EXECUTED = "NOT_EXECUTED"


# --- Stream parsing ----------------------------------------------------------------------


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key")
    return dict(pairs)


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-finite number {value}")


def strict_json_line(raw: bytes) -> Any:
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant)


@dataclass
class StreamResult:
    role: Role
    observations: dict[str, dict[str, Any]] = field(default_factory=dict)
    duplicates: set[str] = field(default_factory=set)
    markers: list[dict[str, Any]] = field(default_factory=list)
    malformed_lines: int = 0
    foreign_records: int = 0
    non_json_lines: int = 0
    ended: bool = False
    truncated: bool = False

    def marker(self, kind: str) -> dict[str, Any] | None:
        for record in self.markers:
            if record.get("pp") == kind:
                return record
        return None

    @property
    def integrity_problems(self) -> list[str]:
        problems = []
        if self.truncated:
            problems.append("collector cap truncated the stream")
        if self.malformed_lines:
            problems.append(f"{self.malformed_lines} malformed line(s)")
        if self.foreign_records:
            problems.append(f"{self.foreign_records} record(s) with wrong nonce/role/probe")
        return problems


def parse_stream(stdout: bytes, role: Role, nonce: str, *, truncated: bool) -> StreamResult:
    """Parse one container's stdout. Flood filler lines are tolerated only for LOGFLOOD."""
    result = StreamResult(role=role, truncated=truncated)
    allowed = {s.probe_id for s in CATALOGUE if role in s.roles} | HOST_JUDGED_OBSERVATIONS.get(role, frozenset())
    records = 0
    lines = stdout.split(b"\n")
    if truncated and lines:
        lines = lines[:-1]  # the last line may be cut mid-record
    for raw in lines:
        if not raw.strip():
            continue
        if not raw.startswith(b"{"):
            if role is Role.LOGFLOOD:
                result.non_json_lines += 1
            else:
                result.malformed_lines += 1
            continue
        records += 1
        if len(raw) > MAX_LINE_BYTES or records > MAX_RECORDS_PER_STREAM:
            result.malformed_lines += 1
            continue
        try:
            record = strict_json_line(raw)
        except (ValueError, UnicodeDecodeError):
            result.malformed_lines += 1
            continue
        if not isinstance(record, dict) or record.get("v") != 1 or record.get("pp") not in STREAM_KINDS:
            result.malformed_lines += 1
            continue
        if record.get("nonce") != nonce or record.get("role") != role.value:
            result.foreign_records += 1
            continue
        if record["pp"] != "obs":
            result.markers.append(record)
            if record["pp"] == "end":
                result.ended = True
            continue
        probe = record.get("probe")
        obs = record.get("obs")
        if not isinstance(probe, str) or probe not in allowed or not isinstance(obs, dict):
            result.foreign_records += 1
            continue
        if probe in result.observations:
            result.duplicates.add(probe)
        result.observations[probe] = obs
    return result


# --- Run facts ---------------------------------------------------------------------------


@dataclass
class ContainerFacts:
    role: Role
    created: bool = False
    gate_passed: bool | None = None
    gate_summary: str = ""
    started: bool = False
    exit_code: int | None = None
    oom_killed: bool | None = None
    wait_timed_out: bool = False
    stream: StreamResult | None = None
    inspect: Mapping[str, Any] | None = None
    error: str = ""


@dataclass
class LogFacts:
    uncapped_bytes: int
    uncapped_truncated: bool
    flood_start_present: bool
    flood_end_present: bool
    flood_end_reported_bytes: int | None
    capped_bytes: int
    capped_truncated: bool
    cap_bytes: int


@dataclass
class SleeperFacts:
    sleeping_marker: bool
    deadline_expired: bool
    stop_ok: bool
    stop_seconds: float
    running_after_stop: bool | None
    removed: bool


@dataclass
class PolicyFact:
    cases: list[tuple[str, bool, str]]  # (case, refused, reason)
    docker_calls: int


@dataclass
class CleanupFacts:
    owned_total: int
    owned_removed: int
    owned_details: list[str]
    other_run_refused: bool | None
    other_run_present_after: bool | None
    foreign_refused: bool | None
    foreign_present_after: bool | None
    decoys_removed: int
    decoys_total: int
    owned_forced: int = 0


@dataclass
class RunFacts:
    nonce: str
    image_env: tuple[str, ...] = ()
    containers: dict[Role, ContainerFacts] = field(default_factory=dict)
    host: dict[str, tuple[Outcome, str]] = field(default_factory=dict)  # PRE-*, CLN-05, CLN-06, NS-03...
    policy: dict[str, PolicyFact] = field(default_factory=dict)
    gate_mutations: list[tuple[str, bool]] | None = None  # (mutation, rejected); "" = unmutated
    log: LogFacts | None = None
    sleeper: SleeperFacts | None = None
    cleanup: CleanupFacts | None = None


@dataclass(frozen=True)
class ProbeOutcome:
    probe_id: str
    outcome: Outcome
    summary: str
    roles: tuple[str, ...] = ()


Verdict = tuple[Outcome, str]


# --- Generic helpers ---------------------------------------------------------------------


def _attempt_blocked(a: Any, *, loopback_refusal_ok: bool = False) -> Verdict:
    if not isinstance(a, Mapping):
        return Outcome.ERROR, "attempt record is not an object"
    where = str(a.get("dest") or a.get("name") or a.get("path") or "?")[:80]
    if a.get("ok") is True:
        return Outcome.FAIL, f"{where}: operation succeeded"
    if a.get("ok") is not False:
        return Outcome.ERROR, f"{where}: attempt has no boolean result"
    if "gai" in a:
        return Outcome.PASS, f"{where}: name did not resolve"
    err = a.get("errno")
    if a.get("loopback") and loopback_refusal_ok and err == "ECONNREFUSED":
        return Outcome.PASS, f"{where}: closed port in the container's own namespace"
    if err in UNREACHABLE:
        return Outcome.PASS, f"{where}: {err}"
    if err in ROUTE_EXISTS:
        return Outcome.FAIL, f"{where}: {err} means a route or peer exists"
    return Outcome.INCONCLUSIVE, f"{where}: unexpected errno {err}"


def _all_blocked(attempts: Any, **kw: bool) -> Verdict:
    if not isinstance(attempts, list) or not attempts:
        return Outcome.ERROR, "no attempts recorded"
    verdicts = [_attempt_blocked(a, **kw) for a in attempts]
    outcome = worst(v[0] for v in verdicts)
    bad = [v[1] for v in verdicts if v[0] is not Outcome.PASS]
    return outcome, ("all blocked" if outcome is Outcome.PASS else "; ".join(bad[:4]))


def _errno_is(a: Any, accepted: frozenset[str] | set[str], label: str) -> Verdict:
    if not isinstance(a, Mapping) or not isinstance(a.get("ok"), bool):
        return Outcome.ERROR, f"{label}: no result"
    if a["ok"]:
        return Outcome.FAIL, f"{label}: succeeded"
    err = a.get("errno")
    if err in accepted:
        return Outcome.PASS, f"{label}: {err}"
    if err == "ENOSYS":
        return Outcome.INCONCLUSIVE, f"{label}: ENOSYS cannot distinguish policy from kernel support"
    return Outcome.INCONCLUSIVE, f"{label}: unexpected errno {err}"


def _succeeded(a: Any, label: str) -> Verdict:
    if isinstance(a, Mapping) and a.get("ok") is True:
        return Outcome.PASS, f"{label}: succeeded"
    return Outcome.FAIL, f"{label}: did not succeed ({_short(a)})"


def _combine(*verdicts: Verdict) -> Verdict:
    outcome = worst(v[0] for v in verdicts)
    if outcome is Outcome.PASS:
        return outcome, "; ".join(v[1] for v in verdicts)
    return outcome, "; ".join(v[1] for v in verdicts if v[0] is not Outcome.PASS)


def _short(value: Any) -> str:
    text = json.dumps(value, sort_keys=True, default=str)
    return text if len(text) <= 160 else text[:157] + "..."


def _limits(role: Role) -> Any:
    return CEILINGS[role.limit_class]


# --- Mount classification (FS-04) -------------------------------------------------------

ALLOWED_MOUNTPOINTS: Final = frozenset(
    {"/", "/proc", "/dev", "/dev/pts", "/dev/mqueue", "/dev/shm", "/sys", "/sys/fs/cgroup",
     "/etc/resolv.conf", "/etc/hostname", "/etc/hosts", "/scratch", "/tmp"}
)
MASK_PREFIXES: Final = ("/proc/", "/sys/firmware", "/sys/devices/virtual/powercap")
FORBIDDEN_MOUNT_TEXT: Final = ("/Users", "/host_mnt", "docker.sock", "/run/host-services", "/Volumes",
                               "/mnt/host", "/private/", "/var/run/docker", "/run/desktop")
ETC_BIND_RE: Final = re.compile(r"/containers/[0-9a-f]{64}/(resolv\.conf|hostname|hosts)$")


def _unescape(field: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), field)


def _size_bytes(text: str) -> int | None:
    match = re.fullmatch(r"([0-9]+)([kmg]?)", text.lower())
    if not match:
        return None
    return int(match.group(1)) * {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}[match.group(2)]


def classify_mounts(lines: Sequence[str]) -> tuple[list[str], bool, bool]:
    """Return (problems, root_mount_seen, scratch_tmpfs_seen) for a mountinfo listing."""
    problems: list[str] = []
    root_seen = scratch_seen = False
    for line in lines:
        if " - " not in line:
            problems.append("unparseable mountinfo line")
            continue
        left, right = line.split(" - ", 1)
        lf, rf = left.split(), right.split()
        if len(lf) < 6 or len(rf) < 2:
            problems.append("unparseable mountinfo line")
            continue
        root, mountpoint, options = _unescape(lf[3]), _unescape(lf[4]), lf[5].split(",")
        fstype, source = rf[0], _unescape(rf[1])
        for text in FORBIDDEN_MOUNT_TEXT:
            if text in root or text in source or text in mountpoint:
                problems.append(f"host-path mount at {mountpoint} (root {root[:80]}, source {source[:80]})")
                break
        if mountpoint == "/":
            root_seen = True
            if fstype != "overlay" or "ro" not in options:
                problems.append(f"root mount is {fstype} with options {lf[5]}, not read-only overlay")
        elif mountpoint in ("/scratch", "/tmp"):
            if fstype != "tmpfs" or not {"nosuid", "nodev", "noexec"} <= set(options):
                problems.append(f"{mountpoint} is {fstype} {lf[5]}, not tmpfs nosuid,nodev,noexec")
            elif mountpoint == "/scratch":
                scratch_seen = True
        elif mountpoint == "/dev/shm":
            sizes = [o[5:] for o in (rf[2].split(",") if len(rf) > 2 else []) if o.startswith("size=")]
            limit = _size_bytes(sizes[0]) if sizes else None
            if fstype != "tmpfs" or not {"nosuid", "nodev", "noexec"} <= set(options):
                problems.append(f"/dev/shm is {fstype} {lf[5]}, not tmpfs nosuid,nodev,noexec")
            elif limit is None or limit > SHM_SIZE_BYTES:
                problems.append(f"/dev/shm size {sizes[0] if sizes else 'unbounded'} exceeds {SHM_SIZE_BYTES}")
        elif mountpoint in ("/sys", "/sys/fs/cgroup"):
            if "ro" not in options:
                problems.append(f"{mountpoint} is mounted read-write")
        elif mountpoint in ("/etc/resolv.conf", "/etc/hostname", "/etc/hosts"):
            if not ETC_BIND_RE.search(root) or not root.endswith(mountpoint.rsplit("/", 1)[1]):
                problems.append(f"{mountpoint} bind source {root[:120]} is not a Docker container file")
        elif mountpoint in ALLOWED_MOUNTPOINTS:
            pass
        elif mountpoint.startswith(MASK_PREFIXES):
            masked = "ro" in options or root.endswith("/null")
            if fstype not in ("proc", "tmpfs", "devtmpfs") or not masked:
                problems.append(f"unexpected writable mount under {mountpoint}")
        else:
            problems.append(f"unexpected mount at {mountpoint} ({fstype})")
    return problems, root_seen, scratch_seen


# --- Per-role judges ---------------------------------------------------------------------

RoleJudge = Callable[[Mapping[str, Any], Role, RunFacts], Verdict]


def j_net_p1(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    if o.get("status") == 200 and o.get("nonce_match") is True:
        return Outcome.PASS, f"HTTP 200 with nonce after {o.get('tries')} tries"
    return Outcome.FAIL, f"loopback request failed: {_short(o)}"


def j_net_p2(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    ok = o.get("ok") is True and o.get("echo_match") is True
    return (Outcome.PASS, "UDP loopback echo matched") if ok else (Outcome.FAIL, _short(o))


def j_net_p3(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    addrs = o.get("addresses")
    if o.get("ok") is True and isinstance(addrs, list) and any(a in ("127.0.0.1", "::1") for a in addrs):
        return Outcome.PASS, "localhost resolves to loopback"
    return Outcome.FAIL, _short(o)


IFF_UP: Final = 0x1
MAX_INTERFACES: Final = 32
# Egress observations that must show every prohibited attempt blocked, per role.
EGRESS_PROBES: Final[Mapping[Role, tuple[str, ...]]] = {
    Role.TARGET: ("NET-02", "NET-03", "NET-04", "NET-05", "NET-06"),
    Role.VERIFIER: ("NET-07",),
}


def _int_field(value: Any, base: int = 10) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value and not value.startswith("error:"):
        try:
            return int(value, base)
        except ValueError:
            return None
    return None


def _interface_problem(name: str, d: Any) -> str | None:
    """Why a NON-loopback interface is not shown to be unusable. None = down, unaddressed, idle."""
    if not isinstance(d, Mapping):
        return f"{name}: no state diagnostics"
    flags = _int_field(d.get("flags"), 16)
    if flags is None:
        return f"{name}: flags unreadable ({_short(d.get('flags'))})"
    if flags & IFF_UP:
        return f"{name}: administratively UP (flags {d.get('flags')})"
    if d.get("operstate") != "down":
        return f"{name}: operational state {_short(d.get('operstate'))}, not down"
    ipv4 = d.get("ipv4")
    if not isinstance(ipv4, str):
        return f"{name}: IPv4 address evidence missing"
    if ipv4 != "none:EADDRNOTAVAIL":
        return f"{name}: IPv4 {ipv4[:40]} (an address, or unverifiable)"
    ipv6 = d.get("ipv6")
    if not isinstance(ipv6, list):
        return f"{name}: IPv6 address evidence missing"
    if ipv6:
        return f"{name}: IPv6 addresses present"
    carrier = d.get("carrier")
    if carrier not in ("0", "error:EINVAL"):  # EINVAL: carrier is not reported while the link is down
        return f"{name}: carrier {_short(carrier)}"
    rx, tx = d.get("rx_bytes"), d.get("tx_bytes")
    if type(rx) is not int or type(tx) is not int:
        return f"{name}: traffic counters missing"
    if rx or tx:
        return f"{name}: traffic observed (rx {rx}, tx {tx} bytes); review required"
    if _int_field(d.get("type")) is None or _int_field(d.get("mtu")) is None:
        return f"{name}: link type or MTU unreadable"
    return None


def j_net_01(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    """Owner decision 2026-10-11: state-based isolation, not a name list.

    PASS requires: loopback UP with 127.0.0.1; every other interface (whatever its name)
    down, unaddressed, carrier-less and idle; no routes (NET-09); all capability sets
    zero (no CAP_NET_ADMIN); every egress attempt blocked. Unverifiable state FAILS.
    Interface state and counters are supporting observations, not proof against every escape.
    """
    a, b = o.get("proc_net_dev"), o.get("if_nameindex")
    if not isinstance(a, list) or not isinstance(b, list) or not all(isinstance(x, str) for x in a + b):
        return Outcome.ERROR, "interface lists missing"
    if sorted(a) != sorted(b):
        return Outcome.FAIL, f"contradictory interface lists: /proc/net/dev {sorted(a)} vs if_nameindex {sorted(b)}"
    names = sorted(set(a))
    others = [n for n in names if n != "lo"]
    if "lo" not in names or len(names) > MAX_INTERFACES:
        return Outcome.FAIL, f"interface set unexpected: {names[:12]}"
    details = o.get("details")
    if not isinstance(details, Mapping):
        if others:
            return Outcome.FAIL, (f"non-loopback interfaces present without the required state evidence: {others}")
        return Outcome.FAIL, "loopback state evidence missing"
    if set(details) != set(names):
        uncovered = sorted(set(details) ^ set(names))
        return Outcome.FAIL, f"diagnostics do not cover exactly the interfaces seen: {uncovered}"
    lo = details["lo"]
    lo_flags = _int_field(lo.get("flags"), 16) if isinstance(lo, Mapping) else None
    lo_ipv4 = lo.get("ipv4") if isinstance(lo, Mapping) else None
    if lo_flags is None or not lo_flags & IFF_UP or lo_ipv4 != "127.0.0.1":
        return Outcome.FAIL, f"loopback not UP with 127.0.0.1: {_short(lo)}"
    problems = [p for n in others if (p := _interface_problem(n, details[n]))]
    if problems:
        return Outcome.FAIL, "; ".join(problems[:4])
    # Same-container corroboration: routing, privileges, egress.
    cf = f.containers.get(r)
    sibling = cf.stream.observations if cf is not None and cf.stream is not None else {}
    routes = sibling.get("NET-09")
    if not isinstance(routes, Mapping):
        return Outcome.INCONCLUSIVE, "routing evidence (NET-09) missing"
    v4, v6 = routes.get("ipv4_routes"), routes.get("ipv6_routes_non_lo")
    if type(v4) is not int or type(v6) is not int:
        return Outcome.INCONCLUSIVE, "routing evidence malformed"
    if v4 or v6:
        return Outcome.FAIL, f"routes present ({v4} IPv4, {v6} non-lo IPv6)"
    caps = sibling.get("PRV-03")
    if not isinstance(caps, Mapping):
        return Outcome.INCONCLUSIVE, "capability evidence (PRV-03) missing"
    if any(caps.get(k) != ZERO_CAPS for k in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")):
        return Outcome.FAIL, "capabilities present; the container could configure networking"
    for probe in EGRESS_PROBES.get(r, ()):
        egress = sibling.get(probe)
        if not isinstance(egress, Mapping) or "probe_error" in egress:
            return Outcome.INCONCLUSIVE, f"egress evidence ({probe}) missing"
        judged = ROLE_JUDGES[probe](egress, r, f)
        if judged[0] is Outcome.FAIL:
            return Outcome.FAIL, f"prohibited egress not blocked ({probe}): {judged[1]}"
        if judged[0] is not Outcome.PASS:
            return Outcome.INCONCLUSIVE, f"egress evidence ({probe}) not conclusive: {judged[1]}"
    fb = o.get("fb_tunnels_only_for_init_net")
    return Outcome.PASS, (f"lo UP; {len(others)} other interface(s) down, unaddressed, carrier-less, idle "
                          f"({', '.join(others[:10]) or 'none'}); 0 routes; no capabilities; egress blocked; "
                          f"fb_tunnels_only_for_init_net={_short(fb)}")


def j_net_09(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    v4, v6 = o.get("ipv4_routes"), o.get("ipv6_routes_non_lo")
    if type(v4) is not int or type(v6) is not int:
        return Outcome.ERROR, "route counts missing"
    if v4 == 0 and v6 == 0:
        return Outcome.PASS, "no routes beyond loopback"
    return Outcome.FAIL, f"{v4} IPv4 route(s), {v6} non-lo IPv6 route(s)"


def j_attempts(key: str = "attempts", **kw: bool) -> RoleJudge:
    def judge(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
        return _all_blocked(o.get(key), **kw)
    return judge


def j_net_07(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    return _combine(
        _all_blocked(o.get("tcp4")), _all_blocked(o.get("tcp6")), _all_blocked(o.get("dns")),
        _all_blocked(o.get("udp")), _all_blocked(o.get("engine"), loopback_refusal_ok=True),
    )


def j_fs_p1(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    targets = o.get("targets")
    if not isinstance(targets, Mapping) or set(targets) != {"/scratch", "/tmp"}:
        return Outcome.ERROR, "scratch results missing"
    bad = [k for k, v in targets.items() if not (isinstance(v, Mapping) and v.get("ok") and v.get("match"))]
    return (Outcome.PASS, "scratch and /tmp writable") if not bad else (Outcome.FAIL, f"not writable: {bad}")


def j_fs_p2(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    n = o.get("own_marker_found")
    return (Outcome.PASS, f"own marker found {n}x") if type(n) is int and n >= 1 else (Outcome.FAIL, _short(o))


def j_fs_p3(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    ok = o.get("own_socket_detected") is True
    return (Outcome.PASS, "own socket detected") if ok else (Outcome.FAIL, "scan did not detect a known socket")


def j_fs_01(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    attempts = o.get("attempts")
    if not isinstance(attempts, list) or not attempts or not all(isinstance(a, Mapping) for a in attempts):
        return Outcome.ERROR, "no write attempts"
    # ENOENT means the parent directory is absent from the image; it says nothing about RO.
    relevant = [a for a in attempts if a.get("errno") != "ENOENT"]
    paths = {a.get("path") for a in relevant}
    if not RO_DISCRIMINATING_PATHS <= paths:
        return Outcome.INCONCLUSIVE, f"discriminating paths {sorted(RO_DISCRIMINATING_PATHS - paths)} not tested"
    return _combine(*[_errno_is(a, {"EROFS"}, str(a.get("path"))) for a in relevant])


def j_fs_02(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    paths, found, connects = o.get("paths"), o.get("sockets_found"), o.get("connects")
    if not isinstance(paths, list) or not isinstance(found, list) or not isinstance(connects, list):
        return Outcome.ERROR, "socket observations missing"
    present = [p.get("path") for p in paths if isinstance(p, Mapping) and p.get("exists") is not False]
    connected = [c.get("path") for c in connects if isinstance(c, Mapping) and c.get("ok") is not False]
    problems = []
    if present:
        problems.append(f"socket paths exist: {present}")
    if found:
        problems.append(f"sockets found by scan: {found[:5]}")
    if connected:
        problems.append(f"connect succeeded or unknown: {connected}")
    if o.get("mountinfo_mentions_docker_sock") is not False:
        problems.append("mountinfo mentions docker.sock")
    return (Outcome.FAIL, "; ".join(problems)) if problems else (Outcome.PASS, "no Docker socket reachable")


def j_fs_03(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    if o.get("control_etc_passwd_exists") is not True:
        return Outcome.ERROR, "internal control failed: /etc/passwd not reported present"
    paths = o.get("paths")
    if not isinstance(paths, list) or not paths:
        return Outcome.ERROR, "no host path checks"
    present = [p.get("path") for p in paths if not (isinstance(p, Mapping) and p.get("exists") is False)]
    return (Outcome.FAIL, f"host paths present: {present}") if present else (Outcome.PASS, "no host paths")


def j_fs_04(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    lines = o.get("lines")
    if not isinstance(lines, list) or not all(isinstance(x, str) for x in lines):
        return Outcome.ERROR, "mountinfo missing"
    if o.get("total") != len(lines):
        return Outcome.INCONCLUSIVE, "mountinfo listing was truncated"
    problems, root_seen, scratch_seen = classify_mounts(lines)
    if not root_seen or not scratch_seen:
        return Outcome.ERROR, "internal control failed: root mount or /scratch tmpfs not parsed"
    return (Outcome.FAIL, "; ".join(problems[:6])) if problems else (Outcome.PASS, f"{len(lines)} mounts classified")


# Owner decision 2026-10-11 (FS-05): the only variable that may appear after interpreter
# start is LC_CTYPE set by CPython's PEP 538 locale coercion, with one of these values.
APPROVED_COERCED_LOCALES: Final = frozenset({"C.UTF-8", "C.utf8"})
DOCKER_RUNTIME_KEYS: Final = frozenset({"HOSTNAME", "HOME"})


def _key_list(value: Any) -> list[str] | None:
    if not isinstance(value, list) or len(value) > 128:
        return None
    if not all(isinstance(k, str) and k and not k.startswith("error:") and len(k) <= 128 for k in value):
        return None
    return value


def j_fs_05(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    """Startup environment (/proc/self/environ) vs the approved contract; runtime-only
    additions limited to PEP 538's LC_CTYPE with an approved value (owner decision 2026-10-11)."""
    keys = _key_list(o.get("keys"))
    if keys is None:
        return Outcome.ERROR, "runtime environment keys missing or malformed"
    image_keys = {e.split("=", 1)[0] for e in f.image_env}
    if not image_keys:
        return Outcome.ERROR, "image Env unknown; cannot compare"
    if "PATH" not in keys:
        return Outcome.ERROR, "internal control failed: PATH not visible"
    initial = _key_list(o.get("initial_keys"))
    if initial is None:
        extra = sorted(set(keys) - image_keys - DOCKER_RUNTIME_KEYS)
        return Outcome.FAIL, (f"startup environment evidence missing or unreadable; runtime keys beyond the "
                              f"contract: {extra}")
    missing = sorted(image_keys - set(initial))
    if missing:
        return Outcome.FAIL, f"process startup environment contradicts Docker Config.Env (missing {missing})"
    unexpected = sorted(set(initial) - image_keys - DOCKER_RUNTIME_KEYS)
    if unexpected:
        return Outcome.FAIL, f"unexpected startup environment variables: {unexpected}"
    runtime_only = _key_list(o.get("runtime_only_keys"))
    if runtime_only is None or sorted(runtime_only) != sorted(set(keys) - set(initial)) or \
            not set(initial) <= set(keys):
        return Outcome.FAIL, "inconsistent initial and runtime environment observations"
    if set(runtime_only) - {"LC_CTYPE"}:
        return Outcome.FAIL, f"unexpected runtime-only variables: {sorted(set(runtime_only) - {'LC_CTYPE'})}"
    value = o.get("lc_ctype_value")
    if "LC_CTYPE" in runtime_only:
        if value not in APPROVED_COERCED_LOCALES:
            return Outcome.FAIL, f"runtime LC_CTYPE value {_short(value)} is not an approved UTF-8 locale"
        return Outcome.PASS, (f"startup environment = contract ({sorted(initial)}); LC_CTYPE={value} added after "
                              "start by CPython locale coercion (absent at startup)")
    if value is not None:
        return Outcome.FAIL, "LC_CTYPE value reported without a runtime-only LC_CTYPE key"
    return Outcome.PASS, f"startup environment = contract ({sorted(initial)}); no runtime-only variables"


def j_cross(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    paths, via_proc = o.get("other_marker_paths"), o.get("other_marker_via_proc")
    if not isinstance(paths, list) or not isinstance(via_proc, list):
        return Outcome.ERROR, "cross-check results missing"
    if paths or via_proc:
        return Outcome.FAIL, f"other container's marker visible: {(paths + via_proc)[:4]}"
    if o.get("truncated") is not False:
        return Outcome.INCONCLUSIVE, "filesystem walk truncated"
    return Outcome.PASS, f"other marker not found ({o.get('scanned')} entries scanned)"


def j_fs_10(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    writable = o.get("writable")
    if not isinstance(writable, list) or not all(isinstance(w, str) for w in writable):
        return Outcome.ERROR, "census missing"
    if not {"/scratch", "/tmp"} <= set(writable):
        return Outcome.ERROR, "internal control failed: /scratch or /tmp not found writable"
    extra = sorted(set(writable) - ALLOWED_WRITABLE_MOUNTS)
    if extra:
        return Outcome.FAIL, f"unexpected writable locations: {extra}"
    return Outcome.PASS, f"writable: {sorted(writable)}"


def j_res_14(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    if o.get("present") is False:
        return Outcome.PASS, "/dev/shm not mounted (recorded as absent)"
    if o.get("present") is not True:
        return Outcome.ERROR, "presence not reported"
    written, err = o.get("bytes_written"), o.get("errno")
    if type(written) is not int:
        return Outcome.ERROR, "byte count missing"
    if err is None or written > SHM_SIZE_BYTES:
        return Outcome.FAIL, f"wrote {written} bytes to /dev/shm (bound {SHM_SIZE_BYTES})"
    if err != "ENOSPC":
        return Outcome.INCONCLUSIVE, f"stopped with {err}, not ENOSPC"
    return Outcome.PASS, f"ENOSPC after {written // MIB} MiB (bound {SHM_SIZE_BYTES // MIB} MiB)"


def j_fs_08(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    attempts = o.get("attempts")
    if not isinstance(attempts, list) or not attempts:
        return Outcome.ERROR, "no tunable attempts"
    existing = [a for a in attempts if not (isinstance(a, Mapping) and a.get("errno") == "ENOENT")]
    if not existing:
        return Outcome.INCONCLUSIVE, "none of the probed paths exist"
    return _combine(*[_errno_is(a, NOT_WRITABLE, str(a.get("path") if isinstance(a, Mapping) else "?"))
                      for a in existing])


def j_fs_09(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    found = o.get("found")
    if not isinstance(found, list):
        return Outcome.ERROR, "walk results missing"
    if found:
        return Outcome.FAIL, f"sensitive names present: {found[:6]}"
    if o.get("truncated") is not False:
        return Outcome.INCONCLUSIVE, "walk truncated"
    return Outcome.PASS, f"none found ({o.get('scanned')} entries)"


def j_prv_01(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    ids = [o.get(k) for k in ("uid", "euid", "gid", "egid")]
    groups = o.get("groups")
    if not all(type(i) is int for i in ids) or not isinstance(groups, list):
        return Outcome.ERROR, "internal control failed: identity not reported"
    if ids != [CONTAINER_UID, CONTAINER_UID, CONTAINER_GID, CONTAINER_GID]:
        return Outcome.FAIL, f"identity {ids}"
    if not set(groups) <= {CONTAINER_GID}:
        return Outcome.FAIL, f"supplementary groups {groups}"
    return Outcome.PASS, f"{CONTAINER_UID}:{CONTAINER_GID}, groups {groups}"


def j_prv_p1(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    return _succeeded(o.get("setuid_self"), "setuid(self)")


def j_prv_02(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    return _combine(*[_errno_is(o.get(k), {"EPERM"}, k) for k in ("setuid0", "setgid0", "setgroups0")])


def j_prv_03(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    values = {k: o.get(k) for k in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")}
    if any(not isinstance(v, str) for v in values.values()):
        return Outcome.ERROR, "capability fields missing"
    nonzero = {k: v for k, v in values.items() if v != ZERO_CAPS}
    return (Outcome.FAIL, f"non-zero capability sets {nonzero}") if nonzero else (Outcome.PASS, "all sets zero")


def j_one(key: str, label: str, accept: frozenset[str] | set[str] = frozenset({"EPERM"})) -> RoleJudge:
    def judge(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
        return _errno_is(o.get(key), accept, label)
    return judge


def j_ok(key: str, label: str) -> RoleJudge:
    def judge(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
        return _succeeded(o.get(key), label)
    return judge


def j_prv_06(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    return _combine(_errno_is(o.get("raw_icmp"), {"EPERM", "EACCES"}, "raw ICMP"),
                    _errno_is(o.get("af_packet"), {"EPERM", "EACCES"}, "AF_PACKET"))


def j_prv_07(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    v = o.get("NoNewPrivs")
    if v is None:
        return Outcome.ERROR, "NoNewPrivs missing"
    return (Outcome.PASS, "NoNewPrivs 1") if v == "1" else (Outcome.FAIL, f"NoNewPrivs {v}")


def j_prv_08(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    mode, filters = o.get("Seccomp"), o.get("Seccomp_filters")
    if mode is None:
        return Outcome.ERROR, "Seccomp missing"
    try:
        count = int(str(filters))
    except ValueError:
        count = -1
    if mode == "2" and count >= 1:
        return Outcome.PASS, f"filter mode with {count} filter(s)"
    return Outcome.FAIL, f"Seccomp {mode}, filters {filters}"


def j_prv_p4(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    a, b = o.get("ctypes_getpid"), o.get("os_getpid")
    ok = type(a) is int and a == b and o.get("arch") == "x86_64"
    return (Outcome.PASS, f"ctypes getpid {a}") if ok else (Outcome.FAIL, _short(o))


def j_prv_09(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    if "unsupported_arch" in o:
        return Outcome.INCONCLUSIVE, f"unsupported architecture {o['unsupported_arch']}"
    return _errno_is(o.get("keyctl"), {"EPERM"}, "keyctl")


def _child_ok(o: Mapping[str, Any]) -> Verdict | None:
    if "child_error" in o:
        return Outcome.ERROR, f"forked child failed: {o.get('child_error')}"
    return None


def j_prv_p5(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    ok = o.get("child_ok") is True and o.get("pid_differs") is True
    return (Outcome.PASS, "child result channel works") if ok else (Outcome.FAIL, _short(o))


NAMESPACE_OPS: Final = ("unshare_newns", "unshare_newnet", "unshare_newpid", "unshare_newuser_newns", "setns_mnt")


def j_prv_10(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    verdicts = []
    for name in NAMESPACE_OPS:
        attempt = o.get(name)
        if not isinstance(attempt, Mapping):
            verdicts.append((Outcome.ERROR, f"{name}: no result"))
            continue
        broken = _child_ok(attempt)
        verdicts.append(broken if broken else _errno_is(attempt, {"EPERM"}, name))
    return _combine(*verdicts)


def j_prv_11(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    attempt = o.get("mount_tmpfs")
    if isinstance(attempt, Mapping) and (broken := _child_ok(attempt)):
        return broken
    return _errno_is(attempt, {"EPERM"}, "mount")


# EPERM: refused by seccomp or the kernel; ENOSPC: user.max_user_namespaces is 0.
USERNS_DENIED: Final = frozenset({"EPERM", "ENOSPC"})


def j_prv_13(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    broken = _child_ok(o)
    if broken:
        return broken
    created = o.get("newuser")
    if not isinstance(created, Mapping) or not isinstance(created.get("ok"), bool):
        return Outcome.ERROR, "unshare(CLONE_NEWUSER) result missing"
    if not created["ok"]:
        err = created.get("errno")
        if err in USERNS_DENIED:
            return Outcome.PASS, f"user namespace creation denied ({err}); recorded as observed behavior"
        return Outcome.INCONCLUSIVE, f"unshare(CLONE_NEWUSER) unexpected errno {err}"
    post = o.get("post")
    if not isinstance(post, Mapping):
        return Outcome.ERROR, "user namespace created but follow-up checks missing"
    checks = _combine(*[_errno_is(post.get(k), {"EPERM"}, k) for k in ("sethostname", "mount_tmpfs", "unshare_newns")])
    if checks[0] is Outcome.PASS:
        return Outcome.PASS, ("user namespace creation PERMITTED by the default profile (recorded behavior); "
                              "it grants no privilege over container namespaces: " + checks[1])
    return checks[0], "user namespace permitted and usable: " + checks[1]


def j_prv_12(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    entries = o.get("entries")
    if not isinstance(entries, list) or "null" not in entries:
        return Outcome.ERROR, "internal control failed: /dev listing missing null"
    extra = sorted(set(entries) - DEFAULT_DEVICES)
    return (Outcome.FAIL, f"extra devices: {extra}") if extra else (Outcome.PASS, f"{len(entries)} default entries")


def j_ns_01(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    pids, self_pid = o.get("pids"), o.get("self_pid")
    if not isinstance(pids, list) or self_pid not in pids:
        return Outcome.ERROR, "internal control failed: own PID not in listing"
    if self_pid == 1 and pids == [1]:
        return Outcome.PASS, "probe is PID 1 and alone"
    return Outcome.FAIL, f"self PID {self_pid}, visible PIDs {pids[:10]}"


def j_res_01(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    want = str(_limits(r).memory_bytes)
    mem, swap = o.get("memory_max"), o.get("memory_swap_max")
    if mem == want and swap == "0":
        return Outcome.PASS, f"memory.max {mem}, swap 0"
    return Outcome.FAIL, f"memory.max {mem} (want {want}), memory.swap.max {swap}"


def j_res_03(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    want = str(_limits(r).pids)
    v = o.get("pids_max")
    return (Outcome.PASS, f"pids.max {v}") if v == want else (Outcome.FAIL, f"pids.max {v}, want {want}")


def j_res_05(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    period = 100000
    want = f"{_limits(r).nano_cpus * period // 1_000_000_000} {period}"
    v = o.get("cpu_max")
    return (Outcome.PASS, f"cpu.max {v}") if v == want else (Outcome.FAIL, f"cpu.max {v}, want {want}")


def j_res_p1(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    ok = o.get("ok") is True and o.get("allocated_mib") == 256
    return (Outcome.PASS, "256 MiB allocated") if ok else (Outcome.FAIL, _short(o))


def j_res_p2(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    ok = o.get("ok") is True and o.get("started") == 16
    return (Outcome.PASS, "16 threads started") if ok else (Outcome.FAIL, _short(o))


def j_res_04(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    started, error = o.get("started_threads"), o.get("error")
    if type(started) is not int:
        return Outcome.ERROR, "thread count missing"
    limit = _limits(r).pids
    if error is None:
        return Outcome.FAIL, f"{started} threads started without hitting a limit"
    if started + 1 <= limit:
        return Outcome.PASS, f"creation failed after {started} threads (+1 main) <= {limit}"
    return Outcome.FAIL, f"{started + 1} tasks exceeded pids limit {limit}"


def j_res_p3(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    ratio = o.get("ratio")
    if isinstance(ratio, (int, float)) and ratio >= 0.5:
        return Outcome.PASS, f"single-process ratio {ratio}"
    return Outcome.FAIL, f"measurement control ratio {ratio}"


def j_res_06(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    ratio = o.get("ratio")
    if not isinstance(ratio, (int, float)) or o.get("workers") != 4:
        return Outcome.ERROR, "CPU measurement missing"
    if ratio <= 1.25:
        return Outcome.PASS, f"4 workers ratio {ratio} <= 1.25"
    if ratio >= 1.6:
        return Outcome.FAIL, f"4 workers ratio {ratio}: CPU not bounded to 1"
    return Outcome.INCONCLUSIVE, f"4 workers ratio {ratio} in the ambiguous band"


def j_res_p4(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    return (Outcome.PASS, "exec works") if o.get("returncode") == 0 else (Outcome.FAIL, _short(o))


def j_fill(limit_attr: str) -> RoleJudge:
    def judge(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
        written, err = o.get("bytes_written"), o.get("errno")
        limit = getattr(_limits(r), limit_attr)
        if type(written) is not int:
            return Outcome.ERROR, "byte count missing"
        if err is None:
            return Outcome.FAIL, f"wrote {written} bytes without hitting a limit"
        if written > limit:
            return Outcome.FAIL, f"wrote {written} bytes, above the {limit}-byte limit"
        if err != "ENOSPC":
            return Outcome.INCONCLUSIVE, f"stopped with {err}, not ENOSPC"
        if written < limit // 2:
            return Outcome.INCONCLUSIVE, f"ENOSPC after only {written} bytes"
        return Outcome.PASS, f"ENOSPC after {written // MIB} MiB (limit {limit // MIB} MiB)"
    return judge


def j_res_09(o: Mapping[str, Any], r: Role, f: RunFacts) -> Verdict:
    return _errno_is(o.get("exec_tmp"), {"EACCES"}, "exec from /tmp")


ROLE_JUDGES: Final[Mapping[str, RoleJudge]] = {
    "NET-P1": j_net_p1, "NET-P2": j_net_p2, "NET-P3": j_net_p3, "NET-01": j_net_01, "NET-09": j_net_09,
    "NET-02": j_attempts(), "NET-03": j_attempts(), "NET-04": j_attempts(), "NET-05": j_attempts(),
    "NET-06": j_attempts(loopback_refusal_ok=True), "NET-07": j_net_07,
    "FS-P1": j_fs_p1, "FS-P2": j_fs_p2, "FS-P3": j_fs_p3, "FS-01": j_fs_01, "FS-02": j_fs_02,
    "FS-03": j_fs_03, "FS-04": j_fs_04, "FS-05": j_fs_05, "FS-06": j_cross, "FS-07": j_cross,
    "FS-08": j_fs_08, "FS-09": j_fs_09, "FS-10": j_fs_10, "RES-14": j_res_14,
    "PRV-01": j_prv_01, "PRV-P1": j_prv_p1, "PRV-02": j_prv_02, "PRV-03": j_prv_03,
    "PRV-P2": j_ok("chown_self", "chown(self)"), "PRV-04": j_one("chown_root", "chown(0,0)"),
    "PRV-05": j_one("mknod_char", "mknod"), "PRV-P3": j_ok("tcp_socket", "TCP socket"),
    "PRV-06": j_prv_06, "PRV-07": j_prv_07, "PRV-08": j_prv_08, "PRV-P4": j_prv_p4, "PRV-09": j_prv_09,
    "PRV-P5": j_prv_p5, "PRV-10": j_prv_10, "PRV-11": j_prv_11, "PRV-13": j_prv_13,
    "PRV-12": j_prv_12, "NS-01": j_ns_01,
    "RES-01": j_res_01, "RES-03": j_res_03, "RES-05": j_res_05, "RES-P1": j_res_p1, "RES-P2": j_res_p2,
    "RES-04": j_res_04, "RES-P3": j_res_p3, "RES-06": j_res_06, "RES-P4": j_res_p4,
    "RES-07": j_fill("scratch_bytes"), "RES-08": j_fill("tmp_bytes"), "RES-09": j_res_09,
}

# Container exit expectations: a stream is only complete if it ended this way.
EXPECTED_EXIT: Final[Mapping[Role, int]] = {
    Role.TARGET: 0, Role.VERIFIER: 0, Role.PIDS: 0, Role.CPU: 0, Role.STORAGE: 0, Role.LOGFLOOD: 0,
}


def stream_problems(facts: ContainerFacts) -> list[str]:
    """Why this container's observations cannot support a PASS."""
    problems: list[str] = []
    if not facts.started:
        problems.append("container did not start")
        return problems
    if facts.stream is None:
        return problems + ["no output collected"]
    problems += facts.stream.integrity_problems
    if facts.wait_timed_out:
        problems.append("container exceeded its deadline")
    expected = EXPECTED_EXIT.get(facts.role)
    if expected is not None:
        if facts.exit_code != expected:
            problems.append(f"exit code {facts.exit_code}, expected {expected}")
        if not facts.stream.ended:
            problems.append("end marker missing")
    if facts.oom_killed and facts.role is not Role.MEMORY:
        problems.append("container was OOM-killed")
    return problems


def judge_container_probe(spec: ProbeSpec, facts: RunFacts) -> ProbeOutcome:
    per_role: list[Verdict] = []
    for role in spec.roles:
        cf = facts.containers.get(role)
        if cf is None or not cf.created:
            per_role.append((Outcome.NOT_RUN, f"{role.value}: container not run"))
            continue
        if cf.gate_passed is False:
            per_role.append((Outcome.BLOCKED, f"{role.value}: inspect gate refused start"))
            continue
        if cf.stream is None:
            per_role.append((Outcome.INCONCLUSIVE, f"{role.value}: no output"))
            continue
        if spec.probe_id in cf.stream.duplicates:
            per_role.append((Outcome.ERROR, f"{role.value}: contradictory duplicate observations"))
            continue
        obs = cf.stream.observations.get(spec.probe_id)
        if obs is None:
            per_role.append((Outcome.INCONCLUSIVE, f"{role.value}: no observation"))
            continue
        if "probe_error" in obs:
            per_role.append((Outcome.ERROR, f"{role.value}: probe raised {obs.get('probe_error')}"))
            continue
        outcome, summary = ROLE_JUDGES[spec.probe_id](obs, role, facts)
        problems = stream_problems(cf)
        if outcome is Outcome.PASS and problems:
            outcome, summary = Outcome.INCONCLUSIVE, f"{summary}; stream not trustworthy: {'; '.join(problems)}"
        per_role.append((outcome, f"{role.value}: {summary}"))
    outcome = worst(v[0] for v in per_role)
    return ProbeOutcome(spec.probe_id, outcome, " | ".join(v[1] for v in per_role)[:600],
                        tuple(r.value for r in spec.roles))


# --- Host-side judges --------------------------------------------------------------------


def j_ns_02(facts: RunFacts) -> Verdict:
    t, v = facts.containers.get(Role.TARGET), facts.containers.get(Role.VERIFIER)
    if t is None or v is None or not t.started or not v.started:
        return Outcome.NOT_RUN, "target and verifier did not both run"
    obs = []
    for cf in (t, v):
        if cf is None or cf.stream is None or "NS-02" not in cf.stream.observations:
            return Outcome.INCONCLUSIVE, "namespace observations missing from target or verifier"
        if stream_problems(cf):
            return Outcome.INCONCLUSIVE, f"{cf.role.value} stream not trustworthy"
        obs.append(cf.stream.observations["NS-02"])
    ot, ov = obs
    for key in ("net", "pid", "mnt", "ipc"):
        if not isinstance(ot.get(key), str) or str(ot.get(key)).startswith("error"):
            return Outcome.ERROR, f"namespace {key} unreadable"
        if not isinstance(ov.get(key), str) or str(ov.get(key)).startswith("error"):
            return Outcome.ERROR, f"namespace {key} unreadable"
    if ot["net"] != ov["net"]:
        return Outcome.FAIL, "target and verifier do not share the network namespace (topology unsupported)"
    shared = [k for k in ("pid", "mnt", "ipc") if ot[k] == ov[k]]
    if shared:
        return Outcome.FAIL, f"namespaces unexpectedly shared: {shared}"
    return Outcome.PASS, "net shared; pid, mnt, ipc private"


def _inspect_fields_empty(inspect: Mapping[str, Any] | None, paths: Sequence[str]) -> list[str]:
    bad = []
    for path in paths:
        current: Any = inspect
        for part in path.split("."):
            current = current.get(part) if isinstance(current, Mapping) else None
        if current not in (None, [], {}, False, ""):
            bad.append(f"{path}={_short(current)}")
    return bad


def j_net_08(facts: RunFacts) -> Verdict:
    problems = []
    for role in (Role.TARGET, Role.VERIFIER):
        cf = facts.containers.get(role)
        if cf is None or cf.inspect is None:
            return Outcome.NOT_RUN, f"{role.value} not inspected"
        problems += [f"{role.value} {b}" for b in _inspect_fields_empty(
            cf.inspect, ("HostConfig.PortBindings", "HostConfig.PublishAllPorts", "NetworkSettings.Ports",
                         "Config.ExposedPorts"))]
    return (Outcome.FAIL, "; ".join(problems)) if problems else (Outcome.PASS, "no ports published or exposed")


def j_ns_03(facts: RunFacts) -> Verdict:
    problems = []
    for role in (Role.TARGET, Role.VERIFIER):
        cf = facts.containers.get(role)
        if cf is None or cf.inspect is None:
            return Outcome.NOT_RUN, f"{role.value} not inspected"
        hc = cf.inspect.get("HostConfig")
        if not isinstance(hc, Mapping):
            return Outcome.ERROR, f"{role.value} HostConfig missing"
        expected = {"PidMode": "", "UTSMode": "", "UsernsMode": "", "IpcMode": "private", "CgroupnsMode": "private"}
        problems += [f"{role.value} {k}={hc.get(k)!r}" for k, want in expected.items() if hc.get(k) != want]
    return (Outcome.FAIL, "; ".join(problems)) if problems else (Outcome.PASS, "no host namespaces")


def j_res_10(facts: RunFacts) -> Verdict:
    want = {"Type": "local", "Config": {"max-size": "5m", "max-file": "2", "compress": "false"}}
    inspected = [cf for cf in facts.containers.values() if cf.inspect is not None]
    if not inspected:
        return Outcome.NOT_RUN, "no container inspected"
    bad = []
    for cf in inspected:
        hc = cf.inspect.get("HostConfig") if cf.inspect else None
        if not isinstance(hc, Mapping) or hc.get("LogConfig") != want:
            bad.append(cf.role.value)
    return (Outcome.FAIL, f"log config differs: {bad}") if bad else (Outcome.PASS, f"{len(inspected)} containers")


def j_res_02(facts: RunFacts) -> Verdict:
    cf = facts.containers.get(Role.MEMORY)
    if cf is None or not cf.started or cf.stream is None:
        return Outcome.NOT_RUN, "memory container not run"
    if cf.stream.integrity_problems:
        return Outcome.INCONCLUSIVE, "; ".join(cf.stream.integrity_problems)
    if "RES-02" in cf.stream.observations:
        return Outcome.FAIL, "allocation loop finished without being killed"
    progress = [m.get("allocated_mib") for m in cf.stream.markers if m.get("pp") == "progress"]
    reached = max((p for p in progress if type(p) is int), default=0)
    limit_mib = _limits(Role.MEMORY).memory_bytes // MIB
    if cf.wait_timed_out:
        return Outcome.INCONCLUSIVE, "memory container hit its deadline instead of an OOM kill"
    if cf.oom_killed is True and cf.exit_code == 137 and reached < limit_mib:
        return Outcome.PASS, f"OOM-killed after {reached} MiB (limit {limit_mib} MiB)"
    if reached >= limit_mib:
        return Outcome.FAIL, f"allocated {reached} MiB, at or above the {limit_mib} MiB limit"
    return Outcome.INCONCLUSIVE, f"exit {cf.exit_code}, OOMKilled {cf.oom_killed}, reached {reached} MiB"


def j_res_p5(facts: RunFacts) -> Verdict:
    log = facts.log
    if log is None:
        return Outcome.NOT_RUN, "log flood not run"
    if log.flood_end_present and (log.flood_end_reported_bytes or 0) >= 30 * MIB:
        return Outcome.PASS, f"flood-end retained; {log.flood_end_reported_bytes} bytes written"
    return Outcome.FAIL, "flood did not complete or its end marker was not retained"


def j_res_11(facts: RunFacts) -> Verdict:
    log = facts.log
    if log is None:
        return Outcome.NOT_RUN, "log flood not run"
    bound = LOG_MAX_SIZE_BYTES * LOG_MAX_FILE + LOG_SLACK_BYTES
    if log.uncapped_truncated:
        return Outcome.FAIL, f"retained log exceeded the {log.cap_bytes}-byte collector read cap"
    if log.uncapped_bytes > bound:
        return Outcome.FAIL, f"retained {log.uncapped_bytes} bytes > bound {bound}"
    if log.flood_start_present:
        return Outcome.FAIL, "flood-start marker still retained: rotation did not discard old output"
    return Outcome.PASS, f"retained {log.uncapped_bytes} bytes <= {bound}; oldest output rotated away"


def j_res_12(facts: RunFacts) -> Verdict:
    s = facts.sleeper
    if s is None:
        return Outcome.NOT_RUN, "deadline probe not run"
    if not s.sleeping_marker:
        return Outcome.ERROR, "internal control failed: sleeper never reported running"
    if not s.deadline_expired:
        return Outcome.ERROR, "deadline did not expire; sleeper exited on its own"
    problems = []
    if not s.stop_ok:
        problems.append("stop failed")
    if s.stop_seconds > STOP_GRACE_SECONDS + SLEEPER_STOP_SLACK_SECONDS:
        problems.append(f"stop took {s.stop_seconds}s")
    if s.running_after_stop is not False:
        problems.append("container still running after stop")
    if not s.removed:
        problems.append("container not removed")
    if problems:
        return Outcome.FAIL, "; ".join(problems)
    return Outcome.PASS, f"stopped in {s.stop_seconds}s and removed"


def j_res_13(facts: RunFacts) -> Verdict:
    log = facts.log
    if log is None:
        return Outcome.NOT_RUN, "log flood not run"
    if log.uncapped_bytes <= MIB:
        return Outcome.ERROR, "internal control failed: uncapped log not larger than the 1 MiB test cap"
    if log.capped_bytes <= log.cap_bytes and log.capped_truncated:
        return Outcome.PASS, f"capped read returned {log.capped_bytes} bytes and reported truncation"
    return Outcome.FAIL, f"capped read returned {log.capped_bytes} bytes, truncated={log.capped_truncated}"


def _policy_judge(probe_id: str) -> Callable[[RunFacts], Verdict]:
    def judge(facts: RunFacts) -> Verdict:
        fact = facts.policy.get(probe_id)
        if fact is None or not fact.cases:
            return Outcome.NOT_RUN, "policy refusal not exercised"
        if fact.docker_calls:
            return Outcome.FAIL, f"{fact.docker_calls} Docker call(s) occurred during refusal checks"
        accepted = [c for c, refused, _ in fact.cases if not refused]
        if probe_id == "POL-P1":
            refused = [c for c, ref, _ in fact.cases if ref]
            return (Outcome.FAIL, f"valid request refused: {refused}") if refused else (
                Outcome.PASS, f"{len(fact.cases)} valid request(s) accepted")
        if accepted:
            return Outcome.FAIL, f"accepted: {accepted}"
        return Outcome.PASS, f"{len(fact.cases)} case(s) refused before Docker"
    return judge


def j_pol_05(facts: RunFacts) -> Verdict:
    m = facts.gate_mutations
    if m is None:
        return Outcome.NOT_RUN, "no real inspect available to mutate"
    base = [rejected for name, rejected in m if name == ""]
    if base != [False]:
        return Outcome.ERROR, "internal control failed: unmutated real inspect did not pass the gate"
    missed = [name for name, rejected in m if name and not rejected]
    if missed:
        return Outcome.FAIL, f"gate accepted drifted configuration: {missed}"
    return Outcome.PASS, f"{len(m) - 1} drifted copies rejected; unmutated copy accepted"


def j_pol_06(facts: RunFacts) -> Verdict:
    created = [cf for cf in facts.containers.values() if cf.created]
    if not created:
        return Outcome.NOT_RUN, "no container created"
    failed = [cf.role.value for cf in created if cf.gate_passed is not True]
    started_bad = [cf.role.value for cf in created if cf.started and cf.gate_passed is not True]
    if started_bad:
        return Outcome.FAIL, f"started despite gate result: {started_bad}"
    if failed:
        return Outcome.BLOCKED, f"gate refused: {failed}"
    return Outcome.PASS, f"{len(created)} containers matched the policy before start"


def j_cln(probe_id: str) -> Callable[[RunFacts], Verdict]:
    def judge(facts: RunFacts) -> Verdict:
        c = facts.cleanup
        if c is None:
            return Outcome.NOT_RUN, "cleanup not exercised"
        if probe_id == "CLN-01":
            if c.owned_total and c.owned_removed == c.owned_total:
                forced = f" ({c.owned_forced} needed the verified force-removal fallback)" if c.owned_forced else ""
                return Outcome.PASS, f"{c.owned_removed}/{c.owned_total} removed and confirmed absent{forced}"
            return Outcome.FAIL, f"{c.owned_removed}/{c.owned_total} removed: {'; '.join(c.owned_details[:4])}"
        if probe_id in ("CLN-02", "CLN-03"):
            refused, present = ((c.other_run_refused, c.other_run_present_after) if probe_id == "CLN-02"
                                else (c.foreign_refused, c.foreign_present_after))
            if refused is None:
                return Outcome.NOT_RUN, "decoy not created"
            if refused and present:
                return Outcome.PASS, "refused; decoy still present"
            return Outcome.FAIL, f"refused={refused}, present afterwards={present}"
        if c.decoys_total == 0:
            return Outcome.NOT_RUN, "no decoy was created"
        if c.decoys_removed == c.decoys_total:
            return Outcome.PASS, f"{c.decoys_removed} decoys removed"
        return Outcome.FAIL, f"{c.decoys_removed}/{c.decoys_total} decoys removed"
    return judge


def _host_fact(probe_id: str) -> Callable[[RunFacts], Verdict]:
    def judge(facts: RunFacts) -> Verdict:
        return facts.host.get(probe_id, (Outcome.NOT_RUN, "not executed"))
    return judge


HOST_JUDGES: Final[Mapping[str, Callable[[RunFacts], Verdict]]] = {
    "PRE-01": _host_fact("PRE-01"), "PRE-02": _host_fact("PRE-02"), "PRE-03": _host_fact("PRE-03"),
    "NET-08": j_net_08, "NS-02": j_ns_02, "NS-03": j_ns_03,
    "RES-02": j_res_02, "RES-P5": j_res_p5, "RES-11": j_res_11, "RES-12": j_res_12, "RES-13": j_res_13,
    "RES-10": j_res_10,
    "POL-P1": _policy_judge("POL-P1"), "POL-01": _policy_judge("POL-01"), "POL-02": _policy_judge("POL-02"),
    "POL-03": _policy_judge("POL-03"), "POL-04": _policy_judge("POL-04"), "POL-05": j_pol_05,
    "POL-06": j_pol_06,
    "CLN-01": j_cln("CLN-01"), "CLN-02": j_cln("CLN-02"), "CLN-03": j_cln("CLN-03"), "CLN-04": j_cln("CLN-04"),
    "CLN-05": _host_fact("CLN-05"), "CLN-06": _host_fact("CLN-06"), "RES-15": _host_fact("RES-15"),
}


# --- Whole-suite interpretation ----------------------------------------------------------


def interpret(facts: RunFacts) -> list[ProbeOutcome]:
    """Judge every catalogue probe, then apply positive-control propagation."""
    raw: dict[str, ProbeOutcome] = {}
    for spec in CATALOGUE:
        if spec.probe_id in HOST_JUDGES:
            outcome, summary = HOST_JUDGES[spec.probe_id](facts)
            raw[spec.probe_id] = ProbeOutcome(spec.probe_id, outcome, summary[:600])
        else:
            raw[spec.probe_id] = judge_container_probe(spec, facts)
    final: list[ProbeOutcome] = []
    for spec in CATALOGUE:
        result = raw[spec.probe_id]
        failed_controls = [c for c in spec.controls if raw[c].outcome is not Outcome.PASS]
        if failed_controls and result.outcome is Outcome.PASS:
            result = ProbeOutcome(
                result.probe_id, Outcome.INCONCLUSIVE,
                f"positive control(s) {failed_controls} did not pass; negative result not interpretable",
                result.roles,
            )
        final.append(result)
    return final


def suite_status(outcomes: Sequence[ProbeOutcome]) -> SuiteStatus:
    """Precedence: observed failure > broken harness > blocked > incomplete > passed."""
    if not outcomes or all(o.outcome is Outcome.NOT_RUN for o in outcomes):
        return SuiteStatus.NOT_EXECUTED
    by_id = {o.probe_id: o for o in outcomes}
    if set(by_id) != set(BY_ID):
        return SuiteStatus.INCOMPLETE
    if any(o.outcome is Outcome.FAIL and BY_ID[o.probe_id].kind is not Kind.POSITIVE_CONTROL for o in outcomes):
        return SuiteStatus.ISOLATION_FAILED
    # A control that ran and did not pass means the harness is broken. A control that never
    # ran because the suite was blocked earlier is reported as BLOCKED/INCOMPLETE instead.
    executed_bad = (Outcome.FAIL, Outcome.ERROR, Outcome.INCONCLUSIVE)
    if any(o.outcome in executed_bad and BY_ID[o.probe_id].kind is Kind.POSITIVE_CONTROL for o in outcomes):
        return SuiteStatus.HARNESS_INVALID
    if any(o.outcome is Outcome.BLOCKED for o in outcomes):
        return SuiteStatus.BLOCKED
    if any(o.outcome is not Outcome.PASS for o in outcomes):
        return SuiteStatus.INCOMPLETE
    return SuiteStatus.ALL_PLANNED_PROBES_PASSED
