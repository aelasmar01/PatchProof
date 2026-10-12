"""Pure assessment of observed environment facts for `patchproof doctor`.

`assess` maps `EnvironmentFacts` to checks. It performs no I/O, so every outcome is
unit-tested with synthetic facts. A required check that fails or cannot be determined
makes the report BLOCKED. Doctor never reports isolation as verified: only a separately
authorized `--probe-isolation` run produces that evidence.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Final

from .environment import EnvironmentFacts

# Review-controlled expectations. Each names where it was decided.
SUPPORTED_PYTHON: Final = "3.13.16"  # .python-version; owner approval 2026-10-12 (v0.0 closeout C1)
SUPPORTED_UV: Final = "0.12.24"  # pyproject.toml [tool.uv] required-version
REVIEWED_GIT: Final = (2, 56, 0)  # STATUS.md approval item 3 (needed by PP-005, not v0.0)
DESKTOP_SECURITY_FLOOR: Final = (4, 44, 3)  # CVE-2025-9074 fixed; docs/environment.lock.md 6.5
REQUIRED_NETWORK_DRIVER: Final = "null"  # `--network none` (INV-03)
READINESS_SCOPE: Final = ("v0.0 environment readiness: host, interpreter, Docker runtime, approved probe image, "
                          "and evidence directory. Not isolation, not v0.1+ requirements, not a release acceptance.")

ASSUMPTIONS: Final = (
    "doctor creates no containers and runs no probes; isolation is not verified by this report. "
    "Only `patchproof doctor --probe-isolation`, separately authorized, produces isolation evidence.",
    "The Docker Desktop security floor (4.44.3, CVE-2025-9074) reflects advisories reviewed on 2026-10-11; "
    "doctor does not query advisories online.",
    "Versions are as reported by the tools themselves; doctor does not verify binary signatures.",
    "Docker facts describe the desktop-linux context only; DOCKER_HOST and other contexts are ignored by design.",
    "Evidence-root readiness is a permission check; doctor never creates or repairs the directory.",
)

_VERSION_RE: Final = re.compile(r"(\d+)\.(\d+)\.(\d+)")
_DESKTOP_RE: Final = re.compile(r"^Docker Desktop (\d+)\.(\d+)\.(\d+)\b")


class Status(Enum):
    OK = "OK"
    WARN = "WARN"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


class Overall(Enum):
    READY = "READY"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class Check:
    check_id: str
    title: str
    status: Status
    required: bool
    observed: str
    expected: str
    action: str | None = None

    @property
    def blocks(self) -> bool:
        return self.required and self.status in (Status.FAIL, Status.UNKNOWN)


@dataclass(frozen=True)
class Assessment:
    overall: Overall
    checks: tuple[Check, ...]
    isolation_verified_by_doctor: bool = False


def parse_version(text: str | None) -> tuple[int, int, int] | None:
    match = _VERSION_RE.search(text or "")
    return (int(match[1]), int(match[2]), int(match[3])) if match else None


def desktop_version(platform_name: str | None) -> tuple[int, int, int] | None:
    match = _DESKTOP_RE.match(platform_name or "")
    return (int(match[1]), int(match[2]), int(match[3])) if match else None


def _dotted(version: tuple[int, int, int]) -> str:
    return ".".join(map(str, version))


def _host(f: EnvironmentFacts) -> list[Check]:
    h = f.host
    checks = [
        Check("HOST-01", "Host is macOS", Status.OK if h.system == "Darwin" else Status.FAIL, True,
              f"{h.system} {h.macos_version or ''}".strip(), "Darwin (macOS)"),
        Check("HOST-02", "Host architecture is Intel x86_64", Status.OK if h.machine == "x86_64" else Status.FAIL,
              True, h.machine, "x86_64"),
    ]
    if h.home_git_repository:
        checks.append(Check("HOST-03", "Home directory is not a Git repository", Status.WARN, False,
                            "a .git entry exists in the home directory", "absent",
                            "Owner decision (STATUS.md approval item 4); never run Git writes from the home directory"))
    else:
        checks.append(Check("HOST-03", "Home directory is not a Git repository", Status.OK, False, "absent", "absent"))
    return checks


def _python(f: EnvironmentFacts) -> list[Check]:
    p = f.python
    if p.version == SUPPORTED_PYTHON:
        status, action = Status.OK, None
    elif p.version.startswith("3.13."):
        status, action = Status.WARN, "Run through `uv run patchproof` to use the pinned interpreter"
    else:
        status, action = Status.FAIL, "PatchProof requires Python 3.13 (PROJECT_SPEC.md 3.1)"
    return [Check("PY-01", "Python interpreter is the pinned release", status, True,
                  f"{p.implementation} {p.version} at {p.executable}", SUPPORTED_PYTHON, action)]


def _tools(f: EnvironmentFacts) -> list[Check]:
    checks: list[Check] = []
    uv = parse_version(f.uv.version_output)
    if uv is None:
        checks.append(Check("UV-01", "uv is the pinned version", Status.WARN, False,
                            f.uv.error or "version unreadable", SUPPORTED_UV, "Install uv " + SUPPORTED_UV))
    else:
        checks.append(Check("UV-01", "uv is the pinned version",
                            Status.OK if _dotted(uv) == SUPPORTED_UV else Status.WARN, False,
                            f"{_dotted(uv)} at {f.uv.path}", SUPPORTED_UV,
                            None if _dotted(uv) == SUPPORTED_UV else "pyproject.toml requires uv " + SUPPORTED_UV))
    git = parse_version(f.git.version_output)
    if git is None:
        checks.append(Check("GIT-01", "Git meets the reviewed version", Status.WARN, False,
                            f.git.error or "version unreadable", f">= {_dotted(REVIEWED_GIT)}",
                            "Git is needed from PP-005 (v0.1)"))
    else:
        current = git >= REVIEWED_GIT
        checks.append(Check("GIT-01", "Git meets the reviewed version", Status.OK if current else Status.WARN, False,
                            f"{_dotted(git)} at {f.git.path}", f">= {_dotted(REVIEWED_GIT)}",
                            None if current else "Upgrade needs owner approval (STATUS.md approval item 3); "
                                                 "needed by PP-005, not v0.0"))
    return checks


def _docker(f: EnvironmentFacts) -> list[Check]:
    d = f.docker
    errors = "; ".join(d.errors)
    checks = [Check("DKR-01", "Docker client is in an allowlisted directory",
                    Status.OK if d.binary else Status.FAIL, True, d.binary or errors or "not found",
                    "docker in /usr/local/bin, Docker.app, or /opt/homebrew/bin")]
    if d.binary is None:
        return checks
    endpoint_ok = d.context_endpoint is not None and d.context_endpoint == d.expected_endpoint
    checks.append(Check("DKR-02", "desktop-linux context points at the Docker Desktop user socket",
                        Status.OK if endpoint_ok else (Status.FAIL if d.context_endpoint else Status.UNKNOWN), True,
                        d.context_endpoint or errors or "unreadable", d.expected_endpoint or "unknown"))
    if not endpoint_ok:
        return checks
    reachable = d.server_version is not None
    checks.append(Check("DKR-03", "Docker daemon is reachable", Status.OK if reachable else Status.FAIL, True,
                        f"client {d.client_version or '?'}, server {d.server_version}" if reachable
                        else errors or "no server version", "server responds on desktop-linux",
                        None if reachable else "Start Docker Desktop; doctor never starts or reconfigures it"))
    if not reachable:
        return checks
    desktop = desktop_version(d.platform_name)
    if desktop is None:
        checks.append(Check("DKR-04", "Docker Desktop is at or above the security floor", Status.UNKNOWN, True,
                            d.platform_name or "platform name absent", f">= {_dotted(DESKTOP_SECURITY_FLOOR)}"))
    else:
        safe = desktop >= DESKTOP_SECURITY_FLOOR
        checks.append(Check("DKR-04", "Docker Desktop is at or above the security floor",
                            Status.OK if safe else Status.FAIL, True, _dotted(desktop),
                            f">= {_dotted(DESKTOP_SECURITY_FLOOR)} (CVE-2025-9074)",
                            None if safe else "Upgrade Docker Desktop (owner action); execution is blocked"))
    checks += [
        Check("DKR-05", "Daemon runs Linux on x86_64",
              Status.OK if (d.os_type, d.architecture) == ("linux", "x86_64") else
              (Status.UNKNOWN if d.os_type is None or d.architecture is None else Status.FAIL), True,
              f"{d.os_type}/{d.architecture}", "linux/x86_64"),
        Check("DKR-06", "cgroup v2 is available for resource limits",
              Status.OK if d.cgroup_version == "2" else (Status.UNKNOWN if d.cgroup_version is None else Status.FAIL),
              True, str(d.cgroup_version), "2"),
        Check("DKR-07", "seccomp is active on the daemon",
              Status.OK if any(o.startswith("name=seccomp") for o in d.security_options) else
              (Status.UNKNOWN if not d.security_options else Status.FAIL), True,
              ", ".join(d.security_options) or "none reported", "name=seccomp"),
        Check("DKR-08", "The `none` network driver is available",
              Status.OK if REQUIRED_NETWORK_DRIVER in d.network_drivers else
              (Status.UNKNOWN if not d.network_drivers else Status.FAIL), True,
              ", ".join(d.network_drivers) or "none reported", REQUIRED_NETWORK_DRIVER),
        Check("DKR-09", "Daemon reports no warnings", Status.WARN if d.warnings else Status.OK, False,
              "; ".join(d.warnings)[:200] or "none", "none"),
    ]
    return checks


def _image(f: EnvironmentFacts) -> list[Check]:
    i = f.image
    expected = f"{i.approved_id or 'an approved identity in policy code'} (linux/amd64)"
    if i.approved_id is None:
        return [Check("IMG-01", "Approved probe image is present", Status.FAIL, True, i.error or "none",
                      expected, "A2: an approved image identity requires owner review")]
    if i.present is None:
        return [Check("IMG-01", "Approved probe image is present", Status.UNKNOWN, True,
                      i.error or "not inspected", expected)]
    if not i.present:
        return [Check("IMG-01", "Approved probe image is present", Status.FAIL, True, "not present locally", expected,
                      "Pulling needs owner approval; doctor never pulls")]
    exact = i.observed_id == i.approved_id and (i.os, i.architecture) == ("linux", "amd64")
    return [Check("IMG-01", "Approved probe image is present", Status.OK if exact else Status.FAIL, True,
                  f"{i.observed_id} ({i.os}/{i.architecture})", expected)]


def _evidence(f: EnvironmentFacts) -> list[Check]:
    e = f.evidence_root
    return [Check("EVD-01", "Private probe evidence directory is ready", Status.OK if e.ready else Status.FAIL, True,
                  f"{e.path}: {e.detail}", "exists, owned by this user, mode 0700, not a symlink",
                  None if e.ready else "A3: creating it needs owner approval; doctor never creates it")]


def assess(facts: EnvironmentFacts) -> Assessment:
    checks = tuple(_host(facts) + _python(facts) + _tools(facts) + _docker(facts) + _image(facts) + _evidence(facts))
    overall = Overall.BLOCKED if any(c.blocks for c in checks) else Overall.READY
    return Assessment(overall=overall, checks=checks)


def report_document(facts: EnvironmentFacts, assessment: Assessment) -> dict[str, Any]:
    """The JSON report: observed facts, derived checks, and stated assumptions, kept apart."""
    return {
        "report": "patchproof-doctor",
        "overall": assessment.overall.value,
        "scope": READINESS_SCOPE,
        "isolation_verified_by_doctor": assessment.isolation_verified_by_doctor,
        "observed": asdict(facts),
        "checks": [{**asdict(c), "status": c.status.value} for c in assessment.checks],
        "assumptions": list(ASSUMPTIONS),
    }


def render_text(facts: EnvironmentFacts, assessment: Assessment) -> str:
    h, p, d = facts.host, facts.python, facts.docker
    mem = f"{h.memory_bytes / 2**30:.1f} GiB" if h.memory_bytes else "unknown"
    lines = [
        "PatchProof doctor (read-only; no containers, pulls, writes, or setting changes)",
        "",
        "Observed",
        f"  host      {h.system} {h.macos_version or ''} {h.machine}, {h.cpu_count} CPUs, {mem} memory",
        f"  python    {p.implementation} {p.version} ({p.executable})",
        f"  git       {facts.git.version_output or facts.git.error}",
        f"  uv        {facts.uv.version_output or facts.uv.error}",
        f"  docker    {d.binary or 'not found'}; context endpoint {d.context_endpoint or 'unknown'}",
        f"            server {d.server_version or 'unknown'}; platform {d.platform_name or 'unknown'}",
        f"  image     {facts.image.observed_id or facts.image.error or 'not present'}",
        f"  evidence  {facts.evidence_root.path}",
        "",
        "Checks",
    ]
    for c in assessment.checks:
        flag = "" if c.required else " (advisory)"
        lines.append(f"  [{c.status.value:<7}] {c.check_id:<7} {c.title}{flag}")
        if c.status is not Status.OK:
            lines.append(f"            observed: {c.observed}")
            lines.append(f"            expected: {c.expected}")
            if c.action:
                lines.append(f"            action:   {c.action}")
    lines += ["", "Assumptions (not observed)"] + [f"  - {a}" for a in ASSUMPTIONS]
    advisories = sum(1 for c in assessment.checks if c.status is not Status.OK and not c.required)
    lines += ["", f"Overall (v0.0 environment readiness): {assessment.overall.value}, "
                  f"{advisories} advisory warning(s) unresolved.",
              f"Scope: {READINESS_SCOPE}",
              "Isolation: NOT VERIFIED by doctor; `patchproof doctor --probe-isolation` is a separately "
              "authorized active Docker operation."]
    return "\n".join(lines)
