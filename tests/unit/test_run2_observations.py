"""PP-003 regression: real observations from A4 run run-cc1e6383d6893c2afe8ab839cc68a08d.

The run's outcome (ISOLATION_FAILED: NET-01 and FS-05) is preserved. Under the revised,
owner-approved checks (2026-10-11) these real observations STILL FAIL, because run 2 did not
capture the interface-state and startup-environment evidence the revised checks require.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

from patchproof.probes.catalogue import BY_ID, load_probe_script
from patchproof.probes.interpret import ContainerFacts, Outcome, RunFacts, judge_container_probe, parse_stream
from patchproof.runner.policy import Role

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "docker-29.8.2-run2-observations.json"
OBS: dict[str, dict[str, Any]] = json.loads(FIXTURE.read_text())["observations"]
IMAGE_ENV = ("PATH=x", "GPG_KEY=x", "PYTHON_VERSION=x", "PYTHON_SHA256=x")  # keys as in Docker Config.Env
NONCE = "c" * 32
FALLBACK_NAMES = {"erspan0", "gre0", "gretap0", "ip6_vti0", "ip6gre0", "ip6tnl0", "ip_vti0", "sit0", "tunl0"}


def facts() -> RunFacts:
    f = RunFacts(nonce=NONCE, image_env=IMAGE_ENV)
    for role_name, obs in OBS.items():
        role = Role(role_name)
        lines = [json.dumps({"pp": "obs", "v": 1, "nonce": NONCE, "role": role.value, "probe": p, "obs": o})
                 for p, o in obs.items()]
        lines.append(json.dumps({"pp": "end", "v": 1, "nonce": NONCE, "role": role.value}))
        stream = parse_stream("\n".join(lines).encode(), role, NONCE, truncated=False)
        f.containers[role] = ContainerFacts(role=role, created=True, gate_passed=True, started=True, exit_code=0,
                                            oom_killed=False, stream=stream)
    return f


def judge(probe_id: str) -> Any:
    return judge_container_probe(BY_ID[probe_id], facts())


def test_real_interface_list_is_loopback_plus_kernel_fallback_tunnels() -> None:
    for role in ("target", "verifier"):
        names = set(OBS[role]["NET-01"]["proc_net_dev"])
        assert names == {"lo"} | FALLBACK_NAMES
        assert set(OBS[role]["NET-01"]["if_nameindex"]) == names


def test_net01_still_fails_on_real_run2_data_for_missing_state_evidence() -> None:
    result = judge("NET-01")
    assert result.outcome is Outcome.FAIL
    assert "gre0" in result.summary and "without the required state evidence" in result.summary


def test_fs05_still_fails_on_real_run2_data_for_missing_startup_evidence() -> None:
    result = judge("FS-05")
    assert result.outcome is Outcome.FAIL
    assert "LC_CTYPE" in result.summary and "startup environment evidence missing" in result.summary
    for role in ("target", "verifier"):
        assert set(OBS[role]["FS-05"]["keys"]) - {"PATH", "GPG_KEY", "PYTHON_VERSION", "PYTHON_SHA256"} == \
            {"HOME", "HOSTNAME", "LC_CTYPE"}


def test_complementary_real_network_evidence_passes() -> None:
    for probe_id in ("NET-09", "NET-02", "NET-03", "NET-05", "NET-07", "PRV-03", "PRV-06"):
        assert judge(probe_id).outcome is Outcome.PASS, probe_id


def test_partial_diagnostics_added_to_real_data_still_fail() -> None:
    script = load_probe_script()
    tree = ast.parse(script)
    strings = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    for needle in ("/proc/self/environ", "/proc/net/if_inet6", "/proc/sys/net/core/fb_tunnels_only_for_init_net"):
        assert needle in strings, needle
    # One interface's state, or startup keys without the runtime-only accounting, is not enough.
    f = facts()
    for role in (Role.TARGET, Role.VERIFIER):
        stream = f.containers[role].stream
        assert stream is not None
        stream.observations["NET-01"]["details"] = {"gre0": {"operstate": "down", "flags": "0x80", "ipv4": "none"}}
        stream.observations["FS-05"]["initial_keys"] = ["GPG_KEY", "HOME", "HOSTNAME", "PATH", "PYTHON_SHA256",
                                                        "PYTHON_VERSION"]
    assert judge_container_probe(BY_ID["NET-01"], f).outcome is Outcome.FAIL
    assert judge_container_probe(BY_ID["FS-05"], f).outcome is Outcome.FAIL
