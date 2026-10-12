"""PP-003 owner decisions 2026-10-11: state-based NET-01 and startup-vs-runtime FS-05.

Interface state and traffic counters are supporting observations, not standalone proof
against every possible escape; NET-01 also requires routing, capability, and egress evidence.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any

import pytest
from _fakes import NONCE, common_observations, down_interface, fs05_observation, net01_observation, obs_stream

from patchproof.probes.catalogue import BY_ID
from patchproof.probes.interpret import (
    ContainerFacts,
    Outcome,
    RunFacts,
    judge_container_probe,
    parse_stream,
)
from patchproof.runner.policy import Role

T, V = Role.TARGET, Role.VERIFIER
IMAGE_ENV = ("PATH=/usr/local/bin:/usr/bin:/bin", "GPG_KEY=x", "PYTHON_VERSION=3.13.16", "PYTHON_SHA256=x")
Mutation = Callable[[dict[str, dict[str, Any]]], None]


def facts(mutate: Mutation | None = None, role: Role = T) -> RunFacts:
    f = RunFacts(nonce=NONCE, image_env=IMAGE_ENV)
    for r in (T, V):
        obs = common_observations(r)
        env_keys = sorted([e.split("=", 1)[0] for e in IMAGE_ENV] + ["HOME", "HOSTNAME"])
        obs["FS-05"] = {"keys": sorted(env_keys + ["LC_CTYPE"]), "initial_keys": env_keys,
                        "runtime_only_keys": ["LC_CTYPE"], "lc_ctype_value": "C.UTF-8"}
        if mutate is not None and r is role:
            mutate(obs)
        stream = parse_stream(obs_stream(r, obs), r, NONCE, truncated=False)
        f.containers[r] = ContainerFacts(role=r, created=True, gate_passed=True, started=True, exit_code=0,
                                         oom_killed=False, stream=stream)
    return f


def outcome(probe: str, mutate: Mutation | None = None, role: Role = T) -> tuple[Outcome, str]:
    result = judge_container_probe(BY_ID[probe], facts(mutate, role))
    return result.outcome, result.summary


def iface(name: str, **changes: Any) -> Mutation:
    def apply(obs: dict[str, dict[str, Any]]) -> None:
        obs["NET-01"]["details"][name].update(changes)
    return apply


# ------------------------------------------------------------------- NET-01


@pytest.mark.parametrize("role", [T, V])
def test_fallback_tunnels_down_unaddressed_idle_are_eligible_for_pass(role: Role) -> None:
    result, summary = outcome("NET-01", role=role)
    assert result is Outcome.PASS, summary
    assert "9 other interface(s) down" in summary and 'fb_tunnels_only_for_init_net="0"' in summary


def test_loopback_only_namespace_passes() -> None:
    assert outcome("NET-01", lambda o: o.__setitem__("NET-01", net01_observation(())))[0] is Outcome.PASS


@pytest.mark.parametrize("name,mutate", [
    ("admin UP", iface("gre0", flags="0x81")),
    ("admin UP|RUNNING", iface("sit0", flags="0x1081")),
    ("operstate up", iface("gre0", operstate="up")),
    ("operstate unknown", iface("gre0", operstate="unknown")),
    ("IPv4 address", iface("tunl0", ipv4="10.0.0.2")),
    ("IPv6 address", iface("ip6tnl0", ipv6=["fe800000000000000000000000000001"])),
    ("carrier up", iface("gretap0", carrier="1")),
    ("rx traffic", iface("gre0", rx_bytes=84)),
    ("tx traffic", iface("erspan0", tx_bytes=1)),
])
def test_usable_or_active_non_loopback_interface_fails(name: str, mutate: Mutation) -> None:
    assert outcome("NET-01", mutate)[0] is Outcome.FAIL, name


@pytest.mark.parametrize("name,mutate,expected", [
    ("routes present", lambda o: o.__setitem__("NET-09", {"ipv4_routes": 1, "ipv6_routes_non_lo": 0}), Outcome.FAIL),
    ("egress succeeded", lambda o: o.__setitem__("NET-02", {"attempts": [{"dest": "1.1.1.1:443", "ok": True}]}),
     Outcome.FAIL),
    ("CAP_NET_ADMIN present", lambda o: o["PRV-03"].__setitem__("CapEff", "0000000000001000"), Outcome.FAIL),
    ("bounding set non-empty", lambda o: o["PRV-03"].__setitem__("CapBnd", "00000000a80425fb"), Outcome.FAIL),
    ("routing evidence missing", lambda o: o.pop("NET-09"), Outcome.INCONCLUSIVE),
    ("capability evidence missing", lambda o: o.pop("PRV-03"), Outcome.INCONCLUSIVE),
    ("egress evidence missing", lambda o: o.pop("NET-06"), Outcome.INCONCLUSIVE),
    ("egress ambiguous", lambda o: o.__setitem__("NET-04", {"attempts": [{"name": "x", "ok": False, "errno": "EWEIRD"}]}),
     Outcome.INCONCLUSIVE),
])
def test_routing_capability_and_egress_corroboration_is_mandatory(name: str, mutate: Mutation,
                                                                  expected: Outcome) -> None:
    assert outcome("NET-01", mutate)[0] is expected, name


def test_verifier_requires_its_own_egress_evidence() -> None:
    assert outcome("NET-01", lambda o: o.pop("NET-07"), role=V)[0] is Outcome.INCONCLUSIVE


@pytest.mark.parametrize("name,mutate", [
    ("details missing", lambda o: o["NET-01"].pop("details")),
    ("one interface undescribed", lambda o: o["NET-01"]["details"].pop("gre0")),
    ("extra described interface", lambda o: o["NET-01"]["details"].__setitem__("ghost0", down_interface())),
    ("flags unreadable", iface("gre0", flags="error:EACCES")),
    ("flags malformed", iface("gre0", flags="down")),
    ("operstate unreadable", iface("gre0", operstate="error:EACCES")),
    ("IPv4 lookup other errno", iface("gre0", ipv4="none:ENODEV")),
    ("IPv4 evidence missing", lambda o: o["NET-01"]["details"]["gre0"].pop("ipv4")),
    ("IPv6 evidence malformed", iface("gre0", ipv6="none")),
    ("carrier unreadable", iface("gre0", carrier="error:EACCES")),
    ("counters missing", iface("gre0", rx_bytes=None)),
    ("counter wrong type", iface("gre0", tx_bytes="0")),
    ("link type unreadable", iface("gre0", type="error:EIO")),
    ("lists contradict", lambda o: o["NET-01"].__setitem__("if_nameindex", ["lo"])),
    ("loopback down", iface("lo", flags="0x8")),
    ("loopback without 127.0.0.1", iface("lo", ipv4="none:EADDRNOTAVAIL")),
    ("no loopback", lambda o: o.__setitem__("NET-01", {k: v for k, v in net01_observation(("gre0",)).items()} | {
        "proc_net_dev": ["gre0"], "if_nameindex": ["gre0"]})),
])
def test_missing_malformed_or_contradictory_diagnostics_never_pass(name: str, mutate: Mutation) -> None:
    result, _ = outcome("NET-01", mutate)
    assert result in (Outcome.FAIL, Outcome.INCONCLUSIVE, Outcome.ERROR), name


def test_interface_names_alone_cannot_determine_the_outcome() -> None:
    # A familiar fallback name that is UP fails; an arbitrary name that is down and idle does not.
    assert outcome("NET-01", iface("gre0", flags="0x81"))[0] is Outcome.FAIL
    renamed = net01_observation(("weird-dev7",))
    assert outcome("NET-01", lambda o: o.__setitem__("NET-01", renamed))[0] is Outcome.PASS
    names_only = {"proc_net_dev": renamed["proc_net_dev"], "if_nameindex": renamed["if_nameindex"]}
    assert outcome("NET-01", lambda o: o.__setitem__("NET-01", names_only))[0] is Outcome.FAIL


# ------------------------------------------------------------------- FS-05


def fs05(**changes: Any) -> Mutation:
    def apply(obs: dict[str, dict[str, Any]]) -> None:
        obs["FS-05"].update(changes)
    return apply


BASE_KEYS = sorted(["PATH", "GPG_KEY", "PYTHON_VERSION", "PYTHON_SHA256", "HOME", "HOSTNAME"])


@pytest.mark.parametrize("value", ["C.UTF-8", "C.utf8"])
def test_approved_startup_env_with_python_added_lc_ctype_passes(value: str) -> None:
    result, summary = outcome("FS-05", fs05(lc_ctype_value=value))
    assert result is Outcome.PASS and f"LC_CTYPE={value}" in summary and "absent at startup" in summary


def test_no_coercion_also_passes() -> None:
    assert outcome("FS-05", lambda o: o.__setitem__("FS-05", {
        "keys": BASE_KEYS, "initial_keys": BASE_KEYS, "runtime_only_keys": [], "lc_ctype_value": None}))[0] is \
        Outcome.PASS


@pytest.mark.parametrize("extra", ["AWS_SECRET_ACCESS_KEY", "SSH_AUTH_SOCK", "PYTHONPATH", "PYTHONSTARTUP",
                                   "LD_PRELOAD", "LANG", "LC_ALL"])
def test_unexpected_startup_variable_fails(extra: str) -> None:
    initial = sorted(BASE_KEYS + [extra])
    result, summary = outcome("FS-05", fs05(initial_keys=initial, keys=sorted(initial + ["LC_CTYPE"])))
    assert result is Outcome.FAIL and extra in summary


def test_lc_ctype_present_at_startup_fails() -> None:
    initial = sorted(BASE_KEYS + ["LC_CTYPE"])
    assert outcome("FS-05", fs05(initial_keys=initial, keys=initial, runtime_only_keys=[]))[0] is Outcome.FAIL


@pytest.mark.parametrize("extra", ["PYTHONIOENCODING", "LC_ALL", "AWS_PROFILE"])
def test_runtime_only_unexpected_variable_fails(extra: str) -> None:
    keys = sorted(BASE_KEYS + ["LC_CTYPE", extra])
    assert outcome("FS-05", fs05(keys=keys, runtime_only_keys=sorted(["LC_CTYPE", extra])))[0] is Outcome.FAIL


@pytest.mark.parametrize("value", ["UTF-8", "en_US.UTF-8", "C", "POSIX", None, "C.UTF-8 ", 7])
def test_unsupported_lc_ctype_value_fails(value: Any) -> None:
    assert outcome("FS-05", fs05(lc_ctype_value=value))[0] is Outcome.FAIL


@pytest.mark.parametrize("name,mutate", [
    ("initial evidence missing", lambda o: o["FS-05"].pop("initial_keys")),
    ("initial evidence unreadable", fs05(initial_keys=["error:EACCES"])),
    ("initial evidence wrong type", fs05(initial_keys="PATH,HOME")),
    ("runtime-only accounting missing", lambda o: o["FS-05"].pop("runtime_only_keys")),
    ("runtime-only accounting inconsistent", fs05(runtime_only_keys=[])),
    ("initial key vanished at runtime", fs05(keys=sorted(set(BASE_KEYS) - {"GPG_KEY"} | {"LC_CTYPE"}))),
    ("value without key", fs05(keys=BASE_KEYS, runtime_only_keys=[], lc_ctype_value="C.UTF-8")),
])
def test_missing_or_inconsistent_environment_evidence_never_passes(name: str, mutate: Mutation) -> None:
    assert outcome("FS-05", mutate)[0] in (Outcome.FAIL, Outcome.ERROR), name


def test_process_env_contradicting_docker_config_env_fails_closed() -> None:
    initial = [k for k in BASE_KEYS if k != "PYTHON_SHA256"]
    result, summary = outcome("FS-05", fs05(initial_keys=initial, keys=sorted(initial + ["LC_CTYPE"])))
    assert result is Outcome.FAIL and "contradicts Docker Config.Env" in summary


def test_existing_fixture_shape_is_the_approved_contract() -> None:
    obs = fs05_observation()
    assert obs["runtime_only_keys"] == ["LC_CTYPE"] and obs["lc_ctype_value"] == "C.UTF-8"
    assert copy.deepcopy(obs)["initial_keys"] == sorted(obs["initial_keys"])
