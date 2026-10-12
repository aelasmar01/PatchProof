"""PP-003: pure interpretation of probe observations. Failures and gaps are never PASS."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from _fakes import IMAGE_ENV, NONCE, common_observations, obs_stream, record_line, sample_mountinfo

from patchproof.probes.catalogue import BY_ID, CATALOGUE, Kind
from patchproof.probes.interpret import (
    HOST_JUDGES,
    ROLE_JUDGES,
    ContainerFacts,
    Outcome,
    ProbeOutcome,
    RunFacts,
    SuiteStatus,
    classify_mounts,
    interpret,
    judge_container_probe,
    parse_stream,
    suite_status,
)
from patchproof.runner.policy import MIB, Role

T, V = Role.TARGET, Role.VERIFIER


def facts_with(target_obs: dict[str, Any] | None = None, verifier_obs: dict[str, Any] | None = None,
               *, exit_code: int = 0, ended: bool = True) -> RunFacts:
    facts = RunFacts(nonce=NONCE, image_env=tuple(IMAGE_ENV))
    for role, obs in ((T, target_obs), (V, verifier_obs)):
        data = obs if obs is not None else common_observations(role)
        stream = parse_stream(obs_stream(role, data, end=ended), role, NONCE, truncated=False)
        facts.containers[role] = ContainerFacts(role=role, created=True, gate_passed=True, started=True,
                                                exit_code=exit_code, oom_killed=False, stream=stream)
    return facts


def judge(probe_id: str, facts: RunFacts) -> Outcome:
    return judge_container_probe(BY_ID[probe_id], facts).outcome


def test_every_probe_has_exactly_one_judge() -> None:
    for spec in CATALOGUE:
        assert (spec.probe_id in ROLE_JUDGES) != (spec.probe_id in HOST_JUDGES) or (
            spec.probe_id in HOST_JUDGES), spec.probe_id
        if spec.roles and spec.probe_id not in HOST_JUDGES:
            assert spec.probe_id in ROLE_JUDGES, spec.probe_id
        if not spec.roles:
            assert spec.probe_id in HOST_JUDGES, spec.probe_id


def test_baseline_synthetic_observations_pass() -> None:
    facts = facts_with()
    for spec in CATALOGUE:
        if spec.probe_id in ROLE_JUDGES and set(spec.roles) <= {T, V}:
            assert judge(spec.probe_id, facts) is Outcome.PASS, spec.probe_id


# Each entry: probe, role, observation that shows the restriction did NOT hold.
ESCAPES: list[tuple[str, Role, dict[str, Any]]] = [
    ("NET-01", T, {"proc_net_dev": ["eth0", "lo"], "if_nameindex": ["eth0", "lo"]}),
    ("NET-09", T, {"ipv4_routes": 1, "ipv6_routes_non_lo": 0}),
    ("NET-02", T, {"attempts": [{"dest": "1.1.1.1:443", "ok": True}]}),
    ("NET-02", T, {"attempts": [{"dest": "1.1.1.1:443", "ok": False, "errno": "TIMEOUT"}]}),
    ("NET-02", T, {"attempts": [{"dest": "1.1.1.1:443", "ok": False, "errno": "ECONNREFUSED"}]}),
    ("NET-03", T, {"attempts": [{"dest": "[::1]:443", "ok": True}]}),
    ("NET-04", T, {"attempts": [{"name": "example.com", "ok": True}]}),
    ("NET-05", T, {"attempts": [{"dest": "8.8.8.8:53", "ok": True}]}),
    ("NET-06", T, {"attempts": [{"dest": "192.168.65.7:2375", "ok": False, "errno": "ECONNREFUSED"}]}),
    ("NET-06", T, {"attempts": [{"dest": "127.0.0.1:2375", "loopback": True, "ok": True}]}),
    ("NET-07", V, {"tcp4": [{"dest": "1.1.1.1:443", "ok": True}], "tcp6": [], "dns": [], "udp": [], "engine": []}),
    ("FS-01", T, {"attempts": [{"path": "/pp-probe", "ok": False, "errno": "EROFS"},
                               {"path": "/var/tmp/pp-probe", "ok": True}]}),
    ("FS-02", T, {"paths": [{"path": "/var/run/docker.sock", "exists": True}], "sockets_found": [],
                  "connects": [], "mountinfo_mentions_docker_sock": False}),
    ("FS-02", T, {"paths": [], "sockets_found": ["/run/host-services/backend.sock"], "connects": [],
                  "mountinfo_mentions_docker_sock": False}),
    ("FS-02", T, {"paths": [], "sockets_found": [], "connects": [],
                  "mountinfo_mentions_docker_sock": True}),
    ("FS-03", T, {"paths": [{"path": "/Users", "exists": True}], "control_etc_passwd_exists": True}),
    ("FS-04", T, {"lines": [*sample_mountinfo(), "700 600 0:60 /Users/me /host rw - virtiofs mount0 rw"],
                  "total": len(sample_mountinfo()) + 1}),
    ("FS-05", T, {"keys": ["HOME", "PATH", "SSH_AUTH_SOCK"]}),
    ("FS-06", T, {"other_marker_paths": ["/scratch/pp-marker-verifier-x"], "other_marker_via_proc": [],
                  "truncated": False}),
    ("FS-07", V, {"other_marker_paths": [], "other_marker_via_proc": ["/proc/7/root/scratch/m"],
                  "truncated": False}),
    ("FS-08", T, {"attempts": [{"path": "/proc/sys/kernel/hostname", "ok": True}]}),
    ("FS-09", T, {"found": ["/workspace/.git"], "scanned": 10, "truncated": False}),
    ("FS-10", T, {"writable": ["/scratch", "/tmp", "/var/tmp"], "refused": {}}),
    ("FS-10", T, {"writable": ["/", "/scratch", "/tmp"], "refused": {}}),
    ("PRV-01", T, {"uid": 0, "euid": 0, "gid": 0, "egid": 0, "groups": [0]}),
    ("PRV-01", T, {"uid": 10001, "euid": 10001, "gid": 10001, "egid": 10001, "groups": [0, 10001]}),
    ("PRV-02", T, {"setuid0": {"ok": True}, "setgid0": {"ok": False, "errno": "EPERM"},
                   "setgroups0": {"ok": False, "errno": "EPERM"}}),
    ("PRV-03", T, {"CapInh": "0" * 16, "CapPrm": "0" * 16, "CapEff": "00000000a80425fb", "CapBnd": "0" * 16,
                   "CapAmb": "0" * 16}),
    ("PRV-04", T, {"chown_root": {"ok": True}}),
    ("PRV-05", T, {"mknod_char": {"ok": True}}),
    ("PRV-06", T, {"raw_icmp": {"ok": True}, "af_packet": {"ok": False, "errno": "EPERM"}}),
    ("PRV-07", T, {"NoNewPrivs": "0"}),
    ("PRV-08", T, {"Seccomp": "0", "Seccomp_filters": "0"}),
    ("PRV-09", T, {"keyctl": {"ok": True, "result": 123}}),
    ("PRV-10", T, {"unshare_newns": {"ok": True, "result": 0}, "unshare_newnet": {"ok": False, "errno": "EPERM"},
                   "unshare_newpid": {"ok": False, "errno": "EPERM"},
                   "unshare_newuser_newns": {"ok": False, "errno": "EPERM"},
                   "setns_mnt": {"ok": False, "errno": "EPERM"}}),
    ("PRV-10", T, {"unshare_newns": {"ok": False, "errno": "EPERM"}, "unshare_newnet": {"ok": False, "errno": "EPERM"},
                   "unshare_newpid": {"ok": False, "errno": "EPERM"},
                   "unshare_newuser_newns": {"ok": True, "result": 0},
                   "setns_mnt": {"ok": False, "errno": "EPERM"}}),
    ("PRV-13", T, {"newuser": {"ok": True, "result": 0},
                   "post": {"sethostname": {"ok": True, "result": 0}, "mount_tmpfs": {"ok": False, "errno": "EPERM"},
                            "unshare_newns": {"ok": False, "errno": "EPERM"}}}),
    ("PRV-13", T, {"newuser": {"ok": True, "result": 0},
                   "post": {"sethostname": {"ok": False, "errno": "EPERM"},
                            "mount_tmpfs": {"ok": False, "errno": "EPERM"},
                            "unshare_newns": {"ok": True, "result": 0}}}),
    ("PRV-11", T, {"mount_tmpfs": {"ok": True, "result": 0}}),
    ("PRV-12", T, {"entries": ["null", "kvm", "fuse"]}),
    ("NS-01", T, {"pids": [1, 25, 90], "self_pid": 1, "process_count": 3}),
    ("NS-01", T, {"pids": [1, 4012], "self_pid": 4012, "process_count": 2}),
    ("RES-01", T, {"memory_max": "max", "memory_swap_max": "max"}),
    ("RES-03", T, {"pids_max": "max"}),
    ("RES-05", T, {"cpu_max": "max 100000"}),
]


@pytest.mark.parametrize("probe_id,role,escape", ESCAPES, ids=[f"{p}-{i}" for i, (p, _, _) in enumerate(ESCAPES)])
def test_escape_observations_fail(probe_id: str, role: Role, escape: dict[str, Any]) -> None:
    t, v = common_observations(T), common_observations(V)
    (t if role is T else v)[probe_id] = escape
    assert judge(probe_id, facts_with(t, v)) is Outcome.FAIL


def test_every_negative_and_configuration_container_probe_has_an_escape_case() -> None:
    covered = {p for p, _, _ in ESCAPES}
    for spec in CATALOGUE:
        if spec.kind in (Kind.NEGATIVE, Kind.CONFIGURATION) and spec.probe_id in ROLE_JUDGES and \
                set(spec.roles) <= {T, V}:
            assert spec.probe_id in covered, spec.probe_id


@pytest.mark.parametrize("probe_id,obs", [
    ("NET-02", {"attempts": [{"dest": "1.1.1.1:443", "ok": False, "errno": "EWEIRD"}]}),
    ("NET-02", {"attempts": []}),
    ("NET-02", {}),
    ("FS-01", {"attempts": [{"path": "/pp-probe", "ok": False, "errno": "EACCES"},
                            {"path": "/var/tmp/pp-probe", "ok": False, "errno": "EROFS"}]}),
    ("FS-01", {"attempts": [{"path": "/home/pp-probe", "ok": False, "errno": "ENOENT"}]}),
    ("PRV-09", {"keyctl": {"ok": False, "errno": "ENOSYS"}}),
    ("PRV-01", {"uid": "10001"}),
    ("FS-06", {"other_marker_paths": [], "other_marker_via_proc": [], "truncated": True}),
    ("FS-09", {"found": [], "truncated": True}),
    ("FS-03", {"paths": [{"path": "/Users", "exists": False}], "control_etc_passwd_exists": False}),
    ("FS-04", {"lines": sample_mountinfo()[:3], "total": 40}),
    ("NS-01", {"pids": [2], "self_pid": 1}),
    ("NET-02", {"probe_error": "OSError", "detail": "boom"}),
    ("NET-02", {"result": "PASS"}),
])
def test_unknown_missing_or_ambiguous_evidence_is_not_pass(probe_id: str, obs: dict[str, Any]) -> None:
    t = common_observations(T)
    t[probe_id] = obs
    assert judge(probe_id, facts_with(t)) in (Outcome.INCONCLUSIVE, Outcome.ERROR)


@pytest.mark.parametrize("obs,outcome,phrase", [
    ({"newuser": {"ok": False, "errno": "EPERM"}}, Outcome.PASS, "denied"),
    ({"newuser": {"ok": False, "errno": "ENOSPC"}}, Outcome.PASS, "denied"),
    ({"newuser": {"ok": True, "result": 0}, "post": {k: {"ok": False, "errno": "EPERM"}
                                                    for k in ("sethostname", "mount_tmpfs", "unshare_newns")}},
     Outcome.PASS, "PERMITTED"),
    ({"newuser": {"ok": False, "errno": "EINVAL"}}, Outcome.INCONCLUSIVE, "unexpected"),
    ({"newuser": {"ok": True, "result": 0}}, Outcome.ERROR, "follow-up"),
    ({"child_error": "OSError"}, Outcome.ERROR, "forked child"),
])
def test_userns_outcome_is_recorded_accurately(obs: dict[str, Any], outcome: Outcome, phrase: str) -> None:
    t = common_observations(T)
    t["PRV-13"] = obs
    result = judge_container_probe(BY_ID["PRV-13"], facts_with(t))
    assert result.outcome is outcome and phrase in result.summary


def test_broken_child_channel_makes_namespace_probes_uninterpretable() -> None:
    t = common_observations(T)
    t["PRV-P5"] = {"child_error": "no result from child"}
    results = {o.probe_id: o for o in interpret(facts_with(t))}
    assert results["PRV-P5"].outcome is Outcome.FAIL
    for pid in ("PRV-10", "PRV-11", "PRV-13"):
        assert results[pid].outcome is Outcome.INCONCLUSIVE, pid
    t = common_observations(T)
    t["PRV-10"] = dict(t["PRV-10"], setns_mnt={"child_error": "OSError"})
    assert judge("PRV-10", facts_with(t)) is Outcome.ERROR


def test_missing_observation_is_inconclusive() -> None:
    t = common_observations(T)
    del t["NET-02"]
    assert judge("NET-02", facts_with(t)) is Outcome.INCONCLUSIVE


# ------------------------------------------------------------------- stream integrity


def test_stream_problems_demote_pass_but_keep_fail() -> None:
    assert judge("NET-01", facts_with(exit_code=1)) is Outcome.INCONCLUSIVE
    assert judge("NET-01", facts_with(ended=False)) is Outcome.INCONCLUSIVE
    t = common_observations(T)
    t["NET-02"] = {"attempts": [{"dest": "1.1.1.1:443", "ok": True}]}
    assert judge("NET-02", facts_with(t, exit_code=1, ended=False)) is Outcome.FAIL


def test_parse_stream_rejects_forgery_and_malformed_lines() -> None:
    good = record_line(T, "obs", probe="NET-01", obs={"proc_net_dev": ["lo"], "if_nameindex": ["lo"]})
    lines = [
        good,
        record_line(T, "obs", nonce="d" * 32, probe="NET-02", obs={}),  # wrong nonce
        record_line(V, "obs", probe="NET-02", obs={}),  # wrong role
        record_line(T, "obs", probe="RES-07", obs={}),  # probe not emitted by this role
        record_line(T, "verdict", result="PASS"),  # unknown kind
        b'{"pp":"obs","v":1,"nonce":"' + NONCE.encode() + b'","role":"target","role":"verifier"}',  # dup key
        b'{"pp":"obs","v":1,"x":NaN}',
        b"PASS: isolation verified",
        b"{" + b"x" * 70000,
    ]
    result = parse_stream(b"\n".join(lines), T, NONCE, truncated=False)
    assert set(result.observations) == {"NET-01"}
    assert result.foreign_records == 3
    assert result.malformed_lines == 5
    assert not result.ended


def test_duplicate_observation_is_contradictory() -> None:
    line = record_line(T, "obs", probe="NET-01", obs={"proc_net_dev": ["lo"], "if_nameindex": ["lo"]})
    stream = parse_stream(line + b"\n" + line + b"\n" + record_line(T, "end") + b"\n", T, NONCE, truncated=False)
    facts = facts_with()
    facts.containers[T].stream = stream
    assert judge("NET-01", facts) is Outcome.ERROR


def test_truncated_stream_drops_partial_last_line_and_is_untrusted() -> None:
    data = obs_stream(T, common_observations(T))
    stream = parse_stream(data[:-40], T, NONCE, truncated=True)
    assert stream.truncated and stream.integrity_problems
    facts = facts_with()
    facts.containers[T].stream = stream
    assert judge("NET-01", facts) is Outcome.INCONCLUSIVE


def test_logflood_filler_is_tolerated_only_for_logflood() -> None:
    assert parse_stream(b"ffff\n", Role.LOGFLOOD, NONCE, truncated=False).malformed_lines == 0
    assert parse_stream(b"ffff\n", T, NONCE, truncated=False).malformed_lines == 1


# ------------------------------------------------------------------- controls and suite status


def test_failed_positive_control_turns_negative_pass_into_inconclusive() -> None:
    v = common_observations(V)
    v["NET-P1"] = {"status": None, "nonce_match": False, "tries": 120}
    results = {o.probe_id: o for o in interpret(facts_with(verifier_obs=v))}
    assert results["NET-P1"].outcome is Outcome.FAIL
    assert results["NET-02"].outcome is Outcome.INCONCLUSIVE
    assert "positive control" in results["NET-02"].summary


def test_failed_control_does_not_hide_an_observed_escape() -> None:
    t, v = common_observations(T), common_observations(V)
    v["NET-P1"] = {"status": None, "nonce_match": False}
    t["NET-02"] = {"attempts": [{"dest": "1.1.1.1:443", "ok": True}]}
    results = {o.probe_id: o for o in interpret(facts_with(t, v))}
    assert results["NET-02"].outcome is Outcome.FAIL


def _all(outcome: Outcome) -> list[ProbeOutcome]:
    return [ProbeOutcome(s.probe_id, outcome, "x") for s in CATALOGUE]


def _with(base: list[ProbeOutcome], probe_id: str, outcome: Outcome) -> list[ProbeOutcome]:
    return [ProbeOutcome(o.probe_id, outcome if o.probe_id == probe_id else o.outcome, "x") for o in base]


def test_suite_status_precedence() -> None:
    passed = _all(Outcome.PASS)
    assert suite_status(passed) is SuiteStatus.ALL_PLANNED_PROBES_PASSED
    assert suite_status(_all(Outcome.NOT_RUN)) is SuiteStatus.NOT_EXECUTED
    assert suite_status(_with(passed, "NET-02", Outcome.FAIL)) is SuiteStatus.ISOLATION_FAILED
    assert suite_status(_with(passed, "NET-P1", Outcome.FAIL)) is SuiteStatus.HARNESS_INVALID
    assert suite_status(_with(passed, "PRE-01", Outcome.BLOCKED)) is SuiteStatus.BLOCKED
    assert suite_status(_with(passed, "RES-06", Outcome.INCONCLUSIVE)) is SuiteStatus.INCOMPLETE
    assert suite_status(_with(passed, "CLN-04", Outcome.NOT_RUN)) is SuiteStatus.INCOMPLETE
    assert suite_status(passed[:-1]) is SuiteStatus.INCOMPLETE
    both = _with(_with(passed, "NET-P1", Outcome.FAIL), "NET-02", Outcome.FAIL)
    assert suite_status(both) is SuiteStatus.ISOLATION_FAILED
    blocked_early = _with(_all(Outcome.NOT_RUN), "PRE-01", Outcome.BLOCKED)
    assert suite_status(blocked_early) is SuiteStatus.BLOCKED


# ------------------------------------------------------------------- mount classification


def test_sample_mounts_classify_clean() -> None:
    problems, root_seen, scratch_seen = classify_mounts(sample_mountinfo())
    assert problems == [] and root_seen and scratch_seen


@pytest.mark.parametrize("bad", [
    "700 600 0:60 / /host rw - virtiofs /host_mnt/Users rw",
    "700 600 0:60 /run/host-services/docker.proxy.sock /var/run/docker.sock rw - tmpfs tmpfs rw",
    "700 600 254:1 / /workspace rw - ext4 /dev/vda1 rw",
    "700 600 0:61 / /proc/sysrq-trigger rw - proc proc rw",
    "700 600 254:1 /docker/containers/" + "f" * 64 + "/hosts /etc/passwd rw - ext4 /dev/vda1 rw",
    "garbage line",
])
def test_unexpected_or_host_mounts_are_flagged(bad: str) -> None:
    problems, _, _ = classify_mounts([*sample_mountinfo(), bad])
    assert problems


@pytest.mark.parametrize("index,replacement", [
    (0, "600 500 0:50 / / rw,relatime - overlay overlay rw"),
    (10, "610 600 0:56 / /scratch rw,nosuid,nodev,relatime - tmpfs tmpfs rw"),
    (4, "604 600 0:55 / /sys rw,nosuid - sysfs sysfs rw"),
    (9, "609 600 254:1 /somewhere/else/hosts /etc/hosts rw - ext4 /dev/vda1 rw"),
])
def test_weakened_expected_mounts_are_flagged(index: int, replacement: str) -> None:
    lines = copy.copy(sample_mountinfo())
    lines[index] = replacement
    problems, _, _ = classify_mounts(lines)
    assert problems


# ------------------------------------------------------------------- resource-limit edge cases


def test_shm_mount_must_be_bounded_and_hardened() -> None:
    base = [ln for ln in sample_mountinfo() if " /dev/shm " not in ln]
    assert classify_mounts(base)[0] == []  # absent /dev/shm is acceptable
    for bad in ("617 602 0:62 / /dev/shm rw,nosuid,nodev,noexec - tmpfs shm rw,size=65536k",
                "617 602 0:62 / /dev/shm rw,nosuid,nodev,noexec - tmpfs shm rw",
                "617 602 0:62 / /dev/shm rw,nosuid,nodev - tmpfs shm rw,size=16384k"):
        assert classify_mounts([*base, bad])[0], bad


def test_shm_fill_judgement() -> None:
    from patchproof.probes.interpret import j_res_14

    f = RunFacts(nonce=NONCE)
    assert j_res_14({"present": False}, Role.STORAGE, f)[0] is Outcome.PASS
    assert j_res_14({"present": True, "bytes_written": 16 * MIB, "errno": "ENOSPC"}, Role.STORAGE, f)[0] is Outcome.PASS
    assert j_res_14({"present": True, "bytes_written": 64 * MIB, "errno": "ENOSPC"}, Role.STORAGE, f)[0] is Outcome.FAIL
    assert j_res_14({"present": True, "bytes_written": 2048 * MIB, "errno": None}, Role.STORAGE, f)[0] is Outcome.FAIL
    assert j_res_14({"present": True, "bytes_written": 8 * MIB, "errno": "EIO"}, Role.STORAGE, f)[0] is \
        Outcome.INCONCLUSIVE
    assert j_res_14({}, Role.STORAGE, f)[0] is Outcome.ERROR


def test_writable_census_control() -> None:
    t = common_observations(T)
    t["FS-10"] = {"writable": ["/dev/shm"], "refused": {"/scratch": "EROFS"}}
    assert judge("FS-10", facts_with(t)) is Outcome.ERROR


def test_fill_limits() -> None:
    from patchproof.probes.interpret import j_fill

    judge_fill = j_fill("scratch_bytes")
    facts = RunFacts(nonce=NONCE)
    assert judge_fill({"bytes_written": 250 * MIB, "errno": "ENOSPC"}, Role.STORAGE, facts)[0] is Outcome.PASS
    assert judge_fill({"bytes_written": 300 * MIB, "errno": "ENOSPC"}, Role.STORAGE, facts)[0] is Outcome.FAIL
    assert judge_fill({"bytes_written": 2048 * MIB, "errno": None}, Role.STORAGE, facts)[0] is Outcome.FAIL
    assert judge_fill({"bytes_written": 10 * MIB, "errno": "ENOSPC"}, Role.STORAGE, facts)[0] is Outcome.INCONCLUSIVE
    assert judge_fill({"bytes_written": 250 * MIB, "errno": "EIO"}, Role.STORAGE, facts)[0] is Outcome.INCONCLUSIVE


def test_cpu_and_pids_thresholds() -> None:
    from patchproof.probes.interpret import j_res_04, j_res_06

    f = RunFacts(nonce=NONCE)
    assert j_res_06({"workers": 4, "ratio": 1.02}, Role.CPU, f)[0] is Outcome.PASS
    assert j_res_06({"workers": 4, "ratio": 3.9}, Role.CPU, f)[0] is Outcome.FAIL
    assert j_res_06({"workers": 4, "ratio": 1.4}, Role.CPU, f)[0] is Outcome.INCONCLUSIVE
    assert j_res_04({"started_threads": 120, "error": "x"}, Role.PIDS, f)[0] is Outcome.PASS
    assert j_res_04({"started_threads": 512, "error": None}, Role.PIDS, f)[0] is Outcome.FAIL
    assert j_res_04({"started_threads": 200, "error": "x"}, Role.PIDS, f)[0] is Outcome.FAIL


def test_namespace_topology_requires_shared_net_and_private_others() -> None:
    from patchproof.probes.interpret import j_ns_02

    assert j_ns_02(facts_with())[0] is Outcome.PASS
    v = common_observations(V)
    v["NS-02"] = dict(v["NS-02"], net="net:[999]")
    assert j_ns_02(facts_with(verifier_obs=v))[0] is Outcome.FAIL
    v = common_observations(V)
    v["NS-02"] = dict(v["NS-02"], pid=common_observations(T)["NS-02"]["pid"])
    assert j_ns_02(facts_with(verifier_obs=v))[0] is Outcome.FAIL
    assert j_ns_02(RunFacts(nonce=NONCE))[0] is Outcome.NOT_RUN


def test_inspect_based_probes_need_inspect_evidence() -> None:
    from patchproof.probes.interpret import j_net_08, j_ns_03, j_res_10

    facts = facts_with()
    for fn in (j_net_08, j_ns_03):
        assert fn(facts)[0] is Outcome.NOT_RUN
    assert j_res_10(facts)[0] is Outcome.NOT_RUN
