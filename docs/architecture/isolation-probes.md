# PP-003 container isolation probe suite — design

**Status:** A0 is implemented. A1 (image pull) is done, and A2 (image identity
`sha256:70729b46…c2f`, linux/amd64) is approved. **No container has run.** No isolation
property is verified; that needs A3 and A4 (`STATUS.md`).

**Sources:** PROJECT_SPEC.md §5.2, §5.4, §10.1–10.3, §10.6, §15.1; ADR-003, ADR-009.

## 1. Components

| Concern | Module | Notes |
|---|---|---|
| Fixed policy | `src/patchproof/runner/policy.py` | Every security setting is a constant. Callers choose only role, image ID, limits at or below a code ceiling, and fixed probe tokens. `ContainerSpec` has no field for mounts, capabilities, security options, network names, devices, environment, or raw arguments. |
| Command construction | `src/patchproof/runner/docker_cli.py` | Typed operations (`Create`, `Inspect`, `Start`, `Wait`, `Logs`, `Stop`, `Remove`, read-only listings) are the only way to reach Docker. Argument arrays, `shell=False`, sanitized environment, deadline and capped output on every call, no prune/filter/force operation. |
| Inspect gate | `src/patchproof/runner/inspect_gate.py` | After `create`, the executed create argv and 57 inspected fields (58 checks) are compared with the policy. The argv must include `--platform linux/amd64`, `--pull=never`, and the approved image ID. Inspect must show `Platform` linux and, when present, `ImageManifestDescriptor.platform` linux/amd64. Any mismatch or missing field means the container is not started and is removed by ID. |
| Cleanup | `src/patchproof/runner/cleanup.py` | Removal only of IDs this run registered, after a fresh inspect shows the registered name and this installation's and run's labels. Write-ahead journal for interrupted runs. Force-removal fallback, owner-approved 2026-10-11, in §6. |
| Probe catalogue | `src/patchproof/probes/catalogue.py` | 82 probes, each with kind, evidence type, and positive control. |
| In-container script | `containers/probes/isolation_probe.py` | Standard library only. Passed as `python3 -I -S -B -c <script>`, so no host path is mounted. It reports raw facts and never decides PASS/FAIL. |
| Interpretation | `src/patchproof/probes/interpret.py` | Pure. Turns observations and Docker facts into outcomes. |
| Evidence | `src/patchproof/probes/evidence.py`, `schemas/isolation-probe-run.schema.json` | Bounded run record. A control is reported as `ENFORCEMENT_EXERCISED` only when a behavioral probe for it passed in that run. |
| Orchestration and CLI | `src/patchproof/probes/orchestrator.py`, `cli.py`, `containers/probes/run_isolation_probes.py` | `plan` is Docker-free. `run` checks the A2, A3, and A4 gates in code before touching Docker. These gates are procedural; they are not a sandbox. |

`patchproof doctor --probe-isolation` (§13.1) is deferred until packaging is approved
(STATUS approval item 2). Until then, the launcher script is the entry point.

## 2. Containers

Ten containers in total, at most two at a time (target and verifier):

| Role | Network | Limits | Purpose |
|---|---|---|---|
| target | `none` | 1 CPU, 1 GiB, 128 PIDs, 256 MiB `/scratch`, 64 MiB `/tmp` | Self-probes, then serves `127.0.0.1:8080` in its own namespace |
| verifier | `container:<exact target ID>` | 1 CPU, 512 MiB, 128 PIDs, 112 MiB `/scratch`, 16 MiB `/tmp` (128 MiB combined, enforced in code) | Self-probes, loopback positive control, cross-container file checks |
| memory, pids, cpu, storage | `none` | target limits | Exercise each limit in a disposable container |
| logflood | `none` | target limits | Writes 30 MiB to stdout to test daemon-side rotation (2 × 5 MiB) |
| sleeper | `none` | target limits | Exceeds a 10 s runner deadline to test stop and removal |
| two decoys | `none` | target limits | Created, never started. Used to show that cleanup refuses containers from another run or without PatchProof ownership |

Verifier writable storage is 112 MiB `/scratch` plus 16 MiB `/tmp` (owner decision,
2026-10-11). `check_limits` enforces a combined writable-tmpfs ceiling per class:
verifier 128 MiB (§5.2), target 320 MiB (256 MiB scratch plus a separate 64 MiB `/tmp`).
Execution-profile contract 1.1 (`execution-profile.v1.1.schema.json`, separate from the
unchanged 1.0 contract) makes the sizes explicit: `scratch_tmpfs_bytes` is
`/scratch` only, and `tmp_tmpfs_bytes` is `/tmp`. Their sum is the application scratch
budget. A 1.0 profile is refused, never reinterpreted.

`/dev/shm` is a separate, fixed bound (`--shm-size 16777216`), outside that budget.
`/dev/mqueue` is bounded only by the kernel's `RLIMIT_MSGQUEUE`. The budget does not
bound total memory. FS-10 checks where the container user can actually create files,
and RES-14 fills `/dev/shm`.

## 3. Rules that keep a broken harness from looking like isolation

1. Every negative probe names a positive control, or carries an internal control in the
   same observation. The catalogue validator enforces this at import time.
2. A negative probe whose control did not pass is `INCONCLUSIVE`. An observed escape stays
   `FAIL` regardless.
3. A container stream that lacks its end marker, was truncated by the collector cap,
   carries a wrong nonce, or ended with an unexpected exit code cannot support a PASS.
4. Unknown errno values and missing fields are `INCONCLUSIVE` or `ERROR`, never PASS.
5. The suite reports `ALL_PLANNED_PROBES_PASSED` only if every catalogue probe passed,
   including an exact before/after preservation snapshot of unrelated Docker resources.
   The record builder and the schema both refuse anything else.

## 4. Corrections to the earlier execution plan

| Earlier plan | Problem | Now |
|---|---|---|
| CPU probe: 4 busy Python threads | The GIL caps threads at about one CPU, so the probe would pass with no limit | 4 forked processes, plus a 1-process measurement control |
| `ptrace(PTRACE_TRACEME)` expected EPERM | Docker's default seccomp profile allows ptrace on current kernels; it would fail falsely | `keyctl`, which default seccomp blocks and which needs no capability, so seccomp is tested separately from capabilities |
| Script fed on stdin (`create -i`, `python3 -`) | `docker create` leaves `StdinOnce` false; Python could wait for EOF indefinitely | Script passed as one `-c` argument; the gate also verifies the exact `Cmd` |
| Root-filesystem write test only in root-owned directories | EACCES and EROFS are hard to tell apart there | Also writes to world-writable `/var/tmp`, which only a read-only mount can refuse. EROFS is required, and missing parents (ENOENT) are not counted |
| Exact mount allowlist | Docker's default `/proc` and `/sys` masks would fail it | Mounts are classified: required properties for `/`, `/scratch`, `/tmp`, `/sys`, and `/etc/hosts`; masks must be read-only or `/dev/null`; any host-path source fails |
| Container-side PASS/FAIL | Target-printed results must not decide outcomes (INV-09) | The container emits facts only; the host judges |
| "Unlabeled" decoy | Conflicts with "every owned container is labeled" | The foreign decoy carries only a decoy marker. Its teardown is a separate, logged path that never uses the owned-container routine |
| PRV-10 expected all user-namespace creation to fail, and ran `unshare` in the probe process | Docker documents that its default seccomp profile permits unprivileged user namespaces, so the probe would fail falsely. A permitted `unshare` would also have moved the probe process into a new namespace and contaminated later probes | Each attempt runs in its own forked child; PRV-P5 is the control for that channel. PRV-10: unshare(NEWNS/NEWNET/NEWPID), unshare(NEWUSER\|NEWNS), and setns(mnt) must fail with EPERM. PRV-13 records whether plain unshare(NEWUSER) is permitted, accepting either outcome. If it is permitted, sethostname, mount, and a nested unshare(NEWNS) from inside it must fail: user-namespace capabilities must not act on the container's namespaces |

## 5. Expectations not yet validated against Docker 29.8.2

**Observed in A4 run 1:** Docker 29.8.2 omits `Config.ExposedPorts` and
`HostConfig.Mounts` when they are empty. The gate accepts an absent key only when the
always-serialized fields (`Mounts`, `Binds`, `VolumesFrom`, `Config.Volumes`;
`PortBindings`, `PublishAllPorts`, `NetworkSettings.Ports`) prove the same property.
Regression fixture: `tests/fixtures/docker-29.8.2-inspect-created.json`.

The following are design assumptions. The first A4 run tests them. If one is wrong, the
suite reports `BLOCKED`, `FAIL`, or `INCONCLUSIVE`; it never silently passes. Any change
to an expectation needs owner review (`CLAUDE.md`, verification integrity).

- Inspect-gate field shapes: for example, `SecurityOpt` stored as `no-new-privileges=true`,
  `MaskedPaths` populated at create time, and `ExtraHosts` empty on Docker Desktop.
- The mount classification rules, and the source path of `/etc/hosts`-family bind mounts.
- `keyctl` and unshare(NEWUSER|NEWNS) return EPERM under the default seccomp profile. Plain
  unshare(NEWUSER) is recorded either way (PRV-13).
- Container inspect on Docker 29.8.2 reports `Platform: linux`, and may report
  `ImageManifestDescriptor.platform`.
- `python:3.13-slim` declares no volumes, has `/usr/local/bin/python3`, and has a
  world-writable `/var/tmp`.
- `docker container logs` from the `local` driver returns at most about 10 MiB after the
  30 MiB flood.

## 6. Cleanup escalation (owner-approved 2026-10-11)

`cleanup.remove_owned` takes an ID only from this run's journaled registry. It then:

1. Inspects the container and requires the registered name plus this installation's and
   run's labels.
2. Runs `docker container stop --time 5`. The daemon escalates SIGTERM to SIGKILL after
   the grace period.
3. Runs `docker container rm -- <id>` without force, then confirms the container is absent.
4. Only if the stop or the removal failed, inspects again. If that re-inspect shows the
   same ID, name, and ownership labels, and the container is still running (or
   restarting, or paused), it runs `docker container rm --force -- <id>` (the typed
   `ForceRemove` operation, fixed shape) and confirms the container is absent. The
   result is recorded as `FORCE_REMOVED` with the reason.

If the container is stopped but ordinary removal failed for another reason, or if the
re-inspect fails or ownership cannot be reconfirmed, nothing is forced. The result is
`FAILED`, with detail beginning `CLEANUP_FAILED`. Decoys never take the force path. The
CLN-05 audit rejects any `force-remove` that does not exactly match its fixed shape or
that lacks a failed stop or remove and a fresh re-inspect of the same ID before it.

## 7. NET-01 and FS-05 semantics (owner decisions 2026-10-11, after A4 run 2)

A4 run 2 (`run-cc1e6383…`) failed NET-01 and FS-05 under the original assertions. That
result is preserved as ISOLATION_FAILED. Under the revised checks, its observations still
fail, because the run did not capture the evidence the revised checks require.

- **NET-01** is state-based. Linux creates fallback tunnel devices (tunl0, gre0, gretap0,
  erspan0, sit0, ip6tnl0, ip6gre0, and in run 2 also ip_vti0, ip6_vti0) in every new
  network namespace when `net.core.fb_tunnels_only_for_init_net=0`. Their existence is not
  a violation. PASS requires all of the following:
  - loopback UP with 127.0.0.1;
  - every other interface, whatever its name, with the UP flag clear, operstate `down`,
    no IPv4 address (the address lookup fails with `EADDRNOTAVAIL`), no IPv6 address, no
    carrier, and zero RX/TX bytes;
  - in the same container, 0 routes (NET-09), all capability sets zero (no
    CAP_NET_ADMIN), and every egress attempt blocked;
  - lists that agree, and diagnostics that cover exactly the interfaces seen.

  Missing, unreadable, or contradictory diagnostics FAIL or are INCONCLUSIVE. No interface
  names are allowlisted. Interface state and counters are supporting observations, not
  standalone proof against every escape.
- **FS-05** compares the startup environment (`/proc/self/environ`, keys only) with the
  contract: the image Env keys, all of which must be present, plus HOSTNAME and HOME.
  Python's runtime view must be consistent with it. The only runtime-only variable
  allowed is `LC_CTYPE`, which must be absent at startup and valued exactly `C.UTF-8` or
  `C.utf8` (CPython's PEP 538 locale coercion; the image sets no locale). Its value is
  recorded; no other value is collected. There is no general LC_* or PYTHON* exception, and
  the container's startup environment is not changed.
- **Still unverified on the real runtime:** the interface states, addresses, counters,
  and sysctl value; the startup environment and `LC_CTYPE` value. All need a new A4 run.

## 8. Execution boundaries (owner-approved 2026-10-11)

There is a monotonic 20-minute budget for active probing. It is checked before every
Docker operation, and each operation's timeout is capped at the remaining budget. A
separate 2-minute window covers cleanup and the read-only after-snapshot. If the budget
expires: no new probe starts, completed observations are kept, unfinished checks are
NOT_RUN or INCONCLUSIVE, and RES-15 is INCONCLUSIVE, so the suite cannot pass.
Containers not removed within the window are `CLEANUP_FAILED`, with no retry.

