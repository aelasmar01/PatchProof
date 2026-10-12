# PP-003 — Container isolation probe evidence (sanitized)

**Status:** PP-003 is `READY_FOR_REVIEW`, not accepted. This is evidence for owner review.
It describes **one run on one Docker Desktop installation on 2026-10-12**. It does not
show that Docker is escape-proof, or that arbitrary hostile repositories are safe to run.
Hashes support local consistency checks only; they are not independent attestation
(ADR-007). The machine-readable companion is `pp-003-isolation-probes.json`.
Excluded from both files: the installation ID, container IDs, absolute local paths, raw
container output, and the probe script text.

## Runtime and identities

| Item | Value |
|---|---|
| Docker Desktop / Engine | 4.94.0 (docs/environment.lock.md) / 29.8.2, context `desktop-linux`, containerd (io.containerd.snapshotter.v1) image store |
| VM kernel | 7.0.14-linuxkit (read-only docker info, 2026-10-11) |
| Image (A2-approved) | `sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f` (linux/amd64; RepoDigest `python@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f`) |
| Probe script | `sha256:734aa57617a4957a69229683e0b9c4b2b82c1cf7ace4038005ee85aacb889f13` |
| Code identity | current code regenerates all 10 executed create argv exactly; probe-script digest label on every owned container equals probe_script_sha256; per-file sha256 in the JSON |

## Execution history (all three runs preserved unchanged in private evidence)

| Run | Outcome | Cause and correction |
|---|---|---|
| `run-d109d3606276fd75137241a6a1bc6b92` | **BLOCKED** (9.004 s) | inspect gate expected Config.ExposedPorts and HostConfig.Mounts to be present; Docker 29.8.2 omits them when empty. Correct fail-closed refusal; no container started. Correction: absent keys accepted only with always-serialized corroborating fields (inspect_gate._OMITEMPTY_CORROBORATED). |
| `run-cc1e6383d6893c2afe8ab839cc68a08d` | **ISOLATION_FAILED** (NET-01, FS-05) | NET-01 asserted 'only lo' but the kernel creates fallback tunnel devices per netns; FS-05 read os.environ after CPython PEP 538 added LC_CTYPE. Required state/startup evidence was not captured. Correction: owner decisions 2026-10-11: state-based NET-01 with expanded diagnostics; FS-05 startup environment (/proc/self/environ) plus exact LC_CTYPE=C.UTF-8|C.utf8 runtime-only allowance. |
| `run-5c176591e0f793ebdb6c2f07667c4ead` | **ALL_PLANNED_PROBES_PASSED** | 2026-10-12T04:28:49Z to 2026-10-12T04:29:25Z; active 36.848 s of 1200 s; deadline expired: False; cleanup COMPLETE |

Run 3 result: PASS 82 of 82 probes.

## Independent verification (read-only, against raw evidence)

Each item was checked from the container output, inspect dumps, command log, journal,
and snapshots, not from the run's own summary:

- All 10 containers passed the inspect gate with 0 mismatches. Each one, as Docker
  reported it: user 10001:10001; read-only root; `CapDrop [ALL]`, no `CapAdd`;
  `SecurityOpt [no-new-privileges=true]` (default seccomp); not privileged; private
  PID, IPC, and cgroup namespaces; `ShmSize` 16 MiB; no mounts, binds, or port bindings;
  platform linux/amd64. The verifier's `NetworkMode` is `container:<exact target ID>`.
- Docker operations: context-inspect 1, version 1, image-inspect 1, snapshot 10, create 10, inspect 42, start 8, wait 8, logs 9, remove 10, stop 1. There was no
  prune, filter, force, kill, pull, build, or exec. Every removal is `container rm -- <id>`.
  Every create carries `--platform linux/amd64 --pull=never` and the approved image ID.
- 10 created, 8 started, the 2 decoys never started, at most 2 at once, and all 10
  removed by exact ID (journal: 10 planned / 10 created / 10 REMOVED). No force-removal
  was needed.
- The before and after inventory snapshots are identical (images, containers, volumes,
  networks including built-in network IDs, build-cache count).

## Observed enforcement (configured vs observed)

| Control | Configured | Observed |
|---|---|---|
| Identity | `--user 10001:10001` | uid/gid 10001/10001, groups [10001]; setuid/setgid/setgroups(0) EPERM |
| Capabilities | `--cap-drop ALL` | all five sets `0000000000000000`; chown(0), mknod, raw and AF_PACKET sockets EPERM |
| no-new-privileges / seccomp | `no-new-privileges=true`, default profile | NoNewPrivs 1; Seccomp 2 (1 filter); keyctl EPERM; unshare(NEWNS/NEWNET/NEWPID/NEWUSER\|NEWNS), setns, mount EPERM; plain user-namespace creation {'errno': 'EPERM', 'ok': False} |
| Memory | 1 GiB, swap 0 | OOM-killed (exit 137) after 960 MiB progress; limit 1 GiB, no swap |
| PIDs | 128 | thread creation failed after 127 threads (+1 main) |
| CPU | 1 CPU | 1 worker ratio 0.999; 4 workers ratio 1.013 |
| Scratch / tmp / shm | 256 MiB / 64 MiB / 16 MiB | ENOSPC at 268435456 / 67108864 / 16777216 bytes; `/tmp` noexec (EACCES) |
| Writable locations | approved tmpfs only | /dev/mqueue, /dev/shm, /scratch, /tmp |
| Logs | local, 5 MiB x 2 | 7122023 bytes retained of 31,457,280 written; oldest output rotated away |
| Deadline | 10 s probe deadline, 5 s grace | stopped in 5.117s and removed |

## Network isolation (NET-01 state-based, owner decision 2026-10-11)

Shared target/verifier network namespace: True. PID, mount, and IPC
namespaces private: True. Routes: {'ipv4_routes': 0, 'ipv6_routes_non_lo': 0}. The verifier reached
the target over loopback: {'nonce_match': True, 'status': 200, 'tries': 1}.
`fb_tunnels_only_for_init_net` inside the container: `error:ENOENT`.

| Interface | flags | operstate | type | carrier | IPv4 | IPv6 addrs | rx/tx bytes |
|---|---|---|---|---|---|---|---|
| erspan0 | 0x1002 | down | 1 | error:EINVAL | none:EADDRNOTAVAIL | 0 | 0/0 |
| gre0 | 0x80 | down | 778 | error:EINVAL | none:EADDRNOTAVAIL | 0 | 0/0 |
| gretap0 | 0x1002 | down | 1 | error:EINVAL | none:EADDRNOTAVAIL | 0 | 0/0 |
| ip6_vti0 | 0x80 | down | 769 | error:EINVAL | none:EADDRNOTAVAIL | 0 | 0/0 |
| ip6gre0 | 0x80 | down | 823 | error:EINVAL | none:EADDRNOTAVAIL | 0 | 0/0 |
| ip6tnl0 | 0x80 | down | 769 | error:EINVAL | none:EADDRNOTAVAIL | 0 | 0/0 |
| ip_vti0 | 0x80 | down | 768 | error:EINVAL | none:EADDRNOTAVAIL | 0 | 0/0 |
| lo | 0x9 | unknown | 772 | 1 | 127.0.0.1 | 1 | 0/0 |
| sit0 | 0x80 | down | 776 | error:EINVAL | none:EADDRNOTAVAIL | 0 | 0/0 |
| tunl0 | 0x80 | down | 768 | error:EINVAL | none:EADDRNOTAVAIL | 0 | 0/0 |

Every non-loopback device is administratively down (no IFF_UP), unaddressed, and idle;
all egress attempts failed (`ENETUNREACH` or name resolution failure). Device state and
counters are supporting observations, not standalone proof against every escape.

## Environment (FS-05 startup vs runtime, owner decision 2026-10-11)

Startup environment keys (`/proc/self/environ`): GPG_KEY, HOME, HOSTNAME, PATH, PYTHON_SHA256, PYTHON_VERSION. These are Docker
`Config.Env` (the image's four keys) plus HOME and HOSTNAME. Runtime-only:
['LC_CTYPE'] with value `C.UTF-8` (CPython PEP 538 locale coercion).

## Control claims

| Control | Status | Probes |
|---|---|---|
| explicit-docker-context | ENFORCEMENT_EXERCISED | PRE-01 |
| fixed-non-root-identity | ENFORCEMENT_EXERCISED | PRV-01, PRV-02 |
| read-only-root-filesystem | ENFORCEMENT_EXERCISED | FS-01 |
| all-capabilities-dropped | ENFORCEMENT_EXERCISED | PRV-03, PRV-04, PRV-05, PRV-06 |
| no-new-privileges | CONFIGURED_ONLY | PRV-07 |
| default-seccomp | ENFORCEMENT_EXERCISED | PRV-08, PRV-09, PRV-10 |
| not-privileged | ENFORCEMENT_EXERCISED | PRV-10, PRV-11, PRV-12, PRV-13, POL-06 |
| no-host-namespaces | CONFIGURED_ONLY | NS-01, NS-02, NS-03, NET-01 |
| no-docker-socket-or-engine-api | ENFORCEMENT_EXERCISED | FS-02, NET-06 |
| no-host-credential-home-or-repo-mounts | ENFORCEMENT_EXERCISED | FS-03, FS-04, FS-09 |
| no-host-environment | CONFIGURED_ONLY | FS-05 |
| no-published-ports | CONFIGURED_ONLY | NET-08 |
| no-external-connectivity | ENFORCEMENT_EXERCISED | NET-02, NET-03, NET-04, NET-05, NET-07, NET-09 |
| approved-loopback-topology | ENFORCEMENT_EXERCISED | NET-P1, NS-02 |
| target-verifier-file-separation | ENFORCEMENT_EXERCISED | FS-06, FS-07 |
| cpu-limit | ENFORCEMENT_EXERCISED | RES-05, RES-06 |
| memory-limit | ENFORCEMENT_EXERCISED | RES-01, RES-02 |
| process-limit | ENFORCEMENT_EXERCISED | RES-03, RES-04 |
| bounded-scratch-storage | ENFORCEMENT_EXERCISED | FS-08, FS-10, RES-07, RES-08, RES-09, RES-14 |
| bounded-logs-and-output | ENFORCEMENT_EXERCISED | RES-10, RES-11, RES-13 |
| deadline-and-forced-termination | ENFORCEMENT_EXERCISED | RES-12, RES-15 |
| immutable-image-no-implicit-pull | ENFORCEMENT_EXERCISED | PRE-02, PRE-03 |
| policy-refusal-before-start | ENFORCEMENT_EXERCISED | POL-01, POL-02, POL-03, POL-04, POL-05 |
| exact-id-ownership-cleanup | ENFORCEMENT_EXERCISED | CLN-01, CLN-02, CLN-03, CLN-04, CLN-05 |
| unrelated-resources-preserved | ENFORCEMENT_EXERCISED | CLN-06 |

`CONFIGURED_ONLY` means the evidence is what Docker or the kernel reports, not a
behavioural exercise.

## Reviewer notes on the four CONFIGURED_ONLY claims (owner acceptance review, 2026-10-12)

`CONFIGURED_ONLY` means no probe of evidence type `behavioral` or `host_check` backs the
claim. The evidence is kernel-reported state read inside the container, or Docker inspect.

| Claim | Property | Recorded evidence | Sufficient for the narrow claim? | Limitation |
|---|---|---|---|---|
| `no-new-privileges` (PRV-07) | §10.2: no-new-privileges enabled | Kernel task flag `NoNewPrivs: 1` in target and verifier (`/proc/self/status`); inspect `SecurityOpt [no-new-privileges=true]` | Yes. It is the kernel's own enforcement flag, and `CapBnd`/`CapEff` are all zero, so even a setuid binary could not gain capabilities | No setuid binary was executed to exercise it |
| `no-host-namespaces` (NS-01, NS-02, NS-03, NET-01) | §10.2: private PID/IPC namespaces, no host namespaces | Each container sees only PID 1 (itself). Namespace inodes for pid/ipc/uts/cgroup (`40265326xx`) differ from the kernel's fixed initial-namespace inodes and between target and verifier; net is shared only between target and verifier, as designed. Inspect: `PidMode ""`, `IpcMode private`, `UTSMode ""`, `UsernsMode ""`, `CgroupnsMode private`. No host interfaces or routes (NET-01, NET-09) | Yes for PID, IPC, UTS, cgroup, and network | **The user namespace is shared with the Docker VM** (`user:[4026531837]`, the initial user namespace): Docker Desktop does not remap user namespaces. This is a documented residual (`docs/environment.lock.md` §4.2; threat model §6), mitigated by the fixed non-root UID and zero capabilities (PRV-01..06) |
| `no-host-environment` (FS-05) | §10.2: no host environment inheritance | Kernel-recorded exec environment (`/proc/self/environ`) keys equal Docker `Config.Env` (the image's keys) plus HOME/HOSTNAME; the gate verified `Config.Env` equals the image Env | Yes. The property is the content of the process environment, and that content was observed directly | Keys only, by design; the approved runtime-only `LC_CTYPE=C.UTF-8` exception |
| `no-published-ports` (NET-08) | INV-03: no host-published port | Inspect: `PortBindings {}`, `PublishAllPorts false`, `NetworkSettings.Ports {}`, `ExposedPorts` absent with corroboration, for target and verifier. Structurally, `--network none` / `container:<target>` gives no interface through which a published port could be reached (NET-01, NET-09) | Yes for the narrow claim, with the structural network evidence | No host-side ingress attempt was made |

§15.1 names topology, resource limits, read-only mounts, non-root execution, lack of
egress, verifier-file invisibility, and Docker-socket invisibility. Each of these has
behavioral evidence in run 3 (NET-P1/NS-02, RES-*, FS-01, PRV-01/02, NET-02..07, FS-06/07,
FS-02).

**Classification note:** the classifier counts `host_check` evidence as exercising a
control. For `immutable-image-no-implicit-pull`, that evidence is PRE-03, a check of the
create argv, together with the command log showing that no pull occurred and the image
being present locally. Docker's refusal to pull a missing image under `--pull=never` was
not exercised against the real daemon, only in unit tests.

## Per-probe results (run 3)

| Probe | Title | Kind | Evidence | Expected | Outcome | Observed |
|---|---|---|---|---|---|---|
| PRE-01 | Docker context is desktop-linux on the expected socket | configuration | host_check | context endpoint is unix://$HOME/.docker/run/docker.sock | **PASS** | desktop-linux context on the Docker Desktop user socket |
| PRE-02 | Approved image identity present locally | configuration | inspect | image inspect Id equals the approved ID; linux/amd64; Config.Volumes empty | **PASS** | approved image present; linux/amd64; no declared volumes |
| PRE-03 | No implicit pull | configuration | host_check | every create argv carries --pull never and the image ID, never a tag | **PASS** | --platform linux/amd64, --pull=never and the full image ID in every create |
| NET-P1 | Verifier reaches target over the shared loopback | positive_control | behavioral | HTTP 200 from 127.0.0.1:8080 with the run nonce | **PASS** | verifier: HTTP 200 with nonce after 1 tries |
| NET-P2 | UDP loopback round trip works | positive_control | behavioral | datagram echoed on 127.0.0.1 | **PASS** | target: UDP loopback echo matched |
| NET-P3 | Resolver answers for localhost | positive_control | behavioral | localhost resolves to loopback | **PASS** | target: localhost resolves to loopback |
| NET-01 | No usable network interface besides loopback | negative | kernel_state | lo UP with 127.0.0.1; every other interface (any name) administratively down, operstate down, no IPv4/IPv6 address, no carrier, zero traffic; 0 routes; no capabilities; egress blocked | **PASS** | target: lo UP; 9 other interface(s) down, unaddressed, carrier-less, idle (erspan0, gre0, gretap0, ip6_vti0, ip6gre0, ip6tnl0, ip_vti0, sit0, tunl0); 0 routes; no capabilities; egress blocked; fb_tunnels_only_for_init_ne |
| NET-09 | No routes beyond loopback | negative | kernel_state | 0 IPv4 routes; 0 non-lo IPv6 routes | **PASS** | target: no routes beyond loopback \| verifier: no routes beyond loopback |
| NET-02 | No IPv4 TCP egress | negative | behavioral | every connect fails with ENETUNREACH/EHOSTUNREACH/EADDRNOTAVAIL | **PASS** | target: all blocked |
| NET-03 | No IPv6 TCP egress | negative | behavioral | every connect fails with an unreachable errno | **PASS** | target: all blocked |
| NET-04 | No DNS resolution of external names | negative | behavioral | getaddrinfo fails for every external name | **PASS** | target: all blocked |
| NET-05 | No UDP egress | negative | behavioral | sendto fails with an unreachable errno | **PASS** | target: all blocked |
| NET-06 | Docker Engine API and host gateway unreachable | negative | behavioral | no TCP connection to gateway/engine addresses; gateway names do not resolve | **PASS** | target: all blocked |
| NET-07 | Joining the target namespace adds no egress | negative | behavioral | NET-02..06 attempts from the verifier all fail | **PASS** | verifier: all blocked; all blocked; all blocked; all blocked; all blocked |
| NET-08 | No published or exposed ports | configuration | inspect | PortBindings/Ports/ExposedPorts empty and PublishAllPorts false for target and verifier | **PASS** | no ports published or exposed |
| FS-P1 | Approved scratch locations are writable | positive_control | behavioral | 1 MiB write and read-back succeed in /scratch and /tmp | **PASS** | target: scratch and /tmp writable \| verifier: scratch and /tmp writable \| storage: scratch and /tmp writable |
| FS-P2 | Marker search finds the container's own marker | positive_control | behavioral | own marker found by the same walk used for the cross-container check | **PASS** | target: own marker found 2x \| verifier: own marker found 2x |
| FS-P3 | Socket scan detects a known socket | positive_control | behavioral | the probe's own AF_UNIX socket in /scratch is detected | **PASS** | target: own socket detected \| verifier: own socket detected |
| FS-01 | Root filesystem is read-only | negative | behavioral | creating files on the image filesystem fails with EROFS, including world-writable /var/tmp | **PASS** | target: /pp-probe: EROFS; /etc/pp-probe: EROFS; /usr/pp-probe: EROFS; /usr/local/lib/pp-probe: EROFS; /var/tmp/pp-probe: EROFS; /home/pp-probe: EROFS; /opt/pp-probe: EROFS \| verifier: /pp-probe: EROFS; /etc/pp-probe: ER |
| FS-02 | Docker socket inaccessible | negative | behavioral | no socket paths exist, none found by scan, connects fail, mountinfo has no docker.sock | **PASS** | target: no Docker socket reachable \| verifier: no Docker socket reachable |
| FS-03 | Host home, repository, and credential paths absent | negative | behavioral | none of the host path names exist | **PASS** | target: no host paths \| verifier: no host paths |
| FS-04 | Mount table contains only expected mounts | negative | kernel_state | every mount matches the classified allowlist; no host-path source; / is read-only overlay | **PASS** | target: 24 mounts classified \| verifier: 24 mounts classified |
| FS-05 | No host environment inherited | negative | kernel_state | startup environment (/proc/self/environ) = image Env keys plus HOSTNAME/HOME; the only runtime-only variable allowed is CPython's LC_CTYPE=C.UTF-8 or C.utf8, absent at startup | **PASS** | target: startup environment = contract (['GPG_KEY', 'HOME', 'HOSTNAME', 'PATH', 'PYTHON_SHA256', 'PYTHON_VERSION']); LC_CTYPE=C.UTF-8 added after start by CPython locale coercion (absent at startup) \| verifier: startup  |
| FS-06 | Target cannot see verifier files | negative | behavioral | verifier marker not found by walk or via /proc/*/root | **PASS** | target: other marker not found (5638 entries scanned) |
| FS-07 | Verifier cannot see target files | negative | behavioral | target marker not found by walk or via /proc/*/root | **PASS** | verifier: other marker not found (5638 entries scanned) |
| FS-10 | Writable locations are only the approved tmpfs mounts | negative | behavioral | a file can be created only under /scratch, /tmp, /dev/shm or /dev/mqueue | **PASS** | target: writable: ['/dev/mqueue', '/dev/shm', '/scratch', '/tmp'] \| verifier: writable: ['/dev/mqueue', '/dev/shm', '/scratch', '/tmp'] |
| FS-08 | Kernel tunables and cgroup files not writable | negative | behavioral | open for write fails with EROFS/EACCES/EPERM on every existing path, including the /etc/hosts, /etc/hostname and /etc/resolv.conf bind mounts | **PASS** | target: /proc/sys/kernel/hostname: EACCES; /proc/sys/net/ipv4/ip_forward: EACCES; /proc/sysrq-trigger: EACCES; /sys/fs/cgroup/memory.max: EACCES; /sys/fs/cgroup/pids.max: EACCES; /sys/kernel/mm/transparent_hugepage/enabl |
| FS-09 | No credential or repository files on the container filesystem | negative | behavioral | no sensitive names found and the walk was not truncated | **PASS** | target: none found (5636 entries) \| verifier: none found (5636 entries) |
| PRV-01 | Fixed non-root identity | negative | kernel_state | uid/euid/gid/egid 10001; no supplementary group 0 | **PASS** | target: 10001:10001, groups [10001] \| verifier: 10001:10001, groups [10001] |
| PRV-P1 | setuid to own uid works | positive_control | behavioral | setuid(own uid) succeeds | **PASS** | target: setuid(self): succeeded \| verifier: setuid(self): succeeded |
| PRV-02 | Cannot become root | negative | behavioral | setuid(0), setgid(0), setgroups([0]) fail with EPERM | **PASS** | target: setuid0: EPERM; setgid0: EPERM; setgroups0: EPERM \| verifier: setuid0: EPERM; setgid0: EPERM; setgroups0: EPERM |
| PRV-03 | All capability sets empty | configuration | kernel_state | CapInh/CapPrm/CapEff/CapBnd/CapAmb all zero | **PASS** | target: all sets zero \| verifier: all sets zero |
| PRV-P2 | chown to own uid works | positive_control | behavioral | chown(own uid, own gid) succeeds | **PASS** | target: chown(self): succeeded \| verifier: chown(self): succeeded |
| PRV-04 | CAP_CHOWN not usable | negative | behavioral | chown to 0:0 fails with EPERM | **PASS** | target: chown(0,0): EPERM \| verifier: chown(0,0): EPERM |
| PRV-05 | CAP_MKNOD not usable | negative | behavioral | mknod char device fails with EPERM | **PASS** | target: mknod: EPERM \| verifier: mknod: EPERM |
| PRV-P3 | Ordinary TCP socket creation works | positive_control | behavioral | AF_INET stream socket created | **PASS** | target: TCP socket: succeeded \| verifier: TCP socket: succeeded |
| PRV-06 | CAP_NET_RAW not usable | negative | behavioral | raw ICMP and AF_PACKET sockets fail with EPERM/EACCES | **PASS** | target: raw ICMP: EPERM; AF_PACKET: EPERM \| verifier: raw ICMP: EPERM; AF_PACKET: EPERM |
| PRV-07 | no-new-privileges set | configuration | kernel_state | NoNewPrivs: 1 | **PASS** | target: NoNewPrivs 1 \| verifier: NoNewPrivs 1 |
| PRV-08 | seccomp filter active | configuration | kernel_state | Seccomp: 2 and Seccomp_filters >= 1 | **PASS** | target: filter mode with 1 filter(s) \| verifier: filter mode with 1 filter(s) |
| PRV-P4 | ctypes syscall path works | positive_control | behavioral | libc getpid via ctypes equals os.getpid | **PASS** | target: ctypes getpid 1 \| verifier: ctypes getpid 1 |
| PRV-09 | seccomp blocks keyctl (needs no capability) | negative | behavioral | keyctl fails with EPERM | **PASS** | target: keyctl: EPERM \| verifier: keyctl: EPERM |
| PRV-P5 | Forked-child result channel works | positive_control | behavioral | a forked child reports its result through the pipe | **PASS** | target: child result channel works \| verifier: child result channel works |
| PRV-10 | Namespace operations needing CAP_SYS_ADMIN refused | negative | behavioral | unshare(NEWNS), unshare(NEWNET), unshare(NEWPID), unshare(NEWUSER\|NEWNS) and setns(mnt) each fail with EPERM, each in its own forked child | **PASS** | target: unshare_newns: EPERM; unshare_newnet: EPERM; unshare_newpid: EPERM; unshare_newuser_newns: EPERM; setns_mnt: EPERM \| verifier: unshare_newns: EPERM; unshare_newnet: EPERM; unshare_newpid: EPERM; unshare_newuser_ |
| PRV-11 | Cannot mount | negative | behavioral | mount tmpfs fails with EPERM (forked child) | **PASS** | target: mount: EPERM \| verifier: mount: EPERM |
| PRV-12 | Only default devices | negative | kernel_state | /dev entries are a subset of the default set | **PASS** | target: 15 default entries \| verifier: 15 default entries |
| PRV-13 | A user namespace, if the default profile permits one, grants no container privilege | negative | behavioral | unshare(CLONE_NEWUSER) outcome recorded (permitted or EPERM both accepted); if permitted, sethostname, mount tmpfs and unshare(NEWNS) from inside it all fail with EPERM | **PASS** | target: user namespace creation denied (EPERM); recorded as observed behavior \| verifier: user namespace creation denied (EPERM); recorded as observed behavior |
| NS-01 | Private PID namespace | negative | kernel_state | the probe is PID 1 and the only process visible | **PASS** | target: probe is PID 1 and alone \| verifier: probe is PID 1 and alone |
| NS-02 | Namespace topology matches 10.1 | negative | kernel_state | net shared between target and verifier; pid, mnt, ipc differ | **PASS** | net shared; pid, mnt, ipc private |
| NS-03 | No host namespaces configured | configuration | inspect | PidMode/UTSMode/UsernsMode empty, IpcMode private, CgroupnsMode private, NetworkMode as planned | **PASS** | no host namespaces |
| RES-01 | Memory limit configured, no swap | configuration | kernel_state | memory.max equals the limit; memory.swap.max is 0 | **PASS** | target: memory.max 1073741824, swap 0 \| verifier: memory.max 536870912, swap 0 |
| RES-P1 | Allocation below the limit works | positive_control | behavioral | 256 MiB allocated and touched | **PASS** | memory: 256 MiB allocated |
| RES-02 | Memory limit enforced | negative | behavioral | OOM-killed (exit 137, OOMKilled true) before progress reaches the limit | **PASS** | OOM-killed after 960 MiB (limit 1024 MiB) |
| RES-03 | PID limit configured | configuration | kernel_state | pids.max equals 128 | **PASS** | target: pids.max 128 \| verifier: pids.max 128 |
| RES-P2 | Thread creation below the limit works | positive_control | behavioral | 16 threads started | **PASS** | pids: 16 threads started |
| RES-04 | PID limit enforced | negative | behavioral | thread creation fails with at most 128 tasks | **PASS** | pids: creation failed after 127 threads (+1 main) <= 128 |
| RES-05 | CPU limit configured | configuration | kernel_state | cpu.max equals '100000 100000' | **PASS** | target: cpu.max 100000 100000 \| verifier: cpu.max 100000 100000 |
| RES-P3 | CPU measurement works | positive_control | behavioral | one busy process reaches ratio >= 0.5 | **PASS** | cpu: single-process ratio 0.999 |
| RES-06 | CPU limit enforced | negative | behavioral | four busy processes reach CPU/wall <= 1.25 | **PASS** | cpu: 4 workers ratio 1.013 <= 1.25 |
| RES-P4 | Exec from the image filesystem works | positive_control | behavioral | interpreter subprocess exits 0 | **PASS** | storage: exec works |
| RES-07 | Scratch tmpfs bounded | negative | behavioral | ENOSPC after at least half and at most the scratch limit | **PASS** | storage: ENOSPC after 256 MiB (limit 256 MiB) |
| RES-08 | /tmp tmpfs bounded | negative | behavioral | ENOSPC after at least half and at most the /tmp limit | **PASS** | storage: ENOSPC after 64 MiB (limit 64 MiB) |
| RES-14 | /dev/shm bounded separately from the scratch budget | negative | behavioral | if /dev/shm is mounted, ENOSPC at or below 16 MiB; if absent, recorded as absent | **PASS** | storage: ENOSPC after 16 MiB (bound 16 MiB) |
| RES-09 | /tmp is noexec | negative | behavioral | executing a script in /tmp fails with EACCES | **PASS** | storage: exec from /tmp: EACCES |
| RES-10 | Daemon log rotation configured | configuration | inspect | LogConfig local, max-size 5m, max-file 2, compress false | **PASS** | 10 containers |
| RES-P5 | Log flood ran to completion | positive_control | behavioral | flood-end marker retained; at least 30 MiB written | **PASS** | flood-end retained; 31457280 bytes written |
| RES-11 | Daemon-side log volume bounded | negative | behavioral | retained log bytes <= 2 x 5 MiB + slack; flood-start marker rotated away | **PASS** | retained 7122023 bytes <= 10747904; oldest output rotated away |
| RES-12 | Deadline and forced termination | negative | behavioral | runner deadline expires, stop escalates within grace, container stopped and removed | **PASS** | stopped in 5.117s and removed |
| RES-15 | Suite finished within the 20-minute global execution deadline | configuration | host_check | active probing completed before the monotonic deadline; on expiry or interruption the result is INCONCLUSIVE, so the suite can never be reported as passed | **PASS** | completed in 36.8 s of 1200 s |
| RES-13 | Collector output cap holds | negative | host_check | a 1 MiB-capped read of the flood log returns <= 1 MiB and is marked truncated | **PASS** | capped read returned 1048576 bytes and reported truncation |
| POL-P1 | Valid fixed-policy request accepted | positive_control | host_check | default target and verifier specs build and the profile example is accepted | **PASS** | 3 valid request(s) accepted |
| POL-01 | Privileged profile refused | policy_refusal | host_check | refused before any Docker invocation | **PASS** | 3 case(s) refused before Docker |
| POL-02 | Forbidden mount, network, and Docker-argument fields refused | policy_refusal | host_check | refused before any Docker invocation | **PASS** | 8 case(s) refused before Docker |
| POL-03 | Floating image references refused | policy_refusal | host_check | tags, name@digest, and short IDs refused before any Docker invocation | **PASS** | 12 case(s) refused before Docker |
| POL-04 | Limits above code ceilings refused | policy_refusal | host_check | refused before any Docker invocation | **PASS** | 6 case(s) refused before Docker |
| POL-05 | Inspect gate rejects drifted configuration | policy_refusal | host_check | real target inspect passes; every mutated copy (privileged, cap-add, socket bind, bridge, unconfined seccomp, unlimited memory) is rejected | **PASS** | 16 drifted copies rejected; unmutated copy accepted |
| POL-06 | Every created container passed the inspect gate before start | configuration | inspect | gate passed for every started container; none started after a mismatch | **PASS** | 10 containers matched the policy before start |
| CLN-01 | Owned containers removed by exact ID | cleanup | host_check | every owned container removed and confirmed absent | **PASS** | 8/8 removed and confirmed absent |
| CLN-02 | Container from another run refused | cleanup | host_check | cleanup refuses the other-run decoy; it still exists afterwards | **PASS** | refused; decoy still present |
| CLN-03 | Container without PatchProof ownership refused | cleanup | host_check | cleanup refuses the foreign decoy; it still exists afterwards | **PASS** | refused; decoy still present |
| CLN-04 | Decoys torn down by their separate path | cleanup | host_check | both decoys removed by exact ID and confirmed absent | **PASS** | 2 decoys removed |
| CLN-05 | Only allowlisted Docker operations executed | cleanup | host_check | command log contains only allowlisted operations; no prune, filter, force, or bulk removal | **PASS** | 101 commands, all allowlisted operations |
| CLN-06 | Unrelated resources preserved | cleanup | host_check | image, container, volume, network, and build-cache snapshots identical before and after | **PASS** | snapshots identical |

## Limitations

- Results describe this Docker Desktop installation on the recorded date only; they are not a guarantee against container-runtime vulnerabilities (PROJECT_SPEC.md 4.1).
- Configuration evidence (inspect, kernel-reported state) is not enforcement evidence; see control_claims.
- Network negatives sample representative destinations; the structural evidence is NET-01 and NET-09.
- CPU enforcement (RES-06) is statistical and sensitive to host load.
- Daemon log retention (RES-11) is measured through docker logs, not on-disk size inside the VM.
- no-new-privileges is kernel-reported (NoNewPrivs); no setuid binary is executed to exercise it.
- Root-only writable mounts (/dev tmpfs, /dev/mqueue) are classified, not write-exercised beyond /etc bind files.
- Interrupted-run recovery is covered by unit tests; the probe run does not deliberately crash itself.
- The sleeper container's stdout was not persisted by the runner; RES-12's 'sleeping' internal control was judged in memory. The command log corroborates it (start ok, wait timed out at 10.0 s, stop 5.1 s, removed).
- net.core.fb_tunnels_only_for_init_net was unreadable inside the container (ENOENT); the fallback-device explanation rests on kernel documentation and the observed device types, not on the sysctl value.
- Results describe one run on one Docker Desktop installation on 2026-10-12; they do not make Docker escape-proof or establish that arbitrary hostile repositories are safe to execute.
