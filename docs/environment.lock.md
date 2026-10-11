# Environment lock — measured host facts

**Issue:** PP-001 (v0.0 foundation)
**Measured:** 2026-10-11
**Method:** Read-only shell inspection. No software installed, no daemon started,
no container run, no `sudo`, no VM setting changed.
**Status:** `READY_FOR_REVIEW`. Values marked UNRESOLVED are blockers or require
owner approval before the issue that depends on them.

> Every row below is a measured command result, not an inference. Where the
> specification assumed a value that does not match this machine, the conflict is
> recorded in Section 6 rather than silently accepted.

---

## 1. Machine and operating system

| Fact | Measured value | Command |
|---|---|---|
| Hardware model | `MacBookPro16,1` (16-inch MacBook Pro, 2019) | `sysctl -n hw.model` |
| CPU | Intel Core i9-9880H @ 2.30 GHz | `sysctl -n machdep.cpu.brand_string` |
| Architecture | `x86_64` | `uname -m` |
| Physical cores | 8 | `sysctl -n hw.physicalcpu` |
| Logical cores | 16 | `sysctl -n hw.logicalcpu` |
| Physical memory | 34359738368 bytes (32.00 GiB) | `sysctl -n hw.memsize` |
| macOS product version | 26.3.1 (a) | `sw_vers` |
| macOS build | 25D771280a | `sw_vers` |
| Darwin kernel | 25.3.0 | `uname -r` |

The specification described the host only as "a 2019 Intel Mac" and used 16 GiB as a
planning target. Both are now measured: the machine is a 2019 16-inch MacBook Pro
with **32 GiB**, double the planning target. The Section 5.2 resource envelope is
therefore comfortable and needs no reduction.

## 2. Storage

| Volume | Size | Used | Available | Command |
|---|---|---|---|---|
| `/` (sealed system) | 932 GiB | 17 GiB | 562 GiB | `df -h /` |
| `/System/Volumes/Data` | 932 GiB | 337 GiB | 562 GiB | `df -h` |

562 GiB available. Sufficient for the Section 5.2 snapshot caps (100 MiB per
snapshot), container images, and evidence retention with wide margin.

## 3. Toolchain present on the host

| Tool | Measured version | Path / source | Specification target | Verdict |
|---|---|---|---|---|
| Git | 2.42.0 | `/usr/local/bin/git` (Homebrew, installed 2023-09-06) | "supported patched Git release" (§9.2) | **CONFLICT — see 6.2** |
| Python | 3.13.1 | `python3` | Python 3.13, "supported patched release" (§3.1) | **CONFLICT — see 6.3** |
| Python (other) | 3.12.13, 3.11.11 | `python3.12`, `python3.11` | n/a | Available |
| `uv` | 0.10.7 | on `PATH` | `uv` packaging (§3.1) | Satisfied |
| Node.js | 22.22.1 | `node` (via `nvm` 0.40.1) | Node.js 24 LTS (§3.1) | **CONFLICT — see 6.4** |
| npm | 10.9.4 | `npm` | npm lockfile (§3.1) | Satisfied |
| Homebrew | 6.0.21 | `brew` | n/a | Available for approved upgrades |
| Xcode command-line tools | selected at `~/Downloads/Xcode.app/Contents/Developer` | `xcode-select -p` | n/a | Non-standard location; noted, not a blocker |

Not installed, and not required before the issue that needs them: Semgrep, Gitleaks,
Trivy, ZAP, Playwright browsers.

## 4. Container runtime

Daemon facts were initially UNRESOLVED because the daemon was not running. The owner
started Docker Desktop on 2026-10-11 and the daemon-side values below are now
measured. **All inspection was read-only** (`docker info`, `docker images`,
`docker ps -a`). No container was created, started, or removed; no image was pulled.

### 4.1 Client and application

| Fact | Measured value |
|---|---|
| Docker CLI | **29.8.2** |
| Docker Desktop application | **4.94.0** (upgraded 2026-10-11 from 4.42.1) |
| Built against | macOS 15.5 SDK (`DTPlatformVersion = 15.5`) |
| Active context | `desktop-linux` |
| Other runtimes | None. No Colima, Podman, nerdctl, Lima, or Rancher Desktop. |

**Blocker 6.5 is RESOLVED.** The owner upgraded to 4.94.0, the current release, on
2026-10-11. See 6.5 for the verification and the residual limitation.

### 4.2 Daemon (measured)

| Fact | Measured value | Relevance |
|---|---|---|
| Server version | **29.8.2** | Matches the client. Was 28.2.2 before the upgrade. |
| Operating system | Docker Desktop (Linux VM) | §4.1 — the daemon is in the TCB. |
| Architecture | `x86_64` | Matches the host. |
| Kernel | **7.0.14-linuxkit** | VM kernel, not macOS. Was 6.10.14-linuxkit. |
| Storage driver | `overlayfs` | — |
| cgroup driver / version | `cgroupfs`, **v2** | §5.2 resource limits depend on cgroup v2. |
| Default runtime | `runc` | — |
| VM CPUs | **16** | §5.2 needs 1 CPU for target + 1 for verifier. |
| VM memory | **8320897024 bytes (7.75 GiB)** | See 4.4. |
| Security options | `seccomp` (profile: **builtin**), `cgroupns` | Default seccomp is active; cgroup namespacing available. |
| User namespace remapping | **Not listed** — `userns` absent from security options | Non-root execution must be enforced per-container (`--user`), not by daemon-wide remapping. Record this in PP-003. |
| Network drivers available | `bridge`, `host`, `ipvlan`, `macvlan`, **`null`**, `overlay` | The `null` driver is present, so INV-03's `--network none` is available [R5]. |
| Daemon warnings | None reported | Docker does not warn about missing CPU/memory limit support on this host. |

### 4.3 Pre-existing Docker resources that must be preserved

The daemon holds unrelated work from other projects:

- **9 images**, ~4.4 GiB total, including `qdrant/qdrant`, `redis:7`, `postgres:16`,
  three `crypto-hybrid-scanner-*` images, `devsecops-pipeline-demo-web`,
  `bkimminich/juice-shop`, and one dangling `<none>` layer.
- **7 stopped containers**, last exited 7–14 months ago (`qdrant`,
  `crypto_scanner_{frontend,backend,worker,postgres,redis}`,
  `devsecops-pipeline-demo-web-1`).

**This is a live constraint, not trivia.** §5.4 states PatchProof must "never run
`docker system prune` or delete unrelated resources," and PP-014's completion
evidence requires "unrelated resources preserved." These 9 images and 7 containers
are the concrete baseline that the PP-014 reconciliation tests must leave untouched.

**These survived the 4.42.1 → 4.94.0 upgrade intact**, verified by `docker system df`
immediately after: 9 images, 7 containers, 10 volumes (2 active), all still present.
Image and build-cache sizes are reported differently by the new daemon (4.60 GB → 3.26
GB images, 816 MB → 2.34 GB build cache) because 29.x accounts for shared layers
differently; no image or container was removed.

Carried forward as requirements:

- PP-008 labels every owned container with the installation ID and run ID.
- PP-014 reconciliation cleans up **only** resources whose installation and run IDs
  match its own registry, and a test must assert this baseline survives a full
  cancel/crash/restart cycle.
- No PatchProof code path may call `docker system prune`, `docker image prune`, or any
  unfiltered bulk removal.

Note also that `bkimminich/juice-shop` is a deliberately vulnerable application image.
It is unrelated to PatchProof and must not be confused with an approved target or
reference profile; §1.3 requires the reference application to be PatchProof's own
synthetic `papertrail` fixture (PP-006).

### 4.4 VM memory is the real ceiling, not host RAM

The host has 32 GiB, but Docker Desktop's Linux VM is allocated **7.75 GiB**. That VM
figure, not host RAM, is what bounds container execution.

The §5.2 envelope needs 1 GiB for the target plus 512 MiB for the verifier — about
1.5 GiB per revision, with one comparison at a time. That fits comfortably, and
§5.2's note about running UI builds separately on low-memory hardware does not apply
here.

No change is requested. §5.1 forbids resizing the VM without explicit approval, and
no resize is needed.

### 4.5 Still not measured

Every value above comes from daemon introspection. **No isolation property has been
tested**, because testing requires running containers (PP-003) and, per 6.5, must not
happen on 4.42.1. Specifically unverified: whether `--network none` actually blocks
egress, whether CPU and memory limits are enforced in practice, whether read-only
root filesystems and tmpfs mounts behave as specified, whether a non-root `--user`
holds, and whether the target side can observe verifier files or the Docker socket.

The presence of a capability in `docker info` is not evidence that a restriction is
enforced. §5.2 is explicit that configured limits require enforcement probes.

## 5. Host Git configuration relevant to the trust model

Measured via `git config --global --list`:

| Setting | Value | Why it matters |
|---|---|---|
| `filter.lfs.clean` / `.smudge` / `.process` | `git-lfs ...` | §9.2 forbids working-tree filters during snapshot creation. |
| `filter.lfs.required` | `true` | A required filter can fail or transform blob bytes. The PP-005 wrapper must disable filters explicitly and not inherit host config. |
| `credential.https://github.com.helper` | `!/usr/local/bin/gh auth git-credential` | Host credential helper. Must never be inherited into the sanitized snapshot environment or a container. |
| `user.name` / `user.email` | set (value not reproduced here) | Local reviewer identity for §7.5 approval records. The configured email differs from the GitHub account email, so approval records and commit authorship will not match. Decide which identity §7.5 records. |

**Carried into PP-005 as a hard requirement:** the Git subprocess wrapper runs with a
sanitized environment and explicit config overrides; it must not rely on the host's
global configuration being benign.

## 6. Conflicts between this machine and the specification

### 6.1 UNRESOLVED (blocker) — a second Git repository owns the home directory

`git rev-parse --show-toplevel` from inside this project, **before** this project was
initialized, returned `/Users/aliel-asmar`. A `.git` directory exists at the home
directory with:

- 2 commits, both titled "first commit", 0 tracked files, one `README.md` in history
- `origin` → `github.com/aelasmar01/BashScripts.git`
- `upstream` → `github.com/aelasmar01/Python_Automation.git`

Because nothing is tracked, every file in `~` — `.ssh/`, `.aws/`, `.config/`,
`Library/`, `.claude.json` — reports as untracked. A single `git add -A` with that
worktree root would stage private keys and cloud credentials.

This project now shadows it (`git init` here re-roots the subtree), so PatchProof
work is contained. The home repository itself is **untouched and still present**.

*Requires owner decision.* Recommended: back up `~/.git/config`, then remove
`~/.git`. Nothing is tracked there, so no content is lost. Not done — removal is
destructive and outside PP-001.

### 6.2 UNRESOLVED (approval required) — Git 2.42.0 is approximately three years old

Installed 2023-09-06; Homebrew's current stable is 2.56.0. §9.2 requires "a supported
patched Git release", and PatchProof's snapshot path depends directly on Git object
reading (`ls-tree`, `cat-file`). Upstream Git has shipped security releases since
2.42.0, so this is the oldest-risk component in the measured toolchain.

*Smallest supported adjustment:* `brew upgrade git`. No core security invariant
changes. Not performed — PP-001 forbids installation.

*Not yet verified:* which specific advisories apply to 2.42.0. That check belongs in
PP-005's dependency review and should cite the Git release notes directly rather than
being asserted here.

### 6.3 Minor (approval required) — Python 3.13.1 is behind on patches

3.13.1 shipped 2024-12. §3.1 asks for a *supported patched release* of 3.13 selected
during preflight. Later 3.13.x patches exist.

*Smallest supported adjustment:* install the current 3.13.x and pin it in
`pyproject.toml` with `uv`. Defer the exact pin to the PP-001 follow-up approval so
`uv.lock` is generated once, against an approved interpreter.

### 6.4 Minor — Node.js 22.22.1 present, specification named Node.js 24 LTS

§3.1 selected Node.js 24 LTS for development and build, with the note "select an
available supported patch at setup". Node 22 is itself an LTS line, and `nvm` 0.40.1
is installed, so either is reachable without a system change.

*Recommendation:* keep Node 22.22.1 for now and revisit at PP-013, when the frontend
is first built. Node is a build-time dependency only — §3.1 confirms production
serves built assets and does not run Node — so this does not affect any security
invariant. Decide at PP-013 rather than installing now.

### 6.5 RESOLVED — Docker Desktop upgraded 4.42.1 → 4.94.0

**Checked 2026-10-11** against Docker's official documentation, then resolved the
same day by owner-approved upgrade.

#### What the check found

Docker's macOS and Intel support were never the problem:

- **macOS version — OK.** Docker's policy is *"Docker Desktop is supported on the
  current and two previous major macOS releases."* [R1] macOS 26 is current, so
  26.3.1 is inside the window. Homebrew's cask metadata for 4.94.0 independently
  states `Required: macOS >= 14`.
- **Intel architecture — OK.** Docker still publishes a "Mac with Intel chip" build
  for the current release, with its own system-requirements section. No Intel
  deprecation or end-of-life date is announced. [R1] Minimum RAM 4 GiB; host has 32.

The **installed version** was the problem. 4.42.1 (placed 2025-06-17, built against
the macOS 14.5 SDK) was ~16 months and ~52 releases behind 4.94.0. That put it outside
every window Docker offers: past the "versions older than 6 months from the latest
release are not available for download" cutoff, and outside all support tiers
(Pro/Team support the latest version only; Business supports up to 6 months older,
with fixes applied to the latest version only). It also predated macOS 26, so its
compatibility with 26.3.1 was untested by Docker rather than merely undocumented.
§5.1 requires "a currently supported Docker Desktop Intel release compatible with the
actual macOS installation"; 4.42.1 did not meet it.

#### Why it was a blocker rather than a hygiene item

§4.1 places the Docker runner inside the trusted computing base: the daemon can mount
and modify host files [R3]. Docker's security announcements list at least twelve
Desktop advisories fixed after 4.42.1, including:

| CVE | Affected | Fixed in | Note |
|---|---|---|---|
| **CVE-2025-9074** | **≤ 4.44.2** | 4.44.3 (2025-08-20) | **Critical, CVSS 9.3.** A running Linux container can reach the Docker Engine API unauthenticated, leading to container escape and host compromise on macOS and Windows. Public proof-of-concept. |
| CVE-2025-23266 | ≤ 4.43.x | 4.44.0 (2025-07-31) | Critical. |
| CVE-2025-6587 | ≤ 4.42.x | 4.43.0 (2025-07-03) | Affected the installed version directly. |

**CVE-2025-9074 undermined INV-02.** That invariant says no target or verifier
container receives the Docker socket, and PatchProof enforces it *by configuration*,
by not mounting the socket. On an affected runtime a container reaches the Engine API
without being given the socket, so the configuration control is bypassed at the
runtime layer — the invariant would read as satisfied in the execution plan while
being false in practice.

The exposure was on-path, not theoretical: §1.3 makes running vulnerable target
revisions the product's normal operation and §4.1 classifies that code as lower-trust
execution, so any PP-003 probe or PP-008 run would have placed lower-trust code in
exactly the position the CVE requires.

#### Resolution

The owner upgraded on 2026-10-11. The first attempted route failed and is recorded
because it affects how this host is maintained:

- `brew upgrade --cask docker` returned `Error: Cask 'docker-desktop' is not
  installed`. **Docker Desktop on this host is not Homebrew-managed** — it was
  installed manually from the `.dmg`. Installed casks are only `codex`,
  `hashicorp-vagrant`, `moonlight`, `wechat`. Homebrew is not the upgrade path here,
  and the `docker-desktop` cask is marked `auto_updates` so it would not be even
  after adoption. Use Docker Desktop's in-app updater or the Intel `.dmg` from
  `https://desktop.docker.com/mac/main/amd64/Docker.dmg`.

Measured after the upgrade:

| Fact | Before | After |
|---|---|---|
| Docker Desktop | 4.42.1 | **4.94.0** |
| Client / server | 28.2.2 | **29.8.2** |
| VM kernel | 6.10.14-linuxkit | **7.0.14-linuxkit** |
| Built against | macOS 14.5 SDK | **macOS 15.5 SDK** |
| VM memory | 7.65 GiB | 7.75 GiB |
| cgroup / seccomp / `null` driver | v2 / builtin / present | unchanged |

4.94.0 is the current release, so §5.1's requirement is met and every advisory listed
above is patched. §5.1's Colima fallback [R2] was not needed.

Pre-existing resources survived: 9 images, 7 containers, 10 volumes (2 active), all
present after the upgrade. See 4.3.

#### Residual limitation

Upgrading removes these **known** advisories as of 2026-10-11. It does not make the
container boundary a comprehensive protection guarantee — §4.1 already places
container-runtime vulnerabilities outside that guarantee. The honest claim is "a
currently supported runtime with no known applicable advisories at the recorded
date," not "escape-proof."

Re-check Docker Desktop's version and advisories at each release gate, and record the
version in that gate's evidence. A runtime that was current at v0.1 will not be
current at v1.0.

### 6.6 Informational — project location

§5.3 suggested `~/Developer/patchproof`. Actual location is
`~/Desktop/PatchProof`, chosen by the owner. `platformdirs` still governs private
state and cache paths, so no invariant is affected.

Note that `~/Desktop` may be covered by macOS privacy protections (TCC) and, if
Desktop sync is ever enabled in iCloud, would become a cloud-synced destination.
§5.3 forbids reports defaulting to such a location. Keep the export folder outside
`~/Desktop`.

---

## 7. What this report does not establish

- No container isolation property has been tested. §4.2 invariants INV-01 through
  INV-03 are **unverified** on this host.
- No resource limit has been shown to be enforced. §5.2 is a design envelope only.
  `docker info` reports cgroup v2 and no limit warnings, but capability is not
  enforcement — see 4.5.
- No image digest is pinned; `containers/` is unwritten. The 9 images already on the
  daemon are unrelated to PatchProof and are not approved profiles.
- No dependency set is resolved; there is no `pyproject.toml` or `uv.lock` yet.
- Docker Desktop 4.42.1's compatibility with macOS 26.3.1 is untested by Docker; it
  predates macOS 26. Resolved as a blocker in 6.5 rather than left open.
- The applicability of specific Git advisories to 2.42.0 is unconfirmed.

## 8. Required next actions, in order

| # | Action | Who | Blocking |
|---|---|---|---|
| 1 | Approve `brew upgrade git` 2.42.0 → 2.56.0 (6.2) | Owner | PP-005 |
| 2 | Decide on removing `~/.git` (6.1) | Owner | Safe local Git hygiene |
| 3 | Approve Python 3.13.x patch + pin (6.3) | Owner | PP-004 packaging |
| 4 | Approve running the PP-003 isolation probe suite — now unblocked on the runtime side | Owner | v0.0 exit gate |

**Completed 2026-10-11:**

- Verify Docker Desktop vs macOS 26.3.1 — result in 6.5.
- Upgrade Docker Desktop 4.42.1 → 4.94.0 — done by the owner; 6.5 is RESOLVED and
  the runtime no longer blocks PP-003.
