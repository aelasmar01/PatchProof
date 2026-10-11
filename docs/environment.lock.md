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
| Docker CLI | 28.2.2, build e6534b4, Go 1.24.3, API 1.50, `darwin/amd64` |
| CLI build date | 2025-05-30 |
| Docker Desktop application | **4.42.1**, placed 2025-06-17 at `/Applications/Docker.app` |
| Built against | macOS 14.5 SDK (`DTPlatformVersion = 14.5`); `LSMinimumSystemVersion = 13.0` |
| Active context | `desktop-linux` |
| Other runtimes | None. No Colima, Podman, nerdctl, Lima, or Rancher Desktop. |

The 4.42.1 version is the subject of blocker 6.5 and is unchanged by the daemon now
being reachable.

### 4.2 Daemon (measured)

| Fact | Measured value | Relevance |
|---|---|---|
| Server version | 28.2.2 | Matches the client. |
| Operating system | Docker Desktop (Linux VM) | §4.1 — the daemon is in the TCB. |
| Architecture | `x86_64` | Matches the host. |
| Kernel | 6.10.14-linuxkit | VM kernel, not macOS. |
| Storage driver | `overlayfs` | — |
| cgroup driver / version | `cgroupfs`, **v2** | §5.2 resource limits depend on cgroup v2. |
| Default runtime | `runc` | — |
| VM CPUs | **16** | §5.2 needs 1 CPU for target + 1 for verifier. |
| VM memory | **8218136576 bytes (7.65 GiB)** | See 4.4. |
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

The host has 32 GiB, but Docker Desktop's Linux VM is allocated **7.65 GiB**. That VM
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

### 6.5 UNRESOLVED (BLOCKER) — installed Docker Desktop 4.42.1 is unsupported and carries an on-path critical container-escape CVE

**Checked 2026-10-11** against Docker's official documentation. Resolved in three
parts; only the third is a problem.

**macOS version — OK.** Docker's stated policy is: *"Docker Desktop is supported on
the current and two previous major macOS releases."* [R1] macOS 26 is the current
release, so macOS 26.3.1 is inside the support window.

**Intel architecture — OK.** Docker still publishes a "Mac with Intel chip" build for
the current release (4.94.0), and the install page keeps a dedicated Intel system
requirements section. No Intel deprecation or end-of-life date is announced. [R1]
Minimum RAM is 4 GiB; this host has 32 GiB.

**Installed Docker Desktop version — NOT SUPPORTED.**

| Fact | Value |
|---|---|
| Installed | **4.42.1**, placed 2025-06-17, built against the macOS 14.5 SDK (`DTPlatformVersion = 14.5`) |
| Current release | **4.94.0**, released 2026-10-05 |
| Gap | ~16 months, ~52 releases |
| Docker download policy | "Docker Desktop versions older than 6 months from the latest release are not available for download" |
| Docker support policy | Pro/Team support the latest version only; Business supports up to 6 months older, with fixes applied to the latest version only |

4.42.1 is roughly 16 months old, so it is outside every window Docker offers: not
downloadable, not supported, and not receiving fixes. It was also built before macOS
26 existed, so its compatibility with macOS 26.3.1 is untested by Docker rather than
merely undocumented. §5.1 requires "a currently supported Docker Desktop Intel
release compatible with the actual macOS installation." **4.42.1 does not meet that
requirement.**

#### Why this is a blocker and not a hygiene item

Docker Desktop sits inside PatchProof's trusted computing base. §4.1 states this
directly: the daemon can mount and modify host files, so "the runner therefore
belongs to the trusted computing base" [R3]. Running deliberately vulnerable target
code against an unpatched runtime puts the untrusted side of the design next to the
component the design trusts most.

Docker's security announcements list at least twelve Docker Desktop advisories fixed
*after* 4.42.1. Two matter here:

| CVE | Affected | Fixed in | Note |
|---|---|---|---|
| **CVE-2025-9074** | **≤ 4.44.2** | 4.44.3 (2025-08-20) | **Critical, CVSS 9.3.** A running Linux container can reach the Docker Engine API unauthenticated, leading to container escape and host compromise on macOS and Windows. A public proof-of-concept exists. |
| CVE-2025-23266 | ≤ 4.43.x | 4.44.0 (2025-07-31) | Critical. |
| CVE-2025-6587 | ≤ 4.42.x | 4.43.0 (2025-07-03) | Affects the installed version directly. |

Later advisories fixed through 4.47.0, 4.49.0, 4.54.0, 4.62.0 (×2), 4.67.0, 4.68.0,
4.71.0 and 4.86.0 also post-date 4.42.1.

**CVE-2025-9074 directly undermines INV-02.** That invariant says no target or
verifier container receives the Docker socket. PatchProof enforces it by
configuration — by not mounting the socket. On an affected runtime a container can
reach the Engine API *without* being given the socket, so the configuration control
is bypassed at the runtime layer. The invariant would read as satisfied in the
execution plan while being false in practice.

The exposure is on-path rather than theoretical. §4.1 classifies the target
application and everything it returns as lower-trust execution, and §1.3 makes
running vulnerable revisions the product's normal operation. Any PP-003 probe or
PP-008 run would place lower-trust code in exactly the position this CVE requires.

#### Required action, in order

1. **Do not start the daemon on 4.42.1.** Starting it to measure isolation would
   generate v0.0 gate evidence from a runtime whose escape boundary is known broken.
   Any such measurement would be invalid for §15.1.
2. **Approve upgrading Docker Desktop to the current 4.94.0 Intel build** (owner
   action — §5.1 forbids silent fallback, and §23.2 requires approval for
   installation). This is the smallest supported adjustment and changes no security
   invariant.
3. Re-measure: record `docker info` server version, OS, architecture, `NCPU`,
   `MemTotal`, and the active context in this file.
4. Then run the PP-003 probe suite and record a tested result per restriction.

If the upgrade turns out to be unavailable for this hardware or macOS combination,
§5.1 permits evaluating Colima's Intel support instead [R2]. Do not proceed on
4.42.1 either way.

#### Recorded limitation

Upgrading to a supported release removes these known advisories. It does not make the
container boundary a comprehensive protection guarantee — §4.1 already places
container-runtime vulnerabilities outside that guarantee. The honest claim after
upgrading is "a currently supported runtime with no known applicable advisories at
the recorded date," not "escape-proof."

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
| 1 | **Approve upgrading Docker Desktop 4.42.1 → 4.94.0 (Intel).** Unsupported release; CVE-2025-9074 (CVSS 9.3) breaks INV-02 at the runtime layer (6.5) | Owner | PP-003 and all execution |
| 2 | Approve `brew upgrade git` (6.2) | Owner | PP-005 |
| 3 | Decide on removing `~/.git` (6.1) | Owner | Safe local Git hygiene |
| 4 | Approve Python 3.13.x patch + pin (6.3) | Owner | PP-004 packaging |
| 5 | Approve starting the Docker daemon and running the PP-003 probe suite — **only after action 1** | Owner | v0.0 exit gate |

Action 4 in the previous revision of this table ("verify Docker Desktop vs macOS 26")
was completed on 2026-10-11; its result is Section 6.5 and it is now action 1.
