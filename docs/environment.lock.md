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

| Fact | Measured value | Command |
|---|---|---|
| Docker CLI | 28.2.2, build e6534b4 | `docker --version` |
| Docker Desktop application | 4.42.1, present at `/Applications/Docker.app` | `defaults read .../Info.plist` |
| Docker daemon | **NOT RUNNING** — `Cannot connect to the Docker daemon at unix:///Users/aliel-asmar/.docker/run/docker.sock` | `docker info` |
| Active context | `desktop-linux` | `docker context ls` |
| Server version / OS / arch | **UNRESOLVED** — daemon unreachable | `docker info` |
| Colima | Not installed | `command -v colima` |

The daemon was deliberately **not started**. PP-001 forbids changing machine state,
and the Section 15.1 isolation probes are PP-003 work that requires separate owner
approval. Every daemon-side fact — server version, enforced CPU/memory limits,
`none` network behaviour, read-only mount support, non-root execution, namespace
separation — is therefore unmeasured.

**Consequence for the Section 15.1 exit gate:** the gate requires "a recorded tested
result" for each runtime restriction. None exist yet. v0.0 cannot pass on the
strength of this report alone.

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

### 6.5 Informational — macOS 26.3.1 on Intel hardware

The machine runs macOS 26.3.1 on `x86_64`. §5.1 requires a "currently supported
Docker Desktop Intel release compatible with the actual macOS installation" and warns
that Docker's macOS support policy shifts with OS releases [R1].

Docker Desktop 4.42.1 is installed. Whether that build is supported on macOS 26 is
**UNRESOLVED** — it was not verified, and the daemon was not started.

*Required before PP-003:* check Docker's current macOS platform requirements against
macOS 26.3.1 and Docker Desktop 4.42.1; if unsupported, present an approved upgrade,
or evaluate Colima's Intel support as §5.1 allows. Do not fall back silently.

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
- No image digest is pinned; `containers/` is unwritten.
- No dependency set is resolved; there is no `pyproject.toml` or `uv.lock` yet.
- Docker Desktop's compatibility with macOS 26.3.1 is unconfirmed.
- The applicability of specific Git advisories to 2.42.0 is unconfirmed.

## 8. Required next actions, in order

| # | Action | Who | Blocking |
|---|---|---|---|
| 1 | Decide on removing `~/.git` (6.1) | Owner | Safe local Git hygiene |
| 2 | Approve `brew upgrade git` (6.2) | Owner | PP-005 |
| 3 | Approve Python 3.13.x patch + pin (6.3) | Owner | PP-004 packaging |
| 4 | Verify Docker Desktop 4.42.1 vs macOS 26.3.1 (6.5) | Agent, then owner approves any upgrade | PP-003 |
| 5 | Approve starting the Docker daemon and running the PP-003 probe suite | Owner | v0.0 exit gate |
