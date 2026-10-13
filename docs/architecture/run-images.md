# Target and verifier run images: preparation plan (PP-008, gate B)

**Status (2026-10-13):** gate B was approved and executed. The eight wheels were downloaded and
verified, and two images were built from the r1 recipes. The verifier image is defective
(G-B1), and the corrected r2 recipes are not built. Results:
`docs/evidence/pp-008-gate-b-images.md`. The original plan follows.
Every step below needs the owner's explicit approval. The resulting local image identities
must then be reviewed before any run (gate C). The PP-003 probe image is **not** assumed to
be approved for these roles. This plan only proposes reusing the same base digest.

Recipes: `containers/target-python/Dockerfile` and `requirements.lock`, and
`containers/verifier/Dockerfile` and `requirements.lock`. `tests/unit/test_run_images.py`
keeps the recipes consistent with the code that will verify the built images.

## 1. Base image (both images)

| Item | Value |
|---|---|
| Registry / repository / tag | `docker.io/library/python:3.13-slim` (the tag is a lookup only, never an identity) |
| Immutable digest | `sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f` (OCI image index) |
| Platform used | `linux/amd64`; manifest `sha256:8fb4cfa1a2616d7b8e0c2175cc6ad68f5729c34ea8488c0b360d2934b7be9024`, created 2026-10-06T01:55:23Z |
| Python | CPython 3.13.16 (recorded at PP-003 A1) |
| Current upstream | On 2026-10-12, Docker Hub's `python:3.13-slim` index digest is **identical** to this one (registry metadata read only; nothing pulled) |
| Local presence | Already in the local image store since PP-003 A1, so **no pull is needed** |

## 2. Target image

| Package | Version | Role | Wheel | SHA-256 | Provenance |
|---|---|---|---|---|---|
| uvicorn | 0.54.0 (2026-09-25) | ASGI server | `uvicorn-0.54.0-py3-none-any.whl` | `505bdb0f318731d45f1f712071fc781a8981f6847a31c902c9f5e652d4f67faf` | Trusted Publishing: GitHub `Kludex/uvicorn` `publish.yml` |
| click | 8.5.0 | uvicorn dependency | `click-8.5.0-py3-none-any.whl` | `255bc9599cf7748b4b1a446ccc735421bd08a2ae529a8b88597d3de5664ee360` | Trusted Publishing: GitHub `pallets/click` `publish.yaml` |
| h11 | 0.16.0 | uvicorn dependency | `h11-0.16.0-py3-none-any.whl` | `63cf8bbe7522de3bf65932fda1d9c2772064ffb3dae62d55932da54b31cb6c86` | no attestation found; hash pin only |

**Dependency graph:**
- uvicorn 0.54.0 requires `click>=7.0` and `h11>=0.8`. `typing-extensions` is required only
  for Python < 3.11, so it is not needed.
- click 8.5.0 and h11 0.16.0 have no dependencies.
- PaperTrail itself imports only the standard library.

All three wheels are `py3-none-any`, so the platform is not a concern for linux/amd64 and
Python 3.13; each declares `requires_python >=3.10` or lower.

**Advisories:** OSV and PyPI list none for these exact versions (checked 2026-10-12).

**Freshness:**
- uvicorn 0.54.0 was published 3 days before the cooldown date
  (`exclude-newer = 2026-09-28`), so it satisfies the existing two-week rule relative to
  that date. It is the newest eligible release.
- The startup flags were checked against the 0.54.0 source tag.

**Fixed startup** (`run_policy.target_command`):
`python3 -I -B -m uvicorn papertrail.app:app --app-dir /app/source --host 127.0.0.1 --port 8080 --workers 1 --loop asyncio --http h11 --ws none --interface asgi3 --lifespan on --no-access-log --no-proxy-headers --no-server-header --timeout-graceful-shutdown 3`

**Health check:** `HEALTHCHECK`, exec form with no shell. It is a fixed standard-library GET
of `/health` and must equal `run_policy.TARGET_HEALTHCHECK`. Docker records it, and the host
only reads the health state.

## 3. Verifier image

| Package | Version | Wheel SHA-256 | Provenance |
|---|---|---|---|
| **pytest** | **9.0.3 (proposed; see the decision below)** | `2c5efc453d45394fdd706ade797c0a81091eccd1d6e4bccfcd476e2b8e0ab5d9` | Trusted Publishing: GitHub `pytest-dev/pytest` `deploy.yml` |
| iniconfig | 2.3.0 | `f631c04d2c48c52b84d0d0549c99ff3859c98df65b3101406327ecc7d53fbf12` | Trusted Publishing: `pytest-dev/iniconfig` |
| packaging | 26.3 | `d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c` | Trusted Publishing: `pypa/packaging` |
| pluggy | 1.6.0 | `e920276dd6813095e9377c0bc5566d94c932c33b27a3e3945d8389c374dd4746` | Trusted Publishing: `pytest-dev/pluggy` |
| pygments | 2.21.0 | `2363c69b61c4a97c838da3b130dcd6468f4848992b21a82f2a63ec34377137d9` | no attestation found; hash pin only |

These pytest dependencies are the same versions already locked for the host's dev tools.
pytest 9.0.3 requires iniconfig ≥1.0.1, packaging ≥22, pluggy ≥1.5,<2 and pygments ≥2.7.2;
colorama, exceptiongroup and tomli apply only on other platforms or older Python versions.

**PatchProof content** (root-owned, read-only to UID 10001):
- `verifier/patchproof_verifier/*.py`, copied into site-packages;
- `verifier/pytest.ini`, at `/opt/patchproof/verifier/pytest.ini`.

**Environment:** `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`, `PYTHONDONTWRITEBYTECODE=1`,
`PYTHONHASHSEED=0`, `LC_ALL=C.UTF-8`, `HOME=/nonexistent`.

**No target source.**

**Fixed entry:**
- run: `python3 -I -B -m patchproof_verifier.launch run ... -- /pack/tests/...`
- collection: `... launch collect --pack /pack -- ...`

### Owner decision 1: pytest version (security advisory)

pytest **8.4.2**, the version the request named, is affected by **CVE-2025-71176**
(GHSA-6w46-j5rx-g56g, PYSEC-2026-1845, CVSS 3.1 AV:L/AC:L/PR:N, moderate):
- **The flaw:** "pytest through 9.0.2 on UNIX relies on directories with the
  `/tmp/pytest-of-{user}` name pattern, which allows local users to cause a denial of
  service or possibly gain privileges."
- **The fix:** 9.0.3, published 2026-04-07, inside the cooldown.

**Options:**
- **(a) Recommended:** pytest **9.0.3** in the verifier image, as written in the recipe. If
  chosen, the host dev pin should also move to 9.0.3, so the plugin is tested against the
  same version that runs it. That is a separate host dependency approval.
- **(b)** Keep **8.4.2** and accept the advisory with mitigations: the verifier is a
  single-user container with a private `/tmp` tmpfs, and `verifier/pytest.ini` now disables
  pytest's `tmpdir` plugin (`-p no:tmpdir`), which never creates `/tmp/pytest-of-*`.

The host's own pytest 8.4.2 (dev tooling on a single-user Mac, which uses a per-user
`$TMPDIR`) is equally affected in principle. Upgrading it is a separate decision.

### Owner decision 2: HTTP client library

§3.1 names HTTPX for the verifier. PP-008 implements the transport with the standard
library's `http.client` (`patchproof_verifier.transport`). That covers a fixed host, no
redirects, no proxies, separate connect and read timeouts, and a bounded body, all tested
against a synthetic local server. It adds **no** dependency.

**Option (a), recommended:** keep the standard-library transport and record a deviation
from §3.1. This removes six packages from the verifier's supply chain.

**Option (b): HTTPX.** The reviewed set would be:

| Package | Version | Wheel SHA-256 | Provenance |
|---|---|---|---|
| httpx | 0.28.1 (2024-12-06) | `d909fcccc110f8c7faf814ca82a9a4d816bc5a6dbfea25d6591d6985b8ba59ad` | no attestation found |
| httpcore | 1.0.9 | `2d400746a40668fc9dec9810239072b40b4484b640a8c38fd654a024c7a1bf55` | no attestation found |
| h11 | 0.16.0 | `63cf8bbe7522de3bf65932fda1d9c2772064ffb3dae62d55932da54b31cb6c86` | no attestation found |
| anyio | 4.15.1 | `6152fdbbf9a77fdec97731721bebf7c4c44f7c29b424b0065826173efc7ed101` | Trusted Publishing: `agronholm/anyio` |
| idna | 3.20 | `ab7ae7122974553370f0bdb919e1a960b2cd1bc1ef0276416d896db81c14582c` | Trusted Publishing: `kjd/idna` |
| certifi | 2026.7.22 | `62f22742b58a1a33014a2b6b706588a8d7e2a88ae7bd1a6ebe8c992928483775` | Trusted Publishing: `certifi/python-certifi` |
| typing-extensions | 4.16.0 | `481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8` (already in uv.lock) | no attestation found |

**HTTPX dependency graph:**
- httpx requires anyio, certifi, `httpcore==1.*` and idna;
- httpcore requires certifi and `h11>=0.16`;
- anyio 4.15.1 requires idna and `typing_extensions>=4.16.0` for Python < 3.15;
- sniffio is not required.

OSV lists no advisories for these versions. Choosing HTTPX would also need a transport
adapter change and new tests.

## 4. Planned preparation steps (only after approval)

| # | Step | Network | Creates |
|---|---|---|---|
| 1 | Create a private preparation directory outside the repository (`~/Library/Caches/PatchProof/prep-pp008`, 0700). | none | host directory |
| 2 | Download the 3 target and 5 verifier wheels from their `files.pythonhosted.org` URLs (exact filenames above), then verify each SHA-256 against the lock before use. A mismatch stops preparation. | **yes**: PyPI file host only | 8 wheel files |
| 3 | Confirm the base image is present by digest: `docker image inspect sha256:70729b46…` (read-only). If it were absent, a pull by digest would be a separate approval. | none | — |
| 4 | `docker build --network=none --platform linux/amd64 --pull=false --build-context wheels=<prep>/target-wheels -t patchproof-target:pp008 containers/target-python` | none during the build | 1 image, build-cache entries |
| 5 | The same for the verifier, adding `--build-context verifier=verifier`. | none | 1 image, build-cache entries |
| 6 | Run `docker image inspect` on both and record the evidence listed in section 5. | none | — |
| 7 | Submit the records for owner review. Only then add `ApprovedRunImage` entries to `runner/run_plan.APPROVED_RUN_IMAGES` as a reviewed code change. | none | code change |

**Docker side effects:**
- two new local images, tagged for convenience only;
- BuildKit build-cache entries;
- no containers, volumes or networks;
- nothing removed; no `prune`.

**Rollback** is removal of exactly these two image IDs, with owner approval.

**Unverified until the build runs:** BuildKit's acceptance of `RUN --mount=... [exec-form]`
and `COPY --chmod`.

## 5. Evidence to record per built image

- the local image ID (index or config digest under the containerd store), `RepoDigests`,
  and the platform;
- `Config.Env`, which becomes `ApprovedRunImage.env` and is compared exactly at every run;
- `Config.Healthcheck` (target), equal to `TARGET_HEALTHCHECK`, and its absence (verifier);
- `Config.User`, `Config.Entrypoint` and `Config.Cmd`;
- the build command, the recipe file hashes, the lock file hashes and the wheel hashes;
- `pip list` inside the image, through a **separately approved** one-off inspection
  container, or derived from the build log;
- a scan for unexpected packages, plus advisory re-checks at the build date.

## 6. Gate C (authorized 2026-10-13; completed with a documented C1b exception)

**Outcome** (evidence `docs/evidence/pp-008-gate-c.md`):
- C1a **PASS**;
- C1b **FAIL**, from an erroneous auxiliary assertion; owner-adjudicated
  ACCEPTED_FOR_C2_PROGRESSION;
- C2 **PASS**, collection only, 8/8 in manifest order;
- 3 of 3 containers used.

The code changes in 6.2 are implemented: the wrapper admission, the `STANDALONE` role
(implemented as a run role rather than a separate spec type), `runner/standalone.py`, and
the self-test pack at `examples/packs/verifier-selftest/`. The proposal text below is kept as
it was approved.

Gate B is complete. Evidence: `docs/evidence/pp-008-gate-b-images.md`. Gate C is split into
steps, each with fixed limits and stop conditions. **No step creates or implies a PaperTrail
pack approval.** That stays a separate owner action after the real collection is reviewed.

### 6.1 Identities to be approved

| Role | Image ID (r2) | Approved-record values |
|---|---|---|
| Target | `sha256:98548ec48d8d796fca5adaf4aab3e461bee38210bd1d568281f79190685eac2e` | Env as recorded; Healthcheck equals `TARGET_HEALTHCHECK` |
| Verifier | `sha256:e880f609a7c4d292441e22d1d0d5d7c876697dd4e1e657a668b2b6266969fecc` | Env as recorded (with `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`); no Healthcheck |

On approval, these become the two `ApprovedRunImage` entries in
`runner/run_plan.APPROVED_RUN_IMAGES`, as a reviewed code change. The r1 IDs `e5d1ad51…` and
`e57f61f8…` are in `REJECTED_RUN_IMAGE_IDS`, and `ApprovedRunImage` refuses them (tested).

**Runtime dependency inventory**, verified statically on the final filesystems:
- target: uvicorn 0.54.0, click 8.5.0, h11 0.16.0;
- verifier: pytest 9.0.3, pluggy 1.6.0, packaging 26.3, iniconfig 2.3.0, pygments 2.21.0, and
  `patchproof_verifier` (10 modules, hashes recorded);
- the base pip 26.2.1 is present in both and is unused at runtime.

### 6.2 Code changes required before any step (Docker-free; for review with this proposal)

1. **`docker_cli.ALLOWED_OP_TYPES`** gains `RunCreate` and `StartAttached`.
   - `assert_no_forbidden_tokens` dispatches `RunCreate` to `run_policy.assert_run_create_shape`:
     exactly one read-only bind, no forbidden token. `--mount` stays forbidden for every other
     operation, including the PP-003 probe `Create`.
   - `StartAttached` is checked against its exact shape: `container start --attach -- <64-hex ID>`.
   - Tests: the probe policy is unchanged; the wrapper refuses a tampered `RunCreate` argv.
2. **A collection-only verifier specification**, added to `run_policy`: verifier image, the
   pack read-only at `/pack`, **`--network=none`** (no target exists during collection), the
   verifier resource ceilings, the fixed command
   `python3 -I -B -m patchproof_verifier.launch collect --pack /pack -- /pack/tests/test_documents.py`,
   a 30 s deadline, and a 256 KiB output cap. It also gets an inspect gate and fake-Docker tests.
3. **A self-test pack**: the synthetic pack used by `tests/unit/test_run_plugin.py`, content-
   addressed and materialized like a real pack. It is used only for the image compatibility
   step (C1).

### 6.3 Steps, limits and stop conditions

| Step | Purpose | Containers | Network | Mounts (all read-only) | Limits |
|---|---|---|---|---|---|
| **C1a** | pytest 9.0.3 / plugin / launcher compatibility: **collect** the self-test pack | 1 created, started and removed | none | self-test pack → `/pack` | verifier ceilings (1 CPU, 512 MiB, 128 PIDs, `/scratch` 112 MiB, `/tmp` 16 MiB); 30 s; 256 KiB |
| **C1b** | the same, in **run mode** on the self-test pack (tests that need no target) | 1 | none | self-test pack → `/pack` | verifier ceilings; 120 s; result cap 10 MiB |
| **C2** | **first real collection** of the PaperTrail pack | 1 | none | PaperTrail pack snapshot `529d3cd3…` → `/pack` | verifier ceilings; 30 s; 256 KiB |
| — | the first live comparison (r1 vs r3: 1 pair, 4 containers) | **not proposed here**; a separate later approval with its own run plan | | | |

**Maximum in total:** 3 container creations, 3 starts and 3 removals, all owned by one
installation ID and labeled with their run IDs. No target container and no PaperTrail code
runs in C1 or C2.

**Expected results:**
- **C1a:** exactly one compact `collected` line on standard output, equal to the self-test
  manifest.
- **C1b:**
  - the host collector classifies the stream `COMPLETE`;
  - the 11 outcome classes equal those derived under pytest 8.4.2 in the unit test
    (`test_host_collector_accepts_the_real_stream_and_derives_each_outcome`);
  - the event channel is clean;
  - exit code 1.

  These are the pytest 9.0.3 compatibility checks.
- **C2:** the output parsed by `parse_collected`, then `review_collection` against the
  manifest's 8 tests. The result is an **unapproved** collection record for owner review.

**Isolation and policy, for every container:**
- `--network=none`;
- the PP-003 security settings (non-root 10001, read-only rootfs, `--cap-drop ALL`,
  `no-new-privileges`, private IPC and cgroup namespaces, bounded tmpfs, `local` logs
  2 × 5 MiB, `--pull=never`);
- exactly one read-only input;
- no host ports;
- the inspect-before-start gate, which must pass, or the container is removed unstarted;
- pack-snapshot re-verification before creation and after removal.

**Event-channel expectations:** standard output carries only launcher and plugin output: in
C1b, the event stream; in C1a and C2, one collected line. Standard error is kept separately
as untrusted diagnostics. Nothing else on standard output is accepted.

**Cleanup:** PP-003 `remove_owned` by exact registered ID, after re-checking identity and the
installation and run labels, and a stop with a 5 s grace if the container is still running.
- No prune and no filters.
- A refused or failed cleanup stops all further steps and is reported.
- The 10 pre-existing images, 7 containers, 5 networks and 10 volumes, and the four PP-008
  images, must be unchanged afterwards (inventory before and after).

**Evidence destination:**
- raw standard output and error, inspect records, the collector result and the inventory
  diffs go to `~/Library/Application Support/PatchProof/evidence/pp-008-gate-c/` (0700). They
  are kept until the owner decides; they are private, not public;
- a sanitized summary goes to `docs/evidence/pp-008-gate-c.md`.

**Stop conditions** (stop, clean up only owned containers, report):
- any image-identity mismatch;
- any inspect-gate mismatch;
- pack-snapshot integrity failure;
- a create, start or attach failure;
- a deadline expiry or output over the cap;
- any non-event bytes on standard output;
- an unexpected exit code;
- a collection that differs from the manifest;
- a cleanup refusal or failure;
- any unrelated Docker resource changing.

Never retry automatically.

## 7. Proposed first live comparison (NOT authorized; nothing below has been performed)

**Scope:** PaperTrail r1 as the baseline and r3 as the candidate, **one pair**, using the
approved pack only after the owner's typed approval. Maximum **4 containers**: baseline
target and verifier, then candidate target and verifier, sequentially by side.

**Prerequisites:**
1. The owner's PaperTrail pack approval, binding the pack `529d3cd3…`, the C2 collection, the
   verifier `e880f609…`, plugin 0.1.0, and the execution profile and its hash.
2. Review of the content-addressed source snapshots of r1 and r3. No Git metadata, no host
   repository, read-only at `/app/source`.
3. **Network design (already implemented and gated; no new wrapper operation):**
   - the target runs with `--network=none`;
   - the verifier joins only the target's namespace, through `--network container:<target ID>`,
     which the run gate verifies;
   - so there is no bridge, no egress and no published port.
4. A run plan that passes `check_preconditions` with the approved images.

**Per side:**
1. target create → inspect gate → start;
2. health check within 30 s;
3. verifier create (gate) → attached start in run mode, with deadline and cap;
4. host collector;
5. stop and exact-ID cleanup of both containers;
6. pack and source re-verification.

**Then:** pure verdict computation from the two observation sets.

**Stop on:** any identity, gate, health, stream or cleanup failure. No retry.

**Evidence:** private raw records, plus a sanitized repository summary.

**What it would establish:** at most one pair's verdict. Repetition and flakiness evaluation
need further pairs and further approval.

