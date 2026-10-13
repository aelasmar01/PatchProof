# PP-008 gate B: image preparation evidence (2026-10-12/13)

**Result: GATE B COMPLETE (r2, 2026-10-13).** The owner-approved corrective rebuild (r2)
produced both images:
- target `sha256:98548ec48d8d796fca5adaf4aab3e461bee38210bd1d568281f79190685eac2e`;
- verifier `sha256:e880f609a7c4d292441e22d1d0d5d7c876697dd4e1e657a668b2b6266969fecc`.

Every completion condition passed (see "Corrective rebuild r2" at the end).

**The r1 images** (`e5d1ad51…` target, `e57f61f8…` defective verifier) are kept unchanged as
evidence. They are **rejected** as execution identities (`run_plan.REJECTED_RUN_IMAGE_IDS`).

**Not performed:** no container was created or started from any image. No verifier
collection, PaperTrail execution or pack approval took place, and no runtime behavior or
isolation property was established by these builds.

## Owner decisions implemented

| Decision | Implemented |
|---|---|
| Base: the exact local PP-003 image | `FROM python:3.13-slim@sha256:70729b46…` resolved from the local store (build log: metadata 0.1 s, no download or auth lines; base image unchanged afterwards). No alias tag was needed or created |
| Target dependencies | uvicorn 0.54.0, click 8.5.0, h11 0.16.0: exact wheels, `--require-hashes`, `--no-index`, `--only-binary :all:` |
| Verifier pytest 9.0.3 (CVE-2025-71176 fix) | pytest 9.0.3, iniconfig 2.3.0, packaging 26.3, pluggy 1.6.0, pygments 2.21.0 |
| Standard-library HTTP client | no HTTPX or other client installed |
| Host dev pytest 8.4.2 | **unchanged**. The advisory is recorded as a separate remediation item (`environment.lock.md` §3.1) |

**Recipe change made before building:** both Dockerfiles began with
`# syntax=docker/dockerfile:1`. That directive makes BuildKit pull the `docker/dockerfile`
frontend image from Docker Hub, which was not approved. It was removed, and the engine's
built-in frontend was used.

## Base image: local ID versus registry digest

| Item | Value |
|---|---|
| Local image ID (containerd store) | `sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f` |
| What that ID is | the digest of the **OCI image index** (`Descriptor.mediaType = application/vnd.oci.image.index.v1+json`, size 10373). Under the containerd store the local ID is the index digest, so it equals the registry digest |
| RepoDigests | `python@sha256:70729b46…`, identical |
| linux/amd64 platform manifest | `sha256:8fb4cfa1a2616d7b8e0c2175cc6ad68f5729c34ea8488c0b360d2934b7be9024` (a different object, from registry metadata) |
| Platform / Python | linux/amd64; `PYTHON_VERSION=3.13.16`, `PYTHON_SHA256=f4b1bfb3…` |
| Config | no User, Entrypoint, WorkingDir, Volumes, ExposedPorts, Healthcheck, Labels or OnBuild; `Cmd ["python3"]`; 4 layers |
| PP-003 evidence | the same ID, repo digest and platform |

## Wheels (downloaded 2026-10-13 00:00 UTC; HTTPS, `--proto =https --tlsv1.2`, normal certificate verification)

Each hash was checked against the reviewed metadata **and** the lock file before download, and
the downloaded bytes were verified afterwards. Nothing was installed on the host. The location
is `~/Library/Caches/PatchProof/prep-pp008/` (mode 0700).

| Wheel | Bytes | SHA-256 |
|---|---|---|
| uvicorn-0.54.0-py3-none-any.whl | 87427 | `505bdb0f318731d45f1f712071fc781a8981f6847a31c902c9f5e652d4f67faf` |
| click-8.5.0-py3-none-any.whl | 125251 | `255bc9599cf7748b4b1a446ccc735421bd08a2ae529a8b88597d3de5664ee360` |
| h11-0.16.0-py3-none-any.whl | 37515 | `63cf8bbe7522de3bf65932fda1d9c2772064ffb3dae62d55932da54b31cb6c86` |
| pytest-9.0.3-py3-none-any.whl | 375249 | `2c5efc453d45394fdd706ade797c0a81091eccd1d6e4bccfcd476e2b8e0ab5d9` |
| iniconfig-2.3.0-py3-none-any.whl | 7484 | `f631c04d2c48c52b84d0d0549c99ff3859c98df65b3101406327ecc7d53fbf12` |
| packaging-26.3-py3-none-any.whl | 129956 | `d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c` |
| pluggy-1.6.0-py3-none-any.whl | 20538 | `e920276dd6813095e9377c0bc5566d94c932c33b27a3e3945d8389c374dd4746` |
| pygments-2.21.0-py3-none-any.whl | 1250147 | `2363c69b61c4a97c838da3b130dcd6468f4848992b21a82f2a63ec34377137d9` |

## Builds (r1 recipes, `docker build --network=none --platform linux/amd64 --pull=false --provenance=false --sbom=false`)

**Build contexts:**
- **Target:** `Dockerfile` and `requirements.lock` only, plus the named context `wheels`.
- **Verifier:** the same, plus a staged named context with exactly the 10 reviewed
  `patchproof_verifier/*.py` files and `pytest.ini`, byte-identical to the repository and with
  no `__pycache__`.

**Recipe hashes (r1, as built):**
- target `Dockerfile` `70c88704…`, `requirements.lock` `bc161893…`;
- verifier `Dockerfile` `17075cbe…`, `requirements.lock` `1872c8c8…`.

| | Target | Verifier |
|---|---|---|
| Tag (alias, not identity) | `patchproof-target:pp008-gateb` | `patchproof-verifier:pp008-gateb` |
| **Local image ID** (single OCI manifest; no attestations) | `sha256:e5d1ad51ecfcf50c3f0835e3d801c76d591396474f13179070a32a1233b1b102` | `sha256:e57f61f8f8a8e8757935159dfaaeb1e891f50b0e44dcfe1eece7528377eef972` |
| Config digest | `sha256:68970a0bf29d89326b22382696bf6ff8363b09b277acd28dba32954124e39af2` | `sha256:61c6852176b3effc13f7505570eb6d9a1242fcd597e24c9a532e19252814fabf` |
| Built (UTC) | 2026-10-13T00:00:44Z | 2026-10-13T00:01:00Z |
| Size / platform | 190,935,583 B, linux/amd64 | 198,956,310 B, linux/amd64 |
| Base layers | intact (first 4 layers equal the base) | intact |
| Installed (pip log and dist-info) | click 8.5.0, h11 0.16.0, uvicorn 0.54.0 | iniconfig 2.3.0, packaging 26.3, pluggy 1.6.0, Pygments 2.21.0, pytest 9.0.3 |
| User | `10001:10001` | `10001:10001` |
| Env (added) | `PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 LC_ALL=C.UTF-8 HOME=/nonexistent` | the same, plus `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` |
| Healthcheck | equals `run_policy.TARGET_HEALTHCHECK` exactly | none |
| Volumes / ports / labels / OnBuild | none | none |
| Application or target source | none (no PaperTrail files) | none (no target source, no pack) |

**Build warnings:** pip's standard warning about running as root, in the build stage only. The
images run as UID 10001.

## Layer audit (read-only `docker image save` exports, inspected on the host)

**No suspicious content:**
- no wheels or `requirements.lock` in any layer (they were bind-mounted only);
- no pip cache, no `.git`, no credentials, no `/root` or `/tmp` content;
- no PaperTrail, pack or `examples` files;
- no whiteouts.

**G-B1 (defect, verifier): directories created with mode `0644`.**
- **Where:** `/usr/local/lib/python3.13/site-packages/patchproof_verifier`, `/opt/patchproof` and
  `/opt/patchproof/verifier`.
- **Cause:** `COPY --chmod=0644` applied the file mode to the directories it created.
- **Effect:** without the execute bit, UID 10001 cannot traverse them. The plugin could not be
  imported and `pytest.ini` could not be read, so the image is unusable.
- **Fix (r2):** pre-create the three directories root-owned `0755` with `install -d` before the
  COPY steps.

**G-B2 (hygiene, both images): stray bytecode.**
- **What:** running pip wrote `__pycache__/*.pyc` for the standard-library modules and the
  site-packages it imported (about 160 stdlib and 321 site-packages files per image).
- **Not a leak:** these are compiled from base-image sources, not credentials or foreign
  content, but they are unintended.
- **Fix (r2):** run pip as `python3 -B`.

**Unverified until a rebuild:** that `COPY --chmod` leaves a **pre-existing** directory's mode
unchanged. The r2 post-build audit must confirm modes `0755` (directories) and `0644` (files).

## Docker inventory

| Resource | Before | After | Difference |
|---|---|---|---|
| Images | 10 | 12 | +2, exactly `patchproof-target:pp008-gateb` (`e5d1ad51…`) and `patchproof-verifier:pp008-gateb` (`e57f61f8…`). Nothing removed or retagged; `python:3.13-slim` unchanged |
| Containers | 7 (all stopped) | 7 | none; no container was created |
| Networks | 5 | 5 | none |
| Volumes | 10 | 10 | none |
| Build-cache entries | 77 | 98 | +21 from the two builds |

No prune or cleanup was run. The two r1 images are retained as evidence until the owner
approves their removal by exact ID.

## Corrective rebuild r2 (owner-approved 2026-10-13; exactly two builds)

**Recipe changes** (pinned by `tests/unit/test_run_images.py`):
- **Both recipes:** pip runs as `python3 -B -m pip ... --no-compile`.
- **Verifier, first layer of protection:** the three directories are pre-created `0755` with
  `install -d`.
- **Verifier, after the final COPY:** on the final paths, `chown -R 0:0`, then
  `find ... -type d -exec chmod 0755`, then `find ... -type f -exec chmod 0644`.
- **Both recipes:** the header and build comment now refer to r2.

| Recipe file (r2, as built) | SHA-256 |
|---|---|
| `containers/target-python/Dockerfile` | `51b691581f7e73be1457db59856ce3669c246c6d378c782e0ecea7eaf3a6e649` |
| `containers/target-python/requirements.lock` | `bc1618931992bc7acdfc24e919990bd25142f86fd26d0644049667a68f5e3b9d` (unchanged) |
| `containers/verifier/Dockerfile` | `f508ca3cd1e047623bb7efd359f87fcb2f5f5755f7276d920e23a05a17b77ea5` |
| `containers/verifier/requirements.lock` | `1872c8c8d360cefbca5b149ff57fdbd6e0727d1c0c9b1c7a8e131977500d5f07` (unchanged) |

**Prebuild checks (all passed):**
- repository root and `HEAD` `d85b6db`;
- the r1 images and the base image present and unchanged (base inspect byte-identical to the
  gate-B record);
- the eight wheels re-hashed OK;
- the r2 tags free;
- the staged verifier context is 11 files, identical to the repository and to the r1 staging;
- both contexts hold only recipes and locks, plus the staged verifier files; no target source,
  pack, private data or ADR-010;
- inventory: 12 images, 7 containers, 5 networks, 10 volumes, 98 build-cache entries;
- 561 GiB free;
- recipe tests 9/9.

**Builds** used the same flags as r1 (`--network=none --platform linux/amd64 --pull=false
--provenance=false --sbom=false`) and the same verified wheels. The base resolved from the
local store; there were no download or authentication lines.

| | Target r2 | Verifier r2 |
|---|---|---|
| Tag (alias) | `patchproof-target:pp008-gateb-r2` | `patchproof-verifier:pp008-gateb-r2` |
| **Image ID** (single OCI manifest) | `sha256:98548ec48d8d796fca5adaf4aab3e461bee38210bd1d568281f79190685eac2e` | `sha256:e880f609a7c4d292441e22d1d0d5d7c876697dd4e1e657a668b2b6266969fecc` |
| Config digest | `sha256:f0c1b5c4d654c81ea099e0e61f45af88d8e5aff459a6f3c66f32cca5b22c951f` | `sha256:c31db2e3e70aded21748dc14f2feb7be4b3c3cde99d98b71661a9fa40cb67ea2` |
| Built (UTC) | 2026-10-13T00:15:27Z | 2026-10-13T00:15:37Z |
| Size / platform | 177,531,355 B, linux/amd64 | 185,607,247 B, linux/amd64 |
| Layers | 5 (4 base, intact, + 1) | 11 (4 base, intact, + 7) |
| New distributions (final filesystem) | click 8.5.0, h11 0.16.0, uvicorn 0.54.0 | iniconfig 2.3.0, packaging 26.3, pluggy 1.6.0, pygments 2.21.0, pytest 9.0.3 |
| site-packages additions | `click`, `h11`, `uvicorn` and their dist-info | `_pytest`, `pytest`, `py.py` (pytest's shim), `pluggy`, `packaging`, `iniconfig`, `pygments`, their dist-info, and `patchproof_verifier` |
| Other additions | `/usr/local/bin/uvicorn` | `/usr/local/bin/{pytest,py.test,pygmentize}`, `/opt/patchproof/verifier/pytest.ini` |
| User / Env / Healthcheck | `10001:10001`; as reviewed; equals `TARGET_HEALTHCHECK` | `10001:10001`; as reviewed, including `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`; none |
| Volumes / ports / labels / OnBuild / Entrypoint | none | none |

**Static audit of the final merged filesystem.** Read-only `docker image save` exports were
analysed by applying every layer in order, including whiteouts. No container was used.
- **Verifier access for UID 10001:**
  - all 9 directory components of `/usr/local/lib/python3.13/site-packages/patchproof_verifier`
    and `/opt/patchproof/verifier` are `0755`, root-owned, and not writable by others;
  - all 10 modules and `pytest.ini` are `0644`, root-owned, and byte-identical to the staged
    sources;
  - there are no unexpected entries. **G-B1 is eliminated.**
- **Bytecode:** the approved base image contains **0** `.pyc` files; the final target and
  verifier images contain **0**, so the new layers introduced none. **G-B2 is eliminated.**
- **Unwanted content:** none. No world-writable added entries and no suspicious names
  (PaperTrail, pack, `.git`, credentials, keys, wheels, lock files, caches, `/root`, `/tmp`).

**Inventory (before r2 → after r2):**
- images 12 → 14: only `patchproof-target:pp008-gateb-r2` and
  `patchproof-verifier:pp008-gateb-r2` were added;
- the r1 images are present with their tags, and their full `inspect` output is
  byte-identical to the gate-B record; only Docker's relative "created … ago" text differs;
- the 10 pre-gate-B images are unchanged;
- containers 7 → 7, none created; networks 5 → 5; volumes 10 → 10;
- build cache 98 → 106 entries;
- no prune, cleanup or forced deletion.

**What this does not establish:** runtime functionality, pytest 9.0.3 compatibility in the
image, or isolation enforcement. Those require gate C.
