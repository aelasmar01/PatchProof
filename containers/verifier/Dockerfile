# PatchProof verifier image (PP-008). Revision r2 (gate B corrective rebuild, owner-approved 2026-10-13). NOT BUILT until that rebuild; never started by gate B.
#
# Runs only PatchProof's launcher, plugin and helpers, with pytest, against an approved pack
# mounted read-only at /pack. No target application source is ever placed in this image.
# Dependencies come from local, hash-verified wheels, with no network during the build.
#
# Build (owner-approved corrective rebuild r2):
#   docker build --network=none --platform linux/amd64 --pull=false --provenance=false --sbom=false \
#     --build-context wheels=<prep-dir>/verifier-wheels --build-context verifier=<prep-dir>/verifier-context \
#     -t patchproof-verifier:pp008-gateb-r2 containers/verifier
FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f

RUN --mount=type=bind,from=wheels,target=/wheels \
    --mount=type=bind,source=requirements.lock,target=/requirements.lock \
    ["/usr/local/bin/python3", "-B", "-m", "pip", "install", "--no-index", "--find-links", "/wheels", "--require-hashes", "--only-binary", ":all:", "--no-compile", "--no-cache-dir", "--disable-pip-version-check", "-r", "/requirements.lock"]

# PatchProof-owned code and configuration, root-owned and read-only to the run user.
# Gate B finding G-B1: COPY --chmod also applied 0644 to the directories it created, which made
# them untraversable for UID 10001. The directories are therefore created first, 0755.
RUN ["/usr/bin/install", "-d", "-o", "0", "-g", "0", "-m", "0755", "/usr/local/lib/python3.13/site-packages/patchproof_verifier", "/opt/patchproof", "/opt/patchproof/verifier"]
COPY --from=verifier --chown=0:0 --chmod=0644 patchproof_verifier/*.py /usr/local/lib/python3.13/site-packages/patchproof_verifier/
COPY --from=verifier --chown=0:0 --chmod=0644 pytest.ini /opt/patchproof/verifier/pytest.ini

# Enforced after the final COPY, on the final paths (G-B1): root-owned, directories 0755 and files 0644.
# Nothing becomes writable by UID 10001.
RUN ["/usr/bin/chown", "-R", "0:0", "/usr/local/lib/python3.13/site-packages/patchproof_verifier", "/opt/patchproof"]
RUN ["/usr/bin/find", "/usr/local/lib/python3.13/site-packages/patchproof_verifier", "/opt/patchproof", "-type", "d", "-exec", "/usr/bin/chmod", "0755", "{}", "+"]
RUN ["/usr/bin/find", "/usr/local/lib/python3.13/site-packages/patchproof_verifier", "/opt/patchproof", "-type", "f", "-exec", "/usr/bin/chmod", "0644", "{}", "+"]

ENV PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 LC_ALL=C.UTF-8 HOME=/nonexistent

USER 10001:10001
