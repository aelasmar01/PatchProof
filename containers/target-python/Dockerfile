# PatchProof target runtime image (PP-008). Revision r2 (gate B corrective rebuild, owner-approved 2026-10-13). NOT BUILT until that rebuild; never started by gate B.
#
# Runs one approved ASGI application from a read-only source snapshot mounted at /app/source.
# No application source is built into the image. Dependencies are installed from local,
# hash-verified wheels only, with no network during the build.
#
# Build (owner-approved corrective rebuild r2):
#   docker build --network=none --platform linux/amd64 --pull=false --provenance=false --sbom=false \
#     --build-context wheels=<prep-dir>/target-wheels -t patchproof-target:pp008-gateb-r2 containers/target-python
# The resulting local image ID is recorded and reviewed; the tag is never an identity.
FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f

RUN --mount=type=bind,from=wheels,target=/wheels \
    --mount=type=bind,source=requirements.lock,target=/requirements.lock \
    ["/usr/local/bin/python3", "-B", "-m", "pip", "install", "--no-index", "--find-links", "/wheels", "--require-hashes", "--only-binary", ":all:", "--no-compile", "--no-cache-dir", "--disable-pip-version-check", "-r", "/requirements.lock"]

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 LC_ALL=C.UTF-8 HOME=/nonexistent

# Reviewed readiness check; must equal patchproof.runner.run_policy.TARGET_HEALTHCHECK exactly.
HEALTHCHECK --interval=1s --timeout=2s --start-period=30s --start-interval=1s --retries=3 \
    CMD ["/usr/local/bin/python3", "-I", "-S", "-B", "-c", "import http.client,sys\nc=http.client.HTTPConnection('127.0.0.1',8080,timeout=1)\ntry:\n c.request('GET','/health');sys.exit(0 if c.getresponse().status==200 else 1)\nexcept Exception:\n sys.exit(1)\n"]

USER 10001:10001
