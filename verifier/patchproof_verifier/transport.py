"""The fixed verifier-to-target HTTP transport (PROJECT_SPEC.md 10.1, 10.3; PP-008).

**What is fixed:**
- **Target:** the address is always 127.0.0.1:8080 inside the target's network namespace.
  A pack supplies only a path, which `http.check_path` validates.
- **Proxies:** none. The standard-library client never reads proxy environment variables,
  and no proxy is configured.
- **Redirects:** never followed. A 3xx is returned as an ordinary response, which the
  witnesses treat as inconclusive.
- **Timeouts:** separate connect and read limits.
- **Body size:** a hard response cap. A body that exceeds it, or a `Content-Length` that
  promises more than the cap, raises `TargetResponseError` instead of being truncated
  silently.
- **Errors:** connection failures and malformed responses raise `TargetRequestError` or
  `TargetResponseError`. They end the test as an error (`failure_class: exception`), never
  as a vulnerability.

The class is installed only in the verifier image. Packs cannot import it: the static pack
policy allows only the helper modules, and the plugin constructs it.
"""

from __future__ import annotations

import http.client
from typing import Final

from .http import MAX_BODY_BYTES, Response, TargetResponseError, check_path

TARGET_HOST: Final = "127.0.0.1"
TARGET_PORT: Final = 8080
CHUNK: Final = 65536


class TargetRequestError(Exception):
    """The request could not be completed (connect, send or read failure, or timeout)."""


class TargetTransport:
    """GET-only client for the one approved target endpoint."""

    def __init__(self, *, connect_timeout: float, read_timeout: float, max_body_bytes: int = MAX_BODY_BYTES,
                 port: int = TARGET_PORT) -> None:
        if not (0 < connect_timeout <= 30 and 0 < read_timeout <= 30):
            raise ValueError("timeouts must be within (0, 30] seconds")
        if not 1 <= max_body_bytes <= MAX_BODY_BYTES:
            raise ValueError("response cap out of range")
        # The port parameter exists only so unit tests can reach a synthetic local server; the
        # plugin always uses TARGET_PORT. The host is never a parameter.
        if not 1 <= port <= 65535:
            raise ValueError("invalid port")
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout
        self._cap = max_body_bytes
        self._port = port

    def get(self, path: str, *, bearer: str | None = None) -> Response:
        check_path(path)
        headers = {"Host": f"{TARGET_HOST}:{TARGET_PORT}", "Accept": "application/json", "Connection": "close"}
        if bearer is not None:
            if not bearer.isascii() or not bearer.isprintable() or len(bearer) > 256:
                raise ValueError("bearer token must be short printable ASCII")
            headers["Authorization"] = f"Bearer {bearer}"
        connection = http.client.HTTPConnection(TARGET_HOST, self._port, timeout=self._connect_timeout)
        try:
            try:
                connection.connect()
                if connection.sock is not None:
                    connection.sock.settimeout(self._read_timeout)
                connection.request("GET", path, headers=headers)
                raw = connection.getresponse()
            except (OSError, http.client.HTTPException) as exc:  # TimeoutError is an OSError
                raise TargetRequestError(f"request failed: {type(exc).__name__}") from None
            declared = raw.getheader("Content-Length")
            if declared is not None and (not declared.isdigit() or int(declared) > self._cap):
                raise TargetResponseError("declared response length is invalid or exceeds the cap")
            body = bytearray()
            try:
                while True:
                    chunk = raw.read(min(CHUNK, self._cap + 1 - len(body)))
                    if not chunk:
                        break
                    body += chunk
                    if len(body) > self._cap:
                        raise TargetResponseError("response body exceeds the cap")
            except (OSError, http.client.HTTPException) as exc:  # TimeoutError is an OSError
                raise TargetRequestError(f"reading the response failed: {type(exc).__name__}") from None
            return Response(raw.status, bytes(body))
        finally:
            connection.close()
