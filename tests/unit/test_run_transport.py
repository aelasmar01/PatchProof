"""PP-008: the verifier's fixed HTTP transport, against a synthetic local server (never PaperTrail)."""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from patchproof_verifier.authz import assess_unauthorized_read
from patchproof_verifier.check import SecurityCheck, TerminalObservation
from patchproof_verifier.documents import load_documents
from patchproof_verifier.http import TargetResponseError
from patchproof_verifier.transport import TARGET_HOST, TARGET_PORT, TargetRequestError, TargetTransport


class Handler(BaseHTTPRequestHandler):
    seen: list[dict[str, str]] = []

    def log_message(self, *args: object) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        Handler.seen.append({"path": self.path, **{k.lower(): v for k, v in self.headers.items()}})
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://example.invalid/stolen")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/big-declared":
            self.send_response(200)
            self.send_header("Content-Length", "999999999")
            self.end_headers()
        elif self.path == "/big-streamed":
            self.send_response(200)
            self.end_headers()
            for _ in range(64):
                self.wfile.write(b"x" * 1024)
        elif self.path == "/slow":
            time.sleep(3)
            self.send_response(200)
            self.end_headers()
        else:
            body = b'{"status":"ok"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


@pytest.fixture(scope="module")
def server() -> Iterator[int]:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd.server_address[1]
    httpd.shutdown()


def transport(port: int, *, cap: int = 4096, read: float = 1.0) -> TargetTransport:
    return TargetTransport(connect_timeout=1.0, read_timeout=read, max_body_bytes=cap, port=port)


def test_fixed_target_identity() -> None:
    assert (TARGET_HOST, TARGET_PORT) == ("127.0.0.1", 8080)


def test_plain_get_with_bearer(server: int) -> None:
    response = transport(server).get("/health", bearer="pt-synthetic-alice-a9388a6e7158")
    assert (response.status, response.body) == (200, b'{"status":"ok"}')
    seen = Handler.seen[-1]
    assert seen["authorization"] == "Bearer pt-synthetic-alice-a9388a6e7158"
    assert seen["host"] == "127.0.0.1:8080"


def test_redirect_is_returned_not_followed(server: int) -> None:
    before = len(Handler.seen)
    response = transport(server).get("/redirect")
    assert response.status == 302
    assert len(Handler.seen) == before + 1


def test_proxy_environment_is_ignored(server: int, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(name, "http://127.0.0.1:9/")
    assert transport(server).get("/health").status == 200


def test_declared_oversized_body_is_refused(server: int) -> None:
    with pytest.raises(TargetResponseError, match="cap"):
        transport(server).get("/big-declared")


def test_streamed_oversized_body_is_refused(server: int) -> None:
    with pytest.raises(TargetResponseError, match="cap"):
        transport(server, cap=10_000).get("/big-streamed")


def test_read_timeout(server: int) -> None:
    started = time.monotonic()
    with pytest.raises(TargetRequestError):
        transport(server, read=0.5).get("/slow")
    assert time.monotonic() - started < 2.5


def test_refused_connection_is_a_request_error_not_a_result() -> None:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    with pytest.raises(TargetRequestError):
        transport(port).get("/health")


@pytest.mark.parametrize("path", ["http://example.invalid/", "//evil/x", "/a/../b", "/x?y=1"])
def test_paths_cannot_leave_the_target(server: int, path: str) -> None:
    with pytest.raises(ValueError):
        transport(server).get(path)


def test_bad_bearer_values(server: int) -> None:
    for bad in ("café", "a\r\nX-Injected: 1", "x" * 300):
        with pytest.raises(ValueError):
            transport(server).get("/health", bearer=bad)


def test_unexpected_http_behavior_is_never_a_vulnerability(server: int) -> None:
    from pathlib import Path

    docs = load_documents(Path(__file__).resolve().parents[2] / "examples/packs/papertrail-document-access/fixtures"
                          / "synthetic-documents-v1.json")
    recorded: list[TerminalObservation] = []
    check = SecurityCheck("AUTH-001", recorded.append)
    response = transport(server).get("/redirect")
    assess_unauthorized_read(check, caller=docs.user("u-bob"), document=docs.document("doc-alice-private"),
                             response=response)
    assert [o.outcome for o in recorded] == ["INCONCLUSIVE"]


def test_timeout_bounds() -> None:
    for c, r in ((0, 1), (1, 0), (31, 1), (1, 31)):
        with pytest.raises(ValueError):
            TargetTransport(connect_timeout=c, read_timeout=r)
