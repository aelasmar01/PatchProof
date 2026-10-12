"""PaperTrail HTTP interface: a minimal ASGI application with no third-party dependencies.

Routes (GET only):
    /health                    readiness; no authentication
    /me                        the authenticated caller
    /documents/{document_id}   one document, subject to papertrail.authz

Authentication is a synthetic bearer token from the fixture. Requests without a valid
token receive 401 before any document is looked up. A document that does not exist and a
document the caller may not read both receive the same 404 response.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

from papertrail import authz
from papertrail.fixtures import FIXTURE, authenticate

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]

DOCUMENT_PREFIX = "/documents/"


def route(method: str, path: str, authorization: bytes | None) -> tuple[int, dict[str, str]]:
    if method != "GET":
        return 405, {"error": "method_not_allowed"}
    if path == "/health":
        return 200, {"status": "ok"}
    user = authenticate(FIXTURE, authorization)
    if path == "/me":
        if user is None:
            return 401, {"error": "authentication_required"}
        return 200, {"user_id": user.user_id, "display_name": user.display_name, "role": user.role}
    if path.startswith(DOCUMENT_PREFIX):
        if user is None:
            return 401, {"error": "authentication_required"}
        document = FIXTURE.document(path.removeprefix(DOCUMENT_PREFIX))
        if document is None or not authz.can_read_document(user, document):
            return 404, {"error": "not_found"}
        return 200, {
            "document_id": document.document_id,
            "owner_id": document.owner_id,
            "title": document.title,
            "content": document.content,
        }
    return 404, {"error": "not_found"}


def _authorization(scope: Scope) -> bytes | None:
    values = [value for name, value in scope["headers"] if name.lower() == b"authorization"]
    return values[0] if len(values) == 1 else None


async def _respond(send: Send, status: int, payload: dict[str, str]) -> None:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"cache-control", b"no-store"),
            (b"x-content-type-options", b"nosniff"),
        ],
    })
    await send({"type": "http.response.body", "body": body})


async def _lifespan(receive: Receive, send: Send) -> None:
    while True:
        message = await receive()
        if message["type"] == "lifespan.startup":
            await send({"type": "lifespan.startup.complete"})
        elif message["type"] == "lifespan.shutdown":
            await send({"type": "lifespan.shutdown.complete"})
            return


async def app(scope: Scope, receive: Receive, send: Send) -> None:
    if scope["type"] == "lifespan":
        await _lifespan(receive, send)
        return
    if scope["type"] != "http":
        return
    status, payload = route(scope["method"], scope["path"], _authorization(scope))
    await _respond(send, status, payload)
