"""Security middleware: request body size limit and response security headers."""

from __future__ import annotations

import json
import uuid


def error_payload(code: str, message: str, request_id: str, details: list | None = None) -> dict:
    body = {"code": code, "message": message}
    if details:
        body["details"] = details
    return {"error": body, "request_id": request_id}


class BodySizeLimitMiddleware:
    """
    Rejects request bodies over `max_bytes` with HTTP 413 before they are parsed.

    FastAPI sets no limit of its own. The Content-Length header is checked
    first; bodies sent without it (chunked) are counted as they arrive, so a
    client cannot get round the limit by leaving the header out.
    """

    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        headers = dict(scope.get("headers") or [])
        declared = headers.get(b"content-length")
        if declared is not None:
            try:
                too_big = int(declared) > self.max_bytes
            except ValueError:
                too_big = True
            if too_big:
                return await self._reject(scope, send)

        received = 0
        rejected = False

        async def limited_receive():
            nonlocal received, rejected
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    rejected = True
                    raise _TooLarge()
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _TooLarge:
            if rejected:
                await self._reject(scope, send)

    async def _reject(self, scope, send):
        body = json.dumps(error_payload(
            "payload_too_large",
            f"The request is larger than the {self.max_bytes // 1024} KB limit.",
            (scope.get("state") or {}).get("request_id") or uuid.uuid4().hex[:12],
        )).encode()
        await send({"type": "http.response.start", "status": 413, "headers": [
            (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
            (b"x-content-type-options", b"nosniff"),
        ]})
        await send({"type": "http.response.body", "body": body})


class _TooLarge(Exception):
    pass


# The interactive docs load Swagger UI from a CDN, so they need a looser
# policy than the JSON API, which needs no scripts, styles or frames at all.
API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
DOCS_CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; "
            "frame-ancestors 'none'; base-uri 'none'")


class SecurityHeadersMiddleware:
    """Adds standard security headers that FastAPI does not set by default."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        is_docs = path in ("/docs", "/redoc", "/openapi.json") or path.startswith("/docs/")

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                extra = [
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
                    (b"cross-origin-opener-policy", b"same-origin"),
                    (b"cross-origin-resource-policy", b"same-site"),
                    (b"content-security-policy", (DOCS_CSP if is_docs else API_CSP).encode()),
                ]
                if not is_docs:
                    extra.append((b"cache-control", b"no-store"))
                message.setdefault("headers", [])
                message["headers"] = list(message["headers"]) + extra
            await send(message)

        await self.app(scope, receive, send_with_headers)
