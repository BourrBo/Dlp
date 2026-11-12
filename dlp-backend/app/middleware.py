"""Request-size limits that run before FastAPI parses multipart uploads."""

from __future__ import annotations

import json


class _RequestBodyTooLarge(Exception):
    pass


class UploadRequestBodyLimitMiddleware:
    """Cap multipart bodies before Starlette can spool attacker-sized files."""

    def __init__(
        self,
        app,
        *,
        max_bytes: int,
        paths: tuple[str, ...] = ("/scans", "/scan-jobs"),
    ):
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        self.app = app
        self.max_bytes = max_bytes
        self.paths = frozenset(paths)

    async def _respond(self, send, status: int, detail: str) -> None:
        body = json.dumps({"detail": detail}, separators=(",", ":")).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"connection", b"close"),
            ],
        })
        await send({"type": "http.response.body", "body": body, "more_body": False})

    async def __call__(self, scope, receive, send) -> None:
        if (
            scope["type"] != "http"
            or scope.get("method") != "POST"
            or scope.get("path") not in self.paths
        ):
            await self.app(scope, receive, send)
            return

        length_headers = [
            value for key, value in scope.get("headers", [])
            if key.lower() == b"content-length"
        ]
        if len(length_headers) > 1:
            await self._respond(send, 400, "Invalid Content-Length")
            return
        declared_length = length_headers[0] if length_headers else None
        if declared_length is not None:
            if not declared_length.isdigit():
                await self._respond(send, 400, "Invalid Content-Length")
                return
            content_length = int(declared_length)
            if content_length > self.max_bytes:
                await self._respond(send, 413, "Upload request body is too large")
                return

        received_bytes = 0
        response_started = False

        async def bounded_receive():
            nonlocal received_bytes
            message = await receive()
            if message["type"] == "http.request":
                received_bytes += len(message.get("body", b""))
                if received_bytes > self.max_bytes:
                    raise _RequestBodyTooLarge
            return message

        async def tracked_send(message):
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, bounded_receive, tracked_send)
        except _RequestBodyTooLarge:
            if response_started:
                # A response should not begin before the request body is parsed.
                # If an application violates that assumption, fail the request
                # rather than attempting to send a second response start.
                raise
            await self._respond(send, 413, "Upload request body is too large")
