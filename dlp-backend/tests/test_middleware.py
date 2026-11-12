import unittest

from app.middleware import UploadRequestBodyLimitMiddleware


def run_inline(coroutine):
    """Drive these no-I/O ASGI fixtures without creating a Windows event loop."""
    iterator = coroutine.__await__()
    while True:
        try:
            suspended_on = iterator.send(None)
        except StopIteration as completed:
            return completed.value
        if suspended_on is not None:
            raise AssertionError("ASGI test fixture unexpectedly performed asynchronous I/O")


def _scope(headers=()):
    return {
        "type": "http",
        "method": "POST",
        "path": "/scan-jobs",
        "headers": list(headers),
    }


class UploadRequestBodyLimitTests(unittest.TestCase):
    def test_rejects_declared_oversize_before_calling_multipart_app(self):
        called = False

        async def app(scope, receive, send):
            nonlocal called
            called = True

        messages = []

        async def receive():
            return {"type": "http.request", "body": b"12345", "more_body": False}

        async def send(message):
            messages.append(message)

        middleware = UploadRequestBodyLimitMiddleware(app, max_bytes=4)
        run_inline(middleware(_scope([(b"content-length", b"5")]), receive, send))
        self.assertFalse(called)
        self.assertEqual(messages[0]["status"], 413)
        self.assertIn((b"connection", b"close"), messages[0]["headers"])

    def test_rejects_ambiguous_or_malformed_content_length(self):
        responses = []

        async def app(scope, receive, send):
            raise AssertionError("Invalid length must be rejected before the app")

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            responses.append(message)

        middleware = UploadRequestBodyLimitMiddleware(app, max_bytes=4)
        for headers in (
            [(b"content-length", b"4x")],
            [(b"content-length", b"4"), (b"content-length", b"5")],
        ):
            responses.clear()
            run_inline(middleware(_scope(headers), receive, send))
            self.assertEqual(responses[0]["status"], 400)

    def test_rejects_streamed_oversize_without_content_length(self):
        called = False
        sent = []
        chunks = iter([
            {"type": "http.request", "body": b"123", "more_body": True},
            {"type": "http.request", "body": b"45", "more_body": True},
        ])

        async def receive():
            return next(chunks)

        async def app(scope, limited_receive, send):
            nonlocal called
            called = True
            while True:
                message = await limited_receive()
                if not message.get("more_body"):
                    break

        async def send(message):
            sent.append(message)

        middleware = UploadRequestBodyLimitMiddleware(app, max_bytes=4)
        run_inline(middleware(_scope(), receive, send))
        self.assertTrue(called)
        self.assertEqual(sent[0]["status"], 413)

    def test_does_not_limit_unrelated_routes(self):
        sent = []

        async def receive():
            return {"type": "http.request", "body": b"12345", "more_body": False}

        async def app(scope, _receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok", "more_body": False})

        async def send(message):
            sent.append(message)

        scope = _scope([(b"content-length", b"5")])
        scope["path"] = "/health"
        middleware = UploadRequestBodyLimitMiddleware(app, max_bytes=4)
        run_inline(middleware(scope, receive, send))
        self.assertEqual(sent[0]["status"], 200)


if __name__ == "__main__":
    unittest.main()
