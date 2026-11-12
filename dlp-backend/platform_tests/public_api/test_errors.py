"""Public API error handler never discloses internal exception details."""

import asyncio
import json
from uuid import uuid4

from starlette.requests import Request

from dlp_platform.public_api.errors import public_internal_error
from dlp_platform.public_api.webhooks import InMemoryReplayStore, WebhookSigner
from dlp_platform.vault.service import SecretVault


class _SyntheticKeyProvider:
    active_key_version = 1

    def key_for_version(self, version: int) -> bytes:
        if version != 1:
            raise ValueError("unknown synthetic test key")
        return bytes(range(32))


def test_public_internal_error_is_redacted_and_correlated() -> None:
    request_id = str(uuid4())
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/v1/policies",
        "query_string": b"",
        "headers": [],
        "server": ("testserver", 80),
        "client": ("testclient", 50000),
        "scheme": "http",
        "state": {"correlation_id": request_id},
    }
    response = asyncio.run(
        public_internal_error(Request(scope), RuntimeError("postgres://secret.internal"))
    )
    body = json.loads(response.body)
    assert response.status_code == 500
    assert body["error"]["code"] == "internal_error"
    assert body["error"]["request_id"] == request_id
    assert response.headers["x-request-id"] == request_id
    assert "secret.internal" not in response.body.decode()
    assert "Traceback" not in response.body.decode()


def test_replay_store_is_bounded_and_releases_expired_claims(monkeypatch) -> None:
    monkeypatch.setenv("DLP_WEBHOOK_TOLERANCE_SECONDS", "120")
    signer = WebhookSigner.from_environment(SecretVault(_SyntheticKeyProvider()))
    assert signer._tolerance_seconds == 120
    store = InMemoryReplayStore(capacity=1)
    assert store.claim("first", 10, now=1)
    assert not store.claim("first", 10, now=1)
    assert not store.claim("second", 20, now=1)
    assert store.claim("second", 20, now=11)
