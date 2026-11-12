"""HTTP exposure and authentication checks for the metadata-only vault routes."""

import base64

from sqlalchemy import select

from dlp_platform.tables import AUDIT_EVENTS, VAULT_SECRETS
from platform_tests.auth.helpers import auth_headers

CANARY = "P09-http-secret-canary"


def prepare_vault(auth_client, monkeypatch) -> None:
    VAULT_SECRETS.create(auth_client.app.state.test_session_factory.kw["bind"], checkfirst=True)
    AUDIT_EVENTS.create(auth_client.app.state.test_session_factory.kw["bind"], checkfirst=True)
    monkeypatch.setenv("DLP_VAULT_ENABLED", "true")
    monkeypatch.setenv("DLP_VAULT_ACTIVE_KEY_VERSION", "1")
    monkeypatch.setenv("DLP_VAULT_MASTER_KEY", base64.b64encode(b"v" * 32).decode())
    monkeypatch.setenv("DLP_VAULT_PREVIOUS_KEYS", "")


def test_vault_http_returns_metadata_only_and_sanitizes_bad_requests(
    auth_client, monkeypatch
) -> None:
    prepare_vault(auth_client, monkeypatch)
    response = auth_client.post(
        "/vault/secrets",
        headers=auth_headers(),
        json={"name": "example_secret", "secret_type": "generic_secret", "value": CANARY},
    )
    assert response.status_code == 201
    assert response.headers["cache-control"] == "no-store"
    assert CANARY not in response.text
    assert "value" not in response.json()
    listed = auth_client.get("/vault/secrets", headers=auth_headers())
    assert listed.status_code == 200
    assert CANARY not in listed.text
    assert "ciphertext" not in listed.text
    assert "nonce" not in listed.text

    invalid = auth_client.post(
        "/vault/secrets",
        headers=auth_headers(),
        json={
            "name": "other_secret",
            "secret_type": "generic_secret",
            "value": CANARY,
            "org_id": "22222222-2222-4222-8222-222222222222",
        },
    )
    assert invalid.status_code == 422
    assert CANARY not in invalid.text

    factory = auth_client.app.state.test_session_factory
    with factory() as session:
        stored = session.execute(select(VAULT_SECRETS)).mappings().one()
    assert CANARY.encode() not in stored["ciphertext"]


def test_vault_api_key_can_write_and_read_metadata_without_plaintext(
    auth_client, monkeypatch
) -> None:
    prepare_vault(auth_client, monkeypatch)
    key = auth_client.post(
        "/api-keys",
        headers=auth_headers(),
        json={
            "name": "vault automation",
            "scopes": ["vault:write", "vault:metadata:read", "audit:read"],
        },
    )
    assert key.status_code == 201
    headers = auth_headers(key.json()["key"])
    created = auth_client.post(
        "/vault/secrets",
        headers=headers,
        json={"name": "api_key_secret", "secret_type": "api_credential", "value": CANARY},
    )
    assert created.status_code == 201
    assert CANARY not in created.text
    created_event = auth_client.get("/audit/events?action=secret.created", headers=headers).json()[
        0
    ]
    assert created_event["resource_id"] == created.json()["secret_id"]
    assert created_event["actor_id"] == key.json()["id"]
    assert CANARY not in str(created_event)
    metadata = auth_client.get("/vault/secrets", headers=headers)
    assert metadata.status_code == 200
    assert CANARY not in metadata.text
