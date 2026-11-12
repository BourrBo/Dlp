"""API-key lifecycle, tenant separation, and scope enforcement tests."""

import hashlib
from uuid import UUID

import pytest
from sqlalchemy import select, text

from dlp_platform.tables import API_KEYS
from platform_tests.auth.conftest import ORG_B
from platform_tests.auth.helpers import auth_headers, signed_token

ADMIN_SCOPES = ["identity:read", "api_keys:read", "api_keys:write"]


def create_key(client, *, headers=None, name="automation", scopes=None, org_id=None):
    payload = {"name": name, "scopes": scopes or ADMIN_SCOPES}
    if org_id is not None:
        payload["org_id"] = str(org_id)
    return client.post("/api-keys", json=payload, headers=headers or auth_headers())


@pytest.mark.parametrize("subject", ["user-owner-a", "user-admin-a"])
def test_owner_and_admin_can_list_api_keys(auth_client, subject: str) -> None:
    headers = auth_headers(signed_token(subject=subject))
    assert auth_client.get("/api-keys", headers=headers).status_code == 200


@pytest.mark.parametrize("subject", ["user-analyst-a", "user-viewer-a", "user-auditor-a"])
def test_non_admin_roles_cannot_manage_api_keys(auth_client, subject: str) -> None:
    headers = auth_headers(signed_token(subject=subject))
    assert auth_client.get("/api-keys", headers=headers).status_code == 403
    assert create_key(auth_client, headers=headers).status_code == 403


def test_create_key_returns_plaintext_once_and_stores_only_hash(auth_client) -> None:
    response = create_key(auth_client)
    assert response.status_code == 201
    assert response.headers["cache-control"] == "no-store"
    created = response.json()
    key = created["key"]
    assert key.startswith(f"dlp_{created['prefix']}.")
    key_id = UUID(created["id"])

    factory = auth_client.app.state.test_session_factory
    with factory() as session:
        row = session.execute(select(API_KEYS).where(API_KEYS.c.id == str(key_id))).mappings().one()
    assert row["prefix"] == created["prefix"]
    assert row["key_hash"] == hashlib.sha256(key.encode()).hexdigest()
    assert row["key_hash"] != key
    assert key not in str(dict(row))

    listed = auth_client.get("/api-keys", headers=auth_headers())
    assert listed.status_code == 200
    assert key not in listed.text
    assert "key_hash" not in listed.text
    assert "key" not in listed.json()[0]


def test_api_key_updates_last_used_and_authenticates(auth_client) -> None:
    created = create_key(auth_client).json()
    headers = auth_headers(created["key"])
    response = auth_client.get("/auth/me", headers=headers)
    assert response.status_code == 200
    assert response.json()["auth_method"] == "api_key"

    factory = auth_client.app.state.test_session_factory
    with factory() as session:
        row = (
            session.execute(select(API_KEYS).where(API_KEYS.c.id == created["id"])).mappings().one()
        )
    assert row["last_used_at"] is not None


def test_revoked_and_invalid_api_keys_are_rejected(auth_client) -> None:
    created = create_key(auth_client).json()
    revoke = auth_client.delete(f"/api-keys/{created['id']}", headers=auth_headers())
    assert revoke.status_code == 204
    assert auth_client.get("/auth/me", headers=auth_headers(created["key"])).status_code == 401
    assert (
        auth_client.get(
            "/auth/me",
            headers=auth_headers(
                "dlp_000000000000.invalid-secret-value-0000000000000000000000000000000000000000"
            ),
        ).status_code
        == 401
    )


def test_only_own_organization_keys_are_listed_and_revoked(auth_client) -> None:
    key_a = create_key(auth_client, name="org-a").json()
    token_b = signed_token(subject="user-owner-b", organization_id=ORG_B)
    key_b = create_key(
        auth_client,
        headers=auth_headers(token_b),
        name="org-b",
    ).json()

    listed_a = auth_client.get(
        f"/api-keys?org_id={ORG_B}",
        headers=auth_headers(),
    )
    assert listed_a.status_code == 200
    assert [item["id"] for item in listed_a.json()] == [key_a["id"]]
    assert auth_client.delete(f"/api-keys/{key_b['id']}", headers=auth_headers()).status_code == 403
    assert (
        auth_client.get("/api-keys", headers=auth_headers(token_b)).json()[0]["id"] == key_b["id"]
    )


def test_client_supplied_org_id_cannot_override_principal(auth_client) -> None:
    response = create_key(auth_client, org_id=ORG_B)
    assert response.status_code == 422
    listed = auth_client.get("/api-keys", headers=auth_headers())
    assert listed.json() == []


def test_wrong_organization_api_key_record_does_not_authenticate(auth_client) -> None:
    created = create_key(auth_client).json()
    factory = auth_client.app.state.test_session_factory
    with factory.begin() as session:
        session.execute(
            text("UPDATE dlp_api_keys SET org_id = :org_id WHERE id = :key_id"),
            {"org_id": str(ORG_B), "key_id": created["id"]},
        )
    response = auth_client.get("/auth/me", headers=auth_headers(created["key"]))
    assert response.status_code == 401


def test_missing_api_key_scope_is_denied(auth_client) -> None:
    created = create_key(
        auth_client,
        scopes=["identity:read"],
    ).json()
    assert auth_client.get("/api-keys", headers=auth_headers(created["key"])).status_code == 403


def test_api_key_cannot_delegate_scopes_it_does_not_have(auth_client) -> None:
    created = create_key(auth_client, scopes=["api_keys:write"]).json()
    response = create_key(
        auth_client,
        headers=auth_headers(created["key"]),
        scopes=["identity:read", "api_keys:write"],
    )
    assert response.status_code == 403


def test_unknown_client_scope_is_rejected(auth_client) -> None:
    response = create_key(auth_client, scopes=["superuser:all"])
    assert response.status_code == 422
    assert "superuser:all" not in response.text
