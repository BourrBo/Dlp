"""P13 interactive sessions, membership context, and organization IP controls."""

import hashlib
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import insert, select, text

from dlp_platform.contracts.audit_event import AuditAction
from dlp_platform.tables import (
    APP_SESSIONS,
    AUDIT_EVENTS,
    IP_ALLOWLIST_ENTRIES,
    IP_ALLOWLIST_SETTINGS,
    MEMBERS,
    SCIM_USERS,
)
from platform_tests.auth.conftest import ORG_A, ORG_B
from platform_tests.auth.helpers import auth_headers, signed_token


def _factory(client):
    return client.app.state.test_session_factory


def test_jwt_session_is_hash_only_listable_and_expires_with_token(auth_client) -> None:
    token = signed_token()
    response = auth_client.get("/auth/me", headers=auth_headers(token))
    assert response.status_code == 200
    session_id = response.json()["session_id"]
    assert session_id
    with _factory(auth_client)() as session:
        row = session.execute(select(APP_SESSIONS)).mappings().one()
        assert row["token_hash"] == hashlib.sha256(token.encode()).hexdigest()
        assert token not in str(dict(row))
        assert row["expires_at"] is not None
    listed = auth_client.get("/auth/sessions", headers=auth_headers(token))
    assert listed.status_code == 200
    assert listed.json()[0]["session_id"] == session_id
    assert listed.json()[0]["current"] is True
    assert token not in listed.text
    expired = signed_token(expires_in=-60)
    assert auth_client.get("/auth/me", headers=auth_headers(expired)).status_code == 401


def test_logout_current_revokes_token_without_revoking_api_keys(auth_client) -> None:
    token = signed_token()
    assert auth_client.get("/auth/me", headers=auth_headers(token)).status_code == 200
    api_key = auth_client.post(
        "/api-keys",
        json={"name": "Independent API key", "scopes": ["identity:read"]},
        headers=auth_headers(token),
    ).json()["key"]
    response = auth_client.delete("/auth/sessions/current", headers=auth_headers(token))
    assert response.status_code == 204
    assert auth_client.get("/auth/me", headers=auth_headers(token)).status_code == 401
    assert auth_client.get("/auth/me", headers=auth_headers(api_key)).status_code == 200
    assert (
        auth_client.get(
            "/auth/sessions", headers=auth_headers(token)
        ).status_code
        == 401
    )


def test_revoke_others_and_cross_user_session_access(auth_client) -> None:
    first = signed_token()
    second = signed_token()
    auth_client.get("/auth/me", headers=auth_headers(first))
    auth_client.get("/auth/me", headers=auth_headers(second))
    result = auth_client.post(
        "/auth/sessions/revoke-others", headers=auth_headers(second)
    )
    assert result.status_code == 200
    assert result.json()["revoked_count"] == 1
    assert auth_client.get("/auth/me", headers=auth_headers(first)).status_code == 401
    assert auth_client.get("/auth/me", headers=auth_headers(second)).status_code == 200

    other = signed_token(subject="user-owner-b", organization_id=ORG_B)
    auth_client.get("/auth/me", headers=auth_headers(other))
    with _factory(auth_client)() as session:
        other_id = session.execute(
            select(APP_SESSIONS.c.id).where(
                APP_SESSIONS.c.token_hash == hashlib.sha256(other.encode()).hexdigest()
            )
        ).scalar_one()
    denied = auth_client.delete(
        f"/auth/sessions/{other_id}", headers=auth_headers(second)
    )
    assert denied.status_code == 404


def test_api_key_is_not_an_interactive_session(auth_client) -> None:
    created = auth_client.post(
        "/api-keys", json={"name": "P13 API key", "scopes": ["identity:read"]},
        headers=auth_headers(),
    ).json()
    with _factory(auth_client)() as session:
        before = session.execute(select(APP_SESSIONS.c.id)).all()
    response = auth_client.get("/auth/sessions", headers=auth_headers(created["key"]))
    assert response.status_code == 403
    with _factory(auth_client)() as session:
        assert len(session.execute(select(APP_SESSIONS.c.id)).all()) == len(before)


def test_membership_switch_reloads_role_and_rejects_forged_or_inactive_org(auth_client) -> None:
    factory = _factory(auth_client)
    member_b = uuid4()
    with factory.begin() as session:
        session.execute(
            insert(MEMBERS).values(
                id=str(member_b),
                organization_id=str(ORG_B),
                auth_subject_id="user-viewer-a",
                role="admin",
                email="viewer-a-org-b@example.test",
                active=True,
            )
        )

    token = signed_token(subject="user-viewer-a", organization_id=ORG_A)
    headers = auth_headers(token)
    assert auth_client.post(
        "/api/scim/credentials", json={"name": "denied"}, headers=headers
    ).status_code == 403
    choices = auth_client.get("/organizations", headers=headers)
    assert choices.status_code == 200
    assert {(row["organization_id"], row["role"]) for row in choices.json()} == {
        (str(ORG_A), "viewer"),
        (str(ORG_B), "admin"),
    }
    forged = auth_client.post(
        f"/organizations/{uuid4()}/switch", headers=headers
    )
    assert forged.status_code == 403
    switched = auth_client.post(f"/organizations/{ORG_B}/switch", headers=headers)
    assert switched.status_code == 200
    assert switched.json()["role"] == "admin"
    assert switched.json()["organization_id"] == str(ORG_B)
    assert auth_client.post(
        "/api/scim/credentials", json={"name": "allowed"}, headers=headers
    ).status_code == 201
    assert auth_client.get("/auth/me", headers=headers).json()["organization_id"] == str(ORG_B)

    second_token = signed_token(subject="user-viewer-a", organization_id=ORG_A)
    second_headers = auth_headers(second_token)
    assert auth_client.get("/auth/me", headers=second_headers).status_code == 200
    with factory.begin() as session:
        session.execute(
            text("UPDATE members SET active=0 WHERE id=:id"), {"id": str(member_b)}
        )
    invalid = auth_client.post(f"/organizations/{ORG_B}/switch", headers=second_headers)
    assert invalid.status_code == 403


def test_profile_contains_only_available_identity_fields(auth_client) -> None:
    response = auth_client.get("/identity/profile", headers=auth_headers())
    assert response.status_code == 200
    data = response.json()
    assert data["organization_id"] == str(ORG_A)
    assert data["role"] == "owner"
    assert "password" not in response.text.lower()
    assert "token" not in response.text.lower()


def test_sso_and_scim_provisioned_identities_use_interactive_sessions(
    auth_client, monkeypatch
) -> None:
    from dlp_platform.identity.mapping import issue_access_token

    monkeypatch.setenv("DLP_SSO_TOKEN_SECRET", "synthetic-sso-secret-for-p13-tests-123456789")
    sso_token = issue_access_token(
        "user-owner-a",
        ORG_A,
        secret="synthetic-sso-secret-for-p13-tests-123456789",
        issuer="dlp-sso",
        audience="dlp-api",
    )
    response = auth_client.get("/auth/me", headers=auth_headers(sso_token))
    assert response.json()["auth_method"] == "sso"

    credential = auth_client.post(
        "/api/scim/credentials", json={"name": "P13 SCIM test"}, headers=auth_headers()
    ).json()["token"]
    created = auth_client.post(
        "/scim/v2/Users",
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "p13-provisioned@example.test",
            "emails": [{"value": "p13-provisioned@example.test", "type": "work"}],
        },
        headers={"Authorization": f"Bearer {credential}", "Content-Type": "application/scim+json"},
    )
    assert created.status_code == 201
    with _factory(auth_client)() as session:
        member_id = session.execute(
            select(SCIM_USERS.c.member_id).where(SCIM_USERS.c.id == created.json()["id"])
        ).scalar_one()
        subject = session.execute(
            select(MEMBERS.c.auth_subject_id).where(MEMBERS.c.id == member_id)
        ).scalar_one()
    provisioned = signed_token(subject=subject, organization_id=ORG_A)
    response = auth_client.get("/auth/me", headers=auth_headers(provisioned))
    assert response.status_code == 200
    assert response.json()["member_id"] == member_id
    assert response.json()["session_id"]


def test_ip_allowlist_admin_crud_validation_and_fail_safe(auth_client, monkeypatch) -> None:
    token = signed_token()
    headers = auth_headers(token)
    api_key = auth_client.post(
        "/api-keys",
        json={
            "name": "unrestricted",
            "scopes": ["identity:read", "identity:security:write"],
        },
        headers=headers,
    ).json()["key"]
    assert auth_client.get(
        "/organizations/current/ip-allowlist", headers=headers
    ).json() == {"enabled": False, "entries": []}
    assert auth_client.get(
        "/organizations/current/ip-allowlist", headers=auth_headers(api_key)
    ).status_code == 403
    assert auth_client.put(
        "/organizations/current/ip-allowlist", json={"enabled": True}, headers=headers
    ).status_code == 409
    denied = auth_client.post(
        "/organizations/current/ip-allowlist/entries",
        json={"network": "192.168.1.999", "label": "bad"},
        headers=headers,
    )
    assert denied.status_code == 422

    networks = [
        ("192.0.2.3", "Single IPv4"),
        ("198.51.100.0/24", "IPv4 office"),
        ("2001:db8::/32", "IPv6 office"),
    ]
    entry_ids = []
    for network, label in networks:
        added = auth_client.post(
            "/organizations/current/ip-allowlist/entries",
            json={"network": network, "label": label},
            headers=headers,
        )
        assert added.status_code == 201
        entry_ids.append(added.json()["id"])
    assert auth_client.put(
        "/organizations/current/ip-allowlist", json={"enabled": True}, headers=headers
    ).status_code == 200

    monkeypatch.setattr("dlp_platform.auth.principal.client_ip", lambda _request: "198.51.100.10")
    assert auth_client.get("/auth/me", headers=headers).status_code == 200
    monkeypatch.setattr("dlp_platform.auth.principal.client_ip", lambda _request: "203.0.113.10")
    blocked_token = signed_token(subject="user-owner-a")
    blocked = auth_client.get("/auth/me", headers=auth_headers(blocked_token))
    assert blocked.status_code == 403
    assert blocked.json()["detail"] == "Access is not allowed from this network"
    with _factory(auth_client)() as session:
        events = session.execute(
            select(AUDIT_EVENTS.c.action).where(
                AUDIT_EVENTS.c.action == AuditAction.IDENTITY_IP_ALLOWLIST_BLOCKED.value
            )
        ).scalars().all()
        assert events

    # API-key traffic remains outside the human-session IP policy.
    assert auth_client.get("/auth/me", headers=auth_headers(api_key)).status_code == 200

    monkeypatch.setattr("dlp_platform.auth.principal.client_ip", lambda _request: "2001:db8::1")
    for entry_id in entry_ids[:-1]:
        assert auth_client.delete(
            f"/organizations/current/ip-allowlist/entries/{entry_id}", headers=headers
        ).status_code == 204
    final_remove = auth_client.delete(
        f"/organizations/current/ip-allowlist/entries/{entry_ids[-1]}", headers=headers
    )
    assert final_remove.status_code == 409
    assert auth_client.put(
        "/organizations/current/ip-allowlist", json={"enabled": False}, headers=headers
    ).status_code == 200
    assert auth_client.delete(
        f"/organizations/current/ip-allowlist/entries/{entry_ids[-1]}", headers=headers
    ).status_code == 204


def test_ip_allowlist_permission_and_tenant_scope(auth_client) -> None:
    viewer = auth_headers(signed_token(subject="user-viewer-a"))
    assert auth_client.get(
        "/organizations/current/ip-allowlist", headers=viewer
    ).status_code == 403
    with _factory(auth_client).begin() as session:
        session.execute(
            insert(IP_ALLOWLIST_SETTINGS).values(
                org_id=str(ORG_B), enabled=True, updated_by="ffffffff-ffff-4fff-8fff-ffffffffffff",
                updated_at=datetime.now(UTC),
            )
        )
        session.execute(
            insert(IP_ALLOWLIST_ENTRIES).values(
                id=str(uuid4()), org_id=str(ORG_B), network="203.0.113.0/24", label="B",
                created_by="ffffffff-ffff-4fff-8fff-ffffffffffff",
                created_at=datetime.now(UTC),
            )
        )
    result = auth_client.get(
        "/organizations/current/ip-allowlist", headers=auth_headers()
    )
    assert result.status_code == 200
    assert result.json() == {"enabled": False, "entries": []}


@pytest.mark.parametrize(
    ("address", "network", "expected"),
    [
        ("192.0.2.1", "192.0.2.1", True),
        ("192.0.2.254", "192.0.2.0/24", True),
        ("192.0.3.1", "192.0.2.0/24", False),
        ("2001:db8::1", "2001:db8::/32", True),
        ("2001:db9::1", "2001:db8::/32", False),
    ],
)
def test_address_and_cidr_match(address: str, network: str, expected: bool) -> None:
    from dlp_platform.identity.network import is_allowed

    assert is_allowed(address, [network]) is expected
