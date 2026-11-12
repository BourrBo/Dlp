"""SCIM API contract, credential, lifecycle, and privilege boundary tests."""

import hashlib
import json
from uuid import UUID

from sqlalchemy import select

from dlp_platform.tables import AUDIT_EVENTS, MEMBERS, SCIM_CREDENTIALS
from platform_tests.auth.conftest import ORG_B
from platform_tests.auth.helpers import auth_headers, signed_token


def _credential(client) -> str:
    response = client.post(
        "/api/scim/credentials", json={"name": "Workforce IdP"}, headers=auth_headers()
    )
    assert response.status_code == 201
    return response.json()["token"]


def _scim(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/scim+json"}


def _user(username: str, **fields: object) -> dict[str, object]:
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": username,
        "displayName": username.title(),
        "active": True,
        **fields,
    }


def test_scim_credentials_are_one_time_hash_only_and_admin_managed(auth_client) -> None:
    created = auth_client.post(
        "/api/scim/credentials", json={"name": "Workforce IdP"}, headers=auth_headers()
    )
    assert created.status_code == 201
    token = created.json()["token"]
    assert token.startswith("scim_")
    assert created.json()["token"] == token  # it is returned only at creation
    client = auth_client.app.state.test_session_factory()
    try:
        row = client.execute(select(SCIM_CREDENTIALS)).mappings().one()
        assert row["token_hash"] == hashlib.sha256(token.encode()).hexdigest()
        assert token not in row["token_hash"]
    finally:
        client.close()
    listing = auth_client.get("/api/scim/credentials", headers=auth_headers())
    assert listing.status_code == 200
    assert token not in json.dumps(listing.json())
    assert "token_hash" not in json.dumps(listing.json())
    revoked = auth_client.delete(
        f"/api/scim/credentials/{created.json()['id']}", headers=auth_headers()
    )
    assert revoked.status_code == 204
    rejected = auth_client.get("/scim/v2/Users", headers=_scim(token))
    assert rejected.status_code == 401
    assert rejected.json()["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]


def test_scim_credentials_require_admin_and_never_authenticate_general_api(
    auth_client,
) -> None:
    denied = auth_client.post(
        "/api/scim/credentials",
        json={"name": "Not allowed"},
        headers=auth_headers(signed_token("user-analyst-a")),
    )
    assert denied.status_code == 403
    token = _credential(auth_client)
    unrelated = auth_client.get("/policies", headers=_scim(token))
    assert unrelated.status_code == 401
    missing = auth_client.get("/scim/v2/Users")
    assert missing.status_code == 401


def test_scim_user_create_duplicate_filter_page_and_cross_tenant_lookup(
    auth_client,
) -> None:
    token = _credential(auth_client)
    headers = _scim(token)
    created = auth_client.post(
        "/scim/v2/Users",
        json=_user(
            "sujal@example.test",
            externalId="emp-1",
            emails=[{"value": "sujal@example.test", "type": "work"}],
        ),
        headers=headers,
    )
    assert created.status_code == 201
    body = created.json()
    assert body["externalId"] == "emp-1"
    assert body["active"] is True
    assert "role" not in body and "organization_id" not in body
    duplicate = auth_client.post(
        "/scim/v2/Users", json=_user("sujal@example.test"), headers=headers
    )
    assert duplicate.status_code == 409
    listed = auth_client.get(
        "/scim/v2/Users?filter=userName%20eq%20%22sujal%40example.test%22&startIndex=1&count=1",
        headers=headers,
    )
    assert listed.status_code == 200
    assert listed.json()["totalResults"] == 1
    assert listed.json()["Resources"][0]["id"] == body["id"]
    second = auth_client.post(
        "/scim/v2/Users", json=_user("second@example.test"), headers=headers
    )
    assert second.status_code == 201
    page = auth_client.get(
        "/scim/v2/Users?startIndex=2&count=1", headers=headers
    ).json()
    assert page["totalResults"] == 2 and page["itemsPerPage"] == 1
    assert (
        auth_client.get(
            "/scim/v2/Users?startIndex=invalid", headers=headers
        ).status_code
        == 400
    )
    assert (
        auth_client.get(
            f"/scim/v2/Users/{body['id']}",
            headers=_scim(_credential_for_org_b(auth_client)),
        ).status_code
        == 404
    )
    forged = auth_client.post(
        "/scim/v2/Users",
        json=_user("forged@example.test", organization_id=str(ORG_B), role="owner"),
        headers=headers,
    )
    assert forged.status_code == 400


def _credential_for_org_b(client) -> str:
    from platform_tests.auth.conftest import JWT_SECRET

    token = signed_token(
        subject="user-owner-b", organization_id=ORG_B, secret=JWT_SECRET
    )
    response = client.post(
        "/api/scim/credentials", json={"name": "Org B"}, headers=auth_headers(token)
    )
    assert response.status_code == 201
    return response.json()["token"]


def test_scim_patch_update_delete_and_protected_role(auth_client) -> None:
    token = _credential(auth_client)
    headers = _scim(token)
    created = auth_client.post(
        "/scim/v2/Users",
        json=_user(
            "person@example.test",
            emails=[{"value": "person@example.test", "type": "work"}],
        ),
        headers=headers,
    )
    resource_id = created.json()["id"]
    patch = auth_client.patch(
        f"/scim/v2/Users/{resource_id}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": False}],
        },
        headers=headers,
    )
    assert patch.status_code == 200 and patch.json()["active"] is False
    forbidden = auth_client.patch(
        f"/scim/v2/Users/{resource_id}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "role", "value": "owner"}],
        },
        headers=headers,
    )
    assert forbidden.status_code == 400
    assert (
        auth_client.delete(f"/scim/v2/Users/{resource_id}", headers=headers).status_code
        == 204
    )
    assert (
        auth_client.get(f"/scim/v2/Users/{resource_id}", headers=headers).json()[
            "active"
        ]
        is False
    )
    session = auth_client.app.state.test_session_factory()
    try:
        user = session.execute(
            select(MEMBERS).where(MEMBERS.c.id == created.json()["id"])
        ).first()
        assert user is None  # SCIM ids are separate stable resource identifiers
        member = session.execute(
            select(MEMBERS).where(MEMBERS.c.email == "person@example.test")
        ).one()
        assert member.role == "viewer" and member.active is False
        subject = member.auth_subject_id
    finally:
        session.close()
    inactive_jwt = signed_token(subject=subject)
    assert (
        auth_client.get("/auth/me", headers=auth_headers(inactive_jwt)).status_code
        == 401
    )


def test_scim_groups_membership_and_no_role_effect(auth_client) -> None:
    token = _credential(auth_client)
    headers = _scim(token)
    user = auth_client.post(
        "/scim/v2/Users", json=_user("grouped@example.test"), headers=headers
    ).json()
    created = auth_client.post(
        "/scim/v2/Groups",
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "externalId": "team-1",
            "displayName": "Engineering",
            "members": [{"value": user["id"]}],
        },
        headers=headers,
    )
    assert created.status_code == 201
    assert created.json()["members"][0]["value"] == user["id"]
    duplicate_member = auth_client.post(
        "/scim/v2/Groups",
        json={
            "displayName": "Duplicate",
            "members": [{"value": user["id"]}, {"value": user["id"]}],
        },
        headers=headers,
    )
    assert duplicate_member.status_code == 400
    unknown_member = auth_client.post(
        "/scim/v2/Groups",
        json={"displayName": "Unknown", "members": [{"value": str(UUID(int=4))}]},
        headers=headers,
    )
    assert unknown_member.status_code == 400
    patched = auth_client.patch(
        f"/scim/v2/Groups/{created.json()['id']}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "remove", "path": "members"}],
        },
        headers=headers,
    )
    assert patched.status_code == 200 and patched.json()["members"] == []
    member_add = auth_client.patch(
        f"/scim/v2/Groups/{created.json()['id']}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                {
                    "op": "add",
                    "path": f'members[value eq "{user["id"]}"]',
                    "value": {"value": user["id"]},
                }
            ],
        },
        headers=headers,
    )
    assert member_add.status_code == 200
    assert len(member_add.json()["members"]) == 1
    member_remove = auth_client.patch(
        f"/scim/v2/Groups/{created.json()['id']}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                {
                    "op": "remove",
                    "path": f'members[value eq "{user["id"]}"]',
                }
            ],
        },
        headers=headers,
    )
    assert member_remove.status_code == 200 and member_remove.json()["members"] == []
    assert (
        auth_client.delete(
            f"/scim/v2/Groups/{created.json()['id']}", headers=headers
        ).status_code
        == 204
    )


def test_scim_errors_filter_validation_and_credential_audit(auth_client) -> None:
    token = _credential(auth_client)
    headers = _scim(token)
    malformed = auth_client.post("/scim/v2/Users", content="{bad", headers=headers)
    assert malformed.status_code == 400
    assert malformed.json()["status"] == "400"
    bad_filter = auth_client.get("/scim/v2/Users?filter=role%20pr", headers=headers)
    assert bad_filter.status_code == 400
    no_type = auth_client.post(
        "/scim/v2/Users", content="{}", headers={"Authorization": f"Bearer {token}"}
    )
    assert no_type.status_code == 415
    rows = auth_client.app.state.test_session_factory()
    try:
        actions = rows.execute(select(AUDIT_EVENTS.c.action)).scalars().all()
        assert "scim.credential_created" in actions
        assert "scim.credential_revoked" not in actions
        contents = rows.execute(select(AUDIT_EVENTS.c.event_metadata)).scalars().all()
        assert all("token" not in json.dumps(value).lower() for value in contents)
    finally:
        rows.close()


def test_scim_credentials_are_rate_limited_per_token_and_organization(
    auth_client, monkeypatch
) -> None:
    from dlp_platform.ratelimit.dependencies import get_rate_limiter

    token = _credential(auth_client)
    headers = _scim(token)
    monkeypatch.setenv("RATE_LIMIT_PER_KEY", "1")
    monkeypatch.setenv("RATE_LIMIT_PER_ORG", "100")
    get_rate_limiter.cache_clear()
    try:
        assert auth_client.get("/scim/v2/Users", headers=headers).status_code == 200
        limited = auth_client.get("/scim/v2/Users", headers=headers)
        assert limited.status_code == 429
        assert limited.headers["Retry-After"]
        assert limited.json()["schemas"] == [
            "urn:ietf:params:scim:api:messages:2.0:Error"
        ]
    finally:
        get_rate_limiter.cache_clear()
