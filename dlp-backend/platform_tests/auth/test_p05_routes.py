"""P05 CRUD route authorization and tenant-filter tests."""

from sqlalchemy import select

from dlp_platform.audit.service import AuditPersistenceError
from dlp_platform.tables import DESTINATIONS, POLICIES, POLICY_VERSIONS, metadata
from platform_tests.auth.conftest import ORG_B
from platform_tests.auth.helpers import auth_headers, signed_token


def prepare_tables(client) -> None:
    factory = client.app.state.test_session_factory
    metadata.create_all(factory.kw["bind"], tables=[POLICIES, DESTINATIONS, POLICY_VERSIONS])


def test_policy_and_destination_crud_are_tenant_scoped(auth_client) -> None:
    prepare_tables(auth_client)
    headers = auth_headers()
    created_policy = auth_client.post(
        "/policies",
        json={"name": "block public API", "conditions": {"channel": "api"}, "action": "block"},
        headers=headers,
    )
    assert created_policy.status_code == 201, created_policy.text
    policy_id = created_policy.json()["policy_id"]
    assert created_policy.json()["version"] == 1
    policy_events = auth_client.get("/audit/events?action=policy.created", headers=headers).json()
    assert policy_events[0]["resource_id"] == policy_id
    assert auth_client.get("/policies", headers=headers).json()[0]["policy_id"] == policy_id

    updated = auth_client.put(
        f"/policies/{policy_id}",
        json={"name": "warn API", "conditions": {"channel": "api"}, "action": "warn"},
        headers=headers,
    )
    assert updated.status_code == 200
    assert updated.json()["version"] == 2
    assert updated.json()["action"] == "warn"
    assert (
        auth_client.get("/audit/events?action=policy.updated", headers=headers).json()[0][
            "resource_id"
        ]
        == policy_id
    )

    destination = auth_client.post(
        "/destinations",
        json={"destination_class": "public", "kind": "domain", "pattern": "*.Example.com."},
        headers=headers,
    )
    assert destination.status_code == 201, destination.text
    destination_id = destination.json()["destination_id"]
    assert destination.json()["pattern"] == "*.example.com"

    headers_b = auth_headers(signed_token(subject="user-owner-b", organization_id=ORG_B))
    assert auth_client.get(f"/policies/{policy_id}", headers=headers_b).status_code == 404
    assert (
        auth_client.put(
            f"/policies/{policy_id}",
            json={"name": "takeover", "conditions": {}, "action": "allow"},
            headers=headers_b,
        ).status_code
        == 404
    )
    assert (
        auth_client.delete(f"/destinations/{destination_id}", headers=headers_b).status_code == 404
    )
    assert auth_client.get("/policies", headers=headers_b).json() == []

    assert auth_client.delete(f"/policies/{policy_id}", headers=headers).status_code == 204
    assert auth_client.delete(f"/destinations/{destination_id}", headers=headers).status_code == 204


def test_client_cannot_supply_another_org_id(auth_client) -> None:
    prepare_tables(auth_client)
    response = auth_client.post(
        "/policies",
        json={"organization_id": str(ORG_B), "name": "forged", "conditions": {}, "action": "block"},
        headers=auth_headers(),
    )
    assert response.status_code == 422
    assert auth_client.get("/policies", headers=auth_headers()).json() == []


def test_policy_change_rolls_back_when_audit_persistence_fails(auth_client, monkeypatch) -> None:
    prepare_tables(auth_client)
    headers = auth_headers()
    assert auth_client.get("/policies", headers=headers).status_code == 200

    def fail_audit(*args, **kwargs):
        raise AuditPersistenceError("synthetic audit sink failure")

    monkeypatch.setattr("dlp_platform.policy.admin_audit.AuditService.record_event", fail_audit)
    response = auth_client.post(
        "/policies",
        json={"name": "must roll back", "conditions": {}, "action": "block"},
        headers=headers,
    )
    assert response.status_code == 503
    assert auth_client.get("/policies", headers=headers).json() == []


def test_policy_crud_enforces_roles_scopes_and_condition_allowlist(auth_client) -> None:
    prepare_tables(auth_client)
    assert auth_client.get("/policies", headers=auth_headers()).status_code == 200
    assert (
        auth_client.post(
            "/policies",
            json={"name": "bad", "conditions": {"python": "exec"}, "action": "block"},
            headers=auth_headers(),
        ).status_code
        == 422
    )
    advanced = auth_client.post(
        "/policies",
        json={"name": "redact", "conditions": {}, "action": "redact"},
        headers=auth_headers(),
    )
    assert advanced.status_code == 201, advanced.text
    analyst = auth_headers(signed_token(subject="user-analyst-a"))
    assert auth_client.get("/policies", headers=analyst).status_code == 200
    assert (
        auth_client.post(
            "/policies",
            json={"name": "no write", "conditions": {}, "action": "block"},
            headers=analyst,
        ).status_code
        == 403
    )


def test_api_key_policy_read_write_scopes(auth_client) -> None:
    prepare_tables(auth_client)
    policy_a = auth_client.post(
        "/policies",
        json={"name": "tenant A policy", "conditions": {}, "action": "block"},
        headers=auth_headers(),
    )
    headers_b = auth_headers(signed_token(subject="user-owner-b", organization_id=ORG_B))
    policy_b = auth_client.post(
        "/policies",
        json={"name": "tenant B policy", "conditions": {}, "action": "warn"},
        headers=headers_b,
    )
    assert policy_a.status_code == policy_b.status_code == 201

    token = auth_headers()
    created = auth_client.post(
        "/api-keys",
        json={"name": "policy reader", "scopes": ["identity:read"]},
        headers=token,
    )
    assert created.status_code == 201
    api_headers = auth_headers(created.json()["key"])
    listed_a = auth_client.get("/policies", headers=api_headers)
    assert listed_a.status_code == 200
    assert [row["policy_id"] for row in listed_a.json()] == [policy_a.json()["policy_id"]]
    assert (
        auth_client.post(
            "/policies",
            json={"name": "forbidden", "conditions": {}, "action": "block"},
            headers=api_headers,
        ).status_code
        == 403
    )

    created_b = auth_client.post(
        "/api-keys",
        json={"name": "tenant B reader", "scopes": ["identity:read"]},
        headers=headers_b,
    )
    assert created_b.status_code == 201
    listed_b = auth_client.get("/policies", headers=auth_headers(created_b.json()["key"]))
    assert [row["policy_id"] for row in listed_b.json()] == [policy_b.json()["policy_id"]]


def test_destination_crud_never_creates_duplicate_patterns(auth_client) -> None:
    prepare_tables(auth_client)
    headers = auth_headers()
    body = {"destination_class": "internal", "kind": "domain", "pattern": "internal.example"}
    assert auth_client.post("/destinations", json=body, headers=headers).status_code == 201
    assert auth_client.post("/destinations", json=body, headers=headers).status_code == 409
    factory = auth_client.app.state.test_session_factory
    with factory() as session:
        assert len(session.execute(select(DESTINATIONS.c.id)).all()) == 1
