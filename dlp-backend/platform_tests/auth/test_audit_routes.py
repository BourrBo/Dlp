"""Audit query authorization, filtering, pagination, and response safety."""

from platform_tests.auth.conftest import ORG_B, OWNER_ID
from platform_tests.auth.helpers import auth_headers, signed_token
from platform_tests.auth.test_api_keys import create_key


def test_audit_query_is_authorized_filterable_and_metadata_only(auth_client) -> None:
    request_headers = {**auth_headers(), "User-Agent": "ExampleBrowser/1.0"}
    created = create_key(auth_client, headers=request_headers, name="audit-query-test")
    assert created.status_code == 201
    all_events = auth_client.get("/audit/events", headers=request_headers)
    assert all_events.status_code == 200
    data = all_events.json()
    assert data[0]["action"] == "auth.api_key_created"
    assert data[0]["actor_id"] == str(OWNER_ID)
    assert data[0]["resource_id"] == created.json()["id"]
    assert data[0]["correlation_id"]
    assert data[0]["correlation_id"] == created.headers["x-request-id"]
    assert data[0]["user_agent"] == "ExampleBrowser/1.0"
    assert data[0]["event_hash"]
    assert created.json()["key"] not in all_events.text
    assert "key_hash" not in all_events.text

    filtered = auth_client.get(
        "/audit/events?action=auth.api_key_created&resource_type=api_key&limit=1",
        headers=request_headers,
    )
    assert filtered.status_code == 200
    assert len(filtered.json()) == 1
    assert filtered.json()[0]["event_id"] == data[0]["event_id"]
    assert auth_client.get("/audit/events?limit=101", headers=auth_headers()).status_code == 422


def test_audit_query_roles_and_api_key_scope(auth_client) -> None:
    assert auth_client.get("/audit/events", headers=auth_headers()).status_code == 200
    analyst = auth_headers(signed_token(subject="user-analyst-a"))
    assert auth_client.get("/audit/events", headers=analyst).status_code == 403
    denied = auth_client.get(
        "/audit/events?action=auth.authorization_denied", headers=auth_headers()
    )
    assert denied.status_code == 200
    assert denied.json()[0]["outcome"] == "denied"
    auditor = auth_headers(signed_token(subject="user-auditor-a"))
    assert auth_client.get("/audit/events", headers=auditor).status_code == 200

    key = create_key(
        auth_client,
        name="audit-reader",
        scopes=["audit:read"],
    ).json()
    response = auth_client.get("/audit/events", headers=auth_headers(key["key"]))
    assert response.status_code == 200


def test_audit_query_is_tenant_scoped(auth_client) -> None:
    created_a = create_key(auth_client, name="tenant-a-key")
    token_b = signed_token(subject="user-owner-b", organization_id=ORG_B)
    created_b = create_key(
        auth_client,
        headers=auth_headers(token_b),
        name="tenant-b-key",
    )
    listed_a = auth_client.get("/audit/events", headers=auth_headers())
    assert created_a.status_code == 201
    assert created_b.status_code == 201
    assert listed_a.status_code == 200
    resource_ids = {item["resource_id"] for item in listed_a.json()}
    assert created_a.json()["id"] in resource_ids
    assert created_b.json()["id"] not in resource_ids


def test_audit_chain_verification_is_tenant_scoped_and_permission_checked(auth_client) -> None:
    created = create_key(auth_client, name="audit-chain-verification")
    assert created.status_code == 201
    verified = auth_client.get("/audit/events/verify-chain", headers=auth_headers())
    assert verified.status_code == 200
    result = verified.json()
    assert result["valid"] is True
    assert result["checked_events"] >= 1
    assert result["online_limit"] == 10_000

    analyst = auth_headers(signed_token(subject="user-analyst-a"))
    assert auth_client.get("/audit/events/verify-chain", headers=analyst).status_code == 403
    auditor = auth_headers(signed_token(subject="user-auditor-a"))
    assert auth_client.get("/audit/events/verify-chain", headers=auditor).status_code == 200


def test_audit_chain_verification_reports_invalid_chain(auth_client, monkeypatch) -> None:
    from dlp_platform.audit.service import AuditChainVerification
    from dlp_platform.routes import audit

    monkeypatch.setattr(
        audit._audit,
        "verify_chain_result",
        lambda *_args, **_kwargs: AuditChainVerification(False, 1),
    )
    response = auth_client.get("/audit/events/verify-chain", headers=auth_headers())
    assert response.status_code == 200
    assert response.json()["valid"] is False
    assert response.json()["checked_events"] == 1


def test_audit_chain_verification_errors_are_bounded_and_sanitized(
    auth_client, monkeypatch
) -> None:
    from dlp_platform.audit.service import AuditPersistenceError, AuditVerificationLimitError
    from dlp_platform.routes import audit

    errors = (
        (AuditVerificationLimitError("large"), 413),
        (AuditPersistenceError("db"), 503),
    )
    for error, status in errors:

        def fail(*_args, _error=error, **_kwargs):
            raise _error

        monkeypatch.setattr(audit._audit, "verify_chain_result", fail)
        response = auth_client.get("/audit/events/verify-chain", headers=auth_headers())
        assert response.status_code == status
        assert "large" not in response.text and "db" not in response.text
