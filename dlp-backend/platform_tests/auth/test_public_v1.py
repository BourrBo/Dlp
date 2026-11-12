"""P15 public API authentication, response stability, and bounds."""

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import insert

from dlp_platform.ratelimit.dependencies import get_rate_limiter
from dlp_platform.ratelimit.limiter import InMemoryRateLimiter
from dlp_platform.tables import POLICIES
from platform_tests.auth.test_api_keys import create_key


def test_public_v1_is_api_key_only_scoped_paginated_and_tenant_scoped(auth_client) -> None:
    factory = auth_client.app.state.test_session_factory
    engine = factory.kw["bind"]
    POLICIES.create(engine, checkfirst=True)
    now = datetime.now(UTC)
    org_a, org_b = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
    owner_a, owner_b = (
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "ffffffff-ffff-4fff-8fff-ffffffffffff",
    )
    policy_a, policy_b = str(uuid4()), str(uuid4())
    with factory.begin() as session:
        session.execute(
            insert(POLICIES),
            [
                {
                    "id": policy_a,
                    "org_id": org_a,
                    "name": "Synthetic A policy",
                    "enabled": True,
                    "priority": 10,
                    "conditions": {"channel": "api"},
                    "action": "block",
                    "version": 3,
                    "created_by": owner_a,
                    "created_at": now,
                    "updated_at": now,
                },
                {
                    "id": policy_b,
                    "org_id": org_b,
                    "name": "Synthetic B policy",
                    "enabled": False,
                    "priority": 20,
                    "conditions": {"channel": "file"},
                    "action": "warn",
                    "version": 1,
                    "created_by": owner_b,
                    "created_at": now,
                    "updated_at": now,
                },
            ],
        )

    auth = {
        "Authorization": f"Bearer {create_key(auth_client, scopes=['identity:read']).json()['key']}"
    }
    no_scope_key = create_key(auth_client, name="public-no-read", scopes=["api_keys:read"]).json()[
        "key"
    ]
    wrong_scope = {"Authorization": f"Bearer {no_scope_key}"}
    assert auth_client.get("/api/v1/policies").status_code == 401
    missing = auth_client.get("/api/v1/policies")
    assert missing.json()["error"]["code"] == "authentication_failed"
    assert missing.json()["error"]["request_id"] == missing.headers["x-request-id"]
    forbidden = auth_client.get("/api/v1/policies", headers=wrong_scope)
    assert forbidden.status_code == 403
    assert forbidden.json()["error"]["code"] == "authorization_failed"

    # Interactive JWTs are valid for internal routes but not this API-key contract.
    from platform_tests.auth.helpers import auth_headers, signed_token

    jwt_response = auth_client.get(
        "/api/v1/policies", headers=auth_headers(signed_token(subject="user-owner-a"))
    )
    assert jwt_response.status_code == 401

    response = auth_client.get("/api/v1/policies?limit=1&offset=0&org_id=" + org_b, headers=auth)
    assert response.status_code == 200
    assert response.headers.get("x-request-id")
    assert response.json()["pagination"] == {"limit": 1, "offset": 0, "total": 1}
    assert response.json()["data"][0]["id"] == policy_a
    assert "conditions" not in response.json()["data"][0]

    detail = auth_client.get(f"/api/v1/policies/{policy_a}", headers=auth)
    cross_tenant = auth_client.get(f"/api/v1/policies/{policy_b}", headers=auth)
    assert detail.status_code == 200
    assert cross_tenant.status_code == 404
    assert cross_tenant.json()["error"]["code"] == "not_found"
    filtered = auth_client.get("/api/v1/policies?action=block&enabled=true", headers=auth)
    assert filtered.status_code == 200 and filtered.json()["pagination"]["total"] == 1
    invalid_limit = auth_client.get("/api/v1/policies?limit=101", headers=auth)
    assert invalid_limit.status_code == 422
    assert invalid_limit.json()["error"]["code"] == "validation_failed"
    assert auth_client.get("/api/v1/policies?offset=1000001", headers=auth).status_code == 422
    assert auth_client.get("/api/v1/policies?action=unsafe", headers=auth).status_code == 422

    # Key revocation remains the existing P02 control and the public route reuses it.
    revoked = create_key(auth_client, scopes=["identity:read"]).json()
    from platform_tests.auth.helpers import auth_headers

    assert (
        auth_client.delete(f"/api-keys/{revoked['id']}", headers=auth_headers()).status_code == 204
    )
    assert (
        auth_client.get(
            "/api/v1/policies", headers={"Authorization": f"Bearer {revoked['key']}"}
        ).status_code
        == 401
    )

    limiter = InMemoryRateLimiter(1, 20, 60, clock=lambda: 60.0)
    auth_client.app.dependency_overrides[get_rate_limiter] = lambda: limiter
    limited_first = auth_client.get("/api/v1/policies", headers=auth)
    limited_second = auth_client.get("/api/v1/policies", headers=auth)
    assert limited_first.status_code == 200
    assert limited_second.status_code == 429
    assert limited_second.headers["retry-after"] == "60"
    assert limited_second.json()["error"]["code"] == "rate_limited"
    auth_client.app.dependency_overrides.pop(get_rate_limiter)


def test_public_v1_openapi_declares_versioned_bearer_api(auth_client) -> None:
    schema = auth_client.get("/openapi.json").json()
    assert "/api/v1/policies" in schema["paths"]
    operation = schema["paths"]["/api/v1/policies"]["get"]
    assert operation["operationId"] == "publicV1ListPolicies"
    assert operation.get("parameters")
    assert operation["security"] == [{"HTTPBearer": []}]
    assert "PublicError" in schema["components"]["schemas"]
    assert "X-Request-ID" in operation["responses"]["200"]["headers"]
    assert "Retry-After" in operation["responses"]["429"]["headers"]


def test_local_rate_limiter_window_resets() -> None:
    clock = [60.0]
    limiter = InMemoryRateLimiter(1, 10, 60, clock=lambda: clock[0])
    assert limiter.check("key", "org").allowed
    assert not limiter.check("key", "org").allowed
    clock[0] = 120.0
    assert limiter.check("key", "org").allowed
