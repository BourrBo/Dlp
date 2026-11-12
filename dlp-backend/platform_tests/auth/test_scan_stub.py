"""P03 endpoint authorization, request validation, and contract handoff tests."""

from uuid import UUID

from dlp_platform.ratelimit.dependencies import get_rate_limiter
from platform_tests.auth.helpers import auth_headers, signed_token


def test_scan_stub_authenticated_and_contract_compatible(auth_client) -> None:
    payload = {
        "request_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "channel": "api",
        "content": "sensitive synthetic content",
        "requested_at": "2026-10-21T00:00:00Z",
    }
    first = auth_client.post("/scan", json=payload, headers=auth_headers())
    second = auth_client.post("/scan", json=payload, headers=auth_headers())
    assert first.status_code == 200
    assert first.json() == second.json()
    result = first.json()
    assert UUID(result["request_id"]) == UUID(payload["request_id"])
    assert result["decision"] == "allow"
    assert result["findings"] == []
    assert result["policy_version"] is None
    assert "no detection performed" in result["reason"]
    assert "sensitive synthetic content" not in first.text
    assert "X-RateLimit-Remaining" in first.headers


def test_scan_requires_auth_role_permission_and_valid_input(auth_client) -> None:
    payload = {"channel": "api", "content": "synthetic"}
    assert auth_client.post("/scan", json=payload).status_code == 401
    viewer = auth_headers(signed_token(subject="user-viewer-a"))
    assert auth_client.post("/scan", json=payload, headers=viewer).status_code == 403
    invalid = {"channel": "api", "content": "", "org_id": "22222222-2222-4222-8222-222222222222"}
    assert auth_client.post("/scan", json=invalid, headers=auth_headers()).status_code == 422
    forged = {
        "channel": "api",
        "content": "valid synthetic input",
        "org_id": "22222222-2222-4222-8222-222222222222",
    }
    assert auth_client.post("/scan", json=forged, headers=auth_headers()).status_code == 422


def test_analyst_can_scan_but_wrong_organization_identity_is_required(auth_client) -> None:
    analyst = auth_headers(signed_token(subject="user-analyst-a"))
    response = auth_client.post("/scan", json={"channel": "api", "content": "x"}, headers=analyst)
    assert response.status_code == 200
    wrong_org = auth_headers(
        signed_token(organization_id=UUID("22222222-2222-4222-8222-222222222222"))
    )
    assert (
        auth_client.post(
            "/scan", json={"channel": "api", "content": "x"}, headers=wrong_org
        ).status_code
        == 401
    )


def test_scan_endpoint_returns_429_and_retry_header(auth_client, monkeypatch) -> None:
    monkeypatch.setenv("RATE_LIMIT_PER_KEY", "1")
    monkeypatch.setenv("RATE_LIMIT_PER_ORG", "5")
    monkeypatch.setenv("RATE_LIMIT_WINDOW_SECONDS", "60")
    monkeypatch.setenv("RATE_LIMIT_BACKEND", "memory")
    get_rate_limiter.cache_clear()
    try:
        headers = auth_headers()
        body = {"channel": "api", "content": "synthetic"}
        assert auth_client.post("/scan", json=body, headers=headers).status_code == 200
        rejected = auth_client.post("/scan", json=body, headers=headers)
        assert rejected.status_code == 429
        assert int(rejected.headers["Retry-After"]) >= 1
        assert rejected.json() == {"detail": "Rate limit exceeded"}
    finally:
        get_rate_limiter.cache_clear()
