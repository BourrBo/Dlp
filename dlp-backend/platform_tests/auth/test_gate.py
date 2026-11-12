"""P04 gate endpoint keeps P02/P03 controls and emits a pass/fail SARIF shell."""

from platform_tests.auth.helpers import auth_headers, signed_token


def test_gate_requires_auth_and_scan_permission(auth_client) -> None:
    body = {"channel": "api", "content": "synthetic"}
    assert auth_client.post("/gate/check", json=body).status_code == 401
    viewer = auth_headers(signed_token(subject="user-viewer-a"))
    assert auth_client.post("/gate/check", json=body, headers=viewer).status_code == 403


def test_gate_uses_shared_scan_and_returns_deterministic_sarif_ready_result(auth_client) -> None:
    body = {
        "request_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "channel": "repository",
        "content": "synthetic repository input",
    }
    response = auth_client.post("/gate/check", json=body, headers=auth_headers())
    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "pass"
    assert result["decision"] == "allow"
    assert result["sarif"]["version"] == "2.1.0"
    assert result["sarif"]["runs"][0]["results"] == []
    assert "synthetic repository input" not in response.text


def test_scan_failure_returns_safe_stable_error_without_content(
    auth_client, monkeypatch, caplog
) -> None:
    def fail(*args, **kwargs):
        raise RuntimeError("private raw input must never be returned")

    monkeypatch.setattr("dlp_platform.routes.scan.scan", fail)
    response = auth_client.post(
        "/scan",
        json={"channel": "api", "content": "private raw input"},
        headers=auth_headers(),
    )
    assert response.status_code == 500
    assert response.json() == {
        "detail": {"code": "internal_error", "message": "Scan could not be completed"}
    }
    assert "private raw input" not in response.text
    assert "private raw input" not in caplog.text
