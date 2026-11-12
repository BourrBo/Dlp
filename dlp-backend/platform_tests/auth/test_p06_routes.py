"""P06 policy lifecycle, exception, suppression and sandbox API behavior."""

from datetime import UTC, datetime, timedelta

from dlp_platform.tables import DESTINATIONS, EXCEPTIONS, POLICIES, POLICY_VERSIONS, SUPPRESSIONS, metadata
from platform_tests.auth.conftest import ORG_B
from platform_tests.auth.helpers import auth_headers, signed_token


def prepare_tables(client) -> None:
    factory = client.app.state.test_session_factory
    metadata.create_all(
        factory.kw["bind"],
        tables=[POLICIES, DESTINATIONS, POLICY_VERSIONS, EXCEPTIONS, SUPPRESSIONS],
    )


def test_policy_versions_diff_rollback_immutability_and_sandbox_are_side_effect_free(
    auth_client,
) -> None:
    prepare_tables(auth_client)
    headers = auth_headers()
    created = auth_client.post(
        "/policies",
        json={"name": "first", "conditions": {"channel": "api"}, "action": "block"},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    policy_id = created.json()["policy_id"]
    updated = auth_client.put(
        f"/policies/{policy_id}",
        json={"name": "second", "conditions": {"channel": "api"}, "action": "warn"},
        headers=headers,
    )
    assert updated.status_code == 200, updated.text
    versions = auth_client.get(f"/policies/{policy_id}/versions", headers=headers)
    assert [item["version"] for item in versions.json()] == [1, 2]
    assert versions.json()[0]["snapshot"]["name"] == "first"
    difference = auth_client.get(
        f"/policies/{policy_id}/diff?from_version=1&to_version=2", headers=headers
    )
    assert difference.status_code == 200
    assert sorted(difference.json()["changes"], key=lambda item: item["path"]) == [
        {"path": "action", "before": "block", "after": "warn"},
        {"path": "name", "before": "first", "after": "second"},
    ]
    rolled_back = auth_client.post(
        f"/policies/{policy_id}/rollback",
        json={"target_version": 1},
        headers=headers,
    )
    assert rolled_back.status_code == 200, rolled_back.text
    assert rolled_back.json()["version"] == 3
    assert rolled_back.json()["action"] == "block"

    before_count = len(auth_client.get(f"/policies/{policy_id}/versions", headers=headers).json())
    sandbox = auth_client.post(
        "/policies/test",
        json={
            "policy": {"name": "draft", "conditions": {"channel": "api"}, "action": "warn"},
            "sample": {"channel": "api", "content": "do-not-store", "findings": []},
        },
        headers=headers,
    )
    assert sandbox.status_code == 200, sandbox.text
    assert sandbox.json()["decision"] == "warn"
    assert sandbox.json()["evaluation_mode"] == "sandbox"
    assert "do-not-store" not in sandbox.text
    historical = auth_client.post(
        f"/policies/{policy_id}/versions/1/test",
        json={"channel": "api", "content": "historical-private", "findings": []},
        headers=headers,
    )
    assert historical.status_code == 200, historical.text
    assert historical.json()["decision"] == "block"
    assert historical.json()["evaluation_mode"] == "historical"
    assert "historical-private" not in historical.text
    assert (
        len(auth_client.get(f"/policies/{policy_id}/versions", headers=headers).json())
        == before_count
    )


def test_exceptions_and_suppressions_are_expiring_scoped_admin_resources(auth_client) -> None:
    prepare_tables(auth_client)
    headers = auth_headers()
    created_policy = auth_client.post(
        "/policies",
        json={"name": "block API", "conditions": {"channel": "api"}, "action": "block"},
        headers=headers,
    )
    assert created_policy.status_code == 201, created_policy.text
    expires = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    exception = auth_client.post(
        "/exceptions",
        json={
            "policy_id": created_policy.json()["policy_id"],
            "scope": {"channel": "api"},
            "reason": "approved temporary exception",
            "expires_at": expires,
        },
        headers=headers,
    )
    assert exception.status_code == 201, exception.text
    assert (
        auth_client.get("/audit/events?action=exception.created", headers=headers).json()[0][
            "resource_id"
        ]
        == exception.json()["exception_id"]
    )
    assert exception.json()["approver_id"] == exception.json()["created_by"]
    assert (
        auth_client.get("/exceptions", headers=headers).json()[0]["exception_id"]
        == exception.json()["exception_id"]
    )
    assert (
        auth_client.delete(
            f"/exceptions/{exception.json()['exception_id']}", headers=headers
        ).status_code
        == 204
    )
    assert (
        auth_client.get("/audit/events?action=exception.deleted", headers=headers).status_code
        == 200
    )
    assert (
        auth_client.get(f"/exceptions/{exception.json()['exception_id']}", headers=headers).json()[
            "enabled"
        ]
        is False
    )

    suppression = auth_client.post(
        "/suppressions",
        json={
            "match": {"fingerprint": "a" * 64},
            "reason": "approved false positive",
            "expires_at": expires,
        },
        headers=headers,
    )
    assert suppression.status_code == 201, suppression.text
    assert (
        auth_client.get("/audit/events?action=suppression.created", headers=headers).json()[0][
            "resource_id"
        ]
        == suppression.json()["suppression_id"]
    )
    assert auth_client.get("/suppressions", headers=headers).json()[0]["match"] == {
        "fingerprint": "a" * 64
    }
    assert (
        auth_client.delete(
            f"/suppressions/{suppression.json()['suppression_id']}", headers=headers
        ).status_code
        == 204
    )
    assert (
        auth_client.get(
            f"/suppressions/{suppression.json()['suppression_id']}", headers=headers
        ).json()["enabled"]
        is False
    )

    tenant_b = auth_headers(signed_token(subject="user-owner-b", organization_id=ORG_B))
    created_b_key = auth_client.post(
        "/api-keys",
        json={"name": "P06 tenant reader", "scopes": ["identity:read"]},
        headers=tenant_b,
    )
    assert created_b_key.status_code == 201
    tenant_b_key = auth_headers(created_b_key.json()["key"])
    assert auth_client.get("/exceptions", headers=tenant_b_key).json() == []
    assert auth_client.get("/suppressions", headers=tenant_b_key).json() == []
    assert (
        auth_client.get(
            f"/exceptions/{exception.json()['exception_id']}", headers=tenant_b_key
        ).status_code
        == 404
    )

    analyst = auth_headers(signed_token(subject="user-analyst-a"))
    denied = auth_client.post(
        "/exceptions",
        json={
            "policy_id": created_policy.json()["policy_id"],
            "scope": {"channel": "api"},
            "reason": "unauthorized",
            "expires_at": expires,
        },
        headers=analyst,
    )
    assert denied.status_code == 403
