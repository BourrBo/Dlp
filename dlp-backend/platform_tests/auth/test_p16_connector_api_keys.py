"""P16 connector read routes use the established API-key scope/revocation checks."""

from datetime import UTC, datetime
from uuid import uuid4

from dlp_platform.routes import connectors
from dlp_platform.tables import DLP_CONNECTORS
from platform_tests.auth.conftest import ORG_A
from platform_tests.auth.helpers import auth_headers
from platform_tests.auth.test_api_keys import create_key


def test_p16_connector_api_key_read_scope_invalid_and_revoked_cases(auth_client) -> None:
    engine = auth_client.app.state.test_session_factory.kw["bind"]
    DLP_CONNECTORS.create(engine, checkfirst=True)

    read_key = create_key(auth_client, scopes=["connectors:read"]).json()
    no_scope_key = create_key(auth_client, scopes=["identity:read"]).json()
    revoked_key = create_key(auth_client, scopes=["connectors:read"]).json()
    assert (
        auth_client.delete(f"/api-keys/{revoked_key['id']}", headers=auth_headers()).status_code
        == 204
    )

    connector_id = uuid4()
    now = datetime.now(UTC)
    with engine.begin() as connection:
        connection.execute(
            DLP_CONNECTORS.insert().values(
                id=str(connector_id),
                org_id=str(ORG_A),
                provider="google_drive",
                name="API-key read fixture",
                status="disconnected",
                credential_secret_id=None,
                config_json={},
                last_sync_at=None,
                last_error_code=None,
                created_at=now,
                updated_at=now,
            )
        )

    own_read = auth_client.get("/connectors", headers=auth_headers(read_key["key"]))
    own_status = auth_client.get(
        f"/connectors/{connector_id}", headers=auth_headers(read_key["key"])
    )
    missing_status_scope = auth_client.get(
        f"/connectors/{connector_id}", headers=auth_headers(no_scope_key["key"])
    )
    missing_scope = auth_client.get("/connectors", headers=auth_headers(no_scope_key["key"]))
    revoked = auth_client.get("/connectors", headers=auth_headers(revoked_key["key"]))
    revoked_status = auth_client.get(
        f"/connectors/{connector_id}", headers=auth_headers(revoked_key["key"])
    )
    invalid = auth_client.get(
        "/connectors",
        headers=auth_headers(
            "dlp_000000000000.invalid-secret-value-0000000000000000000000000000000000000000"
        ),
    )
    assert own_read.status_code == 200
    assert own_status.status_code == 200
    assert own_status.json()["identity"]["connector_id"] == str(connector_id)
    assert missing_scope.status_code == 403
    assert missing_status_scope.status_code == 403
    assert revoked.status_code == 401
    assert revoked_status.status_code == 401
    assert invalid.status_code == 401


def test_p16_connector_write_api_key_is_not_an_interactive_user(auth_client) -> None:
    engine = auth_client.app.state.test_session_factory.kw["bind"]
    DLP_CONNECTORS.create(engine, checkfirst=True)
    auth_client.app.dependency_overrides[connectors._vault] = lambda: object()
    key = create_key(auth_client, scopes=["connectors:write"]).json()
    response = auth_client.post(
        f"/connectors/{uuid4()}/disconnect",
        headers=auth_headers(key["key"]),
    )
    assert response.status_code == 403
