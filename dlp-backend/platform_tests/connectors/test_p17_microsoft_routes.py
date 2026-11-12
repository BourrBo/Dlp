"""Tenant authorization and configuration checks for P17 HTTP routes."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID, uuid4

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from dlp_platform.auth.principal import get_principal
from dlp_platform.connectors import oauth
from dlp_platform.connectors.models import ConnectorHealth, ConnectorIdentity, ConnectorStatus
from dlp_platform.contracts.common import ActorType, AuthMethod, Role
from dlp_platform.contracts.principal import Principal
from dlp_platform.database import get_session
from dlp_platform.ratelimit.dependencies import get_rate_limiter
from dlp_platform.routes import connectors, microsoft_connectors
from dlp_platform.vault.models import SecretType


class FakeSession:
    bind = None


class AllowLimiter:
    def check(self, *_args):
        return type("Result", (), {"allowed": True, "retry_after": 0})()


class CallbackSession:
    bind = None

    def execute(self, _statement):
        return SimpleNamespace(scalar_one_or_none=lambda: "active-member")

    def rollback(self):
        pass


def _principal(organization_id: UUID) -> Principal:
    return Principal(
        organization_id=organization_id,
        subject_id="p17-owner",
        actor_type=ActorType.USER,
        role=Role.OWNER,
        scopes=("connectors:read", "connectors:write"),
        auth_method=AuthMethod.SSO,
        member_id=uuid4(),
        session_id=uuid4(),
    )


def test_sharepoint_site_search_hides_foreign_connector(monkeypatch):
    organization_id, foreign_connector_id = uuid4(), uuid4()
    principal = _principal(organization_id)
    lookups: list[tuple[UUID, UUID]] = []

    class TenantService:
        def get(self, _session, current_principal, connector_id):
            lookups.append((current_principal.organization_id, connector_id))
            assert current_principal.organization_id == organization_id
            assert connector_id == foreign_connector_id
            raise HTTPException(status_code=404, detail="Connector not found")

    monkeypatch.setattr(microsoft_connectors, "_service", TenantService())
    app = FastAPI()
    app.include_router(microsoft_connectors.router)
    app.dependency_overrides[get_principal] = lambda: principal
    app.dependency_overrides[get_session] = lambda: FakeSession()
    app.dependency_overrides[get_rate_limiter] = lambda: AllowLimiter()
    with TestClient(app) as client:
        response = client.post(
            f"/connectors/{foreign_connector_id}/microsoft/sites/search",
            json={"query": "Finance"},
        )
    assert response.status_code == 404
    assert response.json() == {"detail": "Connector not found"}
    assert lookups == [(organization_id, foreign_connector_id)]


def test_microsoft_connector_creation_requires_tenant_guid(monkeypatch):
    principal = _principal(uuid4())

    class NoCreateService:
        def create(self, *_args, **_kwargs):
            raise AssertionError("invalid tenant configuration reached persistence")

    monkeypatch.setattr(connectors, "_service", NoCreateService())
    app = FastAPI()
    app.include_router(connectors.router)
    app.dependency_overrides[get_principal] = lambda: principal
    app.dependency_overrides[get_session] = lambda: FakeSession()
    app.dependency_overrides[get_rate_limiter] = lambda: AllowLimiter()
    with TestClient(app) as client:
        response = client.post(
            "/connectors", json={"provider": "microsoft_onedrive", "name": "Finance"}
        )
    assert response.status_code == 422


def _callback_client(monkeypatch, *, graph_tenant: str):
    principal = _principal(uuid4())
    connector_id, tenant_id = uuid4(), str(uuid4())
    transaction = oauth.OAuthTransaction(
        state="fixture-state",
        verifier="fixture-pkce-verifier",
        organization_id=principal.organization_id,
        principal_id=principal.subject_id,
        binding_id=str(connector_id),
        role=principal.role,
        member_id=principal.member_id,
        session_id=principal.session_id,
        scopes=principal.scopes,
        auth_method=principal.auth_method,
        provider="microsoft_graph",
        redirect_uri="https://dlp.example.test/connectors/oauth/microsoft/callback",
        expires_at=(datetime.now(UTC) + timedelta(minutes=5)).timestamp(),
    )

    class Transactions:
        consumed = False

        def consume_callback(self, _session, state, *, provider):
            if self.consumed or state != transaction.state or provider != "microsoft_graph":
                raise oauth.OAuthRejected("invalid state")
            self.consumed = True
            return transaction

    class Service:
        def __init__(self):
            self.connected = []
            self.failed = []

        def get(self, _session, _principal, requested_id):
            assert requested_id == connector_id
            return ConnectorHealth(
                identity=ConnectorIdentity(
                    connector_id=connector_id,
                    organization_id=principal.organization_id,
                    provider="microsoft_onedrive",
                ),
                status=ConnectorStatus.CONNECTING,
            )

        def configuration(self, *_args):
            return {"microsoft_tenant_id": tenant_id}

        def set_connection(self, *args, **kwargs):
            self.connected.append((args, kwargs))

        def mark_connect_failed(self, *args, **kwargs):
            self.failed.append((args, kwargs))

    class OAuthClient:
        def __init__(self):
            self.calls = []

        def exchange(self, code, verifier, redirect_uri, requested_tenant):
            self.calls.append((code, verifier, redirect_uri, requested_tenant))
            return {
                "access_token": "P17_FIXTURE_ACCESS_TOKEN",
                "refresh_token": "P17_FIXTURE_REFRESH_TOKEN",
                "token_type": "Bearer",
                "scope": "User.Read Files.ReadWrite.All",
            }

    class GraphAPI:
        def __init__(self, token, requested_tenant):
            assert token == "P17_FIXTURE_ACCESS_TOKEN"
            assert requested_tenant == tenant_id

        def organization_tenant_id(self):
            return graph_tenant or tenant_id

        def onedrive_id(self):
            return "fixture-drive-id"

    class Vault:
        def __init__(self):
            self.writes = []

        def set(self, session, actual_principal, **kwargs):
            del session
            assert actual_principal is not None
            assert kwargs["secret_type"] is SecretType.REFRESH_TOKEN
            assert kwargs["value"].get_secret_value() == "P17_FIXTURE_REFRESH_TOKEN"
            self.writes.append(kwargs)
            return SimpleNamespace(secret_id=uuid4())

    service, provider, vault = Service(), OAuthClient(), Vault()
    monkeypatch.setattr(microsoft_connectors, "_transactions", Transactions())
    monkeypatch.setattr(microsoft_connectors, "_service", service)
    monkeypatch.setattr(
        microsoft_connectors,
        "_settings",
        lambda: (SimpleNamespace(), provider),
    )
    monkeypatch.setattr(microsoft_connectors, "MicrosoftGraphAPI", GraphAPI)
    monkeypatch.setattr(
        microsoft_connectors.SecretVault,
        "from_environment",
        classmethod(lambda _cls: vault),
    )
    app = FastAPI()
    app.include_router(microsoft_connectors.router)
    app.dependency_overrides[get_session] = lambda: CallbackSession()
    app.dependency_overrides[get_rate_limiter] = lambda: AllowLimiter()
    return app, principal, connector_id, tenant_id, provider, vault, service


def test_microsoft_oauth_callback_saves_only_after_tenant_verification(monkeypatch):
    app, _principal_value, connector_id, _tenant_id, provider, vault, service = _callback_client(
        monkeypatch, graph_tenant=""
    )
    with TestClient(app) as client:
        response = client.get(
            "/connectors/oauth/microsoft/callback",
            params={"state": "fixture-state", "code": "P17_FIXTURE_CODE"},
            follow_redirects=False,
        )
        replay = client.get(
            "/connectors/oauth/microsoft/callback",
            params={"state": "fixture-state", "code": "P17_FIXTURE_CODE"},
            follow_redirects=False,
        )
    assert response.status_code == 303
    assert replay.status_code == 400
    assert provider.calls[0][1] == "fixture-pkce-verifier"
    assert len(vault.writes) == 1
    assert len(service.connected) == 1
    for marker in (
        "P17_FIXTURE_ACCESS_TOKEN",
        "P17_FIXTURE_REFRESH_TOKEN",
        "P17_FIXTURE_CODE",
    ):
        assert marker not in response.text


def test_microsoft_oauth_callback_rejects_unknown_state_without_vault_write(monkeypatch):
    app, _principal_value, _connector_id, _tenant_id, _provider, vault, service = _callback_client(
        monkeypatch, graph_tenant=""
    )
    with TestClient(app) as client:
        response = client.get(
            "/connectors/oauth/microsoft/callback",
            params={"state": "tampered-state", "code": "P17_FIXTURE_CODE"},
            follow_redirects=False,
        )
    assert response.status_code == 400
    assert vault.writes == []
    assert service.connected == []


def test_microsoft_oauth_callback_tenant_mismatch_never_writes_vault(monkeypatch):
    app, _principal_value, _connector_id, tenant_id, provider, vault, service = _callback_client(
        monkeypatch, graph_tenant=str(uuid4())
    )
    with TestClient(app) as client:
        response = client.get(
            "/connectors/oauth/microsoft/callback",
            params={"state": "fixture-state", "code": "P17_FIXTURE_CODE"},
            follow_redirects=False,
        )
    assert response.status_code == 400
    assert "P17_FIXTURE_ACCESS_TOKEN" not in response.text
    assert "P17_FIXTURE_REFRESH_TOKEN" not in response.text
    assert provider.calls[0][3] == tenant_id
    assert vault.writes == []
    assert service.connected == []
    assert service.failed
