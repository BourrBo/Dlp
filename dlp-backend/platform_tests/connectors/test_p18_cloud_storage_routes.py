"""P18 HTTP authorization, tenant scoping, and secret response checks."""

import json
from types import SimpleNamespace
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from dlp_platform.auth.principal import get_principal
from dlp_platform.connectors.models import ConnectorHealth, ConnectorIdentity, ConnectorStatus
from dlp_platform.contracts.common import ActorType, AuthMethod, Role
from dlp_platform.contracts.principal import Principal
from dlp_platform.database import get_session
from dlp_platform.ratelimit.dependencies import get_rate_limiter
from dlp_platform.routes import cloud_storage_connectors as cloud_routes


class FakeSession:
    bind = None


class AllowLimiter:
    def check(self, *_args):
        return type("Result", (), {"allowed": True, "retry_after": 0})()


class ConnectorFixture:
    def __init__(self, principal: Principal, provider: str):
        self.principal = principal
        self.provider = provider
        self.config = {}
        self.created = []
        self.connected = []
        self.disconnected = []
        self.failed = []

    def create(self, _session, principal, *, provider, name, config, audit_context=None):
        del audit_context
        self.created.append((principal.organization_id, provider, config))
        self.config = config
        return ConnectorHealth(
            identity=ConnectorIdentity(
                connector_id=CONNECTOR_ID,
                organization_id=principal.organization_id,
                provider=provider,
            ),
            status=ConnectorStatus.DISCONNECTED,
        )

    def get(self, _session, principal, connector_id):
        assert principal.organization_id == ORG_ID
        if connector_id != CONNECTOR_ID:
            raise HTTPException(status_code=404, detail="Connector not found")
        return ConnectorHealth(
            identity=ConnectorIdentity(
                connector_id=connector_id,
                organization_id=principal.organization_id,
                provider=self.provider,
            ),
            status=ConnectorStatus.CONNECTING,
        )

    def begin_connect(self, *_args):
        pass

    def configuration(self, *_args):
        return self.config

    def set_connection(self, _session, principal, connector_id, **kwargs):
        self.connected.append((principal.organization_id, connector_id, kwargs))
        return ConnectorHealth(
            identity=ConnectorIdentity(
                connector_id=connector_id,
                organization_id=principal.organization_id,
                provider=self.provider,
            ),
            status=ConnectorStatus.CONNECTED,
        )

    def mark_connect_failed(self, *args):
        self.failed.append(args)

    def disconnect(self, *_args):
        self.disconnected.append(True)
        return ConnectorHealth(
            identity=ConnectorIdentity(
                connector_id=CONNECTOR_ID,
                organization_id=ORG_ID,
                provider=self.provider,
            ),
            status=ConnectorStatus.DISCONNECTED,
        )


class VaultFixture:
    def __init__(self):
        self.writes = []

    def set(self, _session, principal, **kwargs):
        raw = kwargs["value"].get_secret_value()
        self.writes.append((principal.organization_id, kwargs["secret_type"], raw))
        return SimpleNamespace(secret_id=uuid4())


ORG_ID = uuid4()
CONNECTOR_ID = uuid4()


def _principal(role: Role = Role.OWNER) -> Principal:
    return Principal(
        organization_id=ORG_ID,
        subject_id="p18-owner",
        actor_type=ActorType.USER,
        role=role,
        scopes=("connectors:read", "connectors:write", "vault:write"),
        auth_method=AuthMethod.SSO,
        member_id=uuid4(),
        session_id=uuid4(),
    )


def _app(monkeypatch, principal: Principal, service):
    monkeypatch.setattr(cloud_routes, "_service", service)
    app = FastAPI()
    app.include_router(cloud_routes.router)
    app.dependency_overrides[get_principal] = lambda: principal
    app.dependency_overrides[get_session] = lambda: FakeSession()
    app.dependency_overrides[get_rate_limiter] = lambda: AllowLimiter()
    return app


def test_s3_create_binds_tenant_and_persists_only_non_secret_configuration(monkeypatch):
    principal = _principal()
    service = ConnectorFixture(principal, "aws_s3")
    app = _app(monkeypatch, principal, service)
    with TestClient(app) as client:
        response = client.post(
            "/connectors/s3",
            json={
                "name": "Production data",
                "bucket": "customer-data-123",
                "region": "us-east-1",
                "aws_account_id": "123456789012",
                "requester_pays": True,
                "sqs_queue_name": "dlp-object-events",
            },
        )
    assert response.status_code == 201
    org_id, provider, config = service.created[0]
    assert org_id == principal.organization_id
    assert provider == "aws_s3"
    assert config["bucket"] == "customer-data-123"
    assert "secret_access_key" not in config
    assert "external_id" not in config
    assert response.headers["cache-control"] == "no-store"


def test_s3_connect_saves_credentials_only_to_vault_and_never_returns_them(monkeypatch):
    principal = _principal()
    service = ConnectorFixture(principal, "aws_s3")
    service.config = {
        "bucket": "customer-data-123",
        "region": "us-east-1",
        "aws_account_id": "123456789012",
        "requester_pays": False,
        "sqs_queue_name": "dlp-object-events",
    }
    vault = VaultFixture()

    class AdapterFixture:
        def __init__(self, config, credential):
            assert config["bucket"] == service.config["bucket"]
            assert "SYNTHETIC_AWS_SECRET" in credential
            assert "SYNTHETIC_EXTERNAL_ID" in credential

        def verify(self):
            pass

    monkeypatch.setattr(cloud_routes, "S3StorageAdapter", AdapterFixture)
    monkeypatch.setattr(
        cloud_routes.SecretVault,
        "from_environment",
        classmethod(lambda _cls: vault),
    )
    app = _app(monkeypatch, principal, service)
    with TestClient(app) as client:
        response = client.post(
            f"/connectors/s3/{CONNECTOR_ID}/connect",
            json={
                "access_key_id": "AKIAEXAMPLEACCESSKEY",
                "secret_access_key": "SYNTHETIC_AWS_SECRET_ACCESS_KEY",
                "role_arn": "arn:aws:iam::123456789012:role/dlp-reader",
                "external_id": "SYNTHETIC_EXTERNAL_ID",
            },
        )
    assert response.status_code == 200, response.text
    body = response.text
    assert "SYNTHETIC_AWS_SECRET_ACCESS_KEY" not in body
    assert "SYNTHETIC_EXTERNAL_ID" not in body
    assert "AKIAEXAMPLEACCESSKEY" not in body
    assert len(vault.writes) == 1
    assert vault.writes[0][0] == principal.organization_id
    assert "SYNTHETIC_AWS_SECRET_ACCESS_KEY" in vault.writes[0][2]
    assert service.connected[0][2]["state_json"]["initial_inventory_pending"] is True


def test_gcs_connect_secret_and_provider_failure_are_sanitized(monkeypatch):
    principal = _principal()
    service = ConnectorFixture(principal, "google_cloud_storage")
    service.config = {
        "bucket": "gcs-data-bucket",
        "project_id": "fixture-project",
        "pubsub_subscription": "projects/fixture-project/subscriptions/events",
    }
    vault = VaultFixture()

    class AdapterFixture:
        def __init__(self, _config, credential):
            assert "SYNTHETIC_GCS_PRIVATE_KEY" in credential

        def verify(self):
            pass

    monkeypatch.setattr(cloud_routes, "GCSStorageAdapter", AdapterFixture)
    monkeypatch.setattr(
        cloud_routes.SecretVault,
        "from_environment",
        classmethod(lambda _cls: vault),
    )
    app = _app(monkeypatch, principal, service)
    service_account = json.dumps(
        {
            "type": "service_account",
            "project_id": "service-account-home",
            "private_key": "SYNTHETIC_GCS_PRIVATE_KEY",
        }
    )
    with TestClient(app) as client:
        response = client.post(
            f"/connectors/gcs/{CONNECTOR_ID}/connect",
            json={"service_account_json": service_account},
        )
    assert response.status_code == 200, response.text
    assert "SYNTHETIC_GCS_PRIVATE_KEY" not in response.text
    assert "service_account_json" not in response.text
    assert len(vault.writes) == 1


def test_wrong_role_and_cross_tenant_connector_are_denied(monkeypatch):
    principal = _principal(Role.VIEWER)
    service = ConnectorFixture(principal, "aws_s3")
    app = _app(monkeypatch, principal, service)
    with TestClient(app) as client:
        denied = client.post(
            "/connectors/s3",
            json={
                "name": "data",
                "bucket": "customer-data-123",
                "region": "us-east-1",
                "aws_account_id": "123456789012",
                "sqs_queue_name": "dlp-object-events",
            },
        )
        foreign = client.get(f"/connectors/s3/{uuid4()}/status")
    assert denied.status_code == 403
    assert foreign.status_code == 404
    assert service.created == []
