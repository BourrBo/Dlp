"""Exercise the existing scan, policy, P07 approval and connector action boundaries."""

import json
from dataclasses import replace
from datetime import UTC, datetime
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import dlp_platform.scan.pipeline as scan_pipeline
from dlp_platform.actions.interfaces import UnavailableActionExecutor
from dlp_platform.actions.service import ActionProcessor
from dlp_platform.auth.principal import get_principal
from dlp_platform.connectors import action_executor as connector_executor_module
from dlp_platform.connectors.action_executor import GoogleDriveActionExecutor
from dlp_platform.connectors.google_drive import GoogleDriveAPI as RealGoogleDriveAPI
from dlp_platform.connectors.models import DriveObject
from dlp_platform.connectors.service import ConnectorOperationFailed
from dlp_platform.contracts.common import ActorType, AuthMethod, DataChannel, PolicyAction, Role
from dlp_platform.contracts.policy import Policy
from dlp_platform.contracts.principal import Principal
from dlp_platform.contracts.scan_request import ScanRequest
from dlp_platform.database import get_session
from dlp_platform.policy.engine import PolicyEngine
from dlp_platform.ratelimit.dependencies import get_rate_limiter
from dlp_platform.routes import approvals, connectors
from dlp_platform.scan.idempotency import InMemoryIdempotencyStore
from dlp_platform.scan.pipeline import configure_action_processor, configure_pipeline, fake_stages
from dlp_platform.tables import ACTIONS, APPROVALS, AUDIT_EVENTS, MEMBERS, ORGANIZATIONS, metadata


class AllowLimiter:
    def check(self, *args):
        del args
        return type("RateResult", (), {"allowed": True, "retry_after": 0})()


class ExposurePolicy:
    def __init__(self, organization_id):
        self.policy = Policy(
            policy_id=uuid4(),
            organization_id=organization_id,
            name="Revoke reviewed exposed share",
            enabled=True,
            priority=1,
            conditions={},
            action=PolicyAction.REVOKE_SHARE,
            version=1,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        self.engine = PolicyEngine()
        self.decisions = []

    def evaluate(self, findings, request, principal):
        decision = self.engine.evaluate(
            organization_id=principal.organization_id,
            request=request,
            principal=principal,
            findings=findings,
            policies=(self.policy,),
            destinations=(),
        )
        self.decisions.append((request, principal, decision))
        return decision


def test_drive_metadata_flows_through_scan_policy_p07_and_approved_drive_action(monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    metadata.create_all(
        engine,
        tables=[ORGANIZATIONS, MEMBERS, ACTIONS, APPROVALS, AUDIT_EVENTS],
    )
    organization_id = uuid4()
    requester_id, approver_id = uuid4(), uuid4()
    connector_id = uuid4()
    now = datetime.now(UTC)
    owner = Principal(
        organization_id=organization_id,
        subject_id="p16-owner",
        actor_type=ActorType.USER,
        role=Role.OWNER,
        scopes=("scan:request", "approvals:decide", "identity:read", "connectors:write"),
        auth_method=AuthMethod.SSO,
        member_id=requester_id,
    )
    admin = Principal(
        organization_id=organization_id,
        subject_id="p16-admin",
        actor_type=ActorType.USER,
        role=Role.ADMIN,
        scopes=("scan:request", "approvals:decide", "identity:read"),
        auth_method=AuthMethod.SSO,
        member_id=approver_id,
    )
    with engine.begin() as connection:
        connection.execute(
            ORGANIZATIONS.insert().values(
                id=str(organization_id),
                name="P16 action fixture",
                settings_json={},
                created_at=now,
                updated_at=now,
            )
        )
        connection.execute(
            MEMBERS.insert(),
            [
                {
                    "id": str(requester_id),
                    "organization_id": str(organization_id),
                    "auth_subject_id": owner.subject_id,
                    "role": Role.OWNER.value,
                    "active": True,
                    "created_at": now,
                },
                {
                    "id": str(approver_id),
                    "organization_id": str(organization_id),
                    "auth_subject_id": admin.subject_id,
                    "role": Role.ADMIN.value,
                    "active": True,
                    "created_at": now,
                },
            ],
        )

    factory = sessionmaker(bind=engine, expire_on_commit=False)
    provider_calls = []
    credential_secret_id = uuid4()

    class QueryResult:
        def scalar_one_or_none(self):
            return str(credential_secret_id)

    class ConnectorSession:
        def __init__(self, _engine):
            self.claims = None

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, statement, params=None):
            if params and "claims" in params:
                import json

                self.claims = json.loads(params["claims"])
            if "credential_secret_id" in str(statement):
                return QueryResult()
            return QueryResult()

    class ConnectorVault:
        def get_for_trusted_service(self, session, org_id, secret_id, *, allowed_types):
            assert session.claims["org_id"] == str(org_id)
            assert secret_id == credential_secret_id
            assert {item.value for item in allowed_types} == {"refresh_token"}
            return SecretStr("TEST_REFRESH_TOKEN_DO_NOT_LEAK")

    class SyncVault:
        def get_for_trusted_service(self, _session, org_id, secret_id, *, allowed_types):
            assert org_id == organization_id
            assert secret_id == credential_secret_id
            assert {item.value for item in allowed_types} == {"refresh_token"}
            return SecretStr("TEST_REFRESH_TOKEN_DO_NOT_LEAK")

    class SyncService:
        def __init__(self):
            self.completed = []
            self.complete_attempts = 0

        def sync_inputs(self, _session, principal, requested_connector_id):
            assert principal.organization_id == organization_id
            assert requested_connector_id == connector_id
            return credential_secret_id, "checkpoint-before", {}

        def _rls(self, _session, _principal):
            pass

        def complete_sync(self, _session, principal, requested_connector_id, **kwargs):
            self.complete_attempts += 1
            assert requested_connector_id == connector_id
            assert principal.organization_id == organization_id
            if self.complete_attempts == 1:
                raise ConnectorOperationFailed("fixture checkpoint persistence failure")
            self.completed.append(kwargs["checkpoint"])

        def mark_degraded(self, *_args, **_kwargs):
            pass

    class FixtureOAuth:
        def __init__(self, settings, transport):
            del settings, transport

        def refresh(self, refresh_token):
            assert refresh_token == "TEST_REFRESH_TOKEN_DO_NOT_LEAK"
            return {"access_token": "TEST_ACCESS_TOKEN_DO_NOT_LEAK"}

    class FixtureDrive:
        def __init__(self, access_token):
            assert access_token == "TEST_ACCESS_TOKEN_DO_NOT_LEAK"

        def revoke_share(self, revocation):
            provider_calls.append((revocation.object_id, revocation.permission_id))
            return type("ProviderResult", (), {"succeeded": True, "outcome": "revoked"})()

    feed_requests = []

    class ChangeFeedTransport:
        def request(self, method, url, *, headers, body=None, max_bytes=2_000_000):
            del headers, body, max_bytes
            assert method == "GET"
            assert "/changes?" in url
            feed_requests.append(url)
            return json.dumps(
                {
                    "changes": [
                        {
                            "fileId": "drive-file-safe-id",
                            "removed": False,
                            "file": {
                                "id": "drive-file-safe-id",
                                "name": "Synthetic exposed.txt",
                                "mimeType": "text/plain",
                                "permissions": [
                                    {
                                        "id": "drive-permission-safe-id",
                                        "type": "anyone",
                                        "role": "reader",
                                        "allowFileDiscovery": False,
                                    }
                                ],
                            },
                        }
                    ],
                    "newStartPageToken": "checkpoint-after",
                }
            ).encode()

    class ChangeFeedDrive(RealGoogleDriveAPI):
        def __init__(self, access_token):
            super().__init__(access_token, ChangeFeedTransport())

    monkeypatch.setattr(connector_executor_module, "Session", ConnectorSession)
    monkeypatch.setattr(
        connector_executor_module.SecretVault,
        "from_environment",
        classmethod(lambda _cls: ConnectorVault()),
    )
    monkeypatch.setattr(
        connector_executor_module.GoogleOAuthSettings,
        "from_environment",
        classmethod(lambda _cls: object()),
    )
    monkeypatch.setattr(connector_executor_module, "GoogleOAuthClient", FixtureOAuth)
    monkeypatch.setattr(connector_executor_module, "GoogleDriveAPI", FixtureDrive)
    executor = GoogleDriveActionExecutor.__new__(GoogleDriveActionExecutor)
    executor.engine = engine
    policy = ExposurePolicy(organization_id)
    processor = ActionProcessor(engine, executor=executor)
    monkeypatch.setattr(scan_pipeline, "_action_processor", None)
    monkeypatch.setattr(scan_pipeline, "_default_pipeline", None)
    configure_action_processor(processor)
    configure_pipeline(
        replace(fake_stages(), policy=policy),
        InMemoryIdempotencyStore(),
    )
    current_principal = {"value": owner}
    api = FastAPI()
    api.include_router(approvals.router)
    api.include_router(connectors.router)
    api.dependency_overrides[get_principal] = lambda: current_principal["value"]
    api.dependency_overrides[get_session] = lambda: factory()
    api.dependency_overrides[get_rate_limiter] = lambda: AllowLimiter()
    api.dependency_overrides[connectors._vault] = lambda: SyncVault()
    sync_service = SyncService()
    monkeypatch.setattr(connectors, "_service", sync_service)
    monkeypatch.setattr(connectors, "_oauth", lambda: (None, FixtureOAuth(None, None)))
    monkeypatch.setattr(connectors, "GoogleDriveAPI", ChangeFeedDrive)
    configure_approval = approvals.configure_action_executor
    configure_approval(executor)
    try:
        forged_request = ScanRequest(
            channel=DataChannel.CLOUD_STORAGE,
            content=SecretStr("client controlled metadata"),
            context={
                "provider": "google_drive",
                "organization_id": str(organization_id),
                "connector_id": str(connector_id),
                "drive_object_id": "forged-file-id",
                "permission_id": "forged-permission-id",
            },
        )
        forged_result = connectors.scan(forged_request, owner)
        assert forged_result.decision is PolicyAction.REVOKE_SHARE
        assert "P07 action status=failed" in forged_result.reason
        assert provider_calls == []
        with factory() as session:
            assert session.execute(ACTIONS.select()).mappings().all() == []

        with TestClient(api) as client:
            pending_sync = client.post(f"/connectors/{connector_id}/sync")
        assert pending_sync.status_code == 503
        assert len(feed_requests) == 1
        assert "pageToken=checkpoint-before" in feed_requests[0]
        assert policy.decisions[-1][1] is owner
        normalized_request = policy.decisions[-1][0]
        assert normalized_request.context["organization_id"] == str(organization_id)
        assert normalized_request.context["connector_id"] == str(connector_id)
        assert normalized_request.context["drive_object_id"] == "drive-file-safe-id"
        assert "TEST_REFRESH_TOKEN_DO_NOT_LEAK" not in normalized_request.model_dump_json()
        with factory() as session:
            pending_action = session.execute(ACTIONS.select()).mappings().one()
            pending_approval = session.execute(APPROVALS.select()).mappings().one()
            first = {
                "request_id": pending_action["request_id"],
                "approval_id": pending_approval["id"],
                "decision": pending_action["action"],
                "action_status": pending_action["status"],
            }
        assert first["decision"] == PolicyAction.REVOKE_SHARE.value
        assert first["decision"] == PolicyAction.REVOKE_SHARE.value
        assert first["action_status"] == "pending_approval"
        assert first["approval_id"]
        assert provider_calls == []
        with factory() as session:
            pending = (
                session.execute(APPROVALS.select().where(APPROVALS.c.id == first["approval_id"]))
                .mappings()
                .one()
            )
            action = (
                session.execute(ACTIONS.select().where(ACTIONS.c.id == pending["action_id"]))
                .mappings()
                .one()
            )
            assert pending["status"] == "pending"
            assert action["status"] == "pending_approval"
            assert action["metadata"] == {
                "provider": "google_drive",
                "connector_id": str(connector_id),
                "drive_object_id": "drive-file-safe-id",
                "permission_id": "drive-permission-safe-id",
                "organization_id": str(organization_id),
                "policy_id": str(policy.policy.policy_id),
                "policy_version": "1",
            }

        with TestClient(api) as client:
            current_principal["value"] = Principal(
                organization_id=uuid4(),
                subject_id="foreign-approver",
                actor_type=ActorType.USER,
                role=Role.ADMIN,
                scopes=("approvals:decide", "identity:read"),
                auth_method=AuthMethod.SSO,
                member_id=uuid4(),
            )
            foreign = client.post(f"/approvals/{first['approval_id']}/approve", json={})
            assert foreign.status_code == 404
            current_principal["value"] = owner
            self_approval = client.post(f"/approvals/{first['approval_id']}/approve", json={})
            assert self_approval.status_code == 403
            assert provider_calls == []
            current_principal["value"] = admin
            approved = client.post(f"/approvals/{first['approval_id']}/approve", json={})
        assert approved.status_code == 200, approved.text
        assert approved.json()["status"] == "approved"
        assert approved.json()["action_status"] == "succeeded"
        for marker in (
            "TEST_ACCESS_TOKEN_DO_NOT_LEAK",
            "TEST_REFRESH_TOKEN_DO_NOT_LEAK",
            "TEST_OAUTH_CODE_DO_NOT_LEAK",
            "TEST_CLIENT_SECRET_DO_NOT_LEAK",
        ):
            assert marker not in approved.text
        assert provider_calls == [("drive-file-safe-id", "drive-permission-safe-id")]
        # The change feed remains at its old cursor until scan/action completion.
        # First simulate a checkpoint persistence failure after the approved provider
        # action succeeded; subsequent sync retries must reuse the durable P07 result.
        current_principal["value"] = owner
        with TestClient(api) as client:
            checkpoint_failure = client.post(f"/connectors/{connector_id}/sync")
        assert checkpoint_failure.status_code == 503
        assert provider_calls == [("drive-file-safe-id", "drive-permission-safe-id")]
        with TestClient(api) as client:
            retried_sync = client.post(f"/connectors/{connector_id}/sync")
        assert retried_sync.status_code == 200, retried_sync.text
        assert retried_sync.json()["scan_decisions"][0]["action_status"] == "succeeded"
        assert sync_service.completed == ["checkpoint-after"]
        assert sync_service.complete_attempts == 2
        assert len(feed_requests) == 3
        assert provider_calls == [("drive-file-safe-id", "drive-permission-safe-id")]
        current_principal["value"] = admin
        with TestClient(api) as client:
            duplicate_approval = client.post(f"/approvals/{first['approval_id']}/approve", json={})
        assert duplicate_approval.status_code == 409
        assert provider_calls == [("drive-file-safe-id", "drive-permission-safe-id")]
        with factory() as session:
            audit_rows = session.execute(AUDIT_EVENTS.select()).mappings().all()
            audit_actions = [row["action"] for row in audit_rows]
            audit_json = str([dict(row) for row in audit_rows])
        for marker in (
            "TEST_ACCESS_TOKEN_DO_NOT_LEAK",
            "TEST_REFRESH_TOKEN_DO_NOT_LEAK",
            "TEST_OAUTH_CODE_DO_NOT_LEAK",
            "TEST_CLIENT_SECRET_DO_NOT_LEAK",
        ):
            assert marker not in audit_json
        assert "approval.approved" in audit_actions
        assert "action.executed" in audit_actions

        # A rejected approval does not invoke the connector executor.
        current_principal["value"] = owner
        second = connectors._scan_drive_object(
            owner,
            connector_id,
            DriveObject(object_id="drive-file-2", name="Second.txt", mime_type="text/plain"),
            extra_context={"permission_id": "permission-2"},
        )
        assert second["action_status"] == "pending_approval"
        current_principal["value"] = admin
        with TestClient(api) as client:
            rejected = client.post(f"/approvals/{second['approval_id']}/reject", json={})
        assert rejected.status_code == 200, rejected.text
        assert rejected.json()["status"] == "rejected"
        assert provider_calls == [("drive-file-safe-id", "drive-permission-safe-id")]
    finally:
        configure_action_processor(None)
        approvals.configure_action_executor(UnavailableActionExecutor())
        engine.dispose()
