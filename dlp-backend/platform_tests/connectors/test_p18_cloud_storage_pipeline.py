"""P18 connector sync integration with scan(), P05, P07 guard, audit, checkpoints."""

import hashlib
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, update
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from dlp_platform.actions.service import ActionProcessor
from dlp_platform.auth.principal import get_principal
from dlp_platform.connectors.cloud_storage import (
    CloudNotification,
    CloudObjectPage,
    CloudStorageObject,
    NotificationBatch,
)
from dlp_platform.connectors.service import ConnectorOperationFailed, ConnectorService
from dlp_platform.contracts.common import ActorType, AuthMethod, PolicyAction, Role
from dlp_platform.contracts.policy import Policy
from dlp_platform.contracts.principal import Principal
from dlp_platform.database import get_session
from dlp_platform.policy.engine import PolicyEngine
from dlp_platform.ratelimit.dependencies import get_rate_limiter
from dlp_platform.routes import cloud_storage_connectors as cloud_routes
from dlp_platform.scan.idempotency import InMemoryIdempotencyStore
from dlp_platform.scan.pipeline import (
    configure_action_processor,
    configure_pipeline,
    fake_stages,
)
from dlp_platform.tables import (
    ACTIONS,
    APPROVALS,
    AUDIT_EVENTS,
    DLP_CONNECTOR_STATE,
    DLP_CONNECTORS,
    MEMBERS,
    ORGANIZATIONS,
    metadata,
)


class FakeLimiter:
    def check(self, *_args):
        return SimpleNamespace(allowed=True, retry_after=0)


class VaultFixture:
    def get_for_trusted_service(self, _session, org_id, secret_id, *, allowed_types):
        assert org_id == ORG_ID
        assert secret_id == SECRET_ID
        assert {secret_type.value for secret_type in allowed_types} == {"api_credential"}
        return type("Secret", (), {"get_secret_value": lambda _self: "fixture-vault-value"})()


class AdapterFixture:
    def __init__(self, _config, credential):
        assert credential == "fixture-vault-value"

    def list_page(self, page_token, _size):
        assert page_token is None
        return CloudObjectPage(
            objects=(
                CloudStorageObject(
                    provider="aws_s3",
                    bucket="fixture-bucket",
                    object_name="public.txt",
                    version="v1",
                    provider_project_or_account="123456789012",
                    size_bytes=5,
                    etag="etag-1",
                ),
            ),
            next_page_token="resume-token",
        )

    def detect_exposure(self, obj):
        from dlp_platform.connectors.models import Exposure, ExposureKind

        return (Exposure(object_id=obj.object_id, kind=ExposureKind.PUBLIC),)


ORG_ID = uuid4()
CONNECTOR_ID = uuid4()
SECRET_ID = uuid4()
OWNER_ID = uuid4()
NOW = datetime.now(UTC)


def _install_pipeline(action: PolicyAction, engine):
    policy_engine = PolicyEngine()

    class PolicyFixture:
        def evaluate(self, findings, request, principal):
            policy = Policy(
                policy_id=uuid4(),
                organization_id=principal.organization_id,
                name="P18 fixture policy",
                enabled=True,
                priority=1,
                conditions={},
                action=action,
                version=1,
                created_at=NOW,
                updated_at=NOW,
            )
            return policy_engine.evaluate(
                organization_id=principal.organization_id,
                request=request,
                principal=principal,
                findings=findings,
                policies=(policy,),
                destinations=(),
            )

    configure_action_processor(ActionProcessor(engine))
    configure_pipeline(replace(fake_stages(), policy=PolicyFixture()), InMemoryIdempotencyStore())


def _setup(monkeypatch, action: PolicyAction):
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    metadata.create_all(
        engine,
        tables=[
            ORGANIZATIONS,
            MEMBERS,
            ACTIONS,
            APPROVALS,
            AUDIT_EVENTS,
            DLP_CONNECTORS,
            DLP_CONNECTOR_STATE,
        ],
    )
    owner = Principal(
        organization_id=ORG_ID,
        subject_id="p18-pipeline-owner",
        actor_type=ActorType.USER,
        role=Role.OWNER,
        scopes=("connectors:write", "connectors:read", "vault:use"),
        auth_method=AuthMethod.SSO,
        member_id=OWNER_ID,
        session_id=uuid4(),
    )
    with engine.begin() as connection:
        connection.execute(
            ORGANIZATIONS.insert().values(
                id=str(ORG_ID),
                name="P18 fixture",
                settings_json={},
                created_at=NOW,
                updated_at=NOW,
            )
        )
        connection.execute(
            MEMBERS.insert().values(
                id=str(OWNER_ID),
                organization_id=str(ORG_ID),
                auth_subject_id=owner.subject_id,
                role="owner",
                active=True,
                created_at=NOW,
            )
        )
        connection.execute(
            DLP_CONNECTORS.insert().values(
                id=str(CONNECTOR_ID),
                org_id=str(ORG_ID),
                provider="aws_s3",
                name="P18 fixture",
                status="connected",
                credential_secret_id=str(SECRET_ID),
                config_json={
                    "bucket": "fixture-bucket",
                    "region": "us-east-1",
                    "aws_account_id": "123456789012",
                    "requester_pays": False,
                    "sqs_queue_name": "events",
                },
                last_sync_at=None,
                last_error_code=None,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        connection.execute(
            DLP_CONNECTOR_STATE.insert().values(
                connector_id=str(CONNECTOR_ID),
                org_id=str(ORG_ID),
                provider="aws_s3",
                checkpoint="p18_s3_inventory_v1",
                state_json={"initial_inventory_pending": True, "page_token": None},
                updated_at=NOW,
            )
        )
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    service = ConnectorService()
    monkeypatch.setattr(cloud_routes, "_service", service)
    monkeypatch.setattr(cloud_routes, "S3StorageAdapter", AdapterFixture)
    monkeypatch.setattr(
        cloud_routes,
        "_audit_context",
        lambda _request: None,
    )
    app = FastAPI()
    app.include_router(cloud_routes.router)
    app.dependency_overrides[get_principal] = lambda: owner
    app.dependency_overrides[get_session] = lambda: factory()
    app.dependency_overrides[get_rate_limiter] = lambda: FakeLimiter()
    app.dependency_overrides[cloud_routes._vault] = lambda: VaultFixture()
    _install_pipeline(action, engine)
    return engine, factory, app


def test_s3_sync_scans_metadata_through_p05_audits_exposure_and_checkpoints(monkeypatch):
    engine, factory, app = _setup(monkeypatch, PolicyAction.WARN)
    try:
        with TestClient(app) as client:
            response = client.post(f"/connectors/s3/{CONNECTOR_ID}/sync")
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["sync_mode"] == "initial_inventory"
        assert body["processed_objects"] == 1
        assert body["exposure_count"] == 1
        assert body["scan_decisions"][0]["decision"] == "warn"
        with factory() as session:
            state = session.execute(
                select(DLP_CONNECTOR_STATE.c.state_json).where(
                    DLP_CONNECTOR_STATE.c.connector_id == str(CONNECTOR_ID)
                )
            ).scalar_one()
            audit = session.execute(AUDIT_EVENTS.select()).mappings().all()
        assert state["page_token"] == "resume-token"
        assert state["initial_inventory_pending"] is True
        assert any(row["action"] == "connector.exposure_detected" for row in audit)
    finally:
        configure_action_processor(None)
        engine.dispose()


def test_unsupported_p07_revoke_fails_closed_without_advancing_inventory(monkeypatch):
    engine, factory, app = _setup(monkeypatch, PolicyAction.REVOKE_SHARE)
    try:
        with TestClient(app) as client:
            response = client.post(f"/connectors/s3/{CONNECTOR_ID}/sync")
        assert response.status_code == 503
        with factory() as session:
            state = session.execute(
                select(DLP_CONNECTOR_STATE.c.state_json).where(
                    DLP_CONNECTOR_STATE.c.connector_id == str(CONNECTOR_ID)
                )
            ).scalar_one()
            actions = session.execute(ACTIONS.select()).mappings().all()
        assert state["page_token"] is None
        assert state["initial_inventory_pending"] is True
        assert actions == []
    finally:
        configure_action_processor(None)
        engine.dispose()


def test_checkpoint_persistence_failure_keeps_inventory_page_retryable(monkeypatch):
    engine, factory, app = _setup(monkeypatch, PolicyAction.WARN)
    service = cloud_routes._service
    original = service.complete_sync
    attempts = 0

    def fail_once(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise ConnectorOperationFailed("fixture checkpoint failure")
        return original(*args, **kwargs)

    monkeypatch.setattr(service, "complete_sync", fail_once)
    try:
        with TestClient(app) as client:
            first = client.post(f"/connectors/s3/{CONNECTOR_ID}/sync")
            with factory() as session:
                before = session.execute(
                    select(DLP_CONNECTOR_STATE.c.state_json).where(
                        DLP_CONNECTOR_STATE.c.connector_id == str(CONNECTOR_ID)
                    )
                ).scalar_one()
            second = client.post(f"/connectors/s3/{CONNECTOR_ID}/sync")
        assert first.status_code == 503
        assert before["page_token"] is None
        assert second.status_code == 200
        assert attempts == 2
    finally:
        configure_action_processor(None)
        engine.dispose()


def test_s3_event_receipt_is_checkpointed_before_ack_and_duplicates_are_safe(monkeypatch):
    engine, factory, app = _setup(monkeypatch, PolicyAction.WARN)
    with factory.begin() as session:
        session.execute(
            update(DLP_CONNECTOR_STATE)
            .where(DLP_CONNECTOR_STATE.c.connector_id == str(CONNECTOR_ID))
            .values(state_json={"initial_inventory_pending": False, "event_receipts": []})
        )
    ack_count = 0

    class EventAdapter(AdapterFixture):
        def poll_notifications(self, limit):
            assert limit == 10
            return NotificationBatch(
                events=(
                    CloudNotification(
                        event_id="s3:fixture-bucket:event-1",
                        bucket="fixture-bucket",
                        object_name="public.txt",
                        version="v1",
                        acknowledgement="receipt-1",
                    ),
                ),
                acknowledgement_tokens=("receipt-1",),
            )

        def get_event_object(self, name, version, *, deleted):
            assert (name, version, deleted) == ("public.txt", "v1", False)
            return CloudStorageObject(
                provider="aws_s3",
                bucket="fixture-bucket",
                object_name=name,
                version=version,
                provider_project_or_account="123456789012",
                etag="etag-1",
            )

        def acknowledge(self, receipt_tokens):
            nonlocal ack_count
            assert receipt_tokens == ("receipt-1",)
            with factory() as session:
                saved = session.execute(
                    select(DLP_CONNECTOR_STATE.c.state_json).where(
                        DLP_CONNECTOR_STATE.c.connector_id == str(CONNECTOR_ID)
                    )
                ).scalar_one()
            expected_receipt = hashlib.sha256(b"s3:fixture-bucket:event-1").hexdigest()
            assert expected_receipt in saved["event_receipts"]
            ack_count += 1

    monkeypatch.setattr(cloud_routes, "S3StorageAdapter", EventAdapter)
    original_scan = cloud_routes.scan
    scan_count = 0

    def counting_scan(*args, **kwargs):
        nonlocal scan_count
        scan_count += 1
        return original_scan(*args, **kwargs)

    monkeypatch.setattr(cloud_routes, "scan", counting_scan)
    try:
        with TestClient(app) as client:
            first = client.post(f"/connectors/s3/{CONNECTOR_ID}/sync")
            duplicate = client.post(f"/connectors/s3/{CONNECTOR_ID}/sync")
        assert first.status_code == 200, first.text
        assert first.json()["sync_mode"] == "event_notifications"
        assert first.json()["processed_objects"] == 1
        assert duplicate.status_code == 200, duplicate.text
        assert duplicate.json()["processed_objects"] == 0
        assert scan_count == 1
        assert ack_count == 2
    finally:
        configure_action_processor(None)
        engine.dispose()
