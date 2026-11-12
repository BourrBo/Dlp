"""Real PostgreSQL validation for P04 persistence, idempotency, and tenant RLS."""

import json
import os
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

from dlp_platform.contracts.common import ActorType, AuthMethod, DataChannel, Role
from dlp_platform.contracts.principal import Principal
from dlp_platform.contracts.scan_request import ScanRequest
from dlp_platform.scan.fakes import (
    FakeAlertSink,
    FakeAuditSink,
    FakeClassifier,
    FakeDetector,
    FakeEnforcer,
    FakeExtractor,
    FakeFindingStore,
    FakeFingerprinter,
    FakePolicyEvaluator,
    FakeScorer,
    FakeSuppressor,
)
from dlp_platform.scan.idempotency import PostgresIdempotencyStore
from dlp_platform.scan.pipeline import PipelineStages, ScanPipeline

DATABASE_URL = os.getenv("P03_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="P03_TEST_DATABASE_URL is not configured")


def test_postgres_p04_persistence_idempotency_and_rls() -> None:
    assert DATABASE_URL is not None
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", DATABASE_URL)
    command.upgrade(config, "head")
    engine = create_engine(DATABASE_URL)
    org_a, org_b, request_id = str(uuid4()), str(uuid4()), uuid4()
    store = PostgresIdempotencyStore(DATABASE_URL)
    stages = PipelineStages(
        extractor=FakeExtractor(),
        detector=FakeDetector(),
        classifier=FakeClassifier(),
        scorer=FakeScorer(),
        fingerprinter=FakeFingerprinter(),
        suppressor=FakeSuppressor(),
        policy=FakePolicyEvaluator(),
        enforcer=FakeEnforcer(),
        alert_sink=FakeAlertSink(),
        audit_sink=FakeAuditSink(),
        finding_store=FakeFindingStore(),
    )
    try:
        with engine.begin() as conn:
            conn.execute(
                text("INSERT INTO organizations (id, name) VALUES (:a, 'P04 A'), (:b, 'P04 B')"),
                {"a": org_a, "b": org_b},
            )
        raw_content = "4111111111111111 synthetic private payload"
        request = ScanRequest(request_id=request_id, channel=DataChannel.API, content=raw_content)
        principal_a = Principal(
            organization_id=UUID(org_a),
            subject_id="p04-test-a",
            actor_type=ActorType.USER,
            role=Role.OWNER,
            scopes=("scan:request",),
            auth_method=AuthMethod.JWT,
        )
        principal_b = principal_a.model_copy(update={"organization_id": UUID(org_b)})
        pipeline = ScanPipeline(stages, store)
        result_a = pipeline.scan(request, principal_a)
        retry_a = pipeline.scan(request, principal_a)
        result_b = pipeline.scan(request, principal_b)
        assert retry_a == result_a
        assert result_b.scan_id != result_a.scan_id
        with engine.connect() as conn:
            assert conn.execute(
                text("SELECT count(*) FROM events WHERE organization_id=:org AND request_id=:req"),
                {"org": org_a, "req": str(request_id)},
            ).scalar_one() == 1
            persisted_text = conn.execute(
                text(
                    "SELECT result_json::text FROM dlp_scan_idempotency "
                    "WHERE organization_id=:org AND request_id=:req"
                ),
                {"org": org_a, "req": str(request_id)},
            ).scalar_one()
            assert raw_content not in persisted_text
            event_text = conn.execute(
                text(
                    "SELECT concat_ws(' ', reason, destination) FROM events "
                    "WHERE organization_id=:org AND request_id=:req"
                ),
                {"org": org_a, "req": str(request_id)},
            ).scalar_one()
            assert raw_content not in event_text
            claims = json.dumps(
                {
                    "sub": "p04-test-a",
                    "role": "authenticated",
                    "aud": "authenticated",
                    "org_id": org_a,
                    "app_role": "owner",
                }
            )
            conn.execute(text("SET LOCAL ROLE authenticated"))
            conn.execute(
                text("SELECT set_config('request.jwt.claims', :claims, true)"),
                {"claims": claims},
            )
            visible = conn.execute(
                text("SELECT organization_id FROM dlp_scan_idempotency")
            ).scalars().all()
            assert visible == [org_a]
            with pytest.raises(DBAPIError) as denied, conn.begin_nested():
                conn.execute(
                    text(
                        "INSERT INTO dlp_scan_idempotency "
                        "(organization_id, request_id, input_hash, state) "
                        "VALUES (:org, :req, :hash, 'processing')"
                    ),
                    {"org": org_b, "req": str(uuid4()), "hash": "0" * 64},
                )
            assert "row-level security policy" in str(denied.value.orig).lower()
    finally:
        store.engine.dispose()
        with engine.begin() as conn:
            conn.execute(
                text("DELETE FROM organizations WHERE id IN (:a, :b)"), {"a": org_a, "b": org_b}
            )
        engine.dispose()
