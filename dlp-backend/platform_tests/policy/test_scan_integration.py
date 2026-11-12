"""P05 database evaluator handoff into the existing P04 pipeline."""

from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from pydantic import SecretStr
from sqlalchemy import create_engine, insert, text

from dlp_platform.contracts.common import ActorType, AuthMethod, DataChannel, PolicyAction, Role
from dlp_platform.contracts.principal import Principal
from dlp_platform.contracts.scan_request import ScanRequest
from dlp_platform.policy.adapter import DatabasePolicyEvaluator
from dlp_platform.policy.engine import PolicyEvaluationError
from dlp_platform.policy.repository import PolicyRepository
from dlp_platform.scan.errors import PolicyDecisionFailure
from dlp_platform.scan.idempotency import InMemoryIdempotencyStore
from dlp_platform.scan.pipeline import ScanPipeline, fake_stages
from dlp_platform.tables import DESTINATIONS, MEMBERS, ORGANIZATIONS, POLICIES

ORG_A = UUID("11111111-1111-4111-8111-111111111111")
ORG_B = UUID("22222222-2222-4222-8222-222222222222")


def test_database_policy_decision_and_reason_flow_through_scan_result(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{(tmp_path / 'p05.sqlite').as_posix()}")
    for table in (ORGANIZATIONS, MEMBERS, POLICIES, DESTINATIONS):
        table.create(engine)
    now = datetime.now(UTC)
    with engine.begin() as connection:
        connection.execute(
            insert(ORGANIZATIONS).values(
                id=str(ORG_A), name="Tenant A", settings_json={}, created_at=now, updated_at=now
            )
        )
        connection.execute(
            insert(ORGANIZATIONS).values(
                id=str(ORG_B), name="Tenant B", settings_json={}, created_at=now, updated_at=now
            )
        )
        connection.execute(
            insert(MEMBERS).values(
                id=str(uuid4()),
                organization_id=str(ORG_A),
                auth_subject_id="p05-integration",
                role="owner",
                created_at=now,
            )
        )
        connection.execute(
            insert(MEMBERS).values(
                id=str(uuid4()),
                organization_id=str(ORG_B),
                auth_subject_id="p05-integration-b",
                role="owner",
                created_at=now,
            )
        )
        connection.execute(
            insert(POLICIES).values(
                id=str(uuid4()),
                org_id=str(ORG_A),
                name="Block API traffic",
                enabled=True,
                priority=10,
                conditions={"channel": "api"},
                action="block",
                version=7,
                created_by=connection.execute(
                    text("SELECT id FROM members WHERE auth_subject_id='p05-integration'")
                ).scalar_one(),
                created_at=now,
                updated_at=now,
            )
        )

    principal = Principal(
        organization_id=ORG_A,
        subject_id="p05-integration",
        actor_type=ActorType.USER,
        role=Role.OWNER,
        scopes=("scan:request",),
        auth_method=AuthMethod.JWT,
    )
    request = ScanRequest(channel=DataChannel.API, content=SecretStr("ephemeral test input"))
    stages = replace(fake_stages(), policy=DatabasePolicyEvaluator(PolicyRepository(engine)))
    try:
        pipeline = ScanPipeline(stages, InMemoryIdempotencyStore())
        result = pipeline.scan(request, principal)
        assert result.decision == PolicyAction.BLOCK
        assert result.policy_version == "7"
        assert "Block API traffic" not in result.reason
        assert "matched conditions: channel" in result.reason
        assert "ephemeral test input" not in result.model_dump_json()

        tenant_b = Principal(
            organization_id=ORG_B,
            subject_id="p05-integration-b",
            actor_type=ActorType.USER,
            role=Role.OWNER,
            scopes=("scan:request",),
            auth_method=AuthMethod.JWT,
        )
        no_match = pipeline.scan(
            ScanRequest(channel=DataChannel.API, content=SecretStr("tenant B input")), tenant_b
        )
        assert no_match.decision == PolicyAction.ALLOW
        assert no_match.policy_version is None
        assert "No enabled policy matched" in no_match.reason
        assert "tenant B input" not in no_match.model_dump_json()
    finally:
        engine.dispose()


def test_policy_repository_failure_reaches_p04_fail_closed_error() -> None:
    class BrokenRepository(PolicyRepository):
        def load(self, organization_id):
            del organization_id
            raise PolicyEvaluationError("raw secret should not escape")

    evaluator = DatabasePolicyEvaluator(BrokenRepository(create_engine("sqlite://")))
    pipeline = ScanPipeline(replace(fake_stages(), policy=evaluator), InMemoryIdempotencyStore())
    principal = Principal(
        organization_id=ORG_A,
        subject_id="p05-integration",
        actor_type=ActorType.USER,
        role=Role.OWNER,
        scopes=("scan:request",),
        auth_method=AuthMethod.JWT,
    )
    request = ScanRequest(channel=DataChannel.API, content=SecretStr("sensitive input"))
    with pytest.raises(PolicyDecisionFailure) as failure:
        pipeline.scan(request, principal)
    assert str(failure.value) == ""
    assert "raw secret" not in str(failure.value)
