"""P07 PostgreSQL integration, tenant isolation and action lifecycle persistence."""

import json
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

import pytest
from pydantic import SecretStr
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker
from starlette.requests import Request

from dlp_platform.actions.interfaces import ActionExecutionResult, UnavailableActionExecutor
from dlp_platform.actions.service import ActionProcessor
from dlp_platform.approvals.models import ApprovalDecision
from dlp_platform.contracts.common import ActorType, AuthMethod, DataChannel, PolicyAction, Role
from dlp_platform.contracts.principal import Principal
from dlp_platform.contracts.scan_request import ScanRequest
from dlp_platform.policy.lifecycle import PolicyLifecycleEvaluator
from dlp_platform.policy.repository import PolicyRepository
from dlp_platform.policy.suppressions import DatabaseSuppressor
from dlp_platform.routes.approvals import _decide
from dlp_platform.routes.approvals import configure_action_executor as configure_route_executor
from dlp_platform.scan.idempotency import InMemoryIdempotencyStore
from dlp_platform.scan.pipeline import ScanPipeline, configure_action_processor, fake_stages

DATABASE_URL = os.getenv("P03_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    DATABASE_URL is None, reason="P03_TEST_DATABASE_URL is not configured"
)


def _claims(connection, org_id: str | None, app_role: str = "owner") -> None:
    connection.execute(text("SET LOCAL ROLE authenticated"))
    claims = {"role": "authenticated", "aud": "authenticated", "app_role": app_role}
    if org_id is not None:
        claims["org_id"] = org_id
    connection.execute(
        text("SELECT set_config('request.jwt.claims', :claims, true)"),
        {"claims": json.dumps(claims)},
    )


def _request() -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/approvals/test/approve",
            "headers": [],
            "query_string": b"",
            "client": ("127.0.0.1", 12345),
        }
    )


def test_p07_postgres_integration_rls_and_idempotent_approval() -> None:
    assert DATABASE_URL is not None
    engine = create_engine(DATABASE_URL)
    org_a, org_b = str(uuid4()), str(uuid4())
    member_a, member_b = str(uuid4()), str(uuid4())
    approver_a, approver_b = str(uuid4()), str(uuid4())
    policy_id = str(uuid4())
    redact_policy_id = str(uuid4())
    now = datetime.now(UTC)
    with engine.begin() as connection:
        connection.execute(
            text("INSERT INTO organizations (id,name) VALUES (:id,:name)"),
            [{"id": org_a, "name": "P07 A"}, {"id": org_b, "name": "P07 B"}],
        )
        connection.execute(
            text(
                "INSERT INTO members (id,organization_id,auth_subject_id,role) "
                "VALUES (:id,:org,:sub,'owner')"
            ),
            [
                {"id": member_a, "org": org_a, "sub": f"p07-{member_a}"},
                {"id": member_b, "org": org_b, "sub": f"p07-{member_b}"},
                {"id": approver_a, "org": org_a, "sub": f"p07-{approver_a}"},
                {"id": approver_b, "org": org_a, "sub": f"p07-{approver_b}"},
            ],
        )
        connection.execute(
            text("""
                INSERT INTO dlp_policies
                    (id,org_id,name,enabled,priority,conditions,action,version,created_by)
                VALUES (:id,:org,'Approval policy',true,10,'{"channel":"api"}'::jsonb,
                        'require_approval',1,:member)
            """),
            {"id": policy_id, "org": org_a, "member": member_a},
        )
        connection.execute(
            text("""
                INSERT INTO dlp_policy_versions (id,policy_id,org_id,version,snapshot,created_by)
                VALUES (:id,:policy,:org,1,'{"action":"require_approval"}'::jsonb,:member)
            """),
            {"id": str(uuid4()), "policy": policy_id, "org": org_a, "member": member_a},
        )
        connection.execute(
            text("""
                INSERT INTO dlp_policies
                    (id,org_id,name,enabled,priority,conditions,action,version,created_by)
                VALUES (:id,:org,'Redact policy',true,20,'{"channel":"file"}'::jsonb,
                        'redact',1,:member)
            """),
            {"id": redact_policy_id, "org": org_a, "member": member_a},
        )
        connection.execute(
            text("""
                INSERT INTO dlp_policy_versions (id,policy_id,org_id,version,snapshot,created_by)
                VALUES (:id,:policy,:org,1,'{"action":"redact"}'::jsonb,:member)
            """),
            {"id": str(uuid4()), "policy": redact_policy_id, "org": org_a, "member": member_a},
        )
        connection.execute(
            text("""
                INSERT INTO dlp_exceptions
                    (id,org_id,policy_id,scope,reason,approver_id,created_by,updated_by,expires_at)
                VALUES (:id,:org,:policy,'{"channel":"browser"}'::jsonb,'unmatched scope',
                        :member,:member,:member,:expires)
            """),
            {
                "id": str(uuid4()),
                "org": org_a,
                "policy": policy_id,
                "member": member_a,
                "expires": now + timedelta(days=1),
            },
        )
        action_b = str(uuid4())
        connection.execute(
            text("""
                INSERT INTO dlp_actions
                    (id,org_id,request_id,requested_by,action,status,justification,metadata)
                VALUES (:id,:org,:request,:member,'user_override','pending_approval',
                        'tenant B','{}'::jsonb)
            """),
            {"id": action_b, "org": org_b, "request": str(uuid4()), "member": member_b},
        )
        connection.execute(
            text("""
                INSERT INTO dlp_approvals
                    (id,org_id,action_id,requested_by,status,justification,expires_at)
                VALUES (:id,:org,:action,:member,'pending','tenant B',:expires)
            """),
            {
                "id": str(uuid4()),
                "org": org_b,
                "action": action_b,
                "member": member_b,
                "expires": now + timedelta(days=1),
            },
        )

    principal = Principal(
        organization_id=UUID(org_a),
        subject_id=f"p07-{member_a}",
        actor_type=ActorType.USER,
        role=Role.OWNER,
        scopes=("scan:request",),
        auth_method=AuthMethod.JWT,
    )
    request = ScanRequest(channel=DataChannel.API, content=SecretStr("private P07 scan content"))
    processor = ActionProcessor(engine)
    configure_action_processor(processor)
    try:
        stages = replace(
            fake_stages(),
            policy=PolicyLifecycleEvaluator(PolicyRepository(engine)),
            suppressor=DatabaseSuppressor(engine),
        )
        pipeline = ScanPipeline(stages, InMemoryIdempotencyStore())
        result = pipeline.scan(request, principal)
        assert result.decision.value == "require_approval"
        assert "private P07 scan content" not in result.model_dump_json()
        # Replaying the same policy result is idempotent at the database boundary too.
        from dlp_platform.scan.interfaces import PolicyDecision

        decision = PolicyDecision(
            action=result.decision, reason=result.reason, policy_id=policy_id, policy_version="1"
        )
        processor.process_policy_decision(decision, request, principal)
        external_request = ScanRequest(
            channel=DataChannel.FILE, content=SecretStr("second private P07 content")
        )
        redact_result = pipeline.scan(external_request, principal)
        assert redact_result.decision is PolicyAction.REDACT
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT count(*) FROM dlp_actions WHERE org_id=:org"), {"org": org_a}
                ).scalar_one()
                == 2
            )
            assert (
                connection.execute(
                    text(
                        "SELECT count(*) FROM dlp_approvals WHERE org_id=:org AND status='pending'"
                    ),
                    {"org": org_a},
                ).scalar_one()
                == 1
            )
            assert (
                connection.execute(
                    text(
                        "SELECT count(*) FROM dlp_actions WHERE "
                        "justification LIKE '%private P07 scan content%' OR "
                        "justification LIKE '%second private P07 content%'"
                    ),
                ).scalar_one()
                == 0
            )

        with engine.connect() as connection:
            action_id = connection.execute(
                text("SELECT id FROM dlp_actions WHERE org_id=:org AND request_id=:request"),
                {"org": org_a, "request": str(request.request_id)},
            ).scalar_one()
            assert (
                connection.execute(
                    text("SELECT status FROM dlp_actions WHERE request_id=:request"),
                    {"request": str(external_request.request_id)},
                ).scalar_one()
                == "pending_executor"
            )
            redact_action_id = connection.execute(
                text("SELECT id FROM dlp_actions WHERE request_id=:request"),
                {"request": str(external_request.request_id)},
            ).scalar_one()
            assert (
                connection.execute(
                    text("SELECT status FROM dlp_actions WHERE id=:id"),
                    {"id": redact_action_id},
                ).scalar_one()
                == "pending_executor"
            )

        class TestOnlySuccessfulActionExecutor:
            def execute(self, idempotency_key, action, safe_metadata):
                assert idempotency_key
                assert action == "redact"
                assert safe_metadata["policy_id"] == redact_policy_id
                return ActionExecutionResult("succeeded", "test-only simulated execution")

        approval_for_redact = str(uuid5(NAMESPACE_URL, f"dlp-p07-approval:{redact_action_id}"))
        with engine.begin() as connection:
            connection.execute(
                text("""
                    INSERT INTO dlp_approvals
                        (id,org_id,action_id,requested_by,status,justification,expires_at)
                    VALUES (:id,:org,:action,:member,'pending','test executor request',:expires)
                """),
                {
                    "id": approval_for_redact,
                    "org": org_a,
                    "action": redact_action_id,
                    "member": member_a,
                    "expires": now + timedelta(days=1),
                },
            )
        configure_route_executor(TestOnlySuccessfulActionExecutor())
        test_approver = Principal(
            organization_id=UUID(org_a),
            subject_id=f"p07-{approver_a}",
            actor_type=ActorType.USER,
            role=Role.OWNER,
            scopes=("identity:read", "approvals:decide"),
            auth_method=AuthMethod.JWT,
        )
        factory = sessionmaker(bind=engine, class_=Session, expire_on_commit=False)
        with factory() as session:
            approved = _decide(
                UUID(approval_for_redact),
                "approved",
                ApprovalDecision(),
                _request(),
                test_approver,
                session,
            )
        assert approved.status == "approved"
        assert approved.action_status == "succeeded"
        with engine.begin() as connection:
            _claims(connection, org_a)
            assert connection.execute(
                text("SELECT id FROM dlp_actions WHERE org_id=:org AND request_id=:request"),
                {"org": org_a, "request": str(request.request_id)},
            ).scalars().all() == [action_id]
            assert (
                connection.execute(
                    text("SELECT id FROM dlp_actions WHERE org_id=:org"), {"org": org_b}
                )
                .scalars()
                .all()
                == []
            )
            assert (
                connection.execute(
                    text("UPDATE dlp_actions SET status='failed' WHERE org_id=:org"), {"org": org_b}
                ).rowcount
                == 0
            )
            assert (
                connection.execute(
                    text("DELETE FROM dlp_approvals WHERE org_id=:org"), {"org": org_b}
                ).rowcount
                == 0
            )
        with engine.begin() as connection:
            _claims(connection, None)
            assert connection.execute(text("SELECT id FROM dlp_actions")).scalars().all() == []
            assert connection.execute(text("SELECT id FROM dlp_approvals")).scalars().all() == []
        with engine.begin() as connection:
            _claims(connection, org_a)
            with pytest.raises(DBAPIError), connection.begin_nested():
                connection.execute(
                    text("""
                        INSERT INTO dlp_actions
                            (id,org_id,request_id,requested_by,action,status,justification,metadata)
                        VALUES (:id,:org,:request,:member,'user_override','pending_approval',
                                'forged','{}'::jsonb)
                    """),
                    {"id": str(uuid4()), "org": org_b, "request": str(uuid4()), "member": member_b},
                )
        with engine.connect() as connection:
            approval_id = connection.execute(
                text("""
                    SELECT p.id FROM dlp_approvals p JOIN dlp_actions a ON a.id=p.action_id
                    WHERE p.org_id=:org AND p.status='pending' AND a.action='require_approval'
                """),
                {"org": org_a},
            ).scalar_one()
        approvers = [
            Principal(
                organization_id=UUID(org_a),
                subject_id=f"p07-{member_id}",
                actor_type=ActorType.USER,
                role=Role.OWNER,
                scopes=("identity:read", "approvals:decide"),
                auth_method=AuthMethod.JWT,
            )
            for member_id in (approver_a, approver_b)
        ]

        def decide_concurrently(index: int) -> int:
            with factory() as session:
                try:
                    _decide(
                        UUID(approval_id),
                        "approved" if index == 0 else "rejected",
                        ApprovalDecision(),
                        _request(),
                        approvers[index],
                        session,
                    )
                    return 200
                except Exception as exc:
                    return getattr(exc, "status_code", 500)

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(decide_concurrently, (0, 1)))
        assert sorted(outcomes) == [200, 409]
        with engine.connect() as connection:
            final = connection.execute(
                text("SELECT status FROM dlp_approvals WHERE id=:id"), {"id": approval_id}
            ).scalar_one()
            action_state = connection.execute(
                text(
                    "SELECT status FROM dlp_actions WHERE org_id=:org AND action='require_approval'"
                ),
                {"org": org_a},
            ).scalar_one()
            assert (final, action_state) in {("approved", "approved"), ("rejected", "rejected")}
    finally:
        configure_action_processor(None)
        configure_route_executor(UnavailableActionExecutor())
        with engine.begin() as connection:
            connection.execute(
                text("ALTER TABLE audit_events DISABLE TRIGGER audit_events_immutable")
            )
            connection.execute(
                text("DELETE FROM audit_events WHERE organization_id IN (:a,:b)"),
                {"a": org_a, "b": org_b},
            )
            connection.execute(
                text("ALTER TABLE audit_events ENABLE TRIGGER audit_events_immutable")
            )
            connection.execute(
                text("DELETE FROM dlp_approvals WHERE org_id IN (:a,:b)"), {"a": org_a, "b": org_b}
            )
            connection.execute(
                text("DELETE FROM dlp_actions WHERE org_id IN (:a,:b)"), {"a": org_a, "b": org_b}
            )
            connection.execute(text("DELETE FROM dlp_exceptions WHERE org_id=:org"), {"org": org_a})
            connection.execute(
                text(
                    "ALTER TABLE dlp_policy_versions DISABLE TRIGGER dlp_policy_versions_immutable"
                )
            )
            connection.execute(
                text("DELETE FROM dlp_policy_versions WHERE policy_id IN (:id,:redact_id)"),
                {"id": policy_id, "redact_id": redact_policy_id},
            )
            connection.execute(
                text("ALTER TABLE dlp_policy_versions ENABLE TRIGGER dlp_policy_versions_immutable")
            )
            connection.execute(text("DELETE FROM dlp_policies WHERE id=:id"), {"id": policy_id})
            connection.execute(
                text("DELETE FROM dlp_policies WHERE id=:id"), {"id": redact_policy_id}
            )
            connection.execute(
                text("DELETE FROM members WHERE id IN (:a,:b)"), {"a": member_a, "b": member_b}
            )
            connection.execute(
                text("DELETE FROM members WHERE id IN (:a,:b)"),
                {"a": approver_a, "b": approver_b},
            )
            connection.execute(
                text("DELETE FROM organizations WHERE id IN (:a,:b)"), {"a": org_a, "b": org_b}
            )
        engine.dispose()
