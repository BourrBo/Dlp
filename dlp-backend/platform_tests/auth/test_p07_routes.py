"""P07 authenticated approval API behavior on the SQLite route fixture."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from pydantic import SecretStr

from dlp_platform.actions.interfaces import UnavailableActionExecutor
from dlp_platform.actions.service import ActionProcessor
from dlp_platform.contracts.common import ActorType, AuthMethod, DataChannel, PolicyAction, Role
from dlp_platform.contracts.principal import Principal
from dlp_platform.contracts.scan_request import ScanRequest
from dlp_platform.routes.approvals import configure_action_executor
from dlp_platform.scan.idempotency import InMemoryIdempotencyStore
from dlp_platform.scan.interfaces import PolicyDecision
from dlp_platform.scan.pipeline import ScanPipeline, configure_action_processor, fake_stages
from dlp_platform.tables import ACTIONS, APPROVALS, DESTINATIONS, POLICIES, POLICY_VERSIONS
from platform_tests.auth.conftest import ORG_B
from platform_tests.auth.helpers import auth_headers, signed_token


def prepare_tables(client) -> None:
    bind = client.app.state.test_session_factory.kw["bind"]
    for table in (POLICIES, DESTINATIONS, POLICY_VERSIONS, ACTIONS, APPROVALS):
        table.create(bind, checkfirst=True)


def test_approval_api_enforces_auth_self_approval_and_single_decision(auth_client) -> None:
    prepare_tables(auth_client)
    policy = auth_client.post(
        "/policies",
        json={"name": "Require review", "conditions": {"channel": "api"}, "action": "block"},
        headers=auth_headers(),
    )
    assert policy.status_code == 201, policy.text
    policy_id = policy.json()["policy_id"]
    request_id = str(uuid4())
    created = auth_client.post(
        "/approvals",
        json={
            "request_id": request_id,
            "action": "user_override",
            "justification": "Release reviewed build",
            "policy_id": policy_id,
            "policy_version": policy.json()["version"],
        },
        headers=auth_headers(),
    )
    assert created.status_code == 201, created.text
    approval_id = created.json()["approval_id"]
    assert (
        auth_client.get("/audit/events?action=approval.requested", headers=auth_headers()).json()[
            0
        ]["resource_id"]
        == approval_id
    )
    assert created.json()["status"] == "pending"
    assert created.json()["action_status"] == "pending_approval"
    duplicate = auth_client.post(
        "/approvals",
        json={
            "request_id": request_id,
            "action": "user_override",
            "justification": "Retry the reviewed build request",
            "policy_id": policy_id,
            "policy_version": policy.json()["version"],
        },
        headers=auth_headers(),
    )
    assert duplicate.status_code == 201
    assert duplicate.json()["approval_id"] == approval_id

    assert (
        auth_client.post(
            f"/approvals/{approval_id}/approve", json={}, headers=auth_headers()
        ).status_code
        == 403
    )

    analyst = auth_headers(signed_token(subject="user-analyst-a"))
    assert (
        auth_client.post(f"/approvals/{approval_id}/approve", json={}, headers=analyst).status_code
        == 403
    )

    admin = auth_headers(signed_token(subject="user-admin-a"))
    key = auth_client.post(
        "/api-keys",
        json={
            "name": "P07 approval client",
            "scopes": ["identity:read", "approvals:decide"],
        },
        headers=admin,
    )
    assert key.status_code == 201, key.text
    approver = auth_headers(key.json()["key"])
    approved = auth_client.post(f"/approvals/{approval_id}/approve", json={}, headers=approver)
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "approved"
    assert approved.json()["action_status"] == "approved"
    assert (
        auth_client.get("/audit/events?action=approval.approved", headers=auth_headers()).json()[0][
            "resource_id"
        ]
        == approval_id
    )
    assert (
        auth_client.post(f"/approvals/{approval_id}/reject", json={}, headers=approver).status_code
        == 409
    )

    assert auth_client.get("/approvals", headers=auth_headers()).json()[0]["status"] == "approved"
    assert (
        auth_client.get("/actions", headers=auth_headers()).json()[0]["action"] == "user_override"
    )

    class BlockPolicy:
        def evaluate(self, findings, request, principal):
            del findings, request, principal
            return PolicyDecision(
                action=PolicyAction.BLOCK,
                reason="Policy blocks the request",
                policy_id=policy_id,
                policy_version=str(policy.json()["version"]),
            )

    bind = auth_client.app.state.test_session_factory.kw["bind"]
    processor = ActionProcessor(bind)
    configure_action_processor(processor)
    try:
        principal = Principal(
            organization_id=UUID("11111111-1111-4111-8111-111111111111"),
            subject_id="user-owner-a",
            actor_type=ActorType.USER,
            role=Role.OWNER,
            scopes=("scan:request",),
            auth_method=AuthMethod.JWT,
        )
        scan_request = ScanRequest(
            request_id=UUID(request_id),
            channel=DataChannel.API,
            content=SecretStr("private content is not persisted"),
        )
        analyst_principal = Principal(
            organization_id=principal.organization_id,
            subject_id="user-analyst-a",
            actor_type=ActorType.USER,
            role=Role.ANALYST,
            scopes=("scan:request",),
            auth_method=AuthMethod.JWT,
        )
        analyst_pipeline = ScanPipeline(
            replace(fake_stages(), policy=BlockPolicy()), InMemoryIdempotencyStore()
        )
        assert analyst_pipeline.scan(scan_request, analyst_principal).decision is PolicyAction.BLOCK
        pipeline = ScanPipeline(
            replace(fake_stages(), policy=BlockPolicy()), InMemoryIdempotencyStore()
        )
        result = pipeline.scan(scan_request, principal)
        assert result.decision is PolicyAction.ALLOW
        assert "Approved user override applied" in result.reason
        with auth_client.app.state.test_session_factory() as session:
            override = (
                session.execute(
                    ACTIONS.select().where(
                        ACTIONS.c.request_id == request_id,
                        ACTIONS.c.action == "user_override",
                    )
                )
                .mappings()
                .one()
            )
            assert override["status"] == "succeeded"
            assert "private content is not persisted" not in str(override["metadata"])

        class RedactPolicy:
            def evaluate(self, findings, request, principal):
                del findings, request, principal
                return PolicyDecision(
                    action=PolicyAction.REDACT, reason="Policy requested redaction"
                )

        redact_request = ScanRequest(
            channel=DataChannel.API, content=SecretStr("second private payload")
        )
        redact_pipeline = ScanPipeline(
            replace(fake_stages(), policy=RedactPolicy()), InMemoryIdempotencyStore()
        )
        redact_result = redact_pipeline.scan(redact_request, principal)
        assert redact_result.decision is PolicyAction.REDACT
        assert "pending_executor" in redact_result.reason
        with auth_client.app.state.test_session_factory() as session:
            pending = (
                session.execute(
                    ACTIONS.select().where(ACTIONS.c.request_id == str(redact_request.request_id))
                )
                .mappings()
                .one()
            )
            assert pending["status"] == "pending_executor"
            assert "second private payload" not in str(pending["metadata"])
    finally:
        configure_action_processor(None)


def test_approval_api_rejects_forged_tenant_and_hides_other_org(auth_client) -> None:
    prepare_tables(auth_client)
    created = auth_client.post(
        "/approvals",
        json={
            "request_id": str(uuid4()),
            "action": "quarantine",
            "justification": "Contain reviewed artifact",
            "org_id": str(ORG_B),
        },
        headers=auth_headers(),
    )
    assert created.status_code == 422
    created = auth_client.post(
        "/approvals",
        json={
            "request_id": str(uuid4()),
            "action": "quarantine",
            "justification": "Contain reviewed artifact",
        },
        headers=auth_headers(),
    )
    assert created.status_code == 201, created.text
    tenant_b = auth_headers(signed_token(subject="user-owner-b", organization_id=ORG_B))
    approval_id = created.json()["approval_id"]
    assert auth_client.get(f"/approvals/{approval_id}", headers=tenant_b).status_code == 404
    assert auth_client.get("/approvals", headers=tenant_b).json() == []
    tenant_b_key = auth_client.post(
        "/api-keys",
        json={"name": "P07 tenant B reader", "scopes": ["identity:read"]},
        headers=tenant_b,
    )
    assert tenant_b_key.status_code == 201, tenant_b_key.text
    tenant_b_api_key = auth_headers(tenant_b_key.json()["key"])
    assert auth_client.get("/approvals", headers=tenant_b_api_key).json() == []
    assert auth_client.get(f"/approvals/{approval_id}", headers=tenant_b_api_key).status_code == 404


def test_approval_requires_auth_and_validates_payload(auth_client) -> None:
    prepare_tables(auth_client)
    assert auth_client.get("/approvals").status_code == 401
    assert auth_client.post("/approvals", json={}).status_code == 401
    invalid = auth_client.post(
        "/approvals",
        json={"request_id": str(uuid4()), "action": "revoke_share", "justification": "  "},
        headers=auth_headers(),
    )
    assert invalid.status_code == 422
    unbound_override = auth_client.post(
        "/approvals",
        json={
            "request_id": str(uuid4()),
            "action": "user_override",
            "justification": "Release reviewed operation",
        },
        headers=auth_headers(),
    )
    assert unbound_override.status_code == 422
    credential_like = auth_client.post(
        "/approvals",
        json={
            "request_id": str(uuid4()),
            "action": "user_override",
            "justification": "Review this credential Bearer " + "x" * 32,
        },
        headers=auth_headers(),
    )
    assert credential_like.status_code == 422


def test_approval_expiry_escalation_and_safe_executor_failure(auth_client) -> None:
    prepare_tables(auth_client)
    factory = auth_client.app.state.test_session_factory
    created = auth_client.post(
        "/approvals",
        json={
            "request_id": str(uuid4()),
            "action": "quarantine",
            "justification": "Contain the reviewed artifact",
        },
        headers=auth_headers(),
    )
    assert created.status_code == 201, created.text
    approval_id = created.json()["approval_id"]
    with factory.begin() as session:
        session.execute(
            APPROVALS.update()
            .where(APPROVALS.c.id == approval_id)
            .values(created_at=datetime.now(UTC) - timedelta(hours=13))
        )
    escalated = auth_client.get(f"/approvals/{approval_id}", headers=auth_headers())
    assert escalated.status_code == 200, escalated.text
    assert escalated.json()["status"] == "escalated"

    class FailingExecutor:
        def execute(self, idempotency_key, action, safe_metadata):
            del idempotency_key, action, safe_metadata
            raise RuntimeError("private provider failure must not escape")

    configure_action_executor(FailingExecutor())
    try:
        admin = auth_headers(signed_token(subject="user-admin-a"))
        decision = auth_client.post(f"/approvals/{approval_id}/approve", json={}, headers=admin)
        assert decision.status_code == 200, decision.text
        assert decision.json()["status"] == "approved"
        assert decision.json()["action_status"] == "failed"
        assert "private provider failure" not in decision.text
        action_event = auth_client.get(
            "/audit/events?action=action.executed", headers=admin
        ).json()[0]
        assert action_event["outcome"] == "failure"
    finally:
        configure_action_executor(UnavailableActionExecutor())

    expired = auth_client.post(
        "/approvals",
        json={
            "request_id": str(uuid4()),
            "action": "revoke_share",
            "justification": "Review public share revocation",
        },
        headers=auth_headers(),
    )
    assert expired.status_code == 201, expired.text
    with factory.begin() as session:
        session.execute(
            APPROVALS.update()
            .where(APPROVALS.c.id == expired.json()["approval_id"])
            .values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
    expired_result = auth_client.get(
        f"/approvals/{expired.json()['approval_id']}", headers=auth_headers()
    )
    assert expired_result.status_code == 200
    assert expired_result.json()["status"] == "expired"
    assert expired_result.json()["action_status"] == "expired"
