"""P07 deterministic action resolution and approval state tests."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import SecretStr

from dlp_platform.actions.interfaces import UnavailableActionExecutor, resolve_action
from dlp_platform.approvals.state_machine import decide, refreshed_state
from dlp_platform.contracts.common import ActorType, AuthMethod, DataChannel, PolicyAction, Role
from dlp_platform.contracts.policy import Policy
from dlp_platform.contracts.principal import Principal
from dlp_platform.contracts.scan_request import ScanRequest
from dlp_platform.policy.engine import PolicyEngine


@pytest.mark.parametrize(
    ("action", "status", "approval"),
    [
        (PolicyAction.REDACT, "pending_executor", False),
        (PolicyAction.QUARANTINE, "pending_executor", False),
        (PolicyAction.REVOKE_SHARE, "pending_approval", True),
        (PolicyAction.REQUIRE_APPROVAL, "pending_approval", True),
    ],
)
def test_advanced_action_resolution(action, status: str, approval: bool) -> None:
    plan = resolve_action(action)
    assert plan is not None
    assert (plan.status, plan.requires_approval) == (status, approval)


def test_legacy_actions_are_not_action_requests() -> None:
    for action in (PolicyAction.ALLOW, PolicyAction.LOG, PolicyAction.WARN, PolicyAction.BLOCK):
        assert resolve_action(action) is None


def test_p07_action_strictness_order_keeps_block_strictest() -> None:
    org_id = uuid4()
    now = datetime.now(UTC)
    principal = Principal(
        organization_id=org_id,
        subject_id="p07-test",
        actor_type=ActorType.USER,
        role=Role.OWNER,
        scopes=("scan:request",),
        auth_method=AuthMethod.JWT,
    )
    scan_request = ScanRequest(channel=DataChannel.API, content=SecretStr("ephemeral"))
    policies = tuple(
        Policy(
            policy_id=uuid4(),
            organization_id=org_id,
            name=action.value,
            enabled=True,
            priority=0,
            conditions={},
            action=action,
            version=1,
            created_at=now,
            updated_at=now,
        )
        for action in (
            PolicyAction.REDACT,
            PolicyAction.QUARANTINE,
            PolicyAction.REQUIRE_APPROVAL,
            PolicyAction.BLOCK,
        )
    )
    decision = PolicyEngine().evaluate(
        organization_id=org_id,
        request=scan_request,
        principal=principal,
        findings=(),
        policies=policies,
        destinations=(),
    )
    assert decision.action is PolicyAction.BLOCK


def test_unavailable_external_executor_never_claims_success() -> None:
    executor = UnavailableActionExecutor()
    result = executor.execute(
        "stable-action-id", PolicyAction.REVOKE_SHARE, {"policy_id": "safe-id"}
    )
    assert result.status == "pending_executor"
    assert "configured" in result.detail


def test_approval_transition_and_expiry_are_deterministic() -> None:
    now = datetime(2026, 10, 22, 12, tzinfo=UTC)
    expiry = now + timedelta(hours=1)
    assert refreshed_state("pending", expiry, now) == "pending"
    assert refreshed_state("pending", expiry, expiry) == "expired"
    assert decide("escalated", "approved") == "approved"
    with pytest.raises(ValueError):
        decide("approved", "rejected")
