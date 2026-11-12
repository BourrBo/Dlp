"""P06 deterministic time, exact suppression and immutable diff helpers."""

from datetime import UTC, datetime
from uuid import uuid4

from pydantic import SecretStr

from dlp_platform.contracts.common import (
    ActorType,
    AuthMethod,
    ClassificationLevel,
    DataChannel,
    FindingStatus,
    PolicyAction,
    Role,
    SeverityLevel,
)
from dlp_platform.contracts.finding import Finding
from dlp_platform.contracts.policy import Policy
from dlp_platform.contracts.principal import Principal
from dlp_platform.contracts.scan_request import ScanRequest
from dlp_platform.policy.engine import PolicyEngine
from dlp_platform.policy.exceptions import apply_exceptions
from dlp_platform.policy.models import Destination
from dlp_platform.policy.sandbox import evaluate_sandbox
from dlp_platform.policy.suppressions import suppression_matches
from dlp_platform.policy.versions import diff_snapshots


def _finding() -> Finding:
    return Finding(
        finding_id=uuid4(),
        data_type="token",
        classification=ClassificationLevel.CONFIDENTIAL,
        severity=SeverityLevel.HIGH,
        confidence=0.99,
        detector="github_secret_v1",
        masked_evidence="[masked]",
        fingerprint="a" * 64,
        status=FindingStatus.OPEN,
        first_seen_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def test_suppression_is_exact_and_never_matches_raw_evidence() -> None:
    finding = _finding()
    assert suppression_matches({"fingerprint": "a" * 64}, finding)
    assert not suppression_matches({"fingerprint": "A" * 64}, finding)
    assert suppression_matches({"pattern": "github_secret_v1"}, finding)
    assert not suppression_matches({"pattern": "github_*"}, finding)
    assert not suppression_matches({"masked_evidence": "[masked]"}, finding)
    assert not suppression_matches({"fingerprint": "a" * 64, "path": "/x"}, finding)


def test_policy_diff_is_sorted_and_omits_identity_and_version_metadata() -> None:
    before = {
        "policy_id": "a",
        "organization_id": "tenant",
        "version": 1,
        "name": "old",
        "enabled": True,
        "priority": 10,
        "conditions": {"channel": "api"},
        "action": "warn",
    }
    after = {
        **before,
        "policy_id": "different metadata",
        "version": 2,
        "name": "new",
        "conditions": {"channel": "file"},
        "action": "block",
    }
    changes = diff_snapshots(before, after)
    assert [change["path"] for change in changes] == [
        "name",
        "conditions.channel",
        "action",
    ]


def test_exception_allows_only_its_target_policy_and_keeps_strictest_wins() -> None:
    organization_id = uuid4()
    now = datetime.now(UTC)
    principal = Principal(
        organization_id=organization_id,
        subject_id="exception-user",
        actor_type=ActorType.USER,
        role=Role.OWNER,
        scopes=("scan:request",),
        auth_method=AuthMethod.JWT,
    )
    request = ScanRequest(channel=DataChannel.API, content=SecretStr("private"))
    target = Policy(
        policy_id=uuid4(),
        organization_id=organization_id,
        name="target",
        enabled=True,
        priority=1,
        conditions={"channel": "api"},
        action=PolicyAction.BLOCK,
        version=1,
        created_at=now,
        updated_at=now,
    )
    other = target.model_copy(update={"policy_id": uuid4(), "name": "other"})
    modified, applied = apply_exceptions(
        policies=(target, other),
        exceptions=(
            {
                "id": "exception-safe-id",
                "policy_id": str(target.policy_id),
                "scope": {"channel": "api"},
            },
        ),
        request=request,
        principal=principal,
        findings=(),
        destinations=(),
    )
    assert modified[0].action is PolicyAction.ALLOW
    assert modified[1].action is PolicyAction.BLOCK
    assert applied == (("exception-safe-id", str(target.policy_id)),)


def test_sandbox_evaluates_only_draft_without_persisting_or_exposing_content() -> None:
    organization_id = uuid4()
    principal = Principal(
        organization_id=organization_id,
        subject_id="sandbox-user",
        actor_type=ActorType.USER,
        role=Role.OWNER,
        scopes=("identity:read",),
        auth_method=AuthMethod.JWT,
    )
    now = datetime.now(UTC)
    draft = Policy(
        policy_id=uuid4(),
        organization_id=organization_id,
        name="draft",
        enabled=True,
        priority=10,
        conditions={"channel": "api"},
        action=PolicyAction.BLOCK,
        version=1,
        created_at=now,
        updated_at=now,
    )
    request = ScanRequest(channel=DataChannel.API, content=SecretStr("private sample"))
    decision, label = evaluate_sandbox(
        engine=PolicyEngine(),
        draft=draft,
        request=request,
        principal=principal,
        findings=(),
        destinations=(
            Destination(
                destination_id=uuid4(),
                organization_id=organization_id,
                destination_class="public",
                kind="domain",
                pattern="example.com",
            ),
        ),
        mode="sandbox",
    )
    assert decision.action == PolicyAction.BLOCK
    assert label.startswith("sandbox:")
    assert "private sample" not in decision.reason
