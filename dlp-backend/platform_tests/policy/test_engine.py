"""Deterministic condition, destination, priority, and tenant behavior tests."""

from datetime import UTC, datetime
from itertools import product
from uuid import UUID, uuid4

import pytest
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
from dlp_platform.policy.engine import PolicyEngine, PolicyEvaluationError
from dlp_platform.policy.matching import normalize_destination_pattern, resolve_destination_class
from dlp_platform.policy.models import Destination, validate_conditions

ORG_A = UUID("11111111-1111-4111-8111-111111111111")
ORG_B = UUID("22222222-2222-4222-8222-222222222222")


def principal(org: UUID = ORG_A, role: Role = Role.OWNER) -> Principal:
    return Principal(
        organization_id=org,
        subject_id="policy-test-subject",
        actor_type=ActorType.USER,
        role=role,
        scopes=("scan:request",),
        auth_method=AuthMethod.JWT,
    )


def request(
    *,
    channel: DataChannel = DataChannel.API,
    destination: str | None = None,
    content: str = "secret",
    context: dict[str, str | int | bool] | None = None,
) -> ScanRequest:
    return ScanRequest(
        channel=channel, destination=destination, content=SecretStr(content), context=context or {}
    )


def policy(
    conditions: dict[str, object],
    action: PolicyAction = PolicyAction.BLOCK,
    *,
    priority: int = 100,
    org: UUID = ORG_A,
    policy_id: UUID | None = None,
    enabled: bool = True,
    version: int = 1,
) -> Policy:
    return Policy(
        policy_id=policy_id or uuid4(),
        organization_id=org,
        name="test policy",
        enabled=enabled,
        priority=priority,
        conditions=conditions,
        action=action,
        version=version,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )


def finding(
    data_type: str = "secret",
    classification: ClassificationLevel = ClassificationLevel.CONFIDENTIAL,
) -> Finding:
    return Finding(
        finding_id=uuid4(),
        data_type=data_type,
        classification=classification,
        severity=SeverityLevel.HIGH,
        confidence=0.99,
        detector="test",
        masked_evidence="[masked]",
        status=FindingStatus.OPEN,
        first_seen_at=datetime.now(UTC),
    )


@pytest.mark.parametrize(
    ("channel", "actual_channel", "should_match"),
    [(item, item, True) for item in DataChannel]
    + [
        (DataChannel.API, DataChannel.FILE, False),
        (DataChannel.API, DataChannel.BROWSER, False),
        (DataChannel.API, DataChannel.DATABASE, False),
    ],
)
def test_channel_condition_matrix(
    channel: DataChannel, actual_channel: DataChannel, should_match: bool
) -> None:
    cond = {"channel": channel.value}
    scan = request(channel=actual_channel)
    decision = PolicyEngine().evaluate(
        organization_id=ORG_A,
        request=scan,
        principal=principal(),
        findings=(),
        policies=(policy(cond),),
        destinations=(),
    )
    assert decision.action == (PolicyAction.BLOCK if should_match else PolicyAction.ALLOW)


@pytest.mark.parametrize(
    ("key", "expected", "actual", "findings"),
    [
        ("destination_class", "public", "public", ()),
        ("destination_class", "public", "partner", ()),
        ("user_group", "owner", "owner", ()),
        ("user_group", "owner", "admin", ()),
        ("data_type", "secret", "secret", (finding("secret"),)),
        ("data_type", "secret", "token", (finding("token"),)),
        ("classification", "confidential", "confidential", (finding(),)),
        (
            "classification",
            "confidential",
            "restricted",
            (finding(classification=ClassificationLevel.RESTRICTED),),
        ),
        ("volume", 6, 6, ()),
        ("volume", 6, 5, ()),
        ("file_type", "pdf", "pdf", ()),
        ("file_type", "pdf", "docx", ()),
    ],
)
def test_condition_family_matrix(
    key: str, expected: object, actual: object, findings: tuple[Finding, ...]
) -> None:
    context = {"file_type": actual} if key == "file_type" else None
    content = "x" * actual if key == "volume" and isinstance(actual, int) else "secret"
    destinations = (
        (
            Destination(
                destination_id=uuid4(),
                organization_id=ORG_A,
                destination_class=str(actual),
                kind="domain",
                pattern="example.com",
            ),
        )
        if key == "destination_class"
        else ()
    )
    principal_value = principal(role=Role(str(actual))) if key == "user_group" else principal()
    req = request(content=content, destination="example.com", context=context)
    decision = PolicyEngine().evaluate(
        organization_id=ORG_A,
        request=req,
        principal=principal_value,
        findings=findings,
        policies=(policy({key: expected}),),
        destinations=destinations,
    )
    assert decision.action == (PolicyAction.BLOCK if expected == actual else PolicyAction.ALLOW)


@pytest.mark.parametrize(
    ("conditions", "expected"),
    [
        ({}, PolicyAction.BLOCK),
        ({"channel": ["api", "file"]}, PolicyAction.BLOCK),
        ({"channel": "file"}, PolicyAction.ALLOW),
        ({"channel": "api", "destination_class": "public"}, PolicyAction.BLOCK),
        ({"channel": "api", "destination_class": "public"}, PolicyAction.BLOCK),
        ({"volume": 0}, PolicyAction.ALLOW),
        ({"volume": 6}, PolicyAction.BLOCK),
        ({"user_group": ["owner", "admin"]}, PolicyAction.BLOCK),
        ({"file_type": ["pdf", "docx"]}, PolicyAction.BLOCK),
    ],
)
def test_condition_composition_and_lists(
    conditions: dict[str, object], expected: PolicyAction
) -> None:
    destinations = (
        (
            Destination(
                destination_id=uuid4(),
                organization_id=ORG_A,
                destination_class="public",
                kind="domain",
                pattern="example.com",
            ),
        )
        if "destination_class" in conditions
        else ()
    )
    decision = PolicyEngine().evaluate(
        organization_id=ORG_A,
        request=request(destination="example.com", context={"file_type": "pdf"}),
        principal=principal(),
        findings=(),
        policies=(policy(conditions),),
        destinations=destinations,
    )
    assert decision.action == expected


def test_strictest_action_wins_then_priority_and_uuid_tie_break() -> None:
    allow = policy({}, PolicyAction.ALLOW, priority=1)
    warn = policy({}, PolicyAction.WARN, priority=90)
    block = policy({}, PolicyAction.BLOCK, priority=100)
    decision = PolicyEngine().evaluate(
        organization_id=ORG_A,
        request=request(),
        principal=principal(),
        findings=(),
        policies=(allow, warn, block),
        destinations=(),
    )
    assert decision.action == PolicyAction.BLOCK
    assert decision.policy_id == str(block.policy_id)
    assert decision.policy_version == "1"
    assert decision.reason and decision.evaluation_trace


def test_equal_action_priority_uses_stable_uuid_tie_breaker() -> None:
    larger = policy({}, PolicyAction.WARN, priority=20, policy_id=UUID(int=20))
    smaller = policy({}, PolicyAction.WARN, priority=20, policy_id=UUID(int=10), version=4)
    decision = PolicyEngine().evaluate(
        organization_id=ORG_A,
        request=request(),
        principal=principal(),
        findings=(),
        policies=(larger, smaller),
        destinations=(),
    )
    assert decision.policy_id == str(smaller.policy_id)
    assert decision.policy_version == "4"


def test_destination_class_condition_does_not_match_when_destination_is_unmapped() -> None:
    decision = PolicyEngine().evaluate(
        organization_id=ORG_A,
        request=request(destination="unknown.example"),
        principal=principal(),
        findings=(),
        policies=(policy({"destination_class": "public"}),),
        destinations=(),
    )
    assert decision.action == PolicyAction.ALLOW
    assert "No enabled policy matched" in decision.reason


def test_disabled_and_other_tenant_policies_do_not_match() -> None:
    decision = PolicyEngine().evaluate(
        organization_id=ORG_A,
        request=request(),
        principal=principal(),
        findings=(),
        policies=(policy({}, enabled=False), policy({}, org=ORG_B)),
        destinations=(),
    )
    assert decision.action == PolicyAction.ALLOW
    assert decision.policy_id is None


def test_principal_tenant_mismatch_rejected() -> None:
    with pytest.raises(PolicyEvaluationError, match="principal tenant mismatch"):
        PolicyEngine().evaluate(
            organization_id=ORG_A,
            request=request(),
            principal=principal(ORG_B),
            findings=(),
            policies=(),
            destinations=(),
        )


@pytest.mark.parametrize(
    "conditions",
    [
        {"bad": "x"},
        {"channel": "unknown"},
        {"destination_class": "unknown"},
        {"user_group": "root"},
        {"classification": "unknown"},
        {"data_type": ""},
        {"file_type": "x" * 129},
        {"volume": -1},
        {"volume": True},
        {"volume": 1.5},
        {"channel": []},
        {"channel": None},
        {"channel": ["api"] * 101},
    ],
)
def test_invalid_conditions_are_rejected(conditions: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        validate_conditions(conditions)


@pytest.mark.parametrize(
    ("pattern", "destination", "matches"),
    [
        ("example.com", "example.com", True),
        ("example.com", "https://example.com/path", True),
        ("example.com", "www.example.com", False),
        ("*.example.com", "www.example.com", True),
        ("*.example.com", "example.com", False),
        ("*.example.com", "a.b.example.com", True),
        ("team/repo", "team/repo", True),
        ("team/repo", "team/other", False),
        ("example.com", "user@example.com", True),
        ("*.example.com", "user@example.com", False),
    ],
)
def test_destination_matching(pattern: str, destination: str, matches: bool) -> None:
    kind = "repo" if "/" in pattern else ("email_domain" if "@" in destination else "domain")
    normalized = normalize_destination_pattern(kind, pattern)
    item = Destination(
        destination_id=uuid4(),
        organization_id=ORG_A,
        destination_class="public",
        kind=kind,
        pattern=normalized,
    )
    assert (resolve_destination_class(destination, (item,)) == "public") is matches


def test_destination_resolution_is_deterministic_and_tenant_scoped() -> None:
    wildcard = Destination(
        destination_id=UUID(int=2),
        organization_id=ORG_A,
        destination_class="public",
        kind="domain",
        pattern="*.example.com",
    )
    exact = Destination(
        destination_id=UUID(int=3),
        organization_id=ORG_A,
        destination_class="internal",
        kind="domain",
        pattern="api.example.com",
    )
    other = Destination(
        destination_id=UUID(int=1),
        organization_id=ORG_B,
        destination_class="personal",
        kind="domain",
        pattern="api.example.com",
    )
    assert resolve_destination_class("api.example.com", (wildcard, exact, other)) == "internal"
    assert resolve_destination_class("api.example.com", (other, exact, wildcard)) == "internal"


@pytest.mark.parametrize(
    "left,right",
    product(
        (PolicyAction.ALLOW, PolicyAction.LOG, PolicyAction.WARN, PolicyAction.BLOCK), repeat=2
    ),
)
def test_strictness_is_monotonic(left: PolicyAction, right: PolicyAction) -> None:
    result = PolicyEngine().evaluate(
        organization_id=ORG_A,
        request=request(),
        principal=principal(),
        findings=(),
        policies=(policy({}, left), policy({}, right)),
        destinations=(),
    )
    rank = {PolicyAction.ALLOW: 0, PolicyAction.LOG: 1, PolicyAction.WARN: 2, PolicyAction.BLOCK: 3}
    assert rank[result.action] >= rank[left]
    assert rank[result.action] >= rank[right]
