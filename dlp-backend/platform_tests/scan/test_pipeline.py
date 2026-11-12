"""P04 orchestration behavior against deterministic injected phase handoffs."""

from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
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
from dlp_platform.contracts.principal import Principal
from dlp_platform.contracts.scan_request import ScanRequest
from dlp_platform.scan.errors import DetectorFailure, IdempotencyConflict, PolicyDecisionFailure
from dlp_platform.scan.fakes import (
    FakeAlertSink,
    FakeAuditSink,
    FakeClassifier,
    FakeEnforcer,
    FakeExtractor,
    FakeFindingStore,
    FakeFingerprinter,
    FakeScorer,
    FakeSuppressor,
)
from dlp_platform.scan.idempotency import InMemoryIdempotencyStore
from dlp_platform.scan.interfaces import PolicyDecision, PolicyEvaluator, SuppressionOutcome
from dlp_platform.scan.pipeline import PipelineStages, ScanPipeline

ORG_A = UUID("11111111-1111-4111-8111-111111111111")
ORG_B = UUID("22222222-2222-4222-8222-222222222222")
REQUEST_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")


def principal(org_id: UUID = ORG_A) -> Principal:
    return Principal(
        organization_id=org_id,
        subject_id="synthetic-user",
        actor_type=ActorType.USER,
        role=Role.OWNER,
        scopes=("scan:request",),
        auth_method=AuthMethod.JWT,
    )


def request(
    content: str = "synthetic sensitive input", request_id: UUID = REQUEST_ID
) -> ScanRequest:
    return ScanRequest(request_id=request_id, channel=DataChannel.API, content=SecretStr(content))


def finding() -> Finding:
    return Finding(
        finding_id=uuid4(),
        data_type="synthetic-secret",
        classification=ClassificationLevel.CONFIDENTIAL,
        severity=SeverityLevel.HIGH,
        confidence=0.99,
        detector="test-double",
        masked_evidence="[masked]",
        status=FindingStatus.OPEN,
        first_seen_at=datetime.now(UTC),
    )


class CountingDetector:
    def __init__(self) -> None:
        self.calls = 0

    def detect(self, extracted: str, scan_request: ScanRequest) -> Sequence[Finding]:
        self.calls += 1
        assert extracted == scan_request.content.get_secret_value()
        return (finding(),)


class FailingDetector:
    def detect(self, extracted: str, scan_request: ScanRequest) -> Sequence[Finding]:
        del extracted, scan_request
        raise RuntimeError("raw synthetic payload should not reach API or logs")


class FailingPolicy:
    def evaluate(self, findings, scan_request, scan_principal) -> PolicyAction:
        del findings, scan_request, scan_principal
        raise RuntimeError("policy backend unavailable")


class FixedPolicy:
    def __init__(self, action: PolicyAction) -> None:
        self.action = action
        self.calls = 0

    def evaluate(self, findings, scan_request, scan_principal) -> PolicyAction:
        del findings, scan_request, scan_principal
        self.calls += 1
        return self.action


def stages(detector=None, policy: PolicyEvaluator | None = None) -> PipelineStages:
    return PipelineStages(
        extractor=FakeExtractor(),
        detector=detector or CountingDetector(),
        classifier=FakeClassifier(),
        scorer=FakeScorer(),
        fingerprinter=FakeFingerprinter(),
        suppressor=FakeSuppressor(),
        policy=policy or FixedPolicy(PolicyAction.ALLOW),
        enforcer=FakeEnforcer(),
        alert_sink=FakeAlertSink(),
        audit_sink=FakeAuditSink(),
        finding_store=FakeFindingStore(),
    )


def test_pipeline_calls_handoffs_and_normalizes_contract_findings() -> None:
    detector, policy = CountingDetector(), FixedPolicy(PolicyAction.BLOCK)
    result = ScanPipeline(stages(detector, policy), InMemoryIdempotencyStore()).scan(
        request(), principal()
    )
    assert detector.calls == 1
    assert policy.calls == 1
    assert result.decision is PolicyAction.BLOCK
    assert len(result.findings) == 1
    assert result.findings[0].masked_evidence == "[masked]"


def test_idempotent_retry_returns_same_result_without_second_pipeline_execution() -> None:
    detector, store = CountingDetector(), InMemoryIdempotencyStore()
    pipeline = ScanPipeline(stages(detector), store)
    first = pipeline.scan(request(), principal())
    second = pipeline.scan(request(), principal())
    assert first == second
    assert detector.calls == 1


def test_idempotency_is_tenant_scoped_and_conflicting_reuse_is_rejected() -> None:
    store = InMemoryIdempotencyStore()
    pipeline = ScanPipeline(stages(), store)
    result_a = pipeline.scan(request(), principal(ORG_A))
    result_b = pipeline.scan(request(), principal(ORG_B))
    assert result_a.scan_id != result_b.scan_id
    with pytest.raises(IdempotencyConflict):
        pipeline.scan(request("different input"), principal(ORG_A))


def test_detector_failure_releases_reservation_for_retry() -> None:
    store = InMemoryIdempotencyStore()
    with pytest.raises(DetectorFailure):
        ScanPipeline(stages(FailingDetector()), store).scan(request(), principal())
    retry = ScanPipeline(stages(), store).scan(request(), principal())
    assert retry.decision is PolicyAction.ALLOW


def test_policy_failure_is_not_converted_to_allow_and_can_retry() -> None:
    store = InMemoryIdempotencyStore()
    with pytest.raises(PolicyDecisionFailure):
        ScanPipeline(stages(policy=FailingPolicy()), store).scan(request(), principal())
    retry = ScanPipeline(stages(), store).scan(request(), principal())
    assert retry.decision is PolicyAction.ALLOW


def test_content_size_limit_rejects_oversized_input(monkeypatch) -> None:
    monkeypatch.setenv("SCAN_MAX_CONTENT_BYTES", "3")
    from dlp_platform.scan.errors import ScanInputTooLarge

    with pytest.raises(ScanInputTooLarge):
        ScanPipeline(stages(), InMemoryIdempotencyStore()).scan(request("four"), principal())


@pytest.mark.parametrize("channel", [DataChannel.FILE, DataChannel.API, DataChannel.REPOSITORY])
def test_file_paste_and_repository_shapes_use_the_same_scan_pipeline(channel) -> None:
    payload = ScanRequest(channel=channel, content=SecretStr("synthetic input"))
    result = ScanPipeline(stages(), InMemoryIdempotencyStore()).scan(payload, principal())
    assert result.request_id == payload.request_id
    assert result.decision is PolicyAction.ALLOW


def test_exception_and_suppression_hooks_share_the_scan_start_clock() -> None:
    scan_started_at = datetime(2026, 10, 22, 9, 0, tzinfo=UTC)

    class AdvancingClock:
        value = scan_started_at

        def now(self) -> datetime:
            return self.value

    class TimedSuppressor:
        def suppress(self, findings, principal):
            return findings

        def suppress_at(self, findings, principal, started_at):
            assert started_at == scan_started_at
            clock.value += timedelta(hours=2)
            return SuppressionOutcome(tuple(findings), ("suppression-id",))

    class TimedPolicy:
        received_at = None

        def evaluate(self, findings, scan_request, scan_principal):
            return PolicyAction.ALLOW

        def evaluate_at(self, findings, scan_request, scan_principal, started_at):
            self.received_at = started_at
            return PolicyDecision(PolicyAction.WARN, "evaluated at scan start")

    clock = AdvancingClock()
    evaluator = TimedPolicy()
    pipeline_stages = replace(stages(policy=evaluator), suppressor=TimedSuppressor())
    result = ScanPipeline(pipeline_stages, InMemoryIdempotencyStore(), clock=clock).scan(
        request(request_id=uuid4()), principal()
    )
    assert evaluator.received_at == scan_started_at
    assert result.reason is not None and "suppression-id" in result.reason
    assert clock.value == scan_started_at + timedelta(hours=2)
