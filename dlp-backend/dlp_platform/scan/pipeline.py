"""Shared injectable scan orchestration used by all P2 collectors and the gate."""

import logging
import os
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from uuid import NAMESPACE_URL, uuid5

from dlp_platform.actions.service import ActionProcessor
from dlp_platform.clock import Clock, SystemClock
from dlp_platform.contracts.finding import Finding
from dlp_platform.contracts.principal import Principal
from dlp_platform.contracts.scan_request import ScanRequest
from dlp_platform.contracts.scan_result import ScanResult
from dlp_platform.scan.errors import (
    DetectorFailure,
    PipelineUnavailable,
    PolicyDecisionFailure,
    ScanInputTooLarge,
)
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
from dlp_platform.scan.idempotency import IdempotencyStore, get_idempotency_store
from dlp_platform.scan.interfaces import (
    AlertSink,
    AuditSink,
    Classifier,
    Detector,
    Enforcer,
    Extractor,
    FindingStore,
    Fingerprinter,
    PolicyDecision,
    PolicyEvaluator,
    ScanStartPolicyEvaluator,
    ScanStartSuppressor,
    Scorer,
    SuppressionOutcome,
    Suppressor,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PipelineStages:
    extractor: Extractor
    detector: Detector
    classifier: Classifier
    scorer: Scorer
    fingerprinter: Fingerprinter
    suppressor: Suppressor
    policy: PolicyEvaluator
    enforcer: Enforcer
    alert_sink: AlertSink
    audit_sink: AuditSink
    finding_store: FindingStore


def fake_stages() -> PipelineStages:
    """Return deterministic test doubles, never a production detector/policy engine."""
    return PipelineStages(
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


class ScanPipeline:
    def __init__(
        self, stages: PipelineStages, store: IdempotencyStore, clock: Clock | None = None
    ) -> None:
        self.stages = stages
        self.store = store
        self.clock = clock or SystemClock()

    def scan(self, request: ScanRequest, principal: Principal) -> ScanResult:
        max_bytes = int(os.getenv("SCAN_MAX_CONTENT_BYTES", "1048576"))
        if max_bytes < 1:
            raise RuntimeError("SCAN_MAX_CONTENT_BYTES must be positive")
        raw_content = request.content.get_secret_value()
        if len(raw_content.encode("utf-8")) > max_bytes:
            raise ScanInputTooLarge
        scan_started_at = self.clock.now()

        reservation = self.store.reserve(request, principal)
        if not reservation.is_new:
            assert reservation.result is not None
            return reservation.result

        try:
            extracted = self.stages.extractor.extract(request)
            try:
                findings = self.stages.detector.detect(extracted, request)
            except Exception as exc:
                raise DetectorFailure from exc
            findings = self.stages.classifier.classify(findings)
            findings = self.stages.scorer.score(findings)
            findings = self.stages.fingerprinter.fingerprint(findings)
            suppressor = self.stages.suppressor
            applied_suppressions: tuple[str, ...] = ()
            if isinstance(suppressor, ScanStartSuppressor):
                timed_suppression = suppressor.suppress_at(findings, principal, scan_started_at)
                if isinstance(timed_suppression, SuppressionOutcome):
                    applied_suppressions = timed_suppression.applied_ids
                    findings = timed_suppression.findings
                else:
                    findings = timed_suppression
            else:
                legacy_suppression = suppressor.suppress(findings, principal)
                if isinstance(legacy_suppression, SuppressionOutcome):
                    applied_suppressions = legacy_suppression.applied_ids
                    findings = legacy_suppression.findings
                else:
                    findings = legacy_suppression
            normalized = tuple(Finding.model_validate(item.model_dump()) for item in findings)
            try:
                policy_evaluator = self.stages.policy
                if isinstance(policy_evaluator, ScanStartPolicyEvaluator):
                    policy_result = policy_evaluator.evaluate_at(
                        normalized, request, principal, scan_started_at
                    )
                else:
                    policy_result = policy_evaluator.evaluate(normalized, request, principal)
            except Exception as exc:
                raise PolicyDecisionFailure from exc
            if isinstance(policy_result, PolicyDecision):
                if _action_processor is not None:
                    policy_result = _action_processor.process_policy_decision(
                        policy_result, request, principal
                    )
                decision = policy_result.action
                reason = policy_result.reason
                policy_version = policy_result.policy_version
                if applied_suppressions:
                    reason += " Suppression applied: " + ", ".join(applied_suppressions) + "."
            else:
                decision = policy_result
                reason = (
                    "no detection performed by configured fake detector"
                    if not normalized
                    else f"Scan completed with {len(normalized)} finding(s)"
                )
                policy_version = None
            decision = self.stages.enforcer.enforce(decision, normalized)
            scan_id = uuid5(
                NAMESPACE_URL,
                f"dlp-p04-scan:{principal.organization_id}:{request.request_id}",
            )
            result = ScanResult(
                scan_id=scan_id,
                request_id=request.request_id,
                decision=decision,
                reason=reason,
                findings=normalized,
                policy_version=policy_version,
                completed_at=datetime.now(UTC),
            )
            self.stages.finding_store.store(principal, normalized)
            self.stages.alert_sink.emit(request, principal, normalized)
            self.stages.audit_sink.record_scan(principal, str(request.request_id), decision)
            self.store.record(request, principal, result, reservation)
            return result
        except Exception:
            self.store.abort(request, principal, reservation)
            raise


_default_pipeline: ScanPipeline | None = None
_production_stages: PipelineStages | None = None
_policy_evaluator: PolicyEvaluator | None = None
_policy_suppressor: Suppressor | None = None
_action_processor: ActionProcessor | None = None


def configure_action_processor(processor: ActionProcessor | None) -> None:
    """Install P07 persistence for advanced policy decisions."""
    global _action_processor
    _action_processor = processor


def configure_pipeline(stages: PipelineStages, store: IdempotencyStore | None = None) -> None:
    """Install host-supplied P1/P3/P05 adapters during application startup."""
    global _production_stages, _default_pipeline
    if _policy_evaluator is not None:
        stages = replace(stages, policy=_policy_evaluator)
    if _policy_suppressor is not None:
        stages = replace(stages, suppressor=_policy_suppressor)
    _production_stages = stages
    _default_pipeline = ScanPipeline(stages, store or get_idempotency_store())


def configure_policy_evaluator(
    evaluator: PolicyEvaluator, suppressor: Suppressor | None = None
) -> None:
    """Install the P05 evaluator for the local default pipeline without claiming
    that the remaining P1/P3/P04 production adapters are ready."""
    global _policy_evaluator, _policy_suppressor, _default_pipeline
    _policy_evaluator = evaluator
    _policy_suppressor = suppressor
    _default_pipeline = None


def scan(
    request: ScanRequest,
    principal: Principal,
    stages: PipelineStages | None = None,
    store: IdempotencyStore | None = None,
) -> ScanResult:
    """P03-compatible call signature with explicit optional stage injection for P1/P3."""
    global _default_pipeline
    if stages is not None or store is not None:
        return ScanPipeline(stages or fake_stages(), store or get_idempotency_store()).scan(
            request, principal
        )
    if os.getenv("APP_ENV", "development") == "production" and _production_stages is None:
        raise PipelineUnavailable
    if _default_pipeline is None:
        stages = fake_stages()
        if _policy_evaluator is not None:
            stages = replace(stages, policy=_policy_evaluator)
        if _policy_suppressor is not None:
            stages = replace(stages, suppressor=_policy_suppressor)
        _default_pipeline = ScanPipeline(stages, get_idempotency_store())
    try:
        return _default_pipeline.scan(request, principal)
    except Exception as exc:
        # Log only stable code/type labels. Exception text and request content may be sensitive.
        logger.error(
            "Scan pipeline failed code=%s exception_type=%s",
            getattr(exc, "code", "internal_error"),
            type(exc).__name__,
        )
        raise
