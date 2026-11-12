"""Explicit deterministic test/development doubles; these are not security engines."""

from collections.abc import Sequence

from dlp_platform.contracts.common import PolicyAction
from dlp_platform.contracts.finding import Finding
from dlp_platform.contracts.principal import Principal
from dlp_platform.contracts.scan_request import ScanRequest


class FakeExtractor:
    """Test double that passes through already supplied text without retaining it."""

    def extract(self, request: ScanRequest) -> str:
        return request.content.get_secret_value()


class FakeDetector:
    """Test double that reports no findings; it performs no detection."""

    def detect(self, extracted: str, request: ScanRequest) -> Sequence[Finding]:
        del extracted, request
        return ()


class FakeClassifier:
    def classify(self, findings: Sequence[Finding]) -> Sequence[Finding]:
        return findings


class FakeScorer:
    def score(self, findings: Sequence[Finding]) -> Sequence[Finding]:
        return findings


class FakeFingerprinter:
    def fingerprint(self, findings: Sequence[Finding]) -> Sequence[Finding]:
        return findings


class FakeSuppressor:
    def suppress(self, findings: Sequence[Finding], principal: Principal) -> Sequence[Finding]:
        del principal
        return findings


class FakePolicyEvaluator:
    """Deterministic P05 handoff double; contains no policy rules."""

    def evaluate(
        self, findings: Sequence[Finding], request: ScanRequest, principal: Principal
    ) -> PolicyAction:
        del findings, request, principal
        return PolicyAction.ALLOW


class FakeEnforcer:
    def enforce(self, decision: PolicyAction, findings: Sequence[Finding]) -> PolicyAction:
        del findings
        return decision


class FakeAlertSink:
    def emit(self, request: ScanRequest, principal: Principal, findings: Sequence[Finding]) -> None:
        del request, principal, findings


class FakeAuditSink:
    def record_scan(self, principal: Principal, request_id: str, decision: PolicyAction) -> None:
        del principal, request_id, decision


class FakeFindingStore:
    def store(self, principal: Principal, findings: Sequence[Finding]) -> None:
        del principal, findings
