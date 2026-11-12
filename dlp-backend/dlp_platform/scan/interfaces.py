"""Narrow phase handoffs. Implementations must not retain or log raw input."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

from dlp_platform.contracts.common import PolicyAction
from dlp_platform.contracts.finding import Finding
from dlp_platform.contracts.principal import Principal
from dlp_platform.contracts.scan_request import ScanRequest
from dlp_platform.contracts.scan_result import ScanResult


@dataclass(frozen=True)
class PolicyDecision:
    """Structured P04-to-policy handoff; ScanResult remains the external contract."""

    action: PolicyAction
    reason: str
    policy_id: str | None = None
    policy_version: str | None = None
    matched_conditions: tuple[str, ...] = ()
    evaluation_trace: tuple[str, ...] = ()


@dataclass(frozen=True)
class SuppressionOutcome:
    """Findings left for policy evaluation plus safe identifiers of applied rules."""

    findings: tuple[Finding, ...]
    applied_ids: tuple[str, ...] = ()


@runtime_checkable
class ScanStartSuppressor(Protocol):
    def suppress_at(
        self, findings: Sequence[Finding], principal: Principal, scan_started_at: datetime
    ) -> SuppressionOutcome: ...


@runtime_checkable
class ScanStartPolicyEvaluator(Protocol):
    def evaluate_at(
        self,
        findings: Sequence[Finding],
        request: ScanRequest,
        principal: Principal,
        scan_started_at: datetime,
    ) -> PolicyAction | PolicyDecision: ...


class Extractor(Protocol):
    def extract(self, request: ScanRequest) -> str: ...


class Detector(Protocol):
    def detect(self, extracted: str, request: ScanRequest) -> Sequence[Finding]: ...


class Classifier(Protocol):
    def classify(self, findings: Sequence[Finding]) -> Sequence[Finding]: ...


class Scorer(Protocol):
    def score(self, findings: Sequence[Finding]) -> Sequence[Finding]: ...


class Fingerprinter(Protocol):
    def fingerprint(self, findings: Sequence[Finding]) -> Sequence[Finding]: ...


class Suppressor(Protocol):
    def suppress(
        self, findings: Sequence[Finding], principal: Principal
    ) -> Sequence[Finding] | SuppressionOutcome: ...


class PolicyEvaluator(Protocol):
    def evaluate(
        self, findings: Sequence[Finding], request: ScanRequest, principal: Principal
    ) -> PolicyAction | PolicyDecision: ...


class Enforcer(Protocol):
    def enforce(self, decision: PolicyAction, findings: Sequence[Finding]) -> PolicyAction: ...


class Recorder(Protocol):
    def record(
        self, request: ScanRequest, principal: Principal, result: ScanResult, reservation: object
    ) -> None: ...


class AlertSink(Protocol):
    def emit(
        self, request: ScanRequest, principal: Principal, findings: Sequence[Finding]
    ) -> None: ...


class AuditSink(Protocol):
    def record_scan(
        self, principal: Principal, request_id: str, decision: PolicyAction
    ) -> None: ...


class FindingStore(Protocol):
    def store(self, principal: Principal, findings: Sequence[Finding]) -> None: ...
