"""P06 version, exception and deterministic evaluation orchestration."""

from collections.abc import Sequence
from dataclasses import replace
from datetime import datetime

from dlp_platform.clock import Clock, SystemClock
from dlp_platform.contracts.finding import Finding
from dlp_platform.contracts.principal import Principal
from dlp_platform.contracts.scan_request import ScanRequest
from dlp_platform.policy.adapter import DatabasePolicyEvaluator
from dlp_platform.policy.engine import PolicyEngine
from dlp_platform.policy.exceptions import ExceptionRepository, apply_exceptions
from dlp_platform.policy.repository import PolicyRepository
from dlp_platform.scan.interfaces import PolicyDecision


class PolicyLifecycleEvaluator(DatabasePolicyEvaluator):
    """P05 strictest-wins engine wrapped with P06 scan-start exception semantics."""

    def __init__(
        self,
        repository: PolicyRepository,
        engine: PolicyEngine | None = None,
        clock: Clock | None = None,
    ) -> None:
        super().__init__(repository, engine)
        self.clock = clock or SystemClock()
        self.exception_repository = ExceptionRepository(repository.engine)

    def evaluate(
        self, findings: Sequence[Finding], request: ScanRequest, principal: Principal
    ) -> PolicyDecision:
        return self.evaluate_at(findings, request, principal, self.clock.now())

    def evaluate_at(
        self,
        findings: Sequence[Finding],
        request: ScanRequest,
        principal: Principal,
        scan_started_at: datetime,
    ) -> PolicyDecision:
        policies, destinations = self.repository.load(principal.organization_id)
        active_exceptions = self.exception_repository.active_for_tenant(
            principal.organization_id, scan_started_at
        )
        policies, applied = apply_exceptions(
            policies=policies,
            exceptions=active_exceptions,
            request=request,
            principal=principal,
            findings=tuple(findings),
            destinations=destinations,
        )
        decision = self.engine.evaluate(
            organization_id=principal.organization_id,
            request=request,
            principal=principal,
            findings=findings,
            policies=policies,
            destinations=destinations,
        )
        if applied:
            trace = "; ".join(
                f"exception={exception_id} policy={policy_id} "
                f"scan_started_at={scan_started_at.isoformat()}"
                for exception_id, policy_id in applied
            )
            decision = replace(
                decision, reason=f"{decision.reason} P06 exception applied: {trace}."
            )
        return decision
