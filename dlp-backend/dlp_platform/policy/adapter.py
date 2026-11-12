"""P04 PolicyEvaluator adapter backed by the P05 engine and tenant repository."""

from collections.abc import Sequence

from dlp_platform.contracts.finding import Finding
from dlp_platform.contracts.principal import Principal
from dlp_platform.contracts.scan_request import ScanRequest
from dlp_platform.policy.engine import PolicyEngine
from dlp_platform.policy.repository import PolicyRepository
from dlp_platform.scan.interfaces import PolicyDecision


class DatabasePolicyEvaluator:
    def __init__(self, repository: PolicyRepository, engine: PolicyEngine | None = None) -> None:
        self.repository = repository
        self.engine = engine or PolicyEngine()

    def evaluate(
        self, findings: Sequence[Finding], request: ScanRequest, principal: Principal
    ) -> PolicyDecision:
        policies, destinations = self.repository.load(principal.organization_id)
        return self.engine.evaluate(
            organization_id=principal.organization_id,
            request=request,
            principal=principal,
            findings=findings,
            policies=policies,
            destinations=destinations,
        )
