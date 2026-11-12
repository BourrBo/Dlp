"""Pure deterministic P05 policy evaluation; this module executes no policy code."""

from collections.abc import Sequence
from uuid import UUID

from dlp_platform.contracts.common import PolicyAction
from dlp_platform.contracts.finding import Finding
from dlp_platform.contracts.policy import Policy
from dlp_platform.contracts.principal import Principal
from dlp_platform.contracts.scan_request import ScanRequest
from dlp_platform.policy.matching import matched_condition_names, policy_matches, resolve_destination_class
from dlp_platform.policy.models import Destination, PolicyMatch
from dlp_platform.scan.interfaces import PolicyDecision

STRICTNESS = {
    PolicyAction.BLOCK: 7,
    PolicyAction.QUARANTINE: 6,
    PolicyAction.REVOKE_SHARE: 6,
    PolicyAction.REDACT: 5,
    PolicyAction.REQUIRE_APPROVAL: 4,
    PolicyAction.WARN: 2,
    PolicyAction.LOG: 1,
    PolicyAction.ALLOW: 0,
}


class PolicyEvaluationError(Exception):
    """Safe internal error raised for invalid or untrusted policy data."""


class PolicyEngine:
    def evaluate(
        self,
        *,
        organization_id: UUID,
        request: ScanRequest,
        principal: Principal,
        findings: Sequence[Finding],
        policies: Sequence[Policy],
        destinations: Sequence[Destination],
    ) -> PolicyDecision:
        if principal.organization_id != organization_id:
            raise PolicyEvaluationError("principal tenant mismatch")
        tenant_policies = tuple(
            policy for policy in policies if policy.organization_id == organization_id
        )
        tenant_destinations = tuple(
            item for item in destinations if item.organization_id == organization_id
        )
        destination_class = resolve_destination_class(request.destination, tenant_destinations)
        normalized_findings = tuple(findings)
        matches: list[PolicyMatch] = []
        for policy in tenant_policies:
            if not policy.enabled:
                continue
            if policy.action not in STRICTNESS:
                raise PolicyEvaluationError("unsupported action in stored policy")
            if policy_matches(
                policy.conditions,
                request,
                principal,
                normalized_findings,
                destination_class,
            ):
                matches.append(
                    PolicyMatch(
                        policy_id=policy.policy_id,
                        action=policy.action,
                        priority=policy.priority,
                        version=policy.version,
                        matched_conditions=matched_condition_names(policy.conditions),
                    )
                )

        if not matches:
            return PolicyDecision(
                action=PolicyAction.ALLOW,
                reason="No enabled policy matched; default action is allow.",
                evaluation_trace=(),
            )

        # Strictest action wins [SRC]. For equally strict outcomes, lower numeric
        # priority wins [REC]; policy UUID is the stable final tie-breaker [REC].
        matches.sort(
            key=lambda match: (
                -STRICTNESS[match.action],
                match.priority,
                str(match.policy_id),
            )
        )
        winner = matches[0]
        conditions_text = ", ".join(winner.matched_conditions) or "unconditional match"
        trace = tuple(
            f"policy={item.policy_id}; action={item.action.value}; priority={item.priority}"
            for item in matches
        )
        reason = (
            f"Policy {winner.policy_id} matched conditions: {conditions_text}; "
            f"decision={winner.action.value}. Evaluation trace: {' | '.join(trace)}"
        )
        return PolicyDecision(
            action=winner.action,
            policy_id=str(winner.policy_id),
            policy_version=str(winner.version),
            matched_conditions=winner.matched_conditions,
            evaluation_trace=trace,
            reason=reason,
        )
