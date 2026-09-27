"""
Policy Engine — your (lead) module.

Given a ScanRequest and the Findings the Detection Engine produced, decides
allow / warn / block / log. v1 logic: highest-confidence finding drives the
decision; a matching approved-destination on any policy for that data_type
downgrades BLOCK to ALLOW+LOG. Extend here as richer conditions are needed —
this is the single place enforcement decisions get made.
"""

from uuid import UUID

from app import database
from app.models.finding import Decision, Finding, ScanRequest
from app.models.policy import Policy


def evaluate(request: ScanRequest, findings: list[Finding]) -> tuple[Decision, UUID | None, str]:
    if not findings:
        return Decision.ALLOW, None, "No sensitive data detected"

    top = max(findings, key=lambda f: f.confidence)
    policy = _find_matching_policy(request.org_id, top.data_type, request.channel)

    if policy is None:
        # No explicit policy: fail safe to WARN rather than silently allowing
        # or hard-blocking on an unreviewed rule set.
        return Decision.WARN, None, f"No policy configured for {top.data_type.value} on {request.channel.value}"

    if top.confidence < policy.condition.min_confidence:
        return Decision.ALLOW, policy.id, "Confidence below policy threshold"

    if request.destination in policy.condition.approved_destinations:
        return Decision.LOG, policy.id, "Destination is on the approved list"

    return policy.action, policy.id, f"Matched policy for {top.data_type.value} on {request.channel.value}"


def _find_matching_policy(org_id: UUID, data_type, channel) -> Policy | None:
    row = database.get_policy(org_id=str(org_id), data_type=data_type.value, channel=channel.value)
    if not row:
        return None
    return Policy(**row)
