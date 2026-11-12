"""Side-effect-free draft and historical policy evaluation helpers."""

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from hashlib import sha256
from uuid import UUID

from dlp_platform.contracts.finding import Finding
from dlp_platform.contracts.policy import Policy
from dlp_platform.contracts.principal import Principal
from dlp_platform.contracts.scan_request import ScanRequest
from dlp_platform.policy.engine import PolicyEngine
from dlp_platform.policy.models import Destination
from dlp_platform.policy.versions import policy_snapshot
from dlp_platform.scan.interfaces import PolicyDecision


def evaluate_sandbox(
    *,
    engine: PolicyEngine,
    draft: Policy,
    request: ScanRequest,
    principal: Principal,
    findings: Sequence[Finding],
    destinations: Sequence[Destination],
    mode: str,
) -> tuple[PolicyDecision, str]:
    snapshot = policy_snapshot(draft)
    config_fingerprint = sha256(
        json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    decision = engine.evaluate(
        organization_id=principal.organization_id,
        request=request,
        principal=principal,
        findings=findings,
        policies=(draft,),
        destinations=destinations,
    )
    safe_reason = (
        f"P06 {mode} evaluation. {decision.reason} No events or live policy state were changed."
    )
    return PolicyDecision(
        action=decision.action,
        reason=safe_reason,
        policy_id=decision.policy_id or str(draft.policy_id),
        policy_version=decision.policy_version,
        matched_conditions=decision.matched_conditions,
        evaluation_trace=decision.evaluation_trace,
    ), f"{mode}:{config_fingerprint}"


def policy_from_snapshot(
    snapshot: dict[str, object], *, created_at: datetime, policy_id: UUID
) -> Policy:
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=UTC)
    priority = snapshot["priority"]
    version = snapshot["version"]
    if not isinstance(priority, int) or not isinstance(version, int):
        raise ValueError("Policy snapshot contains invalid numeric fields")
    return Policy(
        policy_id=policy_id,
        organization_id=UUID(str(snapshot["organization_id"])),
        name=str(snapshot["name"]),
        enabled=bool(snapshot["enabled"]),
        priority=priority,
        conditions=snapshot["conditions"],  # type: ignore[arg-type]
        action=snapshot["action"],  # type: ignore[arg-type]
        version=version,
        created_at=created_at,
        updated_at=created_at,
    )
