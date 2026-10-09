import logging
from typing import Annotated

from fastapi import APIRouter, Depends

from app import database
from app.auth import AuthenticatedPrincipal, get_current_principal, require_org_membership
from app.models.finding import DlpEvent, ScanRequest, ScanResult
from app.services import policy_engine
from app.services.person_b import detection_service
from app.services.alert_service import send_alert

router = APIRouter(prefix="/api/scan", tags=["scan"])
logger = logging.getLogger(__name__)
Principal = Annotated[AuthenticatedPrincipal, Depends(get_current_principal)]


@router.post("", response_model=ScanResult)
def scan(request: ScanRequest, principal: Principal) -> ScanResult:
    """
    The single entry point every channel (extension, email watcher, Drive
    webhook) calls. This is the Phase-1 wire-up: detection -> policy ->
    persisted event. Channels only need to build a ScanRequest and POST here.
    """
    require_org_membership(principal, request.org_id)

    findings = detection_service.detect(
        request.content, org_id=request.org_id, filename=request.filename
    )
    decision, policy_id, reason = policy_engine.evaluate(request, findings)

    top_finding = findings[0] if findings else None
    event = DlpEvent(
        org_id=request.org_id,
        user_id=principal.user_id,
        channel=request.channel,
        data_type=top_finding.data_type if top_finding else "custom",
        confidence=top_finding.confidence if top_finding else 0.0,
        destination=request.destination,
        decision=decision,
        snippet=top_finding.matched_snippet if top_finding else "",
    )
    _persist_event(event)

    if top_finding and decision.value in {"block", "warn"}:
        alert = send_alert(
            decision=decision.value,
            data_type=top_finding.data_type.value,
            filename=request.filename,
            destination=request.destination,
            reason=reason,
        )
        if not alert["sent"] and alert["reason"] != "No alert required":
            logger.warning("DLP alert was not sent: %s", alert["reason"])

    return ScanResult(findings=findings, decision=decision, matched_policy_id=policy_id, reason=reason)


def _persist_event(event: DlpEvent) -> None:
    # The database generates id and created_at on insert.
    payload = {
        "org_id": str(event.org_id),
        "user_id": str(event.user_id),
        "channel": event.channel.value,
        "data_type": event.data_type.value,
        "confidence": event.confidence,
        "destination": event.destination,
        "decision": event.decision.value,
        "snippet": event.snippet,
    }
    database.post_scan_event(payload)
