from typing import Annotated

from fastapi import APIRouter, Depends
import logging

from app import database
from app.auth import AuthenticatedPrincipal, get_scan_principal, resolve_org
from app.models.finding import DlpEvent, ScanRequest, ScanResult
from app.services import findings_service, policy_engine
from app.services.person_b import detection_service
from app.services.alert_service import send_alert

router = APIRouter(prefix="/api/scan", tags=["scan"])
logger = logging.getLogger(__name__)
Principal = Annotated[AuthenticatedPrincipal, Depends(get_scan_principal)]


@router.post("", response_model=ScanResult)
def scan(request: ScanRequest, principal: Principal) -> ScanResult:
    """
    The single entry point every channel (extension, email watcher, Drive
    webhook) calls. This is the Phase-1 wire-up: detection -> policy ->
    persisted event. Channels only need to build a ScanRequest and POST here.
    """
    request = request.model_copy(update={"org_id": resolve_org(principal, request.org_id)})
    return scan_for_verified_user(request, principal.user_id)


def scan_for_verified_user(request: ScanRequest, user_id) -> ScanResult:
    """Internal scan path for a user already authenticated by an API boundary.

    Background jobs use the principal stored at their authenticated submission;
    HTTP callers must go through ``scan`` above.
    """
    if request.org_id is None:
        raise ValueError("A scan requires a resolved organization")
    request = request.model_copy(update={"user_id": user_id})
    findings = detection_service.detect(
        request.content, org_id=request.org_id, filename=request.filename
    )
    decision, policy_id, reason = policy_engine.evaluate(request, findings)

    top_finding = findings[0] if findings else None
    event = DlpEvent(
        **({"id": request.event_id} if request.event_id else {}),
        org_id=request.org_id,
        user_id=request.user_id,
        channel=request.channel,
        data_type=top_finding.data_type if top_finding else "custom",
        confidence=top_finding.confidence if top_finding else 0.0,
        destination=request.destination,
        decision=decision,
        snippet=top_finding.matched_snippet if top_finding else "",
    )
    inserted = _persist_event(event)
    if inserted:
        findings_service.record_scan(request, findings, decision, policy_id, event.id)

    if inserted and top_finding and decision.value in {"block", "warn"}:
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


def _persist_event(event: DlpEvent) -> bool:
    # The database generates id and created_at on insert.
    payload = {
        "id": str(event.id),
        "org_id": str(event.org_id),
        "user_id": str(event.user_id),
        "channel": event.channel.value,
        "data_type": event.data_type.value,
        "confidence": event.confidence,
        "destination": event.destination,
        "decision": event.decision.value,
        "snippet": event.snippet,
    }
    return bool(database.post_scan_event(payload))
