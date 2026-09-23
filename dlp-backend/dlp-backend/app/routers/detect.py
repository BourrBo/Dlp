from fastapi import APIRouter

from app.database import get_supabase
from app.models.finding import DlpEvent, ScanRequest, ScanResult
from app.services import detection_service, policy_engine

router = APIRouter(prefix="/api/scan", tags=["scan"])


@router.post("", response_model=ScanResult)
def scan(request: ScanRequest) -> ScanResult:
    """
    The single entry point every channel (extension, email watcher, Drive
    webhook) calls. This is the Phase-1 wire-up: detection -> policy ->
    persisted event. Channels only need to build a ScanRequest and POST here.
    """
    findings = detection_service.detect(request.content)
    decision, policy_id, reason = policy_engine.evaluate(request, findings)

    top_finding = findings[0] if findings else None
    event = DlpEvent(
        org_id=request.org_id,
        user_id=request.user_id,
        channel=request.channel,
        data_type=top_finding.data_type if top_finding else "custom",
        confidence=top_finding.confidence if top_finding else 0.0,
        destination=request.destination,
        decision=decision,
        snippet=top_finding.matched_snippet if top_finding else "",
    )
    _persist_event(event)

    return ScanResult(findings=findings, decision=decision, matched_policy_id=policy_id, reason=reason)


def _persist_event(event: DlpEvent) -> None:
    supabase = get_supabase()
    payload = event.model_dump(mode="json")
    supabase.table("dlp_events").insert(payload).execute()
