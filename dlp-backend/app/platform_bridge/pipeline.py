"""Install this backend's extractors, detectors and alerting as the platform's
scan-pipeline stages (``/platform/scan`` and the CI gate)."""

import hashlib
import logging
from collections.abc import Sequence
from datetime import UTC, datetime
from uuid import uuid4

from app.services.alert_service import send_alert
from app.services.person_b import detection_service as detection

logger = logging.getLogger(__name__)

_CLASSIFICATION = {
    "api_key": "restricted", "credit_card": "restricted", "national_id": "restricted",
    "email_pii": "confidential", "phone_number": "confidential",
}


class _Extractor:
    """Platform scans carry text already; binary files go through /api/scans."""

    def extract(self, request) -> str:
        return request.content.get_secret_value()


class _Detector:
    def detect(self, extracted: str, request) -> Sequence:
        from dlp_platform.contracts.common import ClassificationLevel, SeverityLevel
        from dlp_platform.contracts.finding import Finding

        now = datetime.now(UTC)
        out = []
        for f in detection.detect(extracted):
            data_type = f.data_type.value
            classification = _CLASSIFICATION.get(data_type, "internal")
            if classification == "restricted":
                severity = SeverityLevel.CRITICAL if f.confidence >= 0.9 else SeverityLevel.HIGH
            elif classification == "confidential":
                severity = SeverityLevel.MEDIUM
            else:
                severity = SeverityLevel.LOW
            out.append(Finding(
                finding_id=uuid4(), data_type=data_type,
                classification=ClassificationLevel(classification), severity=severity,
                confidence=f.confidence, detector=(f.label or data_type)[:128],
                masked_evidence=(f.matched_snippet or "")[:512],
                fingerprint=hashlib.sha256(f"{data_type}|{f.matched_snippet}".encode()).hexdigest()[:64],
                first_seen_at=now,
            ))
        return out


class _Passthrough:
    def classify(self, findings): return findings
    def score(self, findings): return findings
    def fingerprint(self, findings): return findings
    def suppress(self, findings, principal): return findings
    def enforce(self, decision, findings): return decision


class _SeverityPolicy:
    """Fallback policy used until the platform's database-backed evaluator is installed."""

    def evaluate(self, findings, request, principal):
        from dlp_platform.contracts.common import PolicyAction

        levels = {str(f.severity) for f in findings}
        if levels & {"critical", "high"}:
            return PolicyAction.BLOCK
        if "medium" in levels:
            return PolicyAction.WARN
        return PolicyAction.LOG if findings else PolicyAction.ALLOW


class _AlertSink:
    def emit(self, request, principal, findings) -> None:
        if not findings:
            return
        top = findings[0]
        try:
            send_alert(decision="block", data_type=top.data_type, filename=None,
                       destination=request.destination or "platform", reason="Platform scan finding")
        except Exception:  # alerting must never fail a scan
            logger.warning("Platform alert could not be sent", exc_info=True)


class _AuditSink:
    def record_scan(self, principal, request_id, decision) -> None:
        logger.info("platform scan org=%s request=%s decision=%s", principal.organization_id, request_id, decision)


class _FindingStore:
    def store(self, principal, findings) -> None:
        if not findings:
            return
        from app import database

        try:
            rows = [{
                "org_id": str(principal.organization_id), "user_id": str(principal.subject_id),
                "severity": str(f.severity), "classification": str(f.classification), "data_type": f.data_type,
                "source": "platform", "detector": f.detector, "confidence": f.confidence,
                "masked_evidence": f.masked_evidence, "fingerprint": f.fingerprint,
            } for f in findings]
            database.get_supabase().table("dlp_findings").insert(rows).execute()
        except Exception:
            logger.warning("Platform findings could not be persisted", exc_info=True)


def build_stages():
    from dlp_platform.scan.pipeline import PipelineStages

    p = _Passthrough()
    return PipelineStages(
        extractor=_Extractor(), detector=_Detector(), classifier=p, scorer=p, fingerprinter=p,
        suppressor=p, policy=_SeverityPolicy(), enforcer=p, alert_sink=_AlertSink(),
        audit_sink=_AuditSink(), finding_store=_FindingStore(),
    )


def install_pipeline() -> None:
    from dlp_platform.scan.pipeline import configure_pipeline

    configure_pipeline(build_stages())
