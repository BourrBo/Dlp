"""Persist scan findings and open/refresh incidents.

Only masked evidence is stored. Every function here is best-effort: a storage
failure is logged and never fails or delays the scan decision itself.
"""

import hashlib
import logging
from datetime import datetime, timezone
from uuid import UUID

import httpx

from app import database
from app.models.finding import Decision, Finding, ScanRequest

logger = logging.getLogger(__name__)

_CLASSIFICATION = {
    "api_key": "credentials",
    "credit_card": "financial data",
    "national_id": "personal information",
    "email_pii": "personal information",
    "phone_number": "personal information",
}
_INCIDENT_DECISIONS = {Decision.BLOCK, Decision.WARN}


def severity_for(finding: Finding, decision: Decision) -> str:
    level = (finding.sensitivity_level or "").lower()
    if level == "restricted":
        return "critical" if decision is Decision.BLOCK else "high"
    if level == "confidential":
        return "high" if decision is Decision.BLOCK else "medium"
    if decision is Decision.BLOCK:
        return "high"
    return "medium" if finding.confidence >= 0.8 else "low"


def _fingerprint(finding: Finding) -> str:
    raw = f"{finding.data_type.value}|{finding.matched_snippet or ''}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _finding_row(request: ScanRequest, finding: Finding, decision: Decision,
                 policy_id: UUID | None, event_id: UUID | None) -> dict:
    return {
        "org_id": str(request.org_id),
        "user_id": str(request.user_id),
        "event_id": str(event_id) if event_id else None,
        "severity": severity_for(finding, decision),
        "classification": _CLASSIFICATION.get(finding.data_type.value, "other"),
        "data_type": finding.data_type.value,
        "source": request.channel.value,
        "detector": finding.label or finding.data_type.value,
        "confidence": finding.confidence,
        "destination": request.destination,
        "masked_evidence": finding.matched_snippet,
        "location": request.filename,
        "policy_id": str(policy_id) if policy_id else None,
        "decision": decision.value,
        "fingerprint": _fingerprint(finding),
    }


def record_scan(request: ScanRequest, findings: list[Finding], decision: Decision,
                policy_id: UUID | None, event_id: UUID | None) -> None:
    if not findings:
        return
    try:
        client = database.get_supabase()
        rows = [_finding_row(request, f, decision, policy_id, event_id) for f in findings]
        client.table("dlp_findings").insert(rows).execute()
        if decision in _INCIDENT_DECISIONS:
            top = max(rows, key=lambda r: _rank(r["severity"]))
            _open_or_refresh_incident(client, request, top, policy_id)
    except (httpx.HTTPError, RuntimeError) as exc:
        logger.warning("Could not persist findings or incident: %s", exc)


def _rank(severity: str) -> int:
    return {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(severity, 0)


def _open_or_refresh_incident(client, request: ScanRequest, row: dict, policy_id: UUID | None) -> None:
    now = datetime.now(timezone.utc).isoformat()
    org = str(request.org_id)
    existing = (
        client.table("dlp_incidents").select("*").eq("org_id", org)
        .eq("data_type", row["data_type"]).eq("source", row["source"]).eq("status", "open")
        .order("last_seen", desc=True).limit(1).execute().data
    )
    if existing:
        incident = existing[0]
        severity = row["severity"] if _rank(row["severity"]) > _rank(incident["severity"]) else incident["severity"]
        client.table("dlp_incidents").eq("id", incident["id"]).eq("org_id", org).update(
            {"last_seen": now, "updated_at": now, "severity": severity}
        ).execute()
        incident_id = incident["id"]
        event_type, comment = "detection_repeated", f"Another {row['data_type']} detection via {row['source']}."
    else:
        count = len(client.table("dlp_incidents").select("id").eq("org_id", org).limit(1000).execute().data)
        for attempt in range(5):
            number = f"INC-{count + 1 + attempt:04d}"
            try:
                created = client.table("dlp_incidents").insert({
                    "org_id": org, "number": number,
                    "title": f"{row['detector']} detected in {row['source']}",
                    "severity": row["severity"], "status": "open", "source": row["source"],
                    "policy_id": str(policy_id) if policy_id else None,
                    "data_type": row["data_type"], "first_seen": now, "last_seen": now,
                }).execute().data
                break
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code != 409 or attempt == 4:
                    raise
        incident_id = created[0]["id"]
        event_type, comment = "created", f"Incident opened by a {row['decision']} decision."
    client.table("dlp_incident_events").insert({
        "incident_id": incident_id, "org_id": org, "event_type": event_type,
        "actor": "system", "comment": comment, "created_at": now,
    }).execute()
