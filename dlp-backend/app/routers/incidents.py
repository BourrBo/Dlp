import logging
from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth import AuthenticatedPrincipal, get_current_principal
from app.database import get_authenticated_supabase
from app.models.incident import Incident, IncidentEvent
from app.models.persisted_finding import FindingStatus
from app.schemas.incidents import IncidentUpdate, IncidentWithEvents


router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])
logger = logging.getLogger(__name__)
Principal = Annotated[AuthenticatedPrincipal, Depends(get_current_principal)]


def _client(principal: AuthenticatedPrincipal):
    return get_authenticated_supabase(principal.access_token)


def _incident_query(principal: AuthenticatedPrincipal):
    return (
        _client(principal)
        .table("dlp_incidents")
        .select("*")
        .eq("org_id", str(principal.org_id))
    )


def _raise_database_error(exc: httpx.HTTPError) -> None:
    logger.error("Incident database request failed: %s", exc)
    raise HTTPException(status_code=503, detail="Incident storage is unavailable") from exc


@router.get("", response_model=list[Incident])
def list_incidents(
    principal: Principal,
    status: FindingStatus | None = None,
    severity: str | None = Query(default=None, min_length=1, max_length=40),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[Incident]:
    query = _incident_query(principal).order("created_at", desc=True).limit(limit)
    if status is not None:
        query = query.eq("status", status.value)
    if severity is not None:
        query = query.eq("severity", severity)
    try:
        return [Incident.model_validate(row) for row in query.execute().data]
    except httpx.HTTPError as exc:
        _raise_database_error(exc)


@router.get("/{incident_id}", response_model=IncidentWithEvents)
def get_incident(incident_id: UUID, principal: Principal) -> IncidentWithEvents:
    try:
        rows = _incident_query(principal).eq("id", str(incident_id)).limit(1).execute().data
        if not rows:
            raise HTTPException(status_code=404, detail="Incident not found")

        incident = Incident.model_validate(rows[0])
        event_rows = (
            _client(principal)
            .table("dlp_incident_events")
            .select("*")
            .eq("org_id", str(principal.org_id))
            .eq("incident_id", str(incident_id))
            .order("created_at")
            .execute()
            .data
        )
        return IncidentWithEvents(
            **incident.model_dump(),
            events=[IncidentEvent.model_validate(row) for row in event_rows],
        )
    except httpx.HTTPError as exc:
        _raise_database_error(exc)


@router.patch("/{incident_id}", response_model=Incident)
def update_incident(
    incident_id: UUID,
    request: IncidentUpdate,
    principal: Principal,
) -> Incident:
    try:
        rows = _incident_query(principal).eq("id", str(incident_id)).limit(1).execute().data
        if not rows:
            raise HTTPException(status_code=404, detail="Incident not found")
        current = Incident.model_validate(rows[0])

        changes = request.model_dump(exclude_unset=True, mode="json")
        if "assignee" in changes:
            changes["assignee"] = (changes["assignee"] or "").strip() or None
        if "status" in changes and changes["status"] is None:
            raise HTTPException(status_code=422, detail="status cannot be null")

        event_rows: list[dict[str, str]] = []
        now = datetime.now(timezone.utc).isoformat()
        if "status" in changes and changes["status"] != current.status.value:
            event_rows.append(
                {
                    "incident_id": str(incident_id),
                    "org_id": str(principal.org_id),
                    "event_type": "status_changed",
                    "actor": str(principal.user_id),
                    "comment": f"Status changed from {current.status.value} to {changes['status']}.",
                    "created_at": now,
                }
            )
        if "assignee" in changes and changes["assignee"] != current.assignee:
            next_assignee = changes["assignee"]
            event_rows.append(
                {
                    "incident_id": str(incident_id),
                    "org_id": str(principal.org_id),
                    "event_type": "assignee_changed",
                    "actor": str(principal.user_id),
                    "comment": (
                        f"Assignee changed to {next_assignee}."
                        if next_assignee
                        else "Incident unassigned."
                    ),
                    "created_at": now,
                }
            )

        if not event_rows:
            return current

        updated_rows = (
            _incident_query(principal)
            .eq("id", str(incident_id))
            .update({**changes, "updated_at": now})
            .execute()
            .data
        )
        if not updated_rows:
            raise HTTPException(status_code=404, detail="Incident not found")

        _client(principal).table("dlp_incident_events").insert(event_rows).execute()
        return Incident.model_validate(updated_rows[0])
    except httpx.HTTPError as exc:
        _raise_database_error(exc)
