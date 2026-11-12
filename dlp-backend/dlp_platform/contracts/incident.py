"""Incident references safe identifiers and masked workflow metadata."""

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import Field

from .common import ContractModel, SeverityLevel


class IncidentStatus(StrEnum):
    OPEN = "open"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"


class Incident(ContractModel):
    incident_id: UUID
    organization_id: UUID
    title: str = Field(min_length=1, max_length=200)
    severity: SeverityLevel
    status: IncidentStatus = IncidentStatus.OPEN
    event_ids: tuple[UUID, ...] = ()
    finding_ids: tuple[UUID, ...] = ()
    assigned_to: str | None = Field(default=None, max_length=256)
    created_at: datetime
    updated_at: datetime
