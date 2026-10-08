from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from app.models.persisted_finding import FindingStatus


class Incident(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    org_id: UUID
    number: str = Field(pattern=r"^INC-\d{4}$")
    title: str
    severity: str
    status: FindingStatus = FindingStatus.OPEN
    assignee: Optional[str] = None
    source: str
    policy_id: Optional[UUID] = None
    data_type: str
    first_seen: datetime
    last_seen: datetime
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class IncidentEvent(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    org_id: UUID
    event_type: str
    actor: Optional[str] = None
    comment: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
