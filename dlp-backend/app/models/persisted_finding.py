from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class FindingStatus(str, Enum):
    OPEN = "open"
    TRIAGED = "triaged"
    FIXED = "fixed"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"


class PersistedFinding(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    org_id: UUID
    user_id: UUID
    event_id: Optional[UUID] = None
    severity: str
    classification: Optional[str] = None
    data_type: str
    status: FindingStatus = FindingStatus.OPEN
    source: str
    detector: Optional[str] = None
    confidence: float
    destination: Optional[str] = None
    masked_evidence: Optional[str] = None
    location: Optional[str] = None
    policy_id: Optional[UUID] = None
    decision: Optional[str] = None
    fingerprint: Optional[str] = None
    owner: Optional[str] = None
    notes: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
