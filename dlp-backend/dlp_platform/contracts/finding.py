"""Finding contract. Evidence is masked; raw values are never part of this model."""

from datetime import datetime
from uuid import UUID

from pydantic import Field

from .common import (
    ClassificationLevel,
    ContractModel,
    FindingLocation,
    FindingStatus,
    PolicyAction,
    SeverityLevel,
)


class Finding(ContractModel):
    finding_id: UUID
    event_id: UUID | None = None
    data_type: str = Field(min_length=1, max_length=128)
    classification: ClassificationLevel
    severity: SeverityLevel
    confidence: float = Field(ge=0.0, le=1.0)
    detector: str = Field(min_length=1, max_length=128)
    masked_evidence: str = Field(max_length=512)
    fingerprint: str | None = Field(default=None, max_length=256)
    location: FindingLocation | None = None
    policy_action: PolicyAction | None = None
    status: FindingStatus = FindingStatus.OPEN
    first_seen_at: datetime
    last_seen_at: datetime | None = None
