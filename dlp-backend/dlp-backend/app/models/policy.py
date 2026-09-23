from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from app.models.finding import Channel, DataType, Decision


class PolicyCondition(BaseModel):
    """
    Kept intentionally simple for v1: a destination allowlist and an optional
    minimum confidence. Extend here (not with ad-hoc dict parsing elsewhere)
    when richer conditions are needed.
    """

    approved_destinations: list[str] = Field(default_factory=list)
    min_confidence: float = 0.7


class Policy(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    org_id: UUID
    data_type: DataType
    channel: Channel
    condition: PolicyCondition
    action: Decision
    is_exception: bool = False


class Exception_(BaseModel):
    """Named Exception_ to avoid shadowing the builtin; table is dlp_exceptions."""

    id: UUID = Field(default_factory=uuid4)
    org_id: UUID
    destination_or_user: str
    reason: str
    approved_by: str
    expires_at: Optional[datetime] = None
