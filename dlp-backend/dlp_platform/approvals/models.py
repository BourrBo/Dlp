"""Safe API response models for action and approval records."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ApprovalCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: UUID
    action: str = Field(pattern=r"^(redact|quarantine|revoke_share|user_override)$")
    justification: str = Field(min_length=1, max_length=1000)
    policy_id: UUID | None = None
    policy_version: int | None = Field(default=None, ge=1)


class ApprovalDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(default=None, max_length=1000)


class ApprovalView(BaseModel):
    approval_id: UUID
    action_id: UUID
    request_id: UUID
    action: str
    action_status: str
    status: str
    justification: str
    requested_by: str
    expires_at: datetime
    decided_by: str | None = None
    decision_reason: str | None = None
    created_at: datetime
    decided_at: datetime | None = None


class ActionView(BaseModel):
    action_id: UUID
    request_id: UUID
    policy_id: UUID | None = None
    policy_version: int | None = None
    action: str
    status: str
    justification: str
    created_at: datetime
    updated_at: datetime
