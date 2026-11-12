"""Durable decision record. Raw request content is deliberately excluded."""

from datetime import datetime
from uuid import UUID

from pydantic import Field

from .common import ContractModel, DataChannel, PolicyAction


class Event(ContractModel):
    event_id: UUID
    organization_id: UUID
    request_id: UUID
    scan_id: UUID
    channel: DataChannel
    destination: str | None = Field(default=None, max_length=2048)
    decision: PolicyAction
    reason: str = Field(min_length=1, max_length=2048)
    finding_count: int = Field(ge=0)
    occurred_at: datetime
