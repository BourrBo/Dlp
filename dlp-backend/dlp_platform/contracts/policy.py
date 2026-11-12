"""Policy contract. Evaluation and enforcement are later P2 phases."""

from datetime import datetime
from uuid import UUID

from pydantic import Field

from .common import ContractModel, PolicyAction


class Policy(ContractModel):
    policy_id: UUID
    organization_id: UUID
    name: str = Field(min_length=1, max_length=200)
    enabled: bool = True
    priority: int = Field(default=100, ge=0)
    conditions: dict[str, str | int | float | bool | None | list[str] | list[int]]
    action: PolicyAction
    version: int = Field(default=1, ge=1)
    created_at: datetime
    updated_at: datetime
