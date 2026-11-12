"""Result returned by the shared scan pipeline."""

from datetime import datetime
from uuid import UUID

from pydantic import Field

from .common import ContractModel, PolicyAction
from .finding import Finding


class ScanResult(ContractModel):
    scan_id: UUID
    request_id: UUID
    decision: PolicyAction
    reason: str = Field(min_length=1, max_length=2048)
    findings: tuple[Finding, ...] = ()
    policy_version: str | None = Field(default=None, max_length=64)
    completed_at: datetime
