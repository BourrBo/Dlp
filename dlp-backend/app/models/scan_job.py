from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from app.models.scan_upload import UploadScanResult


class ScanJobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"


class ScanJobView(BaseModel):
    id: UUID
    status: ScanJobStatus
    phase: str
    progress: int = Field(ge=0, le=100)
    filename: str
    size_bytes: int
    created_at: datetime
    updated_at: datetime
    cancel_requested: bool = False
    error_message: str | None = None
    result: UploadScanResult | None = None


class ScanJobList(BaseModel):
    jobs: list[ScanJobView]
