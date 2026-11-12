from typing import Any

from pydantic import BaseModel, Field

from app.models.finding import Decision, Finding


class UploadedChunkResult(BaseModel):
    location: dict[str, Any]
    findings: list[Finding]
    decision: Decision
    reason: str


class UploadedFileResult(BaseModel):
    filename: str
    size_bytes: int
    extracted_chars: int = 0
    encoding: str | None = None
    skipped_reason: str | None = None
    chunks: list[UploadedChunkResult] = Field(default_factory=list)


class UploadScanResult(BaseModel):
    files: list[UploadedFileResult]
