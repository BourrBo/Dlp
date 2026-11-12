"""Synchronous file upload scan slice; async job lifecycle arrives in W7-8."""

import re
from pathlib import PureWindowsPath
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile

from app.extractors.limits import MAX_FILE_BYTES
from app.extractors.runner import extract_bytes_with_timeout
from app.models.finding import Channel, ScanRequest
from app.models.scan_upload import UploadedChunkResult, UploadedFileResult, UploadScanResult
from app.auth import AuthenticatedPrincipal, get_scan_principal, resolve_org
from app.routers.detect import scan_for_verified_user

router = APIRouter(prefix="/scans", tags=["file-scans"])
Principal = Annotated[AuthenticatedPrincipal, Depends(get_scan_principal)]


def _safe_filename(value: str | None) -> str:
    if not value:
        return "uploaded-file"
    name = PureWindowsPath(value.replace("/", "\\")).name
    name = re.sub(r"[^A-Za-z0-9._() -]", "_", name).strip(" .")[:200]
    return name or "uploaded-file"


@router.post("", response_model=UploadScanResult)
def scan_upload(
    principal: Principal,
    file: UploadFile = File(...),
    org_id: UUID | None = Form(None),
    destination: str = Form("file-upload"),
) -> UploadScanResult:
    """Extract and scan one file synchronously, retaining source locations."""
    org_id = resolve_org(principal, org_id)
    filename = _safe_filename(file.filename)
    try:
        data = file.file.read(MAX_FILE_BYTES + 1)
    finally:
        file.file.close()
    if len(data) > MAX_FILE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds the {MAX_FILE_BYTES // (1024 * 1024)} MB limit",
        )

    extracted = extract_bytes_with_timeout(data, display_path=filename)
    output = UploadedFileResult(
        filename=filename,
        size_bytes=len(data),
        extracted_chars=extracted.extracted_chars,
        encoding=extracted.encoding,
        skipped_reason=extracted.skipped_reason,
    )
    if extracted.skipped_reason:
        return UploadScanResult(files=[output])

    for chunk in extracted.chunks:
        result = scan_for_verified_user(
            ScanRequest(
                org_id=org_id,
                user_id=principal.user_id,
                channel=Channel.API,
                destination=destination,
                content=chunk.text,
                filename=filename,
            ),
            principal.user_id,
        )
        output.chunks.append(
            UploadedChunkResult(
                location=chunk.location,
                findings=result.findings,
                decision=result.decision,
                reason=result.reason,
            )
        )
    return UploadScanResult(files=[output])
