"""Durable asynchronous file scans with progress and cancellation."""

import re
from pathlib import PureWindowsPath
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile

from app.extractors.limits import MAX_FILE_BYTES
from app.models.scan_job import ScanJobList, ScanJobView
from app.services.scan_job_store import ScanJobStore, ScanQueueFull, get_scan_job_store
from app.auth import AuthenticatedPrincipal, get_scan_principal, resolve_org

router = APIRouter(prefix="/scan-jobs", tags=["scan-jobs"])
Principal = Annotated[AuthenticatedPrincipal, Depends(get_scan_principal)]


def _store() -> ScanJobStore:
    try:
        return get_scan_job_store()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail="Durable scan jobs require the backend service key") from exc


def _safe_filename(value: str | None) -> str:
    if not value:
        return "uploaded-file"
    name = PureWindowsPath(value.replace("/", "\\")).name
    name = re.sub(r"[^A-Za-z0-9._() -]", "_", name).strip(" .")[:200]
    return name or "uploaded-file"


def _owned_job(job_id: UUID, org_id: UUID | None, principal: AuthenticatedPrincipal) -> ScanJobView:
    org_id = resolve_org(principal, org_id)
    job = _store().get(job_id, org_id, principal.user_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return job


@router.post("", response_model=ScanJobView, status_code=202)
def submit_scan_job(
    principal: Principal,
    file: UploadFile = File(...),
    org_id: UUID | None = Form(None),
    destination: str = Form("file-upload"),
) -> ScanJobView:
    org_id = resolve_org(principal, org_id)
    filename = _safe_filename(file.filename)
    try:
        data = file.file.read(MAX_FILE_BYTES + 1)
    finally:
        file.file.close()
    if len(data) > MAX_FILE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds the {MAX_FILE_BYTES // (1024 * 1024)} MiB limit",
        )
    if not data:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    try:
        return _store().create(
            org_id=org_id,
            user_id=principal.user_id,
            filename=filename,
            destination=destination.strip()[:500] or "file-upload",
            data=data,
        )
    except ScanQueueFull as exc:
        raise HTTPException(
            status_code=429,
            detail="The scan queue is busy. Retry after current jobs finish.",
            headers={"Retry-After": "30"},
        ) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail="Durable scan jobs are not configured") from exc


@router.get("", response_model=ScanJobList)
def list_scan_jobs(
    principal: Principal,
    org_id: UUID | None = None,
    limit: int = Query(default=25, ge=1, le=100),
) -> ScanJobList:
    org_id = resolve_org(principal, org_id)
    return ScanJobList(jobs=_store().list(org_id, principal.user_id, limit=limit))


@router.get("/{job_id}", response_model=ScanJobView)
def get_scan_job(job_id: UUID, principal: Principal, org_id: UUID | None = None) -> ScanJobView:
    return _owned_job(job_id, org_id, principal)


@router.delete("/{job_id}", response_model=ScanJobView)
def cancel_scan_job(job_id: UUID, principal: Principal, org_id: UUID | None = None) -> ScanJobView:
    org_id = resolve_org(principal, org_id)
    job = _store().request_cancel(job_id, org_id, principal.user_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return job
