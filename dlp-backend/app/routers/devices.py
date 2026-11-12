"""Endpoint-agent API: device enrolment, heartbeat, config, events and scan.

Agents authenticate with a per-device key (``Authorization: Bearer dlpd_...``);
org and device identity always come from that key, never from the request body.
Admin routes use the existing ``X-DLP-Admin-Key`` header until P2's roles land.
"""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from app.models.finding import Channel, Decision, ScanRequest
from app.routers.classifications import require_admin_key
from app.routers.detect import scan_for_verified_user
from app.services.device_store import Device, DeviceStore, get_device_store, validate_config

agent_router = APIRouter(prefix="/agent", tags=["endpoint-agent"])
admin_router = APIRouter(prefix="/devices", tags=["devices"], dependencies=[Depends(require_admin_key)])

_BEARER = re.compile(r"^Bearer (dlpd_[A-Za-z0-9_-]{20,100})$")
MAX_SCAN_CHARS = 5_000_000
STRICTNESS = {Decision.ALLOW: 0, Decision.LOG: 1, Decision.WARN: 2, Decision.BLOCK: 3}


def run_scan(request: ScanRequest):
    """Scan for a device already authenticated by its per-device key.

    ``request.user_id`` carries the device ID (set by the caller from the key,
    never from the request body); it is stored as the event actor.
    """
    return scan_for_verified_user(request, request.user_id)


def current_device(
    authorization: Annotated[str | None, Header()] = None,
    store: DeviceStore = Depends(get_device_store),
) -> Device:
    match = _BEARER.match(authorization or "")
    device = store.authenticate(match.group(1)) if match else None
    if device is None:
        raise HTTPException(status_code=401, detail="Invalid or revoked device credentials", headers={"WWW-Authenticate": "Bearer"})
    return device


# ------------------------------------------------------------------ models


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EnrolRequest(StrictModel):
    enrolment_token: str = Field(min_length=10, max_length=100)
    hostname: str = Field(min_length=1, max_length=255)
    os_name: str = Field(min_length=1, max_length=100)
    agent_version: str = Field(min_length=1, max_length=32)


class HeartbeatRequest(StrictModel):
    agent_version: str = Field(min_length=1, max_length=32)
    queue_depth: int = Field(ge=0, le=10_000_000)
    config_version: int = Field(ge=0)
    tamper: list[Literal["service_stop", "config_edit", "watchdog", "agent_modified"]] = Field(default_factory=list, max_length=8)


class AgentEvent(StrictModel):
    kind: Literal["file_scan", "usb_copy", "quarantine", "restore", "tamper", "unscannable", "error"]
    decision: Literal["allow", "warn", "block", "log"]
    folder_class: Literal["downloads", "desktop", "documents", "removable", "clipboard", "other"]
    filename: str | None = Field(default=None, max_length=200, pattern=r"^[^/\\\x00]*$")  # basename only
    data_types: list[str] = Field(default_factory=list, max_length=20)
    findings_count: int = Field(ge=0, le=1_000_000)
    quarantined: bool = False
    detail: str | None = Field(default=None, max_length=300)
    occurred_at: str | None = Field(default=None, max_length=40)


class EventBatch(StrictModel):
    events: list[AgentEvent] = Field(min_length=1, max_length=100)


class ScanChunk(StrictModel):
    text: str = Field(max_length=1_000_000)
    location: dict[str, Any] = Field(default_factory=dict)


class AgentScanRequest(StrictModel):
    filename: str = Field(min_length=1, max_length=200, pattern=r"^[^/\\\x00]*$")
    chunks: list[ScanChunk] = Field(min_length=1, max_length=500)


class EnrolmentTokenRequest(StrictModel):
    org_id: UUID
    ttl_hours: int = Field(default=24, ge=1, le=168)


# ------------------------------------------------------------------- agent


@agent_router.post("/enrol", status_code=201)
def enrol(body: EnrolRequest, store: DeviceStore = Depends(get_device_store)):
    result = store.enrol(body.enrolment_token, body.hostname, body.os_name, body.agent_version)
    if result is None:
        raise HTTPException(status_code=401, detail="Invalid, expired or already used enrolment token")
    device, key = result
    version, config = store.get_config(device.org_id)
    return {"device_id": device.device_id, "device_key": key, "config_version": version, "config": config}


@agent_router.post("/heartbeat")
def heartbeat(body: HeartbeatRequest, device: Device = Depends(current_device), store: DeviceStore = Depends(get_device_store)):
    store.heartbeat(device.device_id, body.agent_version, body.queue_depth, list(body.tamper), body.config_version)
    version, config = store.get_config(device.org_id)
    reply: dict[str, Any] = {"ok": True, "config_version": version}
    if version != body.config_version:
        reply["config"] = config
    return reply


@agent_router.get("/config")
def get_config(device: Device = Depends(current_device), store: DeviceStore = Depends(get_device_store)):
    version, config = store.get_config(device.org_id)
    return {"config_version": version, "config": config}


@agent_router.post("/events", status_code=202)
def post_events(body: EventBatch, device: Device = Depends(current_device), store: DeviceStore = Depends(get_device_store)):
    accepted = store.add_events(device, [e.model_dump() for e in body.events])
    return {"accepted": accepted}


@agent_router.post("/scan")
def agent_scan(body: AgentScanRequest, device: Device = Depends(current_device)):
    """Scan text the agent extracted locally. Returns the strictest decision and masked findings."""
    if sum(len(c.text) for c in body.chunks) > MAX_SCAN_CHARS:
        raise HTTPException(status_code=413, detail="Extracted text is too large for one scan call")
    decision, reason, findings = Decision.ALLOW, "No sensitive data detected", []
    for chunk in body.chunks:
        result = run_scan(ScanRequest(
            org_id=UUID(device.org_id), user_id=UUID(device.device_id), channel=Channel.API,
            destination="endpoint", content=chunk.text, filename=body.filename,
        ))
        for f in result.findings:
            findings.append({"data_type": f.data_type.value, "confidence": f.confidence,
                             "matched_snippet": f.matched_snippet, "location": chunk.location})
        if STRICTNESS[result.decision] > STRICTNESS[decision]:
            decision, reason = result.decision, result.reason
    return {"decision": decision.value, "reason": reason, "findings": findings[:200]}


# ------------------------------------------------------------------- admin


def _device_view(d: Device) -> dict[str, Any]:
    return {"device_id": d.device_id, "hostname": d.hostname, "os_name": d.os_name, "agent_version": d.agent_version,
            "state": d.state, "tamper_flags": d.tamper_flags, "tamper_at": d.tamper_at, "queue_depth": d.queue_depth,
            "config_version": d.config_version, "enrolled_at": d.enrolled_at, "last_seen_at": d.last_seen_at,
            "revoked_at": d.revoked_at}


@admin_router.post("/enrolment-tokens", status_code=201)
def create_token(body: EnrolmentTokenRequest, store: DeviceStore = Depends(get_device_store)):
    token, expires_at = store.create_enrolment_token(str(body.org_id), body.ttl_hours * 3600)
    return {"enrolment_token": token, "expires_at": expires_at}


@admin_router.get("")
def list_devices(org_id: UUID, store: DeviceStore = Depends(get_device_store)):
    return {"devices": [_device_view(d) for d in store.list_devices(str(org_id))]}


@admin_router.post("/{device_id}/revoke")
def revoke(device_id: UUID, store: DeviceStore = Depends(get_device_store)):
    if not store.revoke(str(device_id)):
        raise HTTPException(status_code=404, detail="No active device with that ID")
    return {"revoked": True}


@admin_router.post("/{device_id}/tamper/acknowledge")
def acknowledge(device_id: UUID, store: DeviceStore = Depends(get_device_store)):
    if not store.acknowledge_tamper(str(device_id)):
        raise HTTPException(status_code=404, detail="No device with that ID")
    return {"acknowledged": True}


@admin_router.get("/{device_id}/events")
def device_events(device_id: UUID, store: DeviceStore = Depends(get_device_store), limit: int = 100):
    device = store.get(str(device_id))
    if device is None:
        raise HTTPException(status_code=404, detail="No device with that ID")
    return {"events": store.list_events(device.org_id, device.device_id, limit)}


@admin_router.put("/config/{org_id}")
def put_config(org_id: UUID, config: dict[str, Any], store: DeviceStore = Depends(get_device_store)):
    try:
        validate_config(config)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"config_version": store.set_config(str(org_id), config)}
