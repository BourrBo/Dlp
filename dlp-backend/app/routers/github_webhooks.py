"""Size-bounded, signature-verified GitHub App webhook intake."""

import json
import hashlib
import re
import sqlite3

from fastapi import APIRouter, HTTPException, Request

from app.config import get_settings
from app.services.github_app import verify_github_webhook_signature
from app.services.pr_check import pull_request_target
from app.services.github_webhook_store import WebhookDelivery, WebhookQueueFull, get_github_webhook_store


router = APIRouter(tags=["github"])
MAX_GITHUB_WEBHOOK_BYTES = 2 * 1024 * 1024
_DELIVERY_ID = re.compile(r"^[A-Za-z0-9-]{1,128}$")
_SHA = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_SUPPORTED_EVENTS = {"installation", "installation_repositories", "push", "pull_request"}


async def _read_bounded_body(request: Request) -> bytes:
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_GITHUB_WEBHOOK_BYTES:
                raise HTTPException(status_code=413, detail="Webhook body is too large")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid Content-Length") from exc
    body = bytearray()
    async for part in request.stream():
        if len(body) + len(part) > MAX_GITHUB_WEBHOOK_BYTES:
            raise HTTPException(status_code=413, detail="Webhook body is too large")
        body.extend(part)
    return bytes(body)


def _positive_id(value, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise HTTPException(status_code=400, detail=f"Invalid {field}")
    return value


def _safe_action(value) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 64 or not re.fullmatch(r"[a-z_]+", value):
        raise HTTPException(status_code=400, detail="Invalid webhook action")
    return value


def _delivery_from_payload(delivery_id: str, event_type: str, payload: dict, idempotency_key: str) -> WebhookDelivery:
    installation = payload.get("installation")
    if not isinstance(installation, dict):
        raise HTTPException(status_code=400, detail="Missing GitHub installation metadata")
    installation_id = _positive_id(installation.get("id"), field="installation ID")
    action = _safe_action(payload.get("action"))

    if event_type == "push":
        repository = payload.get("repository")
        if not isinstance(repository, dict):
            raise HTTPException(status_code=400, detail="Missing repository metadata")
        repository_id = _positive_id(repository.get("id"), field="repository ID")
        full_name = repository.get("full_name")
        if not isinstance(full_name, str) or len(full_name) > 201 or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", full_name):
            raise HTTPException(status_code=400, detail="Invalid repository name")
        ref = payload.get("ref")
        if not isinstance(ref, str) or len(ref) > 255 or not ref.startswith("refs/heads/"):
            raise HTTPException(status_code=400, detail="Invalid push ref")
        before, after = payload.get("before"), payload.get("after")
        if not isinstance(before, str) or not _SHA.fullmatch(before) or not isinstance(after, str) or not _SHA.fullmatch(after):
            raise HTTPException(status_code=400, detail="Invalid push commit SHA")
        deleted = payload.get("deleted", False)
        if not isinstance(deleted, bool):
            raise HTTPException(status_code=400, detail="Invalid push deleted flag")
        visibility = repository.get("visibility")
        if not isinstance(visibility, str) or visibility not in {"public", "private", "internal"}:
            visibility = "private" if repository.get("private") is True else "public"
        return WebhookDelivery(
            delivery_id=delivery_id, event_type=event_type, action=action,
            installation_id=installation_id, idempotency_key=idempotency_key, repository_id=repository_id,
            repository_full_name=full_name, visibility=visibility, ref=ref,
            before_sha=before.lower(), after_sha=after.lower(),
            deleted=deleted,
        )

    if event_type == "pull_request":
        target = pull_request_target(payload)
        if target is None:
            raise HTTPException(status_code=400, detail="Invalid pull request metadata")
        full_name, number, head_sha = target
        repository = payload["repository"]
        return WebhookDelivery(
            delivery_id=delivery_id, event_type=event_type, action=action,
            installation_id=installation_id, idempotency_key=idempotency_key,
            repository_id=_positive_id(repository.get("id"), field="repository ID"),
            repository_full_name=full_name, ref=f"refs/pull/{number}/head", after_sha=head_sha,
        )

    return WebhookDelivery(
        delivery_id=delivery_id, event_type=event_type, action=action,
        installation_id=installation_id, idempotency_key=idempotency_key,
    )


@router.post("/webhooks/github", status_code=202)
async def receive_github_webhook(request: Request):
    settings = get_settings()
    if not settings.github_webhook_secret:
        raise HTTPException(status_code=503, detail="GitHub webhook verification is not configured")

    body = await _read_bounded_body(request)
    signature = request.headers.get("x-hub-signature-256")
    if not verify_github_webhook_signature(body, signature, settings.github_webhook_secret):
        raise HTTPException(status_code=401, detail="Invalid GitHub webhook signature")

    delivery_id = request.headers.get("x-github-delivery", "")
    if not _DELIVERY_ID.fullmatch(delivery_id):
        raise HTTPException(status_code=400, detail="Invalid GitHub delivery ID")
    event_type = request.headers.get("x-github-event", "")
    if event_type not in _SUPPORTED_EVENTS:
        return {"accepted": True, "ignored": True}
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="Invalid GitHub webhook JSON") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="GitHub webhook body must be an object")

    if event_type == "pull_request" and payload.get("action") not in {"opened", "synchronize", "reopened"}:
        return {"accepted": True, "ignored": True}

    signature_fingerprint = hashlib.sha256(signature.encode("ascii")).hexdigest()
    delivery = _delivery_from_payload(delivery_id, event_type, payload, signature_fingerprint)
    try:
        accepted = get_github_webhook_store().accept(delivery)
    except (OSError, RuntimeError, sqlite3.Error) as exc:
        raise HTTPException(status_code=503, detail="GitHub webhook queue is unavailable") from exc
    return {"accepted": True, "duplicate": not accepted}
