"""Versioned raw-body webhook signing and replay-aware verification helpers."""

import hashlib
import hmac
import os
import re
import time
from collections import OrderedDict
from dataclasses import dataclass
from threading import Lock
from typing import Protocol
from uuid import UUID

from pydantic import SecretStr
from sqlalchemy.orm import Session

from dlp_platform.vault.models import SecretType
from dlp_platform.vault.service import SecretVault, VaultOperationFailed

SIGNATURE_VERSION = "v1"
SIGNATURE_HEADER = "X-DLP-Webhook-Signature"
MAX_WEBHOOK_BODY_BYTES = 1_048_576
DEFAULT_TOLERANCE_SECONDS = 300
MAX_TOLERANCE_SECONDS = 900
DEFAULT_REPLAY_CACHE_CAPACITY = 10_000
_FORMAT = re.compile(r"^v1;t=([0-9]{1,12});sig=([a-f0-9]{64})$")


class ReplayStore(Protocol):
    def claim(self, token: str, expires_at: int, *, now: int) -> bool: ...


class InMemoryReplayStore:
    """Bounded process-local replay cache; use a shared store for multi-worker deployments."""

    def __init__(self, capacity: int = DEFAULT_REPLAY_CACHE_CAPACITY) -> None:
        if capacity < 1:
            raise ValueError("Replay cache capacity must be positive")
        self.capacity = capacity
        self._lock = Lock()
        self._entries: OrderedDict[str, int] = OrderedDict()

    def claim(self, token: str, expires_at: int, *, now: int) -> bool:
        with self._lock:
            for key, expiration in list(self._entries.items()):
                if expiration < now:
                    del self._entries[key]
            if token in self._entries:
                return False
            if len(self._entries) >= self.capacity:
                return False
            self._entries[token] = expires_at
            return True


@dataclass(frozen=True)
class WebhookVerification:
    valid: bool
    code: str
    version: str | None = None


def _validate_tolerance(tolerance_seconds: int) -> None:
    if not 1 <= tolerance_seconds <= MAX_TOLERANCE_SECONDS:
        raise ValueError(f"Tolerance must be between 1 and {MAX_TOLERANCE_SECONDS} seconds")


class WebhookSigner:
    """Signs and verifies exact HTTP body bytes using a P09 Vault secret reference."""

    def __init__(
        self,
        vault: SecretVault,
        replay_store: ReplayStore | None = None,
        *,
        tolerance_seconds: int = DEFAULT_TOLERANCE_SECONDS,
    ) -> None:
        _validate_tolerance(tolerance_seconds)
        self._vault = vault
        self._replay_store = replay_store or InMemoryReplayStore()
        self._tolerance_seconds = tolerance_seconds

    @classmethod
    def from_environment(
        cls, vault: SecretVault, replay_store: ReplayStore | None = None
    ) -> "WebhookSigner":
        return cls(
            vault,
            replay_store,
            tolerance_seconds=tolerance_from_environment(),
        )

    def sign(
        self,
        session: Session,
        organization_id: UUID,
        secret_id: UUID,
        raw_body: bytes,
        *,
        timestamp: int | None = None,
    ) -> str:
        if len(raw_body) > MAX_WEBHOOK_BODY_BYTES:
            raise ValueError("Webhook body exceeds the supported size")
        signed_at = int(time.time()) if timestamp is None else timestamp
        if isinstance(signed_at, bool) or not isinstance(signed_at, int) or signed_at < 0:
            raise ValueError("Timestamp must be a non-negative integer")
        secret = self._secret(session, organization_id, secret_id)
        digest = self._digest(secret, signed_at, raw_body)
        return f"{SIGNATURE_VERSION};t={signed_at};sig={digest}"

    def verify(
        self,
        session: Session,
        organization_id: UUID,
        secret_id: UUID,
        raw_body: bytes,
        signature_header: str | None,
        *,
        now: int | None = None,
    ) -> WebhookVerification:
        if signature_header is None:
            return WebhookVerification(False, "missing_signature")
        match = _FORMAT.fullmatch(signature_header)
        if match is None:
            return WebhookVerification(False, "malformed_signature")
        if len(raw_body) > MAX_WEBHOOK_BODY_BYTES:
            return WebhookVerification(False, "body_too_large", SIGNATURE_VERSION)
        timestamp_text, provided_digest = match.groups()
        timestamp = int(timestamp_text)
        current_time = int(time.time()) if now is None else now
        if timestamp > current_time + self._tolerance_seconds:
            return WebhookVerification(False, "timestamp_in_future", SIGNATURE_VERSION)
        if current_time - timestamp > self._tolerance_seconds:
            return WebhookVerification(False, "timestamp_stale", SIGNATURE_VERSION)
        try:
            secret = self._secret(session, organization_id, secret_id)
        except VaultOperationFailed:
            # Do not reveal whether this tenant owns the referenced Vault secret.
            return WebhookVerification(False, "invalid_signature", SIGNATURE_VERSION)
        expected_digest = self._digest(secret, timestamp, raw_body)
        if not hmac.compare_digest(provided_digest, expected_digest):
            return WebhookVerification(False, "invalid_signature", SIGNATURE_VERSION)
        replay_token = hashlib.sha256(
            f"{organization_id}:{secret_id}:{signature_header}".encode("ascii")
        ).hexdigest()
        if not self._replay_store.claim(
            replay_token,
            timestamp + self._tolerance_seconds,
            now=current_time,
        ):
            return WebhookVerification(False, "replay_detected", SIGNATURE_VERSION)
        return WebhookVerification(True, "verified", SIGNATURE_VERSION)

    def _secret(self, session: Session, organization_id: UUID, secret_id: UUID) -> bytes:
        value: SecretStr = self._vault.get_for_trusted_service(
            session,
            organization_id,
            secret_id,
            allowed_types=frozenset({SecretType.GENERIC_SECRET}),
        )
        return value.get_secret_value().encode("utf-8")

    @staticmethod
    def _digest(secret: bytes, timestamp: int, raw_body: bytes) -> str:
        message = str(timestamp).encode("ascii") + b"." + raw_body
        return hmac.new(secret, message, hashlib.sha256).hexdigest()


def tolerance_from_environment() -> int:
    raw = os.getenv("DLP_WEBHOOK_TOLERANCE_SECONDS", str(DEFAULT_TOLERANCE_SECONDS))
    try:
        tolerance = int(raw)
    except ValueError as exc:
        raise ValueError("DLP_WEBHOOK_TOLERANCE_SECONDS must be an integer") from exc
    _validate_tolerance(tolerance)
    return tolerance
