"""Tenant-scoped idempotency reservation and event persistence."""

import hashlib
import json
import logging
import threading
from dataclasses import dataclass
from functools import lru_cache
from typing import Protocol, cast

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection, RootTransaction

from dlp_platform.auth.settings import AuthSettings
from dlp_platform.contracts.principal import Principal
from dlp_platform.contracts.scan_request import ScanRequest
from dlp_platform.contracts.scan_result import ScanResult
from dlp_platform.scan.errors import IdempotencyConflict, IdempotencyInProgress, ScanStorageFailure
from dlp_platform.scan.interfaces import Recorder

logger = logging.getLogger(__name__)
type PostgresLease = tuple[Connection, RootTransaction]


@dataclass(frozen=True)
class Reservation:
    result: ScanResult | None
    is_new: bool
    token: PostgresLease | None = None


class IdempotencyStore(Recorder, Protocol):
    def reserve(self, request: ScanRequest, principal: Principal) -> Reservation: ...
    def record(
        self, request: ScanRequest, principal: Principal, result: ScanResult,
        reservation: object,
    ) -> None: ...
    def abort(
        self, request: ScanRequest, principal: Principal, reservation: Reservation
    ) -> None: ...


def request_fingerprint(request: ScanRequest) -> str:
    """Hash the exact input for conflict detection; the raw value is never stored."""
    normalized = {
        "channel": request.channel.value,
        "destination": request.destination,
        "content": request.content.get_secret_value(),
        "context": request.context,
    }
    encoded = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


class InMemoryIdempotencyStore:
    """Single-process test/development store; not suitable for production workers."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[tuple[str, str], tuple[str, ScanResult | None]] = {}

    def reserve(self, request: ScanRequest, principal: Principal) -> Reservation:
        key = (str(principal.organization_id), str(request.request_id))
        fingerprint = request_fingerprint(request)
        with self._lock:
            prior = self._entries.get(key)
            if prior is not None:
                if prior[0] != fingerprint:
                    raise IdempotencyConflict
                if prior[1] is None:
                    raise IdempotencyInProgress
                return Reservation(prior[1], False)
            self._entries[key] = (fingerprint, None)
            return Reservation(None, True)

    def record(
        self, request: ScanRequest, principal: Principal, result: ScanResult,
        reservation: object,
    ) -> None:
        del reservation
        key = (str(principal.organization_id), str(request.request_id))
        with self._lock:
            fingerprint, _ = self._entries[key]
            self._entries[key] = (fingerprint, result)

    def abort(
        self, request: ScanRequest, principal: Principal, reservation: Reservation
    ) -> None:
        del reservation
        key = (str(principal.organization_id), str(request.request_id))
        with self._lock:
            self._entries.pop(key, None)


class PostgresIdempotencyStore:
    """Small service-database store; every key and event is explicitly tenant scoped."""

    def __init__(self, database_url: str) -> None:
        self.engine = create_engine(database_url, pool_pre_ping=True)

    def reserve(self, request: ScanRequest, principal: Principal) -> Reservation:
        org_id, request_id = str(principal.organization_id), str(request.request_id)
        fingerprint = request_fingerprint(request)
        try:
            conn = self.engine.connect()
            transaction = conn.begin()
            try:
                inserted = conn.execute(
                    text(
                        "INSERT INTO dlp_scan_idempotency "
                        "(organization_id, request_id, input_hash, state) "
                        "VALUES (:org, :request, :hash, 'processing') "
                        "ON CONFLICT (organization_id, request_id) DO NOTHING"
                    ),
                    {"org": org_id, "request": request_id, "hash": fingerprint},
                ).rowcount
                if inserted == 1:
                    return Reservation(None, True, (conn, transaction))
                row = conn.execute(
                    text(
                        "SELECT input_hash, state, result_json FROM dlp_scan_idempotency "
                        "WHERE organization_id=:org AND request_id=:request"
                    ),
                    {"org": org_id, "request": request_id},
                ).mappings().one()
                if row["input_hash"] != fingerprint:
                    raise IdempotencyConflict
                if row["state"] != "complete" or row["result_json"] is None:
                    raise IdempotencyInProgress
                transaction.rollback()
                conn.close()
                return Reservation(ScanResult.model_validate(row["result_json"]), False)
            except Exception:
                transaction.rollback()
                conn.close()
                raise
        except (IdempotencyConflict, IdempotencyInProgress):
            raise
        except Exception as exc:
            logger.error(
                "Scan idempotency reservation failed exception_type=%s", type(exc).__name__
            )
            raise ScanStorageFailure from exc

    def record(
        self, request: ScanRequest, principal: Principal, result: ScanResult,
        reservation: object,
    ) -> None:
        org_id, request_id = str(principal.organization_id), str(request.request_id)
        lease = cast(Reservation, reservation)
        if lease.token is None:
            raise ScanStorageFailure
        conn, transaction = lease.token
        try:
            # Events remain the canonical durable decision record; content is never included.
            conn.execute(
                text(
                    "INSERT INTO events (id, organization_id, request_id, scan_id, channel, "
                    "destination, decision, reason, finding_count, occurred_at) "
                    "VALUES (:id, :org, :request, :scan, :channel, :destination, :decision, "
                    ":reason, :count, :occurred)"
                ),
                {
                    "id": str(result.scan_id),
                    "org": org_id,
                    "request": request_id,
                    "scan": str(result.scan_id),
                    "channel": request.channel.value,
                    "destination": request.destination,
                    "decision": result.decision.value,
                    "reason": result.reason,
                    "count": len(result.findings),
                    "occurred": result.completed_at,
                },
            )
            updated = conn.execute(
                text(
                    "UPDATE dlp_scan_idempotency SET state='complete', "
                    "result_json=CAST(:result AS JSONB) "
                    "WHERE organization_id=:org AND request_id=:request AND state='processing'"
                ),
                {
                    "result": json.dumps(result.model_dump(mode="json")),
                    "org": org_id,
                    "request": request_id,
                },
            ).rowcount
            if updated != 1:
                raise RuntimeError("idempotency reservation disappeared")
            transaction.commit()
        except Exception as exc:
            transaction.rollback()
            logger.error("Scan result persistence failed exception_type=%s", type(exc).__name__)
            raise ScanStorageFailure from exc
        finally:
            conn.close()

    def abort(
        self, request: ScanRequest, principal: Principal, reservation: Reservation
    ) -> None:
        if reservation.token is None:
            return
        conn, transaction = reservation.token
        try:
            # Rollback removes the uncommitted reservation; crashes do the same.
            transaction.rollback()
        except Exception as exc:
            logger.error("Scan reservation cleanup failed exception_type=%s", type(exc).__name__)
        finally:
            conn.close()


@lru_cache(maxsize=4)
def _postgres_store(database_url: str) -> PostgresIdempotencyStore:
    return PostgresIdempotencyStore(database_url)


_memory_store = InMemoryIdempotencyStore()


def get_idempotency_store() -> IdempotencyStore:
    url = AuthSettings.from_env().database_url
    if url.startswith("postgresql"):
        return _postgres_store(url)
    import os

    if os.getenv("APP_ENV", "development") == "production":
        raise ScanStorageFailure("Production requires PostgreSQL idempotency storage")
    return _memory_store
