"""Bounded metadata, tenant-derived event recording, and audit hash chaining."""

import hashlib
import ipaddress
import json
import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID, uuid4

from sqlalchemy import insert, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from dlp_platform.contracts.audit_event import AuditAction, AuditEvent, AuditOutcome
from dlp_platform.contracts.principal import Principal
from dlp_platform.tables import AUDIT_EVENTS, MEMBERS

GENESIS_HASH = "0" * 64
MAX_CHAIN_VERIFICATION_EVENTS = 10_000
MAX_METADATA_BYTES = 4096
_SENSITIVE_KEY = re.compile(
    r"(?:password|passwd|secret|token|api[_-]?key|authorization|cookie|"
    r"private[_-]?key|credential|ciphertext|master[_-]?key|refresh|access[_-]?token)",
    re.IGNORECASE,
)
_SECRET_VALUE = re.compile(
    r"(?:\bBearer\s+\S+|\b(?:password|passwd|secret|token|api[_-]?key|"
    r"authorization|cookie|credential)\s*[:=]\s*\S+|"
    r"\bdlp_[0-9a-f]{12}\.[A-Za-z0-9_-]+|"
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:gh[pousr]_[A-Za-z0-9]{20,}|"
    r"sk_(?:live|test)_[A-Za-z0-9]{16,})\b)"
)
_SAFE_METADATA_KEYS = frozenset(
    {
        "action_id",
        "key_version",
        "operation",
        "resource_id",
        "result",
        "scopes",
        "secret_type",
        "target_version",
        "user_agent",
        "version",
    }
)


class AuditPersistenceError(RuntimeError):
    """Audit persistence failed without exposing database details."""


class AuditVerificationLimitError(RuntimeError):
    """Tenant audit chain exceeds the bounded online verification limit."""


@dataclass(frozen=True)
class AuditChainVerification:
    valid: bool
    checked_events: int


@dataclass(frozen=True)
class AuditContext:
    correlation_id: UUID | None = None
    source_ip: str | None = None
    user_agent: str | None = None
    actor_id: str | None = None


def context_from_request(request: Any) -> AuditContext:
    correlation = getattr(request.state, "correlation_id", None)
    client = getattr(request, "client", None)
    peer = getattr(client, "host", None) if client is not None else None
    source_ip: str | None = None
    if isinstance(peer, str):
        try:
            source_ip = str(ipaddress.ip_address(peer))
        except ValueError:
            source_ip = None
    headers = getattr(request, "headers", {})
    user_agent = headers.get("user-agent") if hasattr(headers, "get") else None
    if isinstance(user_agent, str):
        user_agent = sanitize_metadata({"user_agent": user_agent[:512]})["user_agent"]
    key_id = getattr(request.state, "api_key_id", None)
    return AuditContext(
        correlation_id=correlation if isinstance(correlation, UUID) else None,
        source_ip=source_ip,
        user_agent=user_agent if isinstance(user_agent, str) else None,
        actor_id=str(key_id)[:256] if key_id is not None else None,
    )


def sanitize_metadata(value: dict[str, object] | None) -> dict[str, object]:
    """Redact sensitive fields and enforce a small JSON-only metadata envelope."""
    if value is None:
        return {}
    normalized = _normalize(value, depth=0)
    encoded = json.dumps(normalized, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(encoded.encode("utf-8")) > MAX_METADATA_BYTES:
        raise ValueError("Audit metadata exceeds the supported size")
    return cast(dict[str, object], normalized)


def _normalize(value: object, *, depth: int) -> Any:
    if depth > 5:
        raise ValueError("Audit metadata nesting exceeds the supported depth")
    if isinstance(value, dict):
        if len(value) > 64:
            raise ValueError("Audit metadata has too many fields")
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key or len(key) > 64:
                raise ValueError("Audit metadata contains an invalid field name")
            normalized = _normalize(item, depth=depth + 1)
            if (
                _SENSITIVE_KEY.search(key)
                or key not in _SAFE_METADATA_KEYS
                or (
                    key in {"action_id", "resource_id"}
                    and isinstance(normalized, str)
                    and _SECRET_VALUE.search(normalized)
                )
            ):
                result[key] = "[REDACTED]"
            else:
                result[key] = normalized
        return result
    if isinstance(value, (list, tuple)):
        if len(value) > 64:
            raise ValueError("Audit metadata list is too long")
        return [_normalize(item, depth=depth + 1) for item in value]
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Audit metadata contains an invalid number")
        return value
    if isinstance(value, str):
        if len(value) > 512:
            raise ValueError("Audit metadata text is too long")
        return "[REDACTED]" if _SECRET_VALUE.search(value) else value
    raise ValueError("Audit metadata must contain JSON-compatible values")


def _hash_payload(data: dict[str, object]) -> str:
    serialized = json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _event_hash(
    *,
    event_id: str,
    organization_id: str,
    occurred_at: datetime,
    actor_id: str,
    actor_type: str,
    auth_method: str,
    actor_role: str,
    action: str,
    resource_type: str,
    resource_id: str,
    outcome: str,
    correlation_id: str | None,
    source_ip: str | None,
    user_agent: str | None,
    metadata: dict[str, object],
    sequence_number: int,
    previous_hash: str,
) -> str:
    normalized_time = (
        occurred_at.replace(tzinfo=UTC)
        if occurred_at.tzinfo is None
        else occurred_at.astimezone(UTC)
    )
    return _hash_payload(
        {
            "event_id": event_id,
            "organization_id": organization_id,
            "occurred_at": normalized_time.isoformat(),
            "actor_id": actor_id,
            "actor_type": actor_type,
            "auth_method": auth_method,
            "actor_role": actor_role,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "outcome": outcome,
            "correlation_id": correlation_id,
            "source_ip": source_ip,
            "user_agent": user_agent,
            "metadata": metadata,
            "sequence_number": sequence_number,
            "previous_hash": previous_hash,
        }
    )


def _model(row: Any) -> AuditEvent:
    return AuditEvent(
        event_id=UUID(str(row["event_id"])),
        organization_id=UUID(str(row["organization_id"])),
        occurred_at=row["occurred_at"],
        actor_id=str(row["actor_id"]),
        actor_type=str(row["actor_type"]),
        auth_method=str(row["auth_method"]),
        actor_role=str(row["actor_role"]),
        action=AuditAction(str(row["action"])),
        resource_type=str(row["resource_type"]),
        resource_id=str(row["resource_id"]),
        outcome=AuditOutcome(str(row["outcome"])),
        correlation_id=UUID(str(row["correlation_id"])) if row["correlation_id"] else None,
        source_ip=row["source_ip"],
        user_agent=row["user_agent"],
        metadata=row["event_metadata"],
        sequence_number=int(row["sequence_number"]),
        previous_hash=str(row["previous_hash"]),
        event_hash=str(row["event_hash"]),
    )


class AuditService:
    """Creates append-only tenant audit records in the caller's transaction."""

    def record_event(
        self,
        session: Session,
        principal: Principal,
        *,
        action: AuditAction,
        resource_type: str,
        resource_id: str,
        outcome: AuditOutcome = AuditOutcome.SUCCESS,
        metadata: dict[str, object] | None = None,
        context: AuditContext | None = None,
    ) -> AuditEvent:
        context = context or AuditContext()
        safe_metadata = sanitize_metadata(metadata)
        org_id = str(principal.organization_id)
        if _SECRET_VALUE.search(resource_id):
            resource_id = "[REDACTED]"
        identifier, now = uuid4(), datetime.now(UTC)
        actor_id = context.actor_id
        values: dict[str, object] = {
            "event_id": str(identifier),
            "organization_id": org_id,
            "occurred_at": now,
            "actor_id": actor_id,
            "actor_type": principal.actor_type.value,
            "auth_method": principal.auth_method.value,
            "actor_role": principal.role.value,
            "action": action.value,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "outcome": outcome.value,
            "correlation_id": str(context.correlation_id) if context.correlation_id else None,
            "source_ip": context.source_ip,
            "user_agent": context.user_agent,
            "event_metadata": safe_metadata,
        }
        try:
            if actor_id is None:
                actor_member_id = session.execute(
                    select(MEMBERS.c.id).where(
                        MEMBERS.c.organization_id == org_id,
                        MEMBERS.c.auth_subject_id == principal.subject_id,
                    )
                ).scalar_one_or_none()
                actor_id = str(actor_member_id) if actor_member_id else principal.subject_id
            values["actor_id"] = actor_id
            if session.bind is not None and session.bind.dialect.name == "postgresql":
                session.execute(
                    text("SELECT pg_advisory_xact_lock(hashtextextended(:org_id, 0))"),
                    {"org_id": org_id},
                )
            previous = (
                session.execute(
                    select(AUDIT_EVENTS.c.sequence_number, AUDIT_EVENTS.c.event_hash)
                    .where(AUDIT_EVENTS.c.organization_id == org_id)
                    .order_by(AUDIT_EVENTS.c.sequence_number.desc())
                    .limit(1)
                )
                .mappings()
                .one_or_none()
            )
            sequence = int(previous["sequence_number"]) + 1 if previous else 1
            previous_hash = str(previous["event_hash"]) if previous else GENESIS_HASH
            event_hash = _event_hash(
                event_id=str(identifier),
                organization_id=org_id,
                occurred_at=now,
                actor_id=actor_id,
                actor_type=principal.actor_type.value,
                auth_method=principal.auth_method.value,
                actor_role=principal.role.value,
                action=action.value,
                resource_type=resource_type,
                resource_id=resource_id,
                outcome=outcome.value,
                correlation_id=values["correlation_id"],  # type: ignore[arg-type]
                source_ip=context.source_ip,
                user_agent=context.user_agent,
                metadata=safe_metadata,
                sequence_number=sequence,
                previous_hash=previous_hash,
            )
            values.update(
                sequence_number=sequence,
                previous_hash=previous_hash,
                event_hash=event_hash,
            )
            event = _model(values)
            session.execute(insert(AUDIT_EVENTS).values(**values))
        except SQLAlchemyError:
            raise AuditPersistenceError("Audit event could not be recorded") from None
        return event

    def list_events(
        self,
        session: Session,
        organization_id: UUID,
        *,
        action: AuditAction | None = None,
        actor_id: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        outcome: AuditOutcome | None = None,
        correlation_id: UUID | None = None,
        from_time: datetime | None = None,
        to_time: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEvent]:
        query = select(AUDIT_EVENTS).where(AUDIT_EVENTS.c.organization_id == str(organization_id))
        if action is not None:
            query = query.where(AUDIT_EVENTS.c.action == action.value)
        if actor_id is not None:
            query = query.where(AUDIT_EVENTS.c.actor_id == actor_id)
        if resource_type is not None:
            query = query.where(AUDIT_EVENTS.c.resource_type == resource_type)
        if resource_id is not None:
            query = query.where(AUDIT_EVENTS.c.resource_id == resource_id)
        if outcome is not None:
            query = query.where(AUDIT_EVENTS.c.outcome == outcome.value)
        if correlation_id is not None:
            query = query.where(AUDIT_EVENTS.c.correlation_id == str(correlation_id))
        if from_time is not None:
            query = query.where(AUDIT_EVENTS.c.occurred_at >= from_time)
        if to_time is not None:
            query = query.where(AUDIT_EVENTS.c.occurred_at <= to_time)
        query = (
            query.order_by(AUDIT_EVENTS.c.occurred_at.desc(), AUDIT_EVENTS.c.event_id.desc())
            .limit(limit)
            .offset(offset)
        )
        try:
            rows = session.execute(query).mappings().all()
        except SQLAlchemyError:
            raise AuditPersistenceError("Audit events could not be read") from None
        return [_model(row) for row in rows]

    def verify_chain(
        self,
        session: Session,
        organization_id: UUID,
        *,
        max_events: int = MAX_CHAIN_VERIFICATION_EVENTS,
    ) -> bool:
        """Return whether the bounded tenant chain is valid."""
        return self.verify_chain_result(session, organization_id, max_events=max_events).valid

    def verify_chain_result(
        self,
        session: Session,
        organization_id: UUID,
        *,
        max_events: int = MAX_CHAIN_VERIFICATION_EVENTS,
    ) -> AuditChainVerification:
        """Verify one tenant chain with a strict upper bound on rows read."""
        if not 1 <= max_events <= MAX_CHAIN_VERIFICATION_EVENTS:
            raise ValueError("max_events is outside the supported verification bound")
        try:
            rows = (
                session.execute(
                    select(AUDIT_EVENTS)
                    .where(AUDIT_EVENTS.c.organization_id == str(organization_id))
                    .order_by(AUDIT_EVENTS.c.sequence_number)
                    .limit(max_events + 1)
                )
                .mappings()
                .all()
            )
        except SQLAlchemyError:
            raise AuditPersistenceError("Audit chain could not be verified") from None
        if len(rows) > max_events:
            raise AuditVerificationLimitError("Audit chain exceeds online verification limit")
        previous_hash = GENESIS_HASH
        for expected_sequence, row in enumerate(rows, 1):
            data = dict(row)
            if (
                data["sequence_number"] != expected_sequence
                or data["previous_hash"] != previous_hash
            ):
                return AuditChainVerification(False, expected_sequence)
            calculated = _event_hash(
                event_id=str(data["event_id"]),
                organization_id=str(data["organization_id"]),
                occurred_at=data["occurred_at"],
                actor_id=str(data["actor_id"]),
                actor_type=str(data["actor_type"]),
                auth_method=str(data["auth_method"]),
                actor_role=str(data["actor_role"]),
                action=str(data["action"]),
                resource_type=str(data["resource_type"]),
                resource_id=str(data["resource_id"]),
                outcome=str(data["outcome"]),
                correlation_id=str(data["correlation_id"]) if data["correlation_id"] else None,
                source_ip=data["source_ip"],
                user_agent=data["user_agent"],
                metadata=data["event_metadata"],
                sequence_number=int(data["sequence_number"]),
                previous_hash=str(data["previous_hash"]),
            )
            if calculated != data["event_hash"]:
                return AuditChainVerification(False, expected_sequence)
            previous_hash = calculated
        return AuditChainVerification(True, len(rows))
