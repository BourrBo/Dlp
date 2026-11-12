"""Bounded, tenant-scoped retention, export, and organization deletion services."""

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import and_, delete, func, insert, select, text, tuple_, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from dlp_platform.audit.service import AuditContext, AuditService, sanitize_metadata
from dlp_platform.auth.permissions import require_permission
from dlp_platform.auth.roles import Permission
from dlp_platform.contracts.audit_event import AuditAction, AuditOutcome
from dlp_platform.contracts.principal import Principal
from dlp_platform.lifecycle.adapters import adapters
from dlp_platform.tables import (
    ACTIONS,
    API_KEYS,
    APP_SESSIONS,
    APPROVALS,
    AUDIT_EVENTS,
    CHANNELS,
    DESTINATIONS,
    EVENTS,
    EXCEPTIONS,
    IP_ALLOWLIST_ENTRIES,
    IP_ALLOWLIST_SETTINGS,
    LEGAL_HOLDS,
    MEMBERS,
    ORG_DELETION_REQUESTS,
    ORGANIZATIONS,
    POLICIES,
    POLICY_VERSIONS,
    RETENTION_POLICIES,
    RETENTION_RUNS,
    SCAN_IDEMPOTENCY,
    SCIM_CREDENTIALS,
    SCIM_GROUP_MEMBERS,
    SCIM_GROUPS,
    SCIM_USERS,
    SSO_CONFIGS,
    SSO_IDENTITIES,
    SSO_REPLAYS,
    SSO_TRANSACTIONS,
    SUPPRESSIONS,
    VAULT_SECRETS,
)

RETENTION_CATEGORIES = (
    "sessions",
    "scan_records",
    "sso_ephemera",
    "revoked_credentials",
)
MAX_RETENTION_DAYS = 3650
RETENTION_BATCH_SIZE = 500
DELETION_BATCH_SIZE = 100
DELETION_BATCHES_PER_CALL = 20
MAX_EXPORT_ROWS_PER_CATEGORY = 500
MAX_EXPORT_BYTES = 1_000_000


class LifecycleError(RuntimeError):
    """A lifecycle operation failed without exposing database internals."""


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _trusted_role(session: Session) -> None:
    """Restore the backend connection role after principal/RLS validation."""
    if session.bind is not None and session.bind.dialect.name == "postgresql":
        session.execute(text("RESET ROLE"))


def _lock_organization(session: Session, organization_id: UUID) -> None:
    if session.bind is not None and session.bind.dialect.name == "postgresql":
        session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:org_id, 14014))"),
            {"org_id": str(organization_id)},
        )


def _audit(
    session: Session,
    principal: Principal,
    *,
    action: AuditAction,
    resource_type: str,
    resource_id: str,
    outcome: AuditOutcome = AuditOutcome.SUCCESS,
    operation: str,
    result: str | None = None,
    context: AuditContext | None = None,
) -> None:
    metadata: dict[str, object] = {"operation": operation}
    if result is not None:
        metadata["result"] = result
    AuditService().record_event(
        session,
        principal,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        metadata=metadata,
        context=context,
    )


def _active_holds(
    session: Session, organization_id: UUID, category: str | None = None
) -> list[Any]:
    query = select(LEGAL_HOLDS.c.id).where(
        LEGAL_HOLDS.c.org_id == str(organization_id), LEGAL_HOLDS.c.status == "active"
    )
    if category is not None:
        query = query.where(
            LEGAL_HOLDS.c.scope_category.is_(None) | (LEGAL_HOLDS.c.scope_category == category)
        )
    return list(session.execute(query).scalars())


def active_hold_count(session: Session, organization_id: UUID) -> int:
    return len(_active_holds(session, organization_id))


def _batch_delete(
    session: Session,
    table: Any,
    organization_column: Any,
    organization_id: UUID,
    *,
    limit: int,
    extra: Any | None = None,
) -> int:
    primary_key = tuple(table.primary_key.columns)
    predicate = organization_column == str(organization_id)
    if extra is not None:
        predicate = and_(predicate, extra)
    selected = select(*primary_key).where(predicate).order_by(*primary_key).limit(limit)
    condition = tuple_(*primary_key).in_(selected)
    result = session.execute(delete(table).where(condition))
    return int(result.rowcount or 0) if isinstance(result, CursorResult) else 0


def _retention_targets(category: str, cutoff: datetime) -> tuple[tuple[Any, Any, Any], ...]:
    if category == "sessions":
        return (
            (
                APP_SESSIONS,
                APP_SESSIONS.c.org_id,
                func.coalesce(APP_SESSIONS.c.revoked_at, APP_SESSIONS.c.expires_at) <= cutoff,
            ),
        )
    if category == "scan_records":
        return (
            (EVENTS, EVENTS.c.organization_id, EVENTS.c.created_at <= cutoff),
            (
                SCAN_IDEMPOTENCY,
                SCAN_IDEMPOTENCY.c.organization_id,
                SCAN_IDEMPOTENCY.c.created_at <= cutoff,
            ),
        )
    if category == "sso_ephemera":
        return (
            (SSO_TRANSACTIONS, SSO_TRANSACTIONS.c.org_id, SSO_TRANSACTIONS.c.expires_at <= cutoff),
            (SSO_REPLAYS, SSO_REPLAYS.c.org_id, SSO_REPLAYS.c.expires_at <= cutoff),
        )
    if category == "revoked_credentials":
        return (
            (
                API_KEYS,
                API_KEYS.c.org_id,
                API_KEYS.c.revoked_at.is_not(None) & (API_KEYS.c.revoked_at <= cutoff),
            ),
            (
                SCIM_CREDENTIALS,
                SCIM_CREDENTIALS.c.org_id,
                SCIM_CREDENTIALS.c.revoked_at.is_not(None)
                & (SCIM_CREDENTIALS.c.revoked_at <= cutoff),
            ),
        )
    raise ValueError("Unsupported retention category")


def retention_settings(session: Session, organization_id: UUID) -> list[dict[str, object]]:
    rows = session.execute(
        select(RETENTION_POLICIES).where(RETENTION_POLICIES.c.org_id == str(organization_id))
    ).mappings()
    existing = {str(row["category"]): row for row in rows}
    return [
        {
            "category": category,
            "enabled": bool(existing[category]["enabled"]) if category in existing else False,
            "retention_days": existing[category]["retention_days"]
            if category in existing
            else None,
            "effective_at": existing[category]["effective_at"] if category in existing else None,
            "updated_at": existing[category]["updated_at"] if category in existing else None,
        }
        for category in RETENTION_CATEGORIES
    ]


def save_retention_policy(
    session: Session,
    principal: Principal,
    *,
    category: str,
    retention_days: int,
    enabled: bool,
    context: AuditContext | None = None,
) -> dict[str, object]:
    require_permission(principal, Permission.DATA_LIFECYCLE_WRITE)
    if category not in RETENTION_CATEGORIES:
        raise ValueError("Unsupported retention category")
    if not 1 <= retention_days <= MAX_RETENTION_DAYS:
        raise ValueError("Retention days must be between 1 and 3650")
    _trusted_role(session)
    _lock_organization(session, principal.organization_id)
    now = datetime.now(UTC)
    existing = session.execute(
        select(RETENTION_POLICIES.c.created_at).where(
            RETENTION_POLICIES.c.org_id == str(principal.organization_id),
            RETENTION_POLICIES.c.category == category,
        )
    ).scalar_one_or_none()
    values = {
        "org_id": str(principal.organization_id),
        "category": category,
        "retention_days": retention_days,
        "enabled": enabled,
        "effective_at": now,
        "updated_by": str(principal.member_id),
        "created_at": existing or now,
        "updated_at": now,
    }
    if existing is None:
        session.execute(insert(RETENTION_POLICIES).values(**values))
    else:
        session.execute(
            update(RETENTION_POLICIES)
            .where(
                RETENTION_POLICIES.c.org_id == str(principal.organization_id),
                RETENTION_POLICIES.c.category == category,
            )
            .values(
                **{
                    key: value
                    for key, value in values.items()
                    if key not in {"org_id", "category", "created_at"}
                }
            )
        )
    _audit(
        session,
        principal,
        action=AuditAction.RETENTION_POLICY_UPDATED,
        resource_type="retention_policy",
        resource_id=category,
        operation="update_policy",
        context=context,
    )
    session.commit()
    return {
        "category": category,
        "retention_days": retention_days,
        "enabled": enabled,
        "effective_at": now,
        "updated_at": now,
    }


def run_retention_batch(
    session: Session,
    principal: Principal,
    *,
    category: str,
    limit: int = RETENTION_BATCH_SIZE,
    context: AuditContext | None = None,
) -> dict[str, object]:
    require_permission(principal, Permission.DATA_LIFECYCLE_WRITE)
    if category not in RETENTION_CATEGORIES:
        raise ValueError("Unsupported retention category")
    if not 1 <= limit <= RETENTION_BATCH_SIZE:
        raise ValueError("Batch limit must be between 1 and 500")
    policy = (
        session.execute(
            select(RETENTION_POLICIES).where(
                RETENTION_POLICIES.c.org_id == str(principal.organization_id),
                RETENTION_POLICIES.c.category == category,
            )
        )
        .mappings()
        .one_or_none()
    )
    if policy is None or not policy["enabled"]:
        raise ValueError("Retention is not enabled for this category")
    run_id, started = str(uuid4()), datetime.now(UTC)
    _trusted_role(session)
    session.execute(
        insert(RETENTION_RUNS).values(
            id=run_id,
            org_id=str(principal.organization_id),
            category=category,
            status="running",
            deleted_count=0,
            failure_code=None,
            started_at=started,
        )
    )
    session.commit()
    try:
        _lock_organization(session, principal.organization_id)
        # The policy is re-read after the shared organization lock so a concurrent
        # policy update takes effect on a later batch, not halfway through this one.
        policy = (
            session.execute(
                select(RETENTION_POLICIES).where(
                    RETENTION_POLICIES.c.org_id == str(principal.organization_id),
                    RETENTION_POLICIES.c.category == category,
                )
            )
            .mappings()
            .one_or_none()
        )
        if policy is None or not policy["enabled"]:
            raise ValueError("Retention is not enabled for this category")
        holds = _active_holds(session, principal.organization_id, category)
        deleted = 0
        if not holds:
            now = datetime.now(UTC)
            age_cutoff = now - timedelta(days=int(policy["retention_days"]))
            effective_at = _as_utc(policy["effective_at"])
            if effective_at <= age_cutoff:
                for table, org_column, expires_before_cutoff in _retention_targets(
                    category, age_cutoff
                ):
                    deleted += _batch_delete(
                        session,
                        table,
                        org_column,
                        principal.organization_id,
                        limit=limit,
                        extra=expires_before_cutoff,
                    )
        session.execute(
            update(RETENTION_RUNS)
            .where(RETENTION_RUNS.c.id == run_id)
            .values(
                status="completed",
                deleted_count=deleted,
                failure_code=None,
                completed_at=datetime.now(UTC),
            )
        )
        _audit(
            session,
            principal,
            action=AuditAction.RETENTION_BATCH_COMPLETED,
            resource_type="retention_run",
            resource_id=run_id,
            operation="batch",
            result="held" if holds else f"deleted:{deleted}",
            context=context,
        )
        session.commit()
        return {
            "run_id": run_id,
            "category": category,
            "status": "completed",
            "deleted_count": deleted,
            "held": bool(holds),
            "started_at": started,
            "completed_at": datetime.now(UTC),
        }
    except (SQLAlchemyError, ValueError):
        session.rollback()
        try:
            session.execute(
                update(RETENTION_RUNS)
                .where(RETENTION_RUNS.c.id == run_id)
                .values(
                    status="failed",
                    failure_code="retention_batch_failed",
                    completed_at=datetime.now(UTC),
                )
            )
            _audit(
                session,
                principal,
                action=AuditAction.RETENTION_BATCH_FAILED,
                resource_type="retention_run",
                resource_id=run_id,
                outcome=AuditOutcome.FAILURE,
                operation="batch",
                result="failed",
                context=context,
            )
            session.commit()
        except SQLAlchemyError:
            session.rollback()
        raise LifecycleError("Retention batch failed; it can be safely retried") from None


def create_legal_hold(
    session: Session,
    principal: Principal,
    *,
    name: str,
    reason: str,
    scope_category: str | None,
    context: AuditContext | None = None,
) -> dict[str, object]:
    require_permission(principal, Permission.DATA_LIFECYCLE_WRITE)
    clean_name, clean_reason = name.strip(), reason.strip()
    if not clean_name or len(clean_name) > 120:
        raise ValueError("Hold name must be between 1 and 120 characters")
    if not clean_reason or len(clean_reason) > 1000:
        raise ValueError("Hold reason must be between 1 and 1000 characters")
    if scope_category is not None and scope_category not in RETENTION_CATEGORIES:
        raise ValueError("Unsupported hold category")
    _trusted_role(session)
    _lock_organization(session, principal.organization_id)
    deletion = session.execute(
        select(ORG_DELETION_REQUESTS.c.status).where(
            ORG_DELETION_REQUESTS.c.org_id == str(principal.organization_id)
        )
    ).scalar_one_or_none()
    if deletion in {"in_progress", "completed"}:
        session.rollback()
        raise LifecycleError("A hold cannot be created during or after organization deletion")
    identifier, now = str(uuid4()), datetime.now(UTC)
    session.execute(
        insert(LEGAL_HOLDS).values(
            id=identifier,
            org_id=str(principal.organization_id),
            name=clean_name,
            reason=clean_reason,
            scope_category=scope_category,
            status="active",
            created_by_member_id=str(principal.member_id),
            created_at=now,
        )
    )
    _audit(
        session,
        principal,
        action=AuditAction.LEGAL_HOLD_CREATED,
        resource_type="legal_hold",
        resource_id=identifier,
        operation="create_hold",
        context=context,
    )
    session.commit()
    return {
        "hold_id": identifier,
        "name": clean_name,
        "reason": clean_reason,
        "scope_category": scope_category,
        "status": "active",
        "created_by_member_id": str(principal.member_id),
        "created_at": now,
        "released_by_member_id": None,
        "released_at": None,
        "release_reason": None,
    }


def list_legal_holds(session: Session, organization_id: UUID) -> list[dict[str, object]]:
    rows = session.execute(
        select(LEGAL_HOLDS)
        .where(LEGAL_HOLDS.c.org_id == str(organization_id))
        .order_by(LEGAL_HOLDS.c.created_at, LEGAL_HOLDS.c.id)
        .limit(500)
    ).mappings()
    return [
        {
            "hold_id": row["id"],
            **{key: row[key] for key in row if key not in {"id", "org_id"}},
        }
        for row in rows
    ]


def release_legal_hold(
    session: Session,
    principal: Principal,
    *,
    hold_id: UUID,
    release_reason: str,
    context: AuditContext | None = None,
) -> dict[str, object]:
    require_permission(principal, Permission.DATA_LIFECYCLE_WRITE)
    reason = release_reason.strip()
    if not reason or len(reason) > 1000:
        raise ValueError("Release reason must be between 1 and 1000 characters")
    _trusted_role(session)
    _lock_organization(session, principal.organization_id)
    result = session.execute(
        update(LEGAL_HOLDS)
        .where(
            LEGAL_HOLDS.c.id == str(hold_id),
            LEGAL_HOLDS.c.org_id == str(principal.organization_id),
            LEGAL_HOLDS.c.status == "active",
        )
        .values(
            status="released",
            released_by_member_id=str(principal.member_id),
            released_at=datetime.now(UTC),
            release_reason=reason,
        )
    )
    if not isinstance(result, CursorResult) or result.rowcount != 1:
        session.rollback()
        raise LookupError("Legal hold not found or already released")
    _audit(
        session,
        principal,
        action=AuditAction.LEGAL_HOLD_RELEASED,
        resource_type="legal_hold",
        resource_id=str(hold_id),
        operation="release_hold",
        context=context,
    )
    row = (
        session.execute(select(LEGAL_HOLDS).where(LEGAL_HOLDS.c.id == str(hold_id)))
        .mappings()
        .one()
    )
    response = {
        "hold_id": row["id"],
        **{key: row[key] for key in row if key not in {"id", "org_id"}},
    }
    session.commit()
    return response


def deletion_status(session: Session, organization_id: UUID) -> dict[str, object]:
    row = (
        session.execute(
            select(ORG_DELETION_REQUESTS).where(
                ORG_DELETION_REQUESTS.c.org_id == str(organization_id)
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return {"status": "active", "current_table": None, "failure_code": None}
    return {
        "status": row["status"],
        "requested_at": row["requested_at"],
        "confirmed_at": row["confirmed_at"],
        "completed_at": row["completed_at"],
        "current_table": row["current_table"],
        "failure_code": row["failure_code"],
    }


def request_organization_deletion(
    session: Session,
    principal: Principal,
    *,
    confirmation_name: str,
    actual_name: str,
    context: AuditContext | None = None,
) -> dict[str, object]:
    require_permission(principal, Permission.ORGANIZATION_DELETE)
    if confirmation_name.strip() != actual_name:
        raise ValueError("Organization name confirmation does not match")
    _trusted_role(session)
    _lock_organization(session, principal.organization_id)
    org_id, now = str(principal.organization_id), datetime.now(UTC)
    prior = (
        session.execute(
            select(ORG_DELETION_REQUESTS).where(ORG_DELETION_REQUESTS.c.org_id == org_id)
        )
        .mappings()
        .one_or_none()
    )
    if prior is not None and prior["status"] in {"requested", "in_progress", "completed"}:
        raise LifecycleError("Organization deletion is already active or complete")
    values = {
        "org_id": org_id,
        "status": "requested",
        "requested_by_member_id": str(principal.member_id),
        "requested_at": now,
        "confirmed_at": None,
        "completed_at": None,
        "current_table": None,
        "failure_code": None,
        "updated_at": now,
    }
    if prior is None:
        session.execute(insert(ORG_DELETION_REQUESTS).values(**values))
    else:
        session.execute(
            update(ORG_DELETION_REQUESTS)
            .where(ORG_DELETION_REQUESTS.c.org_id == org_id)
            .values(**{key: value for key, value in values.items() if key != "org_id"})
        )
    _audit(
        session,
        principal,
        action=AuditAction.ORGANIZATION_DELETION_REQUESTED,
        resource_type="organization",
        resource_id=org_id,
        operation="request_deletion",
        context=context,
    )
    session.commit()
    return deletion_status(session, principal.organization_id)


def confirm_organization_deletion(
    session: Session,
    principal: Principal,
    *,
    confirmation_name: str,
    actual_name: str,
    context: AuditContext | None = None,
) -> dict[str, object]:
    require_permission(principal, Permission.ORGANIZATION_DELETE)
    if confirmation_name.strip() != actual_name:
        raise ValueError("Organization name confirmation does not match")
    _trusted_role(session)
    _lock_organization(session, principal.organization_id)
    row = (
        session.execute(
            select(ORG_DELETION_REQUESTS).where(
                ORG_DELETION_REQUESTS.c.org_id == str(principal.organization_id)
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None or row["status"] not in {"requested", "failed", "blocked_by_legal_hold"}:
        raise LifecycleError("There is no deletion request awaiting confirmation")
    holds = _active_holds(session, principal.organization_id)
    now = datetime.now(UTC)
    status = "blocked_by_legal_hold" if holds else "in_progress"
    first_table = _DELETION_STEPS[0]
    session.execute(
        update(ORG_DELETION_REQUESTS)
        .where(ORG_DELETION_REQUESTS.c.org_id == str(principal.organization_id))
        .values(
            status=status,
            confirmed_at=now,
            current_table=row["current_table"] or first_table,
            failure_code="active_legal_hold" if holds else None,
            updated_at=now,
        )
    )
    if holds:
        _audit(
            session,
            principal,
            action=AuditAction.ORGANIZATION_DELETION_BLOCKED,
            resource_type="organization",
            resource_id=str(principal.organization_id),
            outcome=AuditOutcome.DENIED,
            operation="deletion_blocked",
            result="active_legal_hold",
            context=context,
        )
    else:
        for action, operation in (
            (AuditAction.ORGANIZATION_DELETION_CONFIRMED, "confirm_deletion"),
            (AuditAction.ORGANIZATION_DELETION_STARTED, "start_deletion"),
        ):
            _audit(
                session,
                principal,
                action=action,
                resource_type="organization",
                resource_id=str(principal.organization_id),
                operation=operation,
                context=context,
            )
    session.commit()
    return deletion_status(session, principal.organization_id)


_DELETION_STEPS: tuple[str, ...] = (
    "dlp_approvals",
    "dlp_actions",
    "dlp_exceptions",
    "dlp_suppressions",
    "dlp_policy_versions",
    "dlp_policies",
    "dlp_destinations",
    "dlp_scim_group_members",
    "dlp_scim_users",
    "dlp_scim_groups",
    "dlp_scim_credentials",
    "dlp_sso_identities",
    "dlp_sso_transactions",
    "dlp_sso_replays",
    "dlp_sso_configs",
    "dlp_api_keys",
    "dlp_ip_allowlist_entries",
    "dlp_ip_allowlist_settings",
    "dlp_retention_runs",
    "dlp_retention_policies",
    "dlp_vault_secrets",
    "dlp_scan_idempotency",
    "events",
    "channels",
    "dlp_app_sessions",
    "external_data",
    "members",
    "finalize",
)

_DELETION_TABLES: dict[str, tuple[Any, Any]] = {
    "dlp_approvals": (APPROVALS, APPROVALS.c.org_id),
    "dlp_actions": (ACTIONS, ACTIONS.c.org_id),
    "dlp_exceptions": (EXCEPTIONS, EXCEPTIONS.c.org_id),
    "dlp_suppressions": (SUPPRESSIONS, SUPPRESSIONS.c.org_id),
    "dlp_policy_versions": (POLICY_VERSIONS, POLICY_VERSIONS.c.org_id),
    "dlp_policies": (POLICIES, POLICIES.c.org_id),
    "dlp_destinations": (DESTINATIONS, DESTINATIONS.c.org_id),
    "dlp_scim_group_members": (SCIM_GROUP_MEMBERS, SCIM_GROUP_MEMBERS.c.org_id),
    "dlp_scim_users": (SCIM_USERS, SCIM_USERS.c.org_id),
    "dlp_scim_groups": (SCIM_GROUPS, SCIM_GROUPS.c.org_id),
    "dlp_scim_credentials": (SCIM_CREDENTIALS, SCIM_CREDENTIALS.c.org_id),
    "dlp_sso_identities": (SSO_IDENTITIES, SSO_IDENTITIES.c.org_id),
    "dlp_sso_transactions": (SSO_TRANSACTIONS, SSO_TRANSACTIONS.c.org_id),
    "dlp_sso_replays": (SSO_REPLAYS, SSO_REPLAYS.c.org_id),
    "dlp_sso_configs": (SSO_CONFIGS, SSO_CONFIGS.c.org_id),
    "dlp_api_keys": (API_KEYS, API_KEYS.c.org_id),
    "dlp_ip_allowlist_entries": (IP_ALLOWLIST_ENTRIES, IP_ALLOWLIST_ENTRIES.c.org_id),
    "dlp_ip_allowlist_settings": (IP_ALLOWLIST_SETTINGS, IP_ALLOWLIST_SETTINGS.c.org_id),
    "dlp_retention_runs": (RETENTION_RUNS, RETENTION_RUNS.c.org_id),
    "dlp_retention_policies": (RETENTION_POLICIES, RETENTION_POLICIES.c.org_id),
    "dlp_vault_secrets": (VAULT_SECRETS, VAULT_SECRETS.c.org_id),
    "dlp_scan_idempotency": (SCAN_IDEMPOTENCY, SCAN_IDEMPOTENCY.c.organization_id),
    "events": (EVENTS, EVENTS.c.organization_id),
    "channels": (CHANNELS, CHANNELS.c.organization_id),
    "dlp_app_sessions": (APP_SESSIONS, APP_SESSIONS.c.org_id),
    "members": (MEMBERS, MEMBERS.c.organization_id),
}


def _delete_org_batch(
    session: Session,
    table_name: str,
    organization_id: UUID,
    principal: Principal,
) -> int:
    table, org_column = _DELETION_TABLES[table_name]
    if (
        table_name == "dlp_policy_versions"
        and session.bind is not None
        and session.bind.dialect.name == "postgresql"
    ):
        # P06 policy snapshots remain immutable to normal callers. P14's
        # trusted organization purge opts in only for this transaction.
        session.execute(text("SELECT set_config('app.p14_lifecycle_cleanup', 'on', true)"))
    extra = None
    if table_name == "dlp_app_sessions":
        extra = APP_SESSIONS.c.id != str(principal.session_id)
    elif table_name == "members":
        extra = MEMBERS.c.id != str(principal.member_id)
    return _batch_delete(
        session,
        table,
        org_column,
        organization_id,
        limit=DELETION_BATCH_SIZE,
        extra=extra,
    )


def _finalize_deletion(
    session: Session,
    principal: Principal,
    *,
    context: AuditContext | None,
) -> None:
    org_id = str(principal.organization_id)
    if _active_holds(session, principal.organization_id):
        session.execute(
            update(ORG_DELETION_REQUESTS)
            .where(ORG_DELETION_REQUESTS.c.org_id == org_id)
            .values(status="blocked_by_legal_hold", failure_code="active_legal_hold")
        )
        _audit(
            session,
            principal,
            action=AuditAction.ORGANIZATION_DELETION_BLOCKED,
            resource_type="organization",
            resource_id=org_id,
            outcome=AuditOutcome.DENIED,
            operation="deletion_blocked",
            result="active_legal_hold",
            context=context,
        )
        return
    session.execute(
        delete(APP_SESSIONS).where(
            APP_SESSIONS.c.id == str(principal.session_id),
            APP_SESSIONS.c.org_id == org_id,
        )
    )
    session.execute(
        delete(MEMBERS).where(
            MEMBERS.c.id == str(principal.member_id), MEMBERS.c.organization_id == org_id
        )
    )
    session.execute(
        update(ORGANIZATIONS)
        .where(ORGANIZATIONS.c.id == org_id)
        .values(
            name=f"Deleted organization {org_id[:8]}",
            settings_json={},
            updated_at=datetime.now(UTC),
        )
    )
    session.execute(
        update(ORG_DELETION_REQUESTS)
        .where(ORG_DELETION_REQUESTS.c.org_id == org_id)
        .values(
            status="completed",
            completed_at=datetime.now(UTC),
            current_table=None,
            failure_code=None,
            updated_at=datetime.now(UTC),
        )
    )
    _audit(
        session,
        principal,
        action=AuditAction.ORGANIZATION_DELETION_COMPLETED,
        resource_type="organization",
        resource_id=org_id,
        operation="complete_deletion",
        context=context,
    )


def execute_organization_deletion(
    session: Session,
    principal: Principal,
    *,
    max_batches: int = DELETION_BATCHES_PER_CALL,
    context: AuditContext | None = None,
) -> dict[str, object]:
    require_permission(principal, Permission.ORGANIZATION_DELETE)
    if not 1 <= max_batches <= DELETION_BATCHES_PER_CALL:
        raise ValueError("Deletion batch count must be between 1 and 20")
    _trusted_role(session)
    org_id = str(principal.organization_id)
    row = (
        session.execute(
            select(ORG_DELETION_REQUESTS).where(ORG_DELETION_REQUESTS.c.org_id == org_id)
        )
        .mappings()
        .one_or_none()
    )
    if row is None or row["status"] not in {"in_progress", "failed"}:
        raise LifecycleError("Organization deletion is not ready to execute")
    if row["status"] == "failed":
        _audit(
            session,
            principal,
            action=AuditAction.ORGANIZATION_DELETION_STARTED,
            resource_type="organization",
            resource_id=org_id,
            operation="retry_deletion",
            context=context,
        )
        session.execute(
            update(ORG_DELETION_REQUESTS)
            .where(ORG_DELETION_REQUESTS.c.org_id == org_id)
            .values(status="in_progress", failure_code=None, updated_at=datetime.now(UTC))
        )
        session.commit()

    deleted_count = 0
    try:
        for _ in range(max_batches):
            _lock_organization(session, principal.organization_id)
            job = (
                session.execute(
                    select(ORG_DELETION_REQUESTS).where(ORG_DELETION_REQUESTS.c.org_id == org_id)
                )
                .mappings()
                .one()
            )
            if _active_holds(session, principal.organization_id):
                session.execute(
                    update(ORG_DELETION_REQUESTS)
                    .where(ORG_DELETION_REQUESTS.c.org_id == org_id)
                    .values(
                        status="blocked_by_legal_hold",
                        failure_code="active_legal_hold",
                        updated_at=datetime.now(UTC),
                    )
                )
                _audit(
                    session,
                    principal,
                    action=AuditAction.ORGANIZATION_DELETION_BLOCKED,
                    resource_type="organization",
                    resource_id=org_id,
                    outcome=AuditOutcome.DENIED,
                    operation="deletion_blocked",
                    result="active_legal_hold",
                    context=context,
                )
                session.commit()
                break

            current = str(job["current_table"] or _DELETION_STEPS[0])
            if current == "finalize":
                _finalize_deletion(session, principal, context=context)
                session.commit()
                break
            if current == "external_data":
                for adapter in adapters():
                    adapter.delete_organization(principal.organization_id)
                current = _DELETION_STEPS[_DELETION_STEPS.index("external_data") + 1]
                session.execute(
                    update(ORG_DELETION_REQUESTS)
                    .where(ORG_DELETION_REQUESTS.c.org_id == org_id)
                    .values(current_table=current, updated_at=datetime.now(UTC))
                )
                session.commit()
                continue

            removed = _delete_org_batch(session, current, principal.organization_id, principal)
            deleted_count += removed
            if removed < DELETION_BATCH_SIZE:
                current = _DELETION_STEPS[_DELETION_STEPS.index(current) + 1]
            session.execute(
                update(ORG_DELETION_REQUESTS)
                .where(ORG_DELETION_REQUESTS.c.org_id == org_id)
                .values(current_table=current, updated_at=datetime.now(UTC))
            )
            session.commit()
    except Exception:
        session.rollback()
        try:
            session.execute(
                update(ORG_DELETION_REQUESTS)
                .where(ORG_DELETION_REQUESTS.c.org_id == org_id)
                .values(
                    status="failed",
                    failure_code="deletion_batch_failed",
                    updated_at=datetime.now(UTC),
                )
            )
            _audit(
                session,
                principal,
                action=AuditAction.ORGANIZATION_DELETION_FAILED,
                resource_type="organization",
                resource_id=org_id,
                outcome=AuditOutcome.FAILURE,
                operation="deletion_batch",
                result="retryable_failure",
                context=context,
            )
            session.commit()
        except SQLAlchemyError:
            session.rollback()
        raise LifecycleError("Organization deletion paused; retry from its saved phase") from None
    status = deletion_status(session, principal.organization_id)
    status["deleted_rows_this_call"] = deleted_count
    status["remaining_batches_possible"] = status["status"] == "in_progress"
    return status


def _rows(session: Session, query: Any) -> list[Any]:
    return list(session.execute(query.limit(MAX_EXPORT_ROWS_PER_CATEGORY)).mappings())


def build_subject_export(
    session: Session,
    *,
    organization_id: UUID,
    organization_name: str,
    member_id: UUID,
    subject_id: str,
) -> dict[str, object]:
    org_id, member = str(organization_id), str(member_id)
    profile = (
        session.execute(
            select(
                MEMBERS.c.id,
                MEMBERS.c.auth_subject_id,
                MEMBERS.c.email,
                MEMBERS.c.role,
                MEMBERS.c.active,
                MEMBERS.c.created_at,
            ).where(MEMBERS.c.id == member, MEMBERS.c.organization_id == org_id)
        )
        .mappings()
        .one_or_none()
    )
    if profile is None:
        raise LookupError("Subject not found")
    if str(profile["auth_subject_id"]) != subject_id:
        raise LookupError("Subject not found")

    categories: dict[str, list[dict[str, object]]] = {}
    queries = {
        "sessions": select(
            APP_SESSIONS.c.id,
            APP_SESSIONS.c.auth_method,
            APP_SESSIONS.c.created_at,
            APP_SESSIONS.c.last_seen_at,
            APP_SESSIONS.c.expires_at,
            APP_SESSIONS.c.revoked_at,
            APP_SESSIONS.c.source_ip,
            APP_SESSIONS.c.user_agent,
        )
        .where(APP_SESSIONS.c.org_id == org_id, APP_SESSIONS.c.member_id == member)
        .order_by(APP_SESSIONS.c.created_at, APP_SESSIONS.c.id),
        "api_keys": select(
            API_KEYS.c.id,
            API_KEYS.c.name,
            API_KEYS.c.prefix,
            API_KEYS.c.scopes,
            API_KEYS.c.created_at,
            API_KEYS.c.last_used_at,
            API_KEYS.c.revoked_at,
        )
        .where(API_KEYS.c.org_id == org_id, API_KEYS.c.created_by == member)
        .order_by(API_KEYS.c.created_at, API_KEYS.c.id),
        "policies_authored": select(
            POLICIES.c.id,
            POLICIES.c.name,
            POLICIES.c.enabled,
            POLICIES.c.action,
            POLICIES.c.version,
            POLICIES.c.created_at,
            POLICIES.c.updated_at,
        )
        .where(POLICIES.c.org_id == org_id, POLICIES.c.created_by == member)
        .order_by(POLICIES.c.created_at, POLICIES.c.id),
        "policy_versions_authored": select(
            POLICY_VERSIONS.c.id,
            POLICY_VERSIONS.c.policy_id,
            POLICY_VERSIONS.c.version,
            POLICY_VERSIONS.c.created_at,
        )
        .where(POLICY_VERSIONS.c.org_id == org_id, POLICY_VERSIONS.c.created_by == member)
        .order_by(POLICY_VERSIONS.c.created_at, POLICY_VERSIONS.c.id),
        "exceptions": select(
            EXCEPTIONS.c.id,
            EXCEPTIONS.c.policy_id,
            EXCEPTIONS.c.enabled,
            EXCEPTIONS.c.expires_at,
            EXCEPTIONS.c.created_at,
        )
        .where(
            EXCEPTIONS.c.org_id == org_id,
            (EXCEPTIONS.c.created_by == member) | (EXCEPTIONS.c.approver_id == member),
        )
        .order_by(EXCEPTIONS.c.created_at, EXCEPTIONS.c.id),
        "suppressions_authored": select(
            SUPPRESSIONS.c.id,
            SUPPRESSIONS.c.enabled,
            SUPPRESSIONS.c.expires_at,
            SUPPRESSIONS.c.created_at,
        )
        .where(
            SUPPRESSIONS.c.org_id == org_id,
            (SUPPRESSIONS.c.created_by == member) | (SUPPRESSIONS.c.updated_by == member),
        )
        .order_by(SUPPRESSIONS.c.created_at, SUPPRESSIONS.c.id),
        "actions_requested": select(
            ACTIONS.c.id,
            ACTIONS.c.action,
            ACTIONS.c.status,
            ACTIONS.c.created_at,
            ACTIONS.c.updated_at,
        )
        .where(ACTIONS.c.org_id == org_id, ACTIONS.c.requested_by == member)
        .order_by(ACTIONS.c.created_at, ACTIONS.c.id),
        "approvals": select(
            APPROVALS.c.id,
            APPROVALS.c.action_id,
            APPROVALS.c.status,
            APPROVALS.c.created_at,
            APPROVALS.c.decided_at,
        )
        .where(
            APPROVALS.c.org_id == org_id,
            (APPROVALS.c.requested_by == member) | (APPROVALS.c.decided_by == member),
        )
        .order_by(APPROVALS.c.created_at, APPROVALS.c.id),
        "scim_identity": select(
            SCIM_USERS.c.id,
            SCIM_USERS.c.external_id,
            SCIM_USERS.c.user_name,
            SCIM_USERS.c.display_name,
            SCIM_USERS.c.created_at,
            SCIM_USERS.c.updated_at,
        )
        .where(SCIM_USERS.c.org_id == org_id, SCIM_USERS.c.member_id == member)
        .order_by(SCIM_USERS.c.created_at, SCIM_USERS.c.id),
        "sso_identities": select(
            SSO_IDENTITIES.c.id,
            SSO_IDENTITIES.c.issuer,
            SSO_IDENTITIES.c.subject,
            SSO_IDENTITIES.c.email,
            SSO_IDENTITIES.c.created_at,
        )
        .where(SSO_IDENTITIES.c.org_id == org_id, SSO_IDENTITIES.c.member_id == member)
        .order_by(SSO_IDENTITIES.c.created_at, SSO_IDENTITIES.c.id),
        "scim_credentials_created": select(
            SCIM_CREDENTIALS.c.id,
            SCIM_CREDENTIALS.c.name,
            SCIM_CREDENTIALS.c.prefix,
            SCIM_CREDENTIALS.c.created_at,
            SCIM_CREDENTIALS.c.last_used_at,
            SCIM_CREDENTIALS.c.revoked_at,
        )
        .where(SCIM_CREDENTIALS.c.org_id == org_id, SCIM_CREDENTIALS.c.created_by == member)
        .order_by(SCIM_CREDENTIALS.c.created_at, SCIM_CREDENTIALS.c.id),
        "audit_events": select(
            AUDIT_EVENTS.c.event_id,
            AUDIT_EVENTS.c.occurred_at,
            AUDIT_EVENTS.c.actor_type,
            AUDIT_EVENTS.c.auth_method,
            AUDIT_EVENTS.c.action,
            AUDIT_EVENTS.c.resource_type,
            AUDIT_EVENTS.c.resource_id,
            AUDIT_EVENTS.c.outcome,
            AUDIT_EVENTS.c.correlation_id,
            AUDIT_EVENTS.c.event_metadata,
            AUDIT_EVENTS.c.sequence_number,
            AUDIT_EVENTS.c.event_hash,
        )
        .where(
            AUDIT_EVENTS.c.organization_id == org_id,
            AUDIT_EVENTS.c.actor_id.in_([member, subject_id]),
        )
        .order_by(AUDIT_EVENTS.c.sequence_number),
    }
    truncated: list[str] = []
    for category, query in queries.items():
        rows = _rows(session, query)
        categories[category] = [
            {
                (
                    "session_id"
                    if key == "id" and category == "sessions"
                    else "api_key_id"
                    if key == "id" and category == "api_keys"
                    else "identity_id"
                    if key == "id" and category in {"scim_identity", "sso_identities"}
                    else "record_id"
                    if key == "id"
                    else key
                ): value
                if key != "user_agent" or category != "sessions"
                else sanitize_metadata({"user_agent": value})["user_agent"]
                for key, value in row.items()
            }
            for row in rows
        ]
        if len(rows) == MAX_EXPORT_ROWS_PER_CATEGORY:
            truncated.append(category)

    external: dict[str, object] = {}
    for adapter in adapters():
        external[adapter.name] = adapter.export_subject(organization_id, member_id)
    data: dict[str, object] = {
        "schema_version": "p2.subject-export.v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "scope": {
            "organization_id": org_id,
            "organization_name": organization_name,
            "member_id": member,
            "multi_organization_scope": "current_organization_only",
        },
        "subject": {
            "subject_id": profile["auth_subject_id"],
            "email": profile["email"],
            "role": profile["role"],
            "active": profile["active"],
            "created_at": profile["created_at"],
        },
        "memberships": [
            {
                "organization_id": org_id,
                "organization_name": organization_name,
                "member_id": member,
                "role": profile["role"],
                "active": profile["active"],
                "created_at": profile["created_at"],
            }
        ],
        "p2_data": categories,
        "external_data": external,
        "truncated_categories": truncated,
        "excluded": [
            "passwords",
            "bearer_tokens_and_session_token_hashes",
            "API_key_plaintext_and_hashes",
            "SCIM_token_values_and_hashes",
            "vault_ciphertext_and_plaintext",
            "private_keys",
            "legal_hold_reasons",
            "other_organizations",
        ],
    }
    serialized = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
    if len(serialized.encode("utf-8")) > MAX_EXPORT_BYTES:
        raise LifecycleError("Subject export exceeds the safe response size")
    return data


def record_subject_export(
    session: Session,
    principal: Principal,
    *,
    member_id: UUID,
    result: str,
    context: AuditContext | None = None,
) -> None:
    if result == "requested":
        _audit(
            session,
            principal,
            action=AuditAction.SUBJECT_EXPORT_REQUESTED,
            resource_type="subject_export",
            resource_id=str(member_id),
            operation="request_export",
            context=context,
        )
    elif result == "completed":
        _audit(
            session,
            principal,
            action=AuditAction.SUBJECT_EXPORT_COMPLETED,
            resource_type="subject_export",
            resource_id=str(member_id),
            operation="complete_export",
            result=result,
            context=context,
        )
    else:
        _audit(
            session,
            principal,
            action=AuditAction.SUBJECT_EXPORT_FAILED,
            resource_type="subject_export",
            resource_id=str(member_id),
            outcome=AuditOutcome.FAILURE,
            operation="complete_export",
            result="failed",
            context=context,
        )
    session.commit()
