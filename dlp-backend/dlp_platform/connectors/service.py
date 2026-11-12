"""Tenant-scoped connector persistence and safe lifecycle operations."""

import json
from datetime import UTC, datetime
from uuid import UUID, uuid4

from fastapi import HTTPException
from sqlalchemy import insert, select, text, update
from sqlalchemy.engine import CursorResult, RowMapping
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from dlp_platform.audit.service import AuditContext, AuditPersistenceError, AuditService
from dlp_platform.auth.permissions import require_permission
from dlp_platform.auth.roles import Permission
from dlp_platform.connectors.models import (
    ConnectorHealth,
    ConnectorIdentity,
    ConnectorStatus,
    validate_status_transition,
)
from dlp_platform.contracts.audit_event import AuditAction, AuditOutcome
from dlp_platform.contracts.principal import Principal
from dlp_platform.tables import DLP_CONNECTOR_STATE, DLP_CONNECTORS


class ConnectorOperationFailed(RuntimeError):
    """Connector persistence failed without exposing database details."""


class ConnectorService:
    @staticmethod
    def _rls(session: Session, principal: Principal) -> None:
        if session.bind is not None and session.bind.dialect.name == "postgresql":
            session.execute(text("SET LOCAL ROLE authenticated"))
            session.execute(
                text("SELECT set_config('request.jwt.claims', :claims, true)"),
                {
                    "claims": json.dumps(
                        {
                            "role": "authenticated",
                            "aud": "authenticated",
                            "org_id": str(principal.organization_id),
                            "app_role": principal.role.value,
                            "sub": principal.subject_id,
                        }
                    )
                },
            )

    def list(self, session: Session, principal: Principal) -> list[ConnectorHealth]:
        require_permission(principal, Permission.CONNECTORS_READ)
        self._rls(session, principal)
        rows = (
            session.execute(
                select(DLP_CONNECTORS)
                .where(DLP_CONNECTORS.c.org_id == str(principal.organization_id))
                .order_by(DLP_CONNECTORS.c.created_at.desc())
            )
            .mappings()
            .all()
        )
        return [self._health(row) for row in rows]

    def get(self, session: Session, principal: Principal, connector_id: UUID) -> ConnectorHealth:
        require_permission(principal, Permission.CONNECTORS_READ)
        self._rls(session, principal)
        row = (
            session.execute(
                select(DLP_CONNECTORS).where(
                    DLP_CONNECTORS.c.id == str(connector_id),
                    DLP_CONNECTORS.c.org_id == str(principal.organization_id),
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise HTTPException(status_code=404, detail="Connector not found")
        return self._health(row)

    def create(
        self,
        session: Session,
        principal: Principal,
        *,
        provider: str,
        name: str,
        config: dict[str, object] | None = None,
        audit_context: AuditContext | None = None,
    ) -> ConnectorHealth:
        require_permission(principal, Permission.CONNECTORS_WRITE)
        self._rls(session, principal)
        if provider not in {
            "google_drive",
            "microsoft_onedrive",
            "microsoft_sharepoint",
            "aws_s3",
            "google_cloud_storage",
        }:
            raise HTTPException(status_code=422, detail="Unsupported connector provider")
        identifier, now = uuid4(), datetime.now(UTC)
        try:
            session.execute(
                insert(DLP_CONNECTORS).values(
                    id=str(identifier),
                    org_id=str(principal.organization_id),
                    provider=provider,
                    name=name,
                    status=ConnectorStatus.DISCONNECTED.value,
                    credential_secret_id=None,
                    config_json=config or {},
                    last_sync_at=None,
                    last_error_code=None,
                    created_at=now,
                    updated_at=now,
                )
            )
            session.execute(
                insert(DLP_CONNECTOR_STATE).values(
                    connector_id=str(identifier),
                    org_id=str(principal.organization_id),
                    provider=provider,
                    checkpoint=None,
                    state_json={},
                    updated_at=now,
                )
            )
            AuditService().record_event(
                session,
                principal,
                action=AuditAction.CONNECTOR_CREATED,
                resource_type="connector",
                resource_id=str(identifier),
                metadata={"provider": provider},
                context=audit_context,
            )
            session.commit()
        except (SQLAlchemyError, AuditPersistenceError, ValueError):
            session.rollback()
            raise ConnectorOperationFailed("Connector operation failed") from None
        return ConnectorHealth(
            identity=ConnectorIdentity(
                connector_id=identifier,
                organization_id=principal.organization_id,
                provider=provider,
            ),
            status=ConnectorStatus.DISCONNECTED,
        )

    def configuration(
        self, session: Session, principal: Principal, connector_id: UUID
    ) -> dict[str, object]:
        """Return non-secret configuration for one connector in the principal tenant."""
        require_permission(principal, Permission.CONNECTORS_READ)
        self._rls(session, principal)
        row = session.execute(
            select(DLP_CONNECTORS.c.config_json).where(
                DLP_CONNECTORS.c.id == str(connector_id),
                DLP_CONNECTORS.c.org_id == str(principal.organization_id),
            )
        ).scalar_one_or_none()
        if not isinstance(row, dict):
            raise HTTPException(status_code=404, detail="Connector not found")
        return dict(row)

    def update_configuration(
        self,
        session: Session,
        principal: Principal,
        connector_id: UUID,
        config: dict[str, object],
    ) -> None:
        """Update bounded non-secret connector configuration under tenant RLS."""
        require_permission(principal, Permission.CONNECTORS_WRITE)
        self._rls(session, principal)
        result = session.execute(
            update(DLP_CONNECTORS)
            .where(
                DLP_CONNECTORS.c.id == str(connector_id),
                DLP_CONNECTORS.c.org_id == str(principal.organization_id),
            )
            .values(config_json=config, updated_at=datetime.now(UTC))
        )
        if not isinstance(result, CursorResult) or result.rowcount != 1:
            session.rollback()
            raise HTTPException(status_code=404, detail="Connector not found")
        session.commit()

    def begin_connect(self, session: Session, principal: Principal, connector_id: UUID) -> None:
        require_permission(principal, Permission.CONNECTORS_WRITE)
        self._rls(session, principal)
        row = session.execute(
            select(DLP_CONNECTORS.c.status)
            .where(
                DLP_CONNECTORS.c.id == str(connector_id),
                DLP_CONNECTORS.c.org_id == str(principal.organization_id),
            )
            .with_for_update()
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(status_code=404, detail="Connector not found")
        try:
            validate_status_transition(ConnectorStatus(str(row)), ConnectorStatus.CONNECTING)
        except ValueError:
            raise HTTPException(
                status_code=409, detail="Connector cannot start authorization"
            ) from None
        session.execute(
            update(DLP_CONNECTORS)
            .where(
                DLP_CONNECTORS.c.id == str(connector_id),
                DLP_CONNECTORS.c.org_id == str(principal.organization_id),
            )
            .values(status=ConnectorStatus.CONNECTING.value, updated_at=datetime.now(UTC))
        )
        session.commit()

    def set_connection(
        self,
        session: Session,
        principal: Principal,
        connector_id: UUID,
        *,
        secret_id: UUID,
        checkpoint: str,
        state_json: dict[str, object] | None = None,
        audit_context: AuditContext | None = None,
    ) -> ConnectorHealth:
        require_permission(principal, Permission.CONNECTORS_WRITE)
        self._rls(session, principal)
        now, org_id = datetime.now(UTC), str(principal.organization_id)
        try:
            row = (
                session.execute(
                    select(DLP_CONNECTORS)
                    .where(
                        DLP_CONNECTORS.c.id == str(connector_id),
                        DLP_CONNECTORS.c.org_id == org_id,
                    )
                    .with_for_update()
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise HTTPException(status_code=404, detail="Connector not found")
            validate_status_transition(
                ConnectorStatus(str(row["status"])), ConnectorStatus.CONNECTED
            )
            session.execute(
                update(DLP_CONNECTORS)
                .where(
                    DLP_CONNECTORS.c.id == str(connector_id),
                    DLP_CONNECTORS.c.org_id == org_id,
                )
                .values(
                    status=ConnectorStatus.CONNECTED.value,
                    credential_secret_id=str(secret_id),
                    last_error_code=None,
                    updated_at=now,
                )
            )
            session.execute(
                update(DLP_CONNECTOR_STATE)
                .where(
                    DLP_CONNECTOR_STATE.c.connector_id == str(connector_id),
                    DLP_CONNECTOR_STATE.c.org_id == org_id,
                )
                .values(
                    checkpoint=checkpoint,
                    state_json=state_json
                    if state_json is not None
                    else {"initial_inventory_pending": True, "inventory_page_token": None},
                    updated_at=now,
                )
            )
            AuditService().record_event(
                session,
                principal,
                action=AuditAction.CONNECTOR_CONNECTED,
                resource_type="connector",
                resource_id=str(connector_id),
                metadata={"provider": str(row["provider"])},
                context=audit_context,
            )
            session.commit()
        except HTTPException:
            session.rollback()
            raise
        except (SQLAlchemyError, AuditPersistenceError, ValueError):
            session.rollback()
            raise ConnectorOperationFailed("Connector operation failed") from None
        return ConnectorHealth(
            identity=ConnectorIdentity(
                connector_id=connector_id,
                organization_id=principal.organization_id,
                provider=str(row["provider"]),
            ),
            status=ConnectorStatus.CONNECTED,
            last_sync_at=now,
        )

    def mark_connect_failed(
        self,
        session: Session,
        principal: Principal,
        connector_id: UUID,
        audit_context: AuditContext | None = None,
    ) -> None:
        self._rls(session, principal)
        try:
            current = (
                session.execute(
                    select(DLP_CONNECTORS.c.status, DLP_CONNECTORS.c.provider)
                    .where(
                        DLP_CONNECTORS.c.id == str(connector_id),
                        DLP_CONNECTORS.c.org_id == str(principal.organization_id),
                    )
                    .with_for_update()
                )
                .mappings()
                .one_or_none()
            )
            if (
                current is None
                or ConnectorStatus(str(current["status"])) is not ConnectorStatus.CONNECTING
            ):
                return
            session.execute(
                update(DLP_CONNECTORS)
                .where(
                    DLP_CONNECTORS.c.id == str(connector_id),
                    DLP_CONNECTORS.c.org_id == str(principal.organization_id),
                )
                .values(
                    status=ConnectorStatus.ERROR.value,
                    last_error_code="connection_failed",
                    updated_at=datetime.now(UTC),
                )
            )
            AuditService().record_event(
                session,
                principal,
                action=AuditAction.CONNECTOR_OAUTH_COMPLETED,
                resource_type="connector",
                resource_id=str(connector_id),
                outcome=AuditOutcome.FAILURE,
                metadata={"provider": str(current["provider"])},
                context=audit_context,
            )
            session.commit()
        except (SQLAlchemyError, AuditPersistenceError, ValueError):
            session.rollback()
            raise ConnectorOperationFailed("Connector operation failed") from None

    def disconnect(
        self,
        session: Session,
        principal: Principal,
        connector_id: UUID,
        audit_context: AuditContext | None = None,
    ) -> ConnectorHealth:
        require_permission(principal, Permission.CONNECTORS_WRITE)
        self._rls(session, principal)
        org_id, now = str(principal.organization_id), datetime.now(UTC)
        try:
            row = (
                session.execute(
                    select(DLP_CONNECTORS)
                    .where(
                        DLP_CONNECTORS.c.id == str(connector_id),
                        DLP_CONNECTORS.c.org_id == org_id,
                    )
                    .with_for_update()
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise HTTPException(status_code=404, detail="Connector not found")
            current = ConnectorStatus(str(row["status"]))
            if current is not ConnectorStatus.DISCONNECTED:
                validate_status_transition(current, ConnectorStatus.DISCONNECTING)
            session.execute(
                update(DLP_CONNECTORS)
                .where(
                    DLP_CONNECTORS.c.id == str(connector_id),
                    DLP_CONNECTORS.c.org_id == org_id,
                )
                .values(
                    status=ConnectorStatus.DISCONNECTED.value,
                    credential_secret_id=None,
                    last_error_code=None,
                    updated_at=now,
                )
            )
            session.execute(
                update(DLP_CONNECTOR_STATE)
                .where(
                    DLP_CONNECTOR_STATE.c.connector_id == str(connector_id),
                    DLP_CONNECTOR_STATE.c.org_id == org_id,
                )
                .values(checkpoint=None, state_json={}, updated_at=now)
            )
            AuditService().record_event(
                session,
                principal,
                action=AuditAction.CONNECTOR_DISCONNECTED,
                resource_type="connector",
                resource_id=str(connector_id),
                metadata={"provider": str(row["provider"])},
                context=audit_context,
            )
            session.commit()
        except HTTPException:
            session.rollback()
            raise
        except (SQLAlchemyError, AuditPersistenceError, ValueError):
            session.rollback()
            raise ConnectorOperationFailed("Connector operation failed") from None
        return ConnectorHealth(
            identity=ConnectorIdentity(
                connector_id=connector_id,
                organization_id=principal.organization_id,
                provider=str(row["provider"]),
            ),
            status=ConnectorStatus.DISCONNECTED,
        )

    def sync_inputs(
        self, session: Session, principal: Principal, connector_id: UUID
    ) -> tuple[UUID, str | None, dict[str, object]]:
        require_permission(principal, Permission.CONNECTORS_WRITE)
        self._rls(session, principal)
        row = (
            session.execute(
                select(
                    DLP_CONNECTORS.c.credential_secret_id,
                    DLP_CONNECTOR_STATE.c.checkpoint,
                    DLP_CONNECTOR_STATE.c.state_json,
                    DLP_CONNECTORS.c.status,
                )
                .join(
                    DLP_CONNECTOR_STATE,
                    (DLP_CONNECTOR_STATE.c.connector_id == DLP_CONNECTORS.c.id)
                    & (DLP_CONNECTOR_STATE.c.org_id == DLP_CONNECTORS.c.org_id),
                )
                .where(
                    DLP_CONNECTORS.c.id == str(connector_id),
                    DLP_CONNECTORS.c.org_id == str(principal.organization_id),
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None or row["credential_secret_id"] is None:
            raise HTTPException(status_code=404, detail="Connector not found")
        if row["status"] not in {ConnectorStatus.CONNECTED.value, ConnectorStatus.DEGRADED.value}:
            raise HTTPException(status_code=409, detail="Connector is not ready to sync")
        state_json = row["state_json"]
        if not isinstance(state_json, dict):
            raise ConnectorOperationFailed("Connector state is invalid")
        return UUID(str(row["credential_secret_id"])), row["checkpoint"], state_json

    def complete_sync(
        self,
        session: Session,
        principal: Principal,
        connector_id: UUID,
        *,
        checkpoint: str,
        exposure_count: int,
        provider: str = "google_drive",
        state_json: dict[str, object] | None = None,
        audit_context: AuditContext | None = None,
    ) -> None:
        self._rls(session, principal)
        now, org_id = datetime.now(UTC), str(principal.organization_id)
        try:
            result = session.execute(
                update(DLP_CONNECTOR_STATE)
                .where(
                    DLP_CONNECTOR_STATE.c.connector_id == str(connector_id),
                    DLP_CONNECTOR_STATE.c.org_id == org_id,
                )
                .values(
                    checkpoint=checkpoint,
                    state_json=state_json
                    if state_json is not None
                    else DLP_CONNECTOR_STATE.c.state_json,
                    updated_at=now,
                )
            )
            if not isinstance(result, CursorResult) or result.rowcount != 1:
                raise ConnectorOperationFailed("Connector state is unavailable")
            current = session.execute(
                select(DLP_CONNECTORS.c.status)
                .where(DLP_CONNECTORS.c.id == str(connector_id), DLP_CONNECTORS.c.org_id == org_id)
                .with_for_update()
            ).scalar_one_or_none()
            if current is None:
                raise ConnectorOperationFailed("Connector state is unavailable")
            current_status = ConnectorStatus(str(current))
            if current_status is not ConnectorStatus.CONNECTED:
                validate_status_transition(current_status, ConnectorStatus.CONNECTED)
            session.execute(
                update(DLP_CONNECTORS)
                .where(DLP_CONNECTORS.c.id == str(connector_id), DLP_CONNECTORS.c.org_id == org_id)
                .values(
                    status=ConnectorStatus.CONNECTED.value,
                    last_sync_at=now,
                    last_error_code=None,
                    updated_at=now,
                )
            )
            if exposure_count:
                AuditService().record_event(
                    session,
                    principal,
                    action=AuditAction.CONNECTOR_EXPOSURE_DETECTED,
                    resource_type="connector",
                    resource_id=str(connector_id),
                    metadata={"provider": provider, "count": exposure_count},
                    context=audit_context,
                )
            session.commit()
        except (SQLAlchemyError, AuditPersistenceError, ValueError, ConnectorOperationFailed):
            session.rollback()
            raise ConnectorOperationFailed("Connector operation failed") from None

    def mark_reauth_required(
        self,
        session: Session,
        principal: Principal,
        connector_id: UUID,
        audit_context: AuditContext | None = None,
        provider: str = "google_drive",
    ) -> None:
        self._rls(session, principal)
        try:
            current = session.execute(
                select(DLP_CONNECTORS.c.status)
                .where(
                    DLP_CONNECTORS.c.id == str(connector_id),
                    DLP_CONNECTORS.c.org_id == str(principal.organization_id),
                )
                .with_for_update()
            ).scalar_one_or_none()
            if current is None:
                raise ConnectorOperationFailed("Connector state is unavailable")
            validate_status_transition(
                ConnectorStatus(str(current)), ConnectorStatus.REAUTH_REQUIRED
            )
            session.execute(
                update(DLP_CONNECTORS)
                .where(
                    DLP_CONNECTORS.c.id == str(connector_id),
                    DLP_CONNECTORS.c.org_id == str(principal.organization_id),
                )
                .values(
                    status=ConnectorStatus.REAUTH_REQUIRED.value,
                    last_error_code="reauth_required",
                    updated_at=datetime.now(UTC),
                )
            )
            AuditService().record_event(
                session,
                principal,
                action=AuditAction.CONNECTOR_REAUTH_REQUIRED,
                resource_type="connector",
                resource_id=str(connector_id),
                metadata={"provider": provider},
                context=audit_context,
            )
            session.commit()
        except (SQLAlchemyError, AuditPersistenceError, ValueError, ConnectorOperationFailed):
            session.rollback()
            raise ConnectorOperationFailed("Connector operation failed") from None

    def mark_degraded(
        self,
        session: Session,
        principal: Principal,
        connector_id: UUID,
        audit_context: AuditContext | None = None,
        provider: str = "google_drive",
    ) -> None:
        self._rls(session, principal)
        try:
            current = session.execute(
                select(DLP_CONNECTORS.c.status)
                .where(
                    DLP_CONNECTORS.c.id == str(connector_id),
                    DLP_CONNECTORS.c.org_id == str(principal.organization_id),
                )
                .with_for_update()
            ).scalar_one_or_none()
            if current is None:
                raise ConnectorOperationFailed("Connector state is unavailable")
            validate_status_transition(ConnectorStatus(str(current)), ConnectorStatus.DEGRADED)
            session.execute(
                update(DLP_CONNECTORS)
                .where(
                    DLP_CONNECTORS.c.id == str(connector_id),
                    DLP_CONNECTORS.c.org_id == str(principal.organization_id),
                )
                .values(
                    status=ConnectorStatus.DEGRADED.value,
                    last_error_code="sync_failed",
                    updated_at=datetime.now(UTC),
                )
            )
            AuditService().record_event(
                session,
                principal,
                action=AuditAction.CONNECTOR_SYNC_FAILED,
                resource_type="connector",
                resource_id=str(connector_id),
                outcome=AuditOutcome.FAILURE,
                metadata={"provider": provider},
                context=audit_context,
            )
            session.commit()
        except (SQLAlchemyError, AuditPersistenceError, ValueError, ConnectorOperationFailed):
            session.rollback()
            raise ConnectorOperationFailed("Connector operation failed") from None

    @staticmethod
    def _health(row: RowMapping) -> ConnectorHealth:
        value = dict(row)
        return ConnectorHealth(
            identity=ConnectorIdentity(
                connector_id=UUID(str(value["id"])),
                organization_id=UUID(str(value["org_id"])),
                provider=str(value["provider"]),
            ),
            status=ConnectorStatus(str(value["status"])),
            last_sync_at=value["last_sync_at"],
            last_error_code=value["last_error_code"],
        )
