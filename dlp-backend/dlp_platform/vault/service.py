"""Tenant-scoped secret operations; plaintext retrieval is Python-internal only."""

from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID, uuid4

from fastapi import HTTPException
from pydantic import SecretStr
from sqlalchemy import insert, select, update
from sqlalchemy.engine import CursorResult, RowMapping
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from dlp_platform.audit.service import AuditContext, AuditPersistenceError, AuditService
from dlp_platform.auth.permissions import require_permission
from dlp_platform.auth.roles import Permission
from dlp_platform.contracts.audit_event import AuditAction
from dlp_platform.contracts.principal import Principal
from dlp_platform.tables import VAULT_SECRETS
from dlp_platform.vault.config import VaultConfigurationError
from dlp_platform.vault.crypto import AesGcmEncryptionProvider, EnvironmentKeyProvider, KeyProvider
from dlp_platform.vault.models import SecretMetadata, SecretType


class SecretNotFound(LookupError):
    """The enabled secret does not exist in the authenticated tenant."""


class SecretExpired(LookupError):
    """The secret exists but has passed its configured expiry time."""


class VaultOperationFailed(RuntimeError):
    """An operation failed without safe-to-disclose low-level detail."""


def _associated_data(org_id: UUID, secret_id: UUID, name: str, secret_type: str) -> bytes:
    return f"dlp-vault:v1:{org_id}:{secret_id}:{name}:{secret_type}".encode()


def _metadata(row: dict[str, object]) -> SecretMetadata:
    expires_at = row["expires_at"]
    return SecretMetadata(
        secret_id=UUID(str(row["id"])),
        name=str(row["name"]),
        secret_type=SecretType(str(row["secret_type"])),
        key_version=int(cast(int, row["key_version"])),
        expires_at=expires_at,  # type: ignore[arg-type]
        enabled=bool(row["enabled"]),
        expired=expires_at is not None and expires_at <= datetime.now(UTC),  # type: ignore[operator]
        created_at=row["created_at"],  # type: ignore[arg-type]
        updated_at=row["updated_at"],  # type: ignore[arg-type]
    )


def _metadata_values(
    *,
    identifier: UUID,
    name: str,
    secret_type: SecretType,
    key_version: int,
    expires_at: datetime | None,
    enabled: bool,
    created_at: datetime,
    updated_at: datetime,
) -> SecretMetadata:
    return SecretMetadata(
        secret_id=identifier,
        name=name,
        secret_type=secret_type,
        key_version=key_version,
        expires_at=expires_at,
        enabled=enabled,
        expired=expires_at is not None and expires_at <= datetime.now(UTC),
        created_at=created_at,
        updated_at=updated_at,
    )


class SecretVault:
    """Encrypted vault adapter that accepts a replaceable versioned key provider."""

    def __init__(self, key_provider: KeyProvider) -> None:
        self._encryption = AesGcmEncryptionProvider(key_provider)

    @classmethod
    def from_environment(cls) -> "SecretVault":
        return cls(EnvironmentKeyProvider.from_env())

    def list_metadata(self, session: Session, principal: Principal) -> list[SecretMetadata]:
        require_permission(principal, Permission.VAULT_METADATA_READ)
        try:
            rows = (
                session.execute(
                    select(VAULT_SECRETS)
                    .where(VAULT_SECRETS.c.org_id == str(principal.organization_id))
                    .order_by(VAULT_SECRETS.c.name)
                )
                .mappings()
                .all()
            )
            return [_metadata(dict(row)) for row in rows]
        except SQLAlchemyError:
            raise VaultOperationFailed("Vault operation failed") from None

    def metadata(self, session: Session, principal: Principal, secret_id: UUID) -> SecretMetadata:
        require_permission(principal, Permission.VAULT_METADATA_READ)
        row = self._find(session, principal, secret_id, include_disabled=True)
        return _metadata(dict(row))

    def set(
        self,
        session: Session,
        principal: Principal,
        *,
        name: str,
        secret_type: SecretType,
        value: SecretStr,
        expires_at: datetime | None,
        secret_id: UUID | None = None,
        audit_context: AuditContext | None = None,
    ) -> SecretMetadata:
        require_permission(principal, Permission.VAULT_WRITE)
        identifier = secret_id or uuid4()
        now = datetime.now(UTC)
        encrypted = self._encryption.encrypt(
            value.get_secret_value(),
            _associated_data(principal.organization_id, identifier, name, secret_type.value),
        )
        values = {
            "org_id": str(principal.organization_id),
            "name": name,
            "secret_type": secret_type.value,
            "ciphertext": encrypted.ciphertext,
            "nonce": encrypted.nonce,
            "key_version": encrypted.key_version,
            "expires_at": expires_at,
            "enabled": True,
            "updated_at": now,
        }
        created_at = now
        try:
            if secret_id is None:
                values["id"] = str(identifier)
                values["created_at"] = now
                session.execute(insert(VAULT_SECRETS).values(**values))
            else:
                old = self._find(session, principal, identifier, for_update=True)
                if not old["enabled"]:
                    raise SecretNotFound("Secret not found")
                values.pop("org_id")
                created_at = old["created_at"]
                result = cast(
                    CursorResult[Any],
                    session.execute(
                        update(VAULT_SECRETS)
                        .where(
                            VAULT_SECRETS.c.id == str(identifier),
                            VAULT_SECRETS.c.org_id == str(principal.organization_id),
                            VAULT_SECRETS.c.enabled.is_(True),
                        )
                        .values(**values)
                    ),
                )
                if result.rowcount != 1:
                    raise SecretNotFound("Secret not found")
            AuditService().record_event(
                session,
                principal,
                action=(
                    AuditAction.SECRET_UPDATED
                    if secret_id is not None
                    else AuditAction.SECRET_CREATED
                ),
                resource_type="secret",
                resource_id=str(identifier),
                metadata={"secret_type": secret_type.value, "key_version": encrypted.key_version},
                context=audit_context,
            )
            session.commit()
        except SecretNotFound:
            session.rollback()
            raise
        except IntegrityError:
            session.rollback()
            raise HTTPException(
                status_code=409, detail="A secret with this name already exists"
            ) from None
        except (SQLAlchemyError, VaultConfigurationError, AuditPersistenceError, ValueError):
            session.rollback()
            raise VaultOperationFailed("Vault operation failed") from None
        return _metadata_values(
            identifier=identifier,
            name=name,
            secret_type=secret_type,
            key_version=encrypted.key_version,
            expires_at=expires_at,
            enabled=True,
            created_at=created_at,
            updated_at=now,
        )

    def get(self, session: Session, principal: Principal, secret_id: UUID) -> SecretStr:
        """Retrieve plaintext for trusted backend workflows; never exposed by HTTP routes."""
        require_permission(principal, Permission.VAULT_USE)
        row = self._find(session, principal, secret_id)
        if not row["enabled"]:
            raise SecretNotFound("Secret not found")
        expires_at = row["expires_at"]
        if expires_at is not None and expires_at <= datetime.now(UTC):
            raise SecretExpired("Secret is expired")
        try:
            value = self._encryption.decrypt(
                bytes(row["ciphertext"]),
                bytes(row["nonce"]),
                int(row["key_version"]),
                _associated_data(
                    principal.organization_id,
                    secret_id,
                    str(row["name"]),
                    str(row["secret_type"]),
                ),
            )
        except Exception:
            raise VaultOperationFailed("Vault operation failed") from None
        return SecretStr(value)

    def get_for_trusted_service(
        self,
        session: Session,
        organization_id: UUID,
        secret_id: UUID,
        *,
        allowed_types: frozenset[SecretType],
    ) -> SecretStr:
        """Read a referenced secret for a trusted server workflow, scoped to one tenant."""
        try:
            row = (
                session.execute(
                    select(VAULT_SECRETS).where(
                        VAULT_SECRETS.c.id == str(secret_id),
                        VAULT_SECRETS.c.org_id == str(organization_id),
                        VAULT_SECRETS.c.enabled.is_(True),
                    )
                )
                .mappings()
                .one_or_none()
            )
            if row is None or SecretType(str(row["secret_type"])) not in allowed_types:
                raise VaultOperationFailed("Vault operation failed")
            expires_at = row["expires_at"]
            if expires_at is not None and expires_at <= datetime.now(UTC):
                raise VaultOperationFailed("Vault operation failed")
            value = self._encryption.decrypt(
                bytes(row["ciphertext"]),
                bytes(row["nonce"]),
                int(row["key_version"]),
                _associated_data(
                    organization_id,
                    secret_id,
                    str(row["name"]),
                    str(row["secret_type"]),
                ),
            )
            return SecretStr(value)
        except VaultOperationFailed:
            raise
        except Exception:
            raise VaultOperationFailed("Vault operation failed") from None

    def exists(self, session: Session, principal: Principal, name: str) -> bool:
        require_permission(principal, Permission.VAULT_USE)
        try:
            row = session.execute(
                select(VAULT_SECRETS.c.enabled, VAULT_SECRETS.c.expires_at).where(
                    VAULT_SECRETS.c.org_id == str(principal.organization_id),
                    VAULT_SECRETS.c.name == name,
                )
            ).one_or_none()
        except SQLAlchemyError:
            raise VaultOperationFailed("Vault operation failed") from None
        if row is None or not row.enabled:
            return False
        return row.expires_at is None or row.expires_at > datetime.now(UTC)

    def disable(
        self,
        session: Session,
        principal: Principal,
        secret_id: UUID,
        *,
        audit_context: AuditContext | None = None,
    ) -> None:
        require_permission(principal, Permission.VAULT_DELETE)
        try:
            result = cast(
                CursorResult[Any],
                session.execute(
                    update(VAULT_SECRETS)
                    .where(
                        VAULT_SECRETS.c.id == str(secret_id),
                        VAULT_SECRETS.c.org_id == str(principal.organization_id),
                        VAULT_SECRETS.c.enabled.is_(True),
                    )
                    .values(enabled=False, updated_at=datetime.now(UTC))
                ),
            )
            if result.rowcount == 1:
                AuditService().record_event(
                    session,
                    principal,
                    action=AuditAction.SECRET_DISABLED,
                    resource_type="secret",
                    resource_id=str(secret_id),
                    context=audit_context,
                )
            session.commit()
        except (SQLAlchemyError, AuditPersistenceError, ValueError):
            session.rollback()
            raise VaultOperationFailed("Vault operation failed") from None
        if result.rowcount != 1:
            raise SecretNotFound("Secret not found")

    def rotate(
        self,
        session: Session,
        principal: Principal,
        secret_id: UUID,
        *,
        audit_context: AuditContext | None = None,
    ) -> SecretMetadata:
        """Re-encrypt in place with the active key version; no prior ciphertext is retained."""
        require_permission(principal, Permission.VAULT_WRITE)
        row = self._find(session, principal, secret_id, for_update=True)
        old_version = int(row["key_version"])
        if old_version == self._encryption.active_key_version:
            raise VaultOperationFailed("Secret is already using the active key version")
        if row["expires_at"] is not None and row["expires_at"] <= datetime.now(UTC):
            raise SecretExpired("Secret is expired")
        try:
            plaintext = self._encryption.decrypt(
                bytes(row["ciphertext"]),
                bytes(row["nonce"]),
                old_version,
                _associated_data(
                    principal.organization_id,
                    secret_id,
                    str(row["name"]),
                    str(row["secret_type"]),
                ),
            )
            encrypted = self._encryption.encrypt(
                plaintext,
                _associated_data(
                    principal.organization_id,
                    secret_id,
                    str(row["name"]),
                    str(row["secret_type"]),
                ),
            )
            result = cast(
                CursorResult[Any],
                session.execute(
                    update(VAULT_SECRETS)
                    .where(
                        VAULT_SECRETS.c.id == str(secret_id),
                        VAULT_SECRETS.c.org_id == str(principal.organization_id),
                        VAULT_SECRETS.c.key_version == old_version,
                        VAULT_SECRETS.c.enabled.is_(True),
                    )
                    .values(
                        ciphertext=encrypted.ciphertext,
                        nonce=encrypted.nonce,
                        key_version=encrypted.key_version,
                        updated_at=datetime.now(UTC),
                    )
                ),
            )
            if result.rowcount != 1:
                raise SecretNotFound("Secret not found")
            AuditService().record_event(
                session,
                principal,
                action=AuditAction.SECRET_ROTATED,
                resource_type="secret",
                resource_id=str(secret_id),
                metadata={"key_version": encrypted.key_version},
                context=audit_context,
            )
            session.commit()
        except Exception:
            session.rollback()
            raise VaultOperationFailed("Vault operation failed") from None
        return _metadata_values(
            identifier=secret_id,
            name=str(row["name"]),
            secret_type=SecretType(str(row["secret_type"])),
            key_version=encrypted.key_version,
            expires_at=cast(datetime | None, row["expires_at"]),
            enabled=True,
            created_at=cast(datetime, row["created_at"]),
            updated_at=datetime.now(UTC),
        )

    def _find(
        self,
        session: Session,
        principal: Principal,
        secret_id: UUID,
        *,
        include_disabled: bool = False,
        for_update: bool = False,
    ) -> RowMapping:
        query = select(VAULT_SECRETS).where(
            VAULT_SECRETS.c.id == str(secret_id),
            VAULT_SECRETS.c.org_id == str(principal.organization_id),
        )
        if not include_disabled:
            query = query.where(VAULT_SECRETS.c.enabled.is_(True))
        if for_update:
            query = query.with_for_update()
        try:
            row = session.execute(query).mappings().one_or_none()
        except SQLAlchemyError:
            raise VaultOperationFailed("Vault operation failed") from None
        if row is None:
            raise SecretNotFound("Secret not found")
        return row
