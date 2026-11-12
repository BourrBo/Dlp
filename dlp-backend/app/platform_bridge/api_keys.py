"""Verify platform-issued API keys (``dlp_<prefix>.<secret>``) for scan callers.

Keys are minted and revoked through ``/platform/api-keys``. This module applies
the same checks as the platform's own authentication: exact format, SHA-256
constant-time hash match, not revoked, and an active owning member.
"""

import hashlib
import hmac
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid5, NAMESPACE_URL

from sqlalchemy import select, text, update


@dataclass(frozen=True)
class ApiKeyIdentity:
    key_id: str
    org_id: UUID
    user_id: UUID
    scopes: tuple[str, ...]


def _session():
    from dlp_platform.auth.settings import AuthSettings
    from dlp_platform.database import _session_factory

    return _session_factory(AuthSettings.from_env().database_url)()


def verify_api_key(token: str) -> ApiKeyIdentity | None:
    from dlp_platform.auth.principal import _API_KEY_FORMAT
    from dlp_platform.tables import API_KEYS

    match = _API_KEY_FORMAT.fullmatch(token)
    if match is None:
        return None
    prefix = match.group(1)
    with _session() as session:
        row = session.execute(select(API_KEYS).where(API_KEYS.c.prefix == prefix)).mappings().one_or_none()
        if row is None or row["revoked_at"] is not None:
            return None
        if not hmac.compare_digest(hashlib.sha256(token.encode()).hexdigest(), row["key_hash"]):
            return None
        member = session.execute(
            text("SELECT auth_subject_id, active FROM members WHERE id = :m AND organization_id = :o"),
            {"m": row["created_by"], "o": row["org_id"]},
        ).mappings().one_or_none()
        if member is None or not member["active"]:
            return None
        session.execute(
            update(API_KEYS).where(API_KEYS.c.id == row["id"], API_KEYS.c.revoked_at.is_(None))
            .values(last_used_at=datetime.now(UTC))
        )
        session.commit()
        try:
            user_id = UUID(str(member["auth_subject_id"]))
        except ValueError:
            user_id = uuid5(NAMESPACE_URL, f"dlp-api-key-owner:{member['auth_subject_id']}")
        return ApiKeyIdentity(str(row["id"]), UUID(row["org_id"]), user_id, tuple(row["scopes"]))
