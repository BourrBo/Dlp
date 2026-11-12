"""Map verified provider subjects to the existing tenant member records."""

import hashlib
import re
from datetime import UTC, datetime
from uuid import UUID, uuid4

import jwt
from sqlalchemy import insert, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from dlp_platform.audit.service import AuditService
from dlp_platform.contracts.audit_event import AuditAction
from dlp_platform.contracts.common import ActorType, AuthMethod, Role
from dlp_platform.contracts.principal import Principal
from dlp_platform.identity.models import SSOProtocol
from dlp_platform.identity.oidc import OIDCError, OIDCIdentity
from dlp_platform.tables import MEMBERS, SSO_IDENTITIES

_EMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def map_identity(
    session: Session,
    *,
    organization_id: UUID,
    config_id: UUID,
    protocol: SSOProtocol,
    identity: OIDCIdentity,
    claimed_domains: list[str],
) -> tuple[str, Role, bool]:
    org_id = str(organization_id)
    config_key = str(config_id)
    link = session.execute(
        select(SSO_IDENTITIES.c.member_id).where(
            SSO_IDENTITIES.c.org_id == org_id,
            SSO_IDENTITIES.c.config_id == config_key,
            SSO_IDENTITIES.c.issuer == identity.issuer,
            SSO_IDENTITIES.c.subject == identity.subject,
        )
    ).scalar_one_or_none()
    if link is not None:
        member = session.execute(
            select(MEMBERS.c.id, MEMBERS.c.auth_subject_id, MEMBERS.c.role).where(
                MEMBERS.c.id == link, MEMBERS.c.organization_id == org_id
            )
        ).one_or_none()
        if member is None:
            raise OIDCError("SSO identity is not available")
        return str(member.auth_subject_id), Role(member.role), False

    email = identity.email.strip().lower()
    if not identity.email_verified or not _EMAIL.fullmatch(email):
        raise OIDCError("SSO identity is not verified")
    domain = email.rsplit("@", 1)[1].encode("idna").decode().lower()
    if domain not in claimed_domains:
        raise OIDCError("SSO identity is not authorized for this organization")

    member = session.execute(
        select(MEMBERS.c.id, MEMBERS.c.auth_subject_id, MEMBERS.c.role, MEMBERS.c.email).where(
            MEMBERS.c.organization_id == org_id,
            MEMBERS.c.email.is_not(None),
            # Lower-case normalization is applied when email is stored.
            MEMBERS.c.email == email,
        )
    ).one_or_none()
    if member is None:
        member_id = uuid4()
        subject_hash = hashlib.sha256(f"{identity.issuer}\0{identity.subject}".encode()).hexdigest()
        local_subject = f"sso:{config_id}:{subject_hash}"
        try:
            session.execute(
                insert(MEMBERS).values(
                    id=str(member_id),
                    organization_id=org_id,
                    auth_subject_id=local_subject,
                    role=Role.VIEWER.value,
                    email=email,
                    created_at=datetime.now(UTC),
                )
            )
        except IntegrityError as exc:
            raise OIDCError("SSO identity conflicts with an existing member") from exc
        mapped_member_id = str(member_id)
        subject_id = local_subject
        role = Role.VIEWER
    else:
        mapped_member_id = str(member.id)
        subject_id = str(member.auth_subject_id)
        role = Role(member.role)

    session.execute(
        insert(SSO_IDENTITIES).values(
            id=str(uuid4()),
            org_id=org_id,
            config_id=config_key,
            member_id=mapped_member_id,
            issuer=identity.issuer,
            subject=identity.subject,
            email=email,
            created_at=datetime.now(UTC),
        )
    )
    service_principal = Principal(
        organization_id=organization_id,
        subject_id="sso-identity-mapper",
        actor_type=ActorType.SERVICE,
        role=Role.VIEWER,
        scopes=(),
        auth_method=AuthMethod.INTERNAL,
    )
    AuditService().record_event(
        session,
        service_principal,
        action=AuditAction.SSO_IDENTITY_MAPPING_CREATED,
        resource_type="member",
        resource_id=mapped_member_id,
        metadata={"operation": protocol.value},
    )
    return subject_id, role, True


def issue_access_token(
    subject_id: str, organization_id: UUID, *, secret: str, issuer: str, audience: str
) -> str:
    now = int(datetime.now(UTC).timestamp())
    return jwt.encode(
        {
            "sub": subject_id,
            "org_id": str(organization_id),
            "iss": issuer,
            "aud": audience,
            "amr": ["sso"],
            "iat": now,
            "exp": now + 900,
            "jti": str(uuid4()),
        },
        secret,
        algorithm="HS256",
    )
