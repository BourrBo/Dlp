"""Shared auth, rate-limit and actor helpers for P06 policy endpoints."""

from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, Request
from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.orm import Session

from dlp_platform.auth.permissions import require_permission, require_role
from dlp_platform.auth.principal import CurrentPrincipal
from dlp_platform.auth.roles import Permission
from dlp_platform.contracts.common import Role
from dlp_platform.database import get_session
from dlp_platform.ratelimit.dependencies import get_rate_limiter
from dlp_platform.ratelimit.limiter import RateLimiter

SessionDependency = Annotated[Session, Depends(get_session)]
LimiterDependency = Annotated[RateLimiter, Depends(get_rate_limiter)]


def require_read(principal: CurrentPrincipal) -> None:
    require_permission(principal, Permission.IDENTITY_READ)


def require_write(principal: CurrentPrincipal) -> None:
    require_permission(principal, Permission.API_KEYS_WRITE)
    require_role(principal, Role.OWNER, Role.ADMIN)


def rate_limit_p06(
    request: Request, principal: CurrentPrincipal, limiter: LimiterDependency
) -> None:
    identity = str(getattr(request.state, "rate_limit_identity", principal.subject_id))
    result = limiter.check(identity, str(principal.organization_id))
    if not result.allowed:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(result.retry_after)},
        )


def member_id(session: Session, principal: CurrentPrincipal) -> str:
    member = session.execute(
        text("SELECT id FROM members WHERE organization_id=:org AND auth_subject_id=:sub"),
        {"org": str(principal.organization_id), "sub": principal.subject_id},
    ).scalar_one_or_none()
    if member is None:
        raise HTTPException(status_code=403, detail="Forbidden")
    return str(member)


def owned_policy_exists(session: Session, policy_id: UUID, organization_id: UUID) -> bool:
    from dlp_platform.tables import POLICIES

    return (
        session.execute(
            POLICIES.select()
            .with_only_columns(POLICIES.c.id)
            .where(
                POLICIES.c.id == str(policy_id),
                POLICIES.c.org_id == str(organization_id),
            )
        ).scalar_one_or_none()
        is not None
    )


def engine_for_session(session: Session) -> Engine:
    bind = session.get_bind()
    return bind.engine if isinstance(bind, Connection) else bind
