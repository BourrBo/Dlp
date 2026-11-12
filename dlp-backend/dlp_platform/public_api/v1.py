"""Small, versioned, read-only public API surface."""

from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from dlp_platform.auth.permissions import require_permission
from dlp_platform.auth.principal import CurrentPrincipal
from dlp_platform.auth.roles import Permission
from dlp_platform.contracts.common import ActorType, PolicyAction
from dlp_platform.database import get_session
from dlp_platform.ratelimit.dependencies import get_rate_limiter
from dlp_platform.ratelimit.limiter import RateLimiter
from dlp_platform.tables import POLICIES

router = APIRouter(prefix="/api/v1", tags=["public API v1"])
SessionDependency = Annotated[Session, Depends(get_session)]
LimiterDependency = Annotated[RateLimiter, Depends(get_rate_limiter)]
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 100


class PublicPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID
    name: str
    enabled: bool
    priority: int
    action: PolicyAction
    version: int
    created_at: datetime
    updated_at: datetime


class Pagination(BaseModel):
    limit: int
    offset: int
    total: int


class PolicyPage(BaseModel):
    data: list[PublicPolicy]
    pagination: Pagination


class PublicErrorDetail(BaseModel):
    code: str
    message: str
    request_id: str | None


class PublicError(BaseModel):
    error: PublicErrorDetail


_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    401: {"model": PublicError, "description": "API-key authentication failed"},
    403: {"model": PublicError, "description": "The API key lacks the required scope"},
    404: {"model": PublicError, "description": "Resource not found in this tenant"},
    409: {"model": PublicError, "description": "Request conflicts with resource state"},
    422: {"model": PublicError, "description": "Request validation failed"},
    429: {
        "model": PublicError,
        "description": "Rate limit exceeded",
        "headers": {
            "Retry-After": {
                "description": "Seconds until the fixed-window limit resets",
                "schema": {"type": "integer", "minimum": 1},
            }
        },
    },
    500: {"model": PublicError, "description": "Internal error"},
    503: {"model": PublicError, "description": "Service unavailable"},
}


def _success_response(description: str) -> dict[str, Any]:
    return {
        "description": description,
        "headers": {
            "X-Request-ID": {
                "description": "Request correlation identifier",
                "schema": {"type": "string", "format": "uuid"},
            }
        },
    }


def _authenticate_public_key(principal: CurrentPrincipal) -> None:
    if principal.actor_type is not ActorType.SERVICE:
        raise HTTPException(status_code=401, detail="API key authentication required")
    require_permission(principal, Permission.IDENTITY_READ)


def _rate_limit(
    principal: CurrentPrincipal,
    request_identity: str,
    limiter: RateLimiter,
) -> None:
    result = limiter.check(request_identity, str(principal.organization_id))
    if not result.allowed:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(result.retry_after)},
        )


@router.get(
    "/policies",
    response_model=PolicyPage,
    operation_id="publicV1ListPolicies",
    responses={200: _success_response("Bounded tenant policy page"), **_ERROR_RESPONSES},
)
def list_policies(
    principal: CurrentPrincipal,
    session: SessionDependency,
    limiter: LimiterDependency,
    request: Request,
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(0, ge=0, le=1_000_000),
    enabled: bool | None = None,
    action: PolicyAction | None = None,
) -> PolicyPage:
    _authenticate_public_key(principal)
    identity = str(getattr(request.state, "rate_limit_identity", principal.subject_id))
    _rate_limit(principal, identity, limiter)

    filters = [POLICIES.c.org_id == str(principal.organization_id)]
    if enabled is not None:
        filters.append(POLICIES.c.enabled.is_(enabled))
    if action is not None:
        filters.append(POLICIES.c.action == action.value)
    total = int(
        session.execute(select(func.count()).select_from(POLICIES).where(*filters)).scalar_one()
    )
    rows = (
        session.execute(
            select(
                POLICIES.c.id,
                POLICIES.c.name,
                POLICIES.c.enabled,
                POLICIES.c.priority,
                POLICIES.c.action,
                POLICIES.c.version,
                POLICIES.c.created_at,
                POLICIES.c.updated_at,
            )
            .where(*filters)
            .order_by(POLICIES.c.created_at.desc(), POLICIES.c.id)
            .limit(limit)
            .offset(offset)
        )
        .mappings()
        .all()
    )
    return PolicyPage(
        data=[PublicPolicy.model_validate(dict(row)) for row in rows],
        pagination=Pagination(limit=limit, offset=offset, total=total),
    )


@router.get(
    "/policies/{policy_id}",
    response_model=PublicPolicy,
    operation_id="publicV1GetPolicy",
    responses={200: _success_response("Tenant policy metadata"), **_ERROR_RESPONSES},
)
def get_policy(
    policy_id: UUID,
    principal: CurrentPrincipal,
    session: SessionDependency,
    limiter: LimiterDependency,
    request: Request,
) -> PublicPolicy:
    _authenticate_public_key(principal)
    identity = str(getattr(request.state, "rate_limit_identity", principal.subject_id))
    _rate_limit(principal, identity, limiter)
    row = (
        session.execute(
            select(
                POLICIES.c.id,
                POLICIES.c.name,
                POLICIES.c.enabled,
                POLICIES.c.priority,
                POLICIES.c.action,
                POLICIES.c.version,
                POLICIES.c.created_at,
                POLICIES.c.updated_at,
            ).where(
                POLICIES.c.id == str(policy_id),
                POLICIES.c.org_id == str(principal.organization_id),
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    return PublicPolicy.model_validate(dict(row))
