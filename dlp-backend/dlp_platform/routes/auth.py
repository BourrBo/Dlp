"""Authenticated identity endpoint."""

from fastapi import APIRouter

from dlp_platform.auth.permissions import require_permission
from dlp_platform.auth.principal import CurrentPrincipal
from dlp_platform.auth.roles import Permission
from dlp_platform.contracts.principal import Principal

router = APIRouter(tags=["authentication"])


@router.get("/auth/me", response_model=Principal)
def auth_me(principal: CurrentPrincipal) -> Principal:
    require_permission(principal, Permission.IDENTITY_READ)
    return principal
