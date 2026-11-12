"""Reusable permission and scope checks with centralized policy."""

from fastapi import HTTPException, status

from dlp_platform.auth.roles import API_KEY_SCOPES, ROLE_PERMISSIONS, Permission
from dlp_platform.contracts.common import Role
from dlp_platform.contracts.principal import Principal


def require_permission(principal: Principal, permission: Permission) -> None:
    if permission not in ROLE_PERMISSIONS[principal.role]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    if permission.value not in principal.scopes:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


def require_role(principal: Principal, *roles: Role) -> None:
    if principal.role not in roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


def validate_requested_scopes(scopes: list[str], principal: Principal) -> tuple[str, ...]:
    normalized = tuple(dict.fromkeys(scopes))
    if any(scope not in API_KEY_SCOPES for scope in normalized):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid scope",
        )
    role_permissions = ROLE_PERMISSIONS[principal.role]
    if any(
        Permission(scope) not in role_permissions or scope not in principal.scopes
        for scope in normalized
    ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    return normalized
