"""Metadata-only HTTP interface to the P09 secret vault."""

from collections.abc import Callable, Coroutine
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from sqlalchemy.orm import Session
from starlette.responses import JSONResponse

from dlp_platform.audit.service import context_from_request
from dlp_platform.auth.principal import CurrentPrincipal
from dlp_platform.database import get_session
from dlp_platform.vault.config import VaultConfigurationError
from dlp_platform.vault.models import SecretMetadata, SetSecretRequest
from dlp_platform.vault.service import SecretNotFound, SecretVault, VaultOperationFailed


class VaultRoute(APIRoute):
    """Ensure body validation errors never echo secret request values."""

    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        original_handler = super().get_route_handler()

        async def safe_handler(request: Request) -> Response:
            try:
                return await original_handler(request)
            except RequestValidationError:
                return JSONResponse(status_code=422, content={"detail": "Invalid secret request"})

        return safe_handler


router = APIRouter(prefix="/vault/secrets", tags=["vault"], route_class=VaultRoute)
SessionDependency = Annotated[Session, Depends(get_session)]


def _vault() -> SecretVault:
    try:
        return SecretVault.from_environment()
    except VaultConfigurationError:
        raise HTTPException(status_code=503, detail="Vault is not configured") from None


VaultDependency = Annotated[SecretVault, Depends(_vault)]


def _metadata_or_error(operation: Callable[[], SecretMetadata]) -> SecretMetadata:
    try:
        return operation()
    except SecretNotFound:
        raise HTTPException(status_code=404, detail="Secret not found") from None
    except VaultOperationFailed:
        raise HTTPException(status_code=503, detail="Vault operation failed") from None


@router.post("", response_model=SecretMetadata, status_code=status.HTTP_201_CREATED)
def set_secret(
    body: SetSecretRequest,
    request: Request,
    response: Response,
    principal: CurrentPrincipal,
    session: SessionDependency,
    vault: VaultDependency,
) -> SecretMetadata:
    response.headers["Cache-Control"] = "no-store"
    return _metadata_or_error(
        lambda: vault.set(
            session,
            principal,
            name=body.name,
            secret_type=body.secret_type,
            value=body.value,
            expires_at=body.expires_at,
            audit_context=context_from_request(request),
        )
    )


@router.get("", response_model=list[SecretMetadata])
def list_secrets(
    response: Response,
    principal: CurrentPrincipal,
    session: SessionDependency,
    vault: VaultDependency,
) -> list[SecretMetadata]:
    response.headers["Cache-Control"] = "no-store"
    try:
        return vault.list_metadata(session, principal)
    except VaultOperationFailed:
        raise HTTPException(status_code=503, detail="Vault operation failed") from None


@router.get("/{secret_id}", response_model=SecretMetadata)
def get_secret_metadata(
    secret_id: UUID,
    response: Response,
    principal: CurrentPrincipal,
    session: SessionDependency,
    vault: VaultDependency,
) -> SecretMetadata:
    response.headers["Cache-Control"] = "no-store"
    return _metadata_or_error(lambda: vault.metadata(session, principal, secret_id))


@router.put("/{secret_id}", response_model=SecretMetadata)
def update_secret(
    secret_id: UUID,
    body: SetSecretRequest,
    request: Request,
    response: Response,
    principal: CurrentPrincipal,
    session: SessionDependency,
    vault: VaultDependency,
) -> SecretMetadata:
    response.headers["Cache-Control"] = "no-store"
    return _metadata_or_error(
        lambda: vault.set(
            session,
            principal,
            name=body.name,
            secret_type=body.secret_type,
            value=body.value,
            expires_at=body.expires_at,
            secret_id=secret_id,
            audit_context=context_from_request(request),
        )
    )


@router.delete("/{secret_id}", status_code=status.HTTP_204_NO_CONTENT)
def disable_secret(
    secret_id: UUID,
    request: Request,
    response: Response,
    principal: CurrentPrincipal,
    session: SessionDependency,
    vault: VaultDependency,
) -> Response:
    response.headers["Cache-Control"] = "no-store"
    try:
        vault.disable(session, principal, secret_id, audit_context=context_from_request(request))
    except SecretNotFound:
        raise HTTPException(status_code=404, detail="Secret not found") from None
    except VaultOperationFailed:
        raise HTTPException(status_code=503, detail="Vault operation failed") from None
    return Response(status_code=status.HTTP_204_NO_CONTENT, headers={"Cache-Control": "no-store"})
