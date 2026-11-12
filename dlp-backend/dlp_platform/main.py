"""FastAPI application for the P2 DLP platform."""

import json
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from uuid import uuid4

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from sqlalchemy import text
from sqlalchemy.orm import Session
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse

from dlp_platform.actions.service import ActionProcessor
from dlp_platform.audit.service import AuditPersistenceError, AuditService, context_from_request
from dlp_platform.auth.settings import AuthSettings
from dlp_platform.connectors.microsoft_action_executor import ConnectorActionExecutor
from dlp_platform.contracts.audit_event import AuditAction, AuditOutcome
from dlp_platform.contracts.principal import Principal
from dlp_platform.policy.lifecycle import PolicyLifecycleEvaluator
from dlp_platform.policy.repository import PolicyRepository
from dlp_platform.policy.suppressions import DatabaseSuppressor
from dlp_platform.public_api.errors import public_http_error, public_internal_error, public_validation_error
from dlp_platform.public_api.v1 import router as public_v1_router
from dlp_platform.routes.api_keys import router as api_keys_router
from dlp_platform.routes.approvals import configure_action_executor as configure_approval_executor
from dlp_platform.routes.approvals import router as approvals_router
from dlp_platform.routes.audit import router as audit_router
from dlp_platform.routes.auth import router as auth_router
from dlp_platform.routes.cloud_storage_connectors import router as cloud_storage_connectors_router
from dlp_platform.routes.connectors import router as connectors_router
from dlp_platform.routes.destinations import router as destinations_router
from dlp_platform.routes.exceptions import router as exceptions_router
from dlp_platform.routes.gate import router as gate_router
from dlp_platform.routes.identity import router as identity_router
from dlp_platform.routes.lifecycle import router as lifecycle_router
from dlp_platform.routes.microsoft_connectors import router as microsoft_connectors_router
from dlp_platform.routes.policies import router as policies_router
from dlp_platform.routes.scan import router as scan_router
from dlp_platform.routes.scim import SCIMError, scim_exception_handler
from dlp_platform.routes.scim import router as scim_router
from dlp_platform.routes.sso import router as sso_router
from dlp_platform.routes.suppressions import router as suppressions_router
from dlp_platform.routes.vault import router as vault_router
from dlp_platform.scan.pipeline import configure_action_processor, configure_policy_evaluator
from dlp_platform.vault.config import VaultSettings
from dlp_platform.vault.crypto import EnvironmentKeyProvider


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    settings = VaultSettings.from_env()
    settings.validate_if_enabled()
    if settings.enabled:
        EnvironmentKeyProvider(
            active_key_version=settings.active_key_version,
            keys=settings.keys,
        ).key_for_version(settings.active_key_version)
    yield


app = FastAPI(title="DLP Platform P2", version="0.10.0", lifespan=lifespan)

app.add_exception_handler(StarletteHTTPException, public_http_error)
app.add_exception_handler(RequestValidationError, public_validation_error)
app.add_exception_handler(Exception, public_internal_error)


@app.exception_handler(AuditPersistenceError)
async def audit_failure_response(_: Request, __: AuditPersistenceError) -> JSONResponse:
    return JSONResponse(status_code=503, content={"detail": "Audit event unavailable"})


def _record_authorization_denial(request: Request) -> None:
    principal = getattr(request.state, "principal", None)
    session = getattr(request.state, "audit_session", None)
    if not isinstance(principal, Principal) or not isinstance(session, Session):
        return
    try:
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
                        }
                    )
                },
            )
        route = request.scope.get("route")
        AuditService().record_event(
            session,
            principal,
            action=AuditAction.AUTHORIZATION_DENIED,
            resource_type="route",
            resource_id=str(getattr(route, "path", "unknown"))[:256],
            outcome=AuditOutcome.DENIED,
            context=context_from_request(request),
        )
        session.commit()
    except Exception:
        session.rollback()
        raise AuditPersistenceError("Audit event could not be recorded") from None


@app.middleware("http")
async def attach_correlation_id(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    correlation_id = uuid4()
    request.state.correlation_id = correlation_id
    response = await call_next(request)
    if response.status_code == 403:
        try:
            _record_authorization_denial(request)
        except AuditPersistenceError:
            return JSONResponse(
                status_code=503,
                content={"detail": "Audit event unavailable"},
                headers={"X-Request-ID": str(correlation_id)},
            )
    response.headers["X-Request-ID"] = str(correlation_id)
    return response


app.include_router(auth_router)
app.include_router(api_keys_router)
app.include_router(connectors_router)
app.include_router(microsoft_connectors_router)
app.include_router(cloud_storage_connectors_router)
app.include_router(audit_router)
app.include_router(scan_router)
app.include_router(gate_router)
app.include_router(policies_router)
app.include_router(destinations_router)
app.include_router(exceptions_router)
app.include_router(suppressions_router)
app.include_router(approvals_router)
app.include_router(vault_router)
app.include_router(sso_router)
app.include_router(identity_router)
app.include_router(lifecycle_router)
app.include_router(scim_router)
app.include_router(public_v1_router)
app.add_exception_handler(SCIMError, scim_exception_handler)

_database_url = AuthSettings.from_env().database_url
if _database_url.startswith(("postgresql://", "postgresql+psycopg://")):
    _connector_action_executor = ConnectorActionExecutor(_database_url)
    _policy_repository = PolicyRepository.from_url(_database_url)
    configure_policy_evaluator(
        PolicyLifecycleEvaluator(_policy_repository),
        DatabaseSuppressor(_policy_repository.engine),
    )
    configure_action_processor(
        ActionProcessor.from_url(_database_url, executor=_connector_action_executor)
    )
    configure_approval_executor(_connector_action_executor)
