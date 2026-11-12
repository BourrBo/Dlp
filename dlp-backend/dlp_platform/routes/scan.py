"""Authenticated P04 scan entry point; all collectors share one orchestration path."""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse

from dlp_platform.auth.permissions import require_permission
from dlp_platform.auth.principal import CurrentPrincipal
from dlp_platform.auth.roles import Permission
from dlp_platform.contracts.principal import Principal
from dlp_platform.contracts.scan_request import ScanRequest
from dlp_platform.contracts.scan_result import ScanResult
from dlp_platform.ratelimit.dependencies import get_rate_limiter
from dlp_platform.ratelimit.limiter import RateLimiter
from dlp_platform.scan.errors import ScanPipelineError
from dlp_platform.scan.pipeline import scan

logger = logging.getLogger(__name__)
router = APIRouter(tags=["scan"])
LimiterDependency = Annotated[RateLimiter, Depends(get_rate_limiter)]


def _check_limit(
    request: Request, response: Response, principal: Principal, limiter: RateLimiter
) -> JSONResponse | None:
    identity = str(request.state.rate_limit_identity)
    organization_id = str(principal.organization_id)
    result = limiter.check(identity, organization_id)
    headers = {
        "X-RateLimit-Limit": str(result.limit),
        "X-RateLimit-Remaining": str(result.remaining),
        "Retry-After": str(result.retry_after),
    }
    response.headers.update(headers)
    if not result.allowed:
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded"},
            headers=headers,
        )
    return None


def _safe_failure(exc: Exception) -> JSONResponse:
    if isinstance(exc, ScanPipelineError):
        code, message, status_code = exc.code, exc.public_message, exc.status_code
    else:
        code, message, status_code = "internal_error", "Scan could not be completed", 500
        logger.error(
            "Scan request failed code=internal_error exception_type=%s", type(exc).__name__
        )
    return JSONResponse(
        status_code=status_code,
        content={"detail": {"code": code, "message": message}},
    )


@router.post("/scan", response_model=ScanResult)
def post_scan(
    payload: ScanRequest,
    request: Request,
    response: Response,
    principal: CurrentPrincipal,
    limiter: LimiterDependency,
) -> ScanResult | JSONResponse:
    require_permission(principal, Permission.SCAN_REQUEST)
    limited = _check_limit(request, response, principal, limiter)
    if limited is not None:
        return limited
    try:
        return scan(payload, principal)
    except Exception as exc:
        return _safe_failure(exc)
