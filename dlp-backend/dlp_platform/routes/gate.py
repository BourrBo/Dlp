"""CI gate API; output is SARIF-ready and does not export a SARIF file."""

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from dlp_platform.auth.permissions import require_permission
from dlp_platform.auth.principal import CurrentPrincipal
from dlp_platform.auth.roles import Permission
from dlp_platform.contracts.common import PolicyAction
from dlp_platform.contracts.scan_request import ScanRequest
from dlp_platform.ratelimit.dependencies import get_rate_limiter
from dlp_platform.ratelimit.limiter import RateLimiter
from dlp_platform.routes.scan import _check_limit, _safe_failure
from dlp_platform.scan.pipeline import scan

router = APIRouter(tags=["gate"])
LimiterDependency = Annotated[RateLimiter, Depends(get_rate_limiter)]


class GateResponse(BaseModel):
    status: Literal["pass", "fail"]
    scan_id: UUID
    request_id: UUID
    decision: PolicyAction
    reason: str
    policy_version: str | None = None
    sarif: dict[str, object]


@router.post("/gate/check", response_model=GateResponse)
def check_gate(
    payload: ScanRequest,
    request: Request,
    response: Response,
    principal: CurrentPrincipal,
    limiter: LimiterDependency,
) -> GateResponse | JSONResponse:
    require_permission(principal, Permission.SCAN_REQUEST)
    limited = _check_limit(request, response, principal, limiter)
    if limited is not None:
        return limited
    try:
        result = scan(payload, principal)
        # P04 recommendation: only an explicit ALLOW passes a CI gate.
        status: Literal["pass", "fail"] = (
            "pass" if result.decision is PolicyAction.ALLOW else "fail"
        )
        sarif_results = [
            {
                "ruleId": finding.data_type,
                "level": finding.severity.value,
                "message": {"text": f"{finding.data_type} finding"},
            }
            for finding in result.findings
        ]
        return GateResponse(
            status=status,
            scan_id=result.scan_id,
            request_id=result.request_id,
            decision=result.decision,
            reason=result.reason,
            policy_version=result.policy_version,
            sarif={
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "DLP P2 Gate"}},
                        "results": sarif_results,
                    }
                ],
            },
        )
    except Exception as exc:
        return _safe_failure(exc)
