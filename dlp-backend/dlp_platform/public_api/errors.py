"""Stable, redacted errors for the versioned public API."""

from typing import Any

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

_STATUS_CODES = {
    400: "bad_request",
    401: "authentication_failed",
    403: "authorization_failed",
    404: "not_found",
    409: "conflict",
    422: "validation_failed",
    423: "resource_locked",
    429: "rate_limited",
    503: "service_unavailable",
    500: "internal_error",
}


def _is_public(request: Request) -> bool:
    return request.url.path == "/api/v1" or request.url.path.startswith("/api/v1/")


def _request_id(request: Request) -> str | None:
    value: Any = getattr(request.state, "correlation_id", None)
    return str(value) if value is not None else None


async def public_http_error(request: Request, error: Exception) -> JSONResponse:
    if not isinstance(error, StarletteHTTPException):
        return JSONResponse({"detail": "Request failed"}, status_code=500)
    exc = error
    if not _is_public(request):
        detail = exc.detail
        return JSONResponse({"detail": detail}, status_code=exc.status_code, headers=exc.headers)
    status_code = exc.status_code
    code = _STATUS_CODES.get(status_code, "request_failed")
    message = "The request could not be completed"
    if status_code == 401:
        message = "Valid API-key authentication is required"
    elif status_code == 403:
        message = "The API key is not authorized for this operation"
    elif status_code == 404:
        message = "The requested resource was not found"
    elif status_code == 422:
        message = "Request validation failed"
    elif status_code == 429:
        message = "Rate limit exceeded"
    elif status_code >= 500:
        message = "The request could not be completed"
    headers = dict(exc.headers or {})
    request_id = _request_id(request)
    if request_id:
        headers["X-Request-ID"] = request_id
    return JSONResponse(
        {"error": {"code": code, "message": message, "request_id": request_id}},
        status_code=status_code,
        headers=headers,
    )


async def public_validation_error(request: Request, error: Exception) -> JSONResponse:
    if not isinstance(error, RequestValidationError):
        return JSONResponse({"detail": "Request validation failed"}, status_code=422)
    exc = error
    if not _is_public(request):
        headers = {"X-Request-ID": request_id} if (request_id := _request_id(request)) else {}
        safe_errors = [
            {key: item[key] for key in ("loc", "msg", "type") if key in item}
            for item in exc.errors()
        ]
        return JSONResponse({"detail": safe_errors}, status_code=422, headers=headers)
    request_id = _request_id(request)
    return JSONResponse(
        {
            "error": {
                "code": "validation_failed",
                "message": "Request validation failed",
                "request_id": request_id,
            }
        },
        status_code=422,
        headers={"X-Request-ID": request_id} if request_id else {},
    )


async def public_internal_error(request: Request, exc: Exception) -> JSONResponse:
    del exc
    if not _is_public(request):
        return JSONResponse({"detail": "Internal server error"}, status_code=500)
    request_id = _request_id(request)
    return JSONResponse(
        {
            "error": {
                "code": "internal_error",
                "message": "The request could not be completed",
                "request_id": request_id,
            }
        },
        status_code=500,
        headers={"X-Request-ID": request_id} if request_id else {},
    )
