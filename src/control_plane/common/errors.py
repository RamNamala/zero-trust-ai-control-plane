"""Standard gateway error envelope and the FastAPI handlers that guarantee it.

Every error leaving an HTTP surface has the same shape, carries the correlation ID, and contains
only messages chosen here - never ``str(exc)``, ``HTTPException.detail`` from deep code, or a
traceback. The full exception is logged to stderr instead, where operators (not callers) see it.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException

from control_plane.common.correlation import HEADER as CORRELATION_HEADER
from control_plane.common.correlation import correlation_id_from_scope, new_correlation_id
from control_plane.common.logging import get_correlation_id, get_logger

_log = get_logger("errors")


class ErrorCode(StrEnum):
    RATE_LIMITED = "RATE_LIMITED"
    REQUEST_TOO_LARGE = "REQUEST_TOO_LARGE"
    INVALID_REQUEST = "INVALID_REQUEST"
    UNAUTHENTICATED = "UNAUTHENTICATED"
    GATEWAY_UPSTREAM_FAILURE = "GATEWAY_UPSTREAM_FAILURE"
    GATEWAY_TIMEOUT = "GATEWAY_TIMEOUT"
    INTERNAL_ERROR = "INTERNAL_ERROR"


DEFAULT_STATUS: dict[ErrorCode, int] = {
    ErrorCode.RATE_LIMITED: 429,
    ErrorCode.REQUEST_TOO_LARGE: 413,
    ErrorCode.INVALID_REQUEST: 400,
    ErrorCode.UNAUTHENTICATED: 401,
    ErrorCode.GATEWAY_UPSTREAM_FAILURE: 502,
    ErrorCode.GATEWAY_TIMEOUT: 504,
    ErrorCode.INTERNAL_ERROR: 500,
}

DEFAULT_MESSAGE: dict[ErrorCode, str] = {
    ErrorCode.RATE_LIMITED: "Rate limit exceeded for this tenant. Retry after the indicated delay.",
    ErrorCode.REQUEST_TOO_LARGE: "The request exceeds the maximum allowed size.",
    ErrorCode.INVALID_REQUEST: "The request is invalid.",
    ErrorCode.UNAUTHENTICATED: "Authentication is required.",
    ErrorCode.GATEWAY_UPSTREAM_FAILURE: (
        "The request could not be completed by primary or backup model providers."
    ),
    ErrorCode.GATEWAY_TIMEOUT: "The request timed out before an upstream provider responded.",
    ErrorCode.INTERNAL_ERROR: "An internal error occurred.",
}


class ErrorDetail(BaseModel):
    loc: list[str | int]
    msg: str


class ErrorBody(BaseModel):
    code: ErrorCode
    message: str
    request_id: str
    correlation_id: str
    timestamp: str
    details: list[ErrorDetail] | None = None


class ErrorEnvelope(BaseModel):
    error: ErrorBody


class GatewayError(Exception):
    """Raise from route code to return a specific envelope. ``message`` must be safe to show."""

    def __init__(
        self,
        code: ErrorCode,
        message: str | None = None,
        *,
        status_code: int | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.code = code
        self.message = message or DEFAULT_MESSAGE[code]
        self.status_code = status_code or DEFAULT_STATUS[code]
        self.headers = headers or {}
        super().__init__(self.message)


def build_envelope(
    code: ErrorCode,
    message: str | None = None,
    *,
    correlation_id: str | None = None,
    details: list[ErrorDetail] | None = None,
) -> dict[str, Any]:
    body = ErrorBody(
        code=code,
        message=message or DEFAULT_MESSAGE[code],
        request_id=str(uuid.uuid4()),
        correlation_id=correlation_id or get_correlation_id() or new_correlation_id(),
        timestamp=datetime.now(UTC).isoformat(),
        details=details,
    )
    return ErrorEnvelope(error=body).model_dump(mode="json", exclude_none=True)


def error_response(
    code: ErrorCode,
    message: str | None = None,
    *,
    status_code: int | None = None,
    headers: dict[str, str] | None = None,
    correlation_id: str | None = None,
    details: list[ErrorDetail] | None = None,
) -> JSONResponse:
    content = build_envelope(code, message, correlation_id=correlation_id, details=details)
    out_headers = dict(headers or {})
    out_headers[CORRELATION_HEADER] = content["error"]["correlation_id"]
    return JSONResponse(
        content=content, status_code=status_code or DEFAULT_STATUS[code], headers=out_headers
    )


def _code_for_status(status: int) -> ErrorCode:
    mapping = {
        401: ErrorCode.UNAUTHENTICATED,
        413: ErrorCode.REQUEST_TOO_LARGE,
        429: ErrorCode.RATE_LIMITED,
        502: ErrorCode.GATEWAY_UPSTREAM_FAILURE,
        504: ErrorCode.GATEWAY_TIMEOUT,
    }
    if status in mapping:
        return mapping[status]
    return ErrorCode.INVALID_REQUEST if 400 <= status < 500 else ErrorCode.INTERNAL_ERROR


def _cid(request: Request) -> str | None:
    return correlation_id_from_scope(request.scope) or get_correlation_id()


async def _gateway_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, GatewayError)  # noqa: S101 - registered for GatewayError only
    return error_response(
        exc.code,
        exc.message,
        status_code=exc.status_code,
        headers=exc.headers,
        correlation_id=_cid(request),
    )


async def _http_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, StarletteHTTPException)  # noqa: S101
    code = _code_for_status(exc.status_code)
    # exc.detail is deliberately dropped: it is free text from arbitrary code paths.
    return error_response(
        code,
        status_code=exc.status_code,
        headers=dict(exc.headers or {}),
        correlation_id=_cid(request),
    )


async def _validation_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)  # noqa: S101
    details = [
        ErrorDetail(
            loc=[p for p in err.get("loc", ()) if isinstance(p, str | int)],
            msg=str(err.get("msg", "invalid")),
        )
        for err in exc.errors()
    ]
    return error_response(
        ErrorCode.INVALID_REQUEST,
        status_code=422,
        correlation_id=_cid(request),
        details=details,
    )


async def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    cid = _cid(request)
    _log.error(
        "unhandled_exception",
        exc_info=(type(exc), exc, exc.__traceback__),
        extra={"correlation_id": cid, "fields": {"path": request.url.path}},
    )
    return error_response(ErrorCode.INTERNAL_ERROR, correlation_id=cid)


def install_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(GatewayError, _gateway_error_handler)
    app.add_exception_handler(StarletteHTTPException, _http_exception_handler)
    app.add_exception_handler(RequestValidationError, _validation_error_handler)
    app.add_exception_handler(Exception, _unhandled_exception_handler)
