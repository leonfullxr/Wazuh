"""Authenticated REST boundary for the thin SOC client."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from datetime import datetime
from typing import Any, Protocol, TypeVar, cast
from uuid import UUID, uuid4

from fastapi import FastAPI, Request, Response
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from starlette.middleware.base import BaseHTTPMiddleware

from ai_soc.api.csrf import CsrfTokens
from ai_soc.api.cursor_errors import service_failure_from_cursor
from ai_soc.application.errors import ServiceFailure
from ai_soc.contracts.errors import public_error, status_for
from ai_soc.contracts.models import (
    Answer,
    AskRequest,
    BootstrapResponse,
    ErrorCode,
    FeedbackQueued,
    FeedbackRequest,
    FetchResult,
    PageRequest,
    VerifiedPrincipal,
)
from ai_soc.contracts.ports import IdentityVerifier
from ai_soc.identity.alb import IdentityError
from ai_soc.query.cursors import CursorError
from ai_soc.state.errors import StateFailure

MAX_REQUEST_BYTES = 65_536
CSRF_COOKIE = "__Host-soc-csrf"
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    ),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}
RequestModel = TypeVar("RequestModel", AskRequest, PageRequest, FeedbackRequest)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            if name not in response.headers:
                response.headers[name] = value
        return response


class Application(Protocol):
    async def bootstrap(self, principal: VerifiedPrincipal) -> BootstrapResponse: ...

    async def ask(
        self,
        request: AskRequest,
        principal: VerifiedPrincipal,
        *,
        idempotency_key: UUID | None = None,
    ) -> Answer: ...

    async def page(self, request: PageRequest, principal: VerifiedPrincipal) -> FetchResult: ...

    async def feedback(
        self, request: FeedbackRequest, principal: VerifiedPrincipal
    ) -> FeedbackQueued: ...


class Clock(Protocol):
    def now(self) -> datetime: ...


class Readiness(Protocol):
    def ready(self) -> bool: ...


def create_app(
    application: Application,
    identity: IdentityVerifier,
    csrf: CsrfTokens,
    clock: Clock,
    readiness: Readiness,
    workspace_runtime: object | None = None,
) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(SecurityHeadersMiddleware)

    async def service_failure(request: Request, error: Exception) -> JSONResponse:
        if isinstance(error, StateFailure):
            domain_error = error.error
        elif isinstance(error, ServiceFailure):
            domain_error = error.error
        else:
            raise error
        status = status_for(domain_error.code)
        headers = {"Retry-After": "60"} if status == 429 else None
        if request.url.path.startswith("/v1/workspace/"):
            headers = dict(headers or {})
            headers["X-Trace-Id"] = domain_error.trace_id
        return JSONResponse(
            status_code=status,
            content=domain_error.model_dump(mode="json"),
            headers=headers,
        )

    async def schema_failure(_: Request, error: Exception) -> JSONResponse:
        if not isinstance(error, ValidationError):
            raise error
        domain_error = public_error(
            ErrorCode.INVALID_SCHEMA,
            "The request does not match the supported schema.",
            trace_id=uuid4().hex,
        )
        return JSONResponse(status_code=422, content=domain_error.model_dump(mode="json"))

    async def principal(request: Request) -> VerifiedPrincipal:
        try:
            headers: Mapping[str, str] = dict(request.headers)
            return await identity.verify(headers=headers, edge="browser")
        except ServiceFailure:
            raise
        except IdentityError as error:
            code = error.code
            messages = {
                ErrorCode.AUTH_REQUIRED: "A valid browser assertion is required.",
                ErrorCode.AUTH_EXPIRED: "The browser assertion has expired.",
                ErrorCode.AUTH_INVALID: "Authentication could not be verified.",
            }
            if code not in messages:
                code = ErrorCode.AUTH_INVALID
            raise ServiceFailure(public_error(code, messages[code], trace_id=uuid4().hex)) from None
        except Exception:
            raise ServiceFailure(
                public_error(
                    ErrorCode.AUTH_INVALID,
                    "Authentication could not be verified.",
                    trace_id=uuid4().hex,
                )
            ) from None

    async def body(request: Request) -> bytes:
        declared = request.headers.get("content-length")
        if declared is not None:
            try:
                if int(declared) > MAX_REQUEST_BYTES:
                    raise _request_too_large()
            except ValueError:
                raise _bad_request() from None
        chunks: list[bytes] = []
        size = 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > MAX_REQUEST_BYTES:
                raise _request_too_large()
            chunks.append(chunk)
        return b"".join(chunks)

    async def parse(request: Request, model: type[RequestModel]) -> RequestModel:
        payload = await body(request)
        try:
            return model.model_validate_json(payload)
        except ValidationError as error:
            if any(item.get("type") == "json_invalid" for item in error.errors()):
                raise _bad_request() from None
            raise ServiceFailure(
                public_error(
                    ErrorCode.INVALID_SCHEMA,
                    "The request does not match the supported schema.",
                    trace_id=uuid4().hex,
                )
            ) from None

    def verify_csrf(request: Request, verified: VerifiedPrincipal) -> None:
        csrf.verify(
            request.headers.get("x-soc-csrf", ""),
            request.cookies.get(CSRF_COOKIE, ""),
            owner_key=verified.owner_key,
            origin=request.headers.get("origin"),
            now=clock.now(),
        )

    async def live() -> dict[str, str]:
        return {"status": "ok"}

    async def ready() -> JSONResponse:
        try:
            ok = await asyncio.wait_for(asyncio.to_thread(readiness.ready), timeout=1.5)
        except TimeoutError:
            ok = False
        if ok:
            return JSONResponse(status_code=200, content={"status": "ready"})
        return JSONResponse(status_code=503, content={"status": "unavailable"})

    if workspace_runtime is not None:
        from psycopg import Error as PsycopgError

        from ai_soc.workspace.api.router import (
            WorkspaceApiError,
            workspace_api_error_handler,
            workspace_database_error_handler,
            workspace_router,
        )
        from ai_soc.workspace.api.runtime import WorkspaceRuntime

        if not isinstance(workspace_runtime, WorkspaceRuntime):
            raise TypeError("workspace_runtime must be a WorkspaceRuntime")

        async def workspace_validation_failure(
            _: Request, error: RequestValidationError
        ) -> JSONResponse:
            if not _.url.path.startswith("/v1/workspace/"):
                return await request_validation_exception_handler(_, error)
            trace_id = uuid4().hex
            body = {
                "code": "BAD_FILTER",
                "message": "One or more query parameters are invalid.",
                "retryable": False,
                "trace_id": trace_id,
                "details": None,
            }
            return JSONResponse(
                status_code=422,
                content=body,
                headers={"X-Trace-Id": trace_id, "Cache-Control": "no-store"},
            )

        app.add_exception_handler(WorkspaceApiError, cast(Any, workspace_api_error_handler))
        app.add_exception_handler(PsycopgError, cast(Any, workspace_database_error_handler))
        app.add_exception_handler(RequestValidationError, cast(Any, workspace_validation_failure))
        app.include_router(
            workspace_router(workspace_runtime, principal, verify_csrf),
            prefix="/v1/workspace",
        )

    async def bootstrap(request: Request, response: Response) -> JSONResponse:
        verified = await principal(request)
        result = await application.bootstrap(verified)
        cookie, token = csrf.issue(
            owner_key=verified.owner_key,
            assertion_expires_at=verified.expires_at,
            now=clock.now(),
        )
        response.set_cookie(
            CSRF_COOKIE,
            cookie,
            max_age=600,
            path="/",
            secure=True,
            httponly=True,
            samesite="strict",
        )
        return JSONResponse(
            content=result.model_copy(update={"csrf_token": token}).model_dump(mode="json"),
            headers={
                "Set-Cookie": response.headers.get("set-cookie", ""),
                "Cache-Control": "no-store",
            },
        )

    async def questions(request: Request) -> JSONResponse:
        verified = await principal(request)
        verify_csrf(request, verified)
        parsed = await parse(request, AskRequest)
        raw_key = request.headers.get("idempotency-key")
        try:
            key = UUID(raw_key) if raw_key else None
        except ValueError:
            raise _bad_request() from None
        result = await application.ask(parsed, verified, idempotency_key=key)
        return JSONResponse(
            content=result.model_dump(mode="json"), headers={"Cache-Control": "no-store"}
        )

    async def page(request: Request) -> JSONResponse:
        verified = await principal(request)
        verify_csrf(request, verified)
        parsed = await parse(request, PageRequest)
        try:
            result = await application.page(parsed, verified)
        except CursorError as error:
            raise service_failure_from_cursor(error) from None
        return JSONResponse(
            content=result.model_dump(mode="json"), headers={"Cache-Control": "no-store"}
        )

    async def feedback(request: Request) -> JSONResponse:
        verified = await principal(request)
        verify_csrf(request, verified)
        parsed = await parse(request, FeedbackRequest)
        result = await application.feedback(parsed, verified)
        return JSONResponse(
            status_code=202,
            content=result.model_dump(mode="json"),
            headers={"Cache-Control": "no-store"},
        )

    app.add_exception_handler(ServiceFailure, service_failure)
    app.add_exception_handler(StateFailure, service_failure)
    app.add_exception_handler(ValidationError, schema_failure)
    app.add_api_route("/health/live", live, methods=["GET"])
    app.add_api_route("/health/ready", ready, methods=["GET"])
    app.add_api_route("/v1/bootstrap", bootstrap, methods=["GET"])
    app.add_api_route("/v1/questions", questions, methods=["POST"])
    app.add_api_route("/v1/fetches/page", page, methods=["POST"])
    app.add_api_route("/v1/feedback", feedback, methods=["POST"], status_code=202)
    return app


def _bad_request() -> ServiceFailure:
    return ServiceFailure(
        public_error(ErrorCode.BAD_REQUEST, "The request could not be parsed.", trace_id="0" * 32)
    )


def _request_too_large() -> ServiceFailure:
    return ServiceFailure(
        public_error(
            ErrorCode.REQUEST_TOO_LARGE,
            "The request exceeds the supported size limit.",
            trace_id="0" * 32,
            limit=MAX_REQUEST_BYTES,
        )
    )
