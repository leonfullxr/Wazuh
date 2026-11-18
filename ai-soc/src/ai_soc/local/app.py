"""Compose the real workspace API and browser console for a local operator."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

import psycopg
from fastapi import FastAPI, Query, Request, Response
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import Field, ValidationError
from starlette.concurrency import run_in_threadpool
from starlette.types import ASGIApp, Receive, Scope, Send

from ai_soc.api.app import MAX_REQUEST_BYTES, LocalBootstrapResponse, create_app
from ai_soc.api.csrf import CsrfTokens
from ai_soc.contracts.canonical import sha256_hex
from ai_soc.contracts.models import (
    PublicLimits,
    SitePublic,
    StrictModel,
    VerifiedPrincipal,
    Visibility,
)
from ai_soc.identity.alb import IdentityError
from ai_soc.identity.policy import SiteAuthorizationError
from ai_soc.local.session import ISSUER, OWNER_GROUP, SESSION_COOKIE, SESSION_SECONDS, LocalSessions
from ai_soc.workspace.api.repository import WorkspaceRepository
from ai_soc.workspace.api.runtime import WorkspaceRuntime
from ai_soc.workspace.runtime import PipelineConfig

_NO_STORE = {"Cache-Control": "no-store"}
_SINGLE_HEADERS = (b"host", b"cookie", b"origin", b"x-soc-csrf")
_PROXY_HEADERS = frozenset(
    {b"forwarded", b"x-forwarded-for", b"x-forwarded-host", b"x-forwarded-proto"}
)


class LoopbackBoundary:
    """Use the actual peer and raw Host header before framework normalization."""

    def __init__(self, app: ASGIApp, *, authority: str) -> None:
        self.app = app
        self.authority = authority.encode("ascii")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            peer = scope.get("client")
            headers = scope.get("headers", [])
            names = [name.lower() for name, _ in headers]
            hosts = [value for name, value in headers if name.lower() == b"host"]
            if (
                peer is None
                or peer[0] != "127.0.0.1"
                or hosts != [self.authority]
                or any(names.count(name) > 1 for name in _SINGLE_HEADERS)
                or any(name in _PROXY_HEADERS for name in names)
            ):
                await Response(status_code=403, headers=_NO_STORE)(scope, receive, send)
                return
        await self.app(scope, receive, send)


@dataclass(frozen=True)
class _Site:
    environment_id: str
    label: str
    policy_hash: str
    visibility: Visibility = Visibility.full


class LocalSitePolicy:
    def __init__(self, config: PipelineConfig, owner_key: str) -> None:
        self._owner_key = owner_key
        self._sites = {
            site.site_id: _Site(
                site.site_id,
                SitePublic(id=site.site_id, label=site.label).label,
                sha256_hex(
                    [
                        "local-workspace-site-v1",
                        site.site_id,
                        site.indexer_url,
                        site.wazuh_version,
                        site.index_pattern,
                        site.full_visibility_attestation,
                        site.expected_roles,
                    ]
                ),
            )
            for site in config.sites
        }
        if len(self._sites) != len(config.sites):
            raise ValueError("duplicate local workspace site")

    def authorized_sites(self, principal: VerifiedPrincipal) -> tuple[_Site, ...]:
        if (
            principal.issuer != ISSUER
            or principal.edge != "browser"
            or principal.groups != (OWNER_GROUP,)
            or principal.owner_key != self._owner_key
            or principal.expires_at <= datetime.now(UTC)
        ):
            return ()
        return tuple(self._sites.values())

    def authorize(self, principal: VerifiedPrincipal, environment_id: str) -> _Site:
        site = self._sites.get(environment_id)
        if site is None or site not in self.authorized_sites(principal):
            raise SiteAuthorizationError()
        return site


class _Clock:
    def now(self) -> datetime:
        return datetime.now(UTC)


@dataclass(frozen=True)
class _DatabaseReadiness:
    dsn: Callable[[], str]

    def ready(self) -> bool:
        try:
            with psycopg.connect(self.dsn(), connect_timeout=1) as conn:
                return conn.execute("SELECT 1").fetchone() == (1,)
        except (psycopg.Error, OSError, ValueError):
            return False


class _SignIn(StrictModel):
    key: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


async def _login_key(request: Request) -> str | None:
    if request.headers.get("content-type", "").split(";")[0].strip() != "application/json":
        return None
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > 512:
            return None
        body.extend(chunk)
    try:
        return _SignIn.model_validate_json(body).key
    except ValidationError:
        return None


def create_local_app(
    config: PipelineConfig,
    *,
    dsn: Callable[[], str],
    origin: str,
    key: str,
    secret: bytes,
    assets: Path,
) -> FastAPI:
    parsed = urlsplit(origin)
    if parsed.port is None or origin != f"http://127.0.0.1:{parsed.port}":
        raise ValueError("local workspace requires an exact numeric loopback origin")
    if len(secret) < 32:
        raise ValueError("local workspace requires an instance secret")
    sessions = LocalSessions(key, secret)
    policy = LocalSitePolicy(config, sessions.owner_key)
    workspace = WorkspaceRuntime(
        dsn_provider=dsn,
        site_policy=policy,
        cursor_secret=sha256(b"ai-soc.local.cursor\0" + secret).digest(),
    )
    models = {
        site.site_id: site.lab_assessment.model
        for site in config.sites
        if site.lab_assessment is not None and site.lab_assessment.enabled
    }

    async def bootstrap(principal: VerifiedPrincipal) -> LocalBootstrapResponse:
        return LocalBootstrapResponse(
            sites=[
                SitePublic(id=site.environment_id, label=site.label)
                for site in policy.authorized_sites(principal)
            ],
            limits=PublicLimits(
                question_bytes=16_384,
                page_size=200,
                window_days=90,
                request_bytes=MAX_REQUEST_BYTES,
                plan_bytes=16_384,
            ),
        )

    app = create_app(
        None,
        sessions,
        CsrfTokens(sha256(b"ai-soc.local.csrf\0" + secret).digest(), origin=origin),
        _Clock(),
        _DatabaseReadiness(dsn),
        workspace,
        local_bootstrap=bootstrap,
    )
    app.add_middleware(LoopbackBoundary, authority=parsed.netloc)

    async def session_state(request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "authenticated": sessions.authenticated(request.headers),
                "model_enabled": bool(models),
            },
            headers=_NO_STORE,
        )

    async def sign_in(request: Request) -> Response:
        if request.headers.get("origin") != origin:
            return Response(status_code=403, headers=_NO_STORE)
        candidate = await _login_key(request)
        token = sessions.sign_in(candidate) if candidate is not None else None
        if token is None:
            return Response(status_code=401, headers=_NO_STORE)
        response = Response(status_code=204, headers=_NO_STORE)
        response.set_cookie(
            SESSION_COOKIE,
            token,
            max_age=SESSION_SECONDS,
            path="/",
            secure=True,
            httponly=True,
            samesite="strict",
        )
        return response

    async def sign_out(request: Request) -> Response:
        if request.headers.get("origin") != origin:
            return Response(status_code=403, headers=_NO_STORE)
        sessions.sign_out(request.headers)
        response = Response(status_code=204, headers=_NO_STORE)
        response.delete_cookie(
            SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="strict"
        )
        return response

    async def activity(
        request: Request, site_id: str = Query(min_length=1, max_length=64)
    ) -> Response:
        try:
            principal = await sessions.verify(headers=request.headers, edge="browser")
            policy.authorize(principal, site_id)
        except IdentityError:
            return Response(status_code=401, headers=_NO_STORE)
        except SiteAuthorizationError:
            return Response(status_code=403, headers=_NO_STORE)
        model = models.get(site_id)
        counts = (0, 0, 0)
        if model is not None:
            # Use the same site transaction and restricted role as the workspace API.
            counts = await run_in_threadpool(read_activity, site_id, model)
        return JSONResponse(
            {"model": model, "attempts": counts[0], "completed": counts[1], "failed": counts[2]},
            headers=_NO_STORE,
        )

    def read_activity(site_id: str, model: str) -> tuple[int, int, int]:
        repo = WorkspaceRepository.connect(dsn(), site_id)
        try:
            row = repo.conn.execute(
                """
                SELECT count(*),
                       count(*) FILTER (WHERE o.status IN ('accepted', 'no_assessment')),
                       count(*) FILTER (
                           WHERE o.status IN ('invalid_response', 'provider_unavailable')
                       )
                FROM group_assessment_attempts a
                JOIN group_assessment_requests r USING (site_id, request_id)
                LEFT JOIN group_assessment_outcomes o USING (site_id, request_id, attempt)
                WHERE a.site_id = %s AND a.model = %s AND a.provider = 'openai-compatible'
                  AND NOT r.synthetic
                """,
                (site_id, model),
            ).fetchone()
            if row is None:
                raise LookupError("assessment activity is unavailable")
            return int(row[0]), int(row[1]), int(row[2])
        finally:
            repo.close()

    app.add_api_route("/v1/local/activity", activity, methods=["GET"])
    app.add_api_route("/v1/local/session", session_state, methods=["GET"])
    app.add_api_route("/v1/local/session", sign_in, methods=["POST"], status_code=204)
    app.add_api_route("/v1/local/session", sign_out, methods=["DELETE"], status_code=204)
    app.mount("/", StaticFiles(directory=assets, html=True), name="console")
    return app
