"""wazuh-ai auth shim (D30, V3.6).

The minting sidecar. It verifies analyst credentials against the environment's
indexer via ``POST /_plugins/_security/authinfo``, then exchanges them for a
short-lived, dual-audience turn JWT that the tool service and the indexer both
verify. The mint key lives ONLY in this process.

Trust rule: credentials are verified by the environment's own security plugin.
The shim never trusts identity that an edge merely forwards.
"""
from __future__ import annotations

import time
import uuid

import httpx
import jwt
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic_settings import BaseSettings, SettingsConfigDict

from . import audit
from .env_registry import EnvEntry, load_environments
from .rate_limit import ExchangeRateLimiter


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SHIM_")

    jwt_issuer: str = "wazuh-ai-shim.lab"
    backend_audience: str = "wazuh-ai-backend.lab"
    indexer_audience: str = "wazuh-indexer.lab"
    ttl_seconds: int = 600  # <= 10 min, one turn
    required_role: str = "wazuh_ai_analyst"
    private_key_path: str = "/keys/jwt-private.pem"
    indexer_verify_ssl: bool = False
    exchanges_per_user_per_minute: int = 20
    exchanges_per_ip_per_minute: int = 60
    cors_origins: str = (
        "https://localhost,http://localhost:5601,https://localhost:5601,"
        "http://localhost:8080"
    )


CFG = Settings()
app = FastAPI(title="wazuh-ai auth shim")
_LIMITER = ExchangeRateLimiter(
    per_user_per_minute=CFG.exchanges_per_user_per_minute,
    per_ip_per_minute=CFG.exchanges_per_ip_per_minute,
)

_origins = [o.strip() for o in CFG.cors_origins.split(",") if o.strip()]
if _origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Env-Id"],
    )

with open(CFG.private_key_path, "rb") as fh:
    _PRIVATE_KEY = fh.read()

try:
    ENV_REGISTRY = load_environments()
except Exception as exc:
    raise RuntimeError(f"failed to load environment registry: {exc}") from exc


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def _resolve_env(env_id: str | None) -> EnvEntry:
    if env_id:
        env = ENV_REGISTRY.get(env_id)
        if env is None:
            audit.emit("exchange_env_rejected", env=env_id, reason="unknown_env")
            raise HTTPException(400, f"unknown environment {env_id!r}")
        return env
    if len(ENV_REGISTRY) == 1:
        return next(iter(ENV_REGISTRY.values()))
    audit.emit("exchange_env_rejected", env=None, reason="env_id_required")
    raise HTTPException(400, "X-Env-Id required when multiple environments are configured")


def _parse_basic(authorization: str) -> tuple[str, str]:
    if not authorization.startswith("Basic "):
        audit.emit("exchange_auth_rejected", reason="missing_basic")
        raise HTTPException(401, "Basic authentication required")
    try:
        import base64

        decoded = base64.b64decode(authorization[6:].strip(), validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        audit.emit("exchange_auth_rejected", reason="invalid_basic_encoding")
        raise HTTPException(401, "invalid Basic credentials encoding") from exc
    username, sep, password = decoded.partition(":")
    if not sep or not username:
        audit.emit("exchange_auth_rejected", reason="invalid_basic_format")
        raise HTTPException(401, "invalid Basic credentials")
    return username, password


def _authinfo(env: EnvEntry, username: str, password: str) -> dict:
    verify: bool | str = env.indexer_ca_path if env.indexer_ca_path else CFG.indexer_verify_ssl
    url = f"{env.indexer_url.rstrip('/')}/_plugins/_security/authinfo"
    try:
        resp = httpx.post(
            url,
            auth=(username, password),
            verify=verify,
            timeout=30.0,
        )
    except httpx.HTTPError as exc:
        audit.emit(
            "exchange_authinfo_unreachable",
            env=env.env_id,
            sub=username,
            reason=str(exc)[:200],
        )
        raise HTTPException(502, f"indexer authinfo unreachable: {exc}") from exc
    if resp.status_code == 401:
        audit.emit("exchange_credentials_rejected", env=env.env_id, sub=username)
        raise HTTPException(401, "invalid username or password")
    if resp.status_code >= 400:
        audit.emit(
            "exchange_authinfo_error",
            env=env.env_id,
            sub=username,
            status=resp.status_code,
        )
        raise HTTPException(502, f"indexer authinfo error {resp.status_code}")
    data = resp.json()
    if not isinstance(data, dict):
        audit.emit("exchange_authinfo_error", env=env.env_id, sub=username, reason="bad_payload")
        raise HTTPException(502, "indexer authinfo returned unexpected payload")
    return data


@app.get("/healthz")
def healthz() -> dict:
    return {
        "ok": True,
        "environments": sorted(ENV_REGISTRY),
    }


@app.post("/v1/token/exchange")
def exchange(
    request: Request,
    authorization: str = Header(...),
    x_env_id: str | None = Header(default=None, alias="X-Env-Id"),
) -> dict:
    """Basic credentials in, turn JWT out."""
    username, password = _parse_basic(authorization)
    env = _resolve_env((x_env_id or "").strip() or None)
    if not _LIMITER.allow(
        client_ip=_client_ip(request),
        username=username,
        env_id=env.env_id,
    ):
        audit.emit("exchange_rate_limited", env=env.env_id, sub=username)
        raise HTTPException(429, "exchange rate limit exceeded, try again in a minute")

    info = _authinfo(env, username, password)

    backend_roles = info.get("backend_roles") or []
    if not isinstance(backend_roles, list):
        backend_roles = []
    roles = [str(r) for r in backend_roles if str(r).startswith("wazuh_")]

    if CFG.required_role not in roles:
        audit.emit(
            "exchange_role_rejected",
            env=env.env_id,
            sub=username,
            role=CFG.required_role,
        )
        raise HTTPException(403, f"user lacks the {CFG.required_role} role")

    sub = str(info.get("user_name") or username)
    now = int(time.time())
    turn_claims = {
        "iss": CFG.jwt_issuer,
        "aud": [CFG.backend_audience, CFG.indexer_audience],
        "sub": sub,
        "backend_roles": roles,
        "tenant": env.env_id,
        "iat": now,
        "nbf": now,
        "exp": now + CFG.ttl_seconds,
        "jti": uuid.uuid4().hex,
    }
    audit.emit("exchange_succeeded", env=env.env_id, sub=sub)
    return {
        "access_token": jwt.encode(turn_claims, _PRIVATE_KEY, algorithm="RS256"),
        "token_type": "Bearer",
        "expires_in": CFG.ttl_seconds,
    }
