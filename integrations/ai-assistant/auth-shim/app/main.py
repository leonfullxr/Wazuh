"""wazuh-ai auth shim (D30).

The minting sidecar. It verifies an incoming OIDC access token against the
customer IdP (Keycloak here) and exchanges it for a short-lived, dual-audience
turn JWT that the tool service and the indexer both verify. The mint key lives
ONLY in this process, so the reasoning core can never forge an identity - the
same property the v1 dashboard plugin provided, re-anchored for a
world without a dashboard session.

Trust rule: this shim verifies the OIDC token itself against the IdP JWKS.
It never trusts an identity that n8n or any other edge merely forwards,
because no hop trusts headers it did not verify.
"""
from __future__ import annotations

import time
import uuid

import jwt
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from jwt import PyJWKClient
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SHIM_")

    tenant: str = "lab"
    kc_url: str = "http://keycloak:8080"
    kc_realm: str = "wazuh-poc"
    # Expected token issuer. Keycloak derives iss from the REQUEST url, so
    # tokens minted from the host (localhost:8085) carry a different issuer
    # than the in-network kc_url the shim fetches JWKS from. Empty = derive
    # from kc_url (single-url deployments).
    kc_issuer: str = ""
    jwt_issuer: str = "wazuh-ai-shim.lab"
    backend_audience: str = "wazuh-ai-backend.lab"
    indexer_audience: str = "wazuh-indexer.lab"
    ttl_seconds: int = 600  # <= 10 min, one turn
    required_role: str = "wazuh_ai_analyst"
    private_key_path: str = "/keys/jwt-private.pem"
    cors_origins: str = (
        "https://localhost,http://localhost:5601,https://localhost:5601,"
        "http://localhost:8080"
    )


CFG = Settings()
app = FastAPI(title="wazuh-ai auth shim")

_origins = [o.strip() for o in CFG.cors_origins.split(",") if o.strip()]
if _origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )

_jwks = PyJWKClient(
    f"{CFG.kc_url}/realms/{CFG.kc_realm}/protocol/openid-connect/certs",
    cache_keys=True,
)

with open(CFG.private_key_path, "rb") as fh:
    _PRIVATE_KEY = fh.read()


def _allowed_issuers() -> set[str]:
    """Host-minted tokens and in-network IdP URLs for this realm."""
    issuers = {f"{CFG.kc_url.rstrip('/')}/realms/{CFG.kc_realm}"}
    if CFG.kc_issuer:
        issuers.add(CFG.kc_issuer.rstrip("/"))
    # Host-side evals / isolation suite use localhost Keycloak; n8n uses keycloak:8080.
    issuers.add(f"http://localhost:8085/realms/{CFG.kc_realm}")
    issuers.add(f"http://keycloak:8080/realms/{CFG.kc_realm}")
    return issuers


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True, "tenant": CFG.tenant}


@app.post("/v1/token/exchange")
def exchange(authorization: str = Header(...)) -> dict:
    """OIDC access token in, turn JWT out. The whole shim is this function."""
    token = authorization.removeprefix("Bearer ").strip()
    try:
        signing_key = _jwks.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            # Issuer checked below: host-facing KC_ISSUER and in-network kc_url
            # both appear in this PoC (n8n → keycloak:8080, host evals → :8085).
            options={"verify_aud": False, "verify_iss": False},
        )
        iss = (claims.get("iss") or "").rstrip("/")
        allowed = {i.rstrip("/") for i in _allowed_issuers()}
        if iss not in allowed:
            raise HTTPException(
                401,
                f"OIDC token rejected: issuer {iss!r} not in {sorted(allowed)!r}",
            )
    except HTTPException:
        raise
    except jwt.PyJWTError as exc:
        raise HTTPException(401, f"OIDC token rejected: {exc}") from exc

    if claims.get("azp") not in (None, "wazuh-ai"):
        raise HTTPException(401, "token was not issued to the wazuh-ai client")

    roles = [
        r
        for r in claims.get("realm_access", {}).get("roles", [])
        if r.startswith("wazuh_")
    ]
    if CFG.required_role not in roles:
        # The opt-in gate (D18): no role mapping, no assistant.
        raise HTTPException(403, f"user lacks the {CFG.required_role} role")

    now = int(time.time())
    turn_claims = {
        "iss": CFG.jwt_issuer,
        "aud": [CFG.backend_audience, CFG.indexer_audience],  # dual audience
        "sub": claims.get("preferred_username") or claims["sub"],
        "backend_roles": roles,  # verbatim - the indexer resolves them (D11)
        "tenant": CFG.tenant,    # from deployment config, never from the token
        "iat": now,
        "nbf": now,
        "exp": now + CFG.ttl_seconds,
        "jti": uuid.uuid4().hex,
    }
    return {
        "access_token": jwt.encode(turn_claims, _PRIVATE_KEY, algorithm="RS256"),
        "token_type": "Bearer",
        "expires_in": CFG.ttl_seconds,
    }
