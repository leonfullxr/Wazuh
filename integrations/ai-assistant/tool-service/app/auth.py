"""Gate 4 - identity. Verify-only: this process holds the public key
and can never mint or extend a token. raw_jwt is retained ONLY to forward to
the indexer, so queries execute as the asking analyst (D11)."""
from __future__ import annotations

from dataclasses import dataclass

import jwt
from fastapi import Header, HTTPException

from .config import CFG
from . import audit
from .env_registry import ENV_REGISTRY

with open(CFG.jwt_public_key_path, "rb") as fh:
    _PUBLIC_KEY = fh.read()


@dataclass
class User:
    sub: str
    roles: list[str]
    raw_jwt: str
    env_id: str = ""

    def __post_init__(self) -> None:
        if not self.env_id:
            object.__setattr__(self, "env_id", CFG.tenant)

    @property
    def admission_key(self) -> str:
        return self.sub

    @property
    def edge(self) -> str:
        return "direct"


def user_from_token(token: str) -> User:
    try:
        claims = jwt.decode(
            token,
            _PUBLIC_KEY,
            algorithms=["RS256"],
            audience=CFG.jwt_audience,
            issuer=CFG.jwt_issuer,
        )
    except jwt.PyJWTError as exc:
        audit.emit("turn_token_rejected", reason=str(exc)[:200])
        raise HTTPException(401, f"turn token rejected: {exc}") from exc

    tenant = str(claims.get("tenant") or CFG.tenant)
    if tenant not in ENV_REGISTRY:
        audit.emit("cross_tenant_token_rejected", sub=claims.get("sub"), tenant=tenant)
        raise HTTPException(403, "tenant mismatch")
    env = ENV_REGISTRY[tenant]
    if not env.enabled:
        audit.emit("env_disabled_rejected", env=tenant, sub=claims.get("sub"))
        raise HTTPException(503, f"environment {tenant!r} is disabled")

    roles = claims.get("backend_roles") or []
    if CFG.access_role not in roles:
        audit.emit(
            "turn_role_rejected",
            env=tenant,
            sub=claims.get("sub"),
            role=CFG.access_role,
        )
        raise HTTPException(403, f"missing role {CFG.access_role}")

    return User(
        sub=claims["sub"],
        roles=roles,
        raw_jwt=token,
        env_id=tenant,
    )


async def verify_jwt(authorization: str = Header(...)) -> User:
    token = authorization.removeprefix("Bearer ").strip()
    return user_from_token(token)
