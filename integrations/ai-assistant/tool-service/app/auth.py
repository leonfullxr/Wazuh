"""Gate 4 - identity. Verify-only: this process holds the public key
and can never mint or extend a token. raw_jwt is retained ONLY to forward to
the indexer, so queries execute as the asking analyst (D11)."""
from __future__ import annotations

from dataclasses import dataclass

import jwt
from fastapi import Header, HTTPException

from .config import CFG
from . import audit

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


async def verify_jwt(authorization: str = Header(...)) -> User:
    token = authorization.removeprefix("Bearer ").strip()
    try:
        claims = jwt.decode(
            token,
            _PUBLIC_KEY,
            algorithms=["RS256"],
            audience=CFG.jwt_audience,
            issuer=CFG.jwt_issuer,
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(401, f"turn token rejected: {exc}") from exc

    if claims.get("tenant") != CFG.tenant:
        # Defense in depth: a token minted for another tenant is rejected even
        # if it somehow arrived here.
        audit.emit("cross_tenant_token_rejected", sub=claims.get("sub"))
        raise HTTPException(403, "tenant mismatch")
    if CFG.access_role not in claims.get("backend_roles", []):
        raise HTTPException(403, f"missing role {CFG.access_role}")

    return User(
        sub=claims["sub"],
        roles=claims["backend_roles"],
        raw_jwt=token,
        env_id=CFG.tenant,
    )
