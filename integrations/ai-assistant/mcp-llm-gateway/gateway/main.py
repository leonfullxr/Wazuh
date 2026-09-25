"""FastAPI entrypoint for the MCP-LLM gateway."""
from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from .config import CFG
from .handler import process_analyze

app = FastAPI(title="Wazuh AI Assistant Gateway", version="0.1.0")


class AnalyzeRequest(BaseModel):
    parameters: dict[str, Any] = Field(default_factory=dict)


def verify_api_key(
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
    authorization: str | None = Header(default=None),
) -> None:
    expected = CFG.gateway_api_key
    if not expected:
        raise HTTPException(status_code=500, detail="GATEWAY_API_KEY is not configured")
    if x_api_key == expected:
        return
    if authorization:
        token = authorization.removeprefix("Bearer ").strip()
        if token == expected:
            return
    raise HTTPException(status_code=401, detail="Invalid API key")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze")
def analyze(
    body: AnalyzeRequest,
    _: None = Depends(verify_api_key),
) -> dict[str, Any]:
    return process_analyze(body.parameters)
