"""The three surfaces of the headless tool service (D21/D28), lab edition:

  POST /v1/chat          SSE chat surface (the product API)
  POST /v1/chat/sync     same turn, single JSON response (n8n-friendly)
  GET  /v1/tools         the typed catalog, self-describing
  POST /v1/tools/{name}  HTTP tool surface - one validated tool call, no model

The MCP surface is a later adapter over the same internals. Every surface
authenticates with the same turn JWT and funnels through the same IR,
veracity pipeline and audit, so a question is equally truthful no matter
which door it came through.
"""
from __future__ import annotations

import json
import uuid

import httpx
from fastapi import Depends, FastAPI, HTTPException, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel, Field, ValidationError
from sse_starlette.sse import EventSourceResponse

from . import audit
from .admission import BusyError
from .auth import User, verify_jwt
from .config import CFG
from .knowledge import mitre_lookup
from .environment import index_health, list_dashboards
from .loop import run_turn
from .tools import REGISTRY
from .veracity import VeracityError, execute_ir

app = FastAPI(title="wazuh-ai tool service", version="0.2.0")


class ChatRequest(BaseModel):
    text: str = Field(min_length=1, max_length=4000)
    conversation_id: str | None = None  # multi-turn context (state.py)
    alert_id: str | None = None  # explain-this-alert entry point (D34)


def _kill_switch() -> None:
    """The per-tenant kill switch: flip WAI_SERVICE_ENABLED=false and
    every surface fails closed with an honest 503."""
    if not CFG.service_enabled:
        raise HTTPException(503, "wazuh-ai is disabled for this tenant (kill switch)")


def _effective_text(req: ChatRequest) -> str:
    if req.alert_id:
        return f"Explain the alert with id {req.alert_id}. {req.text}".strip()
    return req.text


def _indexer_http_error(exc: httpx.HTTPStatusError) -> HTTPException:
    """An indexer rejection mid-turn (expired turn JWT, revoked role) is an
    auth problem, not a server bug - never a 500."""
    status = exc.response.status_code
    if status in (401, 403):
        return HTTPException(401, "indexer rejected the turn credential (expired?)")
    return HTTPException(502, f"indexer error {status}")


def _llm_backend_label() -> str:
    """Human-readable inference endpoint for audit and error messages."""
    if CFG.analysis_base_url:
        return CFG.analysis_base_url
    if CFG.router_base_url and CFG.model_router != CFG.model_analysis:
        return f"router={CFG.router_base_url} analysis={CFG.llm_base_url}"
    return CFG.llm_base_url


def _llm_unreachable_error(exc: httpx.HTTPError) -> HTTPException:
    """Honest rejection when the inference backend cannot be reached (D14)."""
    backend = _llm_backend_label()
    audit.emit("llm_unreachable", backend=backend, reason=str(exc)[:300])
    return HTTPException(
        503,
        f"inference backend unreachable ({backend})",
    )


_LLM_TRANSPORT_ERRORS = (httpx.ConnectError, httpx.ConnectTimeout)


@app.get("/healthz")
async def healthz() -> dict:
    return {
        "ok": True,
        "enabled": CFG.service_enabled,
        "tenant": CFG.tenant,
        "tools": sorted(REGISTRY),
    }


@app.get("/metrics")
async def metrics_endpoint() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/v1/chat")
async def chat(req: ChatRequest, user: User = Depends(verify_jwt)):
    _kill_switch()
    conversation_id = req.conversation_id or uuid.uuid4().hex

    async def gen():
        try:
            async for ev in run_turn(_effective_text(req), user, conversation_id):
                yield {"event": ev["event"], "data": json.dumps(ev["data"])}
        except BusyError as exc:
            yield {"event": "error", "data": json.dumps({"code": "busy", "msg": str(exc)})}
        except _LLM_TRANSPORT_ERRORS as exc:
            audit.emit(
                "llm_unreachable",
                backend=_llm_backend_label(),
                reason=str(exc)[:300],
            )
            yield {
                "event": "error",
                "data": json.dumps(
                    {
                        "code": "llm_unreachable",
                        "msg": f"inference backend unreachable ({_llm_backend_label()})",
                    }
                ),
            }
        except httpx.HTTPStatusError as exc:
            err = _indexer_http_error(exc)
            yield {"event": "error", "data": json.dumps({"code": "indexer", "msg": err.detail})}

    return EventSourceResponse(gen(), ping=15)  # SSE keepalive


@app.post("/v1/chat/sync")
async def chat_sync(req: ChatRequest, user: User = Depends(verify_jwt)) -> dict:
    """The whole turn as one JSON document - what the n8n workflow consumes
    until the SSE-rendering spike settles."""
    _kill_switch()
    conversation_id = req.conversation_id or uuid.uuid4().hex
    answer, done, corrections = "", {}, []
    try:
        async for ev in run_turn(_effective_text(req), user, conversation_id):
            if ev["event"] == "token":
                answer += ev["data"]["text"]
            elif ev["event"] == "done":
                done = ev["data"]
            elif ev["event"] == "correction":
                corrections.append(ev["data"])
    except BusyError as exc:
        raise HTTPException(429, str(exc)) from exc
    except _LLM_TRANSPORT_ERRORS as exc:
        raise _llm_unreachable_error(exc) from exc
    except httpx.HTTPStatusError as exc:
        raise _indexer_http_error(exc) from exc
    return {"answer": answer, **done}


@app.get("/v1/tools")
async def list_tools() -> list[dict]:
    return [
        {
            "name": t.name,
            "lane": t.lane,
            "description": t.description,
            "input_schema": t.schema.model_json_schema(),
        }
        for t in REGISTRY.values()
    ]


@app.post("/v1/tools/{name}")
async def call_tool(name: str, params: dict, user: User = Depends(verify_jwt)) -> dict:
    """One tool call over plain HTTP: validated params -> IR -> veracity
    pipeline -> evidence. No model involved, so this is the drop-in
    replacement for raw community-node arms in an n8n flow."""
    _kill_switch()
    tool = REGISTRY.get(name)
    if tool is None:
        raise HTTPException(404, f"unknown tool '{name}'")
    try:
        validated = tool.schema.model_validate(params)
        if tool.knowledge:
            if tool.name == "mitre_lookup":
                payload = mitre_lookup(validated)
            else:
                raise HTTPException(404, f"unknown knowledge tool '{name}'")
            audit.emit("http_knowledge_tool_executed", tool=name, sub=user.sub)
            return payload
        if tool.environment:
            if tool.name == "index_health":
                payload = await index_health(user.raw_jwt, validated)
            elif tool.name == "list_dashboards":
                payload = await list_dashboards(user.raw_jwt, validated)
            else:
                raise HTTPException(404, f"unknown environment tool '{name}'")
            audit.emit("http_environment_tool_executed", tool=name, sub=user.sub)
            return payload
        ir = tool.to_ir(validated)
        evidence = await execute_ir(ir, user.raw_jwt)
    except ValidationError as exc:
        raise HTTPException(422, exc.errors()) from exc
    except VeracityError as exc:
        raise HTTPException(422, str(exc)) from exc
    except httpx.HTTPStatusError as exc:
        raise _indexer_http_error(exc) from exc
    audit.emit(
        "http_tool_executed",
        tool=name,
        lane=tool.lane,
        sub=user.sub,
        ir=ir.model_dump(mode="json"),
        total=evidence.total,
    )
    return evidence.to_tool_result()
