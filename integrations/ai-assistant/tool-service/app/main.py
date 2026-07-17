"""The surfaces of the headless tool service (D21/D28), lab edition:

  POST /v1/chat              SSE chat surface (the product API)
  POST /v1/chat/sync         same turn, single JSON response (n8n-friendly)
  POST /v1/connector/analyze ML Commons connector edge (V3.1, D42)
  GET  /v1/tools             the typed catalog, self-describing
  POST /v1/tools/{name}      HTTP tool surface - one validated tool call, no model

The MCP surface is a later adapter over the same internals. Every surface
authenticates with the same turn JWT and funnels through the same IR,
veracity pipeline and audit, so a question is equally truthful no matter
which door it came through.
"""
from __future__ import annotations

import asyncio
import json
import uuid
from contextlib import asynccontextmanager

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel, Field, ValidationError
from sse_starlette.sse import EventSourceResponse

from . import audit
from .admission import BusyError
from .auth import User, verify_jwt
from .config import CFG
from .env_registry import resolve_by_key, get_env
from .knowledge import knowledge_search, mitre_lookup
from .environment import dashboard_design_guide, index_health, list_alert_fields, list_dashboards
from .composite_dispatch import dispatch_composite
from .evidence_guard import guard_evidence
from .loop import run_turn
from .principal import EnvPrincipal
from .actions import (
    confirm_proposal,
    create_proposal,
    create_proposal_by_action,
    get_proposal,
    reject_proposal,
)
from .actions.registry import ACTION_REGISTRY, get_action
from .actions.cards import embed_action_cards
from .actions.run import execute_action_by_name
from .actions.types import ActionTier
from .actions.ui_static import INJECT_JS, UI_PAGE_HTML
from .tools import REGISTRY
from .states_veracity import execute_vulnerabilities_ir
from .veracity import VeracityError, execute_ir
from .mcp_surface import MCP, MCP_APP


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    async with MCP.session_manager.run():
        yield


app = FastAPI(title="wazuh-ai tool service", version="0.2.0", lifespan=_lifespan)
app.mount("/mcp", MCP_APP)

_origins = [o.strip() for o in CFG.actions_cors_origins.split(",") if o.strip()]
if _origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )


def _actions_ui_config() -> dict:
    return {
        "toolServiceUrl": CFG.ui_public_base_url.rstrip("/"),
        "shimUrl": CFG.actions_shim_public_url.rstrip("/"),
        "envId": CFG.actions_env_id,
    }


class ChatRequest(BaseModel):
    text: str = Field(min_length=1, max_length=4000)
    conversation_id: str | None = None  # multi-turn context (state.py)
    alert_id: str | None = None  # explain-this-alert entry point (D34)


class ConnectorRequest(BaseModel):
    parameters: dict


ENV_SCOPED_SUFFIX = "· environment-scoped identity"


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
        "actions_enabled": CFG.actions_enabled,
        "actions_direct": CFG.actions_direct,
        "actions_conversational": CFG.actions_conversational,
        "action_tiers": list(get_env(CFG.actions_env_id).actions_tiers),
        "action_tools": sorted(ACTION_REGISTRY) if CFG.actions_enabled else [],
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


def _env_kill_switch(env) -> None:
    if not env.enabled:
        raise HTTPException(
            503, f"wazuh-ai is disabled for environment {env.env_id} (kill switch)"
        )


async def _collect_turn(text: str, principal, timeout_s: float | None = None) -> tuple[str, dict, list]:
    """Drain run_turn into answer text + done payload + corrections."""
    answer_parts: list[str] = []
    done: dict = {}
    corrections: list = []
    budget_note = (
        "I hit the time budget for this turn before finishing. "
        "Here is what I have so far."
    )

    async def _consume():
        nonlocal done, corrections
        async for ev in run_turn(text, principal, None):
            if ev["event"] == "token":
                answer_parts.append(ev["data"]["text"])
            elif ev["event"] == "done":
                done = ev["data"]
            elif ev["event"] == "correction":
                corrections.append(ev["data"])

    try:
        if timeout_s is not None:
            await asyncio.wait_for(_consume(), timeout=timeout_s)
        else:
            await _consume()
    except asyncio.TimeoutError:
        answer_parts.append(budget_note)
        done.setdefault("verifiability", "connector timeout · partial answer")
    answer = "".join(answer_parts).strip()
    return answer, done, corrections


@app.post("/v1/connector/analyze")
async def connector_analyze(
    req: ConnectorRequest,
    x_env_key: str = Header(..., alias="X-Env-Key"),
) -> dict:
    """ML Commons HTTP connector surface (V3.1b, D42)."""
    if not CFG.service_enabled:
        raise HTTPException(503, "wazuh-ai is disabled for this tenant (kill switch)")

    env = resolve_by_key(x_env_key.strip())
    if env is None:
        audit.emit("env_key_rejected", env=None)
        raise HTTPException(401, "invalid environment key")
    _env_kill_switch(env)

    prompt = str((req.parameters or {}).get("prompt", "")).strip()
    if not prompt:
        raise HTTPException(422, "parameters.prompt is required")

    principal = EnvPrincipal(env.env_id)
    try:
        answer, done, _corrections = await _collect_turn(
            prompt, principal, timeout_s=CFG.connector_timeout_s
        )
    except BusyError as exc:
        raise HTTPException(429, str(exc)) from exc
    label = done.get("verifiability", "")
    actions = done.get("actions") or []
    if actions and not CFG.actions_direct:
        answer = embed_action_cards(
            answer, actions, ui_base=CFG.ui_public_base_url
        )
    if label:
        message = f"{answer}\n\n_{label} {ENV_SCOPED_SUFFIX}_"
    else:
        message = f"{answer}\n\n_{ENV_SCOPED_SUFFIX}_"
    payload: dict = {"output": {"message": message}}
    if label:
        payload["verifiability"] = label
    if done.get("checks"):
        payload["checks"] = done["checks"]
    if done.get("action_result"):
        payload["action_result"] = done["action_result"]
    return payload


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
            elif ev["event"] == "action_proposed":
                pass  # included in done.actions
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


@app.get("/v1/actions/ui/config")
async def actions_ui_config() -> dict:
    """Browser-facing URLs for the dashboard confirm card (V3.5c)."""
    return _actions_ui_config()


@app.get("/v1/actions/ui/inject.js")
async def actions_ui_inject() -> Response:
    cfg = json.dumps(_actions_ui_config())
    body = f"window.WAZUH_AI_ACTIONS_CONFIG = {cfg};\n{INJECT_JS}"
    return Response(body, media_type="application/javascript")


@app.get("/v1/actions/ui/{proposal_id}")
async def actions_ui_page(proposal_id: str) -> Response:
    html = (
        UI_PAGE_HTML.replace("__CONFIG_JSON__", json.dumps(_actions_ui_config()))
        .replace("__PROPOSAL_ID_JSON__", json.dumps(proposal_id))
    )
    return Response(html, media_type="text/html")


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
            elif tool.name == "knowledge_search":
                payload = await knowledge_search(validated)
            else:
                raise HTTPException(404, f"unknown knowledge tool '{name}'")
            audit.emit("http_knowledge_tool_executed", tool=name, sub=user.sub)
            return guard_evidence(payload, env_id=getattr(user, "env_id", None), source=f"http:{name}")
        if tool.environment:
            if tool.name == "index_health":
                payload = await index_health(user, validated)
            elif tool.name == "list_dashboards":
                payload = await list_dashboards(user, validated)
            elif tool.name == "list_alert_fields":
                payload = await list_alert_fields(user, validated)
            elif tool.name == "dashboard_design_guide":
                payload = await dashboard_design_guide(user, validated)
            else:
                raise HTTPException(404, f"unknown environment tool '{name}'")
            audit.emit("http_environment_tool_executed", tool=name, sub=user.sub)
            return payload
        if tool.states:
            ir = tool.to_ir(validated)
            evidence = await execute_vulnerabilities_ir(ir, user)
            audit.emit(
                "http_states_tool_executed",
                tool=name,
                sub=user.sub,
                total=evidence.total,
            )
            return evidence.to_tool_result()
        if tool.composite:
            try:
                payload = await dispatch_composite(tool.name, validated, user)
            except ValueError as exc:
                raise HTTPException(404, str(exc)) from exc
            audit.emit("http_composite_tool_executed", tool=name, sub=user.sub)
            return payload
        ir = tool.to_ir(validated)
        evidence = await execute_ir(ir, user)
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


class ConfirmActionRequest(BaseModel):
    idempotency_key: str = Field(min_length=8, max_length=128)
    confirm_target: dict | None = None


class ProposeActionRequest(BaseModel):
    action: str = Field(min_length=1, max_length=64)
    params: dict = Field(default_factory=dict)
    conversation_id: str | None = None


@app.post("/v1/connector/propose")
async def connector_propose(
    req: ProposeActionRequest,
    x_env_key: str = Header(..., alias="X-Env-Key"),
) -> dict:
    """Create a pending proposal on the connector edge (eval / harness use)."""
    if not CFG.service_enabled:
        raise HTTPException(503, "wazuh-ai is disabled for this tenant (kill switch)")
    if not CFG.actions_enabled or CFG.actions_direct:
        raise HTTPException(503, "actions propose/confirm flow is not enabled")
    env = resolve_by_key(x_env_key.strip())
    if env is None:
        audit.emit("env_key_rejected", env=None)
        raise HTTPException(401, "invalid environment key")
    _env_kill_switch(env)
    return create_proposal_by_action(
        req.action, req.params, EnvPrincipal(env.env_id), req.conversation_id
    )


@app.post("/v1/actions/propose")
async def propose_action(req: ProposeActionRequest, user: User = Depends(verify_jwt)) -> dict:
    """Create a pending proposal, or execute immediately when actions_direct=true (dashboard only)."""
    _kill_switch()
    if not CFG.actions_enabled:
        raise HTTPException(503, "actions disabled (set WAI_ACTIONS_ENABLED=true)")
    if CFG.actions_direct:
        action = get_action(req.action)
        if action is None:
            raise HTTPException(400, f"unknown action {req.action!r}")
        if action.tier != ActionTier.DASHBOARD:
            raise HTTPException(
                400,
                "manager and active-response actions require propose/confirm flow",
            )
        return await execute_action_by_name(req.action, req.params, user)
    return create_proposal_by_action(req.action, req.params, user, req.conversation_id)


@app.get("/v1/actions/{proposal_id}")
async def get_action_proposal(proposal_id: str, user: User = Depends(verify_jwt)) -> dict:
    """Fetch a pending action proposal (for UI confirm cards, D20)."""
    _kill_switch()
    prop = get_proposal(proposal_id)
    if prop is None:
        raise HTTPException(404, "proposal not found")
    if prop.env_id != user.env_id:
        raise HTTPException(403, "proposal belongs to another environment")
    return prop.to_public_dict()


@app.post("/v1/actions/{proposal_id}/confirm")
async def confirm_action_proposal(
    proposal_id: str,
    req: ConfirmActionRequest,
    user: User = Depends(verify_jwt),
) -> dict:
    """Execute a proposed action after operator confirmation (D20/D48)."""
    _kill_switch()
    try:
        prop, result = await confirm_proposal(
            proposal_id, user, req.idempotency_key, req.confirm_target
        )
    except HTTPException:
        raise
    return {
        "proposal": prop.to_public_dict(),
        "result": {
            "ok": result.ok,
            "status": result.status,
            "message": result.message,
            "details": result.details,
        },
    }


@app.post("/v1/actions/{proposal_id}/reject")
async def reject_action_proposal(
    proposal_id: str, user: User = Depends(verify_jwt)
) -> dict:
    _kill_switch()
    prop = reject_proposal(proposal_id, user)
    return prop.to_public_dict()
