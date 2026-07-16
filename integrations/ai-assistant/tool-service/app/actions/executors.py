"""Per-tier executors (D35). Credentials come from EnvConfig, never the model."""
from __future__ import annotations

import base64
from typing import Any

import httpx
from pydantic import BaseModel

from ..auth import User
from ..config import CFG
from ..env_registry import EnvConfig
from ..principal import Principal
from .dashboard_templates import build_dashboard_bundle
from .field_resolver import load_known_fields, validate_and_resolve_bundle_fields
from .schemas import (
    ActiveResponseParams,
    CreateDashboardParams,
    CreateVisualizationParams,
    RestartAgentParams,
)
from .types import ActionResult, ActionTier


def _reader_headers(env: EnvConfig) -> dict[str, str]:
    if not env.reader_basic or ":" not in env.reader_basic:
        return {}
    return _basic_header(env.reader_basic)


async def _prepare_dashboard_objects(
    env: EnvConfig, objects: list[dict[str, Any]]
) -> ActionResult | None:
    """Validate visualization fields against the live index pattern; auto-fix suffixes."""
    from ..indexer import get_indexer

    headers = _reader_headers(env)
    if not headers:
        return None
    indexer = get_indexer(env.env_id)
    known = await load_known_fields(indexer, headers)
    if not known:
        return None
    try:
        resolved = validate_and_resolve_bundle_fields(objects, known)
    except ValueError as exc:
        return ActionResult(
            ok=False,
            status="invalid_fields",
            message=str(exc),
            details={"hint": "call list_alert_fields for valid field names"},
        )
    return None


def _basic_header(user_pass: str) -> dict[str, str]:
    token = base64.b64encode(user_pass.encode()).decode("ascii")
    return {"Authorization": f"Basic {token}"}


async def _write_saved_objects(
    env: EnvConfig, objects: list[dict[str, Any]], cred: str
) -> ActionResult:
    index = env.saved_objects_index or CFG.saved_objects_index or ".kibana"
    # Wazuh OSD stores saved objects in the concrete index behind the .kibana alias.
    if index == ".kibana":
        index = ".kibana_1"
    verify: object = env.indexer_ca_path or CFG.indexer_verify_ssl
    headers = {
        **_basic_header(cred),
        "Content-Type": "application/json",
        "osd-xsrf": "true",
    }
    async with httpx.AsyncClient(
        base_url=env.indexer_url, verify=verify, timeout=30.0
    ) as client:
        for obj in objects:
            r = await client.put(
                f"/{index}/_doc/{obj['id']}",
                json=obj["document"],
                headers=headers,
            )
            if r.status_code not in (200, 201):
                return ActionResult(
                    ok=False,
                    status="indexer_error",
                    message=f"saved object write failed for {obj['id']}: HTTP {r.status_code}",
                    details={"body": r.text[:500], "object_id": obj["id"]},
                )
        await client.post(f"/{index}/_refresh", headers=headers)
        if index != ".kibana":
            await client.post("/.kibana/_refresh", headers=headers)
    dash = objects[-1]
    title = dash["document"].get("dashboard", {}).get("title", "")
    dash_uuid = dash["id"].split(":", 1)[-1]
    return ActionResult(
        ok=True,
        status="created",
        message=f"Dashboard '{title}' created with {len(objects) - 1} visualizations",
        details={
            "object_id": dash["id"],
            "dashboard_id": dash_uuid,
            "title": title,
            "visualization_count": len(objects) - 1,
            "dashboard_path": f"/app/dashboards#/view/{dash_uuid}",
        },
    )


async def execute_dashboard_action(
    action_name: str,
    params: BaseModel,
    env: EnvConfig,
    operator: User,
) -> ActionResult:
    if not env.dashboard_executor_basic:
        return ActionResult(
            ok=False,
            status="not_configured",
            message=(
                "dashboard executor credential not configured for this environment "
                "(set dashboard_executor_basic in the environment registry)"
            ),
            details={"action": action_name, "env_id": env.env_id},
        )

    if action_name == "create_dashboard":
        p = CreateDashboardParams.model_validate(params.model_dump())
        try:
            objects = build_dashboard_bundle(p)
        except ValueError as exc:
            return ActionResult(
                ok=False, status="invalid_template", message=str(exc)
            )
        field_err = await _prepare_dashboard_objects(env, objects)
        if field_err is not None:
            return field_err
    elif action_name == "create_visualization":
        p = CreateVisualizationParams.model_validate(params.model_dump())
        objects = [_single_visualization_object(p)]
    else:
        return ActionResult(
            ok=False,
            status="unknown_action",
            message=f"unknown dashboard action {action_name}",
        )

    result = await _write_saved_objects(env, objects, env.dashboard_executor_basic)
    if result.ok:
        result.details["confirmed_by"] = operator.sub
    return result


def _single_visualization_object(p: CreateVisualizationParams) -> dict[str, Any]:
    import json
    import uuid

    from .dashboard_templates import _index_ref, _now_iso, _search_source

    vid = f"wazuh-ai-viz-{uuid.uuid4().hex[:10]}"
    return {
        "id": f"visualization:{vid}",
        "document": {
            "type": "visualization",
            "visualization": {
                "title": p.title,
                "visState": json.dumps(
                    {
                        "title": p.title,
                        "type": p.viz_type,
                        "params": {},
                        "aggs": [
                            {
                                "id": "1",
                                "enabled": True,
                                "type": "count",
                                "schema": "metric",
                                "params": {},
                            }
                        ],
                    }
                ),
                "uiStateJSON": "{}",
                "description": "",
                "version": 1,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": _search_source(""),
                },
            },
            "references": _index_ref(),
            "migrationVersion": {"visualization": "7.10.0"},
            "updated_at": _now_iso(),
        },
    }


async def _wazuh_api_token(env: EnvConfig, cred: str) -> str:
    user, passwd = cred.split(":", 1)
    async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
        r = await client.post(
            f"{env.manager_api_url.rstrip('/')}/security/user/authenticate?raw=true",
            auth=(user, passwd),
        )
        r.raise_for_status()
        return r.json()["data"]["token"]


async def execute_manager_action(
    action_name: str,
    params: BaseModel,
    env: EnvConfig,
    operator: User,
) -> ActionResult:
    if not env.manager_api_url or not env.manager_executor_basic:
        return ActionResult(
            ok=False,
            status="not_configured",
            message=(
                "manager executor not configured "
                "(set manager_api_url and manager_executor_basic)"
            ),
            details={"action": action_name, "env_id": env.env_id},
        )

    if action_name != "restart_agent":
        return ActionResult(
            ok=False,
            status="unknown_action",
            message=f"unknown manager action {action_name}",
        )

    p = RestartAgentParams.model_validate(params.model_dump())
    try:
        token = await _wazuh_api_token(env, env.manager_executor_basic)
    except httpx.HTTPError as exc:
        return ActionResult(
            ok=False,
            status="manager_auth_error",
            message=f"Wazuh API authentication failed: {exc}",
        )

    url = f"{env.manager_api_url.rstrip('/')}/agents/{p.agent_id}/restart"
    async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
        r = await client.put(
            url,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
    if r.status_code not in (200, 201):
        return ActionResult(
            ok=False,
            status="manager_error",
            message=f"agent restart failed: HTTP {r.status_code}",
            details={"body": r.text[:500], "agent_id": p.agent_id},
        )
    return ActionResult(
        ok=True,
        status="restarted",
        message=f"Agent {p.agent_id} restart requested",
        details={"agent_id": p.agent_id, "reason": p.reason, "confirmed_by": operator.sub},
    )


async def execute_active_response_action(
    params: BaseModel,
    env: EnvConfig,
    operator: User,
) -> ActionResult:
    if not env.manager_api_url or not env.ar_executor_basic:
        return ActionResult(
            ok=False,
            status="not_configured",
            message=(
                "active-response executor not configured "
                "(set manager_api_url and ar_executor_basic)"
            ),
            details={"env_id": env.env_id},
        )

    p = ActiveResponseParams.model_validate(params.model_dump())
    try:
        token = await _wazuh_api_token(env, env.ar_executor_basic)
    except httpx.HTTPError as exc:
        return ActionResult(
            ok=False,
            status="manager_auth_error",
            message=f"Wazuh API authentication failed: {exc}",
        )

    url = f"{env.manager_api_url.rstrip('/')}/active-response"
    payload = {
        "command": p.command,
        "arguments": p.arguments or [],
        "alert": {"data": {"id": p.alert_id}} if p.alert_id else {},
        "agents": [p.agent_id],
    }
    async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
        r = await client.put(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
    if r.status_code not in (200, 201):
        return ActionResult(
            ok=False,
            status="ar_error",
            message=f"active response failed: HTTP {r.status_code}",
            details={"body": r.text[:500], "command": p.command},
        )
    return ActionResult(
        ok=True,
        status="executed",
        message=f"Active response {p.command} sent to agent {p.agent_id}",
        details={
            "agent_id": p.agent_id,
            "command": p.command,
            "reason": p.reason,
            "confirmed_by": operator.sub,
        },
    )


async def run_executor(
    tier: ActionTier,
    action_name: str,
    params: BaseModel,
    env: EnvConfig,
    operator: User,
    _principal: Principal,
) -> ActionResult:
    if tier == ActionTier.DASHBOARD:
        return await execute_dashboard_action(action_name, params, env, operator)
    if tier == ActionTier.MANAGER:
        return await execute_manager_action(action_name, params, env, operator)
    if tier == ActionTier.ACTIVE_RESPONSE:
        return await execute_active_response_action(params, env, operator)
    return ActionResult(
        ok=False,
        status="unsupported_tier",
        message=f"tier {tier.value} not implemented",
    )
