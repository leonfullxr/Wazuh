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
from .field_resolver import (
    load_aggregatable_index_pattern_fields,
    load_known_fields,
    validate_and_resolve_bundle_fields,
)
from .fields import FIELD_COUNTRY_ISO2
from .index_pattern_fields import (
    bundle_has_region_map,
    ensure_country_iso2_scripted_field,
    load_index_pattern_fields_from_dashboard,
)
from .schemas import (
    ActiveResponseParams,
    AddAgentToGroupParams,
    CreateDashboardParams,
    CreateIndexerMonitorParams,
    CreateVisualizationParams,
    RestartAgentParams,
    SuppressNoisyRuleParams,
)
from .types import ActionResult, ActionTier
from .monitor_templates import build_monitor_body


def _basic_header(user_pass: str) -> dict[str, str]:
    token = base64.b64encode(user_pass.encode()).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def _reader_headers(env: EnvConfig) -> dict[str, str]:
    if not env.reader_basic or ":" not in env.reader_basic:
        return {}
    return _basic_header(env.reader_basic)


def _manager_verify(env: EnvConfig) -> object:
    return env.manager_ca_path or env.indexer_ca_path or CFG.indexer_verify_ssl


def _require_agent_id(agent_id: str) -> str:
    agent_id = (agent_id or "").strip()
    if not agent_id:
        raise ValueError("agent_id is required — refusing untargeted manager/AR call")
    return agent_id


async def _prepare_dashboard_objects(
    env: EnvConfig, objects: list[dict[str, Any]]
) -> ActionResult | None:
    """Validate visualization fields; rewrite in place before write (R6.4)."""
    from ..indexer import get_indexer

    headers = _reader_headers(env)
    if not headers:
        return None
    indexer = get_indexer(env.env_id)
    needs_region_map = bundle_has_region_map(objects)
    if needs_region_map:
        if not await ensure_country_iso2_scripted_field(env):
            return ActionResult(
                ok=False,
                status="index_pattern_unavailable",
                message=(
                    "could not register GeoLocation.country_iso2 on the wazuh-alerts-* "
                    "index pattern (dashboard_api_url / dashboard_executor_basic required "
                    "for region maps on stock Wazuh)"
                ),
                details={"env_id": env.env_id},
            )
    known = await load_known_fields(indexer, headers)
    aggregatable = await load_aggregatable_index_pattern_fields(indexer, headers)
    dash_names, dash_agg = await load_index_pattern_fields_from_dashboard(env)
    known |= dash_names
    aggregatable |= dash_agg
    if needs_region_map and FIELD_COUNTRY_ISO2 not in aggregatable:
        return ActionResult(
            ok=False,
            status="index_pattern_unavailable",
            message=(
                "GeoLocation.country_iso2 is not on the wazuh-alerts-* index pattern "
                "after registration — check dashboard executor permissions"
            ),
            details={"env_id": env.env_id},
        )
    if not known:
        return None
    try:
        validate_and_resolve_bundle_fields(objects, known, aggregatable)
    except ValueError as exc:
        return ActionResult(
            ok=False,
            status="invalid_fields",
            message=str(exc),
            details={"hint": "call list_alert_fields for valid field names"},
        )
    return None


def _to_saved_object_bulk(obj: dict[str, Any]) -> dict[str, Any]:
    doc = obj["document"]
    obj_type = doc["type"]
    obj_id = obj["id"].split(":", 1)[-1]
    return {
        "type": obj_type,
        "id": obj_id,
        "attributes": doc[obj_type],
        "references": doc.get("references", []),
    }


async def _write_saved_objects(
    env: EnvConfig, objects: list[dict[str, Any]], cred: str
) -> ActionResult:
    """Write via Dashboards saved-objects HTTP API (R6.9)."""
    base = (env.dashboard_api_url or "").rstrip("/")
    if not base:
        return ActionResult(
            ok=False,
            status="not_configured",
            message="dashboard_api_url not configured for this environment",
            details={"env_id": env.env_id},
        )
    verify: object = env.indexer_ca_path or CFG.indexer_verify_ssl
    headers = {
        **_basic_header(cred),
        "Content-Type": "application/json",
        "osd-xsrf": "true",
    }
    bulk = [_to_saved_object_bulk(obj) for obj in objects]
    try:
        async with httpx.AsyncClient(base_url=base, verify=verify, timeout=30.0) as client:
            r = await client.post(
                "/api/saved_objects/_bulk_create?overwrite=true",
                json=bulk,
                headers=headers,
            )
    except httpx.HTTPError as exc:
        return ActionResult(
            ok=False,
            status="dashboard_api_unreachable",
            message=f"could not reach dashboard API at {base}: {exc}",
            details={"dashboard_api_url": base},
        )
    if r.status_code not in (200, 201):
        return ActionResult(
            ok=False,
            status="dashboard_api_error",
            message=f"saved object bulk create failed: HTTP {r.status_code}",
            details={"body": r.text[:500], "dashboard_api_url": base},
        )
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
        field_err = await _prepare_dashboard_objects(env, objects)
        if field_err is not None:
            return field_err
    elif action_name == "create_indexer_monitor":
        return await _create_indexer_monitor(params, env, operator)
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


async def _create_indexer_monitor(
    params: BaseModel, env: EnvConfig, operator: User
) -> ActionResult:
    """Write curated OpenSearch Alerting monitor via indexer HTTP API."""
    cred = env.dashboard_executor_basic or env.reader_basic
    if not cred or ":" not in cred:
        return ActionResult(
            ok=False,
            status="not_configured",
            message=(
                "indexer monitor write needs dashboard_executor_basic "
                "(or reader_basic) on this environment"
            ),
            details={"env_id": env.env_id},
        )
    p = CreateIndexerMonitorParams.model_validate(params.model_dump())
    body = build_monitor_body(p)
    # Strip internal metadata keys the Alerting API does not accept.
    body.pop("wazuh_ai_template", None)
    body.pop("wazuh_ai_reason", None)
    verify: object = env.indexer_ca_path or CFG.indexer_verify_ssl
    base = env.indexer_url.rstrip("/")
    try:
        async with httpx.AsyncClient(base_url=base, verify=verify, timeout=30.0) as client:
            r = await client.post(
                "/_plugins/_alerting/monitors",
                json=body,
                headers={**_basic_header(cred), "Content-Type": "application/json"},
            )
    except httpx.HTTPError as exc:
        return ActionResult(
            ok=False,
            status="indexer_unreachable",
            message=f"could not reach indexer alerting API: {exc}",
            details={"indexer_url": base},
        )
    if r.status_code not in (200, 201):
        return ActionResult(
            ok=False,
            status="alerting_error",
            message=f"create monitor failed: HTTP {r.status_code}",
            details={"body": r.text[:500], "template": p.template},
        )
    data = r.json() if r.content else {}
    return ActionResult(
        ok=True,
        status="created",
        message=f"Monitor '{p.title}' created (template {p.template})",
        details={
            "monitor_id": data.get("_id") or data.get("id"),
            "title": p.title,
            "template": p.template,
            "confirmed_by": operator.sub,
        },
    )


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
    verify = _manager_verify(env)
    async with httpx.AsyncClient(verify=verify, timeout=30.0) as client:
        r = await client.post(
            f"{env.manager_api_url.rstrip('/')}/security/user/authenticate?raw=true",
            auth=(user, passwd),
        )
        r.raise_for_status()
        # raw=true returns the bare JWT as text, not the {"data":{"token"}} JSON.
        return r.text.strip()


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

    if action_name == "restart_agent":
        p = RestartAgentParams.model_validate(params.model_dump())
        try:
            agent_id = _require_agent_id(p.agent_id)
        except ValueError as exc:
            return ActionResult(ok=False, status="invalid_target", message=str(exc))

        try:
            token = await _wazuh_api_token(env, env.manager_executor_basic)
        except httpx.HTTPError as exc:
            return ActionResult(
                ok=False,
                status="manager_auth_error",
                message=f"Wazuh API authentication failed: {exc}",
            )

        verify = _manager_verify(env)
        url = f"{env.manager_api_url.rstrip('/')}/agents/{agent_id}/restart"
        async with httpx.AsyncClient(verify=verify, timeout=30.0) as client:
            r = await client.put(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
            )
        if r.status_code not in (200, 201):
            return ActionResult(
                ok=False,
                status="manager_error",
                message=f"agent restart failed: HTTP {r.status_code}",
                details={"body": r.text[:500], "agent_id": agent_id},
            )
        return ActionResult(
            ok=True,
            status="restarted",
            message=f"Agent {agent_id} restart requested",
            details={
                "agent_id": agent_id,
                "reason": p.reason,
                "confirmed_by": operator.sub,
            },
        )

    if action_name == "add_agent_to_group":
        p = AddAgentToGroupParams.model_validate(params.model_dump())
        try:
            agent_id = _require_agent_id(p.agent_id)
        except ValueError as exc:
            return ActionResult(ok=False, status="invalid_target", message=str(exc))
        group = (p.group or "").strip()
        if not group:
            return ActionResult(
                ok=False, status="invalid_target", message="group is required"
            )
        try:
            token = await _wazuh_api_token(env, env.manager_executor_basic)
        except httpx.HTTPError as exc:
            return ActionResult(
                ok=False,
                status="manager_auth_error",
                message=f"Wazuh API authentication failed: {exc}",
            )
        verify = _manager_verify(env)
        url = f"{env.manager_api_url.rstrip('/')}/agents/{agent_id}/group/{group}"
        async with httpx.AsyncClient(verify=verify, timeout=30.0) as client:
            r = await client.put(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
            )
        if r.status_code not in (200, 201):
            return ActionResult(
                ok=False,
                status="manager_error",
                message=f"add agent to group failed: HTTP {r.status_code}",
                details={
                    "body": r.text[:500],
                    "agent_id": agent_id,
                    "group": group,
                },
            )
        return ActionResult(
            ok=True,
            status="grouped",
            message=f"Agent {agent_id} added to group {group}",
            details={
                "agent_id": agent_id,
                "group": group,
                "reason": p.reason,
                "confirmed_by": operator.sub,
            },
        )

    if action_name == "suppress_noisy_rule":
        p = SuppressNoisyRuleParams.model_validate(params.model_dump())
        rule_id = (p.rule_id or "").strip()
        if not rule_id.isdigit():
            return ActionResult(
                ok=False,
                status="invalid_target",
                message="rule_id must be numeric",
            )
        try:
            token = await _wazuh_api_token(env, env.manager_executor_basic)
        except httpx.HTTPError as exc:
            return ActionResult(
                ok=False,
                status="manager_auth_error",
                message=f"Wazuh API authentication failed: {exc}",
            )
        # Curated local_rules override: if_sid → level 0 (never free-form rule XML).
        xml = (
            f"<!-- wazuh-ai suppress {rule_id}: {p.reason[:80]} -->\n"
            f'<group name="wazuh_ai_suppress,">\n'
            f'  <rule id="9{rule_id.zfill(5)[-5:]}" level="0">\n'
            f"    <if_sid>{rule_id}</if_sid>\n"
            f"    <description>Wazuh AI suppressed noisy rule {rule_id}</description>\n"
            f"  </rule>\n"
            f"</group>\n"
        )
        verify = _manager_verify(env)
        path = f"etc/rules/local_rules_wazuh_ai_{rule_id}.xml"
        url = f"{env.manager_api_url.rstrip('/')}/manager/files"
        async with httpx.AsyncClient(verify=verify, timeout=30.0) as client:
            r = await client.put(
                url,
                params={"path": path, "overwrite": "true"},
                content=xml.encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/octet-stream",
                },
            )
        if r.status_code not in (200, 201):
            return ActionResult(
                ok=False,
                status="manager_error",
                message=f"suppress rule failed: HTTP {r.status_code}",
                details={"body": r.text[:500], "rule_id": rule_id},
            )
        return ActionResult(
            ok=True,
            status="suppressed",
            message=f"Rule {rule_id} suppressed via {path}",
            details={
                "rule_id": rule_id,
                "path": path,
                "reason": p.reason,
                "confirmed_by": operator.sub,
            },
        )

    return ActionResult(
        ok=False,
        status="unknown_action",
        message=f"unknown manager action {action_name}",
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
        agent_id = _require_agent_id(p.agent_id)
    except ValueError as exc:
        return ActionResult(ok=False, status="invalid_target", message=str(exc))

    try:
        token = await _wazuh_api_token(env, env.ar_executor_basic)
    except httpx.HTTPError as exc:
        return ActionResult(
            ok=False,
            status="manager_auth_error",
            message=f"Wazuh API authentication failed: {exc}",
        )

    url = f"{env.manager_api_url.rstrip('/')}/active-response"
    query = {"agents_list": agent_id}
    payload: dict[str, Any] = {"command": p.command}
    if p.alert_id:
        payload["alert"] = {"data": {"id": p.alert_id}}

    verify = _manager_verify(env)
    async with httpx.AsyncClient(verify=verify, timeout=30.0) as client:
        r = await client.put(
            url,
            params=query,
            json=payload,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
    if r.status_code not in (200, 201):
        return ActionResult(
            ok=False,
            status="ar_error",
            message=f"active response failed: HTTP {r.status_code}",
            details={"body": r.text[:500], "command": p.command, "agent_id": agent_id},
        )
    return ActionResult(
        ok=True,
        status="executed",
        message=f"Active response {p.command} sent to agent {agent_id}",
        details={
            "agent_id": agent_id,
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
