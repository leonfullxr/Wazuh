"""Self-describe / capabilities tool (E11) — live registry, no datastore."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from .config import CFG
from .env_registry import get_env
from .principal import Principal, env_id_for


class DescribeCapabilitiesParams(BaseModel):
    """List what this assistant can do in the current environment."""


def describe_capabilities(
    params: DescribeCapabilitiesParams | None = None,
    *,
    principal: Principal | None = None,
) -> dict[str, Any]:
    """Build a capabilities card from REGISTRY + action tiers (never hardcoded)."""
    from .actions.registry import ACTION_REGISTRY
    from .tools import REGISTRY

    env_id = env_id_for(principal) if principal is not None else CFG.tenant
    try:
        env = get_env(env_id)
        tiers = list(env.actions_tiers)
    except Exception:
        env = None
        tiers = []

    tools = [
        {
            "name": t.name,
            "description": t.description.split(".")[0].strip()[:160],
            "lane": t.lane,
            "kind": (
                "knowledge"
                if t.knowledge
                else "environment"
                if t.environment
                else "composite"
                if t.composite
                else "states"
                if t.states
                else "alerts"
            ),
        }
        for t in REGISTRY.values()
    ]
    actions = []
    if CFG.actions_enabled:
        for a in ACTION_REGISTRY.values():
            if a.tier.value in tiers or not tiers:
                # When tiers empty and actions on, still list but mark gated.
                actions.append(
                    {
                        "name": a.name,
                        "tier": a.tier.value,
                        "risk": a.risk.value,
                        "enabled": a.tier.value in tiers,
                    }
                )

    data_families = ["alerts"]
    if any(t.states for t in REGISTRY.values()):
        data_families.append("vulnerabilities")
    if any(t.environment for t in REGISTRY.values()):
        data_families.append("dashboards_environment")
    if any(t.name == "knowledge_search" for t in REGISTRY.values()):
        data_families.append("public_docs_kb")
    if any(t.name in {"rule_reference", "field_dictionary"} for t in REGISTRY.values()):
        data_families.append("reference_lookups")

    lanes = sorted({t.lane for t in REGISTRY.values()})
    return {
        "env_id": env_id,
        "lanes": lanes,
        "lane0_enabled": CFG.lane0_enabled,
        "lane2_enabled": CFG.lane2_enabled,
        "actions_enabled": CFG.actions_enabled,
        "action_tiers_enabled": tiers,
        "tools": tools,
        "actions": actions,
        "data_families": data_families,
        "docs_kb_enabled": CFG.docs_kb_enabled,
        "note": "Built from the live tool/action registry for this environment.",
    }
