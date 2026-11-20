"""Validated, opt-in per-cluster authorization policy."""

import json
import math
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


@dataclass(frozen=True)
class Rule:
    kind: str
    identity: str
    issuer: Optional[str]
    cluster: str
    allow: frozenset[str]
    deny: frozenset[str]


@dataclass(frozen=True)
class ClusterPolicy:
    rules: tuple[Rule, ...]


def load_policy(registry) -> Optional[ClusterPolicy]:
    path = os.environ.get("WAZUH_CLUSTER_POLICY_FILE")
    if path is None:
        return None
    if not path.strip():
        raise ValueError("WAZUH_CLUSTER_POLICY_FILE must name a policy file")
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError) as exc:
        raise ValueError("Cannot read cluster policy") from exc
    if not isinstance(data, dict) or set(data) != {"rules"} or not isinstance(data["rules"], list) or not data["rules"]:
        raise ValueError("Cluster policy requires a nonempty rules list")
    for client in registry._clients.values():
        indexer = getattr(client, "_indexer_client", None)
        if indexer and getattr(indexer, "ccs_prefix", ""):
            raise ValueError("Cluster policy cannot be used with cross-cluster search")
    rules = []
    for item in data["rules"]:
        if not isinstance(item, dict) or set(item) - {"identity", "cluster", "allow", "deny"}:
            raise ValueError("Invalid cluster policy rule")
        identity, cluster = item.get("identity"), item.get("cluster")
        if not isinstance(identity, dict) or set(identity) - {"type", "id", "issuer"}:
            raise ValueError("Invalid cluster policy identity")
        kind, name, issuer = identity.get("type"), identity.get("id"), identity.get("issuer")
        if kind not in {"api_key", "idp_group"} or not isinstance(name, str) or not name.strip():
            raise ValueError("Invalid cluster policy identity")
        if kind == "idp_group":
            if not isinstance(issuer, str) or not issuer.strip():
                raise ValueError("IdP group rules require an issuer")
        elif issuer is not None:
            raise ValueError("API key rules cannot have an issuer")
        if not isinstance(cluster, str) or cluster not in registry.cluster_ids:
            raise ValueError("Invalid cluster policy cluster")
        permissions = []
        for field in ("allow", "deny"):
            value = item.get(field, [])
            if not isinstance(value, list) or any(
                not isinstance(v, str) or v not in {"wazuh:read", "wazuh:write"} for v in value
            ):
                raise ValueError("Invalid cluster policy operation")
            permissions.append(frozenset(value))
        if not any(permissions):
            raise ValueError("Cluster policy rule has no operations")
        rules.append(Rule(kind, name, issuer, cluster, *permissions))
    return ClusterPolicy(tuple(rules))


def authorize_cluster(auth_token: Any, cluster_id: Optional[str], required_scope: str) -> bool:
    from . import state

    policy = state.cluster_policy
    if policy is None:
        return True
    if not auth_token or not auth_token.has_scope(required_scope):
        return False
    cluster = cluster_id or state.cluster_registry.default_id
    if cluster not in state.cluster_registry.cluster_ids:
        return False
    owner = getattr(auth_token, "owner", None) or {}
    metadata = getattr(auth_token, "metadata", None) or {}
    kind, subject = owner.get("family"), owner.get("subject")
    is_key = kind in {"api_key", "bearer_jwt"} or (kind == "oauth" and owner.get("subject_kind") == "api_key")
    groups_at = metadata.get("groups_at")
    fresh = (
        isinstance(groups_at, (int, float))
        and not isinstance(groups_at, bool)
        and math.isfinite(groups_at)
        and 0 <= time.time() - groups_at <= 900
    )
    groups = metadata.get("groups", ()) if fresh and owner.get("subject_kind") == "idp_user" else ()
    if not isinstance(groups, (tuple, list)):
        groups = ()
    allowed, denied = set(), set()
    for rule in policy.rules:
        if rule.cluster != cluster:
            continue
        matches_key = is_key and rule.kind == "api_key" and rule.identity == subject
        matches_group = (
            rule.kind == "idp_group" and rule.issuer == owner.get("identity_issuer") and rule.identity in groups
        )
        if matches_key or matches_group:
            allowed.update(rule.allow)
            denied.update(rule.deny)
    return required_scope in allowed and required_scope not in denied


INDEXER_TOOLS = frozenset(
    {
        "get_wazuh_alerts",
        "get_wazuh_alert_summary",
        "analyze_alert_patterns",
        "get_alerts_aggregated",
        "search_security_events",
        "get_wazuh_vulnerabilities",
        "get_wazuh_critical_vulnerabilities",
        "get_wazuh_vulnerability_summary",
        "analyze_security_threat",
        "check_ioc_reputation",
        "get_top_security_threats",
        "get_iso27001_alerts",
        "wazuh_check_blocked_ip",
        "investigate_agent_timeline",
        "get_investigation_evidence",
    }
)


def supports_tool(cluster_id: str, tool_name: str) -> bool:
    from . import state

    if not state.config.TOOL_PROFILE or (
        tool_name not in INDEXER_TOOLS and not tool_name.startswith("saved_investigation_")
    ):
        return True
    client = state.cluster_registry._clients.get(cluster_id)
    return bool(client and getattr(client, "_indexer_client", None))
