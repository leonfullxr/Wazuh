"""Investigation playbooks (D55) - curated ordered typed tool sequences.

Recognition before reasoning, extended from single-query lane 0 to multi-step
investigations. The sequence (which tools, in what order, how each step's
output seeds the next) is deterministic; only the final synthesis is
generated. Every step passes the normal veracity pipeline.
"""
from __future__ import annotations

import copy
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from pydantic import ValidationError

from . import audit, metrics
from .composite_dispatch import dispatch_composite
from .config import CFG
from .embeddings import embed_corpus, embed_text
from .knowledge import (
    field_dictionary,
    knowledge_search,
    mitre_lookup,
    rule_reference,
)
from .capabilities import describe_capabilities
from .lane0 import extract_slots
from .principal import Principal
from .states_veracity import execute_vulnerabilities_ir
from .tools import REGISTRY
from .veracity import VeracityError, execute_ir

_ALERT_ID = re.compile(
    r"\b(?:alert(?:a)?(?:\s+(?:with\s+)?(?:id|con\s+id))?\s*[:=]?\s*)?"
    r"([A-Za-z0-9][A-Za-z0-9_-]{9,})\b",
    re.I,
)
_AGENT = re.compile(r"\bagent[e]?\s+([\w][\w.-]+)", re.I)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _default_window(hours: int = 24 * 7) -> dict:
    now = _utcnow()
    return {
        "gte": (now - timedelta(hours=hours)).isoformat(),
        "lte": now.isoformat(),
    }


def _dig(obj: Any, path: str) -> Any:
    """Dotted path into dicts/lists. Also supports flat keys like 'data.srcip'."""
    if obj is None:
        return None
    if isinstance(obj, dict) and path in obj:
        return obj[path]
    cur = obj
    parts = path.split(".")
    for i, part in enumerate(parts):
        if cur is None:
            return None
        if isinstance(cur, dict):
            rest = ".".join(parts[i:])
            if rest in cur:
                return cur[rest]
            cur = cur.get(part)
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return cur


@dataclass
class PlaybookStep:
    tool: str
    params: dict = field(default_factory=dict)
    # bind_key -> source: "question.alert_id" | "question.agent" | "slots.time_range"
    # | "prior.<step_idx>.<path>" e.g. prior.0.hits.0.data.srcip
    bind: dict[str, str] = field(default_factory=dict)
    skip_if_unbound: list[str] = field(default_factory=list)


@dataclass
class PlaybookTrigger:
    lang: str
    text: str
    vector: Optional[list[float]] = None


@dataclass
class Playbook:
    id: str
    triggers: list[PlaybookTrigger]
    steps: list[PlaybookStep]


PLAYBOOKS: list[Playbook] = [
    Playbook(
        id="explain-alert",
        triggers=[
            PlaybookTrigger("en", "investigate alert abc123 explain this alert"),
            PlaybookTrigger("en", "investigate alert 4cCrbJ8B_F_lAuh5a9oC"),
            PlaybookTrigger("en", "triage the alert with id nAP8a58B0Y_4M-XCNW9z"),
            PlaybookTrigger("en", "explain the alert with id nAP8a58B0Y_4M-XCNW9z"),
            PlaybookTrigger("es", "investiga la alerta abc123 explica esta alerta"),
            PlaybookTrigger("es", "triar la alerta con id nAP8a58B0Y_4M-XCNW9z"),
            PlaybookTrigger("es", "explica la alerta con id nAP8a58B0Y_4M-XCNW9z"),
        ],
        steps=[
            PlaybookStep(
                "get_alert",
                bind={"alert_id": "question.alert_id"},
                skip_if_unbound=["alert_id"],
            ),
            PlaybookStep(
                "related_alerts",
                params={"size": 15},
                bind={
                    "alert_id": "question.alert_id",
                    "time_range": "slots.time_range",
                },
            ),
            PlaybookStep(
                "search_alerts",
                params={"size": 10},
                bind={
                    "user": "prior.0.hits.0.data.dstuser",
                    "time_range": "slots.time_range",
                },
                skip_if_unbound=["user"],
            ),
            PlaybookStep(
                "mitre_lookup",
                bind={"technique_id": "prior.0.hits.0.rule.mitre.id"},
                skip_if_unbound=["technique_id"],
            ),
        ],
    ),
    Playbook(
        id="brute-force-triage",
        triggers=[
            PlaybookTrigger("en", "investigate this brute force attack triage failed logins"),
            PlaybookTrigger("en", "brute force triage top source ips and timeline"),
            PlaybookTrigger("es", "investiga este ataque de fuerza bruta triaje fallos de login"),
            PlaybookTrigger("es", "triaje de fuerza bruta ips de origen y linea de tiempo"),
        ],
        steps=[
            PlaybookStep(
                "brute_force_summary",
                params={"size": 10, "interval": "1h"},
                bind={"time_range": "slots.time_range"},
            ),
            PlaybookStep(
                "alert_timeline",
                params={"size": 20, "include_histogram": True},
                bind={
                    "source_ip": "prior.0.top_source_ips.0.key",
                    "time_range": "slots.time_range",
                },
                skip_if_unbound=["source_ip"],
            ),
            PlaybookStep(
                "related_alerts",
                params={"size": 15},
                bind={
                    "source_ip": "prior.0.top_source_ips.0.key",
                    "time_range": "slots.time_range",
                },
                skip_if_unbound=["source_ip"],
            ),
        ],
    ),
    Playbook(
        id="agent-triage",
        triggers=[
            PlaybookTrigger("en", "triage agent web-01 investigate agent health posture"),
            PlaybookTrigger("en", "agent triage for host vpn-01 recent alerts and vulns"),
            PlaybookTrigger("es", "triar agente web-01 investiga salud y postura del agente"),
            PlaybookTrigger("es", "triaje del agente vpn-01 alertas recientes y vulnerabilidades"),
        ],
        steps=[
            PlaybookStep(
                "agent_posture",
                params={"severity_gte": 10, "alert_size": 10},
                bind={
                    "agent_name": "question.agent",
                    "time_range": "slots.time_range",
                },
                skip_if_unbound=["agent_name"],
            ),
            PlaybookStep(
                "search_alerts",
                params={"severity_gte": 10, "size": 10},
                bind={
                    "agent_names": "question.agent_list",
                    "time_range": "slots.time_range",
                },
                skip_if_unbound=["agent_names"],
            ),
        ],
    ),
]


def _question_slots(text: str) -> dict[str, Any]:
    slots = extract_slots(text)
    out: dict[str, Any] = {"slots": slots, "question": {}}
    if m := _ALERT_ID.search(text):
        # Prefer an id that is not a common english/spanish word
        candidate = m.group(1)
        if candidate.lower() not in {
            "investigate",
            "alert",
            "alerta",
            "explain",
            "explica",
            "triage",
            "triar",
            "this",
            "esta",
            "with",
            "con",
        }:
            out["question"]["alert_id"] = candidate
    # Explicit "alert <id>" / "alerta <id>" near the end
    m2 = re.search(
        r"(?:alert(?:a)?|id)\s+([A-Za-z0-9][A-Za-z0-9_-]{9,})\s*$",
        text.strip(),
        re.I,
    )
    if m2:
        out["question"]["alert_id"] = m2.group(1)
    if m := _AGENT.search(text):
        out["question"]["agent"] = m.group(1)
        out["question"]["agent_list"] = [m.group(1)]
    if "time_range" not in slots:
        slots["time_range"] = _default_window()
    return out


def _resolve_bind(source: str, ctx: dict[str, Any], prior: list[dict]) -> Any:
    if source.startswith("prior."):
        rest = source[len("prior.") :]
        step_s, _, path = rest.partition(".")
        try:
            idx = int(step_s)
        except ValueError:
            return None
        if idx < 0 or idx >= len(prior):
            return None
        return _dig(prior[idx], path) if path else prior[idx]
    return _dig(ctx, source)


async def invoke_tool(
    name: str, raw_params: dict, principal: Principal
) -> dict[str, Any]:
    """Run one registry tool through the same paths as the agent loop."""
    tool = REGISTRY.get(name)
    if tool is None:
        raise VeracityError(f"unknown tool '{name}'")
    params = tool.schema.model_validate(raw_params)
    if tool.knowledge:
        if name == "mitre_lookup":
            payload = mitre_lookup(params)
            return {
                "name": name,
                "payload": payload,
                "checks": ["knowledge_lookup"],
                "hits": [],
                "aggregations": {},
                "total": 0,
                "kb_ids": (
                    [str(payload["technique_id"]).upper()]
                    if payload.get("found") and payload.get("technique_id")
                    else []
                ),
            }
        if name == "knowledge_search":
            payload = await knowledge_search(params)
            return {
                "name": name,
                "payload": payload,
                "checks": ["knowledge_lookup", "public_kb_retrieval"],
                "hits": [],
                "aggregations": {},
                "total": int(payload.get("total_matching") or 0),
                "kb_ids": [
                    str(h["id"]).upper()
                    for h in (payload.get("hits") or [])
                    if h.get("id")
                ],
            }
        if name == "rule_reference":
            payload = rule_reference(params)
            return {
                "name": name,
                "payload": payload,
                "checks": ["knowledge_lookup", "reference_lookup"],
                "hits": [],
                "aggregations": {},
                "total": 0,
                "kb_ids": (
                    [str(payload["id"]).upper()]
                    if payload.get("found") and payload.get("id")
                    else []
                ),
            }
        if name == "field_dictionary":
            payload = field_dictionary(params)
            return {
                "name": name,
                "payload": payload,
                "checks": ["knowledge_lookup", "reference_lookup"],
                "hits": [],
                "aggregations": {},
                "total": 0,
                "kb_ids": (
                    [str(payload["id"]).upper()]
                    if payload.get("found") and payload.get("id")
                    else []
                ),
            }
        if name == "describe_capabilities":
            payload = describe_capabilities(params, principal=principal)
            return {
                "name": name,
                "payload": payload,
                "checks": ["knowledge_lookup", "capabilities_card"],
                "hits": [],
                "aggregations": {},
                "total": 0,
                "kb_ids": [],
            }
        raise VeracityError(f"unknown knowledge tool '{name}'")
    if tool.composite:
        try:
            payload = await dispatch_composite(name, params, principal)
        except ValueError as exc:
            raise VeracityError(str(exc)) from exc
        hits = payload.get("alerts") or payload.get("high_severity_alerts") or []
        return {
            "name": name,
            "payload": payload,
            "checks": list(payload.get("veracity_checks_passed", []))
            + ["datastore_computed_counts"],
            "hits": hits if isinstance(hits, list) else [],
            "aggregations": {},
            "total": int(payload.get("total_matching") or 0),
            "kb_ids": [],
            # expose composite fields for prior.* binds
            **{
                k: v
                for k, v in payload.items()
                if k
                in (
                    "top_source_ips",
                    "top_target_users",
                    "timeline",
                    "pivot",
                    "last_seen",
                    "open_vuln_count",
                    "high_severity_total",
                    "alert_total",
                )
            },
        }
    if tool.states:
        ir = tool.to_ir(params)
        evidence = await execute_vulnerabilities_ir(ir, principal)
        return {
            "name": name,
            "payload": evidence.to_tool_result(),
            "checks": list(evidence.checks_passed),
            "hits": evidence.hits,
            "aggregations": evidence.aggregations,
            "total": evidence.total,
            "kb_ids": [],
        }
    if tool.environment:
        raise VeracityError(f"playbooks cannot run environment tool '{name}'")
    ir = tool.to_ir(params)
    evidence = await execute_ir(ir, principal)
    return {
        "name": name,
        "payload": evidence.to_tool_result(),
        "checks": list(evidence.checks_passed),
        "hits": evidence.hits,
        "aggregations": evidence.aggregations,
        "total": evidence.total,
        "kb_ids": [],
    }


@dataclass
class PlaybookMatch:
    playbook: Playbook
    score: float


@dataclass
class PlaybookResult:
    playbook_id: str
    score: float
    tools_called: list[str]
    steps: list[dict[str, Any]]
    checks: set[str]
    retrieved_ids: set[str]
    agg_names: set[str]
    agg_values: dict[str, set[int]]
    kb_ids: set[str]
    evidence_blob: list[dict[str, Any]]


_ready = False
_trigger_index: list[tuple[Playbook, PlaybookTrigger]] = []


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    return dot / (na * nb) if na and nb else 0.0


async def _ensure_ready() -> None:
    global _ready, _trigger_index
    if _ready:
        return
    _trigger_index = [(pb, t) for pb in PLAYBOOKS for t in pb.triggers]
    vectors = await embed_corpus([t.text for _, t in _trigger_index])
    for (_, trigger), vec in zip(_trigger_index, vectors):
        trigger.vector = vec
    _ready = True


async def match(text: str, qvec: list[float] | None = None) -> PlaybookMatch | None:
    if not CFG.playbooks_enabled:
        return None
    try:
        await _ensure_ready()
        vec = qvec if qvec is not None else await embed_text(text)
    except Exception as exc:
        audit.emit("playbook_unavailable", reason=str(exc)[:200])
        return None

    best_pb: Playbook | None = None
    best_score = -1.0
    for pb, trigger in _trigger_index:
        score = _cosine(vec, trigger.vector)  # type: ignore[arg-type]
        if score > best_score:
            best_score = score
            best_pb = pb
    threshold = CFG.playbooks_threshold
    if best_pb is None or best_score < threshold:
        audit.emit(
            "playbook_miss",
            best=best_pb.id if best_pb else None,
            score=round(best_score, 3),
        )
        return None
    # Require alert id for explain-alert; agent for agent-triage
    ctx = _question_slots(text)
    if best_pb.id == "explain-alert" and not ctx["question"].get("alert_id"):
        audit.emit("playbook_slot_miss", playbook=best_pb.id, missing="alert_id")
        return None
    if best_pb.id == "agent-triage" and not ctx["question"].get("agent"):
        audit.emit("playbook_slot_miss", playbook=best_pb.id, missing="agent")
        return None
    return PlaybookMatch(playbook=best_pb, score=best_score)


async def run(match_: PlaybookMatch, text: str, principal: Principal) -> PlaybookResult:
    ctx = _question_slots(text)
    prior: list[dict] = []
    tools_called: list[str] = []
    checks: set[str] = set()
    retrieved_ids: set[str] = set()
    agg_names: set[str] = set()
    agg_values: dict[str, set[int]] = {}
    kb_ids: set[str] = set()
    evidence_blob: list[dict] = []

    for step in match_.playbook.steps:
        params = copy.deepcopy(step.params)
        skip = False
        for key, source in step.bind.items():
            val = _resolve_bind(source, ctx, prior)
            if val is None:
                if key in step.skip_if_unbound:
                    skip = True
                    break
                continue
            params[key] = val
        for key in step.skip_if_unbound:
            if key not in params or params[key] in (None, "", []):
                skip = True
                break
        if skip:
            audit.emit(
                "playbook_step_skipped",
                playbook=match_.playbook.id,
                tool=step.tool,
            )
            prior.append({"skipped": True, "tool": step.tool})
            continue

        tools_called.append(step.tool)
        try:
            result = await invoke_tool(step.tool, params, principal)
        except (ValidationError, VeracityError) as exc:
            audit.emit(
                "playbook_step_failed",
                playbook=match_.playbook.id,
                tool=step.tool,
                reason=str(exc)[:300],
            )
            prior.append({"error": str(exc)[:300], "tool": step.tool})
            continue

        checks |= set(result["checks"])
        for h in result.get("hits") or []:
            if isinstance(h, dict) and h.get("_id"):
                retrieved_ids.add(h["_id"])
        payload = result["payload"]
        if isinstance(payload, dict):
            if payload.get("seed_alert_id"):
                retrieved_ids.add(str(payload["seed_alert_id"]))
            total = payload.get("total_matching")
            if isinstance(total, int):
                agg_names.add("total_matching")
                agg_values.setdefault("total_matching", set()).add(total)
                agg_values.setdefault(step.tool, set()).add(total)
            for k, v in (result.get("aggregations") or {}).items():
                agg_names.add(k)
                if isinstance(v, list):
                    for b in v:
                        if isinstance(b, dict) and "count" in b:
                            agg_values.setdefault(k, set()).add(int(b["count"]))
            for k in (
                "delta",
                "alert_total",
                "high_severity_total",
                "open_vuln_count",
                "timeline",
                "top_source_ips",
                "top_target_users",
                "pivot",
            ):
                if k in payload:
                    agg_names.add(k)
            for kid in result.get("kb_ids") or []:
                kb_ids.add(str(kid).upper())
            if step.tool == "mitre_lookup" and payload.get("technique_id"):
                kb_ids.add(str(payload["technique_id"]).upper())
                agg_names.add("mitre_lookup")

        step_record = {
            "tool": step.tool,
            "params": params,
            "payload": payload,
            "hits": result.get("hits") or [],
            "top_source_ips": result.get("top_source_ips"),
            "top_target_users": result.get("top_target_users"),
            "timeline": result.get("timeline"),
            "aggregations": result.get("aggregations") or {},
            "total": result.get("total", 0),
        }
        prior.append(step_record)
        evidence_blob.append(
            {
                "tool": step.tool,
                "result": payload,
            }
        )
        metrics.TOOL_CALLS.labels(tool=step.tool, outcome="ok").inc()

    return PlaybookResult(
        playbook_id=match_.playbook.id,
        score=match_.score,
        tools_called=tools_called,
        steps=prior,
        checks=checks,
        retrieved_ids=retrieved_ids,
        agg_names=agg_names,
        agg_values=agg_values,
        kb_ids=kb_ids,
        evidence_blob=evidence_blob,
    )
