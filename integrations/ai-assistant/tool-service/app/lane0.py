"""Lane 0 - the semantic fast path (D40, README s3.5).

The observation: a large share of SOC questions are recognitions, not
reasoning. "Top 5 noisiest agents" has one right query, and matching the
question to it needs an embedding model (milliseconds, CPU), not a reasoning
model (seconds and tokens). Lane 0 embeds the incoming question, matches it
against a curated bilingual corpus of utterance -> typed-template pairs,
fills the parameter slots deterministically (time window, top-N, agent, rule,
severity), and executes the resulting Query IR through the SAME veracity
pipeline as every other lane. No model ever sees the question or the data,
which makes lane 0 the most verifiable lane, not a shortcut: the answer is
rendered locally from datastore-computed results (the D26 local-render
posture) and labeled "no model involved".

Confidence gating: a match below the cosine threshold, or a template whose
required slots cannot be filled from the text, is a MISS, and the turn
escalates to the normal model loop (lane 1/2). Escalation is the safe
default; lane 0 only answers when it is sure.

The exemplar corpus below is the seed. It is deliberately the same shape as
the golden set: curated NL -> query pairs. One artifact, two jobs.
"""
from __future__ import annotations

import copy
import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from . import audit, metrics
from .auth_groups import AUTH_FAILURE_GROUPS
from .config import CFG
from .embeddings import embed_corpus, embed_text

# ---------------------------------------------------------------------------
# Exemplar corpus (bilingual, D12). `params` is the template; `inject` maps
# extracted slots onto template keys; `require` lists slots that MUST be
# extracted from the text or the match is a miss.
# ---------------------------------------------------------------------------
@dataclass
class Exemplar:
    id: str
    lang: str
    text: str
    tool: str
    params: dict
    inject: dict[str, str] = field(default_factory=dict)
    require: list[str] = field(default_factory=list)
    vector: Optional[list[float]] = None


def _noisy_agents_ir(size: int = 5) -> dict:
    return {
        "filters": [],
        "aggregation": {"kind": "terms", "field": "agent.name", "size": size},
        "limit": 0,
    }


def _auth_fail_count_ir() -> dict:
    return {
        "filters": [
            {
                "field": "rule.groups",
                "op": "in",
                "value": list(AUTH_FAILURE_GROUPS),
            }
        ],
        "aggregation": {"kind": "count"},
        "limit": 0,
    }


def _top_srcips_ir(size: int = 10) -> dict:
    return {
        "filters": [],
        "aggregation": {"kind": "terms", "field": "data.srcip", "size": size},
        "limit": 0,
    }


def _high_sev_by_agent_ir(size: int = 10) -> dict:
    return {
        "filters": [{"field": "rule.level", "op": "gte", "value": 10}],
        "aggregation": {"kind": "terms", "field": "agent.name", "size": size},
        "limit": 0,
    }


EXEMPLARS: list[Exemplar] = [
    # noisiest agents (needs a template lane 1 has no tool for - run_query_ir)
    Exemplar("noisy-agents", "en", "what are the top 5 noisiest agents",
             "run_query_ir", _noisy_agents_ir(),
             inject={"time_range": "time_range", "size": "aggregation.size"}),
    Exemplar("noisy-agents", "es", "cuales son los 5 agentes mas ruidosos",
             "run_query_ir", _noisy_agents_ir(),
             inject={"time_range": "time_range", "size": "aggregation.size"}),
    # top rules
    Exemplar("top-rules", "en", "what are the most frequent rules this week",
             "top_rules", {}, inject={"time_range": "time_range", "size": "size"}),
    Exemplar("top-rules", "es", "cuales son las reglas mas frecuentes esta semana",
             "top_rules", {}, inject={"time_range": "time_range", "size": "size"}),
    # total alert count
    Exemplar("count-alerts", "en", "how many alerts did we get in the last 24 hours",
             "count_alerts", {}, inject={"time_range": "time_range", "severity": "severity_gte"}),
    Exemplar("count-alerts", "es", "cuantas alertas hemos tenido en las ultimas 24 horas",
             "count_alerts", {}, inject={"time_range": "time_range", "severity": "severity_gte"}),
    # auth failure count
    Exemplar("auth-fail-count", "en", "how many authentication failures in the last 24 hours",
             "run_query_ir", _auth_fail_count_ir(), inject={"time_range": "time_range"}),
    Exemplar("auth-fail-count", "es", "cuantos fallos de autenticacion en las ultimas 24 horas",
             "run_query_ir", _auth_fail_count_ir(), inject={"time_range": "time_range"}),
    # brute-force targets by user
    Exemplar("auth-fail-users", "en", "which users have the most failed logins",
             "auth_failures", {"group_by": "data.dstuser"},
             inject={"time_range": "time_range", "size": "size"}),
    Exemplar("auth-fail-users", "es", "que usuarios acumulan mas fallos de login",
             "auth_failures", {"group_by": "data.dstuser"},
             inject={"time_range": "time_range", "size": "size"}),
    # brute-force sources by ip
    Exemplar("auth-fail-ips", "en", "which source ips have the most failed logins",
             "auth_failures", {"group_by": "data.srcip"},
             inject={"time_range": "time_range", "size": "size"}),
    Exemplar("auth-fail-ips", "es", "que ips de origen tienen mas fallos de autenticacion",
             "auth_failures", {"group_by": "data.srcip"},
             inject={"time_range": "time_range", "size": "size"}),
    # trend over time
    Exemplar("alert-trend", "en", "show the alert volume trend over the last week",
             "alert_histogram", {"interval": "1d"}, inject={"time_range": "time_range"}),
    Exemplar("alert-trend", "es", "muestra la tendencia de alertas de la ultima semana",
             "alert_histogram", {"interval": "1d"}, inject={"time_range": "time_range"}),
    # high severity count
    Exemplar("high-sev-count", "en", "how many high severity alerts in the last 7 days",
             "count_alerts", {"severity_gte": 10},
             inject={"time_range": "time_range", "severity": "severity_gte"}),
    Exemplar("high-sev-count", "es", "cuantas alertas de severidad alta en los ultimos 7 dias",
             "count_alerts", {"severity_gte": 10},
             inject={"time_range": "time_range", "severity": "severity_gte"}),
    # agents reporting in a window (C1 list_agents)
    Exemplar("list-agents", "en", "which agents are reporting alerts in the last 7 days",
             "list_agents", {}, inject={"time_range": "time_range"}),
    Exemplar("list-agents", "es", "que agentes estan reportando alertas en los ultimos 7 dias",
             "list_agents", {}, inject={"time_range": "time_range"}),
    # latest alerts for one agent (agent slot REQUIRED)
    Exemplar("agent-alerts", "en", "show me the latest alerts from the agent web-01",
             "search_alerts", {}, inject={"time_range": "time_range", "agent": "agent_names",
                                          "size": "size"}, require=["agent"]),
    Exemplar("agent-alerts", "es", "muestrame las ultimas alertas del agente web-01",
             "search_alerts", {}, inject={"time_range": "time_range", "agent": "agent_names",
                                          "size": "size"}, require=["agent"]),
    # alerts for one rule (rule slot REQUIRED)
    Exemplar("rule-alerts", "en", "show me the alerts for rule 5710",
             "search_alerts", {}, inject={"time_range": "time_range", "rule": "rule_ids",
                                          "size": "size"}, require=["rule"]),
    Exemplar("rule-alerts", "es", "muestrame las alertas de la regla 5710",
             "search_alerts", {}, inject={"time_range": "time_range", "rule": "rule_ids",
                                          "size": "size"}, require=["rule"]),
    # top source IPs
    Exemplar("top-srcips", "en", "what are the top source ips this week",
             "run_query_ir", _top_srcips_ir(),
             inject={"time_range": "time_range", "size": "aggregation.size"}),
    Exemplar("top-srcips", "es", "cuales son las ips de origen mas frecuentes esta semana",
             "run_query_ir", _top_srcips_ir(),
             inject={"time_range": "time_range", "size": "aggregation.size"}),
    # high severity by agent
    Exemplar("high-sev-by-agent", "en", "which agents have the most high severity alerts",
             "run_query_ir", _high_sev_by_agent_ir(),
             inject={"time_range": "time_range", "size": "aggregation.size"}),
    Exemplar("high-sev-by-agent", "es", "que agentes tienen mas alertas de severidad alta",
             "run_query_ir", _high_sev_by_agent_ir(),
             inject={"time_range": "time_range", "size": "aggregation.size"}),
    # most frequent MITRE technique
    Exemplar("top-mitre", "en", "what is the most frequent mitre technique this week",
             "mitre_coverage", {}, inject={"time_range": "time_range", "size": "size"}),
    Exemplar("top-mitre", "es", "cual es la tecnica mitre mas frecuente esta semana",
             "mitre_coverage", {}, inject={"time_range": "time_range", "size": "size"}),
    # vulnerability count
    Exemplar("vuln-count", "en", "how many vulnerabilities were detected in the last 30 days",
             "count_vulnerabilities", {}, inject={"time_range": "time_range"}),
    Exemplar("vuln-count", "es", "cuantas vulnerabilidades se detectaron en los ultimos 30 dias",
             "count_vulnerabilities", {}, inject={"time_range": "time_range"}),
    # agents with last-seen (stopped reporting / fleet posture approximation)
    Exemplar("agents-last-seen", "en", "which agents stopped reporting or have stale last seen",
             "list_agents", {}, inject={"time_range": "time_range", "size": "size"}),
    Exemplar("agents-last-seen", "es", "que agentes dejaron de reportar o tienen last seen antiguo",
             "list_agents", {}, inject={"time_range": "time_range", "size": "size"}),
    # new / newly active agents in window
    Exemplar("new-agents", "en", "which new agents reported alerts this week",
             "list_agents", {}, inject={"time_range": "time_range", "size": "size"}),
    Exemplar("new-agents", "es", "que agentes nuevos reportaron alertas esta semana",
             "list_agents", {}, inject={"time_range": "time_range", "size": "size"}),
]

# ---------------------------------------------------------------------------
# Slot extraction - deterministic, bilingual, no model
# ---------------------------------------------------------------------------
_HOURS = re.compile(r"(?:last|past|ultim[ao]s?)\s+(\d{1,3})\s+(?:hours?|horas?)", re.I)
_DAYS = re.compile(r"(?:last|past|ultim[ao]s?)\s+(\d{1,3})\s+(?:days?|dias?)", re.I)
_WEEK = re.compile(r"\b(?:this week|last week|esta semana|ultima semana|semana)\b", re.I)
_TODAY = re.compile(r"\b(?:today|hoy)\b", re.I)
_TOPN = re.compile(r"\b(?:top|los|las)\s+(\d{1,2})\b", re.I)
_AGENT = re.compile(r"\bagent[e]?\s+([\w][\w.-]+)", re.I)
_RULE = re.compile(r"\b(?:rule|regla)\s+(\d{2,7})\b", re.I)
_SEV = re.compile(r"\b(?:level|nivel|severity|severidad)\s*(?:>=|above|over|mayor(?:\s+que)?)?\s*(\d{1,2})\b", re.I)


def extract_slots(text: str) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    hours = 24
    if m := _HOURS.search(text):
        hours = int(m.group(1))
    elif m := _DAYS.search(text):
        hours = int(m.group(1)) * 24
    elif _WEEK.search(text):
        hours = 7 * 24
    elif _TODAY.search(text):
        hours = 24
    slots: dict[str, Any] = {
        "time_range": {
            "gte": (now - timedelta(hours=min(hours, 90 * 24))).isoformat(),
            "lte": now.isoformat(),
        }
    }
    if m := _TOPN.search(text):
        slots["size"] = max(1, min(int(m.group(1)), 50))
    if m := _AGENT.search(text):
        slots["agent"] = [m.group(1)]
    if m := _RULE.search(text):
        slots["rule"] = [m.group(1)]
    if m := _SEV.search(text):
        slots["severity"] = min(int(m.group(1)), 15)
    return slots


def _set_path(params: dict, dotted: str, value: Any) -> None:
    node = params
    parts = dotted.split(".")
    for key in parts[:-1]:
        node = node.setdefault(key, {})
    node[parts[-1]] = value


# ---------------------------------------------------------------------------
# Embedding matcher (pure-python cosine: ~20 exemplars, trivial)
# ---------------------------------------------------------------------------
_ready = False


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    return dot / (na * nb) if na and nb else 0.0


async def _ensure_ready() -> None:
    global _ready
    if _ready:
        return
    vectors = await embed_corpus([e.text for e in EXEMPLARS])
    for exemplar, vec in zip(EXEMPLARS, vectors):
        exemplar.vector = vec
    _ready = True


@dataclass
class Lane0Match:
    exemplar: Exemplar
    score: float
    params: dict


@dataclass
class Lane0NearMiss:
    """A close miss: inject the exemplar as a transient user hint in the model loop."""

    exemplar: Exemplar
    score: float
    hint: str


@dataclass
class Lane0Analysis:
    qvec: list[float]
    match: Lane0Match | None
    near_miss: Lane0NearMiss | None


def _best_exemplar(qvec: list[float]) -> tuple[Exemplar | None, float]:
    best, best_score = None, -1.0
    for exemplar in EXEMPLARS:
        score = _cosine(qvec, exemplar.vector)
        if score > best_score:
            best, best_score = exemplar, score
    return best, best_score


def _build_match(best: Exemplar, best_score: float, text: str) -> Lane0Match | None:
    slots = extract_slots(text)
    for required in best.require:
        if required not in slots:
            audit.emit("lane0_slot_miss", template=best.id, missing=required,
                       score=round(best_score, 3))
            metrics.LANE0.labels(result="slot_miss").inc()
            return None
    params = copy.deepcopy(best.params)
    for slot, path in best.inject.items():
        if slot in slots:
            _set_path(params, path, slots[slot])
    return Lane0Match(exemplar=best, score=best_score, params=params)


def _build_near_miss(best: Exemplar, best_score: float) -> Lane0NearMiss | None:
    if (
        best_score >= CFG.lane0_threshold
        or best_score < CFG.lane0_near_miss_floor
    ):
        return None
    hint = (
        f"Near-match template {best.id!r} (similarity {best_score:.2f}): "
        f"for questions like {best.text!r}, prefer tool {best.tool!r} with "
        f"params shaped like {json.dumps(best.params, default=str)}."
    )
    audit.emit("lane0_near_miss", template=best.id, score=round(best_score, 3))
    return Lane0NearMiss(exemplar=best, score=best_score, hint=hint)


async def analyze(text: str) -> Lane0Analysis | None:
    """One embed per question: match, near-miss, and scope share the vector."""
    if not CFG.lane0_enabled:
        return None
    try:
        await _ensure_ready()
        qvec = await embed_text(text)
    except Exception as exc:
        audit.emit("lane0_unavailable", reason=str(exc)[:200])
        metrics.LANE0.labels(result="unavailable").inc()
        return None

    best, best_score = _best_exemplar(qvec)
    match = None
    near_miss = None
    if best is not None and best_score >= CFG.lane0_threshold:
        match = _build_match(best, best_score, text)
        if match is None:
            audit.emit("lane0_miss", best=best.id, score=round(best_score, 3))
            metrics.LANE0.labels(result="miss").inc()
    else:
        audit.emit("lane0_miss", best=best.id if best else None, score=round(best_score, 3))
        metrics.LANE0.labels(result="miss").inc()
        if best is not None:
            near_miss = _build_near_miss(best, best_score)
    return Lane0Analysis(qvec=qvec, match=match, near_miss=near_miss)


async def match(text: str) -> Optional[Lane0Match]:
    analysis = await analyze(text)
    return analysis.match if analysis else None


# ---------------------------------------------------------------------------
# Local rendering (D26 local-render): the answer is written by code from
# datastore-computed results. No model saw the question or the data.
# ---------------------------------------------------------------------------
_STR = {
    "en": {
        "count": "{total} matching alerts between {gte} and {lte}.",
        "terms": "Top {n} by count between {gte} and {lte}:",
        "hist": "Alert volume between {gte} and {lte}:",
        "search": "{total} matching alerts between {gte} and {lte}. Latest {n}:",
        "none": "No matching alerts between {gte} and {lte}.",
    },
    "es": {
        "count": "{total} alertas coincidentes entre {gte} y {lte}.",
        "terms": "Top {n} por numero de alertas entre {gte} y {lte}:",
        "hist": "Volumen de alertas entre {gte} y {lte}:",
        "search": "{total} alertas coincidentes entre {gte} y {lte}. Ultimas {n}:",
        "none": "Sin alertas coincidentes entre {gte} y {lte}.",
    },
}


def render_local(match_: Lane0Match, ir, evidence, question: str = "") -> str:
    from .language import detect

    lang_key = detect(question or match_.exemplar.text)
    lang = _STR.get(lang_key, _STR["en"])
    gte, lte = ir.time_range.iso()
    gte, lte = gte[:16].replace("T", " "), lte[:16].replace("T", " ")

    if evidence.total == 0 and not evidence.aggregations:
        return lang["none"].format(gte=gte, lte=lte)

    buckets = evidence.aggregations.get("by")
    if buckets is not None:
        lines = [lang["terms"].format(n=len(buckets), gte=gte, lte=lte)]
        for i, b in enumerate(buckets):
            line = f"{i + 1}. {b['key']} ({b['count']})"
            if b.get("last_seen"):
                line += f" · last seen {b['last_seen']}"
            lines.append(line)
        return "\n".join(lines)

    over_time = evidence.aggregations.get("over_time")
    if over_time is not None:
        lines = [lang["hist"].format(gte=gte, lte=lte)]
        lines += [f"- {b['key']}: {b['count']}" for b in over_time]
        return "\n".join(lines)

    if evidence.hits:
        lines = [lang["search"].format(total=evidence.total, gte=gte, lte=lte,
                                       n=len(evidence.hits))]
        lines += [
            f"- {h['timestamp']} · {h['rule.description']} ({h['agent.name']}) [alert:{h['_id']}]"
            for h in evidence.hits
        ]
        return "\n".join(lines)

    return lang["count"].format(total=evidence.total, gte=gte, lte=lte)
