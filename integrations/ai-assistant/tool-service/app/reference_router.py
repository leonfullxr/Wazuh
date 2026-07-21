"""Deterministic reference/capability recognizer (Round 8 F6/F7).

Sibling to lane 0: recognitions that invoke knowledge/composite tools and
render locally with no model. Not alerts-IR — do not force through execute_ir
or lane0.render_local. Fail open (None) when no pattern matches.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Optional

from .brute_force import BruteForceSummaryParams
from .capabilities import DescribeCapabilitiesParams, describe_capabilities
from .composite_dispatch import dispatch_composite
from .knowledge import (
    FieldDictionaryParams,
    RuleReferenceParams,
    field_dictionary,
    rule_reference,
)
from .lane0 import extract_slots
from .language import detect
from .principal import Principal

# ---------------------------------------------------------------------------
# Patterns — narrow shapes only; leave open how-to / remediate to knowledge_search
# ---------------------------------------------------------------------------
_HOWTO = re.compile(
    r"\b(?:how do i|how to|c[oó]mo (?:configuro|configurar|remedio)|"
    r"configure|remediat|documentation)\b",
    re.I,
)
_FORCE_KB = re.compile(r"\b(?:use\s+)?knowledge_search\b", re.I)

_RULE_ID = re.compile(
    r"(?:what does|qu[eé] significa|explain|describe).{0,40}?\b(?:rule|regla)\s+(\d{2,7})\b"
    r"|\b(?:rule|regla)\s+(\d{2,7})\b.{0,40}?(?:mean|significa|significado|meaning)",
    re.I,
)
_RULE_GROUP = re.compile(
    r"(?:what does|qu[eé] significa).{0,20}?(?:the\s+)?([a-z][a-z0-9_]{2,40})\s+"
    r"(?:rule\s+)?group\b"
    r"|\b(?:rule\s+)?group\s+([a-z][a-z0-9_]{2,40})\b.{0,30}?(?:mean|significa)",
    re.I,
)
_FIELD_DOTTED = re.compile(
    r"(?:what does|qu[eé] significa).{0,20}?(?:the\s+)?([a-z][\w.]{1,60})\s+field\b"
    r"|\b(?:field|campo)\s+([a-z][\w.]{1,60})\b.{0,30}?(?:mean|significa)",
    re.I,
)
_FIELD_ALIAS = re.compile(
    r"(?:what does|qu[eé] significa).{0,20}?(?:the\s+)?"
    r"(severity|level|src_?ip|source_?ip|dst_?user|user|country|mitre)\b"
    r".{0,20}?(?:mean|significa|mean\?|$)",
    re.I,
)
_CAPS = re.compile(
    r"(?:what can you do|qu[eé] puedes hacer|what can i ask|"
    r"list your capabilities|describe_?capabilities|your capabilities|"
    r"\bcapabilities\b)",
    re.I,
)
_BRUTE = re.compile(
    r"(?:brute[\s-]?force|fuerza bruta).{0,40}?(?:summar(?:y|ize)|resumen|triaje|"
    r"top source|top ips?|targeted users?)"
    r"|(?:summar(?:y|ize)|give me|muestra(?:me)?).{0,40}?(?:brute[\s-]?force|fuerza bruta)",
    re.I,
)

# Catalog-backed names (loaded once from the same JSON the tools use)
def _group_names() -> set[str]:
    from .knowledge import _RULE_REF

    return {str(k).casefold() for k in (_RULE_REF.get("groups") or {})}


def _field_names_and_aliases() -> set[str]:
    from .knowledge import _FIELD_DICT

    names = {str(k).casefold() for k in (_FIELD_DICT.get("fields") or {})}
    names |= {str(k).casefold() for k in (_FIELD_DICT.get("aliases") or {})}
    return names


@dataclass
class ReferenceMatch:
    route: str  # rule_reference | field_dictionary | describe_capabilities | brute_force_summary
    tool: str
    params: dict[str, Any]
    reason: str


def match(text: str) -> Optional[ReferenceMatch]:
    """Return a deterministic route, or None to fail open to the model loop."""
    q = (text or "").strip()
    if len(q) < 8:
        return None
    if _HOWTO.search(q) or _FORCE_KB.search(q):
        return None

    if _CAPS.search(q) and not re.search(r"\b(?:rule|field|alert|agent)\b", q, re.I):
        return ReferenceMatch(
            route="describe_capabilities",
            tool="describe_capabilities",
            params={},
            reason="capabilities question",
        )

    if _BRUTE.search(q):
        slots = extract_slots(q)
        return ReferenceMatch(
            route="brute_force_summary",
            tool="brute_force_summary",
            params={
                "time_range": slots.get("time_range"),
                "size": slots.get("size", 10),
                "interval": "1h",
            },
            reason="brute-force summary recognition",
        )

    if m := _RULE_ID.search(q):
        rid = m.group(1) or m.group(2)
        return ReferenceMatch(
            route="rule_reference",
            tool="rule_reference",
            params={"rule_id": rid},
            reason=f"rule id {rid}",
        )

    if m := _RULE_GROUP.search(q):
        g = (m.group(1) or m.group(2) or "").strip()
        if g.casefold() in _group_names() or "group" in q.casefold():
            return ReferenceMatch(
                route="rule_reference",
                tool="rule_reference",
                params={"rule_group": g},
                reason=f"rule group {g}",
            )

    # Known group mentioned with "mean" even without the word "group"
    q_cf = q.casefold()
    if "mean" in q_cf or "significa" in q_cf:
        for g in sorted(_group_names(), key=len, reverse=True):
            if g in q_cf and "rule" in q_cf:
                return ReferenceMatch(
                    route="rule_reference",
                    tool="rule_reference",
                    params={"rule_group": g},
                    reason=f"rule group {g}",
                )

    if m := _FIELD_DOTTED.search(q):
        field = (m.group(1) or m.group(2) or "").strip()
        return ReferenceMatch(
            route="field_dictionary",
            tool="field_dictionary",
            params={"field": field},
            reason=f"field {field}",
        )

    if m := _FIELD_ALIAS.search(q):
        alias = m.group(1).strip()
        return ReferenceMatch(
            route="field_dictionary",
            tool="field_dictionary",
            params={"field": alias},
            reason=f"field alias {alias}",
        )

    # Dotted field name present + meaning question
    if "mean" in q_cf or "significa" in q_cf:
        for name in sorted(_field_names_and_aliases(), key=len, reverse=True):
            if "." in name and name in q_cf:
                return ReferenceMatch(
                    route="field_dictionary",
                    tool="field_dictionary",
                    params={"field": name},
                    reason=f"field {name}",
                )

    return None


def _render_rule(payload: dict[str, Any], lang: str) -> str:
    if not payload.get("found"):
        err = payload.get("error") or "not found"
        if lang == "es":
            return f"No hay entrada local para esa referencia: {err}."
        return f"No local reference entry for that lookup: {err}."
    cite = payload.get("cite_as") or f"[kb:{payload.get('id')}]"
    kind = payload.get("kind")
    if kind == "rule":
        rid = payload.get("rule_id")
        desc = payload.get("description") or ""
        meaning = payload.get("meaning") or ""
        level = payload.get("level")
        groups = ", ".join(payload.get("groups") or [])
        mitre = ", ".join(payload.get("mitre") or []) or "n/a"
        if lang == "es":
            return (
                f"Regla {rid}: {desc} (nivel {level}). {meaning} "
                f"Grupos: {groups}. MITRE: {mitre}. {cite}"
            )
        return (
            f"Rule {rid}: {desc} (level {level}). {meaning} "
            f"Groups: {groups}. MITRE: {mitre}. {cite}"
        )
    if kind == "group":
        g = payload.get("rule_group")
        meaning = payload.get("meaning") or ""
        typical = ", ".join(payload.get("typical_rules") or [])
        if lang == "es":
            return (
                f"Grupo de reglas `{g}`: {meaning} "
                f"Reglas t\u00edpicas: {typical}. {cite}"
            )
        return (
            f"Rule group `{g}`: {meaning} Typical rules: {typical}. {cite}"
        )
    name = payload.get("decoder_name")
    meaning = payload.get("meaning") or ""
    return f"Decoder `{name}`: {meaning} {cite}"


def _render_field(payload: dict[str, Any], lang: str) -> str:
    if not payload.get("found"):
        err = payload.get("error") or "not found"
        if lang == "es":
            return f"Campo no encontrado en el diccionario local: {err}."
        return f"Field not in the local dictionary: {err}."
    cite = payload.get("cite_as") or f"[kb:{payload.get('id')}]"
    field = payload.get("field")
    meaning = payload.get("meaning") or ""
    ftype = payload.get("type") or ""
    if lang == "es":
        return f"Campo `{field}` ({ftype}): {meaning} {cite}"
    return f"Field `{field}` ({ftype}): {meaning} {cite}"


def _render_capabilities(payload: dict[str, Any], lang: str) -> str:
    tools = payload.get("tools") or []
    names = [t.get("name") for t in tools if t.get("name")]
    lanes = payload.get("lanes") or []
    families = payload.get("data_families") or []
    actions = payload.get("actions") or []
    action_names = [
        a.get("name") for a in actions if a.get("enabled") and a.get("name")
    ]
    if lang == "es":
        lines = [
            "Capacidades en este entorno (herramientas tipadas, sin inventar consultas):",
            f"- Lanes disponibles: {', '.join(str(x) for x in lanes) or 'n/a'}",
            f"- Familias de datos: {', '.join(families) or 'n/a'}",
            f"- Herramientas ({len(names)}): {', '.join(names[:18])}"
            + ("…" if len(names) > 18 else ""),
        ]
        if action_names:
            lines.append(f"- Acciones habilitadas: {', '.join(action_names)}")
        lines.append(
            "Pregunta por conteos, fallos de auth, vulnerabilidades, docs, "
            "o 'qué significa la regla N / el campo X'."
        )
        return "\n".join(lines)
    lines = [
        "Capabilities for this environment (typed tools; I never invent queries):",
        f"- Available lanes: {', '.join(str(x) for x in lanes) or 'n/a'}",
        f"- Data families: {', '.join(families) or 'n/a'}",
        f"- Tools ({len(names)}): {', '.join(names[:18])}"
        + ("…" if len(names) > 18 else ""),
    ]
    if action_names:
        lines.append(f"- Enabled actions: {', '.join(action_names)}")
    lines.append(
        "Ask about counts, auth failures, vulnerabilities, docs, "
        "or 'what does rule N / field X mean'."
    )
    return "\n".join(lines)


def _render_brute(payload: dict[str, Any], lang: str) -> str:
    total = int(payload.get("total_matching") or 0)
    window = payload.get("executed_window") or {}
    gte = str(window.get("gte", ""))[:16].replace("T", " ")
    lte = str(window.get("lte", ""))[:16].replace("T", " ")
    ips = payload.get("top_source_ips") or []
    users = payload.get("top_target_users") or []
    if lang == "es":
        lines = [
            f"Resumen de fuerza bruta: {total} alertas coincidentes "
            f"[agg:total_matching] ({gte} → {lte})."
        ]
    else:
        lines = [
            f"Brute-force summary: {total} matching alerts "
            f"[agg:total_matching] ({gte} → {lte})."
        ]
    if ips:
        lines.append("Top source IPs [agg:top_source_ips]:")
        for b in ips[:8]:
            lines.append(f"- {b.get('key')}: {b.get('count', 0)}")
    if users:
        lines.append("Top targeted users [agg:top_target_users]:")
        for b in users[:8]:
            lines.append(f"- {b.get('key')}: {b.get('count', 0)}")
    return "\n".join(lines)


@dataclass
class ReferenceResult:
    answer: str
    tool: str
    route: str
    checks: list[str]
    label: str


async def execute(
    hit: ReferenceMatch, principal: Principal, question: str
) -> ReferenceResult:
    """Invoke the exact tool and render locally — no model."""
    lang = detect(question)

    if hit.tool == "rule_reference":
        payload = rule_reference(RuleReferenceParams(**hit.params))
        answer = _render_rule(payload, lang)
        checks = ["knowledge_lookup", "reference_lookup", "reference_router"]
    elif hit.tool == "field_dictionary":
        payload = field_dictionary(FieldDictionaryParams(**hit.params))
        answer = _render_field(payload, lang)
        checks = ["knowledge_lookup", "reference_lookup", "reference_router"]
    elif hit.tool == "describe_capabilities":
        payload = describe_capabilities(
            DescribeCapabilitiesParams(), principal=principal
        )
        answer = _render_capabilities(payload, lang)
        checks = ["knowledge_lookup", "capabilities_card", "reference_router"]
    elif hit.tool == "brute_force_summary":
        params = BruteForceSummaryParams.model_validate(
            {k: v for k, v in hit.params.items() if v is not None}
        )
        payload = await dispatch_composite(hit.tool, params, principal)
        answer = _render_brute(payload, lang)
        checks = sorted(
            set(payload.get("veracity_checks_passed") or [])
            | {"datastore_computed_counts", "reference_router"}
        )
    else:
        raise ValueError(f"unknown reference route tool {hit.tool}")

    label = (
        f"reference router · {hit.route} ({hit.reason}) · no model involved · "
        f"checks: {', '.join(checks)}"
    )
    return ReferenceResult(
        answer=answer,
        tool=hit.tool,
        route=hit.route,
        checks=checks,
        label=label,
    )
