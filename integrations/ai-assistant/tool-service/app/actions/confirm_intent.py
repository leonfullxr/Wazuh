"""Bilingual affirmation/negation parsing for conversational confirm (D54)."""
from __future__ import annotations

import re
from typing import Literal

from .types import ActionRisk

Intent = Literal["affirm", "negate", "other"]

_AFFIRM = frozenset(
    """
    yes y confirm confirmed proceed go ahead do it ok okay
    si sí confirmar confirmo adelante procede hazlo dale
    """.split()
)
_NEGATE = frozenset(
    """
    no cancel stop abort nope cancela cancelar detente para
    """.split()
)


def _tokens(text: str) -> list[str]:
    folded = text.casefold()
    folded = (
        folded.replace("í", "i")
        .replace("á", "a")
        .replace("é", "e")
        .replace("ó", "o")
        .replace("ú", "u")
        .replace("ñ", "n")
    )
    return re.findall(r"[a-z0-9]+", folded)


def parse_intent(text: str) -> Intent:
    """Match only when the message is essentially just yes/no."""
    raw = (text or "").strip()
    if not raw or len(raw) > 120:
        return "other"
    tokens = _tokens(raw)
    if not tokens or len(tokens) > 8:
        return "other"
    neg = [t for t in tokens if t in _NEGATE]
    aff = [t for t in tokens if t in _AFFIRM]
    if neg and not aff:
        return "negate"
    if aff and not neg:
        return "affirm"
    if len(tokens) == 1 and tokens[0] in _AFFIRM:
        return "affirm"
    if len(tokens) == 1 and tokens[0] in _NEGATE:
        return "negate"
    return "other"


def extract_confirm_target(text: str, action_name: str) -> dict | None:
    """Parse target echo from affirmations like ``yes restart-ossec on 001``."""
    tokens = _tokens(text)
    if action_name == "active_response":
        cmd = None
        agent = None
        for i, t in enumerate(tokens):
            if t in {"restart-ossec", "restart_ossec"} or (
                "restart" in t and "ossec" in t
            ):
                cmd = "restart-ossec"
            if t.isdigit() and len(t) <= 4:
                agent = t.zfill(3) if len(t) < 3 else t
            if t.startswith("00") and t.isdigit():
                agent = t
        if cmd and agent:
            return {"command": cmd, "agent_id": agent}
        joined = " ".join(tokens)
        m = re.search(r"restart[- ]?ossec.*?(?:on|agent)?\s*(\d{1,4})", joined)
        if m:
            aid = m.group(1).zfill(3)
            return {"command": "restart-ossec", "agent_id": aid}
        return None
    if action_name == "restart_agent":
        for t in tokens:
            if t.isdigit():
                return {"agent_id": t.zfill(3) if len(t) < 3 else t}
        m = re.search(r"(?:agent|on)\s*(\d{1,4})", " ".join(tokens))
        if m:
            return {"agent_id": m.group(1).zfill(3)}
        return None
    return None


def confirm_instruction(
    lang: str, risk: ActionRisk, action_name: str, params: dict
) -> str:
    if risk == ActionRisk.HIGH:
        if action_name == "active_response":
            cmd = params.get("command", "restart-ossec")
            agent = params.get("agent_id", "001")
            if lang == "es":
                return (
                    f'Responde **sí {cmd} en {agent}** para confirmar o **no** para cancelar.'
                )
            return f'Reply **yes {cmd} on {agent}** to confirm or **no** to cancel.'
        agent = params.get("agent_id", "001")
        if lang == "es":
            return f"Responde **sí en {agent}** para confirmar o **no** para cancelar."
        return f"Reply **yes on {agent}** to confirm or **no** to cancel."
    if lang == "es":
        return "Responde **sí** para confirmar o **no** para cancelar."
    return "Reply **yes** to confirm or **no** to cancel."
