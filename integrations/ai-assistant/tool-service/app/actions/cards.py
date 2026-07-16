"""Action proposal cards for dashboard UI and connector messages (V3.5c)."""
from __future__ import annotations

import base64
import json
import re
from typing import Any

MARKER_RE = re.compile(
    r"<!--WAZUH_AI_ACTIONS(?P<payload>[A-Za-z0-9_-]*)WAZUH_AI_ACTIONS_END-->",
    re.DOTALL,
)


def _b64_encode(data: dict[str, Any]) -> str:
    raw = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64_decode(token: str) -> dict[str, Any]:
    pad = "=" * (-len(token) % 4)
    raw = base64.urlsafe_b64decode(token + pad)
    parsed = json.loads(raw.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("action card payload must be a JSON object")
    return parsed


def card_from_proposal(payload: dict[str, Any], *, ui_base: str) -> dict[str, Any]:
    """Normalize create_proposal() output for UI consumers."""
    proposal_id = str(payload["proposal_id"])
    base = ui_base.rstrip("/")
    return {
        "proposal_id": proposal_id,
        "action": payload.get("action"),
        "preview": payload.get("preview", ""),
        "tier": payload.get("tier"),
        "risk": payload.get("risk"),
        "status": payload.get("status", "pending"),
        "confirm_path": payload.get("confirm_path", f"/v1/actions/{proposal_id}/confirm"),
        "reject_path": f"/v1/actions/{proposal_id}/reject",
        "ui_url": f"{base}/v1/actions/ui/{proposal_id}",
        "expires_in_s": payload.get("expires_in_s"),
        "note": payload.get("note", ""),
    }


def embed_action_cards(answer: str, proposals: list[dict[str, Any]], *, ui_base: str) -> str:
    """Append a machine-readable marker the dashboard plugin parses (V3.5c)."""
    if not proposals:
        return answer
    cards = [
        p if "ui_url" in p else card_from_proposal(p, ui_base=ui_base)
        for p in proposals
    ]
    block = _b64_encode({"version": 1, "actions": cards})
    links = "\n".join(
        f"- [{c['preview'].split(chr(10), 1)[0][:80]}]({c['ui_url']})"
        for c in cards
    )
    footer = (
        "\n\n---\n**Action proposed · not executed**\n"
        f"{links}\n\n"
        f"<!--WAZUH_AI_ACTIONS{block}WAZUH_AI_ACTIONS_END-->"
    )
    return f"{answer.rstrip()}{footer}"


def strip_action_markers(text: str) -> str:
    return MARKER_RE.sub("", text).strip()


def parse_action_markers(text: str) -> list[dict[str, Any]]:
    cards: list[dict[str, Any]] = []
    for match in MARKER_RE.finditer(text):
        try:
            data = _b64_decode(match.group("payload"))
        except (ValueError, json.JSONDecodeError):
            continue
        for item in data.get("actions") or []:
            if isinstance(item, dict):
                cards.append(item)
    return cards
