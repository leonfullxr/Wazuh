"""Parse ML Commons conversational agent _execute responses (V3.1f)."""

import base64
import json
import re

_ACTION_MARKER_RE = re.compile(
    r"<!--WAZUH_AI_ACTIONS(?P<payload>[A-Za-z0-9_-]*)WAZUH_AI_ACTIONS_END-->",
    re.DOTALL,
)


def parse_action_markers(text: str) -> list[dict]:
    cards: list[dict] = []
    for match in _ACTION_MARKER_RE.finditer(text):
        token = match.group("payload")
        try:
            pad = "=" * (-len(token) % 4)
            raw = base64.urlsafe_b64decode(token + pad)
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, json.JSONDecodeError):
            continue
        for item in data.get("actions") or []:
            if isinstance(item, dict):
                cards.append(item)
    return cards


def parse_agent_message(data: dict) -> str:
    """The answer lives under output[name=response].dataAsMap.response."""
    for block in data.get("inference_results") or []:
        for out in block.get("output") or []:
            if out.get("name") != "response":
                continue
            data_map = out.get("dataAsMap")
            if isinstance(data_map, dict):
                for key in ("response", "message"):
                    if data_map.get(key):
                        return str(data_map[key])
    for block in data.get("inference_results") or []:
        for out in block.get("output") or []:
            if out.get("name") in ("memory_id", "parent_interaction_id"):
                continue
            data_map = out.get("dataAsMap")
            if isinstance(data_map, dict):
                for key in ("response", "message"):
                    if data_map.get(key):
                        return str(data_map[key])
    out = data.get("output")
    if isinstance(out, dict) and out.get("message"):
        return str(out["message"])
    return ""


def split_connector_message(message: str) -> tuple[str, str]:
    msg = message.strip()
    if "\n\n_" in msg:
        body, label = msg.rsplit("\n\n_", 1)
        return body.strip(), label.rstrip("_").strip()
    if msg.startswith("_") and msg.endswith("_"):
        return "", msg.strip("_").strip()
    return msg, ""
