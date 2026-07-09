"""Conversation state - grounded multi-turn follow-ups.

Lab implementation: in-memory, per (analyst, conversation_id), TTL-bounded
and trimmed to the last N question/answer pairs. Only plain text turns are
kept (never tool blocks or raw evidence), which keeps the replayed context
small and avoids resurrecting stale telemetry into later prompts. Production
stores the same shape in the tenant's own indexer under the wazuh_ai_state
principal (D7) - this module is that seam.
"""
from __future__ import annotations

import time

from .config import CFG

_STORE: dict[str, tuple[float, list[dict]]] = {}


def _key(sub: str, conversation_id: str) -> str:
    return f"{sub}:{conversation_id}"


def load(sub: str, conversation_id: str | None) -> list[dict]:
    """Prior turns as Converse messages, oldest first. Empty when unknown."""
    if not conversation_id:
        return []
    entry = _STORE.get(_key(sub, conversation_id))
    if entry is None or entry[0] < time.monotonic():
        _STORE.pop(_key(sub, conversation_id), None)
        return []
    # Deep-enough copy: the loop appends tool blocks to its working list and
    # those must never leak back into the store.
    return [
        {"role": m["role"], "content": [{"text": c["text"]} for c in m["content"]]}
        for m in entry[1]
    ]


def save(sub: str, conversation_id: str | None, user_text: str, answer: str) -> None:
    if not conversation_id or not answer.strip():
        return
    key = _key(sub, conversation_id)
    _, msgs = _STORE.get(key, (0.0, []))
    msgs = msgs + [
        {"role": "user", "content": [{"text": user_text}]},
        {"role": "assistant", "content": [{"text": answer}]},
    ]
    msgs = msgs[-2 * CFG.conversation_max_turns :]
    if len(_STORE) > 512:  # cheap bound: drop expired conversations
        now = time.monotonic()
        for stale in [k for k, v in _STORE.items() if v[0] <= now]:
            del _STORE[stale]
    _STORE[key] = (time.monotonic() + CFG.conversation_ttl, msgs)
