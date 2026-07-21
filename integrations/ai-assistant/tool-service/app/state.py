"""Conversation state - grounded multi-turn follow-ups (D7 / D58).

Default backend is in-memory (PoC). Optional indexer backend persists under
a dedicated index using the reader/state principal - never embeds telemetry.
A rolling summary keeps replayed context within a token budget.
"""
from __future__ import annotations

import json
import time
from typing import Any

from .config import CFG

_STORE: dict[str, tuple[float, list[dict]]] = {}


def _key(sub: str, conversation_id: str) -> str:
    return f"{sub}:{conversation_id}"


def _estimate_tokens(msgs: list[dict]) -> int:
    chars = 0
    for m in msgs:
        for c in m.get("content") or []:
            chars += len(c.get("text") or "")
    return max(1, chars // 4)


def _rolling_summary(msgs: list[dict]) -> list[dict]:
    """Trim to budget: keep a summary of older turns + recent pairs."""
    budget = max(200, CFG.conversation_summary_tokens)
    max_msgs = 2 * CFG.conversation_max_turns
    msgs = msgs[-max_msgs:]
    if _estimate_tokens(msgs) <= budget:
        return msgs
    # Keep the last 2 turns (4 messages); summarize the rest as one user note.
    keep = msgs[-4:] if len(msgs) > 4 else msgs
    older = msgs[:-4] if len(msgs) > 4 else []
    if not older:
        # Still over budget: truncate assistant texts from the end of keep.
        while keep and _estimate_tokens(keep) > budget:
            last = keep[-1]
            texts = last.get("content") or []
            if texts and texts[0].get("text"):
                texts[0]["text"] = texts[0]["text"][: max(80, len(texts[0]["text"]) // 2)]
            else:
                keep.pop()
        return keep
    snippets = []
    for m in older:
        role = m.get("role", "?")
        text = (m.get("content") or [{}])[0].get("text") or ""
        snippets.append(f"{role}: {text[:120]}")
    summary = (
        "[conversation summary — earlier turns, truncated]\n"
        + "\n".join(snippets)
    )[: budget * 2]
    summarized = [
        {"role": "user", "content": [{"text": summary}]},
        {"role": "assistant", "content": [{"text": "Understood."}]},
    ]
    out = summarized + keep
    while _estimate_tokens(out) > budget and len(out) > 2:
        # Drop oldest real turn pair after the summary block.
        if len(out) > 4:
            out = out[:2] + out[4:]
        else:
            break
    return out


def load(sub: str, conversation_id: str | None) -> list[dict]:
    """Prior turns as Converse messages, oldest first. Empty when unknown."""
    if not conversation_id:
        return []
    if CFG.conversation_backend == "indexer":
        return _load_indexer(sub, conversation_id)
    entry = _STORE.get(_key(sub, conversation_id))
    if entry is None or entry[0] < time.monotonic():
        _STORE.pop(_key(sub, conversation_id), None)
        return []
    return [
        {"role": m["role"], "content": [{"text": c["text"]} for c in m["content"]]}
        for m in entry[1]
    ]


def save(sub: str, conversation_id: str | None, user_text: str, answer: str) -> None:
    if not conversation_id or not answer.strip():
        return
    if CFG.conversation_backend == "indexer":
        _save_indexer(sub, conversation_id, user_text, answer)
        return
    key = _key(sub, conversation_id)
    _, msgs = _STORE.get(key, (0.0, []))
    msgs = msgs + [
        {"role": "user", "content": [{"text": user_text}]},
        {"role": "assistant", "content": [{"text": answer}]},
    ]
    msgs = _rolling_summary(msgs)
    if len(_STORE) > 512:
        now = time.monotonic()
        for stale in [k for k, v in _STORE.items() if v[0] <= now]:
            del _STORE[stale]
    _STORE[key] = (time.monotonic() + CFG.conversation_ttl, msgs)


def _doc_id(sub: str, conversation_id: str) -> str:
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in f"{sub}_{conversation_id}")
    return safe[:128]


def _load_indexer(sub: str, conversation_id: str) -> list[dict]:
    try:
        from .indexer import get_indexer
        from .env_registry import get_env
        from .config import CFG as _cfg
        import base64
        import httpx

        env = get_env(_cfg.actions_env_id) if _cfg.actions_env_id else None
        # Prefer default lab indexer from CFG when env registry empty.
        indexer_url = (env.indexer_url if env else None) or _cfg.indexer_url
        cred = (env.reader_basic if env else "") or ""
        if not cred or ":" not in cred:
            # Fall back to memory if no state credential.
            entry = _STORE.get(_key(sub, conversation_id))
            return [
                {"role": m["role"], "content": [{"text": c["text"]} for c in m["content"]]}
                for m in (entry[1] if entry else [])
            ]
        token = base64.b64encode(cred.encode()).decode("ascii")
        headers = {"Authorization": f"Basic {token}"}
        index = _cfg.conversation_index
        doc_id = _doc_id(sub, conversation_id)
        verify: Any = (env.indexer_ca_path if env else None) or _cfg.indexer_verify_ssl
        with httpx.Client(base_url=indexer_url.rstrip("/"), verify=verify, timeout=10.0) as client:
            r = client.get(f"/{index}/_doc/{doc_id}", headers=headers)
        if r.status_code == 404:
            return []
        if r.status_code >= 400:
            return []
        src = r.json().get("_source") or {}
        msgs = src.get("messages") or []
        return [
            {"role": m["role"], "content": [{"text": c["text"]} for c in m["content"]]}
            for m in msgs
        ]
    except Exception:
        entry = _STORE.get(_key(sub, conversation_id))
        if not entry:
            return []
        return [
            {"role": m["role"], "content": [{"text": c["text"]} for c in m["content"]]}
            for m in entry[1]
        ]


def _save_indexer(sub: str, conversation_id: str, user_text: str, answer: str) -> None:
    # Always mirror to memory so a failed indexer write still works in-process.
    key = _key(sub, conversation_id)
    _, msgs = _STORE.get(key, (0.0, []))
    msgs = msgs + [
        {"role": "user", "content": [{"text": user_text}]},
        {"role": "assistant", "content": [{"text": answer}]},
    ]
    msgs = _rolling_summary(msgs)
    _STORE[key] = (time.monotonic() + CFG.conversation_ttl, msgs)

    try:
        import base64
        import httpx
        from .env_registry import get_env

        env = get_env(CFG.actions_env_id) if CFG.actions_env_id else None
        indexer_url = (env.indexer_url if env else None) or CFG.indexer_url
        cred = (env.reader_basic if env else "") or ""
        if not cred or ":" not in cred:
            return
        token = base64.b64encode(cred.encode()).decode("ascii")
        headers = {
            "Authorization": f"Basic {token}",
            "Content-Type": "application/json",
        }
        index = CFG.conversation_index
        doc_id = _doc_id(sub, conversation_id)
        body = {
            "sub": sub,
            "conversation_id": conversation_id,
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "messages": msgs,
        }
        verify: Any = (env.indexer_ca_path if env else None) or CFG.indexer_verify_ssl
        with httpx.Client(base_url=indexer_url.rstrip("/"), verify=verify, timeout=10.0) as client:
            client.put(f"/{index}/_doc/{doc_id}", headers=headers, content=json.dumps(body))
    except Exception:
        pass
