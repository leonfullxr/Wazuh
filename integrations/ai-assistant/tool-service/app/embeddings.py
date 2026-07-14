"""Shared embedding client (R2.4) — one HTTP call per question per turn.

Lane 0 and the scope classifier share a per-turn text→vector cache so the
same question is never embedded more than once.
"""
from __future__ import annotations

from contextvars import ContextVar

import httpx

from .config import CFG

_http = httpx.AsyncClient(timeout=30.0)
_turn_cache: ContextVar[dict[str, list[float]] | None] = ContextVar(
    "embed_turn_cache", default=None
)


def begin_turn() -> None:
    _turn_cache.set({})


async def embed_text(text: str) -> list[float]:
    cache = _turn_cache.get()
    if cache is None:
        cache = {}
        _turn_cache.set(cache)
    if text in cache:
        return cache[text]
    headers = {"Authorization": f"Bearer {CFG.embed_api_key}"} if CFG.embed_api_key else {}
    r = await _http.post(
        f"{CFG.embed_base_url.rstrip('/')}/embeddings",
        json={"model": CFG.embed_model, "input": [text]},
        headers=headers,
    )
    r.raise_for_status()
    vec = r.json()["data"][0]["embedding"]
    cache[text] = vec
    return vec


async def embed_corpus(texts: list[str]) -> list[list[float]]:
    headers = {"Authorization": f"Bearer {CFG.embed_api_key}"} if CFG.embed_api_key else {}
    r = await _http.post(
        f"{CFG.embed_base_url.rstrip('/')}/embeddings",
        json={"model": CFG.embed_model, "input": texts},
        headers=headers,
    )
    r.raise_for_status()
    return [d["embedding"] for d in r.json()["data"]]
