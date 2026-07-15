"""Shared embedding client (R2.4 / C3).

Lane 0 and the scope classifier share a per-turn text→vector cache so the same
question is never embedded more than once.

Providers:
  openai     — any OpenAI-compatible /v1/embeddings endpoint (default: Ollama bge-m3)
  mlcommons  — in-cluster ML Commons on the Wazuh indexer; forwards the analyst
               turn JWT so embedding calls stay per-user (D11).
"""
from __future__ import annotations

from contextvars import ContextVar

import httpx

from .config import CFG
from .indexer import INDEXER

_http = httpx.AsyncClient(timeout=60.0)
_turn_cache: ContextVar[dict[str, list[float]] | None] = ContextVar(
    "embed_turn_cache", default=None
)
_turn_jwt: ContextVar[str | None] = ContextVar("embed_turn_jwt", default=None)


def begin_turn(user_jwt: str | None = None) -> None:
    _turn_cache.set({})
    _turn_jwt.set(user_jwt)


def _cache() -> dict[str, list[float]]:
    cache = _turn_cache.get()
    if cache is None:
        cache = {}
        _turn_cache.set(cache)
    return cache


def _parse_ml_embedding(result: dict) -> list[float]:
    for out in result.get("output") or []:
        if out.get("name") in ("sentence_embedding", "embedding"):
            data = out.get("data")
            if isinstance(data, list):
                return [float(x) for x in data]
    raise ValueError("mlcommons predict response missing sentence_embedding")


async def _embed_openai(texts: list[str]) -> list[list[float]]:
    headers = (
        {"Authorization": f"Bearer {CFG.embed_api_key}"} if CFG.embed_api_key else {}
    )
    r = await _http.post(
        f"{CFG.embed_base_url.rstrip('/')}/embeddings",
        json={"model": CFG.embed_model, "input": texts},
        headers=headers,
    )
    r.raise_for_status()
    return [d["embedding"] for d in r.json()["data"]]


async def _embed_mlcommons(texts: list[str]) -> list[list[float]]:
    jwt = _turn_jwt.get()
    if not jwt:
        raise RuntimeError("mlcommons embeddings require analyst turn JWT")
    if not CFG.embed_ml_model_id:
        raise RuntimeError("WAI_EMBED_ML_MODEL_ID is required for mlcommons provider")
    r = await INDEXER.http.post(
        f"/_plugins/_ml/models/{CFG.embed_ml_model_id}/_predict",
        json={
            "text_docs": texts,
            "return_number": True,
            "target_response": ["sentence_embedding"],
        },
        headers=INDEXER._headers(jwt),
    )
    r.raise_for_status()
    results = r.json().get("inference_results") or []
    if len(results) != len(texts):
        raise ValueError(
            f"mlcommons returned {len(results)} embeddings for {len(texts)} inputs"
        )
    return [_parse_ml_embedding(item) for item in results]


async def _embed_batch(texts: list[str]) -> list[list[float]]:
    if CFG.embed_provider == "mlcommons":
        return await _embed_mlcommons(texts)
    return await _embed_openai(texts)


async def embed_text(text: str) -> list[float]:
    cache = _cache()
    if text in cache:
        return cache[text]
    vec = (await _embed_batch([text]))[0]
    cache[text] = vec
    return vec


async def embed_corpus(texts: list[str]) -> list[list[float]]:
    if not texts:
        return []
    cache = _cache()
    missing = [t for t in texts if t not in cache]
    if missing:
        vectors = await _embed_batch(missing)
        for text, vec in zip(missing, vectors):
            cache[text] = vec
    return [cache[t] for t in texts]
