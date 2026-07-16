"""Static knowledge tools - exact MITRE lookup + public corpus search (D57).

Tenant telemetry is never embedded. The only sanctioned vector store is over
curated public reference content shipped with the deployment.
"""
from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field

from . import embeddings
from .config import CFG

_DIR = Path(__file__).parent / "knowledge"
_TECHNIQUES: dict[str, dict[str, str]] = json.loads(
    (_DIR / "mitre_techniques.json").read_text()
)
_CORPUS: list[dict[str, Any]] = json.loads((_DIR / "corpus.json").read_text())
_MITRE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)

_corpus_vectors: list[list[float]] | None = None


class MitreLookupParams(BaseModel):
    """Look up a MITRE ATT&CK technique by exact id (e.g. T1110)."""

    technique_id: str = Field(
        description="MITRE ATT&CK technique id, e.g. T1110 or T1190"
    )


class KnowledgeSearchParams(BaseModel):
    """Semantic search over curated public remediation / reference docs."""

    query: str = Field(min_length=3, max_length=400)
    size: int = Field(3, ge=1, le=5)


def mitre_lookup(params: MitreLookupParams) -> dict[str, Any]:
    tid = params.technique_id.strip().upper()
    if not _MITRE_ID.fullmatch(tid):
        return {
            "found": False,
            "technique_id": tid,
            "error": "invalid MITRE technique id format (expected T####)",
        }
    base = tid.split(".")[0]
    entry = _TECHNIQUES.get(base)
    if entry is None:
        return {"found": False, "technique_id": tid, "error": "technique not in local catalog"}
    return {"found": True, "technique_id": base, **entry}


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    return dot / (na * nb) if na and nb else 0.0


async def _ensure_corpus() -> list[list[float]]:
    global _corpus_vectors
    if _corpus_vectors is not None:
        return _corpus_vectors
    texts = [
        f"{doc['title']}. {' '.join(doc.get('tags') or [])}. {doc['text']}"
        for doc in _CORPUS
    ]
    _corpus_vectors = await embeddings.embed_corpus(texts)
    return _corpus_vectors


async def knowledge_search(params: KnowledgeSearchParams) -> dict[str, Any]:
    """Retrieve public corpus docs by embedding similarity (never tenant data)."""
    if not CFG.knowledge_search_enabled:
        return {
            "hits": [],
            "note": "knowledge_search disabled",
            "corpus": "public-reference",
        }
    try:
        vectors = await _ensure_corpus()
        qvec = await embeddings.embed_text(params.query)
    except Exception as exc:
        return {
            "hits": [],
            "error": f"embeddings unavailable: {exc}"[:200],
            "corpus": "public-reference",
        }
    scored: list[tuple[float, dict]] = []
    for doc, vec in zip(_CORPUS, vectors):
        scored.append((_cosine(qvec, vec), doc))
    scored.sort(key=lambda x: x[0], reverse=True)
    threshold = CFG.knowledge_search_threshold
    hits = []
    for score, doc in scored[: params.size]:
        if score < threshold:
            continue
        hits.append(
            {
                "id": doc["id"],
                "title": doc["title"],
                "text": doc["text"],
                "score": round(score, 3),
                "cite_as": f"[kb:{doc['id']}]",
            }
        )
    return {
        "hits": hits,
        "total_matching": len(hits),
        "corpus": "public-reference",
        "note": "Public curated content only - not tenant telemetry",
    }


def corpus_ids() -> set[str]:
    return {str(d["id"]) for d in _CORPUS}
