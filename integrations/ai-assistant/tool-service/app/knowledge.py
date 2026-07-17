"""Static knowledge tools - exact MITRE/rule/field lookup + public corpus search
(D57/D60/D61).

Tenant telemetry is never embedded. The only sanctioned vector store is over
curated public reference content shipped with the deployment:
  - knowledge/corpus.json          (hand-curated remediation notes)
  - knowledge/wazuh_docs.json      (D60: version-pinned docs from llms.txt)
Exact-match catalogs (no embeddings):
  - knowledge/rule_reference.json  (D61)
  - knowledge/field_dictionary.json (D61)
"""
from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field, model_validator

from . import embeddings
from .config import CFG

_DIR = Path(__file__).parent / "knowledge"
_TECHNIQUES: dict[str, dict[str, str]] = json.loads(
    (_DIR / "mitre_techniques.json").read_text()
)
_RULE_REF: dict[str, Any] = json.loads((_DIR / "rule_reference.json").read_text())
_FIELD_DICT: dict[str, Any] = json.loads((_DIR / "field_dictionary.json").read_text())
_MITRE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)

_corpus_vectors: list[list[float]] | None = None
_CORPUS_DOCS: list[dict[str, Any]] | None = None


class MitreLookupParams(BaseModel):
    """Look up a MITRE ATT&CK technique by exact id (e.g. T1110)."""

    technique_id: str = Field(
        description="MITRE ATT&CK technique id, e.g. T1110 or T1190"
    )


class KnowledgeSearchParams(BaseModel):
    """Semantic search over curated public remediation / Wazuh documentation."""

    query: str = Field(min_length=3, max_length=400)
    size: int = Field(3, ge=1, le=8)
    source: Optional[str] = Field(
        None,
        description=(
            "Optional filter: 'remediation' (hand corpus), 'wazuh-docs' (D60), "
            "or omit to search both"
        ),
    )


class RuleReferenceParams(BaseModel):
    """Exact-match lookup for a Wazuh rule id, rule group, or decoder name (D61)."""

    rule_id: Optional[str] = Field(None, description="Numeric rule id, e.g. '5710'")
    rule_group: Optional[str] = Field(
        None, description="rule.groups value, e.g. authentication_failed"
    )
    decoder_name: Optional[str] = Field(
        None, description="Decoder name, e.g. sshd"
    )

    @model_validator(mode="after")
    def _one_key(self) -> "RuleReferenceParams":
        provided = sum(
            1
            for v in (self.rule_id, self.rule_group, self.decoder_name)
            if v and str(v).strip()
        )
        if provided != 1:
            raise ValueError("provide exactly one of rule_id, rule_group, decoder_name")
        return self


class FieldDictionaryParams(BaseModel):
    """Look up the meaning of an alert field name (D61)."""

    field: str = Field(
        min_length=1,
        max_length=120,
        description="Alert field or alias, e.g. rule.level or data.srcip",
    )


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


def rule_reference(params: RuleReferenceParams) -> dict[str, Any]:
    """Exact curated lookup — never fabricates unknown ids (D61)."""
    if params.rule_id and str(params.rule_id).strip():
        rid = str(params.rule_id).strip()
        entry = (_RULE_REF.get("rules") or {}).get(rid)
        if entry is None:
            return {
                "found": False,
                "kind": "rule",
                "rule_id": rid,
                "error": "rule id not in local reference catalog",
            }
        cite = f"rule-{rid}"
        return {
            "found": True,
            "kind": "rule",
            "rule_id": rid,
            "id": cite,
            "cite_as": f"[kb:{cite}]",
            **entry,
        }
    if params.rule_group and str(params.rule_group).strip():
        g = str(params.rule_group).strip()
        entry = (_RULE_REF.get("groups") or {}).get(g)
        if entry is None:
            return {
                "found": False,
                "kind": "group",
                "rule_group": g,
                "error": "rule group not in local reference catalog",
            }
        cite = f"group-{g}"
        return {
            "found": True,
            "kind": "group",
            "rule_group": g,
            "id": cite,
            "cite_as": f"[kb:{cite}]",
            **entry,
        }
    name = str(params.decoder_name or "").strip()
    entry = (_RULE_REF.get("decoders") or {}).get(name)
    if entry is None:
        return {
            "found": False,
            "kind": "decoder",
            "decoder_name": name,
            "error": "decoder not in local reference catalog",
        }
    cite = f"decoder-{name}"
    return {
        "found": True,
        "kind": "decoder",
        "decoder_name": name,
        "id": cite,
        "cite_as": f"[kb:{cite}]",
        **entry,
    }


def field_dictionary(params: FieldDictionaryParams) -> dict[str, Any]:
    raw = params.field.strip()
    aliases = _FIELD_DICT.get("aliases") or {}
    fields = _FIELD_DICT.get("fields") or {}
    resolved = aliases.get(raw, aliases.get(raw.lower(), raw))
    entry = fields.get(resolved)
    if entry is None:
        # case-insensitive field match
        lower_map = {k.lower(): k for k in fields}
        key = lower_map.get(resolved.lower())
        entry = fields.get(key) if key else None
        resolved = key or resolved
    if entry is None:
        return {
            "found": False,
            "field": raw,
            "error": "field not in local dictionary",
        }
    cite = f"field-{resolved.replace('.', '-')}"
    return {
        "found": True,
        "field": resolved,
        "requested": raw,
        "id": cite,
        "cite_as": f"[kb:{cite}]",
        **entry,
    }


def reference_ids() -> set[str]:
    """Citable ids from rule/field reference catalogs."""
    ids: set[str] = set()
    for rid in (_RULE_REF.get("rules") or {}):
        ids.add(f"rule-{rid}")
    for g in (_RULE_REF.get("groups") or {}):
        ids.add(f"group-{g}")
    for d in (_RULE_REF.get("decoders") or {}):
        ids.add(f"decoder-{d}")
    for f in (_FIELD_DICT.get("fields") or {}):
        ids.add(f"field-{f.replace('.', '-')}")
    return ids


def _load_hand_corpus() -> list[dict[str, Any]]:
    raw = json.loads((_DIR / "corpus.json").read_text())
    docs: list[dict[str, Any]] = []
    for doc in raw:
        d = dict(doc)
        d.setdefault("source", "remediation")
        docs.append(d)
    return docs


def _load_docs_corpus() -> list[dict[str, Any]]:
    if not CFG.docs_kb_enabled:
        return []
    path = Path(CFG.docs_kb_path) if CFG.docs_kb_path else (_DIR / "wazuh_docs.json")
    if not path.is_file():
        # Relative to the knowledge package dir when only a filename is given.
        alt = _DIR / path.name
        path = alt if alt.is_file() else path
    if not path.is_file():
        return []
    payload = json.loads(path.read_text())
    if isinstance(payload, list):
        docs = payload
    else:
        docs = list(payload.get("documents") or [])
    out: list[dict[str, Any]] = []
    for doc in docs:
        if not doc.get("id") or not doc.get("text"):
            continue
        d = dict(doc)
        d.setdefault("source", "wazuh-docs")
        out.append(d)
    return out


def _all_docs() -> list[dict[str, Any]]:
    global _CORPUS_DOCS
    if _CORPUS_DOCS is not None:
        return _CORPUS_DOCS
    _CORPUS_DOCS = _load_hand_corpus() + _load_docs_corpus()
    return _CORPUS_DOCS


def reload_corpora() -> None:
    """Drop cached docs/vectors (tests / after rebuild)."""
    global _CORPUS_DOCS, _corpus_vectors
    _CORPUS_DOCS = None
    _corpus_vectors = None


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    return dot / (na * nb) if na and nb else 0.0


def _embed_text_for_doc(doc: dict[str, Any]) -> str:
    parts = [
        str(doc.get("title") or ""),
        str(doc.get("section") or ""),
        " ".join(doc.get("tags") or []),
        str(doc.get("text") or ""),
    ]
    return ". ".join(p for p in parts if p)


async def _ensure_corpus() -> tuple[list[dict[str, Any]], list[list[float]]]:
    global _corpus_vectors
    docs = _all_docs()
    if _corpus_vectors is not None and len(_corpus_vectors) == len(docs):
        return docs, _corpus_vectors
    texts = [_embed_text_for_doc(doc) for doc in docs]
    _corpus_vectors = await embeddings.embed_corpus(texts) if texts else []
    return docs, _corpus_vectors


async def knowledge_search(params: KnowledgeSearchParams) -> dict[str, Any]:
    """Retrieve public corpus docs by embedding similarity (never tenant data)."""
    if not CFG.knowledge_search_enabled:
        return {
            "hits": [],
            "note": "knowledge_search disabled",
            "corpus": "public-reference",
        }
    try:
        docs, vectors = await _ensure_corpus()
        qvec = await embeddings.embed_text(params.query)
    except Exception as exc:
        return {
            "hits": [],
            "error": f"embeddings unavailable: {exc}"[:200],
            "corpus": "public-reference",
        }

    source_filter = (params.source or "").strip().lower() or None
    if source_filter in {"docs", "documentation", "wazuh_docs"}:
        source_filter = "wazuh-docs"
    if source_filter in {"hand", "public", "remediation-notes"}:
        source_filter = "remediation"

    scored: list[tuple[float, dict]] = []
    for doc, vec in zip(docs, vectors):
        if source_filter and str(doc.get("source") or "") != source_filter:
            continue
        scored.append((_cosine(qvec, vec), doc))
    scored.sort(key=lambda x: x[0], reverse=True)
    threshold = CFG.knowledge_search_threshold
    top_k = min(params.size, CFG.docs_kb_top_k if source_filter == "wazuh-docs" else params.size)
    hits = []
    for score, doc in scored[:top_k]:
        if score < threshold:
            continue
        hit: dict[str, Any] = {
            "id": doc["id"],
            "title": doc["title"],
            "text": doc["text"],
            "score": round(score, 3),
            "source": doc.get("source", "remediation"),
            "cite_as": f"[kb:{doc['id']}]",
        }
        if doc.get("url"):
            hit["url"] = doc["url"]
        if doc.get("section"):
            hit["section"] = doc["section"]
        hits.append(hit)
    return {
        "hits": hits,
        "total_matching": len(hits),
        "corpus": "public-reference",
        "sources_searched": sorted({str(d.get("source") or "remediation") for d in docs}),
        "note": "Public curated content only - not tenant telemetry",
    }


def corpus_ids() -> set[str]:
    return {str(d["id"]) for d in _all_docs()} | reference_ids()
