"""Manifest-bound knowledge loading and deterministic site-scoped retrieval."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any

import psycopg
from pydantic import TypeAdapter

from ai_soc.content.builder import verify_content_pack
from ai_soc.content.knowledge import PackedKnowledgeDocument
from ai_soc.contracts.models import PackManifest
from ai_soc.workspace.db import require_site_transaction


@dataclass(frozen=True, slots=True)
class KnowledgeSubject:
    rule_ids: tuple[str, ...] = ()
    rule_groups: tuple[str, ...] = ()
    attack_techniques: tuple[str, ...] = ()
    cves: tuple[str, ...] = ()
    query_text: str = ""


@dataclass(frozen=True, slots=True)
class KnowledgeHit:
    chunk_id: str
    document_id: str
    title: str
    kind: str
    language: str
    section: str
    body: str
    source_path: str
    content_version: str
    reviewer: str
    review_date: str
    exact_match: bool
    rank: float


@dataclass(frozen=True, slots=True)
class VerifiedKnowledgePack:
    manifest: PackManifest
    files: Mapping[str, bytes]


def verify_live_knowledge_pack(pack: Path, *, expected_pack_sha256: str) -> VerifiedKnowledgePack:
    """Bind one verified pack snapshot to an independently published live approval pin."""
    if not _is_digest(expected_pack_sha256):
        raise ValueError("expected knowledge pack digest is invalid")
    verified = verify_content_pack(pack)
    manifest = PackManifest.model_validate_json(verified["manifest.json"])
    if manifest.pack_sha256 != expected_pack_sha256:
        raise ValueError("knowledge pack does not match the trusted published digest")
    try:
        provenance = TypeAdapter(dict[str, str]).validate_json(verified["provenance.json"])
    except (KeyError, ValueError) as exc:
        raise ValueError("knowledge pack provenance is invalid") from exc
    if provenance.get("mode") != "live":
        raise ValueError("production knowledge loading requires a live-approved content pack")
    if (
        provenance.get("content_sha") != manifest.content_sha
        or provenance.get("pack_sha256") != manifest.pack_sha256
        or provenance.get("source_repository") != str(manifest.source_repository)
        or not str(manifest.review_attestation).startswith("https://")
    ):
        raise ValueError("knowledge pack provenance does not match its manifest")
    return VerifiedKnowledgePack(manifest, MappingProxyType(verified))


def _is_digest(value: str) -> bool:
    return (
        len(value) == 64 and value.isascii() and all(char in "0123456789abcdef" for char in value)
    )


def load_knowledge_pack(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    pack: Path,
    loaded_at: datetime,
    verified_pack: VerifiedKnowledgePack | None = None,
) -> int:
    """Load verified packed knowledge for one site; repeat loads are idempotent."""
    require_site_transaction(conn, site_id)
    if loaded_at.tzinfo is None or loaded_at.utcoffset() is None:
        raise ValueError("knowledge load cutoff must be timezone-aware")
    if verified_pack is None:
        verified = verify_content_pack(pack)
        manifest = PackManifest.model_validate_json(verified["manifest.json"])
    else:
        verified = verified_pack.files
        manifest = verified_pack.manifest
    paths = sorted(
        path for path in verified if path.startswith("pack/knowledge/") and path.endswith(".json")
    )
    loaded = 0
    seen_ids: set[str] = set()
    for path in paths:
        document = PackedKnowledgeDocument.model_validate_json(verified[path])
        expected = f"{document.document_id}.json"
        if PurePosixPath(path).name != expected or document.document_id in seen_ids:
            raise ValueError("knowledge pack contains a duplicate or mismatched document")
        if document.content_version != manifest.content_sha:
            raise ValueError("knowledge document version does not match its pack")
        seen_ids.add(document.document_id)
        conn.execute(
            """INSERT INTO knowledge_documents
               (site_id,document_id,content_version,title,kind,language,source_path,
                source_sha256,reviewer,review_date,expiry,pack_digest,loaded_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
               ON CONFLICT (site_id,document_id,content_version) DO NOTHING""",
            (
                site_id,
                document.document_id,
                document.content_version,
                document.title,
                document.kind,
                document.language,
                document.source_path,
                document.source_sha256,
                document.reviewer,
                document.review_date,
                document.expiry,
                manifest.pack_sha256,
                loaded_at.astimezone(UTC),
            ),
        )
        applies = document.applies_to
        for chunk in document.chunks:
            conn.execute(
                """INSERT INTO knowledge_chunks
                   (site_id,document_id,content_version,chunk_id,section,ordinal,body,
                    body_sha256,rule_ids,rule_groups,attack_techniques,cves,language)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT (site_id,chunk_id,content_version) DO NOTHING""",
                (
                    site_id,
                    document.document_id,
                    document.content_version,
                    chunk.chunk_id,
                    chunk.section,
                    chunk.ordinal,
                    chunk.text,
                    chunk.sha256,
                    list(applies.rule_ids),
                    list(applies.rule_groups),
                    list(applies.attack_techniques),
                    list(applies.cves),
                    document.language,
                ),
            )
            loaded += 1
    return loaded


def search_knowledge(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    subject: KnowledgeSubject,
    cutoff: datetime,
    limit: int = 5,
) -> tuple[KnowledgeHit, ...]:
    """Return exact-key matches first, then bilingual FTS rank and stable chunk id."""
    require_site_transaction(conn, site_id)
    if cutoff.tzinfo is None or cutoff.utcoffset() is None or not 1 <= limit <= 5:
        raise ValueError("knowledge cutoff must be aware and limit must be between one and five")
    query = subject.query_text.strip()[:4096]
    rows = conn.execute(
        """WITH eligible AS (
               SELECT d.*,
                      row_number() OVER (
                        PARTITION BY d.document_id ORDER BY d.loaded_at DESC, d.content_version DESC
                      ) AS version_rank
               FROM knowledge_documents d
               WHERE d.site_id=%s AND d.loaded_at <= %s
                 AND (d.expiry IS NULL OR d.expiry > (%s AT TIME ZONE 'UTC')::date)
             ), candidates AS (
               SELECT c.chunk_id,c.document_id,d.title,d.kind,c.language,c.section,c.body,
                      d.source_path,c.content_version,d.reviewer,d.review_date,
                      (c.rule_ids && %s::text[] OR c.rule_groups && %s::text[]
                       OR c.attack_techniques && %s::text[] OR c.cves && %s::text[]) exact_match,
                      (c.search_en @@ plainto_tsquery('english', %s)
                       OR c.search_es @@ plainto_tsquery('spanish', %s)) AS text_match,
                      GREATEST(
                        ts_rank(c.search_en, plainto_tsquery('english', %s)),
                        ts_rank(c.search_es, plainto_tsquery('spanish', %s))
                      ) AS text_rank
               FROM eligible d
               JOIN knowledge_chunks c USING (site_id,document_id,content_version)
               WHERE d.version_rank=1
             )
             SELECT chunk_id,document_id,title,kind,language,section,body,source_path,
                    content_version,reviewer,review_date,exact_match,text_rank
             FROM candidates
             WHERE exact_match OR text_match
             ORDER BY exact_match DESC, text_rank DESC, chunk_id
             LIMIT %s""",
        (
            site_id,
            cutoff,
            cutoff,
            list(subject.rule_ids),
            list(subject.rule_groups),
            list(subject.attack_techniques),
            list(subject.cves),
            query,
            query,
            query,
            query,
            limit,
        ),
    ).fetchall()
    return tuple(
        KnowledgeHit(
            chunk_id=row[0],
            document_id=row[1],
            title=row[2],
            kind=row[3],
            language=row[4],
            section=row[5],
            body=row[6],
            source_path=row[7],
            content_version=row[8],
            reviewer=row[9],
            review_date=row[10].isoformat(),
            exact_match=row[11],
            rank=float(row[12]),
        )
        for row in rows
    )
