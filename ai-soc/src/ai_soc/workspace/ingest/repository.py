"""Site-scoped, immutable alert registry and payload writes."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from ai_soc.workspace.ingest.indexer_reader import IndexerHit
from ai_soc.workspace.jobs import enqueue_job
from ai_soc.workspace.normalize.models import MappingProfile
from ai_soc.workspace.normalize.normalizer import source_event_timestamp


class RegistryConflict(RuntimeError):
    """A source uniqueness conflict disagrees with the stable alert key."""


@dataclass(frozen=True, slots=True)
class InsertCounts:
    read: int
    inserted: int
    duplicates: int
    mutations: int


def alert_key(site_id: str, index_name: str, doc_id: str) -> str:
    if not site_id or not index_name or not doc_id:
        raise ValueError("site, index and document identity are required")
    identity = f"{site_id}\0{index_name}\0{doc_id}".encode()
    return hashlib.sha256(identity).hexdigest()


def canonical_source_hash(source: dict[str, Any]) -> str:
    try:
        canonical = json.dumps(
            source,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("indexer source is not canonical JSON") from exc
    return hashlib.sha256(canonical).hexdigest()


def insert_alert_page(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    index_pattern: str,
    run_id: str,
    hits: Sequence[IndexerHit],
    profile: MappingProfile,
) -> InsertCounts:
    """Insert new identities and payloads; changed identities become mutation evidence."""
    inserted = 0
    duplicates = 0
    mutations = 0
    if not index_pattern:
        raise ValueError("configured index pattern is required for source membership")
    for hit in hits:
        key = alert_key(site_id, hit.index_name, hit.doc_id)
        event_ts = source_event_timestamp(hit.source, profile)
        source_hash = canonical_source_hash(hit.source)
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO alert_registry
                    (site_id, alert_key, index_name, doc_id, original_event_ts, source_hash)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING
                RETURNING alert_key
                """,
                (site_id, key, hit.index_name, hit.doc_id, event_ts, source_hash),
            )
            created = cursor.fetchone() is not None
        if created:
            _record_source_membership(
                conn, site_id=site_id, index_pattern=index_pattern, alert_key=key
            )
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO alerts
                        (site_id, alert_key, event_ts, index_name, doc_id, raw, source_hash,
                         mapping_profile)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT DO NOTHING
                    RETURNING alert_key
                    """,
                    (
                        site_id,
                        key,
                        event_ts,
                        hit.index_name,
                        hit.doc_id,
                        Jsonb(hit.source),
                        source_hash,
                        profile.profile_id,
                    ),
                )
                if cursor.fetchone() is None:
                    raise RegistryConflict("new registry identity did not create one raw payload")
            enqueue_job(
                conn,
                site_id=site_id,
                kind="normalize_alert",
                subject=key,
                payload={
                    "alert_key": key,
                    "event_ts": event_ts.isoformat(),
                    "mapping_profile": profile.profile_id,
                },
            )
            inserted += 1
            continue

        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT alert_key, original_event_ts, source_hash
                FROM alert_registry
                WHERE site_id = %s AND (alert_key = %s OR (index_name = %s AND doc_id = %s))
                """,
                (site_id, key, hit.index_name, hit.doc_id),
            )
            existing = cursor.fetchone()
        if existing is None or existing[0] != key:
            raise RegistryConflict("source identity conflicts with a different stable key")
        original_event_ts = existing[1]
        original_source_hash = str(existing[2])
        if original_event_ts != event_ts or original_source_hash != source_hash:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO alert_mutations
                        (site_id, alert_key, observed_event_ts, observed_source_hash)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT DO NOTHING
                    RETURNING mutation_id
                    """,
                    (site_id, key, event_ts, source_hash),
                )
                if cursor.fetchone() is not None:
                    mutations += 1
        _record_source_membership(conn, site_id=site_id, index_pattern=index_pattern, alert_key=key)
        duplicates += 1

    counts = InsertCounts(len(hits), inserted, duplicates, mutations)
    with conn.cursor() as cursor:
        cursor.execute(
            """
            UPDATE pipeline_runs
            SET read_count = COALESCE(read_count, 0) + %s,
                inserted_count = COALESCE(inserted_count, 0) + %s,
                duplicate_count = COALESCE(duplicate_count, 0) + %s,
                mutation_count = mutation_count + %s
            WHERE site_id = %s AND run_id = %s
            """,
            (counts.read, counts.inserted, counts.duplicates, counts.mutations, site_id, run_id),
        )
        if cursor.rowcount != 1:
            raise RuntimeError("pipeline run is unavailable in the active site transaction")
    return counts


def _record_source_membership(
    conn: psycopg.Connection[Any], *, site_id: str, index_pattern: str, alert_key: str
) -> None:
    conn.execute(
        """
        INSERT INTO alert_sources (site_id, index_pattern, alert_key)
        VALUES (%s, %s, %s)
        ON CONFLICT DO NOTHING
        """,
        (site_id, index_pattern, alert_key),
    )
