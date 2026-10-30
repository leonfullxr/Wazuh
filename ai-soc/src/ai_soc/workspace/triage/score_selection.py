"""Select authoritative scores for bounded, exact group revision pins."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, LiteralString, cast

import psycopg

from ai_soc.workspace.api.repository import (
    _score_intent_job_id_sql,  # pyright: ignore[reportPrivateUsage]
)
from ai_soc.workspace.db import require_site_transaction


@dataclass(frozen=True, slots=True)
class ScoreReference:
    computation_version: str
    input_digest: str
    total: float
    frozen_as_of: datetime
    intent_job_id: int


def _timestamp_sql(expression: str) -> str:
    # PostgreSQL accepts zone-less timestamps using the session timezone. Such
    # inputs are not a frozen instant and must remain unavailable here.
    return (
        f"CASE WHEN {expression} ~ '(Z|[+-][0-9]{{2}}:[0-9]{{2}})$' "
        f"AND pg_input_is_valid({expression}, 'timestamp with time zone') "
        f"THEN ({expression})::timestamptz END"
    )


def select_score_references(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    group_revisions: tuple[tuple[str, str], ...],
    as_of: datetime,
) -> dict[tuple[str, str], ScoreReference]:
    """Select at most one completed score per exact pin in one bulk query.

    Requires an active authorized site transaction and at most 512 unique pairs.
    Missing, malformed, naive or future frozen cutoffs and missing completed
    provenance are unavailable (absent keys), never a measured zero. Physical
    Computation must have occurred by this knowledge cutoff. It may be later
    than the score's own frozen input cutoff for legitimate delayed work.
    """
    require_site_transaction(conn, site_id)
    if as_of.tzinfo is None or as_of.utcoffset() is None:
        raise ValueError("as_of must be timezone-aware")
    if len(group_revisions) > 512 or len(set(group_revisions)) != len(group_revisions):
        raise ValueError("score selection requires at most 512 unique revision pairs")
    if any(not group or not revision for group, revision in group_revisions):
        raise ValueError("group and revision pins must be nonempty")
    if not group_revisions:
        return {}
    frozen = _timestamp_sql("sm.manifest->>'as_of'")
    intent = _score_intent_job_id_sql("s", completed_before_cutoff=True)
    query = cast(
        LiteralString,
        "SELECT p.group_id,p.revision,chosen.computation_version,chosen.input_digest,"
        "chosen.total,chosen.frozen_as_of,chosen.intent_job_id "
        "FROM unnest(%s::text[],%s::text[]) AS p(group_id,revision) "
        "CROSS JOIN LATERAL (SELECT ranked.* FROM ("
        "SELECT s.computation_version,s.input_digest,s.total,s.computed_at,"
        + frozen
        + " AS frozen_as_of,"
        + intent
        + " AS intent_job_id FROM scores s JOIN score_manifests sm "
        "USING(site_id,group_id,group_revision,computation_version,input_digest) "
        "WHERE s.site_id=%s AND s.group_id=p.group_id AND s.group_revision=p.revision "
        "AND s.computed_at<=%s"
        ") ranked WHERE ranked.frozen_as_of<=%s AND ranked.intent_job_id>0 "
        "ORDER BY ranked.frozen_as_of DESC,ranked.intent_job_id DESC,"
        "ranked.computed_at DESC,ranked.computation_version DESC,ranked.input_digest DESC "
        "LIMIT 1) chosen",
    )
    rows = conn.execute(
        query,
        (
            [group for group, _ in group_revisions],
            [revision for _, revision in group_revisions],
            as_of,
            site_id,
            as_of,
            as_of,
        ),
    ).fetchall()
    return {
        (str(group), str(revision)): ScoreReference(
            str(version), str(digest), float(total), cutoff, int(job)
        )
        for group, revision, version, digest, total, cutoff, job in rows
    }
