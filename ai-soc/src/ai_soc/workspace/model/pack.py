"""Build bounded, immutable incident evidence packs from exact persisted pins."""

from __future__ import annotations

from datetime import datetime
from typing import Any, cast
from uuid import UUID

import psycopg

from ai_soc.validation.findings import (
    BoundTextRejected,
)
from ai_soc.validation.findings import (
    _bound_display_text as _shared_bound_text,  # pyright: ignore[reportPrivateUsage]
)
from ai_soc.workspace.db import require_site_transaction
from ai_soc.workspace.model.schemas import (
    AlertFact,
    Coverage,
    FrozenIncidentPack,
    GroupFact,
    IncidentReference,
    fact_id,
    frozen_pack_digest,
    incident_reference_id,
)

MAX_GROUP_FACTS = 32
MAX_ALERT_FACTS = 32
MAX_PACK_BYTES = 64 * 1024
BUILDER_VERSION = "workspace.incident-narrative-pack.v1"


def _optional_label(value: object) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 256:
        return None
    try:
        return _shared_bound_text(value)
    except BoundTextRejected:
        return None


def _make_pack(
    *,
    site_id: str,
    incident_id: UUID,
    revision_id: UUID,
    revision_seq: int,
    as_of: datetime,
    membership_count: int,
    alert_count: int,
    score_unknown_count: int,
    group_facts: tuple[GroupFact, ...],
    alert_facts: tuple[AlertFact, ...],
) -> FrozenIncidentPack:
    coverage = Coverage(
        membership_count=membership_count,
        alert_count=alert_count,
        score_unknown_count=score_unknown_count,
        included_group_facts=len(group_facts),
        omitted_group_facts=membership_count - len(group_facts),
        included_alert_facts=len(alert_facts),
        omitted_alert_facts=alert_count - len(alert_facts),
    )
    provisional = FrozenIncidentPack.model_construct(
        site_id=site_id,
        incident_id=incident_id,
        incident_revision_id=revision_id,
        revision_seq=revision_seq,
        as_of=as_of,
        builder_version=BUILDER_VERSION,
        incident_reference=IncidentReference(
            site_id=site_id,
            incident_id=incident_id,
            incident_revision_id=revision_id,
            reference_id=incident_reference_id(site_id, incident_id, revision_id),
        ),
        coverage=coverage,
        group_facts=group_facts,
        alert_facts=alert_facts,
        content_digest="0" * 64,
    )
    return FrozenIncidentPack.model_validate(
        {
            **provisional.model_dump(mode="python"),
            "content_digest": frozen_pack_digest(provisional),
        }
    )


def build_incident_pack(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    incident_id: UUID,
    incident_revision_id: UUID,
) -> FrozenIncidentPack:
    """Freeze bounded facts from one exact incident evidence revision.

    Requires an active transaction for a known site. All evidence is resolved
    from immutable revision and score pins; current group heads are never read.
    """
    require_site_transaction(conn, site_id)
    revision_row = conn.execute(
        "SELECT e.revision_seq,e.as_of FROM incident_evidence_revisions e "
        "JOIN incidents i ON (i.site_id,i.incident_id)=(e.site_id,e.incident_id) "
        "WHERE e.site_id=%s AND e.incident_id=%s AND e.incident_revision_id=%s",
        (site_id, incident_id, incident_revision_id),
    ).fetchone()
    if revision_row is None:
        raise LookupError("incident evidence revision is unavailable")
    revision_seq = int(revision_row[0])
    as_of = cast(datetime, revision_row[1])
    member_rows = conn.execute(
        "SELECT irm.membership_id,irm.group_id,irm.group_revision,irm.score_version,"
        "irm.score_digest,irm.score,gr.first_ts,gr.last_ts,gr.alert_count,"
        "CASE WHEN length(gr.rule_id) BETWEEN 1 AND 256 THEN gr.rule_id END,"
        "CASE WHEN length(gr.agent_id) BETWEEN 1 AND 256 THEN gr.agent_id END "
        "FROM incident_revision_members irm JOIN group_revisions gr "
        "ON (gr.site_id,gr.group_id,gr.revision)="
        "(irm.site_id,irm.group_id,irm.group_revision) "
        "WHERE irm.site_id=%s AND irm.incident_id=%s AND irm.incident_revision_id=%s "
        "ORDER BY irm.group_id LIMIT 101",
        (site_id, incident_id, incident_revision_id),
    ).fetchall()
    membership_count = len(member_rows)
    if not 1 <= membership_count <= 100:
        raise ValueError("incident evidence must contain 1..100 exact member pins")

    all_group_facts: list[GroupFact] = []
    for row in member_rows:
        membership_id = UUID(str(row[0]))
        group_id = str(row[1])
        revision = str(row[2])
        score_version = None if row[3] is None else str(row[3])
        score_digest = None if row[4] is None else str(row[4])
        score = None if row[5] is None else float(row[5])
        all_group_facts.append(
            GroupFact(
                fact_id=fact_id(
                    "group",
                    site_id,
                    incident_id,
                    incident_revision_id,
                    membership_id,
                    group_id,
                    revision,
                ),
                membership_id=membership_id,
                group_id=group_id,
                group_revision=revision,
                alert_count=int(row[8]),
                first_event_at=cast(datetime, row[6]),
                last_event_at=cast(datetime, row[7]),
                rule_id=_optional_label(row[9]),
                agent_id=_optional_label(row[10]),
                score_version=score_version,
                score_digest=score_digest,
                score=score,
            )
        )
    total_alert_count = sum(group.alert_count for group in all_group_facts)
    score_unknown_count = sum(group.score is None for group in all_group_facts)
    group_facts = tuple(all_group_facts[:MAX_GROUP_FACTS])

    alert_rows: list[tuple[Any, ...]] = []
    if group_facts:
        alert_rows = conn.execute(
            "SELECT gm.group_id,gm.group_revision,gm.alert_key,gm.event_ts,gm.source_hash,"
            "CASE WHEN jsonb_typeof(gm.normalized_snapshot->'rule_id')='string' "
            "AND length(gm.normalized_snapshot->>'rule_id') BETWEEN 1 AND 256 "
            "THEN gm.normalized_snapshot->>'rule_id' END,"
            "CASE WHEN jsonb_typeof(gm.normalized_snapshot->'agent_id')='string' "
            "AND length(gm.normalized_snapshot->>'agent_id') BETWEEN 1 AND 256 "
            "THEN gm.normalized_snapshot->>'agent_id' END "
            "FROM unnest(%s::text[],%s::text[]) AS p(group_id,revision) "
            "JOIN group_members gm ON gm.site_id=%s AND gm.group_id=p.group_id "
            "AND gm.group_revision=p.revision ORDER BY gm.group_id,gm.alert_key LIMIT 33",
            (
                [group.group_id for group in group_facts],
                [group.group_revision for group in group_facts],
                site_id,
            ),
        ).fetchall()
    group_by_key = {(group.group_id, group.group_revision): group for group in group_facts}
    alert_fact_list: list[AlertFact] = []
    for row in alert_rows[:MAX_ALERT_FACTS]:
        group = group_by_key[(str(row[0]), str(row[1]))]
        alert_fact_list.append(
            AlertFact(
                fact_id=fact_id(
                    "alert",
                    site_id,
                    incident_id,
                    incident_revision_id,
                    str(row[0]),
                    str(row[1]),
                    str(row[2]),
                ),
                group_fact_id=group.fact_id,
                group_id=str(row[0]),
                group_revision=str(row[1]),
                alert_key=str(row[2]),
                source_hash=str(row[4]),
                event_at=cast(datetime, row[3]),
                rule_id=_optional_label(row[5]),
                agent_id=_optional_label(row[6]),
            )
        )
    alert_facts: tuple[AlertFact, ...] = tuple(alert_fact_list)

    while True:
        pack = _make_pack(
            site_id=site_id,
            incident_id=incident_id,
            revision_id=incident_revision_id,
            revision_seq=revision_seq,
            as_of=as_of,
            membership_count=membership_count,
            alert_count=total_alert_count,
            score_unknown_count=score_unknown_count,
            group_facts=group_facts,
            alert_facts=alert_facts,
        )
        if len(pack.canonical_bytes()) <= MAX_PACK_BYTES:
            return pack
        if alert_facts:
            alert_facts = alert_facts[:-1]
            continue
        if group_facts:
            removed_id = group_facts[-1].fact_id
            group_facts = group_facts[:-1]
            alert_facts = tuple(alert for alert in alert_facts if alert.group_fact_id != removed_id)
            continue
        raise ValueError("incident pack metadata exceeds the canonical byte limit")
