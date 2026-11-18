"""Freeze the matched and missing stages from one published correlation revision."""

from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Any
from uuid import UUID

import psycopg

from ai_soc.contracts.canonical import evidence_id, sha256_hex
from ai_soc.workspace.assessment.pack import EvidenceItem, EvidencePack, EvidenceValue, PackScore
from ai_soc.workspace.db import require_site_transaction


@dataclass(frozen=True, slots=True)
class ChainPin:
    chain_id: str
    revision: str
    manifest_id: UUID

    def key(self, catalog_digest: str) -> str:
        return sha256_hex(
            ["chain", self.chain_id, self.revision, str(self.manifest_id), catalog_digest]
        )


def build_chain_pack(
    conn: psycopg.Connection[Any], *, site_id: str, pin: ChainPin
) -> tuple[EvidencePack, str]:
    require_site_transaction(conn, site_id)
    params = (site_id, pin.chain_id, pin.revision, pin.manifest_id)
    subject = conn.execute(
        """
        SELECT r.anchor_group_id, r.anchor_group_revision, r.rule_id, m.as_of,
               g.score_version, g.score_digest, g.score
        FROM correlation_chain_revisions r
        JOIN correlation_manifests m USING (site_id, manifest_id)
        JOIN correlation_input_groups g ON g.site_id = r.site_id
            AND g.manifest_id = r.manifest_id AND g.group_id = r.anchor_group_id
            AND g.group_revision = r.anchor_group_revision
        WHERE (r.site_id, r.chain_id, r.revision_digest, r.manifest_id) = (%s,%s,%s,%s)
          AND r.result->>'is_candidate' = 'true'
        """,
        params,
    ).fetchone()
    if subject is None or any(value is None for value in subject[4:]):
        raise LookupError("chain assessment requires an exact candidate and anchor score")
    group_id, group_revision, rule_family, as_of, version, digest, total = subject
    stages = conn.execute(
        """
        SELECT ordinal,stage_id,outcome,alert_key,event_ts,confidence,group_id,group_revision
        FROM correlation_stage_evidence
        WHERE (site_id, chain_id, revision_digest, manifest_id) = (%s,%s,%s,%s)
        ORDER BY ordinal
        """,
        params,
    ).fetchall()
    scope = sha256_hex([site_id, pin.chain_id, pin.revision, str(pin.manifest_id)])
    items: list[EvidenceItem] = []
    for ordinal, stage_id, outcome, alert, event_time, confidence, group, revision in stages:
        fields: dict[str, EvidenceValue] = {
            "ordinal": ordinal,
            "stage_id": stage_id,
            "outcome": outcome,
        }
        if outcome == "matched":
            assert isinstance(event_time, datetime)
            fields.update(
                alert_key=alert,
                event_time=event_time.isoformat(),
                confidence=confidence,
                group_id=group,
                group_revision=revision,
            )
        stage_evidence_id = evidence_id(
            question_id=pin.chain_id,
            environment_id=site_id,
            topic_id="workspace.chain-assessment-pack.v1",
            fetch_id="stages",
            check_id=None,
            kind="stage",
            source=ordinal,
            snapshot_key=scope,
            values=fields,
        )
        items.append(
            EvidenceItem(stage_evidence_id, "stage", MappingProxyType(fields), "stages", scope)
        )
    pack = EvidencePack(
        site_id=site_id,
        group_id=group_id,
        revision=pin.revision,
        as_of=as_of,
        member_count=len(items),
        rule_family=rule_family,
        gaps=MappingProxyType(
            {
                "stages": "present"
                if items and all(row[2] == "matched" for row in stages)
                else "stale"
            }
        ),
        missing_fields=(),
        trimmed=False,
        has_excerpt=False,
        items=tuple(items),
        score=PackScore(
            computation_version=version, input_digest=digest, total=total, components=()
        ),
        digest="0" * 64,
        chain_id=pin.chain_id,
        manifest_id=str(pin.manifest_id),
    ).with_digest()
    return pack, group_revision
