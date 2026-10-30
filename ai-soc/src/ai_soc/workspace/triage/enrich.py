"""Frozen, provenance-preserving context snapshots and deterministic score storage."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Literal, Protocol, cast
from uuid import UUID, uuid5

import psycopg
from psycopg.pq import TransactionStatus
from psycopg.types.json import Jsonb

from ai_soc.content.kev import KevLookupIndex, freshness, lookup_kev
from ai_soc.workspace.triage.composites import CompositePolicy, load_composite_policy
from ai_soc.workspace.triage.score import (
    SCORE_VERSION,
    FrozenContext,
    ScoreInputs,
    ScoreResult,
    ScoreWeights,
    score_group,
)

Availability = Literal["available", "unavailable", "stale"]
_SNAPSHOT_NAMESPACE = UUID("e830b3db-924b-451d-9674-4b0dc4fccfd8")


@dataclass(frozen=True, slots=True)
class EnrichmentRecord:
    enrichment_id: UUID
    site_id: str
    group_id: str
    group_revision: str
    source: str
    source_version: str
    availability: Availability
    value: dict[str, Any]
    fetched_at: datetime
    expires_at: datetime | None


@dataclass(frozen=True, slots=True)
class FrozenEnrichmentSnapshot:
    site_id: str
    group_id: str
    group_revision: str
    as_of: datetime
    records: tuple[EnrichmentRecord, ...]

    @property
    def evidence_ids(self) -> tuple[str, ...]:
        return tuple(str(record.enrichment_id) for record in self.records)


@dataclass(frozen=True, slots=True)
class ContextObservation:
    source_version: str
    availability: Availability
    value: dict[str, Any]
    fetched_at: datetime
    expires_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class OpenVulnerabilitySnapshot:
    agent_id: str
    cves: tuple[str, ...]
    source_version: str
    fetched_at: datetime
    expires_at: datetime | None
    availability: Availability = "available"
    site_id: str = ""
    source_id: str = ""
    source_sha256: str = ""


class KevSnapshotAdapter:
    """Join an approved offline KEV index to a frozen open-vulnerability snapshot."""

    def __init__(
        self,
        index: KevLookupIndex | None,
        open_vulnerabilities: Mapping[tuple[str, str], OpenVulnerabilitySnapshot],
        *,
        source_id: str = "approved-kev-pack",
        source_sha256: str = "unversioned",
        open_vulnerability_source_id: str | None = None,
        open_vulnerability_source_sha256: str | None = None,
    ) -> None:
        self._index = index
        self._open_vulnerabilities = dict(open_vulnerabilities)
        self._source_id = source_id
        self._source_sha256 = source_sha256
        self._open_vulnerability_source_id = open_vulnerability_source_id
        self._open_vulnerability_source_sha256 = open_vulnerability_source_sha256
        if any(
            key != (value.site_id, value.agent_id)
            for key, value in self._open_vulnerabilities.items()
        ):
            raise ValueError("open-vulnerability keys must match site and agent identity")

    def fetch(
        self,
        *,
        site_id: str,
        group_id: str,
        group_revision: str,
        member_snapshots: tuple[dict[str, Any], ...],
        as_of: datetime,
    ) -> ContextObservation:
        del group_id, group_revision
        metadata = {
            "source_id": self._source_id,
            "source_sha256": self._source_sha256,
            "open_vulnerability_source_id": self._open_vulnerability_source_id,
            "open_vulnerability_source_sha256": self._open_vulnerability_source_sha256,
        }
        source_version = (
            f"cisa-kev:{self._source_id}:sha256:{self._source_sha256}:"
            f"vuln:{self._open_vulnerability_source_id}:"
            f"sha256:{self._open_vulnerability_source_sha256}"
        )
        if self._index is None:
            return ContextObservation(
                source_version=source_version,
                availability="unavailable",
                value={"reason": "approved KEV snapshot is not loaded", **metadata},
                fetched_at=as_of,
            )
        snapshot = self._index.snapshot
        freshness_state, valid_from, expires_at = freshness(snapshot, as_of)
        if freshness_state != "fresh":
            return ContextObservation(
                source_version=source_version + f":{snapshot.metadata.catalog_version}",
                availability="stale",
                value={
                    "reason": f"KEV snapshot is {freshness_state}",
                    "valid_from": valid_from.isoformat(),
                    **metadata,
                },
                fetched_at=snapshot.metadata.retrieved_at,
                expires_at=expires_at,
            )
        agent_ids = sorted(
            {
                str(member["agent_id"])
                for member in member_snapshots
                if isinstance(member.get("agent_id"), str) and member["agent_id"]
            }
        )
        if not agent_ids:
            return ContextObservation(
                source_version=source_version,
                availability="unavailable",
                value={"reason": "group has no agent identity", **metadata},
                fetched_at=as_of,
            )
        open_snapshots = [
            self._open_vulnerabilities.get((site_id, agent_id)) for agent_id in agent_ids
        ]
        if any(record is None for record in open_snapshots):
            return ContextObservation(
                source_version=source_version,
                availability="unavailable",
                value={
                    "reason": "as-of open-vulnerability state is unavailable for a group agent",
                    **metadata,
                },
                fetched_at=as_of,
            )
        records = cast(list[OpenVulnerabilitySnapshot], open_snapshots)
        if any(
            record.site_id != site_id or record.agent_id != agent_id
            for record, agent_id in zip(records, agent_ids, strict=True)
        ):
            return ContextObservation(
                source_version=source_version,
                availability="unavailable",
                value={
                    "reason": "open-vulnerability identity does not match the group site",
                    **metadata,
                },
                fetched_at=as_of,
            )
        if any(record.availability != "available" for record in records):
            return ContextObservation(
                source_version=source_version,
                availability="unavailable",
                value={"reason": "open-vulnerability source is unavailable", **metadata},
                fetched_at=as_of,
            )
        if any(
            record.fetched_at > as_of
            or (record.expires_at is not None and record.expires_at <= as_of)
            for record in records
        ):
            return ContextObservation(
                source_version=source_version + f":{snapshot.metadata.catalog_version}",
                availability="stale",
                value={
                    "reason": "open-vulnerability snapshot is outside its frozen validity",
                    **metadata,
                },
                fetched_at=max(record.fetched_at for record in records),
                expires_at=min(
                    (record.expires_at for record in records if record.expires_at),
                    default=expires_at,
                ),
            )
        cves = sorted({cve for record in records for cve in record.cves})
        hits = [cve for cve in cves if lookup_kev(self._index, cve)[0] == "hit"]
        fetched_at = max(
            snapshot.metadata.retrieved_at,
            *(record.fetched_at for record in records),
        )
        expiries = [
            expires_at,
            *(record.expires_at for record in records if record.expires_at),
        ]
        return ContextObservation(
            source_version=(
                f"{source_version}:{snapshot.metadata.catalog_version}+"
                f"{','.join(sorted({record.source_version for record in records}))}+"
                f"{','.join(sorted({record.source_sha256 for record in records}))}"
            ),
            availability="available",
            value={
                "score_value": float(bool(hits)),
                "open_cve_count": len(cves),
                "kev_cves": hits,
                "affected_state": "unknown",
                "open_vulnerability_source_ids": sorted({record.source_id for record in records}),
                "open_vulnerability_source_sha256": sorted(
                    {record.source_sha256 for record in records}
                ),
                "open_vulnerability_source_versions": sorted(
                    {record.source_version for record in records}
                ),
                **metadata,
            },
            fetched_at=fetched_at,
            expires_at=min(expiries),
        )


class ContextAdapter(Protocol):
    def fetch(
        self,
        *,
        site_id: str,
        group_id: str,
        group_revision: str,
        member_snapshots: tuple[dict[str, Any], ...],
        as_of: datetime,
    ) -> ContextObservation: ...


class FrozenSnapshotConflict(RuntimeError):
    """The same immutable cutoff produced different source evidence on retry."""


def enrich_group(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    group_id: str,
    group_revision: str,
    as_of: datetime,
    adapters: dict[str, ContextAdapter] | None = None,
    context_revision: str | None = None,
    geoip_version: str | None = None,
    now: datetime | None = None,
) -> FrozenEnrichmentSnapshot:
    """Persist as-of local and injected context; absent providers remain unavailable.

    Vulnerability, KEV, and offline GeoIP data are provider ports. There is no network
    fallback, and a provider result fetched after `as_of` is retained as stale.
    """
    _require_site(conn, site_id)
    _aware(as_of, "as_of")
    captured_at = as_of if now is None else now
    _aware(captured_at, "now")
    group_row = conn.execute(
        """
        SELECT g.bucket_start, gr.rule_id, gr.agent_id, gr.primary_entity
        FROM group_revisions AS gr JOIN groups AS g USING (site_id, group_id)
        WHERE gr.site_id = %s AND gr.group_id = %s AND gr.revision = %s
        """,
        (site_id, group_id, group_revision),
    ).fetchone()
    if group_row is None:
        raise LookupError("group revision does not exist in this site")
    bucket_start, rule_id, agent_id, primary_entity = group_row
    member_rows = conn.execute(
        """
        SELECT normalized_snapshot FROM group_members
        WHERE site_id = %s AND group_id = %s AND group_revision = %s AND event_ts <= %s
        ORDER BY alert_key
        """,
        (site_id, group_id, group_revision, as_of),
    ).fetchall()
    member_snapshots = tuple(cast(dict[str, Any], row[0]) for row in member_rows)
    if not member_snapshots:
        raise RuntimeError("group revision has no retained member snapshots")

    observations: list[tuple[str, ContextObservation]] = [
        ("prevalence", _prevalence(conn, site_id, rule_id, agent_id, as_of)),
        ("first_seen", _first_seen(conn, site_id, primary_entity, bucket_start, as_of)),
        ("asset", _asset(conn, site_id, agent_id, member_snapshots, as_of)),
        ("privilege", _privilege(member_snapshots, as_of)),
        (
            "geoip",
            _provider_observation(
                "geoip",
                (adapters or {}).get("geoip"),
                site_id,
                group_id,
                group_revision,
                member_snapshots,
                as_of,
                default_version=geoip_version or "unconfigured",
            ),
        ),
        (
            "vuln",
            _provider_observation(
                "vuln",
                (adapters or {}).get("vuln"),
                site_id,
                group_id,
                group_revision,
                member_snapshots,
                as_of,
                default_version="unconfigured",
            ),
        ),
        (
            "kev",
            _provider_observation(
                "kev",
                (adapters or {}).get("kev"),
                site_id,
                group_id,
                group_revision,
                member_snapshots,
                as_of,
                default_version="unconfigured",
            ),
        ),
        (
            "known_noise",
            _provider_observation(
                "known_noise",
                (adapters or {}).get("known_noise"),
                site_id,
                group_id,
                group_revision,
                member_snapshots,
                as_of,
                default_version="unconfigured",
            ),
        ),
    ]
    records: list[EnrichmentRecord] = []
    for source, observation in observations:
        if observation.fetched_at > as_of and observation.availability == "available":
            observation = ContextObservation(
                source_version=observation.source_version,
                availability="stale",
                value={
                    "reason": "source snapshot is newer than frozen as_of",
                    "observed": observation.value,
                },
                fetched_at=observation.fetched_at,
                expires_at=observation.expires_at,
            )
        if (
            observation.expires_at is not None
            and observation.expires_at <= as_of
            and observation.availability == "available"
        ):
            observation = ContextObservation(
                source_version=observation.source_version,
                availability="stale",
                value={
                    "reason": "source snapshot expired by frozen as_of",
                    "observed": observation.value,
                },
                fetched_at=observation.fetched_at,
                expires_at=observation.expires_at,
            )
        record_id = uuid5(
            _SNAPSHOT_NAMESPACE,
            (
                f"{site_id}|{group_id}|{group_revision}|{source}|{as_of.isoformat()}"
                if context_revision is None
                else f"{site_id}|{group_id}|{group_revision}|{source}|"
                f"{as_of.isoformat()}|bundle:{context_revision}"
            ),
        )
        record = EnrichmentRecord(
            enrichment_id=record_id,
            site_id=site_id,
            group_id=group_id,
            group_revision=group_revision,
            source=source,
            source_version=observation.source_version,
            availability=observation.availability,
            value=(
                observation.value
                if context_revision is None
                else {
                    **observation.value,
                    "context_bundle_sha256": context_revision,
                }
            ),
            fetched_at=observation.fetched_at,
            expires_at=observation.expires_at,
        )
        _insert_frozen_enrichment(conn, record)
        records.append(record)
    return FrozenEnrichmentSnapshot(site_id, group_id, group_revision, as_of, tuple(records))


def score_group_snapshot(
    conn: psycopg.Connection[Any],
    *,
    snapshot: FrozenEnrichmentSnapshot,
    weights: ScoreWeights,
    computation_version: str = SCORE_VERSION,
    wazuh_version: str | None = None,
    code_hash: str,
    content_hash: str,
    now: datetime,
) -> ScoreResult:
    """Create the immutable score manifest and result from persisted frozen evidence."""
    site_id, group_id, group_revision = snapshot.site_id, snapshot.group_id, snapshot.group_revision
    _require_site(conn, site_id)
    _aware(now, "now")
    validate_frozen_enrichment_snapshot(conn, snapshot)
    row = conn.execute(
        """
        SELECT gr.agent_id, g.bucket_start
        FROM group_revisions AS gr JOIN groups AS g USING (site_id, group_id)
        WHERE gr.site_id = %s AND gr.group_id = %s AND gr.revision = %s
        """,
        (site_id, group_id, group_revision),
    ).fetchone()
    if row is None:
        raise LookupError("score references an unknown group revision")
    agent_id, bucket_start = row
    member_rows = conn.execute(
        """
        SELECT alert_key, normalized_snapshot FROM group_members
        WHERE site_id = %s AND group_id = %s AND group_revision = %s AND event_ts <= %s
        ORDER BY alert_key
        """,
        (site_id, group_id, group_revision, snapshot.as_of),
    ).fetchall()
    members = [(str(key), cast(dict[str, Any], data)) for key, data in member_rows]
    levels: list[tuple[int, str]] = []
    for key, member in members:
        value = member.get("rule_level")
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 15:
            levels.append((value, key))
    top_level = max((item[0] for item in levels), default=None)
    rule_evidence = tuple(f"alert:{key}" for level, key in levels if level == top_level)
    values = {record.source: record for record in snapshot.records}
    contexts = frozen_score_contexts(snapshot)
    prevalence_record = values.get("prevalence")
    prevalence = (
        prevalence_record.value
        if prevalence_record is not None and prevalence_record.availability == "available"
        else None
    )
    rule_count = _count(prevalence, "rule_count")
    alert_count = _count(prevalence, "alert_count")
    prevalence_ids = (
        ()
        if rule_count is None or prevalence_record is None
        else (str(prevalence_record.enrichment_id),)
    )
    composite_policy = load_composite_policy(wazuh_version)
    bucket_closed = snapshot.as_of >= bucket_start + timedelta(hours=1)
    composite_available = bucket_closed and composite_policy.available
    composite_unavailable_reason = (
        None
        if composite_available
        else "bucket_not_closed"
        if not bucket_closed
        else "composite_policy_unavailable"
    )
    composite_evidence: tuple[str, ...] = ()
    composite_overlap = False
    if composite_available:
        evidence = _confirmed_composite_overlap(
            conn,
            site_id=site_id,
            group_id=group_id,
            group_revision=group_revision,
            agent_id=agent_id,
            primary_entity=_revision_primary_entity(conn, site_id, group_id, group_revision),
            bucket_start=bucket_start,
            as_of=snapshot.as_of,
            policy=composite_policy,
        )
        if evidence is not None:
            composite_overlap = True
            composite_evidence = (evidence,)
    inputs = ScoreInputs(
        site_id=site_id,
        group_id=group_id,
        group_revision=group_revision,
        as_of=snapshot.as_of,
        weights=weights,
        rule_level=top_level,
        rule_evidence_ids=rule_evidence,
        rule_on_agent_30d=rule_count,
        alerts_on_agent_30d=alert_count,
        prevalence_evidence_ids=prevalence_ids,
        contexts=tuple(contexts),
        composite_evidence_ids=composite_evidence,
        composite_overlap=composite_overlap,
    )
    result = score_group(inputs, computation_version=computation_version)
    asset_record = values.get("asset")
    bundle_values = [record.value.get("context_bundle_sha256") for record in snapshot.records]
    bundle_hashes = {value for value in bundle_values if isinstance(value, str)}
    has_missing_bundle = bundle_hashes and any(
        not isinstance(value, str) for value in bundle_values
    )
    if len(bundle_hashes) > 1 or has_missing_bundle:
        raise ValueError("score evidence contains inconsistent context bundle identities")
    manifest = {
        "site_id": site_id,
        "group_id": group_id,
        "group_revision": group_revision,
        "as_of": snapshot.as_of.isoformat(),
        "context_bundle_sha256": next(iter(bundle_hashes), None),
        "enrichment_ids": [str(record.enrichment_id) for record in snapshot.records],
        "asset_revision": None if asset_record is None else asset_record.value.get("revision"),
        "weights": weights.model_dump(mode="json"),
        "computation_version": computation_version,
        "content_hash": content_hash,
        "code_hash": code_hash,
        "input_digest": result.input_digest,
        "member_evidence_ids": [f"alert:{key}" for key, _ in members],
        "score_inputs": inputs.model_dump(mode="json"),
        "score_output": result.model_dump(mode="json"),
        "presentation_version": "workspace.score-display.v1",
        "composite_available": composite_available,
        "composite_unavailable_reason": composite_unavailable_reason,
        "composite_policy": composite_policy.document(),
        "composite_policy_sha256": composite_policy.digest,
    }
    conn.execute(
        """
        INSERT INTO score_manifests
            (site_id, group_id, group_revision, computation_version, input_digest,
             manifest, created_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT DO NOTHING
        """,
        (
            site_id,
            group_id,
            group_revision,
            computation_version,
            result.input_digest,
            Jsonb(manifest),
            now,
        ),
    )
    stored_manifest = conn.execute(
        """SELECT manifest FROM score_manifests
           WHERE site_id = %s AND group_id = %s AND group_revision = %s
             AND computation_version = %s AND input_digest = %s""",
        (site_id, group_id, group_revision, computation_version, result.input_digest),
    ).fetchone()
    if stored_manifest is None or stored_manifest[0] != manifest:
        raise FrozenSnapshotConflict("same score key already has a different frozen manifest")
    components = score_display_components(
        result,
        composite_available=composite_available,
        composite_unavailable_reason=composite_unavailable_reason,
    )
    conn.execute(
        """
        INSERT INTO scores
            (site_id, group_id, group_revision, computation_version, input_digest,
             total, components, computed_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT DO NOTHING
        """,
        (
            site_id,
            group_id,
            group_revision,
            computation_version,
            result.input_digest,
            result.total,
            Jsonb(components),
            now,
        ),
    )
    return result


def score_display_components(
    result: ScoreResult,
    *,
    composite_available: bool,
    composite_unavailable_reason: str | None = None,
) -> list[dict[str, Any]]:
    """Versioned M2 availability presentation retained alongside exact score inputs."""
    components = [_score_component_json(item) for item in result.components]
    # M3 is not present yet. Preserve that as unknown, not a measured zero.
    for component in components:
        if component["name"] == "chain_strength":
            component.update(
                value=None,
                available=False,
                evidence_ids=[],
                explanation="Chain scoring is unavailable before M3",
            )
        if component["name"] == "composite_overlap" and not composite_available:
            explanations: dict[str, str] = {
                "bucket_not_closed": "Composite overlap is unavailable before the bucket closes",
                "composite_policy_unavailable": (
                    "Composite overlap policy is unavailable for this Wazuh release"
                ),
            }
            explanation = explanations.get(
                composite_unavailable_reason or "",
                "Composite overlap is unavailable before the bucket closes",
            )
            component.update(
                value=None,
                available=False,
                evidence_ids=[],
                explanation=explanation,
            )
        elif component["name"] == "composite_overlap" and not result.inputs.composite_overlap:
            component.update(
                value=None,
                available=False,
                evidence_ids=[],
                explanation="No same-bucket composite group confirmed this overlap",
            )
    return components


def frozen_score_contexts(snapshot: FrozenEnrichmentSnapshot) -> tuple[FrozenContext, ...]:
    """Project scoring contexts only from the supplied frozen source cohort."""
    values = {record.source: record for record in snapshot.records}
    contexts: list[FrozenContext] = []
    for source in ("asset", "privilege", "first_seen", "kev", "vuln", "known_noise"):
        record = values.get(source)
        if record is None or record.fetched_at > snapshot.as_of:
            continue
        score_value = _score_value(record) if record.availability == "available" else None
        availability = record.availability if score_value is not None else "unavailable"
        contexts.append(
            FrozenContext(
                source=source,
                source_version=record.source_version,
                evidence_id=str(record.enrichment_id),
                fetched_at=record.fetched_at,
                expires_at=record.expires_at,
                availability=availability,
                value=score_value,
            )
        )
    return tuple(contexts)


def _prevalence(
    conn: psycopg.Connection[Any],
    site_id: str,
    rule_id: str | None,
    agent_id: str | None,
    as_of: datetime,
) -> ContextObservation:
    if not rule_id or not agent_id:
        return _unavailable("prevalence", "rule or agent identity is missing", as_of)
    start = as_of - timedelta(days=30)
    row = conn.execute(
        """
        SELECT count(*), count(*) FILTER (WHERE a.normalized->>'rule_id' = %s)
        FROM alerts AS a
        WHERE a.site_id = %s AND a.event_ts >= %s AND a.event_ts < %s
          AND a.ingested_at <= %s
          AND a.normalized_at IS NOT NULL AND a.normalized->>'agent_id' = %s
        """,
        (rule_id, site_id, start, as_of, as_of, agent_id),
    ).fetchone()
    site_row = conn.execute(
        """
        SELECT count(*), count(*) FILTER (WHERE normalized->>'rule_id' = %s),
               count(DISTINCT normalized->>'agent_id') FILTER (WHERE normalized->>'rule_id' = %s)
        FROM alerts WHERE site_id = %s AND event_ts >= %s AND event_ts < %s
          AND ingested_at <= %s
          AND normalized_at IS NOT NULL
        """,
        (rule_id, rule_id, site_id, start, as_of, as_of),
    ).fetchone()
    registry_count_row = conn.execute(
        """SELECT count(*) FROM alert_registry
           WHERE site_id = %s AND original_event_ts >= %s AND original_event_ts < %s
             AND first_seen_at <= %s""",
        (site_id, start, as_of, as_of),
    ).fetchone()
    if row is None or site_row is None or registry_count_row is None:
        return _unavailable("prevalence", "history query returned no aggregate row", as_of)
    retained_count = int(row[0])
    site_alert_count = int(site_row[0])
    if site_alert_count != int(registry_count_row[0]):
        return _unavailable("prevalence", "not all as-of alert payloads are retained", as_of)
    return ContextObservation(
        source_version="workspace.alert_history.v1",
        availability="available",
        value={
            "alert_count": retained_count,
            "rule_count": int(row[1]),
            "site_alert_count": site_alert_count,
            "site_rule_count": int(site_row[1]),
            "distinct_agents_rule": int(site_row[2]),
            "window_from": start.isoformat(),
            "window_to": as_of.isoformat(),
            "agent_id": agent_id,
            "rule_id": rule_id,
        },
        fetched_at=as_of,
    )


def _first_seen(
    conn: psycopg.Connection[Any],
    site_id: str,
    primary_entity: str | None,
    bucket_start: datetime,
    as_of: datetime,
) -> ContextObservation:
    if not primary_entity or ":" not in primary_entity:
        return _unavailable("first_seen", "group has no primary entity", as_of)
    kind, value = primary_entity.split(":", 1)
    row = conn.execute(
        """
        SELECT min(ar.original_event_ts)
        FROM entities AS e JOIN alert_entities AS ae
          ON (ae.site_id, ae.entity_id) = (e.site_id, e.entity_id)
        JOIN alert_registry AS ar
          ON (ar.site_id, ar.alert_key, ar.original_event_ts) =
             (ae.site_id, ae.alert_key, ae.event_ts)
        WHERE e.site_id = %s AND e.kind = %s AND lower(e.value_norm) = lower(%s)
          AND ar.original_event_ts < %s AND ar.first_seen_at <= %s
        """,
        (site_id, kind, value, as_of, as_of),
    ).fetchone()
    first = None if row is None else row[0]
    if first is None:
        return _unavailable("first_seen", "entity history is not retained", as_of)
    return ContextObservation(
        source_version="workspace.entity_history.v1",
        availability="available",
        value={
            "is_first_seen_in_bucket": first >= bucket_start,
            "first_seen_at": first.isoformat(),
            "entity_kind": kind,
            "entity_value": value,
        },
        fetched_at=as_of,
    )


def _asset(
    conn: psycopg.Connection[Any],
    site_id: str,
    agent_id: str | None,
    members: tuple[dict[str, Any], ...],
    as_of: datetime,
) -> ContextObservation:
    if not agent_id:
        return _unavailable("asset", "group has no agent identity", as_of)
    host_values = {agent_id.casefold()}
    for member in members:
        member_agent = member.get("agent_id")
        if isinstance(member_agent, str) and member_agent.casefold() == agent_id.casefold():
            member_name = member.get("agent_name")
            if isinstance(member_name, str) and member_name:
                host_values.add(member_name.casefold())
    row = conn.execute(
        """
        SELECT at.entity_id, at.revision, at.criticality, at.tags, at.set_at
        FROM entities AS e JOIN asset_tags AS at USING (site_id, entity_id)
        WHERE e.site_id = %s AND e.kind = 'host' AND e.value_norm = ANY(%s)
          AND at.set_at <= %s
        ORDER BY at.set_at DESC,
                 CASE WHEN e.value_norm = %s THEN 0 ELSE 1 END,
                 e.entity_id, at.revision DESC
        LIMIT 1
        """,
        (site_id, sorted(host_values), as_of, agent_id.casefold()),
    ).fetchone()
    if row is None:
        return _unavailable("asset", "no operator tag exists as of cutoff", as_of)
    return ContextObservation(
        source_version="operator.asset_tag.v1",
        availability="available",
        value={
            "entity_id": int(row[0]),
            "revision": int(row[1]),
            "criticality": int(row[2]),
            "tags": list(row[3]),
            "criticality_fraction": int(row[2]) / 3,
            "set_at": row[4].isoformat(),
        },
        fetched_at=row[4],
    )


_REQUIRED_ENRICHMENT_SOURCES = frozenset(
    {"prevalence", "first_seen", "asset", "privilege", "geoip", "vuln", "kev", "known_noise"}
)


def validate_frozen_enrichment_snapshot(
    conn: psycopg.Connection[Any], snapshot: FrozenEnrichmentSnapshot
) -> None:
    """Prove the supplied complete cohort exactly matches retained immutable rows."""
    _require_site(conn, snapshot.site_id)
    _aware(snapshot.as_of, "snapshot.as_of")
    records = snapshot.records
    ids = [record.enrichment_id for record in records]
    sources = [record.source for record in records]
    if len(ids) != len(set(ids)):
        raise ValueError("frozen enrichment snapshot contains duplicate evidence ids")
    if len(sources) != len(set(sources)) or frozenset(sources) != _REQUIRED_ENRICHMENT_SOURCES:
        raise ValueError("frozen enrichment snapshot does not contain the complete source cohort")
    for record in records:
        if (
            record.site_id != snapshot.site_id
            or record.group_id != snapshot.group_id
            or record.group_revision != snapshot.group_revision
        ):
            raise ValueError("frozen enrichment record does not match its outer subject")
        _aware(record.fetched_at, "record.fetched_at")
        if record.expires_at is not None:
            _aware(record.expires_at, "record.expires_at")
        context_revision = record.value.get("context_bundle_sha256")
        if context_revision is not None and (
            not isinstance(context_revision, str)
            or len(context_revision) != 64
            or any(character not in "0123456789abcdef" for character in context_revision)
        ):
            raise ValueError("frozen enrichment has an invalid context bundle digest")
        base_identity = (
            f"{snapshot.site_id}|{snapshot.group_id}|{snapshot.group_revision}|"
            f"{record.source}|{snapshot.as_of.isoformat()}"
        )
        expected_id = uuid5(
            _SNAPSHOT_NAMESPACE,
            base_identity
            if not isinstance(context_revision, str)
            else f"{base_identity}|bundle:{context_revision}",
        )
        if record.enrichment_id != expected_id:
            raise ValueError("frozen enrichment id does not bind its subject, source and cutoff")

    rows = conn.execute(
        """
        SELECT enrichment_id, site_id, group_id, group_revision, source, source_version,
               availability, value, fetched_at, expires_at
        FROM enrichments
        WHERE site_id = %s AND enrichment_id = ANY(%s)
        """,
        (snapshot.site_id, ids),
    ).fetchall()
    stored = {row[0]: row for row in rows}
    if len(stored) != len(ids):
        raise ValueError("frozen enrichment snapshot references missing retained evidence")
    for record in records:
        row = stored.get(record.enrichment_id)
        expected = (
            record.enrichment_id,
            record.site_id,
            record.group_id,
            record.group_revision,
            record.source,
            record.source_version,
            record.availability,
            record.value,
            record.fetched_at,
            record.expires_at,
        )
        if row != expected:
            raise ValueError("frozen enrichment record differs from retained immutable evidence")


def _privilege(members: tuple[dict[str, Any], ...], as_of: datetime) -> ContextObservation:
    users = sorted(
        {
            str(member.get(key)).casefold()
            for member in members
            for key in ("src_user", "dst_user")
            if isinstance(member.get(key), str) and member.get(key)
        }
    )
    groups = {
        str(group).casefold()
        for member in members
        for group in member.get("rule_groups", [])
        if isinstance(group, str)
    }
    if not users:
        return _unavailable("privilege", "no normalized account identity", as_of)
    privileged = any(
        user.rsplit("\\", 1)[-1] in {"root", "administrator", "admin", "system"} for user in users
    )
    privileged = privileged or bool(groups.intersection({"sudo", "su"}))
    return ContextObservation(
        source_version="workspace.privilege_hints.v1",
        availability="available",
        value={
            "privileged": privileged,
            "account_values": users,
            "matched_rule_groups": sorted(groups.intersection({"sudo", "su"})),
        },
        fetched_at=as_of,
    )


def _provider_observation(
    source: str,
    adapter: ContextAdapter | None,
    site_id: str,
    group_id: str,
    revision: str,
    members: tuple[dict[str, Any], ...],
    as_of: datetime,
    *,
    default_version: str,
) -> ContextObservation:
    if adapter is None:
        return _unavailable(source, "provider is not configured", as_of, version=default_version)
    try:
        result = adapter.fetch(
            site_id=site_id,
            group_id=group_id,
            group_revision=revision,
            member_snapshots=members,
            as_of=as_of,
        )
    except Exception as exc:
        return _unavailable(
            source, f"provider failed: {type(exc).__name__}", as_of, version=default_version
        )
    if result.availability == "available" and "score_value" not in result.value:
        return ContextObservation(
            source_version=result.source_version,
            availability="unavailable",
            value={
                "reason": "provider result lacks normalized score_value",
                "provider_value": result.value,
            },
            fetched_at=result.fetched_at,
            expires_at=result.expires_at,
        )
    return result


def _unavailable(
    source: str, reason: str, as_of: datetime, *, version: str = "workspace.local.v1"
) -> ContextObservation:
    return ContextObservation(version, "unavailable", {"reason": reason}, as_of)


def _insert_frozen_enrichment(conn: psycopg.Connection[Any], record: EnrichmentRecord) -> None:
    conn.execute(
        """
        INSERT INTO enrichments
            (site_id, enrichment_id, group_id, group_revision, source, source_version,
             availability, value, fetched_at, expires_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (site_id, enrichment_id) DO NOTHING
        """,
        (
            record.site_id,
            record.enrichment_id,
            record.group_id,
            record.group_revision,
            record.source,
            record.source_version,
            record.availability,
            Jsonb(record.value),
            record.fetched_at,
            record.expires_at,
        ),
    )
    row = conn.execute(
        """SELECT group_id, group_revision, source, source_version, availability, value,
                  fetched_at, expires_at
           FROM enrichments WHERE site_id = %s AND enrichment_id = %s""",
        (record.site_id, record.enrichment_id),
    ).fetchone()
    expected = (
        record.group_id,
        record.group_revision,
        record.source,
        record.source_version,
        record.availability,
        record.value,
        record.fetched_at,
        record.expires_at,
    )
    if row is None or tuple(row) != expected:
        raise FrozenSnapshotConflict(f"enrichment {record.source} changed at a frozen as_of cutoff")


def _score_value(record: EnrichmentRecord) -> float | None:
    value = (
        record.value.get("criticality_fraction")
        if record.source == "asset"
        else record.value.get("score_value")
    )
    if record.source == "privilege":
        value = float(bool(record.value.get("privileged")))
    if record.source == "first_seen":
        value = float(bool(record.value.get("is_first_seen_in_bucket")))
    if isinstance(value, bool):
        value = float(value)
    if not isinstance(value, (int, float)) or not 0 <= value <= 1:
        return None
    return float(value)


def _count(value: dict[str, Any] | None, key: str) -> int | None:
    if value is None:
        return None
    item = value.get(key)
    return item if isinstance(item, int) and item >= 0 else None


def _score_component_json(component: Any) -> dict[str, Any]:
    return {
        "name": component.name,
        "value": component.value,
        "weight": component.weight,
        "contribution": component.contribution,
        "available": component.available,
        "evidence_ids": list(component.evidence_ids),
        "explanation": component.explanation,
    }


def _revision_primary_entity(
    conn: psycopg.Connection[Any], site_id: str, group_id: str, revision: str
) -> str | None:
    row = conn.execute(
        """SELECT primary_entity FROM group_revisions
           WHERE site_id = %s AND group_id = %s AND revision = %s""",
        (site_id, group_id, revision),
    ).fetchone()
    return None if row is None else row[0]


def _confirmed_composite_overlap(
    conn: psycopg.Connection[Any],
    *,
    site_id: str,
    group_id: str,
    group_revision: str,
    agent_id: str | None,
    primary_entity: str | None,
    bucket_start: datetime,
    as_of: datetime,
    policy: CompositePolicy,
) -> str | None:
    if not agent_id or not primary_entity or not policy.available:
        return None
    base_rule_ids = sorted({pair.base_rule_id for pair in policy.pairs})
    composite_rule_ids = sorted({pair.composite_rule_id for pair in policy.pairs})
    if not base_rule_ids or not composite_rule_ids:
        return None
    row = conn.execute(
        """
        SELECT candidate.group_id, candidate.revision, base.rule_id, candidate.rule_id
        FROM groups AS base_group
        JOIN group_revisions AS base
          ON (base.site_id, base.group_id) = (base_group.site_id, base_group.group_id)
        JOIN groups AS composite
          ON composite.site_id = base_group.site_id
         AND composite.bucket_start = base_group.bucket_start
        JOIN group_revisions AS candidate
          ON (candidate.site_id, candidate.group_id) = (composite.site_id, composite.group_id)
         AND candidate.agent_id = base.agent_id
         AND candidate.primary_entity = base.primary_entity
        WHERE base_group.site_id = %s AND base_group.group_id = %s
          AND base.revision = %s AND base.created_at <= %s
          AND base_group.bucket_start = %s AND composite.group_id <> base_group.group_id
          AND base.rule_id = ANY(%s) AND candidate.rule_id = ANY(%s)
          AND candidate.created_at <= %s
        ORDER BY candidate.created_at DESC, candidate.revision DESC
        """,
        (
            site_id,
            group_id,
            group_revision,
            as_of,
            bucket_start,
            base_rule_ids,
            composite_rule_ids,
            as_of,
        ),
    ).fetchall()
    for candidate_group_id, candidate_revision, base_rule_id, candidate_rule_id in row:
        if policy.confirms(str(base_rule_id), str(candidate_rule_id)):
            return f"group:{candidate_group_id}:{candidate_revision}"
    return None


def _require_site(conn: psycopg.Connection[Any], site_id: str) -> None:
    if conn.info.transaction_status is TransactionStatus.IDLE:
        raise PermissionError("triage writes require an active site transaction")
    row = conn.execute("SELECT current_setting('app.site_id', true)").fetchone()
    if row is None or row[0] != site_id:
        raise PermissionError("triage operation requires an active transaction for its site")


def _aware(value: datetime, name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")
