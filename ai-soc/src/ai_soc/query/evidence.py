"""Canonical evidence materialization for rows, counts, buckets, probes and checks."""

from __future__ import annotations

from datetime import datetime
from typing import Literal, cast
from uuid import UUID

from ai_soc.contracts.canonical import canonical_bytes, sha256_hex
from ai_soc.contracts.canonical import evidence_id as make_evidence_id
from ai_soc.contracts.models import (
    Bucket,
    Column,
    Count,
    EmptyProof,
    EvidenceItem,
    EvidenceRow,
    EvidenceSourceBucket,
    EvidenceSourceCount,
    EvidenceSourceProbe,
    EvidenceSourceRow,
    EvidenceValue,
    FetchSpec,
    FieldId,
    Filter,
    FilterProbe,
    GroupField,
    LocaleText,
    RecordRef,
    SnapshotKind,
    SnapshotRef,
    TemplateId,
    Visibility,
)

type EvidenceKey = (
    FieldId
    | Literal[
        "count",
        "outcome",
        "matched_nothing",
        "relation",
        "approximate",
        "bucket_key",
        "operand_ids",
        "expectation_id",
        "expectation_version",
        "kev_cve",
        "kev_lookup",
        "kev_freshness",
        "kev_added_on",
        "kev_coverage",
        "kev_reason",
        "kev_row_n",
        "kev_subject_n",
        "kev_annotated_n",
        "kev_omitted_n",
        "kev_hit_n",
        "kev_not_listed_n",
        "kev_invalid_n",
        "kev_unavailable_n",
        "kev_fresh_n",
        "kev_stale_n",
        "kev_not_yet_valid_n",
        "kev_unknown_n",
    ]
)
type EvidenceValues = dict[EvidenceKey, EvidenceValue]


def snapshot_ref(
    *,
    environment_id: str,
    pit_id: str | None,
    question_id: UUID,
    fetch: FetchSpec,
    at: datetime,
    expires_at: datetime | None = None,
    response_identity: str = "",
) -> SnapshotRef:
    if at.tzinfo is None or at.utcoffset() is None:
        raise ValueError("snapshot time must be timezone-aware")
    if pit_id:
        key = sha256_hex({"environment_id": environment_id, "pit_id": pit_id})
        return SnapshotRef(kind=SnapshotKind.pit, key=key, at=at, expires_at=expires_at)
    key = sha256_hex(
        {
            "environment_id": environment_id,
            "question_id": str(question_id),
            "fetch_id": fetch.fetch_id,
            "anchor_at": fetch.window.anchor_at,
            "query": {
                "template_id": fetch.template_id,
                "filters": fetch.filters,
                "window": fetch.window,
            },
            "response_identity": response_identity,
        }
    )
    return SnapshotRef(kind=SnapshotKind.first_page_only, key=key, at=at)


def _lookup(source: dict[str, object], dotted: str) -> object:
    value: object = source
    for part in dotted.split("."):
        if not isinstance(value, dict):
            return None
        mapping = cast(dict[object, object], value)
        value = mapping.get(part)
    return value


def normalize_value(field: FieldId, value: object) -> EvidenceValue:
    if value is None or isinstance(value, (str, int, bool)):
        if isinstance(value, str) and len(value.encode("utf-8")) > 4096:
            raise ValueError("projected value exceeds evidence field bound")
        if isinstance(value, int) and not isinstance(value, bool) and abs(value) > 2**63 - 1:
            raise ValueError("projected integer exceeds evidence field bound")
        return value
    if isinstance(value, list):
        values = cast(list[object], value)
        if not all(isinstance(item, str) for item in values):
            raise ValueError(f"unsupported projected value for {field.value}")
        strings = cast(list[str], values)
        if len(strings) > 64 or any(len(item.encode("utf-8")) > 256 for item in strings):
            raise ValueError("projected list exceeds evidence field bound")
        return strings
    raise ValueError(f"unsupported projected value for {field.value}")


def row_item(
    *,
    question_id: UUID,
    environment_id: str,
    topic_id: str,
    fetch: FetchSpec,
    snapshot: SnapshotRef,
    visibility: Visibility,
    policy_hash: str,
    index_alias: str,
    record_id: str,
    values: dict[FieldId, EvidenceValue],
) -> tuple[EvidenceRow, EvidenceItem]:
    source = EvidenceSourceRow(index_alias=index_alias, record_id=record_id)
    digest = make_evidence_id(
        question_id=str(question_id),
        environment_id=environment_id,
        topic_id=topic_id,
        fetch_id=fetch.fetch_id,
        check_id=None,
        kind="row",
        source={"index_alias": index_alias, "record_id": record_id},
        snapshot_key=snapshot.key,
        values=values,
    )
    record_ref = RecordRef(index_alias=index_alias, record_id=record_id)
    row = EvidenceRow(
        evidence_id=digest,
        topic_id=topic_id,
        fetch_id=fetch.fetch_id,
        record_ref=record_ref,
        values=values,
    )
    scope_hash = sha256_hex(
        {
            "environment_id": environment_id,
            "template_id": fetch.template_id,
            "window": fetch.window,
            "filters": fetch.filters,
            "policy_hash": policy_hash,
            "snapshot": snapshot.key,
        }
    )
    item = EvidenceItem(
        evidence_id=digest,
        topic_id=topic_id,
        fetch_id=fetch.fetch_id,
        check_id=None,
        kind="row",
        source=source,
        snapshot=snapshot,
        values=cast(EvidenceValues, values),
        visibility=Visibility(visibility),
        scope_hash=scope_hash,
    )
    return row, item


def count_item(
    *,
    question_id: UUID,
    environment_id: str,
    topic_id: str,
    fetch: FetchSpec,
    snapshot: SnapshotRef,
    visibility: Visibility,
    policy_hash: str,
    count: Count,
) -> EvidenceItem:
    source = EvidenceSourceCount(
        template_id=TemplateId(fetch.template_id),
        window=fetch.window,
        filters=fetch.filters,
        scope="matching_visible_records",
    )
    values: EvidenceValues = {
        "count": count.value,
        "relation": count.relation,
        "approximate": count.approximate,
    }
    digest = make_evidence_id(
        question_id=str(question_id),
        environment_id=environment_id,
        topic_id=topic_id,
        fetch_id=fetch.fetch_id,
        check_id=None,
        kind="aggregate",
        source={
            "template_id": fetch.template_id,
            "window": {"start": fetch.window.start, "end": fetch.window.end},
            "filters": fetch.filters,
            "scope": "matching_visible_records",
        },
        snapshot_key=snapshot.key,
        values=values,
    )
    return EvidenceItem(
        evidence_id=digest,
        topic_id=topic_id,
        fetch_id=fetch.fetch_id,
        check_id=None,
        kind="aggregate",
        source=source,
        snapshot=snapshot,
        values=values,
        visibility=Visibility(visibility),
        scope_hash=sha256_hex(
            {
                "environment_id": environment_id,
                "template_id": fetch.template_id,
                "window": fetch.window,
                "filters": fetch.filters,
                "policy_hash": policy_hash,
                "snapshot": snapshot.key,
            }
        ),
    )


def bucket_item(
    *,
    question_id: UUID,
    environment_id: str,
    topic_id: str,
    fetch: FetchSpec,
    snapshot: SnapshotRef,
    visibility: Visibility,
    policy_hash: str,
    group_field: object,
    key: str | int,
    count: Count,
) -> tuple[Bucket, EvidenceItem]:
    source = EvidenceSourceBucket(group_field=GroupField(str(group_field)), key=key)
    values: EvidenceValues = {
        "bucket_key": key,
        "count": count.value,
        "relation": count.relation,
        "approximate": count.approximate,
    }
    digest = make_evidence_id(
        question_id=str(question_id),
        environment_id=environment_id,
        topic_id=topic_id,
        fetch_id=fetch.fetch_id,
        check_id=None,
        kind="aggregate",
        source={"group_field": source.group_field, "key": key},
        snapshot_key=snapshot.key,
        values=values,
    )
    item = EvidenceItem(
        evidence_id=digest,
        topic_id=topic_id,
        fetch_id=fetch.fetch_id,
        check_id=None,
        kind="aggregate",
        source=source,
        snapshot=snapshot,
        values=values,
        visibility=Visibility(visibility),
        scope_hash=sha256_hex(
            {
                "environment_id": environment_id,
                "template_id": fetch.template_id,
                "window": fetch.window,
                "filters": fetch.filters,
                "policy_hash": policy_hash,
                "snapshot": snapshot.key,
                "group_field": source.group_field,
            }
        ),
    )
    return Bucket(key=key, count=count, evidence_id=digest), item


def materialize_rows(
    *,
    hits: list[dict[str, object]],
    fields: tuple[FieldId, ...],
    field_names: dict[FieldId, str],
    question_id: UUID,
    environment_id: str,
    topic_id: str,
    fetch: FetchSpec,
    snapshot: SnapshotRef,
    visibility: Visibility,
    policy_hash: str,
) -> tuple[list[Column], list[EvidenceRow], list[EvidenceItem]]:
    rows: list[EvidenceRow] = []
    items: list[EvidenceItem] = []
    seen: dict[tuple[str, str], dict[FieldId, EvidenceValue]] = {}
    for hit in hits:
        source = hit.get("_source")
        index_alias = hit.get("_index")
        record_id = hit.get("_id")
        if (
            not isinstance(source, dict)
            or not isinstance(index_alias, str)
            or not isinstance(record_id, str)
        ):
            raise ValueError("malformed indexer hit")
        source = cast(dict[str, object], source)
        normalized = {
            field: normalize_value(field, _lookup(source, field_names[field])) for field in fields
        }
        source_key = (index_alias, record_id)
        if source_key in seen:
            if canonical_bytes(seen[source_key]) != canonical_bytes(normalized):
                raise ValueError("conflicting duplicate source record")
            continue
        seen[source_key] = normalized
        row, item = row_item(
            question_id=question_id,
            environment_id=environment_id,
            topic_id=topic_id,
            fetch=fetch,
            snapshot=snapshot,
            visibility=visibility,
            policy_hash=policy_hash,
            index_alias=index_alias,
            record_id=record_id,
            values=normalized,
        )
        rows.append(row)
        items.append(item)
    columns = [
        Column(
            field=field,
            label=LocaleText(en=field.value, es=field.value),
            kind=(
                "integer"
                if field in (FieldId.rule_level, FieldId.vulnerability_severity)
                else "date"
                if field in (FieldId.timestamp, FieldId.vulnerability_detected_at)
                else "ip"
                if field in (FieldId.data_srcip, FieldId.data_dstip)
                else "text"
            ),
        )
        for field in fields
    ]
    return columns, rows, items


def build_empty_proof(
    *,
    question_id: UUID,
    environment_id: str,
    topic_id: str,
    fetch: FetchSpec,
    snapshot: SnapshotRef,
    visibility: Visibility,
    policy_hash: str,
    index_exists: bool | None,
    window_count: Count | None,
    filter_counts: list[tuple[Filter, Count | None]],
    combination_count: Count | None,
) -> EmptyProof:
    """Materialize diagnostics only when supplied from this authorized snapshot."""
    visibility = Visibility(visibility)
    items: list[EvidenceItem] = []
    probes: list[FilterProbe] = []
    matched: list[FieldId] = []

    def probe_item(
        probe_kind: Literal["index_exists", "window_data", "filter", "combination"],
        filters: list[Filter],
        count: Count | None,
    ) -> None:
        values: EvidenceValues = {
            "count": count.value if count else None,
            "relation": count.relation if count else None,
            "approximate": count.approximate if count else None,
            "matched_nothing": [str(item.field) for item in filters]
            if count and count.value == 0
            else [],
        }
        source = EvidenceSourceProbe(probe_kind=probe_kind, filters=filters)
        digest = make_evidence_id(
            question_id=str(question_id),
            environment_id=environment_id,
            topic_id=topic_id,
            fetch_id=fetch.fetch_id,
            check_id=None,
            kind="aggregate",
            source={"probe_kind": probe_kind, "filters": filters},
            snapshot_key=snapshot.key,
            values=values,
        )
        items.append(
            EvidenceItem(
                evidence_id=digest,
                topic_id=topic_id,
                fetch_id=fetch.fetch_id,
                check_id=None,
                kind="aggregate",
                source=source,
                snapshot=snapshot,
                values=values,
                visibility=Visibility(visibility),
                scope_hash=sha256_hex(
                    {
                        "environment_id": environment_id,
                        "template_id": fetch.template_id,
                        "window": fetch.window,
                        "filters": filters,
                        "policy_hash": policy_hash,
                        "snapshot": snapshot.key,
                        "probe_kind": probe_kind,
                    }
                ),
            )
        )

    probe_item("window_data", [], window_count)
    for raw_filter, count in filter_counts:
        outcome = (
            "unknown" if count is None or count.relation != "eq" or count.approximate else "passed"
        )
        probes.append(FilterProbe(filter=raw_filter, count=count, outcome=outcome))
        if (
            count is not None
            and count.relation == "eq"
            and not count.approximate
            and count.value == 0
        ):
            matched.append(FieldId(str(raw_filter.field)))
        probe_item("filter", [raw_filter], count)
    if combination_count is not None:
        probe_item("combination", fetch.filters, combination_count)

    exact_window = (
        window_count is not None and window_count.relation == "eq" and not window_count.approximate
    )
    coherent = (
        snapshot.kind == SnapshotKind.pit
        and visibility == Visibility.full
        and index_exists is True
        and exact_window
        and window_count is not None
        and window_count.value > 0
        and all(
            probe.count is not None and probe.count.relation == "eq" and not probe.count.approximate
            for probe in probes
        )
        and (
            bool(matched)
            or (
                combination_count is not None
                and combination_count.relation == "eq"
                and not combination_count.approximate
                and combination_count.value == 0
            )
        )
    )
    return EmptyProof(
        index_exists="confirmed" if index_exists is True else "unknown",
        window_has_data="empty"
        if exact_window and window_count is not None and window_count.value == 0
        else "confirmed"
        if exact_window and window_count and window_count.value > 0
        else "unknown",
        window_count=window_count,
        filter_probes=probes,
        matched_nothing=sorted(set(matched), key=lambda field: field.value),
        visibility=visibility,
        combination_zero=bool(
            combination_count
            and combination_count.relation == "eq"
            and not combination_count.approximate
            and combination_count.value == 0
        ),
        snapshot=snapshot,
        consistency="coherent" if coherent else "unconfirmed",
        items=items,
    )
