"""Post-judgment KEV context decoration for outbound vulnerability tables."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Literal, cast
from uuid import UUID

from ai_soc.content.kev import (
    KevLookupError,
    KevLookupIndex,
    freshness,
    lookup_kev,
    policy_identity,
)
from ai_soc.contracts.canonical import canonical_bytes, evidence_id, sha256_hex
from ai_soc.contracts.models import (
    AuditContextUse,
    BuildProvenance,
    EvidenceItem,
    EvidenceSourceContext,
    EvidenceValues,
    FetchResult,
    FieldId,
    KevPolicy,
    KevUseRef,
    TopicAnswer,
    Visibility,
)

_TEXT: dict[str, dict[str, str]] = {
    "hit": {
        "en": (
            "Listed in CISA KEV (added {date}); known exploitation, not proof of host compromise."
        ),
        "es": (
            "Consta en CISA KEV (alta {date}); explotacion conocida, "
            "no prueba de compromiso del equipo."
        ),
    },
    "not_listed": {
        "en": "Not listed in this KEV snapshot; this does not rule out exploitation.",
        "es": "No consta en esta instantanea KEV; esto no descarta explotacion.",
    },
    "stale": {
        "en": "KEV snapshot expired at {expiry}; historical context only.",
        "es": "Instantanea KEV caducada desde {expiry}; solo contexto historico.",
    },
    "unavailable": {
        "en": "KEV context unavailable ({reason}); telemetry retained.",
        "es": "Contexto KEV no disponible ({reason}); se conservan los registros.",
    },
    "invalid_cve": {
        "en": "Invalid or missing CVE; KEV lookup not performed.",
        "es": "CVE no valido o ausente; no se consulto KEV.",
    },
}
_UNKNOWN = (
    "Current affected state: unknown. Inventory scan age: unknown.",
    "Estado afectado actual: desconocido. Antiguedad del escaneo de inventario: desconocida.",
)
_LOOKUPS = ("hit", "not_listed", "invalid_cve", "unavailable")
_FRESHNESS = ("fresh", "stale", "not_yet_valid", "unknown")
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}", re.ASCII)
type LookupState = Literal["hit", "not_listed", "invalid_cve", "unavailable"]
type FreshnessState = Literal["fresh", "stale", "not_yet_valid", "unknown"]


@dataclass(frozen=True, slots=True)
class DecoratedFetch:
    result: FetchResult
    audit_use: AuditContextUse
    added_bytes: int
    added_items: int


def decorate_answer_tables(
    blocks: Sequence[TopicAnswer],
    *,
    language: Literal["en", "es"],
    catalog: object,
    manifest: BuildProvenance,
    activation_at: datetime,
    question_id: UUID,
) -> tuple[list[TopicAnswer], list[AuditContextUse]]:
    """Decorate only outbound table copies and enforce the aggregate initial allowance."""
    results: list[tuple[int, int, DecoratedFetch]] = []
    copied = [block.model_copy(deep=True) for block in blocks]
    for block_index, block in enumerate(copied):
        if block.topic_id != "vuln_review":
            continue
        for table_index, table in enumerate(block.tables):
            if table.fetch_id != "vuln_rows":
                continue
            results.append(
                (
                    block_index,
                    table_index,
                    decorate_fetch(
                        table,
                        language=language,
                        kev_index=getattr(catalog, "kev_index", None),
                        manifest=manifest,
                        activation_at=activation_at,
                        question_id=question_id,
                        availability_proof="boot",
                    ),
                )
            )
    proposed = [block.model_copy(deep=True) for block in blocks]
    for block_index, table_index, decorated in results:
        proposed[block_index].tables[table_index] = decorated.result
    request_added_bytes = len(canonical_bytes(proposed)) - len(canonical_bytes(blocks))
    if sum(item.added_items for _, _, item in results) > 512 or request_added_bytes > 98304:
        results = [
            (
                block_index,
                table_index,
                decorate_fetch(
                    copied[block_index].tables[table_index],
                    language=language,
                    kev_index=getattr(catalog, "kev_index", None),
                    manifest=manifest,
                    activation_at=activation_at,
                    question_id=question_id,
                    availability_proof="boot",
                    forced_reason="limit",
                ),
            )
            for block_index, table_index, _ in results
        ]
    uses: list[AuditContextUse] = []
    for block_index, table_index, decorated in results:
        copied[block_index].tables[table_index] = decorated.result
        uses.append(decorated.audit_use)
    return copied, uses


def decorate_page(
    result: FetchResult,
    *,
    kev_index: KevLookupIndex | None,
    manifest: BuildProvenance,
    activation_at: datetime,
    question_id: UUID,
    evaluation_at: datetime | None = None,
) -> DecoratedFetch:
    return decorate_fetch(
        result,
        language="en",
        kev_index=kev_index,
        manifest=manifest,
        activation_at=activation_at,
        question_id=question_id,
        availability_proof="cursor",
        both_languages=True,
        evaluation_at=evaluation_at,
    )


def decorate_fetch(
    result: FetchResult,
    *,
    language: Literal["en", "es"],
    kev_index: KevLookupIndex | None,
    manifest: BuildProvenance,
    activation_at: datetime,
    availability_proof: Literal["boot", "cursor"],
    question_id: UUID,
    both_languages: bool = False,
    forced_reason: Literal["limit"] | None = None,
    evaluation_at: datetime | None = None,
) -> DecoratedFetch:
    """Make a detached, row-preserving copy and attach bounded context evidence."""
    if result.topic_id != "vuln_review" or result.fetch_id != "vuln_rows":
        raise ValueError("KEV annotation is restricted to vuln_review/vuln_rows")
    base = (
        _use_ref(kev_index, manifest, evaluation_at or result.snapshot.at)
        if kev_index is not None
        else KevUseRef(
            content_sha=manifest.content_sha,
            pack_sha256=manifest.pack_sha256,
            metadata=None,
            approved_at=None,
            approval_key_id=None,
            policy_sha256=policy_identity(KevPolicy()),
            evaluation_at=evaluation_at or result.snapshot.at,
            valid_from=None,
            expires_at=None,
        )
    )

    row_items = {item.evidence_id: item for item in result.items if item.kind == "row"}
    subjects: list[tuple[str, int, object]] = []
    for row in result.rows:
        row_item = row_items.get(row.evidence_id)
        if (
            row_item is None
            or row_item.topic_id != result.topic_id
            or row_item.fetch_id != result.fetch_id
            or row_item.snapshot.key != result.snapshot.key
            or row_item.values.get(FieldId.vulnerability_id)
            != row.values.get(FieldId.vulnerability_id)
        ):
            raise ValueError("returned row has no matching canonical evidence item")
        raw = row.values.get(FieldId.vulnerability_id)
        if isinstance(raw, list):
            members: list[object] = list(raw) if raw else [None]
        else:
            members = [raw]
        subjects.extend((row.evidence_id, index, value) for index, value in enumerate(members))

    page_limit = forced_reason is None and len(subjects) + 1 <= 256
    page_items: list[EvidenceItem] = []
    lookup_counts = cast(dict[LookupState, int], {key: 0 for key in _LOOKUPS})
    freshness_counts = cast(dict[FreshnessState, int], {key: 0 for key in _FRESHNESS})
    annotations: list[tuple[str, int, object, LookupState, FreshnessState, date | None]] = []
    reason: str | None = forced_reason
    # A missing or not-yet-valid snapshot affects the whole page, so it takes the same
    # all-or-nothing fallback as the limit and lookup-error cases.
    if kev_index is None:
        page_wide: str | None = "not_configured"
    elif freshness(kev_index.snapshot, evaluation_at or result.snapshot.at)[0] == "not_yet_valid":
        page_wide = "not_yet_available"
    else:
        page_wide = None
    if not page_limit:
        reason = "limit"
    elif page_wide is not None:
        reason = page_wide
    elif kev_index is not None:
        for row_id, member_index, cve in subjects:
            if (
                not isinstance(cve, str)
                or not cve
                or cve.strip() != cve
                or len(cve.encode("utf-8")) > 32
                or _CVE.fullmatch(cve) is None
            ):
                lookup, added_on = "invalid_cve", None
            else:
                try:
                    lookup, added_on = lookup_kev(kev_index, cve)
                except KevLookupError:
                    lookup, added_on, reason = "unavailable", None, "lookup_error"
            if lookup == "invalid_cve":
                fresh_state = "unknown"
            else:
                fresh_state, _, _ = freshness(
                    kev_index.snapshot, evaluation_at or result.snapshot.at
                )
            lookup_counts[lookup] += 1
            freshness_counts[cast(FreshnessState, fresh_state)] += 1
            annotations.append(
                (
                    row_id,
                    member_index,
                    cve,
                    lookup,
                    cast(FreshnessState, fresh_state),
                    added_on,
                )
            )
    display_reason = reason
    annotated_subjects = sum(lookup_counts.values())
    omitted = len(subjects) - annotated_subjects
    if reason is not None and reason in {
        "limit",
        "lookup_error",
        "not_configured",
        "not_yet_available",
    }:
        lookup_counts = cast(dict[LookupState, int], {key: 0 for key in _LOOKUPS})
        freshness_counts = cast(dict[FreshnessState, int], {key: 0 for key in _FRESHNESS})
        annotated_subjects = 0
        annotations = []
        omitted = len(subjects)
    coverage = (
        "unavailable"
        if reason and omitted == len(subjects)
        else "incomplete"
        if omitted
        else "complete"
    )
    summary_values: dict[str, object] = {
        "kev_coverage": coverage,
        "kev_row_n": len(result.rows),
        "kev_subject_n": len(subjects),
        "kev_annotated_n": annotated_subjects,
        "kev_omitted_n": omitted,
        "kev_hit_n": lookup_counts["hit"],
        "kev_not_listed_n": lookup_counts["not_listed"],
        "kev_invalid_n": lookup_counts["invalid_cve"],
        "kev_unavailable_n": lookup_counts["unavailable"],
        "kev_fresh_n": freshness_counts["fresh"],
        "kev_stale_n": freshness_counts["stale"],
        "kev_not_yet_valid_n": freshness_counts["not_yet_valid"],
        "kev_unknown_n": freshness_counts["unknown"],
    }
    if reason:
        summary_values["kev_reason"] = reason
    page_source = EvidenceSourceContext(role="page", kev_use=base)
    page_item = _context_item(
        result,
        manifest,
        question_id,
        page_source,
        cast(EvidenceValues, summary_values),
        row_items,
    )
    page_items.append(page_item)
    for row_id, member_index, cve, lookup, fresh_state, added_on in annotations:
        parent = row_items.get(row_id)
        if parent is None:
            raise ValueError("returned row has no matching canonical evidence item")
        parent_raw = parent.values.get(FieldId.vulnerability_id)
        parent_members = (
            (parent_raw if parent_raw else [None]) if isinstance(parent_raw, list) else [parent_raw]
        )
        if member_index >= len(parent_members) or parent_members[member_index] != cve:
            raise ValueError("KEV subject does not match its source row member")
        values: dict[str, object] = {
            "kev_cve": cve if lookup in {"hit", "not_listed", "unavailable"} else None,
            "kev_lookup": lookup,
            "kev_freshness": fresh_state,
        }
        if lookup == "hit" and isinstance(added_on, date):
            values["kev_added_on"] = added_on.isoformat()
        page_ref = page_item.evidence_id
        subject_source = EvidenceSourceContext(
            role="subject",
            parent_evidence_id=row_id,
            member_index=member_index,
            page_evidence_id=page_ref,
        )
        page_items.append(
            _context_item(
                result,
                manifest,
                question_id,
                subject_source,
                cast(EvidenceValues, values),
                row_items,
            )
        )
    encoded_items = canonical_bytes(page_items)
    if (
        len(page_items) > 256
        or len(encoded_items) > 49152
        or len(canonical_bytes(page_item)) > 16384
    ):
        return decorate_fetch(
            result,
            language=language,
            kev_index=kev_index,
            manifest=manifest,
            activation_at=activation_at,
            availability_proof=availability_proof,
            question_id=question_id,
            both_languages=both_languages,
            forced_reason="limit",
            evaluation_at=evaluation_at,
        )
    display = _display_lines(annotations, display_reason, base, language, both_languages)
    message_parts = [result.message] if result.message else []
    message_parts.extend(display)
    message_parts.extend(_UNKNOWN if both_languages else (_UNKNOWN[0 if language == "en" else 1],))
    message = " ".join(part for part in message_parts if part)
    final = result.model_copy(
        deep=True, update={"items": [*result.items, *page_items], "message": message}
    )
    added_bytes = len(canonical_bytes(final)) - len(canonical_bytes(result))
    if added_bytes > 49152:
        return decorate_fetch(
            result,
            language=language,
            kev_index=kev_index,
            manifest=manifest,
            activation_at=activation_at,
            availability_proof=availability_proof,
            question_id=question_id,
            both_languages=both_languages,
            forced_reason="limit",
            evaluation_at=evaluation_at,
        )
    use = AuditContextUse(
        topic_id="vuln_review",
        fetch_id="vuln_rows",
        source_snapshot_key=result.snapshot.key,
        kev_use=base,
        activation_at=activation_at if availability_proof == "boot" else None,
        availability_proof=availability_proof,
        rows_returned=len(result.rows),
        subjects_total=len(subjects),
        annotated_subjects=annotated_subjects,
        omitted_subjects=omitted,
        lookup_counts=lookup_counts,
        freshness_counts=freshness_counts,
        coverage=coverage,
        reason=reason,
        annotation_sha256=sha256_hex(page_items),
    )
    return DecoratedFetch(final, use, added_bytes, len(page_items))


def _use_ref(
    index: KevLookupIndex, manifest: BuildProvenance, evaluation_at: datetime
) -> KevUseRef:
    _, valid_from, expires_at = freshness(index.snapshot, evaluation_at)
    return KevUseRef(
        content_sha=manifest.content_sha,
        pack_sha256=manifest.pack_sha256,
        metadata=index.snapshot.metadata,
        approved_at=index.snapshot.approved_at,
        approval_key_id=index.snapshot.approval_key_id,
        policy_sha256=policy_identity(index.snapshot.metadata.policy),
        evaluation_at=evaluation_at,
        valid_from=valid_from,
        expires_at=expires_at,
    )


def _context_item(
    result: FetchResult,
    manifest: BuildProvenance,
    question_id: UUID,
    source: EvidenceSourceContext,
    values: EvidenceValues,
    row_items: dict[str, EvidenceItem],
) -> EvidenceItem:
    source_row = row_items.get(source.parent_evidence_id or "")
    scope_hash = source_row.scope_hash if source_row is not None else sha256_hex(result.scope)
    identity = evidence_id(
        question_id=str(question_id),
        environment_id=result.scope.environment_id,
        topic_id=result.topic_id,
        fetch_id=result.fetch_id,
        check_id=None,
        kind="context",
        source=source,
        snapshot_key=result.snapshot.key,
        values=values,
    )
    del manifest
    return EvidenceItem(
        evidence_id=identity,
        topic_id=result.topic_id,
        fetch_id=result.fetch_id,
        kind="context",
        source=source,
        snapshot=result.snapshot,
        values=values,
        visibility=Visibility(result.scope.visibility),
        scope_hash=scope_hash,
    )


def _display_lines(
    annotations: list[tuple[str, int, object, LookupState, FreshnessState, date | None]],
    reason: str | None,
    use: KevUseRef,
    language: Literal["en", "es"],
    both_languages: bool,
) -> list[str]:
    languages: tuple[Literal["en", "es"], ...] = ("en", "es") if both_languages else (language,)
    if reason and not annotations:
        return [_TEXT["unavailable"][lang].format(reason=reason) for lang in languages]
    lines: list[str] = []
    expiry = (
        use.expires_at.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
        if use.expires_at
        else "unknown"
    )
    for _, member_index, cve, lookup, fresh_state, added_on in annotations:
        cve_text = cve if lookup != "invalid_cve" and isinstance(cve, str) else "invalid"
        for lang in languages:
            if lookup == "hit" and isinstance(added_on, date):
                state_line = _TEXT["hit"][lang].format(date=added_on.isoformat())
            elif lookup == "not_listed":
                state_line = _TEXT["not_listed"][lang]
            elif lookup == "invalid_cve":
                state_line = _TEXT["invalid_cve"][lang]
            else:
                state_line = _TEXT["unavailable"][lang].format(
                    reason=reason
                    or ("not_yet_available" if fresh_state == "not_yet_valid" else "not_configured")
                )
            lines.append(f"{cve_text}[{member_index}]: {state_line}")
            if fresh_state == "stale":
                lines.append(f"{lang}: {_TEXT['stale'][lang].format(expiry=expiry)}")
    return lines
