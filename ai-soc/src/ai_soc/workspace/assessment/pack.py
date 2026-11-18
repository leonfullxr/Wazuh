"""Freeze bounded assessment evidence from one exact score and group revision."""

from __future__ import annotations

import math
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Any, Literal, cast
from uuid import UUID

import psycopg
from pydantic import BaseModel, ConfigDict, TypeAdapter

from ai_soc.contracts.canonical import canonical_bytes, evidence_id, sha256_hex
from ai_soc.workspace.db import require_site_transaction
from ai_soc.workspace.model.pack import MAX_PACK_BYTES
from ai_soc.workspace.triage.enrich import Availability, GapState, enrichment_gap
from ai_soc.workspace.triage.score import ScoreResult

_PACK_VERSION = "workspace.group-assessment-pack.v1"
_MAX_MEMBER_SAMPLES = 32
_MAX_TEXT_BYTES = 256
_MAX_CONTEXT_VALUES = 8
_SSH_RULES = frozenset({"5763", "5715", "40112"})
_ALERT_FIELDS: tuple[str, ...] = (
    "rule_id",
    "rule_level",
    "decoder",
    "src_ip",
    "dst_user",
    "src_user",
    "agent_id",
    "rule_description",
)
_CONTEXT_FIELDS = {
    "asset": ("criticality", "revision", "tags"),
    "first_seen": ("is_first_seen_in_bucket", "first_seen_at", "entity_kind"),
    "geoip": ("score_value",),
    "kev": ("open_cve_count", "kev_cves", "affected_state", "score_value"),
    "known_noise": ("score_value",),
    "prevalence": (
        "alert_count",
        "rule_count",
        "site_alert_count",
        "site_rule_count",
        "distinct_agents_rule",
        "window_from",
        "window_to",
    ),
    "privilege": ("privileged", "matched_rule_groups"),
    "vuln": ("open_cve_count", "high_severity_cves", "score_value"),
}
_PROVENANCE_FIELDS = (
    "source_id",
    "source_sha256",
    "context_bundle_sha256",
    "open_vulnerability_source_id",
    "open_vulnerability_source_sha256",
    "open_vulnerability_source_ids",
    "open_vulnerability_source_versions",
)
_CONTEXT_LIST_FIELDS = frozenset(
    {
        "tags",
        "kev_cves",
        "high_severity_cves",
        "matched_rule_groups",
        "open_vulnerability_source_ids",
        "open_vulnerability_source_versions",
    }
)
_DISPOSITION_LABELS: tuple[str, ...] = (
    "true_positive",
    "benign_true_positive",
    "false_positive",
    "duplicate",
    "undetermined",
)
_KEY_RE = re.compile(r"[0-9a-f]{64}\Z")

type EvidenceKind = Literal["row", "aggregate", "check", "context", "history", "knowledge"]
type EvidenceValue = bool | int | float | str | tuple[str, ...]


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    id: str
    kind: EvidenceKind
    fields: Mapping[str, EvidenceValue]
    fetch_id: str | None = None
    scope_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "fields": {
                key: list(value) if isinstance(value, tuple) else value
                for key, value in self.fields.items()
            },
            "fetch_id": self.fetch_id,
            "scope_id": self.scope_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceItem:
        return cls(
            id=data["id"],
            kind=_EVIDENCE_KIND.validate_python(data["kind"]),
            fields=MappingProxyType(_EVIDENCE_FIELDS.validate_python(data["fields"])),
            fetch_id=data["fetch_id"],
            scope_id=data["scope_id"],
        )


class PackScoreComponent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    value: float | None
    weight: float
    contribution: float
    available: bool
    explanation: str


class PackScore(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    computation_version: str
    input_digest: str
    total: float
    components: tuple[PackScoreComponent, ...]


@dataclass(frozen=True, slots=True)
class EvidencePack:
    site_id: str
    group_id: str
    revision: str
    as_of: datetime
    member_count: int
    rule_family: str
    gaps: Mapping[str, GapState]
    missing_fields: tuple[str, ...]
    trimmed: bool
    has_excerpt: bool
    items: tuple[EvidenceItem, ...]
    score: PackScore
    digest: str

    def _content(self) -> dict[str, Any]:
        return {
            "builder_version": _PACK_VERSION,
            "subject_kind": "group",
            "site_id": self.site_id,
            "group_id": self.group_id,
            "revision": self.revision,
            "as_of": _instant(self.as_of),
            "member_count": self.member_count,
            "rule_family": self.rule_family,
            "gaps": dict(self.gaps),
            "missing_fields": list(self.missing_fields),
            "trimmed": self.trimmed,
            "has_excerpt": self.has_excerpt,
            "items": [item.as_dict() for item in self.items],
            "score": self.score.model_dump(mode="json"),
        }

    def as_dict(self) -> dict[str, Any]:
        return {**self._content(), "digest": self.digest}

    def with_digest(self) -> EvidencePack:
        return replace(self, digest=sha256_hex(self._content()))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidencePack:
        """Rehydrate the same pack and verify its content digest before use."""
        if data.get("builder_version") != _PACK_VERSION or data.get("subject_kind") != "group":
            raise ValueError("unsupported group assessment pack version")
        pack = cls(
            site_id=data["site_id"],
            group_id=data["group_id"],
            revision=data["revision"],
            as_of=datetime.fromisoformat(data["as_of"]),
            member_count=data["member_count"],
            rule_family=data["rule_family"],
            gaps=MappingProxyType(_GAPS.validate_python(data["gaps"])),
            missing_fields=tuple(data["missing_fields"]),
            trimmed=data["trimmed"],
            has_excerpt=data["has_excerpt"],
            items=tuple(EvidenceItem.from_dict(item) for item in data["items"]),
            score=PackScore.model_validate(data["score"]),
            digest=data["digest"],
        )
        item_ids = {item.id for item in pack.items}
        if (
            pack.as_dict() != data
            or pack.digest != sha256_hex(pack._content())
            or len(item_ids) != len(pack.items)
            or len(canonical_bytes(data)) > MAX_PACK_BYTES
        ):
            raise ValueError("invalid group assessment pack content")
        return pack


_EVIDENCE_KIND = TypeAdapter[EvidenceKind](EvidenceKind)
_EVIDENCE_FIELDS = TypeAdapter[dict[str, EvidenceValue]](dict[str, EvidenceValue])
_GAPS = TypeAdapter[dict[str, GapState]](dict[str, GapState])


@dataclass(frozen=True, slots=True)
class _Subject:
    site_id: str
    group_id: str
    revision: str
    as_of: datetime
    member_count: int
    rule_id: str | None
    agent_id: str | None
    primary_entity: str | None
    scope_id: str

    def item(
        self, kind: EvidenceKind, fetch_id: str, source: str, fields: dict[str, EvidenceValue]
    ) -> EvidenceItem:
        item_id = evidence_id(
            question_id=self.group_id,
            environment_id=self.site_id,
            topic_id=_PACK_VERSION,
            fetch_id=fetch_id,
            check_id=None,
            kind=kind,
            source=source,
            snapshot_key=self.scope_id,
            values=fields,
        )
        return EvidenceItem(item_id, kind, MappingProxyType(fields), fetch_id, self.scope_id)


def build_pack(
    conn: psycopg.Connection[Any], *, score: ScoreResult, as_of: datetime
) -> EvidencePack:
    """Resolve immutable observations and context at the score's own cutoff."""
    require_site_transaction(conn, score.site_id)
    if (
        as_of.tzinfo is None
        or as_of.utcoffset() is None
        or as_of != score.inputs.as_of
        or (score.site_id, score.group_id) != (score.inputs.site_id, score.inputs.group_id)
    ):
        raise ValueError("assessment pack differs from the frozen score cutoff or subject")
    revision = score.inputs.group_revision
    pins = (score.site_id, score.group_id, revision)
    revision_row = conn.execute(
        "SELECT alert_count, rule_id, agent_id, primary_entity FROM group_revisions "
        "WHERE site_id=%s AND group_id=%s AND revision=%s AND created_at <= %s",
        (*pins, as_of),
    ).fetchone()
    if revision_row is None:
        raise LookupError("group assessment revision is unavailable at the score cutoff")
    manifest_row = conn.execute(
        "SELECT manifest->'enrichment_ids', manifest->'score_output' FROM score_manifests "
        "WHERE site_id=%s AND group_id=%s AND group_revision=%s "
        "AND computation_version=%s AND input_digest=%s",
        (*pins, score.computation_version, score.input_digest),
    ).fetchone()
    if manifest_row is None or ScoreResult.model_validate(manifest_row[1]) != score:
        raise LookupError("group assessment score has no exact retained manifest")
    member_count, rule_id, agent_id, primary_entity = revision_row
    subject = _Subject(
        site_id=score.site_id,
        group_id=score.group_id,
        revision=revision,
        as_of=as_of.astimezone(UTC),
        member_count=member_count,
        rule_id=rule_id,
        agent_id=agent_id,
        primary_entity=primary_entity,
        scope_id=sha256_hex((*pins, as_of, score.computation_version, score.input_digest)),
    )
    context, gaps, matched_noise_keys = _context_items(conn, subject, manifest_row[0])
    aggregate, samples, missing_fields, is_ssh = _observations(conn, subject, matched_noise_keys)
    observed_count = aggregate.fields["observed_member_count"]
    gaps["observations"] = "present" if observed_count == subject.member_count else "failed"
    history, gaps["history"] = _history(conn, subject)
    gaps["knowledge"] = "not_configured"
    score_view = PackScore(
        computation_version=score.computation_version,
        input_digest=score.input_digest,
        total=score.total,
        components=tuple(
            PackScoreComponent.model_validate(component.model_dump(exclude={"evidence_ids"}))
            for component in score.components
        ),
    )
    pack = EvidencePack(
        site_id=subject.site_id,
        group_id=subject.group_id,
        revision=subject.revision,
        as_of=subject.as_of,
        member_count=subject.member_count,
        rule_family="ssh" if is_ssh else "default",
        gaps=MappingProxyType(gaps),
        missing_fields=missing_fields,
        trimmed=observed_count != len(samples),
        has_excerpt=False,
        items=(aggregate, *context),
        score=score_view,
        digest="0" * 64,
    )
    return _fit_pack(pack, samples=samples, history=history, knowledge=[])


def _fit_pack(
    required: EvidencePack,
    *,
    samples: list[EvidenceItem],
    history: list[EvidenceItem],
    knowledge: list[EvidenceItem],
) -> EvidencePack:
    trimmed = required.trimmed
    while True:
        pack = replace(
            required,
            trimmed=trimmed,
            items=(*required.items, *samples, *history, *knowledge),
        )
        if len(canonical_bytes(pack.as_dict())) <= MAX_PACK_BYTES:
            return pack.with_digest()
        for section in (samples, history, knowledge):
            if section:
                section.pop()
                trimmed = True
                break
        else:
            raise ValueError("required group assessment evidence exceeds the pack budget")


def _observations(
    conn: psycopg.Connection[Any], subject: _Subject, matched_noise_keys: frozenset[str]
) -> tuple[EvidenceItem, list[EvidenceItem], tuple[str, ...], bool]:
    counts = dict.fromkeys(_ALERT_FIELDS, 0)
    observed_count = brute_count = success_count = known_noise_count = 0
    is_ssh = subject.rule_id in _SSH_RULES
    first_event = last_event = None
    samples: list[EvidenceItem] = []
    with conn.cursor(name="assessment_members") as cursor:
        cursor.execute(
            """SELECT alert_key, event_ts, normalized_snapshot -> 'rule_id',
                      normalized_snapshot -> 'rule_level', normalized_snapshot -> 'decoder',
                      normalized_snapshot -> 'src_ip', normalized_snapshot -> 'dst_user',
                      normalized_snapshot -> 'src_user', normalized_snapshot -> 'agent_id',
                      normalized_snapshot -> 'rule_description'
               FROM group_members
               WHERE site_id=%s AND group_id=%s AND group_revision=%s AND event_ts <= %s
               ORDER BY event_ts, alert_key""",
            (subject.site_id, subject.group_id, subject.revision, subject.as_of),
        )
        for alert_key, event_at, *values in cursor:
            observed_count += 1
            first_event = event_at if first_event is None else first_event
            last_event = event_at
            raw = dict(zip(_ALERT_FIELDS, values, strict=True))
            if raw["decoder"] == "sshd":
                is_ssh = True
                brute_count += int(raw["rule_id"] == "5763")
                success_count += int(raw["rule_id"] in ("5715", "40112"))
            known_noise_count += int(alert_key in matched_noise_keys)
            fields, flags = _alert_fields(raw)
            for field in fields:
                counts[field] += 1
            if len(samples) < _MAX_MEMBER_SAMPLES:
                fields["event_at"] = _instant(event_at)
                fields["alert_key"] = alert_key
                if flags:
                    fields["input_flags"] = flags
                samples.append(subject.item("row", "group_members", alert_key, fields))
    if observed_count > subject.member_count:
        raise ValueError("observed group members exceed retained revision count")
    aggregate: dict[str, EvidenceValue] = {
        "member_count": subject.member_count,
        "observed_member_count": observed_count,
        "ssh_brute_force_count": brute_count,
        "ssh_success_count": success_count,
        "known_noise_member_count": known_noise_count,
    }
    if first_event is not None and last_event is not None:
        aggregate["first_event_at"] = _instant(first_event)
        aggregate["last_event_at"] = _instant(last_event)
    missing_fields = tuple(field for field, count in counts.items() if count < subject.member_count)
    return (
        subject.item("aggregate", "group_members", "summary", aggregate),
        samples,
        missing_fields,
        is_ssh,
    )


def _alert_fields(raw: Mapping[str, object]) -> tuple[dict[str, EvidenceValue], tuple[str, ...]]:
    fields: dict[str, EvidenceValue] = {}
    flagged: list[str] = []
    for field, value in raw.items():
        if field == "rule_level":
            if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 32767:
                fields[field] = value
        elif isinstance(value, str):
            sanitized, has_controls = _text(value)
            if sanitized:
                fields[field] = sanitized
            if has_controls:
                flagged.append(field)
    return fields, tuple(flagged)


def _context_items(
    conn: psycopg.Connection[Any], subject: _Subject, enrichment_ids: object
) -> tuple[list[EvidenceItem], dict[str, GapState], frozenset[str]]:
    pins = _ENRICHMENT_PINS.validate_python(enrichment_ids)
    rows = conn.execute(
        """SELECT enrichment_id, source, source_version, availability, gap_state,
                  fetched_at, expires_at, value
           FROM enrichments WHERE site_id=%s AND group_id=%s AND group_revision=%s
             AND enrichment_id = ANY(%s) ORDER BY source""",
        (subject.site_id, subject.group_id, subject.revision, pins),
    ).fetchall()
    if len(rows) != len(pins) or {row[1] for row in rows} != set(_CONTEXT_FIELDS):
        raise ValueError("group assessment manifest has missing or duplicate context pins")
    gaps: dict[str, GapState] = dict.fromkeys(_CONTEXT_FIELDS, "failed")
    items: list[EvidenceItem] = []
    matched_noise_keys: frozenset[str] = frozenset()
    for record_id, source, version, availability, gap, fetched, expires, value in rows:
        future = fetched > subject.as_of
        expired = expires is not None and expires <= subject.as_of
        state = enrichment_gap(_AVAILABILITY.validate_python(availability), gap)
        if future or (expired and state in ("present", "empty")):
            state = "stale"
        gaps[source] = state
        fields: dict[str, EvidenceValue] = {"category": source, "gap_state": state}
        if not future:
            fields.update(
                snapshot_id=str(record_id),
                source_version=_text(version)[0],
                fetched_at=_instant(fetched),
            )
            if expires is not None:
                fields["expires_at"] = _instant(expires)
            fields.update(_context_fields(value, _PROVENANCE_FIELDS))
        if state in ("present", "empty"):
            fields.update(_context_fields(value, _CONTEXT_FIELDS[source]))
        if source == "known_noise" and state == "present":
            matched_noise_keys = _matched_noise_keys(value)
        kind: EvidenceKind = "context" if state == "present" else "check"
        items.append(subject.item(kind, source, str(record_id) if not future else source, fields))
    return items, gaps, matched_noise_keys


_AVAILABILITY = TypeAdapter[Availability](Availability)
_ENRICHMENT_PINS = TypeAdapter[list[UUID]](list[UUID])


def _matched_noise_keys(value: Mapping[str, object]) -> frozenset[str]:
    score = value.get("score_value")
    matched = value.get("matched_alert_keys")
    if (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not 0 < score <= 1
        or not isinstance(matched, list)
    ):
        return frozenset()
    return frozenset(
        key
        for key in cast(list[object], matched)
        if isinstance(key, str) and _KEY_RE.fullmatch(key)
    )


def _context_fields(
    value: Mapping[str, object], allowed: tuple[str, ...]
) -> dict[str, EvidenceValue]:
    fields: dict[str, EvidenceValue] = {}
    for field in allowed:
        raw = value.get(field)
        if field in _CONTEXT_LIST_FIELDS:
            if isinstance(raw, list):
                values = cast(list[object], raw)[:_MAX_CONTEXT_VALUES]
                fields[field] = tuple(_text(item)[0] for item in values if isinstance(item, str))
        elif isinstance(raw, (bool, int)) or (isinstance(raw, float) and math.isfinite(raw)):
            fields[field] = raw
        elif isinstance(raw, str):
            fields[field] = _text(raw)[0]
    return fields


def _history(
    conn: psycopg.Connection[Any], subject: _Subject
) -> tuple[list[EvidenceItem], GapState]:
    if not subject.rule_id or not (subject.agent_id or subject.primary_entity):
        return [], "failed"
    start = subject.as_of - timedelta(days=90)
    rows = conn.execute(
        """SELECT d.label, count(*) FROM dispositions d JOIN group_revisions g
             ON (g.site_id,g.group_id,g.revision)=(d.site_id,d.group_id,d.group_revision_seen)
           WHERE d.site_id=%s AND g.rule_id=%s AND (g.agent_id=%s OR g.primary_entity=%s)
             AND d.at >= %s AND d.at < %s AND g.created_at < %s
           GROUP BY d.label""",
        (
            subject.site_id,
            subject.rule_id,
            subject.agent_id,
            subject.primary_entity,
            start,
            subject.as_of,
            subject.as_of,
        ),
    ).fetchall()
    counts = dict.fromkeys(_DISPOSITION_LABELS, 0)
    counts.update(rows)
    fields: dict[str, EvidenceValue] = {label: count for label, count in counts.items()}
    fields["window_from"] = _instant(start)
    fields["window_to"] = _instant(subject.as_of)
    fields["conflicting"] = counts["true_positive"] > 0 and counts["false_positive"] > 0
    return [subject.item("history", "dispositions", "counts", fields)], (
        "present" if any(counts.values()) else "empty"
    )


def _instant(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("assessment evidence timestamps must be timezone aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _text(value: str) -> tuple[str, bool]:
    def control(char: str) -> bool:
        return (
            unicodedata.category(char) in {"Cc", "Cf", "Zl", "Zp"}
            or char == "\u034f"
            or "\ufe00" <= char <= "\ufe0f"
            or "\U000e0100" <= char <= "\U000e01ef"
        )

    normalized = unicodedata.normalize("NFKC", value)
    flagged = any(map(control, value)) or any(map(control, normalized))
    printable = "".join("\ufffd" if control(char) else char for char in normalized).strip()
    return printable.encode("utf-8")[:_MAX_TEXT_BYTES].decode("utf-8", errors="ignore"), flagged
