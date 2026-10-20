"""Finite query templates and allowlisted Wazuh indexer DSL compilation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC
from urllib.parse import quote

from ai_soc.contracts.models import (
    AuthorizedSite,
    ErrorCode,
    FetchSpec,
    FieldId,
    Filter,
    IndexFamily,
    TemplateId,
)


class QueryCompileError(ValueError):
    def __init__(self, code: ErrorCode = ErrorCode.QUERY_INVALID) -> None:
        self.code = code
        super().__init__(code.value)


@dataclass(frozen=True, slots=True)
class MappingProfile:
    profile_id: str
    fields: dict[FieldId, str]
    alert_projection: tuple[FieldId, ...]
    vulnerability_projection: tuple[FieldId, ...]
    tie_break_field: str | None


@dataclass(frozen=True, slots=True)
class CompiledQuery:
    path: str
    body: dict[str, object]
    family: IndexFamily
    template_id: TemplateId
    projected_fields: tuple[FieldId, ...]
    exact_count: bool
    is_grouped: bool


_TEMPLATES: dict[TemplateId, tuple[IndexFamily, str]] = {
    TemplateId.alerts_rows_v1: (IndexFamily.alerts, "rows"),
    TemplateId.alerts_count_v1: (IndexFamily.alerts, "count"),
    TemplateId.alerts_group_v1: (IndexFamily.alerts, "group"),
    TemplateId.vulnerabilities_rows_v1: (IndexFamily.vulnerabilities, "rows"),
    TemplateId.vulnerabilities_count_v1: (IndexFamily.vulnerabilities, "count"),
    TemplateId.vulnerabilities_group_v1: (IndexFamily.vulnerabilities, "group"),
}

_FAMILY_FIELDS: dict[IndexFamily, frozenset[FieldId]] = {
    IndexFamily.alerts: frozenset(
        {
            FieldId.timestamp,
            FieldId.agent_id,
            FieldId.agent_name,
            FieldId.rule_id,
            FieldId.rule_level,
            FieldId.rule_groups,
            FieldId.data_srcip,
            FieldId.data_dstip,
        }
    ),
    IndexFamily.vulnerabilities: frozenset(
        {
            FieldId.agent_id,
            FieldId.agent_name,
            FieldId.vulnerability_id,
            FieldId.vulnerability_severity,
            FieldId.vulnerability_detected_at,
            FieldId.package_name,
            FieldId.package_version,
        }
    ),
}


def default_profile(profile_id: str = "wazuh-v4-fixture") -> MappingProfile:
    """A fixture profile; live sites must select and validate a pinned mapping profile."""
    names = {
        FieldId.timestamp: "@timestamp",
        FieldId.agent_id: "agent.id",
        FieldId.agent_name: "agent.name",
        FieldId.rule_id: "rule.id",
        FieldId.rule_level: "rule.level",
        FieldId.rule_groups: "rule.groups",
        FieldId.data_srcip: "data.srcip",
        FieldId.data_dstip: "data.dstip",
        FieldId.vulnerability_id: "vulnerability.id",
        FieldId.vulnerability_severity: "vulnerability.severity",
        FieldId.vulnerability_detected_at: "vulnerability.detected_at",
        FieldId.package_name: "package.name",
        FieldId.package_version: "package.version",
    }
    alert = tuple(field for field in names if field in _FAMILY_FIELDS[IndexFamily.alerts])
    vuln = tuple(field for field in names if field in _FAMILY_FIELDS[IndexFamily.vulnerabilities])
    return MappingProfile(profile_id, names, alert, vuln, "_id")


def _field(profile: MappingProfile, family: IndexFamily, field: FieldId) -> str:
    if field not in _FAMILY_FIELDS[family] or field not in profile.fields:
        raise QueryCompileError(ErrorCode.MAPPING_UNSUPPORTED)
    name = profile.fields[field]
    if not name or name.startswith("_") or any(ch in name for ch in "*?[]{}"):
        raise QueryCompileError(ErrorCode.MAPPING_UNSUPPORTED)
    return name


def _filter_clause(profile: MappingProfile, family: IndexFamily, item: Filter) -> dict[str, object]:
    field = _field(profile, family, item.field)
    if item.op == "eq":
        return {"term": {field: item.value}}
    if item.op == "in":
        return {"terms": {field: item.value}}
    if item.op == "exists":
        return {"exists": {"field": field}}
    if item.op in ("gte", "lte") and item.field == FieldId.rule_level:
        return {"range": {field: {item.op: item.value}}}
    raise QueryCompileError()


def compile_fetch(fetch: FetchSpec, site: AuthorizedSite, profile: MappingProfile) -> CompiledQuery:
    """Compile a contract FetchSpec to one of six service-owned templates."""
    if profile.profile_id != site.config.mapping_profile:
        raise QueryCompileError(ErrorCode.MAPPING_UNSUPPORTED)
    try:
        family, operation = _TEMPLATES[fetch.template_id]
    except KeyError as exc:
        raise QueryCompileError() from exc
    if fetch.template_id not in site.config.allowed_templates:
        raise QueryCompileError(ErrorCode.SITE_DENIED)
    if family not in site.config.allowed_index_patterns:
        raise QueryCompileError(ErrorCode.MAPPING_UNSUPPORTED)
    patterns = site.config.allowed_index_patterns[family]
    if not patterns or len(patterns) > 8:
        raise QueryCompileError(ErrorCode.MAPPING_UNSUPPORTED)
    if any(not p or p.startswith("/") or ".." in p or any(c in p for c in "?#") for p in patterns):
        raise QueryCompileError(ErrorCode.MAPPING_UNSUPPORTED)
    index_path = quote(",".join(patterns), safe="*,_-.")
    filters: list[dict[str, object]] = [
        {
            "range": {
                _field(
                    profile,
                    family,
                    FieldId.timestamp
                    if family == IndexFamily.alerts
                    else FieldId.vulnerability_detected_at,
                ): {
                    "gte": fetch.window.start.astimezone(UTC).isoformat().replace("+00:00", "Z"),
                    "lt": fetch.window.end.astimezone(UTC).isoformat().replace("+00:00", "Z"),
                }
            }
        }
    ]
    filters.extend(_filter_clause(profile, family, item) for item in fetch.filters)
    query: dict[str, object] = {"bool": {"filter": filters}}
    if operation == "count":
        return CompiledQuery(
            f"/{index_path}/_count", {"query": query}, family, fetch.template_id, (), True, False
        )
    if operation == "group":
        group = fetch.group_by
        if group is None:
            raise QueryCompileError()
        mapped = _field(profile, family, FieldId(str(group)))
        body: dict[str, object] = {
            "size": 0,
            "query": query,
            "aggs": {
                "visible_groups": {"terms": {"field": mapped, "size": 20, "order": {"_key": "asc"}}}
            },
            "track_total_hits": True,
        }
        return CompiledQuery(
            f"/{index_path}/_search", body, family, fetch.template_id, (), True, True
        )
    projection = (
        profile.alert_projection
        if family == IndexFamily.alerts
        else profile.vulnerability_projection
    )
    mapped_projection = [_field(profile, family, field) for field in projection]
    sort_field = _field(
        profile,
        family,
        FieldId.timestamp if family == IndexFamily.alerts else FieldId.vulnerability_detected_at,
    )
    direction = "desc" if fetch.order == "latest" else "asc"
    if not profile.tie_break_field:
        # Positive first pages remain useful; cursor support is independently gated.
        sort = [{sort_field: {"order": direction}}]
    else:
        if profile.tie_break_field != "_id":
            raise QueryCompileError(ErrorCode.MAPPING_UNSUPPORTED)
        sort = [
            {sort_field: {"order": direction}},
            {"_index": {"order": direction}},
            {"_id": {"order": direction}},
        ]
    size = min(fetch.page_size, fetch.limit or fetch.page_size)
    body = {
        "size": size,
        "query": query,
        "_source": mapped_projection,
        "sort": sort,
        "track_total_hits": 10_000,
    }
    return CompiledQuery(
        f"/{index_path}/_search", body, family, fetch.template_id, projection, False, False
    )
