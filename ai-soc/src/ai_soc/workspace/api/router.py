"""M0 authorization boundary and bounded M1 read endpoints."""

# FastAPI requires Depends/Query metadata in route defaults.
# ruff: noqa: B008

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, NoReturn
from uuid import uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Depends, Header, Query, Request
from fastapi.responses import JSONResponse
from psycopg import Error as PsycopgError
from pydantic import TypeAdapter

from ai_soc.contracts.models import VerifiedPrincipal, Visibility
from ai_soc.identity.policy import SiteAuthorizationError
from ai_soc.workspace.api.common import (
    CURSOR_VALUES,
    ERROR_RESPONSES,
    WorkspaceApiError,
    WorkspaceJSONResponse,
)
from ai_soc.workspace.api.common import (
    aware as _aware,
)
from ai_soc.workspace.api.common import (
    count as _count,
)
from ai_soc.workspace.api.common import (
    cursor_datetime as _cursor_datetime,
)
from ai_soc.workspace.api.common import (
    cursor_decode as _cursor_decode,
)
from ai_soc.workspace.api.common import (
    cursor_encode as _cursor_encode,
)
from ai_soc.workspace.api.common import (
    cursor_filters as _cursor_filters,
)
from ai_soc.workspace.api.common import (
    cursor_pair as _cursor_pair,
)
from ai_soc.workspace.api.common import (
    mapping as _mapping,
)
from ai_soc.workspace.api.common import (
    optional_datetime as _optional_datetime,
)
from ai_soc.workspace.api.common import (
    validate_query as _validate_query,
)
from ai_soc.workspace.api.common import (
    window as _window,
)
from ai_soc.workspace.api.models import (
    AlertDetail,
    AlertSummary,
    AssetTag,
    AssetTagUpsertRequest,
    AssignRequest,
    BacklogStats,
    BulkActionRequest,
    BulkActionResponse,
    Disposition,
    DispositionRequest,
    Enrichment,
    EntityRef,
    ErrorResponse,
    GroupContextResponse,
    GroupDetail,
    GroupSummary,
    HistoryEntry,
    HourlyBucket,
    IngestionCounts,
    IngestionFreshness,
    IngestionHealthResponse,
    LabelCount,
    MetricStats,
    OpsMetricsResponse,
    OverviewResponse,
    OverviewTotals,
    Page,
    PipelineRunSummary,
    PrecisionAtK,
    QualityMetricsResponse,
    QueueSummary,
    ReconciliationSummary,
    RulePrecision,
    ScoreComponent,
    SiteSummary,
    StatusRequest,
    TopCount,
    Window,
    WorkState,
)
from ai_soc.workspace.api.repository import WorkspaceRepository
from ai_soc.workspace.api.runtime import WorkspaceRuntime
from ai_soc.workspace.feedback import (
    FeedbackConflict,
    assign_group,
    bulk_group_action,
    change_group_status,
    record_group_disposition,
    upsert_asset_tag,
)
from ai_soc.workspace.metrics import ops_metrics, quality_metrics

_SCORE_COMPONENT_ROWS: TypeAdapter[list[dict[str, object]]] = TypeAdapter(list[dict[str, object]])


def _summary(row: dict[str, Any]) -> AlertSummary:
    n: dict[str, Any] = row.get("normalized") or {}
    return AlertSummary(
        alert_key=row["alert_key"],
        event_ts=row["event_ts"],
        rule_id=n.get("rule_id"),
        rule_level=n.get("rule_level"),
        rule_description=n.get("rule_description"),
        rule_groups=n.get("rule_groups") or [],
        mitre_tactics=n.get("mitre_tactics") or [],
        mitre_techniques=n.get("mitre_techniques") or [],
        agent_id=n.get("agent_id"),
        agent_name=n.get("agent_name"),
        agent_ip=n.get("agent_ip"),
        src_ip=n.get("src_ip"),
        dst_ip=n.get("dst_ip"),
        src_user=n.get("src_user"),
        dst_user=n.get("dst_user"),
        group_id=None,
    )


def _site_summary(row: dict[str, Any]) -> SiteSummary:
    return SiteSummary(
        **{
            key: row[key]
            for key in (
                "site_id",
                "label",
                "wazuh_version",
                "health",
                "health_detail",
                "updated_at",
            )
        }
    )


def _entity_ref(row: dict[str, Any]) -> EntityRef:
    return EntityRef(
        kind=row["kind"],
        value=row["value_norm"],
        role=row["role"],
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
    )


def _metric_value(value: Any) -> float | None:
    return None if value is None else float(value)


def workspace_router(
    runtime: WorkspaceRuntime,
    principal_dependency: Callable[..., Any],
    verify_csrf: Callable[[Request, VerifiedPrincipal], None],
) -> APIRouter:
    router = APIRouter(default_response_class=WorkspaceJSONResponse)

    def authorize(principal: VerifiedPrincipal, site_id: str):
        try:
            result = runtime.site_policy.authorize(principal, site_id)
        except SiteAuthorizationError:
            raise WorkspaceApiError(
                403, "WORKSPACE_DENIED", "Full site visibility is required"
            ) from None
        if result.visibility != Visibility.full:
            raise WorkspaceApiError(403, "WORKSPACE_DENIED", "Full site visibility is required")
        return result

    def repository(site_id: str, principal: VerifiedPrincipal) -> WorkspaceRepository:
        authorize(principal, site_id)
        try:
            repo = WorkspaceRepository.connect(runtime.dsn_provider(), site_id)
            if repo.site() is None:
                repo.close()
                raise WorkspaceApiError(404, "SITE_UNKNOWN", "Site is unknown")
            return repo
        except WorkspaceApiError:
            raise
        except PermissionError:
            raise WorkspaceApiError(
                403, "WORKSPACE_DENIED", "Full site visibility is required"
            ) from None
        except PsycopgError:
            raise WorkspaceApiError(
                503, "UNAVAILABLE", "Workspace data is temporarily unavailable", retryable=True
            ) from None

    def write_repository(site_id: str, principal: VerifiedPrincipal) -> WorkspaceRepository:
        return repository(site_id, principal)

    def _write_error(error: Exception) -> NoReturn:
        if isinstance(error, FeedbackConflict):
            raise WorkspaceApiError(409, "CONFLICT", str(error)) from None
        if isinstance(error, LookupError):
            raise WorkspaceApiError(
                404, "RESOURCE_UNKNOWN", "Workspace resource is unknown"
            ) from None
        if isinstance(error, ValueError):
            raise WorkspaceApiError(422, "BAD_FILTER", str(error)) from None
        raise error

    def _disposition(row: dict[str, Any]) -> Disposition | None:
        if row.get("disposition_id") is None:
            return None
        return Disposition.model_validate(
            {
                "disposition_id": str(row["disposition_id"]),
                "label": row["label"],
                "reason_code": row["reason_code"],
                "note": row["note"],
                "actor_key": row["actor_key"],
                "at": row["disposition_at"],
                "propagate_to_members": row["propagate_to_members"],
            }
        )

    def _group_summary(row: dict[str, Any]) -> GroupSummary:
        entity = row["primary_entity"]
        primary_entity = None
        if entity:
            kind, _, value = str(entity).partition(":")
            primary_entity = EntityRef.model_validate(
                {
                    "kind": kind,
                    "value": value,
                    "role": "primary",
                    "first_seen": row["primary_first_seen"] or row["first_ts"],
                    "last_seen": row["primary_last_seen"] or row["last_ts"],
                }
            )
        return GroupSummary(
            group_id=str(row["group_id"]),
            group_revision=str(row["revision"]),
            title=str(row["title"]),
            score=None if row["total"] is None else float(row["total"]),
            computation_version=row["computation_version"],
            input_digest=row["input_digest"],
            components=[
                ScoreComponent.model_validate(item)
                for item in _SCORE_COMPONENT_ROWS.validate_python(row["components"] or [])
            ],
            alert_count=int(row["alert_count"]),
            first_ts=row["first_ts"],
            last_ts=row["last_ts"],
            rule_id=row["rule_id"],
            primary_entity=primary_entity,
            status=str(row["status"]),
            owner_key=row["owner_key"],
            disposition=_disposition(row),
            pipeline_version=str(row["pipeline_version"]),
        )

    def _work_state(row: dict[str, Any]) -> WorkState:
        return WorkState.model_validate(
            {
                "status": row["status"],
                "owner_key": row["owner_key"],
                "updated_at": row["updated_at"],
            }
        )

    def _work_result(result: dict[str, Any]) -> WorkState:
        return WorkState.model_validate(
            {
                "status": result["status"],
                "owner_key": result["owner_key"],
                "updated_at": datetime.fromisoformat(result["updated_at"]),
            }
        )

    @router.get(
        "/sites",
        response_model=Page[SiteSummary],
        operation_id="workspace_list_sites",
        responses=ERROR_RESPONSES,
    )
    def sites(
        request: Request,
        principal: VerifiedPrincipal = Depends(principal_dependency),
        limit: int = Query(50, ge=1, le=200),
        cursor: str | None = None,
    ):
        _validate_query(request, {"limit", "cursor"})
        # Resolve configured sites from policy, then authorize each exact site and
        # read it under its own scalar RLS context.
        configs = runtime.site_policy.authorized_sites(principal)
        rows: list[dict[str, Any]] = []
        after: str | None = None
        if cursor:
            token = _cursor_decode(runtime.cursor_secret, cursor, runtime.now().astimezone(UTC))
            if token.get("route") != "sites" or token.get("owner") != principal.owner_key:
                raise WorkspaceApiError(400, "CURSOR_INVALID", "cursor does not match this request")
            raw_after = token.get("after")
            if not isinstance(raw_after, str):
                raise WorkspaceApiError(400, "CURSOR_INVALID", "cursor does not match this request")
            after = raw_after
        for config in configs:
            site_id = config.environment_id
            try:
                authorized = authorize(principal, site_id)
            except WorkspaceApiError:
                continue
            if authorized.visibility != Visibility.full:
                continue
            try:
                repo = WorkspaceRepository.connect(runtime.dsn_provider(), site_id)
                try:
                    row = repo.site()
                finally:
                    repo.close()
            except PermissionError:
                raise WorkspaceApiError(
                    403, "WORKSPACE_DENIED", "Full site visibility is required"
                ) from None
            except PsycopgError:
                raise WorkspaceApiError(
                    503, "UNAVAILABLE", "Workspace data is temporarily unavailable", retryable=True
                ) from None
            if row and (after is None or site_id > after):
                rows.append(row)
        rows.sort(key=lambda row: row["site_id"])
        page = rows[: limit + 1]
        next_cursor = None
        if len(page) > limit:
            next_cursor = _cursor_encode(
                runtime.cursor_secret,
                {
                    "route": "sites",
                    "owner": principal.owner_key,
                    "after": page[limit - 1]["site_id"],
                    "exp": (runtime.now() + timedelta(minutes=15)).timestamp(),
                },
            )
            page = page[:limit]
        return Page[SiteSummary](
            items=[_site_summary(row) for row in page], next_cursor=next_cursor, limit=limit
        )

    @router.get(
        "/overview",
        response_model=OverviewResponse,
        operation_id="workspace_overview",
        responses=ERROR_RESPONSES,
    )
    def overview(
        request: Request,
        site_id: str,
        from_: datetime | None = Query(None, alias="from"),
        to: datetime | None = None,
        range_: str | None = Query(None, alias="range"),
        tz: str = Query("UTC", max_length=64),
        principal: VerifiedPrincipal = Depends(principal_dependency),
    ):
        _validate_query(request, {"site_id", "from", "to", "range", "tz"})
        try:
            ZoneInfo(tz)
        except (ZoneInfoNotFoundError, ValueError):
            raise WorkspaceApiError(
                422, "BAD_FILTER", "tz must be a supported IANA timezone", details={"field": "tz"}
            ) from None
        start, end, preset = _window(runtime.now(), from_, to, range_)
        repo = repository(site_id, principal)
        try:
            site = repo.site()
            if site is None:
                raise WorkspaceApiError(404, "SITE_UNKNOWN", "Site is unknown")
            data = repo.overview(start, end, runtime.now().astimezone(UTC))
        finally:
            repo.close()
        success_row = _mapping(data.get("success"))
        checkpoint_row = _mapping(data.get("checkpoint"))
        success = _optional_datetime(success_row.get("last_success_at"))
        checkpoint = _optional_datetime(checkpoint_row.get("checkpoint_at"))
        checkpoint_source = checkpoint_row
        lag = (
            max(0, int((runtime.now().astimezone(UTC) - checkpoint).total_seconds()))
            if checkpoint
            else None
        )
        source_count = _count(checkpoint_source.get("source_count"))
        checkpoint_updated = _optional_datetime(checkpoint_source.get("oldest_updated_at"))
        success_lag = (
            max(0, int((runtime.now().astimezone(UTC) - success).total_seconds()))
            if success
            else None
        )
        stale = (
            success_lag is None
            or success_lag > 900
            or checkpoint_updated is None
            or (runtime.now().astimezone(UTC) - checkpoint_updated).total_seconds() > 900
            or source_count == 0
        )
        health = (
            site["health"]
            if site["health"] in {"auth_failed", "unreachable"}
            else (
                "unknown" if source_count == 0 and success is None else "lagging" if stale else "ok"
            )
        )
        freshness = IngestionFreshness(
            last_success_at=success,
            checkpoint_at=checkpoint,
            lag_seconds=lag,
            reconcile_mismatches_48h=_count(_mapping(data.get("mismatch")).get("mismatched")),
            state=health,
        )

        def tops(rows: list[dict[str, Any]]) -> list[TopCount]:
            return [
                TopCount(
                    key=str(row["key"]),
                    label=str(row.get("label") or row["key"]),
                    count=int(row["count"]),
                )
                for row in rows
            ]

        hourly = [
            HourlyBucket(hour=row["hour"], level_band=row["level_band"], count=int(row["count"]))
            for row in data["hourly"]
        ]
        return OverviewResponse(
            site=_site_summary(site),
            window=Window.model_validate({"from": start, "to": end, "preset": preset}),
            totals=OverviewTotals(alerts=int(data["totals"]["alerts"])),
            hourly=hourly,
            top_rules=tops(data["rules"]),
            top_agents=tops(data["agents"]),
            top_tactics=tops(data["tactics"]),
            top_src_ips=tops(data["ips"]),
            top_users=tops(data["users"]),
            freshness=freshness,
        )

    @router.get(
        "/alerts",
        response_model=Page[AlertSummary],
        operation_id="workspace_list_alerts",
        responses=ERROR_RESPONSES,
    )
    def alerts(
        request: Request,
        site_id: str,
        from_: datetime | None = Query(None, alias="from"),
        to: datetime | None = None,
        rule_id: str | None = Query(None, max_length=64),
        min_level: int | None = Query(None, ge=0, le=15),
        max_level: int | None = Query(None, ge=0, le=15),
        agent_id: str | None = Query(None, max_length=128),
        tactic: str | None = Query(None, max_length=64),
        entity_kind: str | None = None,
        entity: str | None = Query(None, max_length=512),
        sort: str = "event_ts_desc",
        limit: int = Query(50, ge=1, le=200),
        cursor: str | None = None,
        principal: VerifiedPrincipal = Depends(principal_dependency),
    ):
        _validate_query(
            request,
            {
                "site_id",
                "from",
                "to",
                "rule_id",
                "min_level",
                "max_level",
                "agent_id",
                "tactic",
                "entity_kind",
                "entity",
                "sort",
                "limit",
                "cursor",
            },
        )
        if sort not in {"event_ts_desc", "event_ts_asc"}:
            raise WorkspaceApiError(
                422, "BAD_FILTER", "sort is unsupported", details={"field": "sort"}
            )
        if min_level is not None and max_level is not None and min_level > max_level:
            raise WorkspaceApiError(
                422,
                "BAD_FILTER",
                "min_level must not exceed max_level",
                details={"field": "min_level"},
            )
        if (entity is None) != (entity_kind is None) or (
            entity_kind is not None
            and entity_kind not in {"host", "ip", "user", "process", "file", "hash", "cve", "rule"}
        ):
            raise WorkspaceApiError(
                422,
                "BAD_FILTER",
                "entity and supported entity_kind must be supplied together",
                details={"field": "entity_kind"},
            )
        filters: dict[str, object] = {
            "rule_id": rule_id,
            "min_level": min_level,
            "max_level": max_level,
            "agent_id": agent_id,
            "tactic": tactic,
            "entity_kind": entity_kind,
            "entity": entity,
        }
        after = None
        token = None
        authorized = authorize(principal, site_id)
        if cursor:
            token = _cursor_decode(runtime.cursor_secret, cursor, runtime.now().astimezone(UTC))
            cursor_filters = _cursor_filters(token)
            for name, value in filters.items():
                if value is not None and cursor_filters.get(name) != value:
                    raise WorkspaceApiError(
                        400, "CURSOR_INVALID", "cursor does not match this request"
                    )
            filters = cursor_filters
            if "sort" not in request.query_params:
                token_sort = token.get("sort", sort)
                if not isinstance(token_sort, str):
                    raise WorkspaceApiError(
                        400, "CURSOR_INVALID", "cursor does not match this request"
                    )
                sort = token_sort
            bind = {
                "route": "alerts",
                "site": site_id,
                "owner": principal.owner_key,
                "policy": authorized.policy_hash,
                "sort": sort,
            }
            if any(token.get(key) != value for key, value in bind.items()):
                raise WorkspaceApiError(400, "CURSOR_INVALID", "cursor does not match this request")
            start = _cursor_datetime(token.get("from"))
            end = _cursor_datetime(token.get("to"))
            after_time, after_key = _cursor_pair(token)
            if not isinstance(after_key, str):
                raise WorkspaceApiError(400, "CURSOR_INVALID", "cursor does not match this request")
            after = (_cursor_datetime(after_time), after_key)
        else:
            start, end, _ = _window(runtime.now(), from_, to, None)
        if cursor and (
            from_ is not None
            and _aware(from_, "from") != start
            or to is not None
            and _aware(to, "to") != end
        ):
            raise WorkspaceApiError(400, "CURSOR_INVALID", "cursor does not match this request")
        repo = repository(site_id, principal)
        try:
            rows = repo.list_alerts(
                start=start, end=end, filters=filters, sort=sort, limit=limit + 1, after=after
            )
        finally:
            repo.close()
        has_more = len(rows) > limit
        rows = rows[:limit]
        next_cursor = None
        if has_more:
            last = rows[-1]
            next_cursor = _cursor_encode(
                runtime.cursor_secret,
                {
                    "route": "alerts",
                    "site": site_id,
                    "owner": principal.owner_key,
                    "policy": authorized.policy_hash,
                    "filters": filters,
                    "sort": sort,
                    "from": start.isoformat(),
                    "to": end.isoformat(),
                    "after": [last["event_ts"].isoformat(), last["alert_key"]],
                    "exp": (runtime.now() + timedelta(minutes=15)).timestamp(),
                },
            )
        return Page[AlertSummary](
            items=[_summary(row) for row in rows], next_cursor=next_cursor, limit=limit
        )

    @router.get(
        "/alerts/{alert_key}",
        response_model=AlertDetail,
        operation_id="workspace_get_alert",
        responses=ERROR_RESPONSES,
    )
    def alert_detail(
        request: Request,
        alert_key: str,
        site_id: str,
        principal: VerifiedPrincipal = Depends(principal_dependency),
    ):
        _validate_query(request, {"site_id"})
        repo = repository(site_id, principal)
        try:
            row = repo.alert(alert_key)
            if row is None:
                state = repo.alert_registry_state(alert_key)
                if state == "expired":
                    raise WorkspaceApiError(
                        404,
                        "RESOURCE_UNKNOWN",
                        "Alert payload has expired",
                        details={"reason": "payload_expired"},
                    )
                raise WorkspaceApiError(404, "RESOURCE_UNKNOWN", "Alert is unknown")
            entities = repo.entities_for_alert(alert_key, row["event_ts"])
        finally:
            repo.close()
        details = _summary(row).model_dump()
        n: dict[str, Any] = row.get("normalized") or {}
        detail = {
            **details,
            "wazuh_id": n.get("wazuh_id"),
            "manager": n.get("manager"),
            "decoder": n.get("decoder"),
            "location": n.get("location"),
            "entities": [_entity_ref(entity) for entity in entities],
            "raw": row["raw"],
            "normalize_gaps": row["normalize_gaps"] or [],
            "mapping_profile": row["mapping_profile"],
            "ingested_at": row["ingested_at"],
            "wazuh_url": None,
        }
        return AlertDetail.model_validate(detail)

    @router.get(
        "/alerts/{alert_key}/context",
        response_model=GroupContextResponse,
        operation_id="workspace_alert_context",
        responses=ERROR_RESPONSES,
    )
    def alert_context(
        request: Request,
        alert_key: str,
        site_id: str,
        from_: datetime | None = Query(None, alias="from"),
        to: datetime | None = None,
        limit: int = Query(50, ge=1, le=200),
        principal: VerifiedPrincipal = Depends(principal_dependency),
    ):
        _validate_query(request, {"site_id", "from", "to", "limit"})
        repo = repository(site_id, principal)
        try:
            anchor = repo.alert(alert_key)
            if anchor is None:
                state = repo.alert_registry_state(alert_key)
                if state == "expired":
                    raise WorkspaceApiError(
                        404,
                        "RESOURCE_UNKNOWN",
                        "Alert payload has expired",
                        details={"reason": "payload_expired"},
                    )
                raise WorkspaceApiError(404, "RESOURCE_UNKNOWN", "Alert is unknown")
            event_ts = anchor["event_ts"]
            start = _aware(from_, "from") or event_ts - timedelta(hours=1)
            end = _aware(to, "to") or event_ts + timedelta(hours=1)
            if end <= start or end - start > timedelta(hours=24):
                raise WorkspaceApiError(
                    422, "BAD_FILTER", "context window must be positive and no longer than 24 hours"
                )
            rows, entities = repo.context(alert_key, start, end, limit)
        finally:
            repo.close()
        return GroupContextResponse(
            group_id=alert_key,
            site_id=site_id,
            alerts=[_summary(row) for row in rows],
            entities=[_entity_ref(entity) for entity in entities],
            enrichments=[],
            related_groups=[],
            window=Window.model_validate({"from": start, "to": end, "preset": None}),
        )

    @router.get(
        "/health/ingestion",
        response_model=IngestionHealthResponse,
        operation_id="workspace_ingestion_health",
        responses=ERROR_RESPONSES,
    )
    def ingestion_health(
        request: Request, site_id: str, principal: VerifiedPrincipal = Depends(principal_dependency)
    ):
        _validate_query(request, {"site_id"})
        repo = repository(site_id, principal)
        try:
            site = repo.site()
            if site is None:
                raise WorkspaceApiError(404, "SITE_UNKNOWN", "Site is unknown")
            data = repo.health(runtime.now().astimezone(UTC))
        finally:
            repo.close()
        run = data["run"]
        success_row = _mapping(data.get("last"))
        checkpoint_row = _mapping(data.get("checkpoint"))
        success = _optional_datetime(success_row.get("at"))
        checkpoint = _optional_datetime(checkpoint_row.get("at"))
        reconciliation = data["reconciliation"]
        run_summary = None
        if run:
            run_summary = PipelineRunSummary(
                run_id=str(run["run_id"]),
                kind=run["kind"],
                started_at=run["started_at"],
                finished_at=run["finished_at"],
                outcome=run["outcome"] or "running",
                error_code=run["error_code"],
                pipeline_version=run["pipeline_version"],
            )
        return IngestionHealthResponse(
            site=_site_summary(site),
            checkpoint_at=checkpoint,
            last_success_at=success,
            last_run=run_summary,
            lag_seconds=max(0, int((runtime.now().astimezone(UTC) - checkpoint).total_seconds()))
            if checkpoint
            else None,
            counts=IngestionCounts(
                read=int(run["read_count"] or 0) if run else 0,
                inserted=int(run["inserted_count"] or 0) if run else 0,
                duplicates=int(run["duplicate_count"] or 0) if run else 0,
                normalized=int(data["normalized"]),
                rejected=None,
            ),
            reconciliation=ReconciliationSummary(
                checked_hours=int(reconciliation["checked"] or 0),
                mismatched_hours=int(reconciliation["mismatched"] or 0),
                last_checked_at=reconciliation["last_checked"],
            ),
        )

    @router.get(
        "/queue",
        response_model=Page[QueueSummary],
        operation_id="workspace_group_queue",
        responses=ERROR_RESPONSES,
    )
    def queue(
        request: Request,
        site_id: str,
        from_: datetime | None = Query(None, alias="from"),
        to: datetime | None = None,
        min_score: float | None = Query(None, ge=0, le=100),
        max_score: float | None = Query(None, ge=0, le=100),
        status: list[str] | None = Query(None),
        owner_key: str | None = Query(None, max_length=256),
        unassigned: bool | None = None,
        rule_id: str | None = Query(None, max_length=64),
        entity_kind: str | None = None,
        entity: str | None = Query(None, max_length=512),
        sort: str = "priority_desc",
        limit: int = Query(50, ge=1, le=200),
        cursor: str | None = None,
        principal: VerifiedPrincipal = Depends(principal_dependency),
    ):
        _validate_query(
            request,
            {
                "site_id",
                "from",
                "to",
                "min_score",
                "max_score",
                "status",
                "owner_key",
                "unassigned",
                "rule_id",
                "entity_kind",
                "entity",
                "sort",
                "limit",
                "cursor",
            },
            repeatable={"status"},
        )
        if sort not in {"priority_desc", "last_ts_desc", "first_ts_asc"}:
            raise WorkspaceApiError(
                422, "BAD_FILTER", "sort is unsupported", details={"field": "sort"}
            )
        if min_score is not None and max_score is not None and min_score > max_score:
            raise WorkspaceApiError(422, "BAD_FILTER", "min_score exceeds max_score")
        if status is not None and any(
            item not in {"new", "in_progress", "resolved", "closed"} for item in status
        ):
            raise WorkspaceApiError(422, "BAD_FILTER", "status is unsupported")
        if owner_key is not None and unassigned:
            raise WorkspaceApiError(422, "BAD_FILTER", "owner_key and unassigned are exclusive")
        if (entity is None) != (entity_kind is None) or (
            entity_kind is not None
            and entity_kind not in {"host", "ip", "user", "process", "file", "hash", "cve", "rule"}
        ):
            raise WorkspaceApiError(
                422, "BAD_FILTER", "entity and entity_kind must be supplied together"
            )
        authorized = authorize(principal, site_id)
        supplied: dict[str, object] = {
            "min_score": min_score,
            "max_score": max_score,
            "status": sorted(status or []),
            "owner_key": owner_key,
            "unassigned": bool(unassigned),
            "rule_id": rule_id,
            "entity_kind": entity_kind,
            "entity": entity,
        }
        if cursor:
            token = _cursor_decode(runtime.cursor_secret, cursor, runtime.now().astimezone(UTC))
            filters = _cursor_filters(token)
            if any(
                token.get(key) != value
                for key, value in {
                    "route": "queue",
                    "site": site_id,
                    "owner": principal.owner_key,
                    "policy": authorized.policy_hash,
                    "sort": sort,
                }.items()
            ):
                raise WorkspaceApiError(400, "CURSOR_INVALID", "cursor does not match this request")
            if any(
                value is not None and filters.get(key) != value for key, value in supplied.items()
            ):
                raise WorkspaceApiError(400, "CURSOR_INVALID", "cursor does not match this request")
            start = _cursor_datetime(filters.get("from"))
            end = _cursor_datetime(filters.get("to"))
            explicit_start = _aware(from_, "from")
            explicit_end = _aware(to, "to")
            if explicit_start is not None or explicit_end is not None:
                requested_start = explicit_start or start
                requested_end = explicit_end or end
                _window(runtime.now(), requested_start, requested_end, None)
                if (
                    explicit_start is not None
                    and explicit_start != start
                    or explicit_end is not None
                    and explicit_end != end
                ):
                    raise WorkspaceApiError(
                        400, "CURSOR_INVALID", "cursor does not match this request"
                    )
            normalized_filters = {
                key: filters[key]
                for key in (
                    "from",
                    "to",
                    "min_score",
                    "max_score",
                    "status",
                    "owner_key",
                    "unassigned",
                    "rule_id",
                    "entity_kind",
                    "entity",
                )
                if key in filters
            }
            after_value, after_group = _cursor_pair(token)
            if not isinstance(after_group, str):
                raise WorkspaceApiError(400, "CURSOR_INVALID", "cursor does not match this request")
            after = (
                (float(after_value), after_group)
                if sort == "priority_desc" and isinstance(after_value, int | float)
                else (_cursor_datetime(after_value), after_group)
            )
        else:
            start, end, _ = _window(runtime.now(), from_, to, None)
            normalized_filters = {**supplied, "from": start.isoformat(), "to": end.isoformat()}
            after = None
        repo = repository(site_id, principal)
        try:
            rows = repo.queue_rows(
                filters=normalized_filters, sort=sort, limit=limit + 1, after=after
            )
        finally:
            repo.close()
        more = len(rows) > limit
        rows = rows[:limit]
        next_cursor = None
        if more:
            row = rows[-1]
            key = (
                float(row["total"] or 0)
                if sort == "priority_desc"
                else row["last_ts" if sort == "last_ts_desc" else "first_ts"].isoformat()
            )
            next_cursor = _cursor_encode(
                runtime.cursor_secret,
                {
                    "route": "queue",
                    "site": site_id,
                    "owner": principal.owner_key,
                    "policy": authorized.policy_hash,
                    "sort": sort,
                    "filters": normalized_filters,
                    "after": [key, str(row["group_id"])],
                    "exp": (runtime.now() + timedelta(minutes=15)).timestamp(),
                },
            )
        return Page[QueueSummary](
            items=[
                QueueSummary(
                    group=_group_summary(row),
                    work_state=_work_state(row),
                    queue_reasons=[
                        component.explanation
                        for component in _group_summary(row).components
                        if component.contribution > 0
                    ][:3],
                )
                for row in rows
            ],
            next_cursor=next_cursor,
            limit=limit,
        )

    @router.get(
        "/groups/{group_id}",
        response_model=GroupDetail,
        operation_id="workspace_group_detail",
        responses=ERROR_RESPONSES,
    )
    def group_detail(
        request: Request,
        group_id: str,
        site_id: str,
        member_limit: int = Query(50, ge=1, le=200),
        member_cursor: str | None = None,
        principal: VerifiedPrincipal = Depends(principal_dependency),
    ):
        _validate_query(request, {"site_id", "member_limit", "member_cursor"})
        authorized = authorize(principal, site_id)
        after = None
        if member_cursor:
            token = _cursor_decode(
                runtime.cursor_secret, member_cursor, runtime.now().astimezone(UTC)
            )
            bind = {
                "route": "group-members",
                "site": site_id,
                "group": group_id,
                "owner": principal.owner_key,
                "policy": authorized.policy_hash,
            }
            if any(token.get(key) != value for key, value in bind.items()):
                raise WorkspaceApiError(400, "CURSOR_INVALID", "cursor does not match this request")
            raw_time, raw_key = _cursor_pair(token)
            if not isinstance(raw_key, str):
                raise WorkspaceApiError(400, "CURSOR_INVALID", "cursor does not match this request")
            after = (_cursor_datetime(raw_time), raw_key)
        repo = repository(site_id, principal)
        try:
            row = repo.group_detail(group_id)
            if row is None:
                raise WorkspaceApiError(404, "RESOURCE_UNKNOWN", "Group is unknown")
            members = repo.group_members(group_id, member_limit + 1, after)
            extras = repo.group_extras(group_id)
        finally:
            repo.close()
        more = len(members) > member_limit
        members = members[:member_limit]
        member_next = None
        if more:
            last = members[-1]
            member_next = _cursor_encode(
                runtime.cursor_secret,
                {
                    "route": "group-members",
                    "site": site_id,
                    "group": group_id,
                    "owner": principal.owner_key,
                    "policy": authorized.policy_hash,
                    "after": [last["event_ts"].isoformat(), last["alert_key"]],
                    "exp": (runtime.now() + timedelta(minutes=15)).timestamp(),
                },
            )
        summary = _group_summary(row)
        return GroupDetail(
            **summary.model_dump(),
            site_id=site_id,
            members=Page[AlertSummary](
                items=[
                    _summary(item).model_copy(update={"group_id": group_id}) for item in members
                ],
                next_cursor=member_next,
                limit=member_limit,
            ),
            enrichments=[Enrichment.model_validate(item) for item in extras["enrichments"]],
            edges=[],
            chain_ids=[],
            history=[HistoryEntry.model_validate(item) for item in extras["history"]],
            work_state=_work_state(row),
        )

    @router.post("/groups/{group_id}/assign", response_model=WorkState, responses=ERROR_RESPONSES)
    def group_assign(
        request: Request,
        group_id: str,
        body: AssignRequest,
        principal: VerifiedPrincipal = Depends(principal_dependency),
        idempotency_key: str = Header(..., alias="Idempotency-Key"),
    ):
        verify_csrf(request, principal)
        repo = write_repository(body.site_id, principal)
        try:
            result = assign_group(
                repo.conn,
                site_id=body.site_id,
                group_id=group_id,
                owner_key=body.owner_key,
                actor_key=principal.owner_key,
                now=runtime.now().astimezone(UTC),
                principal_key=principal.owner_key,
                idempotency_key=idempotency_key,
            )
        except (ValueError, LookupError, FeedbackConflict) as error:
            _write_error(error)
        finally:
            repo.close()
        return _work_result(result)

    @router.post("/groups/{group_id}/status", response_model=WorkState, responses=ERROR_RESPONSES)
    def group_status(
        request: Request,
        group_id: str,
        body: StatusRequest,
        principal: VerifiedPrincipal = Depends(principal_dependency),
        idempotency_key: str = Header(..., alias="Idempotency-Key"),
    ):
        verify_csrf(request, principal)
        repo = write_repository(body.site_id, principal)
        try:
            result = change_group_status(
                repo.conn,
                site_id=body.site_id,
                group_id=group_id,
                status=body.status,
                expected_updated_at=body.expected_updated_at,
                actor_key=principal.owner_key,
                now=runtime.now().astimezone(UTC),
                principal_key=principal.owner_key,
                idempotency_key=idempotency_key,
            )
        except (ValueError, LookupError, FeedbackConflict) as error:
            _write_error(error)
        finally:
            repo.close()
        return _work_result(result)

    @router.post(
        "/groups/{group_id}/disposition", response_model=Disposition, responses=ERROR_RESPONSES
    )
    def group_disposition(
        request: Request,
        group_id: str,
        body: DispositionRequest,
        principal: VerifiedPrincipal = Depends(principal_dependency),
        idempotency_key: str = Header(..., alias="Idempotency-Key"),
    ):
        verify_csrf(request, principal)
        repo = write_repository(body.site_id, principal)
        try:
            result = record_group_disposition(
                repo.conn,
                site_id=body.site_id,
                group_id=group_id,
                label=body.label,
                actor_key=principal.owner_key,
                now=runtime.now().astimezone(UTC),
                principal_key=principal.owner_key,
                idempotency_key=idempotency_key,
                reason_code=body.reason_code,
                note=body.note,
                propagate_to_members=body.propagate_to_members,
            )
        except (ValueError, LookupError, FeedbackConflict) as error:
            _write_error(error)
        finally:
            repo.close()
        return Disposition.model_validate(
            {
                "disposition_id": result["disposition_id"],
                "label": result["label"],
                "reason_code": result["reason_code"],
                "note": result["note"],
                "actor_key": result["actor_key"],
                "at": datetime.fromisoformat(result["at"]),
                "propagate_to_members": result["propagate_to_members"],
            }
        )

    @router.post("/bulk", response_model=BulkActionResponse, responses=ERROR_RESPONSES)
    def bulk(
        request: Request,
        body: BulkActionRequest,
        principal: VerifiedPrincipal = Depends(principal_dependency),
        idempotency_key: str = Header(..., alias="Idempotency-Key"),
    ):
        if len(set(body.group_ids)) != len(body.group_ids):
            raise WorkspaceApiError(422, "VALIDATION_ERROR", "group_ids must be unique")
        verify_csrf(request, principal)
        repo = write_repository(body.site_id, principal)
        try:
            result = bulk_group_action(
                repo.conn,
                site_id=body.site_id,
                group_ids=body.group_ids,
                action=body.action.model_dump(exclude_none=True),
                actor_key=principal.owner_key,
                principal_key=principal.owner_key,
                idempotency_key=idempotency_key,
                now=runtime.now().astimezone(UTC),
            )
        except (ValueError, LookupError, FeedbackConflict) as error:
            _write_error(error)
        finally:
            repo.close()
        return BulkActionResponse.model_validate(
            {
                "updated": result["updated"],
                "items": [
                    {
                        "group_id": item["group_id"],
                        "result": {key: value for key, value in item.items() if key != "group_id"},
                    }
                    for item in result["items"]
                ],
            }
        )

    @router.get(
        "/assets",
        response_model=Page[AssetTag],
        operation_id="workspace_list_assets",
        responses=ERROR_RESPONSES,
    )
    def assets(
        request: Request,
        site_id: str,
        kind: str | None = None,
        q: str | None = Query(None, max_length=256),
        limit: int = Query(50, ge=1, le=200),
        cursor: str | None = None,
        principal: VerifiedPrincipal = Depends(principal_dependency),
    ):
        _validate_query(request, {"site_id", "kind", "q", "limit", "cursor"})
        if kind is not None and kind not in {
            "host",
            "ip",
            "user",
            "process",
            "file",
            "hash",
            "cve",
            "rule",
        }:
            raise WorkspaceApiError(422, "BAD_FILTER", "kind is unsupported")
        authorized = authorize(principal, site_id)
        after = None
        if cursor:
            token = _cursor_decode(runtime.cursor_secret, cursor, runtime.now().astimezone(UTC))
            bind = {
                "route": "assets",
                "site": site_id,
                "owner": principal.owner_key,
                "policy": authorized.policy_hash,
                "filters": {"kind": kind, "q": q},
            }
            if any(token.get(key) != value for key, value in bind.items()):
                raise WorkspaceApiError(400, "CURSOR_INVALID", "cursor does not match this request")
            raw = token.get("after")
            if not isinstance(raw, list):
                raise WorkspaceApiError(400, "CURSOR_INVALID", "cursor does not match this request")
            values = CURSOR_VALUES.validate_python(raw, strict=True)
            if (
                len(values) != 3
                or not isinstance(values[0], str)
                or not isinstance(values[1], str)
                or not isinstance(values[2], int)
                or isinstance(values[2], bool)
            ):
                raise WorkspaceApiError(400, "CURSOR_INVALID", "cursor does not match this request")
            after = (values[0], values[1], values[2])
        repo = repository(site_id, principal)
        try:
            rows = repo.list_asset_tags(kind=kind, query=q, limit=limit + 1, after=after)
        finally:
            repo.close()
        more = len(rows) > limit
        rows = rows[:limit]
        next_cursor = None
        if more:
            row = rows[-1]
            next_cursor = _cursor_encode(
                runtime.cursor_secret,
                {
                    "route": "assets",
                    "site": site_id,
                    "owner": principal.owner_key,
                    "policy": authorized.policy_hash,
                    "filters": {"kind": kind, "q": q},
                    "after": [row["kind"], row["value_norm"], row["entity_id"]],
                    "exp": (runtime.now() + timedelta(minutes=15)).timestamp(),
                },
            )
        return Page[AssetTag](
            items=[
                AssetTag(
                    site_id=site_id,
                    entity_kind=row["kind"],
                    entity_value=row["value_norm"],
                    **{
                        key: row[key]
                        for key in ("entity_id", "criticality", "tags", "set_by", "set_at")
                    },
                )
                for row in rows
            ],
            next_cursor=next_cursor,
            limit=limit,
        )

    @router.put("/assets", response_model=AssetTag, responses=ERROR_RESPONSES)
    def asset_upsert(
        request: Request,
        body: AssetTagUpsertRequest,
        principal: VerifiedPrincipal = Depends(principal_dependency),
        idempotency_key: str = Header(..., alias="Idempotency-Key"),
    ):
        verify_csrf(request, principal)
        repo = write_repository(body.site_id, principal)
        try:
            result = upsert_asset_tag(
                repo.conn,
                site_id=body.site_id,
                entity_id=body.entity_id,
                criticality=body.criticality,
                tags=body.tags,
                actor_key=principal.owner_key,
                principal_key=principal.owner_key,
                idempotency_key=idempotency_key,
                now=runtime.now().astimezone(UTC),
            )
            entity = repo.entity_identity(int(result["canonical_entity_id"]))
        except (ValueError, LookupError, FeedbackConflict) as error:
            _write_error(error)
        finally:
            repo.close()
        if entity is None:
            raise WorkspaceApiError(404, "RESOURCE_UNKNOWN", "Workspace resource is unknown")
        return AssetTag(
            site_id=body.site_id,
            entity_id=int(result["canonical_entity_id"]),
            entity_kind=entity["kind"],
            entity_value=entity["value_norm"],
            criticality=int(result["criticality"]),
            tags=result["tags"],
            set_by=str(result["set_by"]),
            set_at=datetime.fromisoformat(result["set_at"]),
        )

    @router.get(
        "/metrics/ops",
        response_model=OpsMetricsResponse,
        operation_id="workspace_ops_metrics",
        responses=ERROR_RESPONSES,
    )
    def metrics_ops(
        request: Request,
        site_id: str,
        from_: datetime | None = Query(None, alias="from"),
        to: datetime | None = None,
        bucket: str = "hour",
        principal: VerifiedPrincipal = Depends(principal_dependency),
    ):
        _validate_query(request, {"site_id", "from", "to", "bucket"})
        if bucket not in {"hour", "day"}:
            raise WorkspaceApiError(422, "BAD_FILTER", "bucket is unsupported")
        start, end, preset = _window(runtime.now(), from_, to, None)
        repo = repository(site_id, principal)
        try:
            result = ops_metrics(
                repo.conn, site_id=site_id, from_=start, to=end, now=runtime.now().astimezone(UTC)
            )
            volume_rows = repo.alert_volume(
                from_=start, to=end, bucket="hour" if bucket == "hour" else "day"
            )
        finally:
            repo.close()
        queue_data = result["queue"]
        ingest = result["ingestion"]

        def stats(
            prefix: str, p50: Any, p90: Any, pmax: Any, count: Any, p95: Any = None
        ) -> MetricStats:
            return MetricStats(
                p50=_metric_value(p50),
                p90=_metric_value(p90),
                p95=_metric_value(p95),
                max=_metric_value(pmax),
                sample_count=int(count or 0),
            )

        return OpsMetricsResponse(
            window=Window.model_validate({"from": start, "to": end, "preset": preset}),
            volume=[
                HourlyBucket(hour=row["hour"], level_band=row["band"], count=row["count"])
                for row in volume_rows
            ],
            ingest_lag_seconds=stats(
                "ingest",
                ingest["ingest_lag_p50_seconds"]["value"],
                None,
                None,
                ingest["ingest_lag_p50_seconds"]["denominator"],
                ingest["ingest_lag_p95_seconds"]["value"],
            ),
            queue_age_seconds=stats(
                "queue",
                queue_data["queue_age_p50_seconds"]["value"],
                queue_data["queue_age_p90_seconds"]["value"],
                queue_data["queue_age_max_seconds"]["value"],
                queue_data["queue_age_p50_seconds"]["denominator"],
            ),
            backlog=BacklogStats(
                current=int(queue_data["open_backlog"]["value"] or 0),
                previous=int(
                    (queue_data["open_backlog"]["value"] or 0)
                    - (queue_data["backlog_delta"]["value"] or 0)
                ),
                delta=int(queue_data["backlog_delta"]["value"] or 0),
                unassigned=int(queue_data["unassigned_actionable_groups"]["value"] or 0),
            ),
            time_to_ack_seconds=stats(
                "ack",
                queue_data["time_to_acknowledge_p50_seconds"]["value"],
                queue_data["time_to_acknowledge_p90_seconds"]["value"],
                None,
                queue_data["time_to_acknowledge_p50_seconds"]["denominator"],
            ),
            time_to_triage_seconds=stats(
                "triage",
                queue_data["time_to_triage_p50_seconds"]["value"],
                queue_data["time_to_triage_p90_seconds"]["value"],
                None,
                queue_data["time_to_triage_p50_seconds"]["denominator"],
            ),
            dead_jobs=int(result["jobs"]["dead_job_count"]["value"] or 0),
        )

    @router.get(
        "/metrics/quality",
        response_model=QualityMetricsResponse,
        operation_id="workspace_quality_metrics",
        responses=ERROR_RESPONSES,
    )
    def metrics_quality(
        request: Request,
        site_id: str,
        from_: datetime | None = Query(None, alias="from"),
        to: datetime | None = None,
        rule_id: str | None = Query(None, max_length=64),
        principal: VerifiedPrincipal = Depends(principal_dependency),
    ):
        _validate_query(request, {"site_id", "from", "to", "rule_id"})
        now = runtime.now().astimezone(UTC)
        if from_ is None and to is None:
            start, end = now - timedelta(days=30), now
            preset = "30d"
        else:
            start, end, preset = _window(now, from_, to, None, max_span=timedelta(days=90))
        if end - start > timedelta(days=90):
            raise WorkspaceApiError(422, "BAD_FILTER", "quality window cannot exceed 90 days")
        repo = repository(site_id, principal)
        try:
            result = quality_metrics(
                repo.conn, site_id=site_id, from_=start, to=end, now=now, rule_id=rule_id
            )
            topk = repo.precision_at_k(start, end, end, rule_id=rule_id)
        finally:
            repo.close()
        shares = result["disposition_shares"]
        rules = result["per_rule_precision"]
        coverage = result["label_coverage"]["value"]
        return QualityMetricsResponse(
            window=Window.model_validate({"from": start, "to": end, "preset": preset}),
            dispositions=[
                LabelCount(label=label, count=int(item["numerator"] or 0))
                for label, item in sorted(shares.items())
            ],
            label_coverage=_metric_value(coverage),
            labelled_group_count=int(result["labelled_group_count"]),
            group_count=int(result["group_count"]),
            rule_precision=[
                RulePrecision(
                    rule_id=str(row["rule_id"] or "unknown"),
                    labelled_count=int(row["labelled_groups"]),
                    true_positive_count=int(row["true_positive"]),
                    false_positive_count=int(row["false_positive"]),
                    benign_true_positive_count=int(row["benign_true_positive"]),
                    precision=_metric_value(row["precision"]),
                )
                for row in rules
            ],
            precision_at_k=[
                PrecisionAtK(
                    k=int(row["k"]),
                    precision=None
                    if int(row["labelled"] or 0) == 0
                    else int(row["relevant"] or 0) / int(row["labelled"]),
                    relevant_count=int(row["relevant"] or 0),
                    labelled_count=int(row["labelled"] or 0),
                )
                for row in topk
            ],
        )

    registered_handlers = (
        sites,
        overview,
        alerts,
        alert_detail,
        alert_context,
        ingestion_health,
        queue,
        group_detail,
        group_assign,
        group_status,
        group_disposition,
        bulk,
        assets,
        asset_upsert,
        metrics_ops,
        metrics_quality,
    )
    if len(router.routes) != len(registered_handlers):
        raise RuntimeError("workspace API route registration is incomplete")
    from ai_soc.workspace.api.m3 import m3_router

    router.include_router(m3_router(runtime, principal_dependency, verify_csrf))
    return router


async def workspace_api_error_handler(_: Request, error: WorkspaceApiError) -> JSONResponse:
    trace_id = uuid4().hex
    body = ErrorResponse(
        code=error.code,
        message=error.message,
        retryable=error.retryable,
        trace_id=trace_id,
        details=error.details,
    )
    return JSONResponse(
        status_code=error.status,
        content=body.model_dump(mode="json"),
        headers={"X-Trace-Id": trace_id, "Cache-Control": "no-store"},
    )


async def workspace_database_error_handler(request: Request, _: PsycopgError) -> JSONResponse:
    return await workspace_api_error_handler(
        request,
        WorkspaceApiError(
            503,
            "UNAVAILABLE",
            "Workspace data is temporarily unavailable",
            retryable=True,
        ),
    )
