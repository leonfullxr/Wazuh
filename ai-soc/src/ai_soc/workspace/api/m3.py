"""M3 deterministic chain and incident API routes."""

# FastAPI binds request metadata in route signatures.
# ruff: noqa: B008

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Annotated, Any, NoReturn, cast
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Path, Query, Request
from psycopg import Error as PsycopgError

from ai_soc.contracts.models import VerifiedPrincipal
from ai_soc.workspace.api.chain_queries import get_candidate, list_candidates
from ai_soc.workspace.api.common import (
    ERROR_RESPONSES,
    WorkspaceApiError,
    WorkspaceJSONResponse,
    authorize_site,
    aware,
    cursor_datetime,
    cursor_decode,
    cursor_encode,
    cursor_filters,
    cursor_pair,
    validate_query,
)
from ai_soc.workspace.api.incident_queries import incident_context, incident_events, list_incidents
from ai_soc.workspace.api.m3_repository import connect_read_repository, connect_write_repository
from ai_soc.workspace.api.models import (
    ChainCandidateDetail,
    ChainCandidateDTO,
    ChainDismissRequest,
    ChainDismissResponse,
    ChainPage,
    ChainPromoteRequest,
    IncidentActionResponse,
    IncidentAssignRequest,
    IncidentCommentDTO,
    IncidentCommentRequest,
    IncidentContextResponse,
    IncidentCreateRequest,
    IncidentDetailResponse,
    IncidentDispositionDTO,
    IncidentDispositionRequest,
    IncidentEventsResponse,
    IncidentMembersRequest,
    IncidentPage,
    IncidentSnapshotDTO,
    IncidentStatusRequest,
    NarrativeReadResponse,
)
from ai_soc.workspace.api.narrative_queries import get_incident_narrative
from ai_soc.workspace.api.repository import WorkspaceRepository
from ai_soc.workspace.api.runtime import WorkspaceRuntime
from ai_soc.workspace.correlate.repository import CorrelationConflict, dismiss_reviewed_candidate
from ai_soc.workspace.incidents import (
    IncidentConflict,
    add_incident_comment,
    assign_incident,
    change_incident_members,
    change_incident_status,
    create_incident,
    get_incident_detail,
    promote_chain,
    record_incident_disposition,
)


def _api_error(error: Exception) -> NoReturn:
    if isinstance(error, (IncidentConflict, CorrelationConflict)):
        raise WorkspaceApiError(409, "CONFLICT", str(error)) from None
    if isinstance(error, (LookupError,)):
        raise WorkspaceApiError(404, "RESOURCE_UNKNOWN", "Workspace resource is unknown") from None
    if isinstance(error, ValueError):
        raise WorkspaceApiError(422, "VALIDATION_ERROR", str(error)) from None
    if isinstance(error, PermissionError):
        raise WorkspaceApiError(
            403, "WORKSPACE_DENIED", "Full site visibility is required"
        ) from None
    raise error


def _snapshot(value: Any) -> IncidentSnapshotDTO:
    return IncidentSnapshotDTO(
        incident_id=str(value.incident_id),
        title=value.title,
        owner_key=value.owner_key,
        status=value.status,
        work_version=value.work_version,
        evidence_head=str(value.evidence_head),
        revision_seq=value.revision_seq,
        priority=value.priority,
    )


def _candidate(
    value: dict[str, Any], detail: bool = False
) -> ChainCandidateDTO | ChainCandidateDetail:
    stages = value.get("stages", [])
    if stages and isinstance(stages[0], tuple):
        stages = [
            dict(
                zip(
                    (
                        "ordinal",
                        "stage_id",
                        "outcome",
                        "group_id",
                        "group_revision",
                        "alert_key",
                        "event_ts",
                        "confidence",
                        "source_hash",
                        "projection_availability",
                    ),
                    stage,
                    strict=True,
                )
            )
            for stage in stages
        ]
    base: dict[str, Any] = dict(
        chain_id=str(value["chain_id"]),
        revision_digest=str(value["revision_digest"]),
        manifest_id=str(value["manifest_id"]),
        rule_id=str(value["rule_id"]),
        rule_version=str(value["rule_version"]),
        state=str(value["state"]),
        decision_version=int(value["decision_version"]),
        created_at=value["created_at"],
        updated_at=value["updated_at"],
        score=None if value["score"] is None else float(value["score"]),
        score_available=bool(value["score_available"]),
        result=value["result"],
        stages=stages,
        weak_heuristic=bool(value["weak"]),
    )
    if detail:

        def rows(items: object, columns: tuple[str, ...]) -> list[dict[str, Any]]:
            return [dict(zip(columns, item, strict=True)) for item in items]  # type: ignore[arg-type]

        base["edges"] = rows(
            value.get("edges", []),
            (
                "edge_id",
                "from_group",
                "from_revision",
                "from_alert_key",
                "to_group",
                "to_revision",
                "to_alert_key",
                "edge_type",
                "confidence",
                "reason",
                "time_delta_seconds",
                "shared_fields",
            ),
        )
        base["weak_edges"] = [edge for edge in base["edges"] if edge["edge_type"] == "same_host"]
        for edge in base["edges"]:
            edge["weak"] = edge["edge_type"] == "same_host"
        base["score_pins"] = rows(
            value.get("score_pins", []),
            ("group_id", "group_revision", "score_version", "score_digest", "score"),
        )
        return ChainCandidateDetail(**base)
    return ChainCandidateDTO(**base)


def m3_router(
    runtime: WorkspaceRuntime,
    principal_dependency: Callable[..., Any],
    verify_csrf: Callable[[Request, VerifiedPrincipal], None],
) -> APIRouter:
    router = APIRouter(default_response_class=WorkspaceJSONResponse)

    def read_repo(site_id: str, principal: VerifiedPrincipal) -> WorkspaceRepository:
        authorize_site(runtime, principal, site_id)
        try:
            repo = connect_read_repository(runtime.dsn_provider(), site_id)
            if repo.site() is None:
                repo.close()
                raise WorkspaceApiError(404, "SITE_UNKNOWN", "Site is unknown")
            return repo
        except (PsycopgError, PermissionError):
            raise WorkspaceApiError(
                503, "UNAVAILABLE", "Workspace data is temporarily unavailable", retryable=True
            ) from None

    def write_repo(site_id: str, principal: VerifiedPrincipal) -> WorkspaceRepository:
        authorize_site(runtime, principal, site_id)
        try:
            return connect_write_repository(runtime.dsn_provider(), site_id)
        except PermissionError:
            raise WorkspaceApiError(
                403, "WORKSPACE_DENIED", "Full site visibility is required"
            ) from None
        except PsycopgError:
            raise WorkspaceApiError(
                503, "UNAVAILABLE", "Workspace data is temporarily unavailable", retryable=True
            ) from None

    @router.get("/chains", response_model=ChainPage, responses=ERROR_RESPONSES)
    def chains(
        request: Request,
        site_id: Annotated[str, Query(min_length=1, max_length=64)],
        principal: VerifiedPrincipal = Depends(principal_dependency),
        state: str | None = None,
        rule_id: str | None = None,
        diagnostic: str | None = None,
        min_score: float | None = Query(default=None, ge=0, le=100),
        max_score: float | None = Query(default=None, ge=0, le=100),
        from_: datetime | None = Query(default=None, alias="from"),
        to: datetime | None = None,
        limit: int = Query(50, ge=1, le=100),
        cursor: str | None = None,
    ) -> ChainPage:
        validate_query(
            request,
            {
                "site_id",
                "state",
                "rule_id",
                "diagnostic",
                "min_score",
                "max_score",
                "from",
                "to",
                "limit",
                "cursor",
            },
        )
        if state is not None and state not in {"open", "dismissed", "promoted"}:
            raise WorkspaceApiError(422, "BAD_FILTER", "state is unsupported")
        if diagnostic is not None and diagnostic not in {
            "missing_stage",
            "fallback_join",
            "weak_heuristic",
            "score_unavailable",
            "promotion_eligible",
        }:
            raise WorkspaceApiError(422, "BAD_FILTER", "diagnostic is unsupported")
        if min_score is not None and max_score is not None and min_score > max_score:
            raise WorkspaceApiError(422, "BAD_FILTER", "min_score exceeds max_score")
        from_ = aware(from_, "from")
        to = aware(to, "to")
        if (
            from_ is not None
            and to is not None
            and (from_ >= to or to - from_ > timedelta(days=30))
        ):
            raise WorkspaceApiError(
                422, "BAD_FILTER", "candidate time range must be positive and at most 30 days"
            )
        filters: dict[str, object] = {
            "site": site_id,
            "state": state,
            "rule_id": rule_id,
            "diagnostic": diagnostic,
            "min_score": min_score,
            "max_score": max_score,
            "from": None if from_ is None else from_.isoformat(),
            "to": None if to is None else to.isoformat(),
            "sort": "created_desc",
            "limit": limit,
        }
        after: tuple[Any, str] | None = None
        if cursor:
            token = cursor_decode(runtime.cursor_secret, cursor, runtime.now())
            if (
                token.get("route") != "chains"
                or token.get("site") != site_id
                or token.get("principal") != principal.owner_key
                or cursor_filters(token) != filters
                or token.get("policy") != "workspace.chain-candidates.v1"
                or token.get("authorization_policy")
                != authorize_site(runtime, principal, site_id).policy_hash
            ):
                raise WorkspaceApiError(400, "CURSOR_INVALID", "cursor does not match this request")
            a, b = cursor_pair(token)
            after = (cursor_datetime(a), str(b))
        repo = read_repo(site_id, principal)
        try:
            rows = list_candidates(
                repo.conn,
                site_id=site_id,
                filters={
                    **{
                        k: v
                        for k, v in filters.items()
                        if v is not None and k not in {"site", "sort"}
                    },
                    "from": from_,
                    "to": to,
                },
                after=after,
                limit=limit + 1,
            )
            more = len(rows) > limit
            rows = rows[:limit]
            next_cursor = None
            if more and rows:
                last = rows[-1]
                next_cursor = cursor_encode(
                    runtime.cursor_secret,
                    {
                        "route": "chains",
                        "site": site_id,
                        "principal": principal.owner_key,
                        "policy": "workspace.chain-candidates.v1",
                        "authorization_policy": authorize_site(
                            runtime, principal, site_id
                        ).policy_hash,
                        "filters": filters,
                        "after": [last["created_at"].isoformat(), str(last["chain_id"])],
                        "exp": runtime.now().timestamp() + 900,
                    },
                )
            return ChainPage(
                items=[_candidate(row) for row in rows], next_cursor=next_cursor, limit=limit
            )
        finally:
            repo.close()

    @router.get(
        "/chains/{chain_id}", response_model=ChainCandidateDetail, responses=ERROR_RESPONSES
    )
    def chain_detail(
        request: Request,
        chain_id: Annotated[str, Path(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")],
        site_id: Annotated[str, Query(min_length=1, max_length=64)],
        principal: VerifiedPrincipal = Depends(principal_dependency),
    ) -> ChainCandidateDetail:
        validate_query(request, {"site_id"})
        repo = read_repo(site_id, principal)
        try:
            candidate = get_candidate(repo.conn, site_id=site_id, chain_id=chain_id)
            if candidate is None:
                raise WorkspaceApiError(404, "RESOURCE_UNKNOWN", "Candidate is unknown")
            return cast(ChainCandidateDetail, _candidate(candidate, detail=True))
        finally:
            repo.close()

    @router.post(
        "/chains/{chain_id}/promote",
        response_model=IncidentActionResponse,
        responses=ERROR_RESPONSES,
    )
    def promote(
        chain_id: Annotated[str, Path(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")],
        body: ChainPromoteRequest,
        request: Request,
        idempotency_key: str = Header(..., alias="Idempotency-Key"),
        principal: VerifiedPrincipal = Depends(principal_dependency),
    ) -> IncidentActionResponse:
        verify_csrf(request, principal)
        repo = write_repo(body.site_id, principal)
        try:
            snapshot = promote_chain(
                repo.conn,
                site_id=body.site_id,
                chain_id=chain_id,
                expected_chain_revision=body.expected_revision,
                expected_manifest_id=body.expected_manifest_id,
                expected_decision_version=body.expected_decision_version,
                actor_key=principal.owner_key,
                principal_key=principal.owner_key,
                idempotency_key=idempotency_key,
                now=runtime.now(),
                title_override=body.title_override,
            )
            result = IncidentActionResponse(incident=_snapshot(snapshot), chain_state="promoted")
            repo.close()
            return result
        except Exception as exc:
            repo.close()
            _api_error(exc)

    @router.post(
        "/chains/{chain_id}/dismiss", response_model=ChainDismissResponse, responses=ERROR_RESPONSES
    )
    def dismiss(
        chain_id: Annotated[str, Path(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")],
        body: ChainDismissRequest,
        request: Request,
        idempotency_key: str = Header(..., alias="Idempotency-Key"),
        principal: VerifiedPrincipal = Depends(principal_dependency),
    ) -> ChainDismissResponse:
        verify_csrf(request, principal)
        repo = write_repo(body.site_id, principal)
        try:
            decision = dismiss_reviewed_candidate(
                repo.conn,
                site_id=body.site_id,
                chain_id=chain_id,
                expected_revision=body.expected_revision,
                expected_manifest_id=body.expected_manifest_id,
                expected_decision_version=body.expected_decision_version,
                actor_key=principal.owner_key,
                principal_key=principal.owner_key,
                reason=body.reason,
                idempotency_key=idempotency_key,
                now=runtime.now(),
            )
            result = ChainDismissResponse(
                chain_id=decision.chain_id,
                state="dismissed",
                version=decision.version,
                updated_at=decision.updated_at,
            )
            repo.close()
            return result
        except Exception as exc:
            repo.close()
            _api_error(exc)

    @router.post(
        "/incidents",
        response_model=IncidentActionResponse,
        status_code=201,
        responses=ERROR_RESPONSES,
    )
    def incidents_create(
        body: IncidentCreateRequest,
        request: Request,
        idempotency_key: str = Header(..., alias="Idempotency-Key"),
        principal: VerifiedPrincipal = Depends(principal_dependency),
    ) -> IncidentActionResponse:
        verify_csrf(request, principal)
        repo = write_repo(body.site_id, principal)
        try:
            snapshot = create_incident(
                repo.conn,
                site_id=body.site_id,
                group_ids=tuple(body.group_ids),
                actor_key=principal.owner_key,
                principal_key=principal.owner_key,
                idempotency_key=idempotency_key,
                now=runtime.now(),
                title=body.title,
                owner_key=body.owner_key,
            )
            result = IncidentActionResponse(incident=_snapshot(snapshot), members=body.group_ids)
            repo.close()
            return result
        except Exception as exc:
            repo.close()
            _api_error(exc)

    @router.post(
        "/incidents/{incident_id}/members",
        response_model=IncidentActionResponse,
        responses=ERROR_RESPONSES,
    )
    def members(
        incident_id: UUID,
        body: IncidentMembersRequest,
        request: Request,
        idempotency_key: str = Header(..., alias="Idempotency-Key"),
        principal: VerifiedPrincipal = Depends(principal_dependency),
    ) -> IncidentActionResponse:
        verify_csrf(request, principal)
        if set(body.add_group_ids) & set(body.remove_group_ids):
            raise WorkspaceApiError(
                422, "VALIDATION_ERROR", "add and remove groups must be disjoint"
            )
        if len(set(body.add_group_ids)) != len(body.add_group_ids) or len(
            set(body.remove_group_ids)
        ) != len(body.remove_group_ids):
            raise WorkspaceApiError(422, "VALIDATION_ERROR", "membership group IDs must be unique")
        repo = write_repo(body.site_id, principal)
        try:
            snapshot = change_incident_members(
                repo.conn,
                site_id=body.site_id,
                incident_id=incident_id,
                add_group_ids=tuple(body.add_group_ids),
                remove_group_ids=tuple(body.remove_group_ids),
                expected_work_version=body.expected_work_version,
                actor_key=principal.owner_key,
                principal_key=principal.owner_key,
                idempotency_key=idempotency_key,
                now=runtime.now(),
            )
            result = IncidentActionResponse(
                incident=_snapshot(snapshot),
                added=body.add_group_ids,
                removed=body.remove_group_ids,
            )
            repo.close()
            return result
        except Exception as exc:
            repo.close()
            _api_error(exc)

    @router.post(
        "/incidents/{incident_id}/assign",
        response_model=IncidentActionResponse,
        responses=ERROR_RESPONSES,
    )
    def assign(
        incident_id: UUID,
        body: IncidentAssignRequest,
        request: Request,
        idempotency_key: str = Header(..., alias="Idempotency-Key"),
        principal: VerifiedPrincipal = Depends(principal_dependency),
    ) -> IncidentActionResponse:
        return _work_action(
            request,
            body.site_id,
            principal,
            lambda repo: assign_incident(
                repo.conn,
                site_id=body.site_id,
                incident_id=incident_id,
                owner_key=body.owner_key,
                expected_work_version=body.expected_work_version,
                actor_key=principal.owner_key,
                principal_key=principal.owner_key,
                idempotency_key=idempotency_key,
                now=runtime.now(),
            ),
            verify_csrf,
            write_repo,
        )

    @router.post(
        "/incidents/{incident_id}/status",
        response_model=IncidentActionResponse,
        responses=ERROR_RESPONSES,
    )
    def status(
        incident_id: UUID,
        body: IncidentStatusRequest,
        request: Request,
        idempotency_key: str = Header(..., alias="Idempotency-Key"),
        principal: VerifiedPrincipal = Depends(principal_dependency),
    ) -> IncidentActionResponse:
        return _work_action(
            request,
            body.site_id,
            principal,
            lambda repo: change_incident_status(
                repo.conn,
                site_id=body.site_id,
                incident_id=incident_id,
                status=body.status,
                expected_work_version=body.expected_work_version,
                actor_key=principal.owner_key,
                principal_key=principal.owner_key,
                idempotency_key=idempotency_key,
                now=runtime.now(),
            ),
            verify_csrf,
            write_repo,
        )

    @router.post(
        "/incidents/{incident_id}/comment",
        response_model=IncidentActionResponse,
        status_code=201,
        responses=ERROR_RESPONSES,
    )
    def comment(
        incident_id: UUID,
        body: IncidentCommentRequest,
        request: Request,
        idempotency_key: str = Header(..., alias="Idempotency-Key"),
        principal: VerifiedPrincipal = Depends(principal_dependency),
    ) -> IncidentActionResponse:
        verify_csrf(request, principal)
        repo = write_repo(body.site_id, principal)
        try:
            comment_id = add_incident_comment(
                repo.conn,
                site_id=body.site_id,
                incident_id=incident_id,
                body=body.body,
                expected_work_version=body.expected_work_version,
                actor_key=principal.owner_key,
                principal_key=principal.owner_key,
                idempotency_key=idempotency_key,
                now=runtime.now(),
            )
            stored = repo.conn.execute(
                "SELECT comment_id,incident_revision_id,work_version,actor_key,body,at "
                "FROM incident_comments WHERE site_id=%s AND incident_id=%s AND comment_id=%s",
                (body.site_id, incident_id, comment_id),
            ).fetchone()
            if stored is None:
                raise RuntimeError("stored comment action is missing")
            result = IncidentActionResponse(
                incident_id=incident_id,
                action_id=comment_id,
                action="comment",
                work_version=int(stored[2]),
                comment=IncidentCommentDTO(
                    comment_id=stored[0],
                    evidence_revision=stored[1],
                    work_version=stored[2],
                    actor_key=stored[3],
                    body=stored[4],
                    at=stored[5],
                ),
            )
            repo.close()
            return result
        except Exception as exc:
            repo.close()
            _api_error(exc)

    @router.post(
        "/incidents/{incident_id}/disposition",
        response_model=IncidentActionResponse,
        responses=ERROR_RESPONSES,
    )
    def disposition(
        incident_id: UUID,
        body: IncidentDispositionRequest,
        request: Request,
        idempotency_key: str = Header(..., alias="Idempotency-Key"),
        principal: VerifiedPrincipal = Depends(principal_dependency),
    ) -> IncidentActionResponse:
        verify_csrf(request, principal)
        repo = write_repo(body.site_id, principal)
        try:
            disposition_id = record_incident_disposition(
                repo.conn,
                site_id=body.site_id,
                incident_id=incident_id,
                label=body.label,
                expected_work_version=body.expected_work_version,
                expected_evidence_revision=body.expected_evidence_revision,
                actor_key=principal.owner_key,
                principal_key=principal.owner_key,
                idempotency_key=idempotency_key,
                now=runtime.now(),
                reason_code=body.reason_code,
                note=body.note,
                propagate_to_members=body.propagate_to_members,
            )
            stored = repo.conn.execute(
                "SELECT disposition_id,incident_revision_id,work_version,label,reason_code,note,"
                "actor_key,at FROM incident_dispositions WHERE site_id=%s AND incident_id=%s "
                "AND disposition_id=%s",
                (body.site_id, incident_id, disposition_id),
            ).fetchone()
            if stored is None:
                raise RuntimeError("stored disposition action is missing")
            result = IncidentActionResponse(
                incident_id=incident_id,
                action_id=disposition_id,
                action="disposition",
                work_version=int(stored[2]),
                evidence_revision=stored[1],
                disposition=IncidentDispositionDTO(
                    disposition_id=stored[0],
                    evidence_revision=stored[1],
                    work_version=stored[2],
                    label=stored[3],
                    reason_code=stored[4],
                    note=stored[5],
                    actor_key=stored[6],
                    at=stored[7],
                ),
            )
            repo.close()
            return result
        except Exception as exc:
            repo.close()
            _api_error(exc)

    @router.get(
        "/incidents/{incident_id}/narrative",
        response_model=NarrativeReadResponse,
        responses=ERROR_RESPONSES,
    )
    def incident_narrative(
        request: Request,
        incident_id: UUID,
        site_id: Annotated[str, Query(min_length=1, max_length=64)],
        principal: VerifiedPrincipal = Depends(principal_dependency),
        evidence_revision: UUID | None = None,
    ) -> NarrativeReadResponse:
        validate_query(request, {"site_id", "evidence_revision"})
        repo = read_repo(site_id, principal)
        try:
            result = get_incident_narrative(
                repo.conn,
                site_id=site_id,
                incident_id=incident_id,
                evidence_revision=evidence_revision,
                now=runtime.now(),
            )
            repo.close()
            return result
        except Exception as exc:
            repo.close()
            _api_error(exc)

    @router.get(
        "/incidents/{incident_id}", response_model=IncidentDetailResponse, responses=ERROR_RESPONSES
    )
    def incident_detail(
        request: Request,
        incident_id: UUID,
        site_id: Annotated[str, Query(min_length=1, max_length=64)],
        principal: VerifiedPrincipal = Depends(principal_dependency),
        limit: int = Query(50, ge=1, le=100),
        history_cursor: str | None = None,
        comments_cursor: str | None = None,
        dispositions_cursor: str | None = None,
        membership_cursor: str | None = None,
    ) -> IncidentDetailResponse:
        validate_query(
            request,
            {
                "site_id",
                "limit",
                "history_cursor",
                "comments_cursor",
                "dispositions_cursor",
                "membership_cursor",
            },
        )
        repo = read_repo(site_id, principal)
        try:
            current_head_row = repo.conn.execute(
                "SELECT evidence_head FROM incidents WHERE site_id=%s AND incident_id=%s",
                (site_id, incident_id),
            ).fetchone()
            if current_head_row is None:
                raise WorkspaceApiError(404, "RESOURCE_UNKNOWN", "Incident is unknown")
            evidence_head = UUID(str(current_head_row[0]))
            cursor_values: dict[str, tuple[datetime, UUID] | None] = {}
            for key, token in (
                ("history", history_cursor),
                ("comments", comments_cursor),
                ("dispositions", dispositions_cursor),
                ("membership", membership_cursor),
            ):
                cursor_values[key] = _detail_cursor(
                    runtime,
                    principal,
                    site_id,
                    incident_id,
                    token,
                    key,
                    evidence_head=evidence_head,
                    limit=limit,
                )
            detail = get_incident_detail(
                repo.conn,
                site_id=site_id,
                incident_id=incident_id,
                limit=limit,
                membership_before=cursor_values["membership"],
                history_before=cursor_values["history"],
                comments_before=cursor_values["comments"],
                dispositions_before=cursor_values["dispositions"],
            )
            result = {
                "incident": _snapshot(detail.incident),
                "members": [
                    item.__dict__
                    if hasattr(item, "__dict__")
                    else {
                        "group_id": item.group_id,
                        "group_revision": item.group_revision,
                        "title": item.title,
                        "first_ts": item.first_ts,
                        "last_ts": item.last_ts,
                        "alert_count": item.alert_count,
                        "score_version": item.score_version,
                        "score_digest": item.score_digest,
                        "score": item.score,
                    }
                    for item in detail.evidence_members
                ],
                "membership_intervals": [
                    {
                        "membership_id": str(i.membership_id),
                        "group_id": i.group_id,
                        "added_by": i.added_by,
                        "added_at": i.added_at,
                        "removed_by": i.removed_by,
                        "removed_at": i.removed_at,
                    }
                    for i in detail.memberships
                ],
                "history": [
                    {
                        "history_id": str(i.history_id),
                        "work_version": i.work_version,
                        "actor_key": i.actor_key,
                        "action": i.action,
                        "before": i.before_value,
                        "after": i.after_value,
                        "at": i.at,
                    }
                    for i in detail.history
                ],
                "comments": [
                    {
                        "comment_id": str(i.comment_id),
                        "evidence_revision": str(i.revision_id),
                        "work_version": i.work_version,
                        "actor_key": i.actor_key,
                        "body": i.body,
                        "at": i.at,
                    }
                    for i in detail.comments
                ],
                "dispositions": [
                    {
                        "disposition_id": str(i.disposition_id),
                        "evidence_revision": str(i.revision_id),
                        "work_version": i.work_version,
                        "label": i.label,
                        "reason_code": i.reason_code,
                        "note": i.note,
                        "actor_key": i.actor_key,
                        "at": i.at,
                    }
                    for i in detail.dispositions
                ],
                "next_cursors": {
                    "membership": _detail_next(
                        runtime,
                        principal,
                        site_id,
                        incident_id,
                        "membership",
                        detail.next_membership_cursor,
                        evidence_head=evidence_head,
                        limit=limit,
                    ),
                    "history": _detail_next(
                        runtime,
                        principal,
                        site_id,
                        incident_id,
                        "history",
                        detail.next_history_cursor,
                        evidence_head=evidence_head,
                        limit=limit,
                    ),
                    "comments": _detail_next(
                        runtime,
                        principal,
                        site_id,
                        incident_id,
                        "comments",
                        detail.next_comment_cursor,
                        evidence_head=evidence_head,
                        limit=limit,
                    ),
                    "dispositions": _detail_next(
                        runtime,
                        principal,
                        site_id,
                        incident_id,
                        "dispositions",
                        detail.next_disposition_cursor,
                        evidence_head=evidence_head,
                        limit=limit,
                    ),
                },
            }
            return IncidentDetailResponse.model_validate(result, strict=False)
        except Exception as exc:
            _api_error(exc)
        finally:
            repo.close()

    @router.get("/incidents", response_model=IncidentPage, responses=ERROR_RESPONSES)
    def incident_list(
        request: Request,
        site_id: Annotated[str, Query(min_length=1, max_length=64)],
        principal: VerifiedPrincipal = Depends(principal_dependency),
        status_filter: str | None = Query(default=None, alias="status"),
        owner_key: str | None = None,
        unassigned: bool = False,
        min_priority: float | None = Query(default=None, ge=0, le=100),
        max_priority: float | None = Query(default=None, ge=0, le=100),
        from_: datetime | None = Query(default=None, alias="from"),
        to: datetime | None = None,
        limit: int = Query(50, ge=1, le=100),
        cursor: str | None = None,
    ) -> IncidentPage:
        validate_query(
            request,
            {
                "site_id",
                "status",
                "owner_key",
                "unassigned",
                "min_priority",
                "max_priority",
                "from",
                "to",
                "limit",
                "cursor",
            },
        )
        if status_filter is not None and status_filter not in {
            "new",
            "in_progress",
            "resolved",
            "closed",
        }:
            raise WorkspaceApiError(422, "BAD_FILTER", "incident status is unsupported")
        if owner_key is not None and unassigned:
            raise WorkspaceApiError(422, "BAD_FILTER", "owner_key and unassigned are exclusive")
        if min_priority is not None and max_priority is not None and min_priority > max_priority:
            raise WorkspaceApiError(422, "BAD_FILTER", "min_priority exceeds max_priority")
        from_ = aware(from_, "from")
        to = aware(to, "to")
        if (
            from_ is not None
            and to is not None
            and (from_ >= to or to - from_ > timedelta(days=30))
        ):
            raise WorkspaceApiError(
                422, "BAD_FILTER", "time range must be positive and at most 30 days"
            )
        filters: dict[str, object] = {
            "status": status_filter,
            "owner_key": owner_key,
            "unassigned": unassigned,
            "min_priority": min_priority,
            "max_priority": max_priority,
            "from": None if from_ is None else from_.isoformat(),
            "to": None if to is None else to.isoformat(),
            "sort": "created_desc",
            "limit": limit,
        }
        after: tuple[datetime, str] | None = None
        if cursor:
            payload = cursor_decode(runtime.cursor_secret, cursor, runtime.now())
            if (
                payload.get("route") != "incidents"
                or payload.get("site") != site_id
                or payload.get("principal") != principal.owner_key
                or payload.get("policy") != "workspace.incidents.v1"
                or payload.get("authorization_policy")
                != authorize_site(runtime, principal, site_id).policy_hash
                or cursor_filters(payload) != filters
            ):
                raise WorkspaceApiError(400, "CURSOR_INVALID", "cursor does not match this request")
            raw_time, raw_id = cursor_pair(payload)
            after = (cursor_datetime(raw_time), str(raw_id))
        repo = read_repo(site_id, principal)
        try:
            rows = list_incidents(
                repo.conn,
                site_id=site_id,
                filters={
                    key: val
                    for key, val in {
                        "status": status_filter,
                        "owner_key": owner_key,
                        "unassigned": unassigned,
                        "min_priority": min_priority,
                        "max_priority": max_priority,
                        "from": from_,
                        "to": to,
                    }.items()
                    if val is not None
                },
                after=after,
                limit=limit + 1,
            )
            more = len(rows) > limit
            page = rows[:limit]
            next_cursor = None
            if more and page:
                last = page[-1]
                next_cursor = cursor_encode(
                    runtime.cursor_secret,
                    {
                        "route": "incidents",
                        "site": site_id,
                        "principal": principal.owner_key,
                        "policy": "workspace.incidents.v1",
                        "authorization_policy": authorize_site(
                            runtime, principal, site_id
                        ).policy_hash,
                        "filters": filters,
                        "after": [last["created_at"].isoformat(), str(last["incident_id"])],
                        "exp": runtime.now().timestamp() + 900,
                    },
                )
            return IncidentPage.model_validate(
                {
                    "items": [
                        {
                            "incident_id": str(row["incident_id"]),
                            "title": row["title"],
                            "owner_key": row["owner_key"],
                            "status": row["status"],
                            "work_version": int(row["work_version"]),
                            "evidence_head": str(row["evidence_head"]),
                            "revision_seq": int(row["revision_seq"]),
                            "priority": None if row["priority"] is None else float(row["priority"]),
                            "created_at": row["created_at"],
                            "created_by": row["created_by"],
                        }
                        for row in page
                    ],
                    "next_cursor": next_cursor,
                    "limit": limit,
                },
                strict=False,
            )
        finally:
            repo.close()

    @router.get(
        "/incidents/{incident_id}/events",
        response_model=IncidentEventsResponse,
        responses=ERROR_RESPONSES,
    )
    def events(
        request: Request,
        incident_id: UUID,
        site_id: Annotated[str, Query(min_length=1, max_length=64)],
        evidence_revision: UUID,
        principal: VerifiedPrincipal = Depends(principal_dependency),
        from_: datetime | None = Query(default=None, alias="from"),
        to: datetime | None = None,
        limit: int = Query(100, ge=1, le=500),
        cursor: str | None = None,
    ) -> IncidentEventsResponse:
        validate_query(request, {"site_id", "evidence_revision", "from", "to", "limit", "cursor"})
        from_ = aware(from_, "from")
        to = aware(to, "to")
        if (
            from_ is not None
            and to is not None
            and (from_ >= to or to - from_ > timedelta(hours=48))
        ):
            raise WorkspaceApiError(
                422, "BAD_FILTER", "event window must be positive and at most 48 hours"
            )
        event_filters = {
            "from": None if from_ is None else from_.isoformat(),
            "to": None if to is None else to.isoformat(),
            "limit": limit,
            "sort": "event_asc",
        }
        after = None
        if cursor:
            payload = cursor_decode(runtime.cursor_secret, cursor, runtime.now())
            if any(
                payload.get(k) != v
                for k, v in {
                    "route": "incident-events",
                    "site": site_id,
                    "incident": str(incident_id),
                    "evidence_revision": str(evidence_revision),
                    "principal": principal.owner_key,
                    "policy": "workspace.incident-events.v1",
                    "authorization_policy": authorize_site(runtime, principal, site_id).policy_hash,
                    "filters": event_filters,
                }.items()
            ):
                raise WorkspaceApiError(400, "CURSOR_INVALID", "cursor does not match this request")
            a, b = cursor_pair(payload)
            after = (cursor_datetime(a), str(b))
        repo = read_repo(site_id, principal)
        try:
            rows = incident_events(
                repo.conn,
                site_id=site_id,
                incident_id=incident_id,
                evidence_revision=evidence_revision,
                start=from_,
                end=to,
                after=after,
                limit=limit + 1,
            )
            if (
                not rows
                and repo.conn.execute(
                    "SELECT 1 FROM incident_evidence_revisions "
                    "WHERE site_id=%s AND incident_id=%s AND incident_revision_id=%s",
                    (site_id, incident_id, evidence_revision),
                ).fetchone()
                is None
            ):
                raise WorkspaceApiError(
                    404, "RESOURCE_UNKNOWN", "Incident evidence revision is unknown"
                )
            more = len(rows) > limit
            rows = rows[:limit]
            next_cursor = None
            if more:
                last = rows[-1]
                next_cursor = cursor_encode(
                    runtime.cursor_secret,
                    {
                        "route": "incident-events",
                        "site": site_id,
                        "incident": str(incident_id),
                        "evidence_revision": str(evidence_revision),
                        "principal": principal.owner_key,
                        "policy": "workspace.incident-events.v1",
                        "authorization_policy": authorize_site(
                            runtime, principal, site_id
                        ).policy_hash,
                        "filters": event_filters,
                        "after": [last["event_ts"].isoformat(), last["event_id"]],
                        "exp": runtime.now().timestamp() + 900,
                    },
                )
            return IncidentEventsResponse.model_validate(
                {
                    "evidence_revision": str(evidence_revision),
                    "events": rows,
                    "next_cursor": next_cursor,
                    "limit": limit,
                },
                strict=False,
            )
        finally:
            repo.close()

    @router.get(
        "/incidents/{incident_id}/context",
        response_model=IncidentContextResponse,
        responses=ERROR_RESPONSES,
    )
    def context(
        request: Request,
        incident_id: UUID,
        site_id: Annotated[str, Query(min_length=1, max_length=64)],
        evidence_revision: UUID,
        principal: VerifiedPrincipal = Depends(principal_dependency),
        from_: datetime | None = Query(default=None, alias="from"),
        to: datetime | None = None,
        sample_limit: int = Query(100, ge=1, le=200),
    ) -> IncidentContextResponse:
        validate_query(request, {"site_id", "evidence_revision", "from", "to", "sample_limit"})
        from_ = aware(from_, "from")
        to = aware(to, "to")
        if (
            from_ is not None
            and to is not None
            and (from_ >= to or to - from_ > timedelta(hours=48))
        ):
            raise WorkspaceApiError(
                422, "BAD_FILTER", "context window must be positive and at most 48 hours"
            )
        repo = read_repo(site_id, principal)
        try:
            result = incident_context(
                repo.conn,
                site_id=site_id,
                incident_id=incident_id,
                evidence_revision=evidence_revision,
                start=from_,
                end=to,
                limit=sample_limit,
            )
            if result is None:
                raise WorkspaceApiError(
                    404, "RESOURCE_UNKNOWN", "Incident evidence revision is unknown"
                )
            return IncidentContextResponse.model_validate(result, strict=False)
        except ValueError as exc:
            raise WorkspaceApiError(422, "BAD_FILTER", str(exc)) from None
        finally:
            repo.close()

    registered_handlers = (
        chains,
        chain_detail,
        promote,
        dismiss,
        incidents_create,
        members,
        assign,
        status,
        comment,
        disposition,
        incident_detail,
        incident_narrative,
        incident_list,
        events,
        context,
    )
    if len(router.routes) != len(registered_handlers):
        raise RuntimeError("M3 workspace route registration is incomplete")

    return router


def _work_action(
    request: Request,
    site_id: str,
    principal: VerifiedPrincipal,
    operation: Callable[[WorkspaceRepository], Any],
    verify_csrf: Callable[..., None],
    write_repo: Callable[..., WorkspaceRepository],
) -> IncidentActionResponse:
    verify_csrf(request, principal)
    repo = write_repo(site_id, principal)
    try:
        snapshot = operation(repo)
        result = IncidentActionResponse(incident=_snapshot(snapshot))
        repo.close()
        return result
    except Exception as exc:
        repo.close()
        _api_error(exc)


def _detail_cursor(
    runtime: WorkspaceRuntime,
    principal: VerifiedPrincipal,
    site_id: str,
    incident_id: UUID,
    token: str | None,
    kind: str,
    *,
    evidence_head: UUID,
    limit: int,
) -> tuple[datetime, UUID] | None:
    if not token:
        return None
    payload = cursor_decode(runtime.cursor_secret, token, runtime.now())
    expected = {
        "route": "incident-detail",
        "site": site_id,
        "incident": str(incident_id),
        "principal": principal.owner_key,
        "kind": kind,
        "policy": "workspace.incident-detail.v1",
        "authorization_policy": authorize_site(runtime, principal, site_id).policy_hash,
        "evidence_revision": str(evidence_head),
        "limit": limit,
        "sort": (
            "added_at_desc_membership_id_desc" if kind == "membership" else "at_desc_record_id_desc"
        ),
    }
    if any(payload.get(key) != value for key, value in expected.items()):
        raise WorkspaceApiError(400, "CURSOR_INVALID", "cursor does not match this request")
    raw_time, raw_id = cursor_pair(payload)
    try:
        return cursor_datetime(raw_time), UUID(str(raw_id))
    except ValueError:
        raise WorkspaceApiError(
            400, "CURSOR_INVALID", "cursor does not match this request"
        ) from None


def _detail_next(
    runtime: WorkspaceRuntime,
    principal: VerifiedPrincipal,
    site_id: str,
    incident_id: UUID,
    kind: str,
    value: tuple[datetime, UUID] | None,
    *,
    evidence_head: UUID,
    limit: int,
) -> str | None:
    if value is None:
        return None
    return cursor_encode(
        runtime.cursor_secret,
        {
            "route": "incident-detail",
            "site": site_id,
            "incident": str(incident_id),
            "principal": principal.owner_key,
            "kind": kind,
            "policy": "workspace.incident-detail.v1",
            "authorization_policy": authorize_site(runtime, principal, site_id).policy_hash,
            "evidence_revision": str(evidence_head),
            "limit": limit,
            "sort": (
                "added_at_desc_membership_id_desc"
                if kind == "membership"
                else "at_desc_record_id_desc"
            ),
            "after": [value[0].isoformat(), str(value[1])],
            "exp": runtime.now().timestamp() + 900,
        },
    )
