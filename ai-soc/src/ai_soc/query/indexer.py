"""Read-only indexer execution with analyst JWTs, byte bounds and no retry/cache."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol, cast
from urllib.parse import quote
from uuid import UUID, uuid4

import httpx

from ai_soc.contracts.canonical import canonical_bytes, sha256_hex
from ai_soc.contracts.models import (
    AuthorizedSite,
    Bucket,
    CallKind,
    Column,
    Count,
    CursorPayload,
    DomainError,
    ErrorCode,
    EvidenceCheck,
    EvidenceItem,
    EvidenceRow,
    ExecutionContext,
    FetchResult,
    FetchScope,
    FetchSpec,
    FetchState,
    Filter,
    IndexerCredential,
    IndexFamily,
    ReadOperationGrant,
    SnapshotKind,
    SnapshotRef,
    StageCapacityRejection,
    StageName,
    StageOutcome,
    TemplateId,
    VerifiedPrincipal,
    Visibility,
)
from ai_soc.contracts.ports import IndexerTokenBroker, ReadAdmissionStore, Telemetry
from ai_soc.query.compiler import (
    CompiledQuery,
    MappingProfile,
    QueryCompileError,
    compile_fetch,
)
from ai_soc.query.cursors import CursorCipher, CursorError
from ai_soc.query.evidence import (
    bucket_item,
    build_empty_proof,
    count_item,
    materialize_rows,
    snapshot_ref,
)
from ai_soc.telemetry.instrumentation import question_stage
from ai_soc.telemetry.metrics import MetricExporter
from ai_soc.telemetry.operational import emit_token_broker_failure


class Transport(Protocol):
    async def stream(self, method: str, url: str, **kwargs: object): ...


class WazuhIndexer:
    """Execute only service-compiled requests using per-operation analyst credentials."""

    def __init__(
        self,
        broker: IndexerTokenBroker,
        read_admission: ReadAdmissionStore,
        transport_for: Callable[[AuthorizedSite], httpx.AsyncClient],
        *,
        profiles: dict[str, MappingProfile],
        clock: Callable[[], datetime],
        content_sha: str,
        cursor_cipher: CursorCipher | None = None,
        response_bytes: int = 2_097_152,
        fetch_bytes: int = 262_144,
        pit_keep_alive: str = "5m",
        telemetry: Telemetry | None = None,
        metrics: MetricExporter | None = None,
    ) -> None:
        if response_bytes < 1 or response_bytes > 2_097_152:
            raise ValueError("backend response byte bound must be in 1..2097152")
        if fetch_bytes < 1 or fetch_bytes > 262_144:
            raise ValueError("fetch evidence byte bound must be in 1..262144")
        if pit_keep_alive != "5m":
            raise ValueError("PIT lifetime is fixed to the reviewed five-minute bound")
        self._broker = broker
        self._read_admission = read_admission
        self._transport_for = transport_for
        self._profiles = dict(profiles)
        self._clock = clock
        self._content_sha = content_sha
        self._cursor_cipher = cursor_cipher
        self._response_bytes = response_bytes
        self._fetch_bytes = fetch_bytes
        self._pit_keep_alive = pit_keep_alive
        self._telemetry = telemetry
        self._metrics = metrics
        self._background_cleanup: set[asyncio.Task[None]] = set()

    async def execute(
        self,
        fetch: FetchSpec,
        *,
        topic_id: str,
        question_id: UUID,
        principal: VerifiedPrincipal,
        site: AuthorizedSite,
        execution: ExecutionContext,
    ) -> FetchResult:
        context_error = self._context_error(principal, site, execution)
        if context_error is not None:
            return self._unavailable(
                fetch,
                topic_id,
                site,
                context_error,
                "The authorized indexer operation could not start.",
            )
        try:
            profile = self._profile(site)
            compiled = compile_fetch(fetch, site, profile)
        except QueryCompileError as exc:
            return self._unavailable(
                fetch, topic_id, site, exc.code, "The approved query is unavailable."
            )
        try:
            credential = await self._credential(principal, site, execution)
        except _IndexerFailure as exc:
            return self._unavailable(
                fetch, topic_id, site, exc.code, "The analyst credential is unavailable."
            )
        client = self._transport_for(site)
        pit_id: str | None = None
        keep_pit_open = False
        try:
            if site.config.pit_supported:
                try:
                    pit_id = await self._open_pit(
                        client, compiled, site, credential, question_id, execution
                    )
                except _IndexerFailure as exc:
                    if exc.status not in (400, 404, 405):
                        return self._failure(fetch, topic_id, site, exc)
                    pit_id = None
                except Exception:
                    return self._unavailable(
                        fetch,
                        topic_id,
                        site,
                        ErrorCode.CAPACITY_LIMIT,
                        "The bounded indexer operation is unavailable.",
                    )
            body = dict(compiled.body)
            if pit_id is not None:
                body["pit"] = {"id": pit_id, "keep_alive": self._pit_keep_alive}
                body.pop("track_total_hits", None)
                body["track_total_hits"] = True
                path = "/_search"
            else:
                path = compiled.path
            query_value = compiled.body.get("query")
            if not isinstance(query_value, dict):
                return self._unavailable(
                    fetch,
                    topic_id,
                    site,
                    ErrorCode.QUERY_INVALID,
                    "The approved query is unavailable.",
                )
            index_part = compiled.path.split("/", 2)[1]
            try:
                validation = await self._admitted_request_json(
                    client,
                    "POST",
                    f"/{index_part}/_validate/query",
                    {"query": query_value},
                    credential,
                    call="validate",
                    question_id=question_id,
                    site=site,
                    execution=execution,
                )
            except _IndexerFailure as exc:
                if exc.status not in (404, 405):
                    return self._failure(fetch, topic_id, site, exc)
            except (ValueError, json.JSONDecodeError):
                return self._unavailable(
                    fetch,
                    topic_id,
                    site,
                    ErrorCode.INDEXER_UNAVAILABLE,
                    "Indexer validation response was invalid.",
                )
            except Exception:
                return self._unavailable(
                    fetch,
                    topic_id,
                    site,
                    ErrorCode.CAPACITY_LIMIT,
                    "The bounded indexer operation is unavailable.",
                )
            else:
                if validation.get("valid") is not True:
                    return self._unavailable(
                        fetch,
                        topic_id,
                        site,
                        ErrorCode.MAPPING_UNSUPPORTED,
                        "The approved query could not be validated.",
                    )
            try:
                response = await self._admitted_request_json(
                    client,
                    "POST",
                    path,
                    body,
                    credential,
                    call="search",
                    question_id=question_id,
                    site=site,
                    execution=execution,
                )
            except _IndexerFailure as exc:
                return self._failure(fetch, topic_id, site, exc)
            except (ValueError, json.JSONDecodeError):
                return self._unavailable(
                    fetch,
                    topic_id,
                    site,
                    ErrorCode.INDEXER_UNAVAILABLE,
                    "Indexer response was invalid.",
                )
            except Exception:
                return self._unavailable(
                    fetch,
                    topic_id,
                    site,
                    ErrorCode.CAPACITY_LIMIT,
                    "The bounded indexer operation is unavailable.",
                )
            empty_diagnostics: tuple[
                bool | None, Count | None, list[tuple[Filter, Count | None]], Count | None
            ] = (None, None, [], None)
            if pit_id and _response_exact_zero(response, compiled):
                try:
                    empty_diagnostics = await self._empty_diagnostics(
                        client, compiled, fetch, pit_id, credential, question_id, site, execution
                    )
                except _IndexerFailure as exc:
                    return self._failure(fetch, topic_id, site, exc)
            result = self._result(
                response,
                compiled,
                fetch,
                topic_id,
                question_id,
                site,
                pit_id=pit_id,
                profile=profile,
                principal=principal,
                empty_diagnostics=empty_diagnostics,
            )
            if pit_id is not None and result.next_cursor is not None:
                keep_pit_open = True
            return result
        finally:
            if pit_id is not None and not keep_pit_open:
                await self._close_pit(client, pit_id, credential, question_id, site, execution)

    async def page(
        self,
        cursor: str,
        *,
        principal: VerifiedPrincipal,
        site: AuthorizedSite,
        execution: ExecutionContext,
    ) -> FetchResult:
        payload = self.open_cursor(cursor, principal=principal, site=site)
        context_error = self._context_error(principal, site, execution)
        if context_error is not None:
            raise CursorError(context_error)
        profile = self._profile(site)
        if profile.tie_break_field != "_id" or not _valid_cursor_values(payload.sort_values):
            raise CursorError()
        fetch = FetchSpec(
            fetch_id=payload.fetch_id,
            template_id=TemplateId(payload.template_id),
            window=payload.window,
            filters=payload.filters,
            page_size=payload.page_size,
            limit=payload.remaining_top_n,
            order=payload.order,
        )
        compiled = compile_fetch(fetch, site, profile)
        try:
            credential = await self._credential(principal, site, execution)
        except _IndexerFailure as exc:
            raise CursorError(exc.code) from exc
        body = dict(compiled.body)
        body["pit"] = {"id": payload.pit_id, "keep_alive": self._pit_keep_alive}
        body["search_after"] = payload.sort_values
        client = self._transport_for(site)
        try:
            response = await self._admitted_request_json(
                client,
                "POST",
                "/_search",
                body,
                credential,
                call="search",
                question_id=payload.question_id,
                site=site,
                execution=execution,
            )
        except _IndexerFailure as exc:
            if exc.status in (400, 404, 410):
                raise CursorError() from exc
            if exc.status == 403:
                raise CursorError(ErrorCode.SITE_DENIED) from exc
            if exc.code in (ErrorCode.CAPACITY_LIMIT, ErrorCode.DEPENDENCY_UNAVAILABLE):
                raise CursorError(exc.code) from exc
            raise CursorError(ErrorCode.INDEXER_UNAVAILABLE) from exc
        except Exception as exc:
            raise CursorError(ErrorCode.CAPACITY_LIMIT) from exc
        result = self._result(
            response,
            compiled,
            fetch,
            payload.topic_id,
            payload.question_id,
            site,
            pit_id=payload.pit_id,
            profile=profile,
            principal=principal,
            prior_cursor=payload,
        )
        return result

    def open_cursor(
        self,
        cursor: str,
        *,
        principal: VerifiedPrincipal,
        site: AuthorizedSite,
    ) -> CursorPayload:
        """Authenticate continuation binding before the application starts a fetch."""
        if self._cursor_cipher is None:
            raise CursorError()
        payload = self._cursor_cipher.open(
            cursor,
            owner_key=principal.owner_key,
            environment_id=site.config.environment_id,
            policy_hash=site.policy_hash,
            content_sha=self._content_sha,
        )
        if principal.expires_at <= self._clock():
            raise CursorError(ErrorCode.AUTH_EXPIRED)
        return payload

    def _profile(self, site: AuthorizedSite) -> MappingProfile:
        profile = self._profiles.get(site.config.mapping_profile)
        if profile is None or profile.profile_id != site.config.mapping_profile:
            raise QueryCompileError(ErrorCode.MAPPING_UNSUPPORTED)
        return profile

    def _context_error(
        self, principal: VerifiedPrincipal, site: AuthorizedSite, execution: ExecutionContext
    ) -> ErrorCode | None:
        now = self._clock()
        if (
            execution.owner_key != principal.owner_key
            or execution.environment_id != site.config.environment_id
        ):
            return ErrorCode.FORBIDDEN
        if principal.expires_at <= now:
            return ErrorCode.AUTH_EXPIRED
        if execution.deadline_at <= now:
            return ErrorCode.DEADLINE_EXCEEDED
        try:
            if execution.cancel.is_cancelled():
                return ErrorCode.DEADLINE_EXCEEDED
            execution.cancel.raise_if_cancelled()
        except Exception:
            return ErrorCode.DEADLINE_EXCEEDED
        return None

    async def _credential(
        self, principal: VerifiedPrincipal, site: AuthorizedSite, execution: ExecutionContext
    ) -> IndexerCredential:
        try:
            if self._telemetry is None:
                credential = await self._broker.issue(principal, site, execution=execution)
                if (
                    credential.expires_at <= self._clock()
                    or credential.expires_at > principal.expires_at
                ):
                    raise _IndexerFailure(0, ErrorCode.TOKEN_BROKER_UNAVAILABLE)
            else:
                with question_stage(
                    self._telemetry, StageName.broker, execution.trace_context
                ) as span:
                    try:
                        credential = await self._broker.issue(principal, site, execution=execution)
                        if (
                            credential.expires_at <= self._clock()
                            or credential.expires_at > principal.expires_at
                        ):
                            span.set_outcome(StageOutcome.unavailable)
                            if self._metrics is not None:
                                emit_token_broker_failure(self._metrics)
                            raise _IndexerFailure(0, ErrorCode.TOKEN_BROKER_UNAVAILABLE)
                        span.set_outcome(StageOutcome.ok)
                    except _IndexerFailure:
                        raise
                    except Exception as exc:
                        span.set_outcome(StageOutcome.unavailable)
                        if self._metrics is not None:
                            emit_token_broker_failure(self._metrics)
                        code = getattr(exc, "code", ErrorCode.TOKEN_BROKER_UNAVAILABLE)
                        unavailable = ErrorCode.TOKEN_BROKER_UNAVAILABLE
                        broker_code = code if isinstance(code, ErrorCode) else unavailable
                        raise _IndexerFailure(0, broker_code) from exc
        except _IndexerFailure:
            raise
        except Exception as exc:
            code = getattr(exc, "code", ErrorCode.TOKEN_BROKER_UNAVAILABLE)
            raise _IndexerFailure(
                0, code if isinstance(code, ErrorCode) else ErrorCode.TOKEN_BROKER_UNAVAILABLE
            ) from exc
        return credential

    async def _open_pit(
        self,
        client: httpx.AsyncClient,
        compiled: CompiledQuery,
        site: AuthorizedSite,
        credential: IndexerCredential,
        question_id: UUID,
        execution: ExecutionContext,
    ) -> str | None:
        index_part = compiled.path.split("/", 2)[1]
        path = (
            f"/{index_part}/_search/point_in_time?keep_alive={quote(self._pit_keep_alive, safe='')}"
        )
        body = await self._admitted_request_json(
            client,
            "POST",
            path,
            None,
            credential,
            call="pit",
            question_id=question_id,
            site=site,
            execution=execution,
        )
        pit_id = body.get("pit_id") or body.get("id")
        if not isinstance(pit_id, str) or not pit_id or len(pit_id.encode()) > 4096:
            raise _IndexerFailure(502, ErrorCode.INDEXER_UNAVAILABLE)
        return pit_id

    async def _request_json(
        self,
        client: httpx.AsyncClient,
        method: str,
        path: str,
        body: dict[str, object] | None,
        credential: IndexerCredential,
    ) -> dict[str, object]:
        headers = {
            "authorization": f"Bearer {credential.bearer_token.get_secret_value()}",
            "accept": "application/json",
            "accept-encoding": "identity",
        }
        try:
            if body is None:
                stream = client.stream(
                    method,
                    path,
                    headers=headers,
                    timeout=httpx.Timeout(10.0, connect=2.0, read=8.0, write=2.0, pool=2.0),
                    follow_redirects=False,
                )
            else:
                stream = client.stream(
                    method,
                    path,
                    headers=headers,
                    json=body,
                    timeout=httpx.Timeout(10.0, connect=2.0, read=8.0, write=2.0, pool=2.0),
                    follow_redirects=False,
                )
            async with stream as response:
                if response.is_redirect:
                    raise _IndexerFailure(response.status_code, ErrorCode.INDEXER_UNAVAILABLE)
                if response.status_code != 200:
                    raise _IndexerFailure(response.status_code, _status_code(response.status_code))
                encoding = response.headers.get("content-encoding", "identity").lower()
                if encoding != "identity":
                    raise _IndexerFailure(502, ErrorCode.EVIDENCE_LIMIT)
                length = response.headers.get("content-length")
                if length is not None and (
                    not length.isdigit() or int(length) > self._response_bytes
                ):
                    raise _IndexerFailure(502, ErrorCode.EVIDENCE_LIMIT)
                chunks: list[bytes] = []
                size = 0
                # Compression is forbidden above, so decoded and wire bytes are identical.
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > self._response_bytes:
                        raise _IndexerFailure(502, ErrorCode.EVIDENCE_LIMIT)
                    chunks.append(chunk)
            raw = b"".join(chunks)
            value: object = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError("expected object")
            return _json_object(cast(dict[object, object], value))
        except httpx.TimeoutException as exc:
            raise _IndexerFailure(504, ErrorCode.INDEXER_UNAVAILABLE) from exc
        except httpx.HTTPError as exc:
            raise _IndexerFailure(502, ErrorCode.INDEXER_UNAVAILABLE) from exc

    async def _admitted_request_json(
        self,
        client: httpx.AsyncClient,
        method: str,
        path: str,
        body: dict[str, object] | None,
        credential: IndexerCredential,
        *,
        call: Literal["mapping", "validate", "pit", "search", "probe"],
        question_id: UUID,
        site: AuthorizedSite,
        execution: ExecutionContext,
    ) -> dict[str, object]:
        """Run one transport attempt while holding its site-scoped physical-read grant."""
        operation_id = uuid4()
        now = self._clock().astimezone(UTC)
        execution.cancel.raise_if_cancelled()
        try:
            admitted = await self._read_admission.acquire(
                environment_id=site.config.environment_id,
                question_id=question_id,
                operation_id=operation_id,
                call=call,
                now=now,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            raise _IndexerFailure(0, ErrorCode.DEPENDENCY_UNAVAILABLE) from exc

        if isinstance(admitted, StageCapacityRejection):
            if (
                admitted.question_id != question_id
                or admitted.operation_id != operation_id
                or admitted.call != call
            ):
                raise _IndexerFailure(0, ErrorCode.DEPENDENCY_UNAVAILABLE)
            raise _IndexerFailure(0, admitted.code)
        if type(admitted) is not ReadOperationGrant:
            raise _IndexerFailure(0, ErrorCode.DEPENDENCY_UNAVAILABLE)
        if (
            admitted.question_id != question_id
            or admitted.environment_id != site.config.environment_id
            or admitted.operation_id != operation_id
            or admitted.call != call
        ):
            raise _IndexerFailure(0, ErrorCode.DEPENDENCY_UNAVAILABLE)

        physical_call: asyncio.Task[dict[str, object]] | None = None
        handed_off = False
        try:
            execution.cancel.raise_if_cancelled()
            request_started_at = self._clock().astimezone(UTC)
            if execution.deadline_at <= request_started_at:
                raise _IndexerFailure(0, ErrorCode.DEADLINE_EXCEEDED)
            remaining = (admitted.hard_deadline_at - request_started_at).total_seconds()
            if remaining <= 0:
                raise _IndexerFailure(0, ErrorCode.DEADLINE_EXCEEDED)
            execution.calls.claim(CallKind(call))

            async def bounded_request() -> dict[str, object]:
                try:
                    async with asyncio.timeout(remaining):
                        return await self._request_json(client, method, path, body, credential)
                except TimeoutError as exc:
                    raise _IndexerFailure(504, ErrorCode.DEADLINE_EXCEEDED) from exc

            physical_call = asyncio.create_task(bounded_request())
            try:
                return await asyncio.shield(physical_call)
            except asyncio.CancelledError:
                if not physical_call.done():
                    handed_off = True
                    cleanup = asyncio.create_task(
                        self._release_after_physical_call(physical_call, admitted)
                    )
                    self._track_cleanup(cleanup)
                raise
        finally:
            if not handed_off:
                release = asyncio.create_task(self._read_admission.release(admitted))
                self._track_cleanup(release)
                try:
                    await asyncio.shield(release)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    raise _IndexerFailure(0, ErrorCode.DEPENDENCY_UNAVAILABLE) from exc

    async def _release_after_physical_call(
        self,
        physical_call: asyncio.Task[dict[str, object]],
        grant: ReadOperationGrant,
    ) -> None:
        try:
            await physical_call
        except (Exception, asyncio.CancelledError):
            # The caller was cancelled; consume the detached transport result while retaining
            # the permit until the transport really terminates.
            pass
        await self._read_admission.release(grant)

    def _track_cleanup(self, task: asyncio.Task[None]) -> None:
        self._background_cleanup.add(task)
        task.add_done_callback(self._cleanup_finished)

    def _cleanup_finished(self, task: asyncio.Task[None]) -> None:
        self._background_cleanup.discard(task)
        if not task.cancelled():
            task.exception()

    async def _empty_diagnostics(
        self,
        client: httpx.AsyncClient,
        compiled: CompiledQuery,
        fetch: FetchSpec,
        pit_id: str,
        credential: IndexerCredential,
        question_id: UUID,
        site: AuthorizedSite,
        execution: ExecutionContext,
    ) -> tuple[bool | None, Count | None, list[tuple[Filter, Count | None]], Count | None]:
        query = _mapping(compiled.body.get("query"))
        bool_query = _mapping(query.get("bool")) if query else None
        raw_filters = bool_query.get("filter") if bool_query else None
        if not isinstance(raw_filters, list) or not raw_filters:
            return None, None, [], None
        clauses = cast(list[object], raw_filters)

        index_exists: bool | None = None
        index_part = compiled.path.split("/", 2)[1]
        try:
            resolved = await self._admitted_request_json(
                client,
                "GET",
                f"/_resolve/index/{index_part}",
                None,
                credential,
                call="mapping",
                question_id=question_id,
                site=site,
                execution=execution,
            )
            indices = resolved.get("indices")
            aliases = resolved.get("aliases")
            data_streams = resolved.get("data_streams")
            index_exists = any(
                isinstance(value, list) and bool(cast(list[object], value))
                for value in (indices, aliases, data_streams)
            )
        except _IndexerFailure as exc:
            if exc.status == 0:
                raise
            index_exists = None
        except Exception:
            index_exists = None

        async def count_for(filters: list[object]) -> Count | None:
            try:
                response = await self._admitted_request_json(
                    client,
                    "POST",
                    "/_search",
                    {
                        "size": 0,
                        "track_total_hits": True,
                        "pit": {"id": pit_id, "keep_alive": self._pit_keep_alive},
                        "query": {"bool": {"filter": filters}},
                    },
                    credential,
                    call="probe",
                    question_id=question_id,
                    site=site,
                    execution=execution,
                )
            except _IndexerFailure as exc:
                if exc.status == 0:
                    raise
                return None
            except Exception:
                return None
            return self._count(response, compiled)

        window_count = await count_for([clauses[0]])
        filter_counts: list[tuple[Filter, Count | None]] = []
        for index, item in enumerate(fetch.filters, start=1):
            filter_counts.append(
                (item, await count_for([clauses[0], clauses[index]]))
                if index < len(clauses)
                else (item, None)
            )
        combination_count = await count_for(clauses)
        return index_exists, window_count, filter_counts, combination_count

    def _result(
        self,
        response: dict[str, object],
        compiled: CompiledQuery,
        fetch: FetchSpec,
        topic_id: str,
        question_id: UUID,
        site: AuthorizedSite,
        *,
        pit_id: str | None,
        profile: MappingProfile,
        principal: VerifiedPrincipal,
        prior_cursor: CursorPayload | None = None,
        empty_diagnostics: tuple[
            bool | None, Count | None, list[tuple[Filter, Count | None]], Count | None
        ]
        | None = None,
    ) -> FetchResult:
        now = self._clock().astimezone(UTC)
        expires_at = now + timedelta(seconds=300) if pit_id else None
        hits_obj = _mapping(response.get("hits")) or {}
        hits_value = hits_obj.get("hits", [])
        raw_hits = cast(list[object], hits_value) if isinstance(hits_value, list) else []
        hit_dicts = [mapped for hit in raw_hits if (mapped := _mapping(hit)) is not None]
        sort_hits = hit_dicts
        missing_hit_object = len(hit_dicts) != len(raw_hits)
        response_identity = sha256_hex([hit.get("_id") for hit in hit_dicts])
        snapshot = (
            prior_cursor.snapshot
            if prior_cursor
            else snapshot_ref(
                environment_id=site.config.environment_id,
                pit_id=pit_id,
                question_id=question_id,
                fetch=fetch,
                at=now,
                expires_at=expires_at,
                response_identity=response_identity,
            )
        )
        count = self._count(response, compiled)
        columns: list[Column] = []
        rows: list[EvidenceRow] = []
        items: list[EvidenceItem] = []
        buckets: list[Bucket] = []
        completeness = "complete"
        if compiled.template_id in _ROW_TEMPLATES and hit_dicts:
            try:
                columns, rows, row_items = materialize_rows(
                    hits=hit_dicts,
                    fields=compiled.projected_fields,
                    field_names=profile.fields,
                    question_id=question_id,
                    environment_id=site.config.environment_id,
                    topic_id=topic_id,
                    fetch=fetch,
                    snapshot=snapshot,
                    visibility=site.visibility,
                    policy_hash=site.policy_hash,
                )
            except (ValueError, TypeError):
                return self._unavailable(
                    fetch,
                    topic_id,
                    site,
                    ErrorCode.EVIDENCE_INVALID,
                    "Indexer evidence could not be validated.",
                )
            items.extend(row_items)
        duplicate_source = compiled.template_id in _ROW_TEMPLATES and len(hit_dicts) > len(rows)
        if compiled.is_grouped:
            aggs = _mapping(response.get("aggregations"))
            agg = _mapping(aggs.get("visible_groups")) if aggs else None
            bucket_raw: object = agg.get("buckets", []) if agg else []
            bucket_values: list[object] = (
                cast(list[object], bucket_raw) if isinstance(bucket_raw, list) else []
            )
            if not isinstance(bucket_raw, list):
                return self._unavailable(
                    fetch,
                    topic_id,
                    site,
                    ErrorCode.INDEXER_UNAVAILABLE,
                    "Indexer response was invalid.",
                )
            group_field = fetch.group_by
            if group_field is None:
                return self._unavailable(
                    fetch,
                    topic_id,
                    site,
                    ErrorCode.QUERY_INVALID,
                    "The approved query is unavailable.",
                )
            for raw_value in bucket_values:
                raw_bucket = _mapping(raw_value)
                key = raw_bucket.get("key") if raw_bucket else None
                if raw_bucket is None or not isinstance(key, (str, int)) or isinstance(key, bool):
                    continue
                count_obj = raw_bucket.get("doc_count")
                if not isinstance(count_obj, int) or isinstance(count_obj, bool) or count_obj < 0:
                    continue
                result, item = bucket_item(
                    question_id=question_id,
                    environment_id=site.config.environment_id,
                    topic_id=topic_id,
                    fetch=fetch,
                    snapshot=snapshot,
                    visibility=site.visibility,
                    policy_hash=site.policy_hash,
                    group_field=group_field,
                    key=key,
                    count=Count(
                        value=count_obj,
                        relation="eq",
                        scope="bucket_visible_records",
                        computed_by="indexer",
                    ),
                )
                buckets.append(result)
                items.append(item)
            other_count = agg.get("sum_other_doc_count") if agg else None
            if (
                isinstance(other_count, int)
                and not isinstance(other_count, bool)
                and other_count > 0
            ):
                completeness = "partial"
        if count is not None:
            items.append(
                count_item(
                    question_id=question_id,
                    environment_id=site.config.environment_id,
                    topic_id=topic_id,
                    fetch=fetch,
                    snapshot=snapshot,
                    visibility=site.visibility,
                    policy_hash=site.policy_hash,
                    count=count,
                )
            )
        next_cursor = None
        cursor_boundary: list[str | int] | None = None
        cursor_unavailable = (
            not pit_id
            or profile.tie_break_field != "_id"
            or self._cursor_cipher is None
            or missing_hit_object
        )
        if (
            pit_id
            and self._cursor_cipher
            and profile.tie_break_field == "_id"
            and compiled.template_id in _ROW_TEMPLATES
            and not missing_hit_object
            and sort_hits
        ):
            boundaries = [_cursor_boundary(hit) for hit in sort_hits]
            if boundaries and all(boundary is not None for boundary in boundaries):
                last_boundary = boundaries[-1]
                if last_boundary is not None:
                    cursor_boundary = last_boundary
            else:
                cursor_unavailable = True
            if cursor_boundary is not None:
                expiry = min(
                    now + timedelta(seconds=300),
                    snapshot.expires_at or now + timedelta(seconds=300),
                )
                remaining = max(0, fetch.limit - len(rows)) if fetch.limit is not None else None
                if prior_cursor and prior_cursor.remaining_top_n is not None:
                    remaining = max(0, prior_cursor.remaining_top_n - len(rows))
                if remaining is None or remaining > 0:
                    payload = CursorPayload(
                        key_id=self._cursor_cipher.current_key_id,
                        owner_key=principal.owner_key,
                        environment_id=site.config.environment_id,
                        policy_hash=site.policy_hash,
                        content_sha=self._content_sha,
                        question_id=question_id,
                        topic_id=topic_id,
                        fetch_id=fetch.fetch_id,
                        template_id=TemplateId(fetch.template_id),
                        filters=fetch.filters,
                        window=fetch.window,
                        projection_hash=sha256_hex(compiled.projected_fields),
                        sort_values=cursor_boundary,
                        pit_id=pit_id,
                        snapshot=snapshot,
                        page_size=fetch.page_size,
                        remaining_top_n=remaining,
                        order=fetch.order,
                        expires_at=expiry,
                    )
                    try:
                        next_cursor = self._cursor_cipher.seal(payload)
                    except CursorError:
                        next_cursor = None
                        cursor_unavailable = True
        positive_count = count is not None and count.value > 0
        state = (
            FetchState.filtered
            if site.visibility == Visibility.filtered
            else FetchState.rows
            if rows or positive_count
            else FetchState.empty
        )
        empty_proof = None
        message = None
        if not rows and not buckets and count is not None and count.value == 0:
            index_exists, window_count, filter_counts, combination_count = empty_diagnostics or (
                None,
                None,
                [],
                None,
            )
            empty_proof = build_empty_proof(
                question_id=question_id,
                environment_id=site.config.environment_id,
                topic_id=topic_id,
                fetch=fetch,
                snapshot=snapshot,
                visibility=site.visibility,
                policy_hash=site.policy_hash,
                index_exists=index_exists,
                window_count=window_count,
                filter_counts=filter_counts,
                combination_count=combination_count,
            )
            message = (
                "No matching visible records; an approved filter matched nothing."
                if empty_proof.consistency == "coherent" and empty_proof.matched_nothing
                else "No matching visible records; ingestion status is unconfirmed."
            )
        if compiled.template_id in _ROW_TEMPLATES and next_cursor is None and cursor_unavailable:
            limitation = (
                "Paging is unavailable because a stable three-part cursor boundary "
                "was not available."
            )
            message = f"{message} {limitation}" if message else limitation
        if prior_cursor and prior_cursor.snapshot.key != snapshot.key:
            return self._unavailable(
                fetch,
                topic_id,
                site,
                ErrorCode.EVIDENCE_INVALID,
                "Indexer snapshot changed during paging.",
            )
        scope = FetchScope(
            environment_id=site.config.environment_id,
            template_id=TemplateId(fetch.template_id),
            index_family=compiled.family,
            filters=fetch.filters,
            visibility=Visibility(site.visibility),
            policy_hash=site.policy_hash,
            snapshot=SnapshotKind(snapshot.kind),
            displayed_rows=len(rows),
        )
        result = FetchResult(
            fetch_id=fetch.fetch_id,
            topic_id=topic_id,
            state=state,
            scope=scope,
            window=fetch.window,
            columns=columns,
            rows=rows,
            count=count,
            checks=[
                EvidenceCheck(
                    name="duplicate_source",
                    outcome="passed",
                    code="identical_source_rows_deduplicated",
                )
            ]
            if duplicate_source
            else [],
            empty_proof=empty_proof,
            next_cursor=next_cursor,
            snapshot_at=snapshot.at,
            snapshot=snapshot,
            items=items,
            buckets=buckets,
            bucket_completeness=completeness,
            message=message,
        )
        if len(canonical_bytes(result)) > self._fetch_bytes:
            return self._unavailable(
                fetch,
                topic_id,
                site,
                ErrorCode.EVIDENCE_LIMIT,
                "The bounded fetch evidence could not be returned.",
            )
        return result

    def _count(self, response: dict[str, object], compiled: CompiledQuery) -> Count | None:
        if compiled.template_id in _COUNT_TEMPLATES:
            value = response.get("count")
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                return Count(
                    value=value,
                    relation="eq",
                    scope="matching_visible_records",
                    computed_by="indexer",
                )
            # PIT searches use hits.total even for a configured count template.
            if "hits" not in response:
                return None
        hits = _mapping(response.get("hits"))
        total = hits.get("total") if hits else None
        if isinstance(total, int) and not isinstance(total, bool) and total >= 0:
            return Count(
                value=total, relation="eq", scope="matching_visible_records", computed_by="indexer"
            )
        total_object = _mapping(total)
        if total_object is not None:
            value = total_object.get("value")
            relation = total_object.get("relation")
            if (
                isinstance(value, int)
                and not isinstance(value, bool)
                and value >= 0
                and relation in ("eq", "gte")
            ):
                return Count(
                    value=value,
                    relation=relation,
                    scope="matching_visible_records",
                    computed_by="indexer",
                    approximate=relation == "gte",
                )
        return None

    def _failure(
        self, fetch: FetchSpec, topic_id: str, site: AuthorizedSite, failure: _IndexerFailure
    ) -> FetchResult:
        if failure.status == 403 or failure.code == ErrorCode.INDEXER_DENIED:
            return self._denied(
                fetch, topic_id, site, ErrorCode.INDEXER_DENIED, "The site denied this read."
            )
        code = failure.code
        if failure.status == 401:
            code = ErrorCode.INDEXER_AUTH_REJECTED
        return self._unavailable(
            fetch, topic_id, site, code, "The site could not complete this read."
        )

    def _base(
        self,
        fetch: FetchSpec,
        topic_id: str,
        site: AuthorizedSite,
        state: FetchState,
        code: ErrorCode,
        message: str,
    ) -> FetchResult:
        now = self._clock().astimezone(UTC)
        snap = SnapshotRef(
            kind=SnapshotKind.first_page_only,
            key=sha256_hex(
                {"site": site.config.environment_id, "fetch": fetch.fetch_id, "time": now}
            ),
            at=now,
        )
        family = _FAMILY.get(fetch.template_id)
        if family is None:
            family = next(iter(site.config.allowed_index_patterns), None)
        if family is None:
            family = "alerts"
        scope = FetchScope(
            environment_id=site.config.environment_id,
            template_id=TemplateId(fetch.template_id),
            index_family=IndexFamily(family),
            filters=fetch.filters,
            visibility=Visibility(site.visibility),
            policy_hash=site.policy_hash,
            snapshot=SnapshotKind(snap.kind),
            displayed_rows=0,
        )
        error = DomainError(
            code=code,
            message=message,
            retryable=code in (ErrorCode.INDEXER_UNAVAILABLE, ErrorCode.TOKEN_BROKER_UNAVAILABLE),
            trace_id="00000000000000000000000000000000",
            details={},
        )
        return FetchResult(
            fetch_id=fetch.fetch_id,
            topic_id=topic_id,
            state=state,
            scope=scope,
            window=fetch.window,
            columns=[],
            rows=[],
            count=None,
            checks=[],
            snapshot=snap,
            items=[],
            message=message,
            error=error,
        )

    def _denied(
        self, fetch: FetchSpec, topic_id: str, site: AuthorizedSite, code: ErrorCode, message: str
    ) -> FetchResult:
        return self._base(fetch, topic_id, site, FetchState.denied, code, message)

    def _unavailable(
        self, fetch: FetchSpec, topic_id: str, site: AuthorizedSite, code: ErrorCode, message: str
    ) -> FetchResult:
        return self._base(fetch, topic_id, site, FetchState.unavailable, code, message)

    async def _close_pit(
        self,
        client: httpx.AsyncClient,
        pit_id: str,
        credential: IndexerCredential,
        question_id: UUID,
        site: AuthorizedSite,
        execution: ExecutionContext,
    ) -> None:
        try:
            await self._admitted_request_json(
                client,
                "DELETE",
                "/_search/point_in_time",
                {"pit_id": pit_id},
                credential,
                call="pit",
                question_id=question_id,
                site=site,
                execution=execution,
            )
        except (_IndexerFailure, ValueError, json.JSONDecodeError):
            # The reviewed five-minute TTL remains the hard bound if close is unavailable.
            return


class _IndexerFailure(RuntimeError):
    def __init__(self, status: int, code: ErrorCode) -> None:
        self.status = status
        self.code = code
        super().__init__(code.value)


_ROW_TEMPLATES = {TemplateId.alerts_rows_v1, TemplateId.vulnerabilities_rows_v1}
_COUNT_TEMPLATES = {TemplateId.alerts_count_v1, TemplateId.vulnerabilities_count_v1}
_FAMILY = {
    TemplateId.alerts_rows_v1: "alerts",
    TemplateId.alerts_count_v1: "alerts",
    TemplateId.alerts_group_v1: "alerts",
    TemplateId.vulnerabilities_rows_v1: "vulnerabilities",
    TemplateId.vulnerabilities_count_v1: "vulnerabilities",
    TemplateId.vulnerabilities_group_v1: "vulnerabilities",
}


def _mapping(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    return _json_object(cast(dict[object, object], value))


def _valid_cursor_values(values: object) -> bool:
    if not isinstance(values, list):
        return False
    raw_values = cast(list[object], values)
    if len(raw_values) != 3:
        return False
    timestamp, index_name, record_id = raw_values
    return (
        (
            isinstance(timestamp, str)
            or isinstance(timestamp, int)
            and not isinstance(timestamp, bool)
        )
        and isinstance(index_name, str)
        and bool(index_name)
        and isinstance(record_id, str)
        and bool(record_id)
    )


def _cursor_boundary(hit: dict[str, object]) -> list[str | int] | None:
    values = hit.get("sort")
    index_name = hit.get("_index")
    record_id = hit.get("_id")
    if not _valid_cursor_values(values):
        return None
    raw_values = cast(list[object], values)
    if raw_values[1] != index_name or raw_values[2] != record_id:
        return None
    return cast(list[str | int], raw_values)


def _json_object(value: dict[object, object]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ValueError("JSON object keys must be strings")
        if isinstance(item, dict):
            result[key] = _json_object(cast(dict[object, object], item))
        elif isinstance(item, list):
            children = cast(list[object], item)
            result[key] = [
                _json_object(cast(dict[object, object], child))
                if isinstance(child, dict)
                else child
                for child in children
            ]
        else:
            result[key] = item
    return result


def _status_code(status: int) -> ErrorCode:
    if status == 401:
        return ErrorCode.INDEXER_AUTH_REJECTED
    if status == 403:
        return ErrorCode.INDEXER_DENIED
    if status in (400, 404):
        return ErrorCode.MAPPING_UNSUPPORTED
    return ErrorCode.INDEXER_UNAVAILABLE


def _response_exact_zero(response: dict[str, object], compiled: CompiledQuery) -> bool:
    if compiled.template_id in _COUNT_TEMPLATES:
        value = response.get("count")
        if isinstance(value, int) and not isinstance(value, bool):
            return value == 0
    hits = _mapping(response.get("hits"))
    total = hits.get("total") if hits else None
    if isinstance(total, int) and not isinstance(total, bool):
        return total == 0
    total_object = _mapping(total)
    return (
        total_object is not None
        and total_object.get("value") == 0
        and total_object.get("relation") == "eq"
    )
