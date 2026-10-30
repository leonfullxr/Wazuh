"""Shared application sequencing for REST and MCP transports."""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from hashlib import sha256
from typing import Literal, Protocol, cast
from uuid import UUID, uuid4

from pydantic import TypeAdapter

from ai_soc.application.answers import AnswerAssembly, audit_fetch_record
from ai_soc.application.errors import ServiceFailure
from ai_soc.application.kev_annotations import decorate_answer_tables, decorate_page
from ai_soc.application.runtime import RequestCancellation, RequestCancelled
from ai_soc.application.topic_evidence import TopicEvidence
from ai_soc.application.topic_judgment import (
    QuestionBudgetHandle,
    TopicJudgment,
)
from ai_soc.contracts.canonical import canonical_bytes, sha256_hex
from ai_soc.contracts.errors import public_error
from ai_soc.contracts.models import (
    SHA256,
    AdmissionGrant,
    Answer,
    AnswerStatus,
    AskRequest,
    AuditAck,
    AuditContextUse,
    AuditEvent,
    AuditPageReturn,
    AuthorizedSite,
    BootstrapResponse,
    BuildProvenance,
    Clarified,
    Clarify,
    CompletionCommand,
    Effort,
    ErrorCode,
    ExecutionContext,
    FeedbackControlContext,
    FeedbackEvent,
    FeedbackMetadata,
    FeedbackQueued,
    FeedbackRequest,
    FetchResult,
    FetchSpec,
    FetchState,
    FollowupRecord,
    HTTPSUrl,
    IdempotencyRecord,
    JudgmentResult,
    JudgmentState,
    Lease,
    LeftOut,
    ModelCapability,
    ModelCapabilityPublic,
    PageRequest,
    PublicLimits,
    QuestionPlan,
    Refused,
    SemanticSuggestion,
    SitePublic,
    StageName,
    StageOutcome,
    StageSpan,
    TemplateId,
    TopicAnswer,
    TopicDefinition,
    TopicPlan,
    TraceContext,
    ValidationContext,
    VerifiedPrincipal,
)
from ai_soc.contracts.ports import (
    AdmissionStore,
    BudgetStore,
    Clock,
    CompletionStore,
    ContentCatalog,
    FeedbackSink,
    FeedbackStore,
    FetchExecutor,
    FindingValidator,
    JudgmentEngine,
    JudgmentProvider,
    LeaseStore,
    Planner,
    PlanStore,
    PlaybookExecutor,
    SemanticSuggester,
    SitePolicy,
    Telemetry,
)
from ai_soc.feedback.receipts import FeedbackReceiptCodec
from ai_soc.feedback.redaction import redact_note
from ai_soc.identity.policy import SiteAuthorizationError
from ai_soc.judgment.capabilities import CapabilityError, validate_selection
from ai_soc.planning.followups import InvalidContinuation
from ai_soc.planning.parser import has_deterministic_route
from ai_soc.query.cursors import CursorCipher, CursorError
from ai_soc.state.errors import StateFailure
from ai_soc.telemetry.audit_delivery import AuditUnavailable
from ai_soc.telemetry.events import TelemetryAdapter
from ai_soc.telemetry.instrumentation import question_stage
from ai_soc.telemetry.metrics import MetricExporter
from ai_soc.telemetry.operational import (
    emit_content_provenance_failure,
    emit_feedback_enqueue_failure,
    emit_lease_conflict,
)
from ai_soc.telemetry.outcomes import (
    begin_stage_outcomes,
    current_stage_outcomes,
    reset_stage_outcomes,
)
from ai_soc.telemetry.worker_capacity import document_slot

_LEASE_RENEW_INTERVAL = timedelta(seconds=20)


class RequestRuntime(Protocol):
    def create(
        self,
        *,
        question_id: UUID,
        operation: Literal["ask", "page", "feedback", "semantic"],
        owner_key: str,
        environment_id: str,
        admission: AdmissionGrant,
        trace_context: TraceContext | None = None,
    ) -> ExecutionContext: ...


def derive_answer_status(
    blocks: Sequence[TopicAnswer], left_out: Sequence[LeftOut]
) -> AnswerStatus:
    if (
        left_out
        or any(
            block.judgment.state
            not in {
                JudgmentState.not_requested,
                JudgmentState.validated,
                JudgmentState.no_findings,
            }
            for block in blocks
        )
        or any(
            table.state in {FetchState.denied, FetchState.unavailable}
            for block in blocks
            for table in block.tables
        )
    ):
        return AnswerStatus.partial
    return AnswerStatus.answered


def invalid_continuation_failure() -> ServiceFailure:
    return ServiceFailure(
        public_error(
            ErrorCode.INVALID_CONTINUATION,
            "The continuation selection is invalid.",
            trace_id=uuid4().hex,
        )
    )


def order_topic_answers(blocks: Sequence[TopicAnswer]) -> list[TopicAnswer]:
    """Keep rendered answer blocks in the plan's first-mention order."""
    return sorted(blocks, key=lambda block: block.ordinal)


class QuestionAdmission(Protocol):
    async def begin_request(
        self,
        *,
        owner_key: str,
        environment_id: str,
        question_id: UUID,
        request_hash: str,
        idempotency_key: UUID | None,
        now: datetime,
    ) -> Lease: ...


@dataclass(slots=True)
class ApplicationService:
    clock: Clock
    catalog: ContentCatalog
    planner: Planner
    site_policy: SitePolicy
    plans: PlanStore
    admissions: AdmissionStore
    question_admission: QuestionAdmission
    leases: LeaseStore
    budgets: BudgetStore
    completions: CompletionStore
    fetches: FetchExecutor
    playbooks: PlaybookExecutor
    judgment_engine: JudgmentEngine
    judgment_provider: JudgmentProvider
    finding_validator: FindingValidator
    telemetry: Telemetry
    feedback_sink: FeedbackSink
    feedback_store: FeedbackStore
    receipts: FeedbackReceiptCodec
    runtime: RequestRuntime
    models: tuple[ModelCapability, ...]
    mode: Literal["fixture", "live"] = "fixture"
    token_limit: int = 100_000
    owner_daily_token_limit: int = 200_000
    service_daily_token_limit: int = 1_000_000
    guardrail_identifier: str = ""
    guardrail_version: str = ""
    semantic_suggester: SemanticSuggester | None = None
    kev_activation_at: datetime | None = None
    cursor_cipher: CursorCipher | None = None
    _document_slots: asyncio.Semaphore = field(
        default_factory=lambda: asyncio.Semaphore(16), init=False, repr=False
    )

    def _metrics(self) -> MetricExporter | None:
        if isinstance(self.telemetry, TelemetryAdapter):
            return self.telemetry.metrics_exporter
        return None

    @staticmethod
    def _question_trace() -> TraceContext:
        return TraceContext(
            trace_id=secrets.token_hex(16),
            span_id=secrets.token_hex(8),
            trace_flags=1,
        )

    @contextmanager
    def _stage(self, stage: StageName, trace_context: TraceContext) -> Iterator[StageSpan | None]:
        telemetry = getattr(self, "telemetry", None)
        if telemetry is None:
            yield None
            return
        with question_stage(telemetry, stage, trace_context) as span:
            yield span

    async def _maybe_renew_lease(self, lease: Lease) -> Lease:
        now = self.clock.now()
        if now - lease.last_renewed_at >= _LEASE_RENEW_INTERVAL:
            lease = await self.leases.renew(lease, now=now)
        return lease

    async def _lease_renewal_loop(
        self, holder: list[Lease], stop: asyncio.Event, cancel: RequestCancellation
    ) -> None:
        """Renew the question lease on a control path while backend work runs."""
        try:
            while not stop.is_set():
                await asyncio.sleep(0.05)
                if stop.is_set():
                    break
                now = self.clock.now()
                if now - holder[0].last_renewed_at >= _LEASE_RENEW_INTERVAL:
                    try:
                        holder[0] = await self.leases.renew(holder[0], now=now)
                    except (StateFailure, ServiceFailure):
                        cancel.cancel()
                        return
        except asyncio.CancelledError:
            raise

    async def bootstrap(self, principal: VerifiedPrincipal) -> BootstrapResponse:
        async with document_slot(self._document_slots):
            return await self._bootstrap_impl(principal)

    async def _bootstrap_impl(self, principal: VerifiedPrincipal) -> BootstrapResponse:
        sites = self.site_policy.authorized_sites(principal)
        manifest = self.catalog.manifest()
        return BootstrapResponse(
            sites=[SitePublic(id=item.environment_id, label=item.label) for item in sites],
            models=[
                ModelCapabilityPublic(
                    id=item.id,
                    label=item.label,
                    efforts=list(item.efforts),
                    context_tokens=item.context_tokens,
                    max_output_tokens=item.max_output_tokens,
                )
                for item in self.models
            ],
            provenance=manifest,
            mode=self.mode,
            limits=PublicLimits(
                question_bytes=16384,
                page_size=50,
                window_days=90,
                request_bytes=65536,
                plan_bytes=131072,
            ),
        )

    def _authorize_site(self, principal: VerifiedPrincipal, environment_id: str) -> AuthorizedSite:
        """Translate policy denials once at the shared REST/MCP application boundary."""
        try:
            return self.site_policy.authorize(principal, environment_id)
        except SiteAuthorizationError as error:
            if error.code != ErrorCode.SITE_DENIED:
                raise
            raise ServiceFailure(
                public_error(
                    ErrorCode.SITE_DENIED,
                    "Access to this site is denied.",
                    trace_id=uuid4().hex,
                )
            ) from None

    async def ask(
        self,
        request: AskRequest,
        principal: VerifiedPrincipal,
        *,
        idempotency_key: UUID | None = None,
    ) -> Answer:
        trace_context = self._question_trace()
        outcomes_token = begin_stage_outcomes()
        try:
            return await self._ask_impl(
                request,
                principal,
                idempotency_key=idempotency_key,
                trace_context=trace_context,
            )
        except AuditUnavailable:
            raise ServiceFailure(
                public_error(
                    ErrorCode.AUDIT_UNAVAILABLE,
                    "The audit service is temporarily unavailable.",
                    trace_id=trace_context.trace_id,
                    retryable=True,
                )
            ) from None
        finally:
            reset_stage_outcomes(outcomes_token)

    async def _ask_impl(
        self,
        request: AskRequest,
        principal: VerifiedPrincipal,
        *,
        idempotency_key: UUID | None,
        trace_context: TraceContext,
    ) -> Answer:
        with self._stage(StageName.auth, trace_context):
            site = self._authorize_site(principal, request.environment_id)
        ingress = await self.admissions.acquire(
            principal.owner_key,
            request.environment_id,
            "ingress",
            uuid4(),
            self.clock.now(),
        )
        await self.admissions.release(ingress)
        with self._stage(StageName.content, trace_context):
            manifest = self.catalog.manifest()
        previous: FollowupRecord | None = None
        if request.followup_id is not None and request.followup_revision is not None:
            previous = await self.plans.load(
                request.followup_id,
                owner_key=principal.owner_key,
                environment_id=request.environment_id,
                revision=request.followup_revision,
                policy_hash=site.policy_hash,
                content_sha=manifest.content_sha,
                now=self.clock.now(),
            )
        with self._stage(StageName.plan, trace_context):
            try:
                result = self.planner.plan(
                    request,
                    principal,
                    previous,
                    policy_hash=site.policy_hash,
                    clock=self.clock,
                )
            except InvalidContinuation as exc:
                raise invalid_continuation_failure() from exc
        if isinstance(result, Refused):
            suggestion = await self._semantic_suggestion(request, principal, site)
            if suggestion is not None and suggestion.qualifies:
                topic = self.catalog.topic(suggestion.topic_id)
                if topic is not None and (
                    topic.public_document is not None
                    or any(
                        binding.template_id in site.config.allowed_templates
                        for binding in topic.fetch_bindings
                    )
                ):
                    language = request.language_hint or "en"
                    clarify = Clarify(
                        kind="semantic_suggestion",
                        question=(
                            f"\u00bfTe refieres a {topic.name.es}?"
                            if language == "es"
                            else f"Did you mean {topic.name.en}?"
                        ),
                        slots=["topic"],
                        suggested_topic=suggestion.topic_id,
                    )
                    return await self._unplanned_answer(
                        request,
                        principal,
                        site.policy_hash,
                        manifest,
                        status=AnswerStatus.clarify,
                        message=None,
                        clarify=clarify,
                        topic_ids=[],
                        cue_ids=[],
                        trace_context=trace_context,
                    )
        if isinstance(result, Clarified):
            return await self._unplanned_answer(
                request,
                principal,
                site.policy_hash,
                manifest,
                status=AnswerStatus.clarify,
                message=None,
                clarify=result.clarify,
                topic_ids=[],
                cue_ids=[],
                trace_context=trace_context,
            )
        if isinstance(result, Refused):
            return await self._unplanned_answer(
                request,
                principal,
                site.policy_hash,
                manifest,
                status=AnswerStatus.refused,
                message=result.message,
                clarify=None,
                topic_ids=[],
                cue_ids=[],
                trace_context=trace_context,
            )
        # The two non-plan variants returned above leave the planned branch here.
        plan = result.plan
        if plan.content_sha != manifest.content_sha:
            metrics = self._metrics()
            if metrics is not None:
                emit_content_provenance_failure(metrics)
        if (
            plan.owner_key != principal.owner_key
            or plan.environment_id != request.environment_id
            or plan.policy_hash != site.policy_hash
            or plan.content_sha != manifest.content_sha
        ):
            raise self._failure(
                ErrorCode.POLICY_CHANGED, "Authorization changed; ask a new question."
            )
        plan_bytes = len(canonical_bytes(plan))
        if plan_bytes > 131072:
            return await self._unplanned_answer(
                request,
                principal,
                site.policy_hash,
                manifest,
                status=AnswerStatus.clarify,
                message=None,
                clarify=Clarify(
                    kind="ambiguous_scope", question="Please narrow the question.", slots=["scope"]
                ),
                topic_ids=[],
                cue_ids=[],
                trace_context=trace_context,
            )
        if not self._has_backend_work(plan):
            blocks = [self._document_block(topic, plan) for topic in plan.topics]
            return await self._answer_without_state(
                request,
                principal,
                plan,
                site.policy_hash,
                manifest,
                blocks,
                [],
                None,
                trace_context=trace_context,
            )
        selection = self._judgment_selection_issue(plan)
        if isinstance(selection, Clarify):
            return await self._unplanned_answer(
                request,
                principal,
                site.policy_hash,
                manifest,
                status=AnswerStatus.clarify,
                message=None,
                clarify=selection,
                topic_ids=[topic.topic_id for topic in plan.topics],
                cue_ids=[cue_id for topic in plan.topics for cue_id in topic.cue_ids],
                trace_context=trace_context,
            )
        if isinstance(selection, ServiceFailure):
            raise selection
        admission = await self.admissions.acquire(
            principal.owner_key,
            request.environment_id,
            "ask",
            plan.question_id,
            self.clock.now(),
        )
        lease = None
        renew_stop: asyncio.Event | None = None
        renew_task: asyncio.Task[None] | None = None
        lease_holder: list[Lease] | None = None
        try:
            request_hash = sha256_hex(
                {
                    "request": request.model_dump(mode="json", exclude_none=False),
                    "owner_key": principal.owner_key,
                    "environment_id": request.environment_id,
                    "content_sha": plan.content_sha,
                    "policy_hash": plan.policy_hash,
                }
            )
            lease = await self.question_admission.begin_request(
                owner_key=principal.owner_key,
                environment_id=request.environment_id,
                question_id=plan.question_id,
                request_hash=request_hash,
                idempotency_key=idempotency_key,
                now=self.clock.now(),
            )
            lease_holder = [lease]
            execution = self.runtime.create(
                question_id=plan.question_id,
                operation="ask",
                owner_key=principal.owner_key,
                environment_id=request.environment_id,
                admission=admission,
                trace_context=trace_context,
            )
            renew_stop = asyncio.Event()
            renew_task = asyncio.create_task(
                self._lease_renewal_loop(
                    lease_holder, renew_stop, cast(RequestCancellation, execution.cancel)
                )
            )
            lease = lease_holder[0]
            if any(topic.judgment for topic in plan.topics):
                await self.budgets.open(
                    question_id=plan.question_id,
                    owner_key=principal.owner_key,
                    environment_id=request.environment_id,
                    token_limit=self.token_limit,
                    expires_at=self.clock.now() + timedelta(hours=24),
                    lease=lease,
                    operation_id=uuid4(),
                    lease_supplier=lambda: lease_holder[0],
                )
            blocks: list[TopicAnswer] = []
            left_out: list[LeftOut] = []
            for topic in plan.topics:
                execution.cancel.raise_if_cancelled()
                lease = lease_holder[0]
                block, omitted = await self._run_topic(
                    principal,
                    site,
                    manifest,
                    plan,
                    request.question,
                    topic,
                    execution,
                    lease_holder,
                )
                blocks.append(block)
                left_out.extend(omitted)
            kev_uses: list[AuditContextUse] = []
            if any(block.topic_id == "vuln_review" for block in blocks):
                blocks, kev_uses = decorate_answer_tables(
                    blocks,
                    language=plan.language,
                    catalog=self.catalog,
                    manifest=manifest,
                    activation_at=self.kev_activation_at or self.clock.now(),
                    question_id=plan.question_id,
                )
            blocks = order_topic_answers(blocks)
            status = derive_answer_status(blocks, left_out)
            followup = self._followup(plan, previous, blocks, left_out)
            with self._stage(StageName.render, trace_context):
                answer = await self._build_answer(
                    request,
                    principal,
                    plan,
                    site.policy_hash,
                    manifest,
                    blocks,
                    left_out,
                    status,
                    followup,
                    trace_id=trace_context.trace_id,
                )
            attempted_ack = await self._audit(
                answer,
                principal,
                plan,
                site.policy_hash,
                manifest,
                "attempted",
                execution,
                context_uses=kev_uses,
            )
            command = CompletionCommand(
                question_id=plan.question_id,
                owner_key=principal.owner_key,
                environment_id=request.environment_id,
                answer_status=status,
                followup=followup,
                idempotency=self._active_idempotency(
                    principal,
                    request,
                    idempotency_key,
                    request_hash,
                    plan.question_id,
                    self.clock.now(),
                ),
                audit_ack=attempted_ack,
                metadata_sha256=sha256_hex(answer.model_dump(mode="json")),
            )
            receipt = await self.completions.commit(
                command,
                lease=lease_holder[0],
                now=self.clock.now(),
                operation_id=uuid4(),
                lease_supplier=lambda: lease_holder[0],
            )
            try:
                await self._audit(
                    answer,
                    principal,
                    plan,
                    site.policy_hash,
                    manifest,
                    "completed",
                    execution,
                    completion_id=receipt.completion_id,
                    context_uses=kev_uses,
                )
            except Exception:
                # The attempted event was durably acknowledged before commit; this lifecycle
                # marker is post-commit telemetry and cannot revoke an authorized completion.
                pass
            return answer
        except RequestCancelled:
            metrics = self._metrics()
            if metrics is not None:
                emit_lease_conflict(metrics)
            raise StateFailure(
                public_error(
                    ErrorCode.LEASE_LOST,
                    "Request lease was lost.",
                    trace_id=trace_context.trace_id,
                )
            ) from None
        except StateFailure as error:
            if error.code == ErrorCode.LEASE_LOST:
                metrics = self._metrics()
                if metrics is not None:
                    emit_lease_conflict(metrics)
            raise
        finally:
            try:
                if renew_task is not None and renew_stop is not None and lease_holder is not None:
                    renew_stop.set()
                    renew_task.cancel()
                    try:
                        await renew_task
                    except (asyncio.CancelledError, StateFailure, ServiceFailure):
                        pass
                    except Exception:
                        pass
                    await self.leases.release(lease_holder[0])
            finally:
                await self.admissions.release(admission)

    async def page(self, request: PageRequest, principal: VerifiedPrincipal) -> FetchResult:
        trace_context = self._question_trace()
        outcomes_token = begin_stage_outcomes()
        try:
            site = self._authorize_site(principal, request.environment_id)
            if self.cursor_cipher is None:
                raise CursorError()
            manifest = self.catalog.manifest()
            payload = self.cursor_cipher.open(
                request.cursor,
                owner_key=principal.owner_key,
                environment_id=request.environment_id,
                policy_hash=site.policy_hash,
                content_sha=manifest.content_sha,
            )
            if principal.expires_at <= self.clock.now():
                raise CursorError(ErrorCode.AUTH_EXPIRED)
            grant = await self.admissions.acquire(
                principal.owner_key, request.environment_id, "page", uuid4(), self.clock.now()
            )
            execution = self.runtime.create(
                question_id=payload.question_id,
                operation="page",
                owner_key=principal.owner_key,
                environment_id=request.environment_id,
                admission=grant,
                trace_context=trace_context,
            )
            try:
                result = await self.fetches.page(
                    request.cursor, principal=principal, site=site, execution=execution
                )
                context_uses: list[AuditContextUse] = []
                if result.topic_id == "vuln_review" and result.fetch_id == "vuln_rows":
                    decorated = decorate_page(
                        result,
                        kev_index=getattr(self.catalog, "kev_index", None),
                        manifest=manifest,
                        activation_at=self.kev_activation_at or self.clock.now(),
                        question_id=payload.question_id,
                        evaluation_at=payload.snapshot.at,
                    )
                    result = decorated.result
                    context_uses.append(decorated.audit_use)
                fetch = FetchSpec(
                    fetch_id=payload.fetch_id,
                    template_id=TemplateId(payload.template_id),
                    window=payload.window,
                    filters=payload.filters,
                    page_size=payload.page_size,
                    limit=payload.remaining_top_n,
                    order=payload.order,
                )
                record = audit_fetch_record(self.catalog, result, fetch)
                event = AuditEvent(
                    event_id=uuid4(),
                    question_id=payload.question_id,
                    trace_id=trace_context.trace_id,
                    owner_key=principal.owner_key,
                    environment_id=request.environment_id,
                    authenticated_issuer=principal.issuer,
                    auth_edge=principal.edge,
                    service_sha=manifest.service_sha,
                    image_digest=manifest.image_digest,
                    content_sha=manifest.content_sha,
                    pack_sha256=manifest.pack_sha256,
                    policy_hash=site.policy_hash,
                    cue_ids=[],
                    topic_ids=[payload.topic_id],
                    stage_outcomes=current_stage_outcomes(),
                    outcome="attempted",
                    fetches=[record] if record is not None else [],
                    context_uses=context_uses,
                    page_return=AuditPageReturn(
                        input_cursor_sha256=sha256(request.cursor.encode("utf-8")).hexdigest(),
                        next_cursor_sha256=(
                            sha256(result.next_cursor.encode("utf-8")).hexdigest()
                            if result.next_cursor is not None
                            else None
                        ),
                        response_sha256=sha256(canonical_bytes(result)).hexdigest(),
                    ),
                    created_at=self.clock.now(),
                )
                started = self.clock.monotonic()
                with self._stage(StageName.audit, trace_context) as span:
                    if span is not None:
                        span.set_outcome(StageOutcome.ok)
                        span.record_latency(max(0, int((self.clock.monotonic() - started) * 1000)))
                await self.telemetry.event(event, execution=execution)
                return result
            finally:
                await self.admissions.release(grant)
        except AuditUnavailable:
            raise ServiceFailure(
                public_error(
                    ErrorCode.AUDIT_UNAVAILABLE,
                    "The audit service is temporarily unavailable.",
                    trace_id=trace_context.trace_id,
                    retryable=True,
                )
            ) from None
        finally:
            reset_stage_outcomes(outcomes_token)

    async def feedback(
        self, request: FeedbackRequest, principal: VerifiedPrincipal
    ) -> FeedbackQueued:
        entry_mono = self.clock.monotonic()
        self._authorize_site(principal, request.environment_id)
        receipt = self.receipts.open(
            request.feedback_receipt,
            question_id=request.question_id,
            owner_key=principal.owner_key,
            environment_id=request.environment_id,
            now=self.clock.now(),
        )
        try:
            note = redact_note(request.note)
        except ValueError:
            raise self._failure(
                ErrorCode.FEEDBACK_INVALID, "Feedback note is invalid or contains sensitive data."
            ) from None
        note_hash = sha256_hex(
            {
                "domain": "soc.feedback.note.v1",
                "kind": request.kind,
                "note_redacted": note,
            }
        )
        grant = await self.admissions.acquire(
            principal.owner_key,
            request.environment_id,
            "feedback",
            request.question_id,
            self.clock.now(),
        )
        execution: ExecutionContext | None = None
        try:
            execution = self.runtime.create(
                question_id=request.question_id,
                operation="feedback",
                owner_key=principal.owner_key,
                environment_id=request.environment_id,
                admission=grant,
            )
            sampled_mono = self.clock.monotonic()
            sampled_utc = self.clock.now()
            runtime_remaining = max(0.0, (execution.deadline_at - sampled_utc).total_seconds())
            total_deadline = min(entry_mono + 120.0, sampled_mono + runtime_remaining)
            control = FeedbackControlContext(
                deadline_monotonic=total_deadline - 10.0,
                monotonic=self.clock.monotonic,
                cancel=execution.cancel,
                calls=execution.calls,
            )
            metadata = await self._feedback_read(
                receipt_id=receipt.receipt_id, note_hash=note_hash, control=control
            )
            if metadata is None:
                try:
                    metadata = await self.feedback_store.try_create_feedback(
                        receipt_id=receipt.receipt_id,
                        note_hash=note_hash,
                        now=self.clock.now(),
                        control=control,
                    )
                except (asyncio.CancelledError, RequestCancelled):
                    raise
                except Exception:
                    metadata = None
                if metadata is None:
                    metadata = await self._feedback_read(
                        receipt_id=receipt.receipt_id, note_hash=note_hash, control=control
                    )
                if metadata is None:
                    raise self._feedback_unavailable(execution)
            control.cancel.raise_if_cancelled()
            if metadata.status == "queued":
                return FeedbackQueued(feedback_id=metadata.feedback_id, status="queued")
            event = FeedbackEvent(
                feedback_id=metadata.feedback_id,
                receipt_id=receipt.receipt_id,
                question_id=request.question_id,
                owner_key=principal.owner_key,
                environment_id=request.environment_id,
                content_sha=receipt.content_sha,
                kind=request.kind,
                note_redacted=note,
                created_at=metadata.created_at,
            )
            self._require_feedback_budget(control, 10.0)
            try:
                with self._stage(StageName.feedback, execution.trace_context):
                    await self.feedback_sink.enqueue(event, execution=execution)
            except (asyncio.CancelledError, RequestCancelled):
                raise
            except Exception:
                reconciled = await self._feedback_read(
                    receipt_id=receipt.receipt_id, note_hash=note_hash, control=control
                )
                if (
                    reconciled is not None
                    and reconciled.feedback_id == metadata.feedback_id
                    and reconciled.status == "queued"
                ):
                    return FeedbackQueued(feedback_id=metadata.feedback_id, status="queued")
                raise self._feedback_unavailable(execution) from None
            self._require_feedback_budget(control, 5.0)
            try:
                marked = await self.feedback_store.mark_feedback_queued(
                    receipt_id=receipt.receipt_id,
                    note_hash=note_hash,
                    feedback_id=metadata.feedback_id,
                    now=self.clock.now(),
                    control=control,
                )
            except (asyncio.CancelledError, RequestCancelled):
                raise
            except Exception:
                marked = False
            if not marked:
                reconciled = await self._feedback_read(
                    receipt_id=receipt.receipt_id, note_hash=note_hash, control=control
                )
                if (
                    reconciled is None
                    or reconciled.feedback_id != metadata.feedback_id
                    or reconciled.status != "queued"
                ):
                    raise self._feedback_unavailable(execution)
            control.cancel.raise_if_cancelled()
            return FeedbackQueued(feedback_id=metadata.feedback_id, status="queued")
        except (asyncio.CancelledError, RequestCancelled):
            raise
        except Exception:
            metrics = self._metrics()
            if metrics is not None:
                emit_feedback_enqueue_failure(metrics)
            raise self._feedback_unavailable(execution) from None
        finally:
            await self.admissions.release(grant)

    async def _feedback_read(
        self, *, receipt_id: UUID, note_hash: SHA256, control: FeedbackControlContext
    ) -> FeedbackMetadata | None:
        self._require_feedback_budget(control, 5.0)
        record = await self.feedback_store.read_feedback(
            receipt_id=receipt_id,
            note_hash=note_hash,
            now=self.clock.now(),
            control=control,
        )
        control.cancel.raise_if_cancelled()
        return record

    @staticmethod
    def _require_feedback_budget(control: FeedbackControlContext, seconds: float) -> None:
        control.cancel.raise_if_cancelled()
        if control.monotonic() + seconds > control.deadline_monotonic:
            raise ApplicationService._feedback_unavailable(None)

    @staticmethod
    def _feedback_unavailable(execution: ExecutionContext | None) -> ServiceFailure:
        return ServiceFailure(
            public_error(
                ErrorCode.FEEDBACK_UNAVAILABLE,
                "Feedback is temporarily unavailable.",
                trace_id=(execution.trace_context.trace_id if execution else uuid4().hex),
                retryable=True,
            )
        )

    async def _run_topic(
        self,
        principal: VerifiedPrincipal,
        site: AuthorizedSite,
        manifest: BuildProvenance,
        plan: QuestionPlan,
        original_question: str,
        topic: TopicPlan,
        execution: ExecutionContext,
        lease_holder: list[Lease],
    ) -> tuple[TopicAnswer, list[LeftOut]]:
        definition = self.catalog.topic(topic.topic_id)
        document = self._pointer(definition, manifest)
        missing: list[Literal["public_document", "playbook"]] = []
        if definition is None or definition.public_document is None:
            missing.append("public_document")
        if topic.failure and topic.playbook_id is None:
            missing.append("playbook")
        evidence = await self._topic_evidence().gather(
            topic,
            plan=plan,
            principal=principal,
            site=site,
            build_pack=topic.judgment,
            execution=execution,
        )
        omitted = list(evidence.left_out)
        effort = Effort(plan.effort) if plan.effort is not None else None
        judgment = JudgmentResult(
            state=JudgmentState.not_requested,
            sentences=[],
            removed=[],
            model_id=plan.model_id,
            effort=effort,
        )
        if topic.judgment:
            pack = evidence.pack
            assert pack is not None
            context = ValidationContext(
                topic_pack=self.catalog.topic_context(topic.topic_id, language=plan.language),
                templates=self.catalog.finding_templates(topic.topic_id),
                policy_hash=plan.policy_hash,
                content_sha=plan.content_sha,
                language=plan.language,
                expected_checks=tuple(evidence.checks),
            )
            model = next((item for item in self.models if item.id == plan.model_id), None)
            judgment, left = await self._topic_judgment(lease_holder).judge(
                topic,
                pack,
                context,
                model=model,
                effort=effort,
                question=original_question,
                execution=execution,
            )
            if left:
                omitted.append(left)
        block = TopicAnswer(
            topic_id=topic.topic_id,
            ordinal=topic.ordinal,
            document=document,
            missing=missing,
            tables=evidence.tables,
            checks=evidence.checks,
            judgment=judgment,
        )
        return block, omitted

    def _topic_evidence(self) -> TopicEvidence:
        return TopicEvidence(
            playbooks=self.playbooks,
            fetches=self.fetches,
            stage=self._stage,
            metrics=self._metrics(),
        )

    def _answers(self) -> AnswerAssembly:
        return AnswerAssembly(
            catalog=self.catalog,
            receipts=self.receipts,
            clock=self.clock,
            guardrail_identifier=self.guardrail_identifier,
            guardrail_version=self.guardrail_version,
        )

    def _topic_judgment(self, lease_holder: list[Lease]) -> TopicJudgment:
        return TopicJudgment(
            engine=self.judgment_engine,
            provider=self.judgment_provider,
            validator=self.finding_validator,
            budget=QuestionBudgetHandle(
                budgets=self.budgets,
                clock=self.clock,
                lease_holder=lease_holder,
                token_limit=self.token_limit,
                owner_daily_limit=self.owner_daily_token_limit,
                service_daily_limit=self.service_daily_token_limit,
            ),
            clock=self.clock,
            stage=self._stage,
            metrics=self._metrics(),
        )

    def _document_block(self, topic: TopicPlan, plan: QuestionPlan) -> TopicAnswer:
        definition = self.catalog.topic(topic.topic_id)
        pointer = self._pointer(definition, self.catalog.manifest())
        missing: list[Literal["public_document", "playbook"]] = []
        if pointer is None:
            missing.append("public_document")
        if definition and definition.playbook_id is None and topic.failure:
            missing.append("playbook")
        return TopicAnswer(
            topic_id=topic.topic_id,
            ordinal=topic.ordinal,
            document=pointer,
            missing=missing,
            tables=[],
            checks=[],
            judgment=JudgmentResult(state=JudgmentState.not_requested, sentences=[], removed=[]),
        )

    def _pointer(self, definition: TopicDefinition | None, manifest: BuildProvenance):
        if definition is None or definition.public_document is None:
            return None
        from ai_soc.contracts.models import DocPointer

        document = definition.public_document
        url: HTTPSUrl = TypeAdapter[HTTPSUrl](HTTPSUrl).validate_python(
            f"{str(manifest.docs_origin).rstrip('/')}/{document.published_path}#{document.anchor}"
        )
        return DocPointer(
            document_id=document.document_id,
            source_path=document.source_path,
            heading=document.heading,
            anchor=document.anchor,
            url=url,
            content_sha=manifest.content_sha,
            document_sha256=document.sha256,
        )

    def _followup(
        self,
        plan: QuestionPlan,
        previous: FollowupRecord | None,
        blocks: list[TopicAnswer],
        left_out: list[LeftOut],
    ) -> FollowupRecord | None:
        if not blocks:
            return None
        now = self.clock.now()
        left_ids = list(dict.fromkeys(item.topic_id for item in left_out))
        retryable_left_out = [item for item in left_out if item.retryable]
        retryable_ids = list(dict.fromkeys(item.topic_id for item in retryable_left_out))
        return FollowupRecord(
            followup_id=uuid4(),
            owner_key=plan.owner_key,
            environment_id=plan.environment_id,
            plan=plan,
            answered_topic_ids=[
                block.topic_id for block in blocks if block.topic_id not in left_ids
            ],
            leftout_topic_ids=retryable_ids,
            leftout_stages=retryable_left_out,
            parent_id=previous.followup_id if previous else None,
            created_at=now,
            expires_at=now + timedelta(minutes=30),
        )

    async def _answer_without_state(
        self,
        request: AskRequest,
        principal: VerifiedPrincipal,
        plan: QuestionPlan,
        policy_hash: str,
        manifest: BuildProvenance,
        blocks: list[TopicAnswer],
        left_out: list[LeftOut],
        followup: FollowupRecord | None,
        *,
        trace_context: TraceContext,
    ) -> Answer:
        async with document_slot(self._document_slots):
            return await self._answer_without_state_impl(
                request,
                principal,
                plan,
                policy_hash,
                manifest,
                blocks,
                left_out,
                followup,
                trace_context=trace_context,
            )

    async def _answer_without_state_impl(
        self,
        request: AskRequest,
        principal: VerifiedPrincipal,
        plan: QuestionPlan,
        policy_hash: str,
        manifest: BuildProvenance,
        blocks: list[TopicAnswer],
        left_out: list[LeftOut],
        followup: FollowupRecord | None,
        *,
        trace_context: TraceContext,
    ) -> Answer:
        with self._stage(StageName.render, trace_context):
            answer = await self._build_answer(
                request,
                principal,
                plan,
                policy_hash,
                manifest,
                blocks,
                left_out,
                AnswerStatus.answered,
                followup,
                trace_id=trace_context.trace_id,
            )
        local = self._local_execution(plan, principal, trace_context=trace_context)
        started = self.clock.monotonic()
        with self._stage(StageName.audit, trace_context) as span:
            if span is not None:
                span.set_outcome(StageOutcome.ok)
                span.record_latency(max(0, int((self.clock.monotonic() - started) * 1000)))
        await self.telemetry.event(
            self._audit_event(answer, principal, plan, policy_hash, manifest, "attempted"),
            execution=local,
        )
        return answer

    async def _semantic_suggestion(
        self, request: AskRequest, principal: VerifiedPrincipal, site: AuthorizedSite
    ) -> SemanticSuggestion | None:
        suggester = self.semantic_suggester
        if suggester is None or request.followup_id is not None:
            return None
        if any(
            has_deterministic_route(request.question, self.catalog, language)
            for language in ("en", "es")
        ):
            return None
        grant = await self.admissions.acquire(
            principal.owner_key,
            request.environment_id,
            "semantic",
            uuid4(),
            self.clock.now(),
        )
        question_id = uuid4()
        try:
            execution = self.runtime.create(
                question_id=question_id,
                operation="semantic",
                owner_key=principal.owner_key,
                environment_id=request.environment_id,
                admission=grant,
            )
            return await suggester.suggest(
                request.question,
                language=request.language_hint or "en",
                catalog=self.catalog,
                execution=execution,
            )
        finally:
            await self.admissions.release(grant)

    async def _build_answer(
        self,
        request: AskRequest,
        principal: VerifiedPrincipal,
        plan: QuestionPlan,
        policy_hash: str,
        manifest: BuildProvenance,
        blocks: list[TopicAnswer],
        left_out: list[LeftOut],
        status: AnswerStatus,
        followup: FollowupRecord | None,
        *,
        trace_id: str,
    ) -> Answer:
        return self._answers().answer(
            question_id=plan.question_id,
            owner_key=principal.owner_key,
            environment_id=plan.environment_id,
            language=plan.language,
            content_sha=plan.content_sha,
            cue_ids=[span.id for span in plan.provenance.matched_spans],
            topic_ids=[topic.topic_id for topic in plan.topics],
            status=status,
            manifest=manifest,
            trace_id=trace_id,
            blocks=blocks,
            left_out=left_out,
            followup=followup,
        )

    async def _unplanned_answer(
        self,
        request: AskRequest,
        principal: VerifiedPrincipal,
        policy_hash: str,
        manifest: BuildProvenance,
        *,
        status: AnswerStatus,
        message: str | None,
        clarify: Clarify | None,
        topic_ids: list[str],
        cue_ids: list[str],
        trace_context: TraceContext,
    ) -> Answer:
        async with document_slot(self._document_slots):
            return await self._unplanned_answer_impl(
                request,
                principal,
                policy_hash,
                manifest,
                status=status,
                message=message,
                clarify=clarify,
                topic_ids=topic_ids,
                cue_ids=cue_ids,
                trace_context=trace_context,
            )

    async def _unplanned_answer_impl(
        self,
        request: AskRequest,
        principal: VerifiedPrincipal,
        policy_hash: str,
        manifest: BuildProvenance,
        *,
        status: AnswerStatus,
        message: str | None,
        clarify: Clarify | None,
        topic_ids: list[str],
        cue_ids: list[str],
        trace_context: TraceContext,
    ) -> Answer:
        question_id = uuid4()
        answer = self._answers().answer(
            question_id=question_id,
            owner_key=principal.owner_key,
            environment_id=request.environment_id,
            language=request.language_hint or "en",
            content_sha=manifest.content_sha,
            cue_ids=cue_ids,
            topic_ids=topic_ids,
            status=status,
            manifest=manifest,
            trace_id=trace_context.trace_id,
            message=message,
            clarify=clarify,
        )
        local = self._local_execution_for_id(
            question_id, principal, request.environment_id, trace_context=trace_context
        )
        started = self.clock.monotonic()
        with self.telemetry.stage(StageName.audit, trace_context=trace_context) as span:
            span.set_outcome(StageOutcome.ok)
            span.record_latency(max(0, int((self.clock.monotonic() - started) * 1000)))
        event = self._answers().audit_event(
            answer,
            principal,
            manifest,
            policy_hash,
            "attempted",
            plan=None,
            cue_ids=cue_ids,
            topic_ids=topic_ids,
        )
        await self.telemetry.event(event, execution=local)
        return answer

    async def _audit(
        self,
        answer: Answer,
        principal: VerifiedPrincipal,
        plan: QuestionPlan,
        policy_hash: str,
        manifest: BuildProvenance,
        outcome: Literal["attempted", "completed", "cancelled"],
        execution: ExecutionContext,
        completion_id: UUID | None = None,
        context_uses: list[AuditContextUse] | None = None,
    ) -> AuditAck:
        started = self.clock.monotonic()
        with self.telemetry.stage(StageName.audit, trace_context=execution.trace_context) as span:
            span.set_outcome(StageOutcome.ok)
            span.record_latency(max(0, int((self.clock.monotonic() - started) * 1000)))
        return await self.telemetry.event(
            self._audit_event(
                answer,
                principal,
                plan,
                policy_hash,
                manifest,
                outcome,
                completion_id,
                context_uses=context_uses,
            ),
            execution=execution,
        )

    def _audit_event(
        self,
        answer: Answer,
        principal: VerifiedPrincipal,
        plan: QuestionPlan,
        policy_hash: str,
        manifest: BuildProvenance,
        outcome: Literal["attempted", "completed", "cancelled"],
        completion_id: UUID | None = None,
        context_uses: list[AuditContextUse] | None = None,
    ) -> AuditEvent:
        return self._answers().audit_event(
            answer,
            principal,
            manifest,
            policy_hash,
            outcome,
            plan=plan,
            cue_ids=[cue_id for topic in plan.topics for cue_id in topic.cue_ids],
            topic_ids=[topic.topic_id for topic in plan.topics],
            completion_id=completion_id,
            context_uses=context_uses,
        )

    def _local_execution(
        self,
        plan: QuestionPlan,
        principal: VerifiedPrincipal,
        *,
        trace_context: TraceContext | None = None,
    ) -> ExecutionContext:
        grant = AdmissionGrant(
            holder_id=uuid4(),
            slot_ids=("local-doc",),
            expires_at=self.clock.now() + timedelta(seconds=5),
            fence=1,
        )
        return self.runtime.create(
            question_id=plan.question_id,
            operation="ask",
            owner_key=principal.owner_key,
            environment_id=plan.environment_id,
            admission=grant,
            trace_context=trace_context,
        )

    def _local_execution_for_id(
        self,
        question_id: UUID,
        principal: VerifiedPrincipal,
        environment_id: str,
        *,
        trace_context: TraceContext | None = None,
    ) -> ExecutionContext:
        grant = AdmissionGrant(
            holder_id=uuid4(),
            slot_ids=("local-audit",),
            expires_at=self.clock.now() + timedelta(seconds=5),
            fence=1,
        )
        return self.runtime.create(
            question_id=question_id,
            operation="ask",
            owner_key=principal.owner_key,
            environment_id=environment_id,
            admission=grant,
            trace_context=trace_context,
        )

    @staticmethod
    def _active_idempotency(
        principal: VerifiedPrincipal,
        request: AskRequest,
        key: UUID | None,
        request_hash: str,
        question_id: UUID,
        now: datetime,
    ) -> IdempotencyRecord | None:
        if key is None:
            return None
        return IdempotencyRecord(
            owner_key=principal.owner_key,
            environment_id=request.environment_id,
            key=key,
            request_hash=request_hash,
            question_id=question_id,
            status="active",
            expires_at=now + timedelta(minutes=10),
        )

    def _judgment_selection_issue(self, plan: QuestionPlan) -> Clarify | ServiceFailure | None:
        if not any(topic.judgment for topic in plan.topics):
            return None
        if plan.model_id is not None and not any(item.id == plan.model_id for item in self.models):
            raise self._failure(ErrorCode.UNSUPPORTED_MODEL, "The selected model is not supported.")
        model = next((item for item in self.models if item.id == plan.model_id), None)
        effort = Effort(plan.effort) if plan.effort is not None else None
        if plan.model_id is None or (model is not None and model.efforts and effort is None):
            question = (
                "\u00bfQu\u00e9 modelo y esfuerzo debo usar?"
                if plan.language == "es"
                else "Which model and effort should I use for this question?"
            )
            return Clarify(
                kind="model_selection",
                question=question,
                slots=["model_id", "effort"],
            )
        try:
            validate_selection(model, effort)
        except CapabilityError as error:
            raise self._failure(ErrorCode.UNSUPPORTED_EFFORT, str(error)) from None
        return None

    @staticmethod
    def _has_backend_work(plan: QuestionPlan) -> bool:
        return any(topic.fetches or topic.failure or topic.judgment for topic in plan.topics)

    @staticmethod
    def _failure(code: ErrorCode, message: str) -> ServiceFailure:
        return ServiceFailure(public_error(code, message, trace_id=str(uuid4())))
