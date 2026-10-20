"""Frozen component seams. Implementations belong to the assigned consumer bundles."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from datetime import datetime
from typing import Literal, Protocol
from uuid import UUID

from .models import (
    SHA256,
    AdmissionGrant,
    AskRequest,
    AuditAck,
    AuditEvent,
    AuthorizedSite,
    BuildProvenance,
    CompletionCommand,
    CompletionReceipt,
    ContentId,
    CueCatalog,
    DomainError,
    Effort,
    EmbeddingGrant,
    ErrorCode,
    EvidencePack,
    ExecutionContext,
    ExpectationDefinition,
    FeedbackControlContext,
    FeedbackEvent,
    FeedbackMetadata,
    FetchResult,
    FetchSpec,
    FindingTemplate,
    FollowupRecord,
    GitSHA40,
    IndexerCredential,
    JudgmentPreparation,
    JudgmentRequest,
    JudgmentResult,
    Lease,
    ModelCapability,
    ModelCountGrant,
    PlanningResult,
    PlaybookDefinition,
    PlaybookRun,
    PolicyHash,
    RawJudgment,
    ReadOperationGrant,
    RecoveryPage,
    Reservation,
    SemanticSuggestion,
    SiteConfig,
    StageCapacityRejection,
    StageName,
    StageSpan,
    TopicDefinition,
    TopicPlan,
    TopicPromptPack,
    TraceContext,
    ValidationContext,
    VerifiedPrincipal,
)


class Clock(Protocol):
    def now(self) -> datetime: ...
    def monotonic(self) -> float: ...


class ContentCatalog(Protocol):
    def manifest(self) -> BuildProvenance: ...
    def topics(self) -> tuple[TopicDefinition, ...]: ...
    def topic(self, topic_id: str) -> TopicDefinition | None: ...
    def cues(self) -> CueCatalog: ...
    def topic_context(self, topic_id: str, *, language: str) -> TopicPromptPack: ...
    def expectation(
        self, expectation_id: str, *, topic_id: str
    ) -> ExpectationDefinition | None: ...
    def playbook(self, playbook_id: str) -> PlaybookDefinition | None: ...
    def finding_templates(self, topic_id: str) -> tuple[FindingTemplate, ...]: ...


class Planner(Protocol):
    def plan(
        self,
        request: AskRequest,
        principal: VerifiedPrincipal,
        previous: FollowupRecord | None,
        *,
        policy_hash: PolicyHash,
        clock: Clock,
    ) -> PlanningResult: ...


class IdentityVerifier(Protocol):
    async def verify(self, *, headers: Mapping[str, str], edge: str) -> VerifiedPrincipal: ...


class SitePolicy(Protocol):
    def authorized_sites(self, principal: VerifiedPrincipal) -> tuple[SiteConfig, ...]: ...
    def authorize(self, principal: VerifiedPrincipal, environment_id: str) -> AuthorizedSite: ...


class IndexerTokenBroker(Protocol):
    async def issue(
        self, principal: VerifiedPrincipal, site: AuthorizedSite, *, execution: ExecutionContext
    ) -> IndexerCredential: ...


class FetchExecutor(Protocol):
    async def execute(
        self,
        fetch: FetchSpec,
        *,
        topic_id: str,
        question_id: UUID,
        principal: VerifiedPrincipal,
        site: AuthorizedSite,
        execution: ExecutionContext,
    ) -> FetchResult: ...

    async def page(
        self,
        cursor: str,
        *,
        principal: VerifiedPrincipal,
        site: AuthorizedSite,
        execution: ExecutionContext,
    ) -> FetchResult: ...


class PlaybookExecutor(Protocol):
    async def run(
        self,
        plan: TopicPlan,
        *,
        principal: VerifiedPrincipal,
        site: AuthorizedSite,
        question_id: UUID,
        execution: ExecutionContext,
    ) -> PlaybookRun: ...


class PlanStore(Protocol):
    async def load(
        self,
        followup_id: UUID,
        *,
        owner_key: SHA256,
        environment_id: ContentId,
        revision: int,
        policy_hash: PolicyHash,
        content_sha: GitSHA40,
        now: datetime,
    ) -> FollowupRecord: ...


class LeaseStore(Protocol):
    async def acquire(
        self,
        *,
        owner_key: str,
        environment_id: str,
        question_id: UUID,
        holder_id: UUID,
        now: datetime,
    ) -> Lease: ...
    async def renew(self, lease: Lease, *, now: datetime) -> Lease: ...
    async def release(self, lease: Lease) -> None: ...


class BudgetStore(Protocol):
    async def open(
        self,
        *,
        question_id: UUID,
        owner_key: str,
        environment_id: str,
        token_limit: int,
        expires_at: datetime,
        lease: Lease,
        operation_id: UUID,
        lease_supplier: Callable[[], Lease] | None = None,
    ) -> None: ...
    async def daily_judgment_blocked(
        self,
        *,
        owner_key: str,
        now: datetime,
        owner_daily_limit: int,
        service_daily_limit: int,
    ) -> bool: ...
    async def daily_cannot_reserve(
        self,
        *,
        owner_key: str,
        tokens: int,
        now: datetime,
        owner_daily_limit: int,
        service_daily_limit: int,
    ) -> bool: ...
    async def question_budget_remaining(self, question_id: UUID) -> int | None: ...
    async def reserve(
        self,
        *,
        question_id: UUID,
        topic_id: str,
        tokens: int,
        lease: Lease,
        operation_id: UUID,
        now: datetime,
        owner_daily_limit: int,
        service_daily_limit: int,
        lease_supplier: Callable[[], Lease] | None = None,
    ) -> Reservation: ...
    async def mark_started(
        self,
        reservation: Reservation,
        *,
        lease: Lease,
        operation_id: UUID,
        now: datetime,
        lease_supplier: Callable[[], Lease] | None = None,
    ) -> Reservation: ...
    async def settle(
        self,
        reservation: Reservation,
        *,
        charged_tokens: int | None,
        lease: Lease,
        operation_id: UUID,
        now: datetime,
        release: bool = False,
        lease_supplier: Callable[[], Lease] | None = None,
    ) -> None: ...


class JudgmentProvider(Protocol):
    async def count(self, request: JudgmentRequest, *, execution: ExecutionContext) -> int: ...
    async def converse(
        self, request: JudgmentRequest, *, execution: ExecutionContext
    ) -> RawJudgment: ...


class JudgmentEngine(Protocol):
    def prepare(
        self,
        plan: TopicPlan,
        pack: EvidencePack,
        *,
        context: ValidationContext,
        model: ModelCapability | None,
        effort: Effort | None,
    ) -> JudgmentPreparation: ...


class FindingValidator(Protocol):
    def validate(
        self, raw: RawJudgment, pack: EvidencePack, *, context: ValidationContext
    ) -> JudgmentResult: ...


class EmbeddingProvider(Protocol):
    async def embed(
        self,
        texts: tuple[str, ...],
        *,
        purpose: str,
        execution: ExecutionContext,
    ) -> tuple[tuple[float, ...], ...]: ...


class SemanticSuggester(Protocol):
    async def suggest(
        self,
        question: str,
        *,
        language: str,
        catalog: ContentCatalog,
        execution: ExecutionContext,
    ) -> SemanticSuggestion | None: ...


class FeedbackSink(Protocol):
    async def enqueue(self, event: FeedbackEvent, *, execution: ExecutionContext) -> UUID: ...


class FeedbackStore(Protocol):
    async def read_feedback(
        self,
        *,
        receipt_id: UUID,
        note_hash: SHA256,
        now: datetime,
        control: FeedbackControlContext,
    ) -> FeedbackMetadata | None: ...

    async def try_create_feedback(
        self,
        *,
        receipt_id: UUID,
        note_hash: SHA256,
        now: datetime,
        control: FeedbackControlContext,
    ) -> FeedbackMetadata | None: ...

    async def mark_feedback_queued(
        self,
        *,
        receipt_id: UUID,
        note_hash: SHA256,
        feedback_id: UUID,
        now: datetime,
        control: FeedbackControlContext,
    ) -> bool: ...


class Telemetry(Protocol):
    async def event(self, event: AuditEvent, *, execution: ExecutionContext) -> AuditAck: ...
    def stage(
        self, name: StageName, *, trace_context: TraceContext
    ) -> AbstractContextManager[StageSpan]: ...


class CompletionStore(Protocol):
    async def commit(
        self,
        command: CompletionCommand,
        *,
        lease: Lease,
        now: datetime,
        operation_id: UUID,
        lease_supplier: Callable[[], Lease] | None = None,
    ) -> CompletionReceipt: ...


class AdmissionStore(Protocol):
    async def acquire(
        self,
        owner_key: str,
        environment_id: str,
        operation: str,
        question_id: UUID,
        now: datetime,
    ) -> AdmissionGrant: ...
    async def renew(self, grant: AdmissionGrant, now: datetime) -> AdmissionGrant: ...
    async def release(self, grant: AdmissionGrant) -> None: ...


class ReadAdmissionStore(Protocol):
    async def acquire(
        self,
        *,
        environment_id: ContentId,
        question_id: UUID,
        operation_id: UUID,
        call: Literal["mapping", "validate", "pit", "search", "probe"],
        now: datetime,
    ) -> ReadOperationGrant | StageCapacityRejection: ...
    async def release(self, grant: ReadOperationGrant) -> None: ...


class ModelCountAdmissionStore(Protocol):
    async def acquire(
        self,
        *,
        environment_id: ContentId,
        question_id: UUID,
        operation_id: UUID,
        call: Literal["count", "converse"],
        now: datetime,
    ) -> ModelCountGrant | StageCapacityRejection: ...
    async def release(self, grant: ModelCountGrant) -> None: ...


class EmbeddingAdmissionStore(Protocol):
    async def acquire(
        self,
        *,
        environment_id: ContentId,
        question_id: UUID,
        operation_id: UUID,
        now: datetime,
    ) -> EmbeddingGrant | StageCapacityRejection: ...
    async def release(self, grant: EmbeddingGrant) -> None: ...


class RecoveryStore(Protocol):
    async def reconcile(
        self,
        *,
        now: datetime,
        bucket: int,
        after: str | None,
        page_size: int = 100,
    ) -> RecoveryPage: ...


class CompletionFence(Protocol):
    def accepts(self, lease: Lease, *, now: datetime, operation_id: UUID) -> bool: ...


class ErrorMapper(Protocol):
    def public_error(self, error: DomainError) -> tuple[int, DomainError]: ...
    def code_for_status(self, status: int) -> ErrorCode: ...


__all__ = [
    "AdmissionStore",
    "BudgetStore",
    "Clock",
    "CompletionFence",
    "CompletionStore",
    "ContentCatalog",
    "ErrorMapper",
    "FetchExecutor",
    "FindingValidator",
    "FeedbackSink",
    "EmbeddingAdmissionStore",
    "ModelCountAdmissionStore",
    "ReadAdmissionStore",
    "IdentityVerifier",
    "IndexerTokenBroker",
    "JudgmentEngine",
    "JudgmentProvider",
    "LeaseStore",
    "PlanStore",
    "Planner",
    "PlaybookExecutor",
    "RecoveryStore",
    "SemanticSuggester",
    "SitePolicy",
    "Telemetry",
]
