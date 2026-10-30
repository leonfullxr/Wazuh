"""Explicit composition root for REST, MCP, state, query and audit adapters."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from typing import Literal, Protocol, cast
from uuid import uuid4

import httpx
from fastapi import FastAPI
from starlette.applications import Starlette
from starlette.types import ASGIApp, Receive, Scope, Send

from ai_soc.api.app import Readiness, create_app
from ai_soc.api.csrf import CsrfTokens
from ai_soc.application.errors import ServiceFailure
from ai_soc.application.runtime import RequestRuntime
from ai_soc.application.service import ApplicationService
from ai_soc.config import ServiceConfig
from ai_soc.contracts.errors import public_error
from ai_soc.contracts.models import (
    AuthorizedSite,
    ErrorCode,
    ExecutionContext,
    JudgmentRequest,
    RawJudgment,
    VerifiedPrincipal,
)
from ai_soc.contracts.ports import (
    Clock,
    ContentCatalog,
    EmbeddingAdmissionStore,
    FeedbackSink,
    IdentityVerifier,
    JudgmentProvider,
    ModelCountAdmissionStore,
    SemanticSuggester,
    Telemetry,
)
from ai_soc.feedback.receipts import FeedbackReceiptCodec
from ai_soc.feedback.sqs import SqsClient as FeedbackSqsClient
from ai_soc.feedback.sqs import SqsFeedbackSink
from ai_soc.identity.alb import AlbAssertionVerifier, IdentityError, McpBearerVerifier
from ai_soc.identity.broker import KmsIndexerTokenBroker, KmsSigner
from ai_soc.identity.policy import MappedSitePolicy
from ai_soc.identity.verifier import RouteIdentityVerifier
from ai_soc.judgment.bedrock import ProviderFailure
from ai_soc.judgment.embeddings import AdmittedSemanticSuggester
from ai_soc.judgment.engine import JudgmentEngine
from ai_soc.mcp.server import VerifiedRequestContext, create_mcp_app
from ai_soc.planning.parser import DeterministicPlanner
from ai_soc.query.compiler import MappingProfile
from ai_soc.query.cursors import CursorCipher
from ai_soc.query.indexer import WazuhIndexer
from ai_soc.query.playbooks import DeclarativePlaybookExecutor
from ai_soc.state.admission import DynamoAdmissionStore, MemoryAdmissionStore
from ai_soc.state.dynamodb import DynamoClient, DynamoState
from ai_soc.state.feedback_control import FeedbackControlPool
from ai_soc.state.memory import MemoryState
from ai_soc.state.recovery import RecoveryRunner
from ai_soc.state.stage_admission import (
    DynamoEmbeddingAdmissionStore,
    DynamoModelCountAdmissionStore,
    DynamoReadAdmissionStore,
    MemoryEmbeddingAdmissionStore,
    MemoryModelCountAdmissionStore,
    MemoryReadAdmissionStore,
)
from ai_soc.telemetry.audit_delivery import AuditTelemetry
from ai_soc.telemetry.audit_delivery import SqsClient as AuditSqsClient
from ai_soc.telemetry.events import TelemetryAdapter
from ai_soc.telemetry.metrics import MetricExporter
from ai_soc.telemetry.tracing import SpanExporter
from ai_soc.validation.findings import FindingValidator
from ai_soc.workspace.api.runtime import WorkspaceRuntime


class TransportFactory(Protocol):
    def __call__(self, site: AuthorizedSite) -> httpx.AsyncClient: ...


class JudgmentProviderFactory(Protocol):
    def __call__(self, admission: ModelCountAdmissionStore) -> JudgmentProvider: ...


class SemanticSuggesterFactory(Protocol):
    def __call__(self, admission: EmbeddingAdmissionStore) -> AdmittedSemanticSuggester: ...


@dataclass(frozen=True, slots=True)
class _JudgmentProviderAdapter:
    provider: JudgmentProvider

    async def count(self, request: JudgmentRequest, *, execution: ExecutionContext) -> int:
        try:
            return await self.provider.count(request, execution=execution)
        except ProviderFailure as error:
            _translate_provider_failure(error, execution, "count")
            raise

    async def converse(
        self, request: JudgmentRequest, *, execution: ExecutionContext
    ) -> RawJudgment:
        try:
            return await self.provider.converse(request, execution=execution)
        except ProviderFailure as error:
            _translate_provider_failure(error, execution, "converse")
            raise


@dataclass(frozen=True, slots=True)
class _McpIdentityAdapter:
    """Translate the concrete identity verifier's finite failures at MCP's boundary."""

    identity: IdentityVerifier

    async def verify(self, *, headers: Mapping[str, str], edge: str) -> VerifiedPrincipal:
        try:
            return await self.identity.verify(headers=headers, edge=edge)
        except IdentityError as error:
            code = error.code
        except Exception:
            code = ErrorCode.AUTH_INVALID
        messages = {
            ErrorCode.AUTH_REQUIRED: "A valid bearer token is required.",
            ErrorCode.AUTH_EXPIRED: "The bearer token has expired.",
            ErrorCode.ORIGIN_DENIED: "This origin is not allowed.",
            ErrorCode.SCOPE_DENIED: "The bearer token lacks the required scope.",
            ErrorCode.AUTH_INVALID: "Authentication could not be verified.",
        }
        if code not in messages:
            code = ErrorCode.AUTH_INVALID
        raise ServiceFailure(public_error(code, messages[code], trace_id=uuid4().hex)) from None


def _translate_provider_failure(
    error: ProviderFailure, execution: ExecutionContext, stage: str
) -> None:
    if error.state == "capacity_limited":
        raise ServiceFailure(
            public_error(
                ErrorCode.CAPACITY_LIMIT,
                "The model/count stage is at capacity.",
                trace_id=execution.trace_context.trace_id,
                stage=stage,
            )
        ) from None
    if error.state == "guardrail_blocked":
        raise ServiceFailure(
            public_error(
                ErrorCode.GUARDRAIL_BLOCKED,
                "The model guardrail blocked this judgment.",
                trace_id=execution.trace_context.trace_id,
                stage=stage,
            )
        ) from None


@dataclass(frozen=True, slots=True)
class SocRuntime:
    application: ApplicationService
    rest: FastAPI
    mcp: ASGIApp
    recovery: RecoveryRunner
    identity: IdentityVerifier
    telemetry: Telemetry
    feedback_control_pool: FeedbackControlPool | None = None

    def close_feedback_control(self) -> None:
        if self.feedback_control_pool is not None:
            self.feedback_control_pool.close()


def runtime_asgi_app(runtime: SocRuntime, *, shutdown: Callable[[], Awaitable[None]]) -> ASGIApp:
    rest = runtime.rest
    mcp = runtime.mcp
    recovery = runtime.recovery
    mcp_context = cast(VerifiedRequestContext, mcp)
    context_attributes = cast(Mapping[str, object], mcp_context.__dict__)
    sdk_app = cast(Starlette, context_attributes["_app"])

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            async with rest.router.lifespan_context(rest):
                async with sdk_app.router.lifespan_context(sdk_app):
                    recovery_task = asyncio.create_task(recovery.run_forever())
                    try:
                        while True:
                            message = await receive()
                            if message["type"] == "lifespan.startup":
                                await send({"type": "lifespan.startup.complete"})
                            elif message["type"] == "lifespan.shutdown":
                                break
                    finally:
                        recovery.stop()
                        try:
                            await asyncio.wait_for(recovery_task, timeout=5.0)
                        except TimeoutError:
                            recovery_task.cancel()
                            with suppress(asyncio.CancelledError):
                                await recovery_task
                        except Exception:
                            pass
                        await shutdown()
            await send({"type": "lifespan.shutdown.complete"})
            return
        path = str(scope.get("path", ""))
        if path == "/mcp" or path.startswith("/.well-known/oauth-protected-resource"):
            await mcp(scope, receive, send)
        else:
            await rest(scope, receive, send)

    return app


@dataclass(frozen=True, slots=True)
class StageAdmissionAdapters:
    reads: DynamoReadAdmissionStore | MemoryReadAdmissionStore
    model_count: DynamoModelCountAdmissionStore | MemoryModelCountAdmissionStore
    embeddings: DynamoEmbeddingAdmissionStore | MemoryEmbeddingAdmissionStore


def compose_state_adapters(
    mode: Literal["fixture", "live"],
    *,
    client: DynamoClient | None,
    table_name: str | None,
    metrics: MetricExporter | None = None,
    clock: Clock | None = None,
    feedback_control_pool: FeedbackControlPool | None = None,
) -> tuple[DynamoState | MemoryState, DynamoAdmissionStore | MemoryAdmissionStore]:
    """Select fixture memory or paired cross-replica DynamoDB adapters explicitly."""
    if (client is None) != (table_name is None):
        raise ValueError("state client and table must be supplied together")
    if client is not None and table_name is not None:
        return (
            DynamoState(
                client,
                table_name,
                metrics=metrics,
                clock=clock,
                feedback_control_pool=feedback_control_pool,
            ),
            DynamoAdmissionStore(client, table_name, metrics=metrics),
        )
    if mode == "live":
        raise ValueError("live mode requires explicit DynamoDB state and admission")
    return MemoryState(metrics=metrics), MemoryAdmissionStore(metrics=metrics)


def compose_stage_admission_adapters(
    mode: Literal["fixture", "live"],
    *,
    client: DynamoClient | None,
    table_name: str | None,
) -> StageAdmissionAdapters:
    """Select the fixed-slot physical-stage stores from the same explicit state backend."""
    if (client is None) != (table_name is None):
        raise ValueError("stage admission client and table must be supplied together")
    if client is not None and table_name is not None:
        return StageAdmissionAdapters(
            reads=DynamoReadAdmissionStore(client, table_name),
            model_count=DynamoModelCountAdmissionStore(client, table_name),
            embeddings=DynamoEmbeddingAdmissionStore(client, table_name),
        )
    if mode == "live":
        raise ValueError("live mode requires explicit DynamoDB stage admission")
    return StageAdmissionAdapters(
        reads=MemoryReadAdmissionStore(),
        model_count=MemoryModelCountAdmissionStore(),
        embeddings=MemoryEmbeddingAdmissionStore(),
    )


def compose_soc(
    config: ServiceConfig,
    *,
    clock: Clock,
    catalog: ContentCatalog,
    state_client: DynamoClient | None,
    state_table: str | None,
    kms: KmsSigner,
    indexer_key_ids: Mapping[str, str],
    transport_for: TransportFactory,
    mapping_profiles: Mapping[str, MappingProfile],
    cursor_cipher: CursorCipher | None,
    judgment_provider: JudgmentProvider | None = None,
    audit_client: AuditSqsClient,
    audit_queue_url: str,
    feedback_client: FeedbackSqsClient,
    feedback_queue_url: str,
    span_exporter: SpanExporter,
    metric_exporter: MetricExporter,
    receipt_keys: dict[str, bytes],
    current_receipt_key: str,
    csrf_secret: bytes,
    browser_origin: str,
    alb_verifier: AlbAssertionVerifier,
    mcp_verifier: McpBearerVerifier,
    readiness: Readiness,
    standing_rules: str,
    mcp_issuer_url: str,
    mcp_resource_url: str,
    semantic_suggester: SemanticSuggester | None = None,
    judgment_provider_factory: JudgmentProviderFactory | None = None,
    semantic_suggester_factory: SemanticSuggesterFactory | None = None,
    workspace_dsn_provider: Callable[[], str] | None = None,
    workspace_cursor_secret: bytes | None = None,
) -> SocRuntime:
    """Build all shared request adapters without ambient env, home or credential reads."""
    if not config.sites or not config.models:
        raise ValueError("SOC composition requires explicit site and model registries")
    stage_admissions = compose_stage_admission_adapters(
        config.mode, client=state_client, table_name=state_table
    )
    if (judgment_provider is None) == (judgment_provider_factory is None):
        raise ValueError("supply exactly one judgment provider or factory")
    if semantic_suggester is not None and semantic_suggester_factory is not None:
        raise ValueError("supply a semantic suggester or factory, not both")
    if (workspace_dsn_provider is None) != (workspace_cursor_secret is None):
        raise ValueError("workspace API DSN provider and cursor secret must be supplied together")
    if config.mode == "live" and judgment_provider_factory is None:
        raise ValueError("live composition requires a model/count admission provider factory")
    if config.mode == "live" and semantic_suggester is not None:
        raise ValueError("live semantic suggestion requires an embedding admission factory")
    provider = (
        judgment_provider_factory(stage_admissions.model_count)
        if judgment_provider_factory is not None
        else judgment_provider
    )
    if provider is None:
        raise ValueError("judgment provider composition is incomplete")
    if semantic_suggester_factory is not None:
        semantic_suggester = semantic_suggester_factory(stage_admissions.embeddings)
    provider_adapter = _JudgmentProviderAdapter(provider)
    if any(site.mapping_profile not in mapping_profiles for site in config.sites if site.enabled):
        raise ValueError("every enabled site requires a pinned mapping profile")

    feedback_control_pool = FeedbackControlPool() if state_client is not None else None
    try:
        state, admissions = compose_state_adapters(
            config.mode,
            client=state_client,
            table_name=state_table,
            metrics=metric_exporter,
            clock=clock,
            feedback_control_pool=feedback_control_pool,
        )

        kev_pack_sha256 = (
            catalog.manifest().pack_sha256
            if getattr(catalog, "kev_snapshot", None) is not None
            else None
        )
        policy = MappedSitePolicy(
            config.sites,
            now=clock.now,
            kev_pack_sha256=kev_pack_sha256,
        )
        workspace_runtime = (
            WorkspaceRuntime(
                workspace_dsn_provider,
                policy,
                workspace_cursor_secret,
                clock.now,
            )
            if workspace_dsn_provider is not None and workspace_cursor_secret is not None
            else None
        )
        identity = RouteIdentityVerifier(alb_verifier, mcp_verifier)
        token_broker = KmsIndexerTokenBroker(kms, key_ids=indexer_key_ids, now=clock.now)
        telemetry = TelemetryAdapter(
            audit=AuditTelemetry(audit_client, queue_url=audit_queue_url, clock=clock),
            spans=span_exporter,
            metrics=metric_exporter,
        )
        fetches = WazuhIndexer(
            token_broker,
            stage_admissions.reads,
            transport_for,
            profiles=dict(mapping_profiles),
            clock=clock.now,
            content_sha=catalog.manifest().content_sha,
            cursor_cipher=cursor_cipher,
            response_bytes=config.bounds.backend_decoded_bytes,
            fetch_bytes=config.bounds.fetch_bytes,
            telemetry=telemetry,
            metrics=metric_exporter,
        )
        playbooks = DeclarativePlaybookExecutor(
            catalog, fetches, clock, content_sha=catalog.manifest().content_sha
        )
        feedback_sink: FeedbackSink = SqsFeedbackSink(feedback_client, feedback_queue_url)
        application = ApplicationService(
            clock=clock,
            catalog=catalog,
            planner=DeterministicPlanner(catalog),
            site_policy=policy,
            plans=state,
            admissions=admissions,
            question_admission=state,
            leases=state,
            budgets=state,
            completions=state,
            fetches=fetches,
            playbooks=playbooks,
            judgment_engine=JudgmentEngine(
                standing_rules=standing_rules,
                guardrail_identifier=config.guardrail_identifier,
                guardrail_version=config.guardrail_version,
                playbook=catalog.playbook,
            ),
            judgment_provider=provider_adapter,
            finding_validator=FindingValidator(),
            telemetry=telemetry,
            feedback_sink=feedback_sink,
            feedback_store=state,
            receipts=FeedbackReceiptCodec(receipt_keys, current_receipt_key),
            runtime=RequestRuntime(clock),
            models=config.models,
            mode=config.mode,
            owner_daily_token_limit=config.bounds.owner_daily_token_limit,
            service_daily_token_limit=config.bounds.service_daily_token_limit,
            guardrail_identifier=config.guardrail_identifier,
            guardrail_version=config.guardrail_version,
            semantic_suggester=semantic_suggester,
            kev_activation_at=clock.now(),
            cursor_cipher=cursor_cipher,
        )
        browser = create_app(
            application,
            identity,
            CsrfTokens(csrf_secret, origin=browser_origin),
            clock,
            readiness,
            workspace_runtime=workspace_runtime,
        )
        mcp = create_mcp_app(
            application,
            _McpIdentityAdapter(identity),
            issuer_url=mcp_issuer_url,
            resource_url=mcp_resource_url,
        )
        recovery = RecoveryRunner(state, clock)
        return SocRuntime(
            application=application,
            rest=browser,
            mcp=mcp,
            recovery=recovery,
            identity=identity,
            telemetry=telemetry,
            feedback_control_pool=feedback_control_pool,
        )
    except BaseException:
        if feedback_control_pool is not None:
            feedback_control_pool.close()
        raise
