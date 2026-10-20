from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Literal, cast
from uuid import UUID, uuid4

import httpx
import pytest
from botocore.exceptions import ClientError
from pydantic import TypeAdapter
from starlette.applications import Starlette

from ai_soc.api.app import CSRF_COOKIE, create_app
from ai_soc.api.csrf import CsrfTokens
from ai_soc.application.composition import compose_soc
from ai_soc.application.errors import ServiceFailure
from ai_soc.application.service import ApplicationService
from ai_soc.config import ServiceConfig
from ai_soc.content.catalog import ContentCatalog
from ai_soc.contracts.models import (
    Answer,
    AnswerStatus,
    AskRequest,
    AuditAck,
    AuthorizedSite,
    BuildProvenance,
    CompletionCommand,
    Count,
    CueCatalog,
    DocumentDefinition,
    DomainError,
    Effort,
    ErrorCode,
    EvidenceItem,
    EvidenceRow,
    EvidenceSourceRow,
    ExecutionContext,
    FeedbackEvent,
    FeedbackRequest,
    FetchBinding,
    FetchResult,
    FetchScope,
    FetchSpec,
    FetchState,
    FieldId,
    FindingTemplate,
    FollowupRecord,
    HTTPSUrl,
    IndexFamily,
    JudgmentRequest,
    JudgmentResult,
    JudgmentState,
    Lease,
    LeftOut,
    LocaleText,
    ModelCapability,
    Planned,
    PlanProvenance,
    QuestionPlan,
    RawJudgment,
    Refused,
    ResolvedWindow,
    SemanticSuggestion,
    SiteConfig,
    SnapshotKind,
    SnapshotRef,
    TemplateId,
    TokenUsage,
    TopicAnswer,
    TopicDefinition,
    TopicPlan,
    TopicPromptPack,
    VerifiedPrincipal,
    Visibility,
)
from ai_soc.contracts.ports import (
    Clock,
    FeedbackSink,
    FetchExecutor,
    JudgmentProvider,
    Planner,
)
from ai_soc.contracts.ports import ContentCatalog as ContentCatalogPort
from ai_soc.feedback.sqs import SqsClient as FeedbackSqsClient
from ai_soc.feedback.sqs import SqsFeedbackSink
from ai_soc.identity.alb import AlbAssertionVerifier, McpBearerVerifier
from ai_soc.judgment.embeddings import AdmittedSemanticSuggester
from ai_soc.mcp.server import VerifiedRequestContext, create_mcp_app
from ai_soc.query.compiler import default_profile
from ai_soc.state.errors import StateFailure
from ai_soc.state.memory import MemoryState
from ai_soc.telemetry.audit_delivery import FeedbackArchiveConsumer
from ai_soc.telemetry.audit_delivery import SqsClient as AuditSqsClient
from ai_soc.telemetry.metrics import FixtureMetricExporter
from ai_soc.telemetry.tracing import FixtureSpanExporter

NOW = datetime(2026, 10, 3, 12, tzinfo=UTC)
FIXTURE = Path(__file__).parent / "data" / "arch_001_completion_cases.json"
FIXTURE_BYTES = FIXTURE.read_bytes()
FIXTURE_SHA256 = "212d735dad68716bc65b3f6675c44f10059f1e2d226c63d2f874be77938214ed"
G035_FIXTURE = Path(__file__).parent / "data" / "g035_mixed_access_app_cases.json"
G035_FIXTURE_BYTES = G035_FIXTURE.read_bytes()
G035_FIXTURE_SHA256 = "2f2cd95f44fff63bc2b75273ea77970676b1059fa092ce038c6dda4ebf203bda"
G035_NEGATIVE_FIXTURE = Path(__file__).parent / "data" / "g035_mixed_access_negative_app_case.json"
G035_NEGATIVE_FIXTURE_BYTES = G035_NEGATIVE_FIXTURE.read_bytes()
G035_NEGATIVE_FIXTURE_SHA256 = "2bbcce182dd41d4f93e968842e48e4016869f7ee90e64cbc9411752d2efd7129"
FOLLOWUP_FIXTURE = Path(__file__).parent / "data" / "followup_application_cases.json"
FOLLOWUP_FIXTURE_BYTES = FOLLOWUP_FIXTURE.read_bytes()
FOLLOWUP_FIXTURE_SHA256 = "4bff6231cac258c03415d74d0bfab077e13fce3a5170ffa90a35092df16b3131"
G052_FIXTURE = Path(__file__).parent / "data" / "g052_application_budget_case.json"
G052_FIXTURE_BYTES = G052_FIXTURE.read_bytes()
G052_FIXTURE_SHA256 = "4bc6167e332a445f2cc6615bfd2b4fc1d77fbe6276cd700e865a429d6b3e0b47"
G053_TOKEN_FIXTURE = Path(__file__).parent / "data" / "g053_provider_token_cases.json"
G053_TOKEN_FIXTURE_BYTES = G053_TOKEN_FIXTURE.read_bytes()
G053_TOKEN_FIXTURE_SHA256 = "21598a271610d1986d7a575aad0ebf96289e19c9bbb57dc5b7a46c518a386e19"
GP2_APP_FIXTURE = Path(__file__).parent / "data" / "feedback_application_cases.json"
GP2_APP_FIXTURE_BYTES = GP2_APP_FIXTURE.read_bytes()
GP2_APP_FIXTURE_SHA256 = "3714a45e552cca66d4712f78b75c869b018ed352e898b6ef251bdd87743a8cf6"


class _Clock:
    def now(self) -> datetime:
        return NOW

    def monotonic(self) -> float:
        return 0.0


class _ControlledClock(_Clock):
    def __init__(self) -> None:
        self.current = NOW

    def now(self) -> datetime:
        return self.current


class _Readiness:
    def ready(self) -> bool:
        return True


class _Kms:
    def sign(self, **kwargs: object) -> dict[str, object]:
        return {}


class _Sqs:
    def send_message(self, *, QueueUrl: str, MessageBody: str) -> dict[str, object]:
        return {"MessageId": "fixture-message"}


class _FeedbackSqs:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls = 0
        self.params: dict[str, object] = {}
        self.bodies: list[str] = []

    def send_message(self, **kwargs: object) -> dict[str, object]:
        self.calls += 1
        self.params = kwargs
        self.bodies.append(cast(str, kwargs["MessageBody"]))
        if self.fail:
            raise OSError("private feedback queue detail")
        return {"MessageId": "fixture-feedback-message"}


class _FeedbackArchiveQueue:
    def __init__(self) -> None:
        self.deleted: list[str] = []

    def receive_message(
        self,
        *,
        QueueUrl: str,
        MaxNumberOfMessages: int,
        WaitTimeSeconds: int,
        VisibilityTimeout: int,
    ) -> dict[str, object]:
        return {"Messages": []}

    def delete_message(self, *, QueueUrl: str, ReceiptHandle: str) -> object:
        self.deleted.append(ReceiptHandle)
        return None


class _FeedbackArchiveObjects:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def put_object(
        self, *, Bucket: str, Key: str, Body: bytes, ContentType: str, IfNoneMatch: str
    ) -> dict[str, object]:
        key = Key
        if key in self.objects:
            raise ClientError({"Error": {"Code": "PreconditionFailed"}}, "PutObject")
        self.objects[key] = Body
        return {}


class _LazyProvider:
    async def count(self, request: JudgmentRequest, *, execution: ExecutionContext) -> int:
        raise AssertionError("test plan does not call count")

    async def converse(
        self, request: JudgmentRequest, *, execution: ExecutionContext
    ) -> RawJudgment:
        raise AssertionError("test plan does not call Converse")


class _LazySuggester:
    async def suggest(
        self,
        question: str,
        *,
        language: str,
        catalog: ContentCatalogPort,
        execution: ExecutionContext,
    ) -> SemanticSuggestion | None:
        raise AssertionError("deterministic topic plan must not request semantic fallback")


class _Planner:
    def __init__(self, plan: QuestionPlan) -> None:
        self.plan_result = Planned(plan=plan)

    def plan(
        self,
        request: AskRequest,
        principal: VerifiedPrincipal,
        previous: FollowupRecord | None,
        *,
        policy_hash: str,
        clock: Clock,
    ) -> Planned:
        assert previous is None
        assert request.environment_id == self.plan_result.plan.environment_id
        assert principal.owner_key == self.plan_result.plan.owner_key
        assert policy_hash == self.plan_result.plan.policy_hash
        return self.plan_result


class _FollowupPlanner:
    def __init__(
        self,
        planned: QuestionPlan,
        *,
        previous: FollowupRecord,
        continue_topic_ids: list[str] | None,
        result: Planned | Refused | None = None,
    ) -> None:
        self.planned = planned
        self.previous = previous
        self.continue_topic_ids = continue_topic_ids
        self.result = result or Planned(plan=planned)

    def plan(
        self,
        request: AskRequest,
        principal: VerifiedPrincipal,
        previous: FollowupRecord | None,
        *,
        policy_hash: str,
        clock: Clock,
    ) -> Planned | Refused:
        assert previous == self.previous
        assert request.continue_topic_ids == self.continue_topic_ids
        assert principal.owner_key == self.planned.owner_key
        assert policy_hash == self.planned.policy_hash
        return self.result


def _site() -> SiteConfig:
    return SiteConfig(
        environment_id="alpha",
        label="Alpha",
        enabled=True,
        indexer_origin="https://alpha.private.example.test",
        private_network_ref="fixture-alpha",
        jwt_issuer="soc-alpha",
        jwt_audience="wazuh-alpha",
        kms_signing_key_arn="arn:aws:kms:us-east-1:123456789012:key/alpha",
        ca_secret_arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:alpha",
        ca_secret_version="fixture-version",
        ca_sha256="a" * 64,
        group_role_map={"soc": ("analyst",)},
        role_visibility={"analyst": Visibility.full},
        allowed_index_patterns={IndexFamily.alerts: ("wazuh-alerts-alpha-*",)},
        mapping_profile="wazuh-v4-fixture",
        policy_version="policy-1",
        pit_supported=True,
        allowed_templates=(TemplateId.alerts_rows_v1,),
        dls_attestation_version="dls-1",
        composite_role_visibility={"analyst": Visibility.full},
    )


def _model() -> ModelCapability:
    return ModelCapability(
        id="fixture-model",
        label="Fixture model",
        region="us-east-1",
        resource_arns=("arn:aws:bedrock:us-east-1:123456789012:inference-profile/fixture",),
        context_tokens=8192,
        max_output_tokens=1024,
        count_tokens_model_id="fixture-count-model",
        efforts=(Effort.low,),
        effort_transport="additionalModelRequestFields",
        effort_parameters={Effort.low: {}},
        output_strategy="strict_json_messages",
        count_strategy="count_tokens_converse",
        count_contract_sha256="b" * 64,
        cache_min_tokens=0,
        cache_max_checkpoints=0,
        cache_ttl="5m",
        validated_at=NOW,
        primary_doc_url=TypeAdapter(HTTPSUrl).validate_python("https://docs.example.test/model"),
    )


def _provenance() -> BuildProvenance:
    return BuildProvenance(
        service_sha="a" * 40,
        content_repository="https://example.test/soc-content",
        content_sha="b" * 40,
        pack_sha256="c" * 64,
        image_digest="sha256:" + "d" * 64,
        docs_origin="https://docs.example.test",
        docs_manifest_sha256="e" * 64,
    )


def _runtime(clock: Clock | None = None):
    site = _site()
    config = ServiceConfig(
        mode="fixture",
        guardrail_identifier="fixture-guardrail",
        guardrail_version="1",
        sites=(site,),
        models=(_model(),),
    )
    provenance = _provenance()
    catalog = ContentCatalog(
        provenance,
        CueCatalog(version="1", sha256="f" * 64, cues=[], aliases=[], ambiguities=[]),
        (),
        (),
    )
    active_clock = clock or _Clock()
    alb = AlbAssertionVerifier(
        region="us-east-1",
        signer_arn="arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/soc/fixture",
        issuer="https://issuer.example.test",
        client_id="soc-client",
        groups_claim="groups",
        key_resolver=lambda _key_id: "fixture-key",
        now=active_clock.now,
    )
    mcp = McpBearerVerifier(
        issuer="https://issuer.example.test",
        resource="https://soc.example.test/mcp",
        jwks_uri="https://issuer.example.test/.well-known/jwks.json",
        key_resolver=lambda _key_id: "fixture-key",
        now=active_clock.now,
        allowed_origins=frozenset({"https://soc.example.test"}),
    )
    sqs = cast(AuditSqsClient, _Sqs())
    feedback_sqs = cast(FeedbackSqsClient, _Sqs())
    return compose_soc(
        config,
        clock=active_clock,
        catalog=catalog,
        state_client=None,
        state_table=None,
        kms=_Kms(),
        indexer_key_ids={"alpha": "fixture-key"},
        transport_for=lambda _site: httpx.AsyncClient(),
        mapping_profiles={"wazuh-v4-fixture": default_profile()},
        cursor_cipher=None,
        judgment_provider_factory=lambda _admission: _LazyProvider(),
        audit_client=sqs,
        audit_queue_url="https://sqs.us-east-1.amazonaws.com/123456789012/audit",
        feedback_client=feedback_sqs,
        feedback_queue_url="https://sqs.us-east-1.amazonaws.com/123456789012/feedback",
        span_exporter=FixtureSpanExporter(),
        metric_exporter=FixtureMetricExporter(),
        receipt_keys={"fixture": b"k" * 32},
        current_receipt_key="fixture",
        csrf_secret=b"s" * 32,
        browser_origin="https://soc.example.test",
        alb_verifier=alb,
        mcp_verifier=mcp,
        readiness=_Readiness(),
        standing_rules="fixture standing rules",
        mcp_issuer_url="https://issuer.example.test",
        mcp_resource_url="https://soc.example.test/mcp",
        semantic_suggester_factory=lambda admission: AdmittedSemanticSuggester(
            _LazySuggester(), admission_store=admission
        ),
    )


def _plan(
    stage: Literal["fetch", "document", "model"], *, owner: str, question_id: UUID, policy_hash: str
) -> QuestionPlan:
    window = ResolvedWindow(
        start=NOW - timedelta(hours=1),
        end=NOW,
        semantics="absolute",
        source_text="fixture interval",
        timezone="UTC",
        anchor_at=NOW,
    )
    fetches = [
        FetchSpec(
            fetch_id="alerts",
            template_id=TemplateId.alerts_rows_v1,
            window=window,
            filters=[],
        )
    ]
    topic = TopicPlan(
        topic_id="ldap",
        ordinal=0,
        document=stage == "document",
        failure=False,
        judgment=stage == "model",
        fetches=fetches,
        cue_ids=[],
        alias_ids=[],
    )
    return QuestionPlan(
        question_id=question_id,
        environment_id="alpha",
        owner_key=owner,
        content_sha=_provenance().content_sha,
        policy_hash=policy_hash,
        language="en",
        timezone="UTC",
        anchor_at=NOW,
        topics=[topic],
        model_id="fixture-model" if stage == "model" else None,
        effort=Effort.low if stage == "model" else None,
        provenance=PlanProvenance(
            cue_pack_sha="f" * 64,
            normalized_question_hash="1" * 64,
            origin="new",
            matched_spans=[],
        ),
    )


def _principal(owner: str) -> VerifiedPrincipal:
    return VerifiedPrincipal(
        issuer="https://issuer.example.test",
        sub="fixture-analyst",
        owner_key=owner,
        groups=("soc",),
        edge="fixture",
        authenticated_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        assertion_hash="9" * 64,
    )


class _MixedFetches:
    def __init__(self, by_topic: dict[str, FetchResult]) -> None:
        self.by_topic = by_topic
        self.calls: list[str] = []
        self.requests: list[tuple[str, FetchSpec]] = []

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
        assert fetch.fetch_id == "alerts"
        assert question_id == execution.question_id
        assert principal.owner_key
        assert site.config.environment_id == "alpha"
        self.calls.append(topic_id)
        self.requests.append((topic_id, fetch))
        return self.by_topic[topic_id]

    async def page(
        self,
        cursor: str,
        *,
        principal: VerifiedPrincipal,
        site: AuthorizedSite,
        execution: ExecutionContext,
    ) -> FetchResult:
        raise AssertionError("mixed access ask does not page")


class _PausedFetches(_MixedFetches):
    def __init__(self, by_topic: dict[str, FetchResult]) -> None:
        super().__init__(by_topic)
        self.entered = asyncio.Event()
        self.resume = asyncio.Event()

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
        result = await super().execute(
            fetch,
            topic_id=topic_id,
            question_id=question_id,
            principal=principal,
            site=site,
            execution=execution,
        )
        self.entered.set()
        await self.resume.wait()
        return result


class _PausedCountProvider:
    def __init__(self) -> None:
        self.entered = asyncio.Event()
        self.resume = asyncio.Event()

    async def count(self, request: JudgmentRequest, *, execution: ExecutionContext) -> int:
        self.entered.set()
        await self.resume.wait()
        return 8

    async def converse(
        self, request: JudgmentRequest, *, execution: ExecutionContext
    ) -> RawJudgment:
        raise AssertionError("a reclaimed lease must fence model invocation")


class _FixedCountProvider:
    def __init__(self, count: int, *, fail_count: bool = False) -> None:
        self.counted_tokens = count
        self.fail_count = fail_count
        self.count_requests: list[JudgmentRequest] = []
        self.converse_requests: list[JudgmentRequest] = []

    async def count(self, request: JudgmentRequest, *, execution: ExecutionContext) -> int:
        self.count_requests.append(request)
        if self.fail_count:
            raise OSError("fixture CountTokens transport failure")
        return self.counted_tokens

    async def converse(
        self, request: JudgmentRequest, *, execution: ExecutionContext
    ) -> RawJudgment:
        self.converse_requests.append(request)
        if request.reservation_id is None:
            raise AssertionError("Converse requires a durable token reservation")
        return RawJudgment(
            text='{"schema_version":"1","findings":[]}',
            stop_reason="end_turn",
            guardrail_intervened=False,
            usage=TokenUsage(
                topic_id=request.topic_id,
                input_tokens=self.counted_tokens,
                output_tokens=4,
                cache_read_input_tokens=0,
                cache_write_input_tokens=0,
                total_input_tokens=self.counted_tokens,
                reserved_tokens=request.reserved_tokens,
                reservation_id=request.reservation_id,
            ),
            provider_request_id="fixture-budget-judgment",
        )


class _AllowedTopicProvider:
    def __init__(self, *, raw_text: str | None = None, failure_detail: str | None = None) -> None:
        self.count_requests: list[JudgmentRequest] = []
        self.converse_requests: list[JudgmentRequest] = []
        self.raw_text = raw_text
        self.failure_detail = failure_detail

    async def count(self, request: JudgmentRequest, *, execution: ExecutionContext) -> int:
        self.count_requests.append(request)
        return 8

    async def converse(
        self, request: JudgmentRequest, *, execution: ExecutionContext
    ) -> RawJudgment:
        self.converse_requests.append(request)
        if self.failure_detail is not None:
            raise TimeoutError(self.failure_detail)
        if self.raw_text is not None:
            return RawJudgment(
                text=self.raw_text,
                stop_reason="end_turn",
                guardrail_intervened=False,
                provider_request_id="fixture-hostile-first-token",
            )
        evidence = request.evidence.items[0]
        return RawJudgment(
            text=json.dumps(
                {
                    "schema_version": "1",
                    "findings": [
                        {
                            "finding_id": "vpn_rule_observation",
                            "kind": "observation",
                            "template_id": "vpn_rule_observation",
                            "evidence_ids": [evidence.evidence_id],
                            "bindings": {
                                "rule": {
                                    "evidence_id": evidence.evidence_id,
                                    "field": "rule.id",
                                }
                            },
                        }
                    ],
                }
            ),
            stop_reason="end_turn",
            guardrail_intervened=False,
            provider_request_id="fixture-vpn-judgment",
        )


def _catalog_for_plan(service: ApplicationService, *, with_prompt: bool) -> ContentCatalog:
    original = cast(ContentCatalog, service.catalog)
    definition = TopicDefinition(
        topic_id="ldap",
        name=LocaleText(en="LDAP", es="LDAP"),
        aliases=[],
        public_document=DocumentDefinition(
            document_id="ldap-doc",
            language="en",
            source_path="docs/ldap.md",
            heading="LDAP",
            anchor="ldap",
            sha256="6" * 64,
            published_path="ldap.html",
        ),
        finding_template_ids=[],
        fetch_bindings=[FetchBinding(template_id=TemplateId.alerts_rows_v1, filters=[])],
    )
    template = FindingTemplate(
        template_id="ldap_observation",
        topic_id="ldap",
        kind="observation",
        required_bindings={"rule": (FieldId.rule_id,)},
        texts=LocaleText(en="Observed rule: {rule}", es="Regla observada: {rule}"),
        required_check_outcomes=[],
        allowed_evidence_kinds=["row"],
    )
    prompt_packs = (
        (
            TopicPromptPack(
                topic_id="ldap",
                language="en",
                content_sha=original.provenance.content_sha,
                sha256="7" * 64,
                document_section=None,
                internal_context="Use only the bounded fixture evidence.",
                missing=[],
            ),
        )
        if with_prompt
        else ()
    )
    catalog = ContentCatalog(
        original.provenance,
        original.cue_catalog,
        (definition,),
        prompt_packs,
        templates=(template,),
    )
    service.catalog = catalog
    return catalog


def _mixed_fetch_result(
    topic_id: str, state: FetchState, *, question_id: UUID, policy_hash: str
) -> FetchResult:
    window = ResolvedWindow(
        start=NOW - timedelta(hours=1),
        end=NOW,
        semantics="absolute",
        source_text="fixture interval",
        timezone="UTC",
        anchor_at=NOW,
    )
    denied_or_unavailable = state in {FetchState.denied, FetchState.unavailable}
    row = EvidenceRow(
        evidence_id=f"ev1_{sha256(f'{question_id}:{topic_id}'.encode()).hexdigest()}",
        topic_id=topic_id,
        fetch_id="alerts",
        record_ref=None,
        values={FieldId.rule_id: f"Synthetic {topic_id} alert"},
    )
    item = EvidenceItem(
        evidence_id=row.evidence_id,
        topic_id=topic_id,
        fetch_id="alerts",
        check_id=None,
        kind="row",
        source=EvidenceSourceRow(
            index_alias="wazuh-alerts-alpha-2026.10.03", record_id="fixture-1"
        ),
        snapshot=SnapshotRef(
            kind=SnapshotKind.first_page_only,
            key=sha256(f"{question_id}:{topic_id}".encode()).hexdigest(),
            at=NOW,
        ),
        values={FieldId.rule_id: f"Synthetic {topic_id} alert"},
        visibility=Visibility.full,
        scope_hash=sha256(f"{question_id}:{topic_id}:scope".encode()).hexdigest(),
    )
    return FetchResult(
        fetch_id="alerts",
        topic_id=topic_id,
        state=state,
        scope=FetchScope(
            environment_id="alpha",
            template_id=TemplateId.alerts_rows_v1,
            index_family=IndexFamily.alerts,
            filters=[],
            visibility=Visibility.full,
            policy_hash=policy_hash,
            snapshot=SnapshotKind.first_page_only,
            displayed_rows=0 if denied_or_unavailable else 1,
        ),
        window=window,
        columns=[],
        rows=[] if denied_or_unavailable else [row],
        count=(
            None
            if denied_or_unavailable
            else Count(
                value=1,
                relation="eq",
                scope="matching_visible_records",
                computed_by="indexer",
            )
        ),
        checks=[],
        empty_proof=None,
        next_cursor=None,
        snapshot_at=NOW,
        snapshot=SnapshotRef(
            kind=SnapshotKind.first_page_only,
            key=sha256(f"{question_id}:{topic_id}".encode()).hexdigest(),
            at=NOW,
        ),
        items=[] if denied_or_unavailable else [item],
        error=(
            DomainError(
                code=(
                    ErrorCode.INDEXER_DENIED
                    if state == FetchState.denied
                    else ErrorCode.INDEXER_UNAVAILABLE
                ),
                message="Synthetic bounded fetch outcome.",
                retryable=state == FetchState.unavailable,
                trace_id="8" * 32,
                details={},
            )
            if denied_or_unavailable
            else None
        ),
    )


def _b_followup(plan: QuestionPlan, *, created_at: datetime) -> FollowupRecord:
    return FollowupRecord(
        followup_id=uuid4(),
        owner_key=plan.owner_key,
        environment_id=plan.environment_id,
        plan=plan,
        answered_topic_ids=[topic.topic_id for topic in plan.topics],
        leftout_topic_ids=[],
        leftout_stages=[],
        created_at=created_at,
        expires_at=created_at + timedelta(minutes=30),
    )


async def _assert_committed_answer_can_be_delivered_late(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = json.loads(FIXTURE_BYTES)["expected"]
    assert fixture["same_operation_delayed_delivery"] == "same completion receipt"
    assert fixture["committed_answer_late_delivery"] == "allowed"
    runtime = _runtime()
    state = cast(MemoryState, runtime.application.plans)
    owner = "d" * 64
    principal = _principal(owner)
    question_id = uuid4()
    policy_hash = runtime.application.site_policy.authorize(principal, "alpha").policy_hash
    plan = _plan("fetch", owner=owner, question_id=question_id, policy_hash=policy_hash)
    runtime.application.planner = cast(Planner, _Planner(plan))

    async def complete_topic(
        _self: ApplicationService,
        _principal_value: VerifiedPrincipal,
        _site_value: AuthorizedSite,
        _manifest: BuildProvenance,
        _plan_value: QuestionPlan,
        _original_question: str,
        topic: TopicPlan,
        _execution: ExecutionContext,
        _lease: object,
    ) -> tuple[TopicAnswer, list[LeftOut]]:
        return (
            TopicAnswer(
                topic_id=topic.topic_id,
                ordinal=topic.ordinal,
                document=None,
                missing=[],
                tables=[],
                checks=[],
                judgment=JudgmentResult(
                    state=JudgmentState.not_requested, sentences=[], removed=[]
                ),
            ),
            [],
        )

    completed_event = asyncio.Event()
    deliver = asyncio.Event()

    async def delay_completed_delivery(
        _self: ApplicationService,
        _answer: object,
        _principal_value: VerifiedPrincipal,
        _plan_value: QuestionPlan,
        _policy_hash: str,
        _manifest: BuildProvenance,
        outcome: Literal["attempted", "completed", "cancelled"],
        _execution: ExecutionContext,
        completion_id: UUID | None = None,
    ) -> AuditAck:
        assert (outcome == "completed") == (completion_id is not None)
        if outcome == "completed":
            completed_event.set()
            await deliver.wait()
        return AuditAck(event_id=uuid4(), delivery_id="late-delivery", accepted_at=NOW)

    monkeypatch.setattr(ApplicationService, "_run_topic", complete_topic)
    monkeypatch.setattr(ApplicationService, "_audit", delay_completed_delivery)
    answer_task = asyncio.create_task(
        runtime.application.ask(
            AskRequest(question="show LDAP alerts", environment_id="alpha"), principal
        )
    )
    await asyncio.wait_for(completed_event.wait(), timeout=2)
    original_followup = state.completions[question_id].followup_id
    assert original_followup is not None

    later_question_id = uuid4()
    later_lease = await state.begin_request(
        owner_key=owner,
        environment_id="alpha",
        question_id=later_question_id,
        request_hash="e" * 64,
        idempotency_key=None,
        now=NOW + timedelta(seconds=61),
    )
    later_command = CompletionCommand(
        question_id=later_question_id,
        owner_key=owner,
        environment_id="alpha",
        answer_status=AnswerStatus.answered,
        followup=None,
        idempotency=None,
        audit_ack=AuditAck(
            event_id=uuid4(), delivery_id="later-worker", accepted_at=NOW + timedelta(seconds=61)
        ),
        metadata_sha256="e" * 64,
    )
    await state.commit_completion(
        later_command,
        lease=later_lease,
        now=NOW + timedelta(seconds=61),
        operation_id=uuid4(),
    )
    deliver.set()
    delayed_answer = await answer_task
    assert delayed_answer.question_id == question_id
    assert delayed_answer.followup_id == original_followup
    assert original_followup in state.plans


@pytest.mark.parametrize("variant", ["positive", "negative", "boundary", "failure"])
@pytest.mark.asyncio
async def test_ask_does_not_publish_after_replacement_holder_completes(
    variant: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert sha256(FIXTURE_BYTES).hexdigest() == FIXTURE_SHA256
    fixture = json.loads(FIXTURE_BYTES)["cases"][variant]
    stage = cast(Literal["fetch", "document", "model"], fixture["paused_stage"])
    runtime = _runtime()
    assert isinstance(runtime.application.plans, MemoryState)
    state = cast(MemoryState, runtime.application.plans)
    owner = "a" * 64
    question_id = uuid4()
    policy_hash = runtime.application.site_policy.authorize(_principal(owner), "alpha").policy_hash
    plan = _plan(stage, owner=owner, question_id=question_id, policy_hash=policy_hash)
    runtime.application.planner = cast(Planner, _Planner(plan))
    _catalog_for_plan(runtime.application, with_prompt=stage == "model")
    fetch_result = _mixed_fetch_result(
        "ldap", FetchState.rows, question_id=question_id, policy_hash=policy_hash
    )
    paused_fetches = _PausedFetches({"ldap": fetch_result})
    ordinary_fetches = _MixedFetches({"ldap": fetch_result})
    runtime.application.fetches = cast(
        FetchExecutor, ordinary_fetches if stage == "model" else paused_fetches
    )
    paused_provider: _PausedCountProvider | None = None
    if stage == "model":
        paused_provider = _PausedCountProvider()
        runtime.application.judgment_provider = cast(JudgmentProvider, paused_provider)
    idempotency_key = uuid4() if fixture["idempotency"] == "present" else None
    request = AskRequest(question="show LDAP alerts", environment_id="alpha")
    principal = _principal(owner)
    worker_a = asyncio.create_task(
        runtime.application.ask(request, principal, idempotency_key=idempotency_key)
    )
    if paused_provider is None:
        await asyncio.wait_for(paused_fetches.entered.wait(), timeout=2)
        assert paused_fetches.calls == ["ldap"]
        if stage == "document":
            assert plan.topics[0].document
            assert runtime.application.catalog.topic("ldap") is not None
    else:
        await asyncio.wait_for(paused_provider.entered.wait(), timeout=2)
        assert ordinary_fetches.calls == ["ldap"]

    question = state.questions[question_id]
    recovered_at = NOW + timedelta(seconds=61)
    lease_b = await state.begin_request(
        owner_key=owner,
        environment_id="alpha",
        question_id=question_id,
        request_hash=question.request_hash,
        idempotency_key=None,
        now=recovered_at,
    )
    followup_b = _b_followup(plan, created_at=recovered_at)
    command_b = CompletionCommand(
        question_id=question_id,
        owner_key=owner,
        environment_id="alpha",
        answer_status=AnswerStatus.answered,
        followup=followup_b,
        idempotency=None,
        audit_ack=AuditAck(event_id=uuid4(), delivery_id="worker-b", accepted_at=recovered_at),
        metadata_sha256=fixture["replacement_metadata_sha256"],
    )
    await state.commit_completion(command_b, lease=lease_b, now=recovered_at, operation_id=uuid4())

    if paused_provider is None:
        paused_fetches.resume.set()
    else:
        paused_provider.resume.set()
    with pytest.raises(StateFailure) as failure:
        await worker_a
    assert failure.value.code == "LEASE_LOST"
    assert set(state.plans) == {followup_b.followup_id}
    assert question_id in state.completions
    await _assert_committed_answer_can_be_delivered_late(monkeypatch)


@pytest.mark.parametrize(
    "variant",
    [
        pytest.param(
            "positive",
            marks=(
                pytest.mark.acceptance("G035"),
                pytest.mark.case_id("B5-G035.application-judgment"),
                pytest.mark.variant("positive"),
                pytest.mark.fixture_sha256(G035_FIXTURE_SHA256),
            ),
        ),
        pytest.param("negative"),
        pytest.param(
            "boundary",
            marks=(
                pytest.mark.acceptance("G035"),
                pytest.mark.case_id("B5-G035.application-judgment"),
                pytest.mark.variant("boundary"),
                pytest.mark.fixture_sha256(G035_FIXTURE_SHA256),
            ),
        ),
        pytest.param(
            "failure",
            marks=(
                pytest.mark.acceptance("G035"),
                pytest.mark.case_id("B5-G035.application-judgment"),
                pytest.mark.variant("failure"),
                pytest.mark.fixture_sha256(G035_FIXTURE_SHA256),
            ),
        ),
    ],
)
@pytest.mark.asyncio
async def test_application_keeps_allowed_topic_when_another_fetch_is_denied(variant: str) -> None:
    assert sha256(G035_FIXTURE_BYTES).hexdigest() == G035_FIXTURE_SHA256
    scenario = json.loads(G035_FIXTURE_BYTES)["cases"][variant]
    await _assert_application_mixed_access_case(scenario)


@pytest.mark.parametrize(
    "variant",
    [
        pytest.param(
            "positive",
            marks=(
                pytest.mark.acceptance("G053"),
                pytest.mark.case_id("B5-G053.provider-token-application"),
                pytest.mark.variant("positive"),
                pytest.mark.fixture_sha256(G053_TOKEN_FIXTURE_SHA256),
            ),
        ),
        pytest.param(
            "negative",
            marks=(
                pytest.mark.acceptance("G053"),
                pytest.mark.case_id("B5-G053.provider-token-application"),
                pytest.mark.variant("negative"),
                pytest.mark.fixture_sha256(G053_TOKEN_FIXTURE_SHA256),
            ),
        ),
        pytest.param(
            "boundary",
            marks=(
                pytest.mark.acceptance("G053"),
                pytest.mark.case_id("B5-G053.provider-token-application"),
                pytest.mark.variant("boundary"),
                pytest.mark.fixture_sha256(G053_TOKEN_FIXTURE_SHA256),
            ),
        ),
        pytest.param(
            "failure",
            marks=(
                pytest.mark.acceptance("G053"),
                pytest.mark.case_id("B5-G053.provider-token-application"),
                pytest.mark.variant("failure"),
                pytest.mark.fixture_sha256(G053_TOKEN_FIXTURE_SHA256),
            ),
        ),
    ],
)
@pytest.mark.asyncio
async def test_application_never_returns_an_unvalidated_first_provider_token(variant: str) -> None:
    fixture = json.loads(G053_TOKEN_FIXTURE_BYTES)
    assert sha256(G053_TOKEN_FIXTURE_BYTES).hexdigest() == G053_TOKEN_FIXTURE_SHA256
    case = fixture["cases"][variant]
    raw_text, failure_detail = _g053_provider_input(fixture, case)
    answer = await _assert_application_mixed_access_case(
        json.loads(G035_FIXTURE_BYTES)["cases"]["positive"],
        raw_text=raw_text,
        failure_detail=failure_detail,
    )

    serialized = answer.model_dump_json()
    assert fixture["hostile_first_token"] not in serialized
    assert "PRIVATE-CONVERSE-TIMEOUT:" not in serialized
    allowed = next(block for block in answer.blocks if block.topic_id == "vpn")
    assert allowed.judgment.state == JudgmentState(case["expected_judgment_state"])
    if "expected_public_sentences" in case:
        assert len(allowed.judgment.sentences) == case["expected_public_sentences"]
    else:
        assert [finding.text for finding in allowed.judgment.sentences] == [
            case["expected_safe_text"]
        ]


def _g053_provider_input(
    fixture: dict[str, object], case: dict[str, object]
) -> tuple[str | None, str | None]:
    path = case["provider_path"]
    if path == "valid_structured_candidate":
        return None, None
    sentinel = cast(str, fixture["hostile_first_token"])
    if path == "raw_hostile_first_token":
        return sentinel, None
    if path == "exact_output_byte_limit_with_unapproved_field":
        output_bytes = cast(int, case["output_bytes"])
        payload = json.dumps(
            {"schema_version": "1", "findings": [], "provider_output": sentinel},
            separators=(",", ":"),
        )
        padding = output_bytes - len(payload.encode("utf-8"))
        assert padding >= 0
        bounded = payload + (" " * padding)
        assert len(bounded.encode("utf-8")) == output_bytes
        return bounded, None
    if path == "timeout_with_hostile_transport_detail":
        return None, cast(str, case["transport_error_prefix"]) + sentinel
    raise AssertionError(f"unknown G053 provider fixture path: {path}")


@pytest.mark.parametrize("variant", ["positive", "negative", "boundary", "failure"])
@pytest.mark.asyncio
async def test_rest_serializes_only_the_validated_application_answer(variant: str) -> None:
    fixture = json.loads(G053_TOKEN_FIXTURE_BYTES)
    case = fixture["cases"][variant]
    raw_text, failure_detail = _g053_provider_input(fixture, case)
    answer = await _assert_application_mixed_access_case(
        json.loads(G035_FIXTURE_BYTES)["cases"]["positive"],
        raw_text=raw_text,
        failure_detail=failure_detail,
    )
    principal = _principal("f" * 64).model_copy(update={"edge": "browser"})

    class AnswerApplication:
        async def ask(self, request, verified_principal, *, idempotency_key=None) -> Answer:
            assert verified_principal.owner_key == principal.owner_key
            return answer

    class Identity:
        async def verify(self, *, headers, edge: str) -> VerifiedPrincipal:
            assert edge == "browser"
            return principal

    csrf = CsrfTokens(b"k" * 32, origin="https://soc.example.test")
    cookie, csrf_token = csrf.issue(
        owner_key=principal.owner_key,
        assertion_expires_at=principal.expires_at,
        now=NOW,
    )
    rest = create_app(AnswerApplication(), Identity(), csrf, _Clock(), _Readiness())
    async with httpx.AsyncClient(
        base_url="https://soc.example.test", transport=httpx.ASGITransport(app=rest)
    ) as client:
        response = await client.post(
            "/v1/questions",
            json={"question": "show LDAP alerts", "environment_id": "alpha"},
            headers={"Origin": "https://soc.example.test", "X-SOC-CSRF": csrf_token},
            cookies={CSRF_COOKIE: cookie},
        )

    assert response.status_code == 200
    assert fixture["hostile_first_token"] not in response.text
    assert "PRIVATE-CONVERSE-TIMEOUT:" not in response.text
    rendered_blocks = response.json()["blocks"]
    vpn = next(block for block in rendered_blocks if block["topic_id"] == "vpn")
    assert vpn["judgment"]["state"] == case["expected_judgment_state"]


@pytest.mark.parametrize("variant", ["positive", "negative", "boundary", "failure"])
@pytest.mark.asyncio
async def test_mcp_serializes_only_the_validated_application_answer(variant: str) -> None:
    fixture = json.loads(G053_TOKEN_FIXTURE_BYTES)
    case = fixture["cases"][variant]
    raw_text, failure_detail = _g053_provider_input(fixture, case)
    answer = await _assert_application_mixed_access_case(
        json.loads(G035_FIXTURE_BYTES)["cases"]["positive"],
        raw_text=raw_text,
        failure_detail=failure_detail,
    )
    now = datetime.now(UTC)
    principal = _principal("f" * 64).model_copy(
        update={"edge": "mcp", "authenticated_at": now, "expires_at": now + timedelta(hours=1)}
    )

    class AnswerApplication:
        async def ask(self, request, verified_principal, *, idempotency_key=None) -> Answer:
            assert verified_principal.owner_key == principal.owner_key
            return answer

    class Identity:
        async def verify(self, *, headers, edge: str) -> VerifiedPrincipal:
            assert edge == "mcp"
            return principal

    app = create_mcp_app(
        AnswerApplication(),
        Identity(),
        issuer_url="https://issuer.example.test",
        resource_url="https://soc.example.test/mcp",
    )
    sdk_app = cast(Starlette, cast(VerifiedRequestContext, app)._app)
    async with sdk_app.router.lifespan_context(sdk_app):
        async with httpx.AsyncClient(
            base_url="https://soc.example.test",
            transport=httpx.ASGITransport(app=app),
            headers={
                "Authorization": "Bearer fixture-token",
                "Origin": "https://soc.example.test",
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
            },
        ) as client:
            initialized = await client.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "clientInfo": {"name": "g053-fixture", "version": "1"},
                    },
                },
            )
            response = await client.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "soc_ask",
                        "arguments": {
                            "request": {
                                "question": "show LDAP alerts",
                                "environment_id": "alpha",
                            }
                        },
                    },
                },
            )

    assert initialized.status_code == 200
    assert response.status_code == 200
    assert fixture["hostile_first_token"] not in response.text
    assert "PRIVATE-CONVERSE-TIMEOUT:" not in response.text
    rendered_blocks = response.json()["result"]["structuredContent"]["blocks"]
    vpn = next(block for block in rendered_blocks if block["topic_id"] == "vpn")
    assert vpn["judgment"]["state"] == case["expected_judgment_state"]


async def _assert_application_mixed_access_case(
    scenario: dict[str, object],
    *,
    raw_text: str | None = None,
    failure_detail: str | None = None,
) -> Answer:
    runtime = _runtime()
    owner = "f" * 64
    principal = _principal(owner)
    question_id = uuid4()
    policy_hash = runtime.application.site_policy.authorize(principal, "alpha").policy_hash
    template = _plan("fetch", owner=owner, question_id=question_id, policy_hash=policy_hash)
    base_fetch = template.topics[0].fetches[0]
    topics = [
        TopicPlan(
            topic_id=item["topic_id"],
            ordinal=item["ordinal"],
            document=False,
            failure=False,
            judgment=item.get("judgment", False),
            fetches=[base_fetch],
            cue_ids=[],
            alias_ids=[],
        )
        for item in scenario["topics"]
    ]
    plan = template.model_copy(
        update={"topics": topics, "model_id": "fixture-model", "effort": Effort.low}
    )
    runtime.application.planner = cast(Planner, _Planner(plan))
    original_catalog = cast(ContentCatalog, runtime.application.catalog)
    vpn_definition = TopicDefinition(
        topic_id="vpn",
        name=LocaleText(en="VPN", es="VPN"),
        aliases=[],
        public_document=None,
        playbook_id=None,
        finding_template_ids=["vpn_rule_observation"],
        fetch_bindings=[FetchBinding(template_id=TemplateId.alerts_rows_v1, filters=[])],
    )
    vpn_prompt = TopicPromptPack(
        topic_id="vpn",
        language="en",
        content_sha=original_catalog.provenance.content_sha,
        sha256="e" * 64,
        internal_context="Use only the supplied VPN evidence.",
        missing=[],
    )
    vpn_template = FindingTemplate(
        template_id="vpn_rule_observation",
        topic_id="vpn",
        kind="observation",
        required_bindings={"rule": (FieldId.rule_id,)},
        texts=LocaleText(
            en="Allowed VPN evidence: {rule}",
            es="Evidencia VPN permitida: {rule}",
        ),
        required_check_outcomes=[],
        allowed_evidence_kinds=["row"],
    )
    runtime.application.catalog = ContentCatalog(
        original_catalog.provenance,
        original_catalog.cue_catalog,
        original_catalog.topic_records + (vpn_definition,),
        original_catalog.prompt_packs + (vpn_prompt,),
        original_catalog.playbook_records,
        original_catalog.expectations,
        original_catalog.templates + (vpn_template,),
    )
    provider = _AllowedTopicProvider(raw_text=raw_text, failure_detail=failure_detail)
    runtime.application.models = (_model(),)
    runtime.application.judgment_provider = cast(JudgmentProvider, provider)
    fetches = _MixedFetches(
        {
            item["topic_id"]: _mixed_fetch_result(
                item["topic_id"],
                FetchState(item["fetch_state"]),
                question_id=question_id,
                policy_hash=policy_hash,
            )
            for item in scenario["topics"]
        }
    )
    runtime.application.fetches = cast(FetchExecutor, fetches)

    answer = await runtime.application.ask(
        AskRequest(question="compare authentication and VPN alerts", environment_id="alpha"),
        principal,
    )

    assert fetches.calls == scenario["expected_calls"]
    assert [block.topic_id for block in answer.blocks] == [
        item["topic_id"] for item in scenario["topics"]
    ]
    assert answer.status == AnswerStatus.partial
    denied = next(block for block in answer.blocks if block.topic_id == "authentication")
    assert denied.tables[0].state == FetchState.denied
    assert denied.tables[0].rows == []
    assert denied.judgment.sentences == []
    allowed = next((block for block in answer.blocks if block.topic_id == "vpn"), None)
    if allowed:
        assert allowed.tables[0].state == FetchState.rows
        assert allowed.tables[0].rows[0].values == {FieldId.rule_id: "Synthetic vpn alert"}
    failed = next((block for block in answer.blocks if block.topic_id == "tls"), None)
    if failed:
        assert failed.tables[0].state == FetchState.unavailable
        assert failed.tables[0].rows == []
    expected_left_out = list(scenario["expected_left_out"])
    if failure_detail is not None:
        expected_left_out.append(
            {"topic_id": "vpn", "stage": "judgment", "reason": "model_unavailable"}
        )
    elif raw_text is not None:
        expected_left_out.append(
            {"topic_id": "vpn", "stage": "judgment", "reason": "invalid_output"}
        )
    assert [
        {"topic_id": item.topic_id, "stage": item.stage, "reason": item.reason}
        for item in answer.left_out
    ] == expected_left_out
    allowed = next((block for block in answer.blocks if block.topic_id == "vpn"), None)
    if allowed is None:
        assert len(provider.count_requests) == scenario["expected_judgment_attempts"]
        assert len(provider.converse_requests) == scenario["expected_judgment_attempts"]
    else:
        if raw_text is None and failure_detail is None:
            assert allowed.judgment.state == JudgmentState.validated
            assert [finding.text for finding in allowed.judgment.sentences] == scenario[
                "expected_allowed_findings"
            ]
        elif raw_text is not None:
            assert allowed.judgment.state == JudgmentState.invalid_output
            assert not allowed.judgment.sentences
            assert raw_text not in answer.model_dump_json()
        else:
            assert allowed.judgment.state == JudgmentState.model_unavailable
            assert not allowed.judgment.sentences
            assert failure_detail not in answer.model_dump_json()
        assert len(provider.count_requests) == scenario["expected_judgment_attempts"]
        assert len(provider.converse_requests) == scenario["expected_judgment_attempts"]
        request = provider.converse_requests[0]
        assert [item.topic_id for item in request.evidence.items] == ["vpn"]
        assert len(request.evidence.items) == 1
    return answer


@pytest.mark.acceptance("G035")
@pytest.mark.case_id("B5-G035.application-judgment")
@pytest.mark.variant("negative")
@pytest.mark.fixture_sha256(G035_NEGATIVE_FIXTURE_SHA256)
@pytest.mark.asyncio
async def test_g035_negative_keeps_allowed_judgment_when_denial_follows() -> None:
    assert sha256(G035_NEGATIVE_FIXTURE_BYTES).hexdigest() == G035_NEGATIVE_FIXTURE_SHA256
    scenario = json.loads(G035_NEGATIVE_FIXTURE_BYTES)["case"]
    await _assert_application_mixed_access_case(scenario)


def _topic_plans(
    base: QuestionPlan,
    topic_ids: list[str],
    *,
    ordinals: list[int] | None = None,
    window: ResolvedWindow | None = None,
) -> list[TopicPlan]:
    chosen_ordinals = ordinals or list(range(len(topic_ids)))
    assert len(chosen_ordinals) == len(topic_ids)
    return [
        TopicPlan(
            topic_id=topic_id,
            ordinal=ordinal,
            document=False,
            failure=False,
            judgment=False,
            fetches=[base.topics[0].fetches[0].model_copy(update={"window": window})]
            if window is not None
            else [base.topics[0].fetches[0]],
            cue_ids=[],
            alias_ids=[],
        )
        for topic_id, ordinal in zip(topic_ids, chosen_ordinals, strict=True)
    ]


def _previous_followup(
    state: MemoryState,
    plan: QuestionPlan,
    *,
    answered: list[str],
    left_out: list[str],
) -> FollowupRecord:
    previous = _b_followup(plan, created_at=NOW).model_copy(
        update={"answered_topic_ids": answered, "leftout_topic_ids": left_out}
    )
    state.plans[previous.followup_id] = previous
    return previous


@pytest.mark.parametrize(
    "variant",
    [
        pytest.param(
            "positive",
            marks=(
                pytest.mark.acceptance("G033"),
                pytest.mark.case_id("B5-G033.followup-application.private"),
                pytest.mark.variant("positive"),
                pytest.mark.fixture_sha256(FOLLOWUP_FIXTURE_SHA256),
            ),
        ),
        pytest.param(
            "negative",
            marks=(
                pytest.mark.acceptance("G033"),
                pytest.mark.case_id("B5-G033.followup-application.private"),
                pytest.mark.variant("negative"),
                pytest.mark.fixture_sha256(FOLLOWUP_FIXTURE_SHA256),
            ),
        ),
        pytest.param(
            "boundary",
            marks=(
                pytest.mark.acceptance("G033"),
                pytest.mark.case_id("B5-G033.followup-application.private"),
                pytest.mark.variant("boundary"),
                pytest.mark.fixture_sha256(FOLLOWUP_FIXTURE_SHA256),
            ),
        ),
        pytest.param(
            "failure",
            marks=(
                pytest.mark.acceptance("G033"),
                pytest.mark.case_id("B5-G033.followup-application.private"),
                pytest.mark.variant("failure"),
                pytest.mark.fixture_sha256(FOLLOWUP_FIXTURE_SHA256),
            ),
        ),
    ],
)
@pytest.mark.asyncio
async def test_window_followup_refreshes_all_prior_fetches_with_one_new_anchor(
    variant: str,
) -> None:
    assert sha256(FOLLOWUP_FIXTURE_BYTES).hexdigest() == FOLLOWUP_FIXTURE_SHA256
    scenario = json.loads(FOLLOWUP_FIXTURE_BYTES)["g033_window"][variant]
    runtime = _runtime()
    state = cast(MemoryState, runtime.application.plans)
    owner = "c" * 64
    principal = _principal(owner)
    policy_hash = runtime.application.site_policy.authorize(principal, "alpha").policy_hash
    prior_plan = _plan("fetch", owner=owner, question_id=uuid4(), policy_hash=policy_hash)
    prior_topics = _topic_plans(
        prior_plan,
        scenario["topics"],
        ordinals=scenario.get("ordinals"),
    )
    prior_plan = prior_plan.model_copy(update={"topics": prior_topics})
    previous = _previous_followup(
        state,
        prior_plan,
        answered=scenario["topics"],
        left_out=[],
    )
    question_id = uuid4()
    next_window = ResolvedWindow(
        start=NOW - timedelta(hours=6),
        end=NOW,
        semantics="absolute",
        source_text="last six hours",
        timezone="UTC",
        anchor_at=NOW,
    )
    target_topics = _topic_plans(
        prior_plan,
        scenario["topics"],
        ordinals=scenario.get("ordinals"),
        window=next_window,
    )
    planned = prior_plan.model_copy(update={"question_id": question_id, "topics": target_topics})
    runtime.application.planner = cast(
        Planner,
        _FollowupPlanner(
            planned,
            previous=previous,
            continue_topic_ids=None,
        ),
    )
    fetches = _MixedFetches(
        {
            topic_id: _mixed_fetch_result(
                topic_id,
                FetchState(state_value),
                question_id=question_id,
                policy_hash=policy_hash,
            )
            for topic_id, state_value in zip(
                scenario["topics"],
                scenario.get("fetch_states", ["rows"] * len(scenario["topics"])),
                strict=True,
            )
        }
    )
    runtime.application.fetches = cast(FetchExecutor, fetches)
    revision = scenario.get("revision", previous.revision)
    request = AskRequest(
        question="refresh prior topics",
        environment_id="alpha",
        followup_id=previous.followup_id,
        followup_revision=revision,
    )
    if variant == "negative":
        with pytest.raises(StateFailure) as failure:
            await runtime.application.ask(request, principal)
        assert failure.value.code == scenario["expected_error"]
        assert not fetches.calls
        return

    answer = await runtime.application.ask(request, principal)
    assert fetches.calls == scenario["expected_calls"]
    assert [spec.window for _, spec in fetches.requests] == [
        next_window for _ in scenario["expected_calls"]
    ]
    assert all(spec.window.anchor_at == prior_plan.anchor_at for _, spec in fetches.requests)
    assert [item.topic_id for item in answer.left_out] == scenario.get("expected_left_out", [])


@pytest.mark.parametrize(
    "variant",
    [
        pytest.param(
            "positive",
            marks=(
                pytest.mark.acceptance("G034"),
                pytest.mark.case_id("B5-G034.continuation-application.private"),
                pytest.mark.variant("positive"),
                pytest.mark.fixture_sha256(FOLLOWUP_FIXTURE_SHA256),
            ),
        ),
        pytest.param(
            "negative",
            marks=(
                pytest.mark.acceptance("G034"),
                pytest.mark.case_id("B5-G034.continuation-application.private"),
                pytest.mark.variant("negative"),
                pytest.mark.fixture_sha256(FOLLOWUP_FIXTURE_SHA256),
            ),
        ),
        pytest.param(
            "boundary",
            marks=(
                pytest.mark.acceptance("G034"),
                pytest.mark.case_id("B5-G034.continuation-application.private"),
                pytest.mark.variant("boundary"),
                pytest.mark.fixture_sha256(FOLLOWUP_FIXTURE_SHA256),
            ),
        ),
        pytest.param(
            "failure",
            marks=(
                pytest.mark.acceptance("G034"),
                pytest.mark.case_id("B5-G034.continuation-application.private"),
                pytest.mark.variant("failure"),
                pytest.mark.fixture_sha256(FOLLOWUP_FIXTURE_SHA256),
            ),
        ),
    ],
)
@pytest.mark.asyncio
async def test_continuation_executes_only_planner_selected_left_out_topics(variant: str) -> None:
    assert sha256(FOLLOWUP_FIXTURE_BYTES).hexdigest() == FOLLOWUP_FIXTURE_SHA256
    scenario = json.loads(FOLLOWUP_FIXTURE_BYTES)["g034_continue"][variant]
    runtime = _runtime()
    state = cast(MemoryState, runtime.application.plans)
    owner = "e" * 64
    principal = _principal(owner)
    policy_hash = runtime.application.site_policy.authorize(principal, "alpha").policy_hash
    prior_plan = _plan("fetch", owner=owner, question_id=uuid4(), policy_hash=policy_hash)
    prior_topics = _topic_plans(
        prior_plan,
        scenario["topics"],
        ordinals=scenario.get("ordinals"),
    )
    prior_plan = prior_plan.model_copy(update={"topics": prior_topics})
    previous = _previous_followup(
        state,
        prior_plan,
        answered=scenario["answered"],
        left_out=scenario["left_out"],
    )
    question_id = uuid4()
    selected = scenario["selected"]
    target_topics = [topic for topic in prior_topics if topic.topic_id in selected]
    planned = prior_plan.model_copy(update={"question_id": question_id, "topics": target_topics})
    result: Planned | Refused | None = (
        Refused(message="Only unfinished topics can be continued.")
        if variant == "negative"
        else None
    )
    runtime.application.planner = cast(
        Planner,
        _FollowupPlanner(
            planned,
            previous=previous,
            continue_topic_ids=selected,
            result=result,
        ),
    )
    if variant == "negative":
        runtime.application.semantic_suggester = None
        fetches = _MixedFetches({})
        runtime.application.fetches = cast(FetchExecutor, fetches)
        answer = await runtime.application.ask(
            AskRequest(
                question="continue an unfinished topic",
                environment_id="alpha",
                followup_id=previous.followup_id,
                followup_revision=previous.revision,
                continue_topic_ids=selected,
            ),
            principal,
        )
        assert answer.status == scenario["expected_status"]
        assert not answer.blocks
        assert not fetches.calls
        return

    fetch_state = scenario.get("fetch_states", ["rows"])[0]
    fetches = _MixedFetches(
        {
            topic_id: _mixed_fetch_result(
                topic_id,
                FetchState(fetch_state),
                question_id=question_id,
                policy_hash=policy_hash,
            )
            for topic_id in selected
        }
    )
    runtime.application.fetches = cast(FetchExecutor, fetches)
    answer = await runtime.application.ask(
        AskRequest(
            question="continue an unfinished topic",
            environment_id="alpha",
            followup_id=previous.followup_id,
            followup_revision=previous.revision,
            continue_topic_ids=selected,
        ),
        principal,
    )
    assert fetches.calls == scenario["expected_calls"]
    assert [block.topic_id for block in answer.blocks] == selected
    assert [item.topic_id for item in answer.left_out] == scenario.get("expected_left_out", [])


@pytest.mark.parametrize(
    "variant",
    [
        pytest.param(
            "positive",
            marks=(
                pytest.mark.acceptance("G052"),
                pytest.mark.case_id("B5-G052.application-budget.private"),
                pytest.mark.variant("positive"),
                pytest.mark.fixture_sha256(G052_FIXTURE_SHA256),
            ),
        ),
        pytest.param(
            "negative",
            marks=(
                pytest.mark.acceptance("G052"),
                pytest.mark.case_id("B5-G052.application-budget.private"),
                pytest.mark.variant("negative"),
                pytest.mark.fixture_sha256(G052_FIXTURE_SHA256),
            ),
        ),
        pytest.param(
            "boundary",
            marks=(
                pytest.mark.acceptance("G052"),
                pytest.mark.case_id("B5-G052.application-budget.private"),
                pytest.mark.variant("boundary"),
                pytest.mark.fixture_sha256(G052_FIXTURE_SHA256),
            ),
        ),
        pytest.param(
            "failure",
            marks=(
                pytest.mark.acceptance("G052"),
                pytest.mark.case_id("B5-G052.application-budget.private"),
                pytest.mark.variant("failure"),
                pytest.mark.fixture_sha256(G052_FIXTURE_SHA256),
            ),
        ),
    ],
)
@pytest.mark.asyncio
async def test_application_context_budget_keeps_evidence_and_reserves_only_after_fit(
    variant: str,
) -> None:
    assert sha256(G052_FIXTURE_BYTES).hexdigest() == G052_FIXTURE_SHA256
    fixture = json.loads(G052_FIXTURE_BYTES)
    case = fixture["cases"][variant]
    assert fixture["evidence_must_remain_identical"] is True
    if "count_failure" in case:
        assert case["count_failure"] is True
    else:
        expected_total = (
            case["counted_input_tokens"]
            + case["reserved_output_tokens"]
            + case["safety_margin_tokens"]
        )
        assert expected_total == case["expected_total_tokens"]
        assert case["context_tokens"] - expected_total == case["expected_context_difference"]
    runtime = _runtime()
    owner = "9" * 64
    principal = _principal(owner)
    question_id = uuid4()
    policy_hash = runtime.application.site_policy.authorize(principal, "alpha").policy_hash
    plan = _plan("model", owner=owner, question_id=question_id, policy_hash=policy_hash)
    runtime.application.planner = cast(Planner, _Planner(plan))
    runtime.application.models = (
        _model().model_copy(update={"context_tokens": case["context_tokens"]}),
    )
    _catalog_for_plan(runtime.application, with_prompt=True)
    fetched = _mixed_fetch_result(
        "ldap", FetchState.rows, question_id=question_id, policy_hash=policy_hash
    )
    fetches = _MixedFetches({"ldap": fetched})
    provider = _FixedCountProvider(
        count=case.get("counted_input_tokens", 0),
        fail_count=case.get("count_failure", False),
    )
    runtime.application.fetches = cast(FetchExecutor, fetches)
    runtime.application.judgment_provider = cast(JudgmentProvider, provider)

    ask_request = AskRequest(question="show LDAP alerts", environment_id="alpha")
    answer = await runtime.application.ask(ask_request, principal)

    assert fetches.calls == ["ldap"]
    assert len(provider.count_requests) == 1
    assert provider.count_requests[0].question == ask_request.question
    assert provider.count_requests[0].evidence.fetches == [fetched]
    assert len(provider.converse_requests) == case["expected_converse_attempts"]
    if provider.converse_requests:
        assert provider.converse_requests[0].question == ask_request.question
    assert answer.blocks[0].tables == [fetched]
    assert answer.blocks[0].judgment.state == JudgmentState(case["expected_judgment_state"])
    assert [str(item.reason) for item in answer.left_out] == case["expected_left_out"]
    state = cast(MemoryState, runtime.application.plans)
    if case["expected_converse_attempts"] == 0:
        assert not state.reservations
        assert answer.status == AnswerStatus.partial
    else:
        assert len(state.reservations) == 1
        reservation = next(iter(state.reservations.values()))
        assert reservation.state == "settled"
        assert reservation.charged_tokens == case["counted_input_tokens"] + 4
        assert answer.blocks[0].judgment.usage is not None
        assert answer.blocks[0].judgment.usage.reserved_tokens == case["expected_total_tokens"]
        assert answer.status == AnswerStatus.answered


@pytest.mark.parametrize(
    "variant",
    [
        pytest.param(
            "positive",
            marks=(
                pytest.mark.acceptance("GP2"),
                pytest.mark.case_id("B5-GP2.feedback-lifecycle.private"),
                pytest.mark.variant("positive"),
                pytest.mark.fixture_sha256(GP2_APP_FIXTURE_SHA256),
            ),
        ),
        pytest.param(
            "negative",
            marks=(
                pytest.mark.acceptance("GP2"),
                pytest.mark.case_id("B5-GP2.feedback-lifecycle.private"),
                pytest.mark.variant("negative"),
                pytest.mark.fixture_sha256(GP2_APP_FIXTURE_SHA256),
            ),
        ),
        pytest.param(
            "boundary",
            marks=(
                pytest.mark.acceptance("GP2"),
                pytest.mark.case_id("B5-GP2.feedback-lifecycle.private"),
                pytest.mark.variant("boundary"),
                pytest.mark.fixture_sha256(GP2_APP_FIXTURE_SHA256),
            ),
        ),
        pytest.param(
            "failure",
            marks=(
                pytest.mark.acceptance("GP2"),
                pytest.mark.case_id("B5-GP2.feedback-lifecycle.private"),
                pytest.mark.variant("failure"),
                pytest.mark.fixture_sha256(GP2_APP_FIXTURE_SHA256),
            ),
        ),
    ],
)
@pytest.mark.asyncio
async def test_application_feedback_receipt_is_owner_bound_redacted_and_durable(
    variant: str,
) -> None:
    assert sha256(GP2_APP_FIXTURE_BYTES).hexdigest() == GP2_APP_FIXTURE_SHA256
    scenario = json.loads(GP2_APP_FIXTURE_BYTES)["cases"][variant]
    clock = _ControlledClock()
    runtime = _runtime(clock)
    owner = "a" * 64
    principal = _principal(owner)
    question_id = uuid4()
    policy_hash = runtime.application.site_policy.authorize(principal, "alpha").policy_hash
    plan = _plan("fetch", owner=owner, question_id=question_id, policy_hash=policy_hash)
    runtime.application.planner = cast(Planner, _Planner(plan))
    _catalog_for_plan(runtime.application, with_prompt=False)
    fetched = _mixed_fetch_result(
        "ldap", FetchState.rows, question_id=question_id, policy_hash=policy_hash
    )
    runtime.application.fetches = cast(FetchExecutor, _MixedFetches({"ldap": fetched}))
    sqs = _FeedbackSqs(fail=variant == "failure")
    runtime.application.feedback_sink = cast(
        FeedbackSink,
        SqsFeedbackSink(
            cast(FeedbackSqsClient, sqs),
            "https://sqs.us-east-1.amazonaws.com/123456789012/feedback",
        ),
    )

    answer = await runtime.application.ask(
        AskRequest(question="show LDAP alerts", environment_id="alpha"), principal
    )
    assert answer.question_id == question_id
    assert answer.feedback_receipt is not None
    request = FeedbackRequest(
        question_id=answer.question_id,
        environment_id="alpha",
        feedback_receipt=answer.feedback_receipt,
        kind="wrong",
        note=scenario.get("note"),
    )

    if variant == "negative":
        foreign = _principal("8" * 64)
        with pytest.raises(ServiceFailure) as invalid:
            await runtime.application.feedback(request, foreign)
        assert invalid.value.error.code == scenario["expected_error"]
        assert sqs.calls == scenario["expected_sqs_attempts"]
        return

    if variant == "boundary":
        clock.current = NOW + timedelta(seconds=scenario["last_valid_offset_seconds"])
        accepted = await runtime.application.feedback(request, principal)
        assert accepted.status == "queued"
        clock.current = NOW + timedelta(seconds=scenario["expiry_offset_seconds"])
        with pytest.raises(ServiceFailure) as expired:
            await runtime.application.feedback(request, principal)
        assert expired.value.error.code == scenario["expected_error"]
        assert sqs.calls == scenario["expected_sqs_attempts"]
        return

    if variant == "failure":
        with pytest.raises(ServiceFailure) as unavailable:
            await runtime.application.feedback(request, principal)
        assert unavailable.value.error.code == scenario["expected_error"]
        assert scenario["queue_private_detail"] not in unavailable.value.error.message
        assert sqs.calls == scenario["expected_sqs_attempts"]
        failed_body = sqs.params["MessageBody"]
        sqs.fail = False
        clock.current = clock.current + timedelta(seconds=7)
        retried = await runtime.application.feedback(request, principal)
        assert retried.status == "queued"
        assert sqs.calls == scenario["expected_sqs_attempts"] + 1
        assert sqs.params["MessageBody"] == failed_body
        archive_queue = _FeedbackArchiveQueue()
        archive_objects = _FeedbackArchiveObjects()
        archive = FeedbackArchiveConsumer(
            sqs=archive_queue,
            s3=archive_objects,
            queue_url="https://sqs.example.test/feedback",
            bucket="feedback-archive",
        )
        for index, body in enumerate(sqs.bodies):
            assert archive.handle(body=body, receipt_handle=f"retry-{index}") == retried.feedback_id
        assert len(archive_objects.objects) == 1
        assert archive_queue.deleted == ["retry-0", "retry-1"]
        receipt_payload = runtime.application.receipts.open(
            request.feedback_receipt,
            question_id=request.question_id,
            owner_key=principal.owner_key,
            environment_id=request.environment_id,
            now=clock.now(),
        )
        stored_feedback = cast(MemoryState, runtime.application.feedback_store)
        expected_digest = "cadc32037319ef11b259f67d0986bbc62633c847db754d76edf7e3063333d30e"
        record_key = (receipt_payload.receipt_id, expected_digest)
        assert record_key in stored_feedback.feedback_records
        assert stored_feedback.feedback_records[record_key].feedback_id == retried.feedback_id
        return

    queued = await runtime.application.feedback(request, principal)
    assert queued.status == "queued"
    assert sqs.calls == scenario["expected_sqs_attempts"]
    raw_body = sqs.params["MessageBody"]
    first_feedback_id = queued.feedback_id
    assert isinstance(raw_body, str)
    event = FeedbackEvent.model_validate_json(raw_body)
    assert event.feedback_id == queued.feedback_id
    assert event.question_id == answer.question_id
    assert event.owner_key == owner
    assert event.environment_id == "alpha"
    assert event.content_sha == plan.content_sha
    assert event.note_redacted == scenario["expected_redacted_note"]
    assert "alice@example.test" not in raw_body
    assert "203.0.113.44" not in raw_body
    duplicate = await runtime.application.feedback(request, principal)
    assert duplicate.feedback_id == first_feedback_id
    assert duplicate.status == "queued"
    assert sqs.calls == scenario["expected_sqs_attempts"]
    assert sqs.params["MessageBody"] == raw_body
    receipt_payload = runtime.application.receipts.open(
        request.feedback_receipt,
        question_id=request.question_id,
        owner_key=principal.owner_key,
        environment_id=request.environment_id,
        now=clock.now(),
    )
    stored_feedback = cast(MemoryState, runtime.application.feedback_store)
    expected_digest = "4d6c6c7ba8841728e2c0dea892fae5d635db99dc8d909168d5a8c671fd7e7ef8"
    record_key = (receipt_payload.receipt_id, expected_digest)
    assert record_key in stored_feedback.feedback_records
    assert stored_feedback.feedback_records[record_key].feedback_id == first_feedback_id


class _AdvancingClock:
    def __init__(self, start: datetime) -> None:
        self._now = start

    def now(self) -> datetime:
        return self._now

    def advance(self, seconds: int) -> None:
        self._now = self._now + timedelta(seconds=seconds)

    def monotonic(self) -> float:
        return 0.0


class _FixedPlanner:
    def __init__(self, plan: QuestionPlan) -> None:
        self._plan = plan

    def plan(
        self,
        request: object,
        principal: object,
        previous: object,
        *,
        policy_hash: str,
        clock: object,
    ) -> Planned:
        return Planned(plan=self._plan)


class _SlowFetches:
    def __init__(self, clock: _AdvancingClock, seconds_per_fetch: int) -> None:
        self._clock = clock
        self._seconds = seconds_per_fetch
        self.calls = 0

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
        self.calls += 1
        self._clock.advance(self._seconds)
        await asyncio.sleep(0.1)
        return _mixed_fetch_result(
            topic_id, FetchState.rows, question_id=question_id, policy_hash=site.policy_hash
        )


def _fetch_only_plan(owner: str, fetch_count: int, *, policy_hash: str) -> QuestionPlan:
    window = ResolvedWindow(
        start=NOW - timedelta(hours=1),
        end=NOW,
        semantics="absolute",
        source_text="fixture interval",
        timezone="UTC",
        anchor_at=NOW,
    )
    fetches = [
        FetchSpec(
            fetch_id=f"fetch-{index}",
            template_id=TemplateId.alerts_rows_v1,
            window=window,
            filters=[],
        )
        for index in range(fetch_count)
    ]
    topic = TopicPlan(
        topic_id="ldap",
        ordinal=0,
        document=False,
        failure=False,
        judgment=False,
        fetches=fetches,
        cue_ids=[],
        alias_ids=[],
    )
    return QuestionPlan(
        question_id=uuid4(),
        environment_id="alpha",
        owner_key=owner,
        content_sha=_provenance().content_sha,
        policy_hash=policy_hash,
        language="en",
        timezone="UTC",
        anchor_at=NOW,
        topics=[topic],
        model_id=None,
        effort=None,
        provenance=PlanProvenance(
            cue_pack_sha="f" * 64,
            normalized_question_hash="1" * 64,
            origin="new",
            matched_spans=[],
        ),
    )


@pytest.mark.asyncio
async def test_h1_ask_completes_when_fetch_work_exceeds_lease_ttl_on_fixture_clock() -> None:
    clock = _AdvancingClock(NOW)
    owner = "a" * 64
    runtime = _runtime(clock)
    policy_hash = runtime.application.site_policy.authorize(_principal(owner), "alpha").policy_hash
    plan = _fetch_only_plan(owner, fetch_count=5, policy_hash=policy_hash)
    runtime.application.planner = _FixedPlanner(plan)
    slow = _SlowFetches(clock, seconds_per_fetch=15)
    runtime.application.fetches = cast(FetchExecutor, slow)
    renew_calls = 0
    leases = runtime.application.leases
    original_renew = leases.renew

    async def counting_renew(lease: Lease, *, now: datetime) -> Lease:
        nonlocal renew_calls
        renew_calls += 1
        return await original_renew(lease, now=now)

    leases.renew = counting_renew  # type: ignore[method-assign]

    answer = await runtime.application.ask(
        AskRequest(question="show ldap alerts", environment_id="alpha"),
        _principal(owner),
    )

    assert answer.status == AnswerStatus.answered
    assert slow.calls == 5
    assert clock.now() - NOW >= timedelta(seconds=75)
    assert renew_calls >= 1


class _PausingFetches:
    def __init__(self, result: FetchResult) -> None:
        self._result = result
        self.entered = asyncio.Event()
        self.resume = asyncio.Event()

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
        self.entered.set()
        await self.resume.wait()
        return self._result

    async def page(
        self,
        cursor: str,
        *,
        principal: VerifiedPrincipal,
        site: AuthorizedSite,
        execution: ExecutionContext,
    ) -> FetchResult:
        raise AssertionError("ask does not page")


@pytest.mark.asyncio
async def test_h1_renew_failure_mid_fetch_yields_lease_lost_and_releases_lease() -> None:
    from ai_soc.contracts.errors import public_error

    clock = _AdvancingClock(NOW)
    owner = "a" * 64
    runtime = _runtime(clock)
    policy_hash = runtime.application.site_policy.authorize(_principal(owner), "alpha").policy_hash
    question_id = uuid4()
    plan = _fetch_only_plan(owner, fetch_count=1, policy_hash=policy_hash).model_copy(
        update={"question_id": question_id}
    )
    runtime.application.planner = _FixedPlanner(plan)
    fetch_result = _mixed_fetch_result(
        "ldap", FetchState.rows, question_id=question_id, policy_hash=policy_hash
    )
    paused = _PausingFetches(fetch_result)
    runtime.application.fetches = cast(FetchExecutor, paused)

    release_calls = 0
    leases = runtime.application.leases
    original_release = leases.release

    async def counting_release(lease: Lease) -> None:
        nonlocal release_calls
        release_calls += 1
        await original_release(lease)

    leases.release = counting_release  # type: ignore[method-assign]

    original_renew = leases.renew

    async def failing_renew(lease: Lease, *, now: datetime) -> Lease:
        raise StateFailure(
            public_error(ErrorCode.LEASE_LOST, "fixture lease lost on renew", trace_id="a" * 32)
        )

    leases.renew = failing_renew  # type: ignore[method-assign]

    worker = asyncio.create_task(
        runtime.application.ask(
            AskRequest(question="show ldap alerts", environment_id="alpha"),
            _principal(owner),
        )
    )
    await asyncio.wait_for(paused.entered.wait(), timeout=2)
    clock.advance(21)
    await asyncio.sleep(0.15)
    paused.resume.set()
    with pytest.raises(StateFailure) as failure:
        await worker
    assert failure.value.code == ErrorCode.LEASE_LOST
    assert release_calls == 1
    leases.renew = original_renew  # type: ignore[method-assign]


@pytest.mark.asyncio
async def test_h1_renew_failure_after_commit_still_returns_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ai_soc.application.service import ApplicationService
    from ai_soc.contracts.errors import public_error

    async def renew_loop_raises_after_stop(
        self: ApplicationService,
        holder: list[Lease],
        stop: asyncio.Event,
        cancel: object,
    ) -> None:
        while not stop.is_set():
            await asyncio.sleep(0.01)
        raise StateFailure(
            public_error(ErrorCode.LEASE_LOST, "fixture renew after stop", trace_id="b" * 32)
        )

    monkeypatch.setattr(ApplicationService, "_lease_renewal_loop", renew_loop_raises_after_stop)

    owner = "a" * 64
    runtime = _runtime()
    policy_hash = runtime.application.site_policy.authorize(_principal(owner), "alpha").policy_hash
    question_id = uuid4()
    plan = _plan("fetch", owner=owner, question_id=question_id, policy_hash=policy_hash)
    runtime.application.planner = _FixedPlanner(plan)
    runtime.application.fetches = cast(
        FetchExecutor,
        _MixedFetches(
            {
                "ldap": _mixed_fetch_result(
                    "ldap", FetchState.rows, question_id=question_id, policy_hash=policy_hash
                )
            }
        ),
    )

    release_calls = 0
    leases = runtime.application.leases
    original_release = leases.release

    async def counting_release(lease: Lease) -> None:
        nonlocal release_calls
        release_calls += 1
        await original_release(lease)

    leases.release = counting_release  # type: ignore[method-assign]

    answer = await runtime.application.ask(
        AskRequest(question="show ldap alerts", environment_id="alpha"),
        _principal(owner),
    )

    assert answer.status == AnswerStatus.answered
    assert release_calls == 1
