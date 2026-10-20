"""ApplicationService stage spans, audit outcomes, and operational metrics."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID, uuid4

import httpx
import pytest
from pydantic import TypeAdapter

from ai_soc.application.composition import compose_soc
from ai_soc.config import ServiceConfig
from ai_soc.content.catalog import ContentCatalog
from ai_soc.contracts.models import (
    AskRequest,
    AuditEvent,
    AuthorizedSite,
    BuildProvenance,
    Count,
    CueCatalog,
    Effort,
    FetchResult,
    FetchScope,
    FetchSpec,
    FetchState,
    HTTPSUrl,
    IndexFamily,
    JudgmentRequest,
    ModelCapability,
    Planned,
    PlanProvenance,
    QuestionPlan,
    RawJudgment,
    ResolvedWindow,
    SiteConfig,
    SnapshotKind,
    SnapshotRef,
    StageName,
    TemplateId,
    TopicPlan,
    VerifiedPrincipal,
    Visibility,
)
from ai_soc.contracts.ports import ExecutionContext, FetchExecutor, JudgmentProvider
from ai_soc.identity.alb import AlbAssertionVerifier, McpBearerVerifier
from ai_soc.query.compiler import default_profile
from ai_soc.telemetry.audit_delivery import AuditTelemetry
from ai_soc.telemetry.audit_delivery import SqsClient as AuditSqsClient
from ai_soc.telemetry.events import TelemetryAdapter
from ai_soc.telemetry.metrics import FixtureMetricExporter, MetricName
from ai_soc.telemetry.outcomes import (
    begin_stage_outcomes,
    current_stage_outcomes,
    reset_stage_outcomes,
)
from ai_soc.telemetry.tracing import FixtureSpanExporter

NOW = datetime(2026, 10, 3, 12, tzinfo=UTC)


class _Clock:
    def now(self) -> datetime:
        return NOW

    def monotonic(self) -> float:
        return 0.0


class _Readiness:
    def ready(self) -> bool:
        return True


class _Kms:
    def sign(self, **kwargs: object) -> dict[str, object]:
        return {}


class _Sqs:
    def __init__(self) -> None:
        self.bodies: list[str] = []

    def send_message(self, *, QueueUrl: str, MessageBody: str) -> dict[str, object]:
        self.bodies.append(MessageBody)
        return {"MessageId": "fixture-message"}


class _LazyProvider(JudgmentProvider):
    async def count(self, request: JudgmentRequest, *, execution: ExecutionContext) -> int:
        raise AssertionError("fetch-only plan must not count tokens")

    async def converse(
        self, request: JudgmentRequest, *, execution: ExecutionContext
    ) -> RawJudgment:
        raise AssertionError("fetch-only plan must not converse")


class _FetchOnly(FetchExecutor):
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
        from hashlib import sha256

        from ai_soc.contracts.models import (
            EvidenceItem,
            EvidenceRow,
            EvidenceSourceRow,
            FieldId,
        )

        window = fetch.window
        row = EvidenceRow(
            evidence_id=f"ev1_{sha256(f'{question_id}:{topic_id}'.encode()).hexdigest()}",
            topic_id=topic_id,
            fetch_id="alerts",
            record_ref=None,
            values={FieldId.rule_id: "Synthetic alert"},
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
            values={FieldId.rule_id: "Synthetic alert"},
            visibility=Visibility.full,
            scope_hash=sha256(f"{question_id}:{topic_id}:scope".encode()).hexdigest(),
        )
        return FetchResult(
            fetch_id="alerts",
            topic_id=topic_id,
            state=FetchState.rows,
            scope=FetchScope(
                environment_id="alpha",
                template_id=TemplateId.alerts_rows_v1,
                index_family=IndexFamily.alerts,
                filters=[],
                visibility=Visibility.full,
                policy_hash=site.policy_hash,
                snapshot=SnapshotKind.first_page_only,
                displayed_rows=1,
            ),
            window=window,
            columns=[],
            rows=[row],
            count=Count(
                value=1,
                relation="eq",
                scope="matching_visible_records",
                computed_by="indexer",
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
            items=[item],
            error=None,
        )

    async def page(self, cursor: object, *, principal: object, site: object, execution: object):
        raise AssertionError("page not used")


class _Planner:
    def __init__(self, plan: QuestionPlan) -> None:
        self._plan = plan

    def plan(self, request: AskRequest, principal: VerifiedPrincipal, previous: object, **kwargs):
        assert previous is None
        return Planned(plan=self._plan)


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


def _plan(question_id: UUID, owner: str, policy_hash: str) -> QuestionPlan:
    window = ResolvedWindow(
        start=NOW - timedelta(hours=1),
        end=NOW,
        semantics="absolute",
        source_text="fixture interval",
        timezone="UTC",
        anchor_at=NOW,
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
        topics=[
            TopicPlan(
                topic_id="ldap",
                ordinal=0,
                document=False,
                failure=False,
                judgment=False,
                fetches=[
                    FetchSpec(
                        fetch_id="alerts",
                        template_id=TemplateId.alerts_rows_v1,
                        window=window,
                        filters=[],
                    )
                ],
                cue_ids=[],
                alias_ids=[],
            )
        ],
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


def _compose(spans: FixtureSpanExporter, metrics: FixtureMetricExporter, sqs: _Sqs | None = None):
    audit_sqs = sqs or _Sqs()
    config = ServiceConfig(
        mode="fixture",
        guardrail_identifier="fixture-guardrail",
        guardrail_version="1",
        sites=(_site(),),
        models=(_model(),),
    )
    catalog = ContentCatalog(
        _provenance(),
        CueCatalog(version="1", sha256="f" * 64, cues=[], aliases=[], ambiguities=[]),
        (),
        (),
    )
    return compose_soc(
        config,
        clock=_Clock(),
        catalog=catalog,
        state_client=None,
        state_table=None,
        kms=_Kms(),
        indexer_key_ids={"alpha": "fixture-key"},
        transport_for=lambda _site: httpx.AsyncClient(),
        mapping_profiles={"wazuh-v4-fixture": default_profile()},
        cursor_cipher=None,
        judgment_provider_factory=lambda _admission: _LazyProvider(),
        audit_client=cast(AuditSqsClient, audit_sqs),
        audit_queue_url="https://sqs.us-east-1.amazonaws.com/123456789012/audit",
        feedback_client=cast(AuditSqsClient, _Sqs()),
        feedback_queue_url="https://sqs.us-east-1.amazonaws.com/123456789012/feedback",
        span_exporter=spans,
        metric_exporter=metrics,
        receipt_keys={"fixture": b"k" * 32},
        current_receipt_key="fixture",
        csrf_secret=b"s" * 32,
        browser_origin="https://soc.example.test",
        alb_verifier=AlbAssertionVerifier(
            region="us-east-1",
            signer_arn="arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/soc/fixture",
            issuer="https://issuer.example.test",
            client_id="soc-client",
            groups_claim="groups",
            key_resolver=lambda _key_id: "fixture-key",
            now=_Clock().now,
        ),
        mcp_verifier=McpBearerVerifier(
            issuer="https://issuer.example.test",
            resource="https://soc.example.test/mcp",
            jwks_uri="https://issuer.example.test/.well-known/jwks.json",
            key_resolver=lambda _key_id: "fixture-key",
            now=_Clock().now,
            allowed_origins=frozenset({"https://soc.example.test"}),
        ),
        readiness=_Readiness(),
        standing_rules="fixture standing rules",
        mcp_issuer_url="https://issuer.example.test",
        mcp_resource_url="https://soc.example.test/mcp",
    )


@pytest.mark.asyncio
async def test_ask_emits_stage_spans_audit_outcomes_and_metrics() -> None:
    spans = FixtureSpanExporter()
    metrics = FixtureMetricExporter()
    audit_sqs = _Sqs()
    runtime = _compose(spans, metrics, audit_sqs)
    owner = "a" * 64
    principal = _principal(owner)
    policy_hash = runtime.application.site_policy.authorize(principal, "alpha").policy_hash
    question_id = uuid4()
    plan = _plan(question_id, owner, policy_hash)
    runtime.application.planner = _Planner(plan)  # type: ignore[method-assign]
    runtime.application.fetches = _FetchOnly()  # type: ignore[method-assign]

    answer = await runtime.application.ask(
        AskRequest(environment_id="alpha", question="show ldap alerts"),
        principal,
    )

    assert answer.question_id == question_id
    stage_names = [span.stage for span in spans.spans]
    for expected in (
        StageName.auth,
        StageName.plan,
        StageName.content,
        StageName.fetch,
        StageName.render,
        StageName.audit,
    ):
        assert expected in stage_names
    assert any(sample.name is MetricName.fetch_result for sample in metrics.samples)
    assert any(sample.name is MetricName.stage_latency for sample in metrics.samples)
    encoded = json.dumps([asdict(span) for span in spans.spans], default=str)
    for forbidden in (str(question_id), "show ldap alerts", owner, "fixture-analyst"):
        assert forbidden not in encoded

    assert audit_sqs.bodies
    audit_events = [AuditEvent.model_validate_json(body) for body in audit_sqs.bodies]
    attempted = next(event for event in audit_events if event.outcome == "attempted")
    assert attempted.stage_outcomes
    recorded_stages = {StageName(item.stage) for item in attempted.stage_outcomes}
    assert StageName.auth in recorded_stages
    assert StageName.fetch in recorded_stages
    assert StageName.audit in recorded_stages


def test_telemetry_adapter_stage_records_audit_outcomes() -> None:
    from ai_soc.contracts.models import TraceContext

    class _Clock:
        def now(self) -> datetime:
            return NOW

    spans = FixtureSpanExporter()
    metrics = FixtureMetricExporter()
    telemetry = TelemetryAdapter(
        audit=AuditTelemetry(_Sqs(), queue_url="https://sqs.example.test/audit", clock=_Clock()),
        spans=spans,
        metrics=metrics,
    )
    context = TraceContext(trace_id="a" * 32, span_id="b" * 16, trace_flags=1)
    token = begin_stage_outcomes()
    with telemetry.stage(StageName.plan, trace_context=context):
        pass
    assert len(current_stage_outcomes()) == 1
    assert StageName(current_stage_outcomes()[0].stage) is StageName.plan
    reset_stage_outcomes(token)


def test_stage_outcome_survives_export_failure() -> None:
    from ai_soc.contracts.models import TraceContext
    from ai_soc.telemetry.outcomes import (
        append_stage_outcome,
        begin_stage_outcomes,
        reset_stage_outcomes,
    )
    from ai_soc.telemetry.tracing import StageSpan, TraceSpan

    class FailingSpanExporter:
        def export(self, span: TraceSpan) -> None:
            raise RuntimeError("export down")

    class FailingMetricExporter:
        def emit(self, sample: object) -> None:
            raise RuntimeError("metrics down")

    token = begin_stage_outcomes()
    context = TraceContext(trace_id="a" * 32, span_id="b" * 16, trace_flags=1)
    with StageSpan(
        stage=StageName.validate,
        trace_context=context,
        spans=FailingSpanExporter(),
        metrics=FailingMetricExporter(),
        on_record=append_stage_outcome,
    ):
        pass
    assert StageName(current_stage_outcomes()[0].stage) is StageName.validate
    reset_stage_outcomes(token)
