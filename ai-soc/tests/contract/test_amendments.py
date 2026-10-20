from __future__ import annotations

import inspect
import json
from datetime import UTC, datetime
from importlib.metadata import distribution, version
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import TypeAdapter, ValidationError

from ai_soc.contracts.models import (
    AnswerStatus,
    AuditEvent,
    AuditFetchRecord,
    Count,
    FetchState,
    PolicyHash,
    QuestionPlan,
    RemovedReason,
    SemanticSuggestion,
    StageAttributes,
    StageName,
    StageOutcome,
    TemplateId,
    TopicDefinition,
    TraceContext,
)
from ai_soc.contracts.ports import (
    EmbeddingProvider,
    Planner,
    PlanStore,
    SemanticSuggester,
    Telemetry,
)

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
HASH = "a" * 64


def test_semantic_suggestion_is_finite_and_boundary_typed() -> None:
    suggestion = SemanticSuggestion(
        topic_id="ldap",
        score=0.8,
        margin=0.0,
        model_id="fixture-model",
        qualifies=False,
        near_threshold=True,
    )
    assert suggestion.margin == 0.0
    for score in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValidationError):
            SemanticSuggestion(
                topic_id="ldap",
                score=score,
                margin=0.1,
                model_id="fixture-model",
                qualifies=False,
                near_threshold=False,
            )
    with pytest.raises(ValidationError):
        SemanticSuggestion(
            topic_id="ldap",
            score=0.8,
            margin=-0.1,
            model_id="fixture-model",
            qualifies=False,
            near_threshold=False,
        )
    with pytest.raises(ValidationError):
        SemanticSuggestion(
            topic_id="ldap",
            score=0.8,
            margin=0.1,
            model_id="fixture-model",
            qualifies=True,
            near_threshold=True,
        )
    assert inspect.iscoroutinefunction(SemanticSuggester.suggest)
    assert (
        inspect.signature(SemanticSuggester.suggest).return_annotation
        == "SemanticSuggestion | None"
    )
    assert inspect.iscoroutinefunction(EmbeddingProvider.embed)
    assert (
        inspect.signature(EmbeddingProvider.embed).return_annotation
        == "tuple[tuple[float, ...], ...]"
    )


def test_trace_context_and_span_attributes_are_explicit_and_bounded() -> None:
    context = TraceContext(trace_id="1" * 32, span_id="2" * 16, trace_flags=1)
    assert context.trace_flags == 1
    assert StageName.fetch.value == "fetch"
    assert StageName("count") is StageName.count_stage
    attributes = StageAttributes(outcome=StageOutcome.ok, latency_ms=0, fetch_state=FetchState.rows)
    assert attributes.latency_ms == 0
    for values in (
        {"trace_id": "0" * 32, "span_id": "2" * 16, "trace_flags": 1},
        {"trace_id": "1" * 32, "span_id": "0" * 16, "trace_flags": 1},
        {"trace_id": "1" * 32, "span_id": "2" * 16, "trace_flags": 256},
    ):
        with pytest.raises(ValidationError):
            TraceContext.model_validate(values)
    with pytest.raises(ValidationError):
        StageAttributes.model_validate({"outcome": "ok", "question_id": "private"})
    assert (
        inspect.signature(Telemetry.stage).parameters["trace_context"].kind
        is inspect.Parameter.KEYWORD_ONLY
    )


def test_audit_event_records_safe_complete_provenance_and_rejects_content() -> None:
    event = AuditEvent(
        event_id=UUID("00000000-0000-4000-8000-000000000001"),
        question_id=UUID("00000000-0000-4000-8000-000000000002"),
        trace_id="1" * 32,
        owner_key=HASH,
        environment_id="alpha",
        authenticated_issuer="https://issuer.example.test",
        auth_edge="fixture",
        service_sha="b" * 40,
        image_digest="sha256:" + "c" * 64,
        content_sha="d" * 40,
        pack_sha256=HASH,
        policy_hash=HASH,
        cue_ids=["ldap"],
        topic_ids=["ldap"],
        stage_outcomes=[{"stage": StageName.fetch, "outcome": StageOutcome.ok, "latency_ms": 0}],
        removed_findings=[
            {
                "topic_id": "ldap",
                "finding_id": "f-1",
                "reason": RemovedReason.unknown_evidence,
                "candidate_sha256": HASH,
            }
        ],
        usage_by_topic=[
            {
                "topic_id": "ldap",
                "input_tokens": 12,
                "output_tokens": 3,
                "cache_read_input_tokens": 0,
                "cache_write_input_tokens": 0,
                "total_input_tokens": 12,
                "reserved_tokens": 16,
                "reservation_id": UUID("00000000-0000-4000-8000-000000000004"),
            }
        ],
        answer_status=AnswerStatus.answered,
        outcome="completed",
        completion_id=UUID("00000000-0000-4000-8000-000000000003"),
        created_at=NOW,
    )
    dumped = event.model_dump_json()
    assert 'question"' not in dumped and "provider_output" not in dumped
    wire = json.loads(dumped)
    for outcome in ("attempted", "cancelled"):
        terminal = {
            **wire,
            "outcome": outcome,
            "completion_id": None,
            "answer_status": None,
        }
        assert AuditEvent.model_validate_json(json.dumps(terminal)).outcome == outcome
    event_values = event.model_dump()
    event_values["stage_outcomes"] = [
        {"stage": StageName.fetch, "outcome": StageOutcome.ok, "latency_ms": 0}
    ]
    event_values["removed_findings"][0]["reason"] = RemovedReason.unknown_evidence
    for key in ("raw_rows", "prompt", "provider_output"):
        with pytest.raises(ValidationError):
            AuditEvent.model_validate({**event_values, key: "must-not-cross-contract"})
    with pytest.raises(ValidationError):
        AuditEvent.model_validate({**event_values, "outcome": "attempted"})


def test_fetch_audit_exactness_matches_count_quality() -> None:
    window = {
        "start": NOW.replace(hour=10),
        "end": NOW.replace(hour=11),
        "semantics": "absolute",
        "source_text": "fixture interval",
        "timezone": "UTC",
        "anchor_at": NOW,
    }
    base = {
        "scope_hash": HASH,
        "window": window,
        "template_id": TemplateId.alerts_rows_v1,
        "query_sha256": HASH,
        "result_classification": FetchState.rows,
    }
    exact = Count(value=0, relation="eq", scope="matching_visible_records", computed_by="indexer")
    assert (
        AuditFetchRecord.model_validate({**base, "count": exact, "count_exact": True}).count_exact
        is True
    )
    approximate = Count(
        value=0, relation="gte", scope="matching_visible_records", computed_by="indexer"
    )
    with pytest.raises(ValidationError):
        AuditFetchRecord.model_validate({**base, "count": approximate, "count_exact": True})
    with pytest.raises(ValidationError):
        AuditFetchRecord.model_validate({**base, "count": None, "count_exact": False})


def test_opentelemetry_components_are_exact_and_importable() -> None:
    assert version("opentelemetry-api") == "1.45.0"
    assert version("opentelemetry-sdk") == "1.45.0"
    assert version("opentelemetry-exporter-otlp-proto-grpc") == "1.45.0"
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.trace import TracerProvider

    assert OTLPSpanExporter and TracerProvider
    scripts = {
        entry.name: entry.value
        for entry in distribution("ai-soc").entry_points
        if entry.group == "console_scripts"
    }
    assert scripts["ai-soc-content"] == "ai_soc.content.cli:main"


def test_topic_definition_is_a_strict_versioned_source_record() -> None:
    record = TopicDefinition.model_validate_json(
        json.dumps(
            {
                "topic_id": "ldap",
                "name": {"en": "LDAP", "es": "LDAP"},
                "aliases": [],
                "finding_template_ids": [],
                "fetch_bindings": [],
            }
        )
    )
    assert record.schema_version == "1"
    assert TopicDefinition.model_validate_json(record.model_dump_json()).schema_version == "1"
    invalid_records = (
        {**record.model_dump(), "schema_version": "2"},
        {**record.model_dump(), "unknown_source_field": True},
    )
    for invalid in invalid_records:
        with pytest.raises(ValidationError):
            TopicDefinition.model_validate(invalid)


def test_planner_and_store_require_current_valid_policy_binding() -> None:
    oracle = json.loads(
        (Path(__file__).resolve().parents[1] / "fixtures/v1/policy_binding_oracles.json").read_text(
            "utf-8"
        )
    )
    assert oracle["mode"] == "fixture"
    positive, stale = oracle["cases"]
    assert positive["expected"] == "plan-uses-current-authorized-policy"
    assert stale["expected"] == "reject-before-planning"
    positive_policy = TypeAdapter(PolicyHash).validate_python(positive["current_policy_hash"])
    current_policy = TypeAdapter(PolicyHash).validate_python(stale["current_policy_hash"])
    stale_or_foreign_policy = TypeAdapter(PolicyHash).validate_python(
        stale["prior_plan_policy_hash"]
    )
    assert positive_policy == positive["current_policy_hash"]
    assert current_policy == stale["current_policy_hash"]
    assert current_policy != stale_or_foreign_policy

    planner_signature = inspect.signature(Planner.plan)
    planner_policy = planner_signature.parameters["policy_hash"]
    assert planner_policy.kind is inspect.Parameter.KEYWORD_ONLY
    assert planner_policy.default is inspect.Parameter.empty
    assert planner_policy.annotation == "PolicyHash"
    bound_plan = planner_signature.bind(
        object(), object(), object(), object(), policy_hash=current_policy, clock=object()
    )
    assert bound_plan.arguments["policy_hash"] == current_policy
    with pytest.raises(TypeError):
        planner_signature.bind(object(), object(), object(), object(), clock=object())

    store_signature = inspect.signature(PlanStore.load)
    for name in ("owner_key", "environment_id", "policy_hash", "content_sha"):
        parameter = store_signature.parameters[name]
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
        assert parameter.default is inspect.Parameter.empty
    assert store_signature.parameters["policy_hash"].annotation == "PolicyHash"
    assert {
        name: store_signature.parameters[name].annotation
        for name in ("owner_key", "environment_id", "policy_hash", "content_sha")
    } == {
        "owner_key": "SHA256",
        "environment_id": "ContentId",
        "policy_hash": "PolicyHash",
        "content_sha": "GitSHA40",
    }
    bound_load = store_signature.bind(
        object(),
        object(),
        owner_key="c" * 64,
        environment_id="alpha",
        revision=1,
        policy_hash=current_policy,
        content_sha="d" * 40,
        now=NOW,
    )
    assert bound_load.arguments["policy_hash"] == current_policy
    for invalid_hash in ("0" * 64, "not-a-hash", "A" * 64):
        with pytest.raises(ValidationError):
            TypeAdapter(PolicyHash).validate_python(invalid_hash)

    plan_input = {
        "question_id": "00000000-0000-4000-8000-000000000021",
        "environment_id": "alpha",
        "owner_key": "c" * 64,
        "content_sha": "d" * 40,
        "policy_hash": positive_policy,
        "language": "en",
        "timezone": "UTC",
        "anchor_at": NOW.isoformat(),
        "topics": [],
        "provenance": {
            "cue_pack_sha": HASH,
            "normalized_question_hash": HASH,
            "origin": "new",
            "previous_question_id": None,
            "matched_spans": [],
        },
    }
    current_plan = QuestionPlan.model_validate_json(json.dumps(plan_input))
    assert current_plan.policy_hash == positive_policy
    with pytest.raises(ValidationError):
        QuestionPlan.model_validate_json(json.dumps({**plan_input, "policy_hash": "0" * 64}))
