from __future__ import annotations

import hashlib
import inspect
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import UUID

import pytest
from pydantic import TypeAdapter, ValidationError

from ai_soc.config import ServiceConfig
from ai_soc.contracts.canonical import canonical_bytes, evidence_id
from ai_soc.contracts.models import (
    AdmissionGrant,
    AnswerStatus,
    AskRequest,
    AuditAck,
    CallKind,
    CompletionCommand,
    CompletionReceipt,
    Count,
    EmbeddingGrant,
    ErrorCode,
    EvidenceSource,
    EvidenceSourceBucket,
    EvidenceSourceCheck,
    EvidenceSourceCount,
    EvidenceSourceProbe,
    EvidenceSourceRow,
    ExecutionContext,
    ExpectationDefinition,
    FeedbackMetadata,
    FeedbackReceipt,
    FieldId,
    Filter,
    FindingRelationAggregateScope,
    GoldenCase,
    GuardrailPin,
    HTTPSOrigin,
    HTTPSUrl,
    IdempotencyRecord,
    LocaleText,
    ModelCountGrant,
    PlaybookStep,
    QuestionBudget,
    ReadOperationGrant,
    RecordAgeStep,
    RecoveryPage,
    ResolvedWindow,
    StageCapacityRejection,
    StageOutcome,
    TopicPromptPack,
    TraceContext,
)
from ai_soc.contracts.ports import (
    AdmissionStore,
    Clock,
    CompletionStore,
    EmbeddingAdmissionStore,
    FetchExecutor,
    JudgmentProvider,
    ModelCountAdmissionStore,
    ReadAdmissionStore,
    RecoveryStore,
    Telemetry,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "v1"
ANCHOR = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
CONFIG_PROFILE_SHA256 = hashlib.sha256(
    (FIXTURES / "config_profile_inputs.json").read_bytes()
).hexdigest()


def config_profile_case(name: str) -> dict[str, object]:
    fixture = json.loads((FIXTURES / "config_profile_inputs.json").read_text("utf-8"))
    cases = cast(dict[str, object], fixture["cases"])
    return cast(dict[str, object], cases[name])


class FixtureCancellationToken:
    def is_cancelled(self) -> bool:
        return False

    def raise_if_cancelled(self) -> None:
        return None

    async def wait(self) -> None:
        return None


class FixtureCallLedger:
    def __init__(self) -> None:
        self.claims: list[CallKind] = []

    def claim(self, kind: CallKind) -> None:
        self.claims.append(kind)


def test_ask_request_strictness_and_wire_round_trip() -> None:
    valid = AskRequest(question="Check LDAP", environment_id="alpha", timezone="Europe/Madrid")
    assert AskRequest.model_validate_json(valid.model_dump_json()) == valid
    with pytest.raises(ValidationError):
        AskRequest.model_validate(
            {"question": "x", "environment_id": "alpha", "backend_roles": ["admin"]}
        )
    with pytest.raises(ValidationError):
        AskRequest.model_validate({"question": "x", "environment_id": "alpha", "effort": "high"})
    with pytest.raises(ValidationError):
        AskRequest.model_validate(
            {
                "question": "x",
                "environment_id": "alpha",
                "followup_id": "00000000-0000-4000-8000-000000000001",
            }
        )


def test_utf8_question_byte_boundaries() -> None:
    accepted = "x" * 16384
    AskRequest(question=accepted, environment_id="alpha")
    with pytest.raises(ValidationError):
        AskRequest(question="x" * 16385, environment_id="alpha")
    with pytest.raises(ValidationError):
        AskRequest(question="\u00e9" * 8193, environment_id="alpha")


def test_strict_count_filter_and_error_enums() -> None:
    with pytest.raises(ValidationError):
        Count(value=True, relation="eq", scope="matching_visible_records", computed_by="indexer")
    with pytest.raises(ValidationError):
        Count(value=-1, relation="eq", scope="matching_visible_records", computed_by="indexer")
    with pytest.raises(ValidationError):
        TypeAdapter(GuardrailPin).validate_python({"identifier": "fixture", "version": "DRAFT"})
    assert {item.value for item in ErrorCode} >= {
        "INDEXER_AUTH_REJECTED",
        "INVALID_MODEL_OUTPUT",
        "AUDIT_UNAVAILABLE",
        "REQUEST_COMPLETED",
        "REQUEST_ABANDONED",
        "INVALID_CONTINUATION",
        "REQUEST_TOO_LARGE",
        "REQUEST_COMPLEXITY",
    }
    assert {item.value for item in CallKind} == {
        "identity",
        "kms",
        "mapping",
        "validate",
        "pit",
        "search",
        "probe",
        "count",
        "converse",
        "embedding",
        "state",
        "feedback",
        "audit",
    }


def test_https_origins_and_bilingual_types_are_constrained() -> None:
    assert (
        TypeAdapter(HTTPSOrigin).validate_python("https://indexer.example.test:9200")
        == "https://indexer.example.test:9200"
    )
    assert str(TypeAdapter(HTTPSUrl).validate_json('"https://docs.example.test/setup"')).startswith(
        "https://"
    )
    for origin in (
        "http://indexer.example.test",
        "https://user@indexer.example.test",
        "https://indexer.example.test/path",
        "https://indexer.example.test:70000",
    ):
        with pytest.raises(ValidationError):
            TypeAdapter(HTTPSOrigin).validate_python(origin)
    with pytest.raises(ValidationError):
        TypeAdapter(HTTPSUrl).validate_json('"http://docs.example.test/setup"')
    assert LocaleText(en="LDAP", es="LDAP").es == "LDAP"
    with pytest.raises(ValidationError):
        LocaleText(en="LDAP")


def test_window_boundaries_timezone_and_dst() -> None:
    payload = {
        "start": "2026-03-28T12:00:00+00:00",
        "end": "2026-03-29T12:00:00+00:00",
        "semantics": "absolute",
        "source_text": "fixture absolute range",
        "timezone": "Europe/Madrid",
        "anchor_at": "2026-03-29T12:00:00+00:00",
    }
    window = ResolvedWindow.model_validate_json(json.dumps(payload))
    assert window.end - window.start == __import__("datetime").timedelta(hours=24)
    assert window.model_dump(mode="json")["start"].endswith("Z")
    for start, end in ((payload["end"], payload["end"]), (payload["end"], payload["start"])):
        invalid = {**payload, "start": start, "end": end}
        with pytest.raises(ValidationError):
            ResolvedWindow.model_validate_json(json.dumps(invalid))
    with pytest.raises(ValidationError):
        ResolvedWindow.model_validate(
            {
                **payload,
                "start": datetime(2026, 3, 28, 12),
                "end": datetime(2026, 3, 29, 12),
                "anchor_at": datetime(2026, 3, 29, 12),
            }
        )
    dst = json.loads((FIXTURES / "dst_windows.json").read_text("utf-8"))
    assert dst["timezone_database"] == "tzdata 2025.3"
    for case in dst["cases"]:
        start = datetime.fromisoformat(case["start"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(case["end"].replace("Z", "+00:00"))
        assert (end - start) == timedelta(hours=case["duration_hours"])
        ResolvedWindow(
            start=start,
            end=end,
            semantics="calendar",
            source_text=case["name"],
            timezone="Europe/Madrid",
            anchor_at=end,
        )


def test_finite_filter_and_window_resource_boundaries() -> None:
    in_16 = {"field": "agent.id", "op": "in", "value": [f"{index:03d}" for index in range(16)]}
    parsed = TypeAdapter(Filter).validate_json(json.dumps(in_16))
    assert len(parsed.value) == 16
    in_17 = {**in_16, "value": [f"{index:03d}" for index in range(17)]}
    with pytest.raises(ValidationError):
        TypeAdapter(Filter).validate_json(json.dumps(in_17))
    same = {"field": "agent.id", "op": "in", "value": ["007", "007"]}
    with pytest.raises(ValidationError):
        TypeAdapter(Filter).validate_json(json.dumps(same))
    with pytest.raises(ValidationError):
        TypeAdapter(Filter).validate_json(
            json.dumps({"field": "rule.level", "op": "eq", "value": "10"})
        )
    with pytest.raises(ValidationError):
        TypeAdapter(Filter).validate_json(
            json.dumps({"field": "data.srcip", "op": "eq", "value": "192.0.2.01"})
        )
    with pytest.raises(ValidationError):
        TypeAdapter(Filter).validate_json(
            json.dumps({"field": "vulnerability.id", "op": "eq", "value": "CVE-26-1"})
        )
    start = datetime(2026, 7, 2, 12, tzinfo=UTC)
    end = datetime(2026, 9, 30, 12, tzinfo=UTC)
    ResolvedWindow(
        start=start, end=end, semantics="absolute", source_text="90d", timezone="UTC", anchor_at=end
    )
    with pytest.raises(ValidationError):
        ResolvedWindow(
            start=start - timedelta(microseconds=1),
            end=end,
            semantics="absolute",
            source_text="90d+1us",
            timezone="UTC",
            anchor_at=end,
        )


def test_canonical_evidence_vectors_match_independent_oracles() -> None:
    source_vectors = json.loads((FIXTURES / "evidence_vectors.json").read_text("utf-8"))["vectors"]
    extra_vectors = json.loads((FIXTURES / "canonical_vectors.json").read_text("utf-8"))["vectors"]
    for vector in [*source_vectors, *extra_vectors]:
        input_value = cast(dict[str, object], vector["canonical_input"])
        assert "kind" not in cast(dict[str, object], input_value["source"])
        if vector in extra_vectors or input_value["kind"] == "row":
            source = cast(dict[str, object], input_value["source"])
            source_model = TypeAdapter(EvidenceSource).validate_json(json.dumps(source))
            assert source_model.model_dump(mode="json") == source
        encoded = canonical_bytes(input_value)
        assert encoded.decode("utf-8") == vector["canonical_utf8"]
        assert hashlib.sha256(encoded).hexdigest() == str(vector["expected_evidence_id"])[4:]
        assert (
            evidence_id(
                question_id=str(input_value["question_id"]),
                environment_id=str(input_value["environment_id"]),
                topic_id=str(input_value["topic_id"]),
                fetch_id=cast(str | None, input_value["fetch_id"]),
                check_id=cast(str | None, input_value["check_id"]),
                kind=str(input_value["kind"]),
                source=input_value["source"],
                snapshot_key=str(input_value["snapshot_key"]),
                values=input_value["values"],
            )
            == vector["expected_evidence_id"]
        )
    assert len({vector["expected_evidence_id"] for vector in extra_vectors}) == len(extra_vectors)


def test_evidence_source_shapes_match_section_five_and_reject_discriminator_drift() -> None:
    document = json.loads((FIXTURES / "evidence_source_shapes.json").read_text("utf-8"))
    assert document["mode"] == "fixture" and document["synthetic"] is True
    models = {
        "EvidenceSourceRow": EvidenceSourceRow,
        "EvidenceSourceBucket": EvidenceSourceBucket,
        "EvidenceSourceCount": EvidenceSourceCount,
        "EvidenceSourceProbe": EvidenceSourceProbe,
        "EvidenceSourceCheck": EvidenceSourceCheck,
    }
    for row in document["source_shapes"]:
        model_name = str(row["model"])
        model = models[model_name]
        source = cast(dict[str, object], row["source"])
        assert set(source) == set(model.model_fields)
        assert "kind" not in source
        validated = TypeAdapter(EvidenceSource).validate_json(json.dumps(source))
        assert validated.model_dump(mode="json") == source
        with pytest.raises(ValidationError):
            model.model_validate(
                {**source, "kind": model_name.removeprefix("EvidenceSource").lower()}
            )


def test_superseded_source_discrepancy_is_preserved_as_noncanonical_evidence() -> None:
    document = json.loads((FIXTURES / "canonical_source_discrepancy.json").read_text("utf-8"))
    assert document["mode"] == "fixture" and document["synthetic"] is True
    assert "docs/contracts.md \u00a75" in str(document["discrepancy"])
    old_vectors = document["prior_supplemental_vectors"]
    assert len(old_vectors) == 4
    assert {vector["name"] for vector in old_vectors} == {"probe", "bucket", "page-one", "page-two"}
    assert all("kind" in vector["canonical_input"]["source"] for vector in old_vectors)
    for vector in old_vectors:
        encoded = str(vector["canonical_utf8"]).encode("utf-8")
        assert hashlib.sha256(encoded).hexdigest() == str(vector["expected_evidence_id"])[4:]
        assert json.loads(encoded) == vector["canonical_input"]


def test_fixture_config_is_explicit_and_live_mode_fails_closed() -> None:
    fixture = ServiceConfig.model_validate_json(
        (ROOT / "config/examples/fixture.json").read_text("utf-8")
    )
    assert fixture.mode == "fixture"
    with pytest.raises(ValidationError):
        ServiceConfig(mode="live", guardrail_identifier="DRAFT", guardrail_version="0")
    with pytest.raises(ValidationError):
        ServiceConfig(
            mode="live",
            guardrail_identifier="fixture",
            guardrail_version="1",
            fixture_signing_key="ephemeral-only",
        )


@pytest.mark.case_id("B1-T01.config-profile")
@pytest.mark.variant("positive")
@pytest.mark.fixture_sha256(CONFIG_PROFILE_SHA256)
def test_config_profile_positive_accepts_numbered_fixture_guardrail() -> None:
    config = ServiceConfig.model_validate(config_profile_case("positive"))
    assert config.mode == "fixture"
    assert config.guardrail_identifier == "fixture-guardrail"
    assert config.guardrail_version == "1"


@pytest.mark.case_id("B1-T01.config-profile")
@pytest.mark.variant("negative")
@pytest.mark.fixture_sha256(CONFIG_PROFILE_SHA256)
def test_config_profile_negative_rejects_placeholder_and_live_fixture_mode() -> None:
    payload = config_profile_case("negative")
    with pytest.raises(ValidationError) as error:
        ServiceConfig.model_validate(payload)
    assert {item["loc"] for item in error.value.errors()} >= {
        ("guardrail_identifier",),
        ("guardrail_version",),
    }


@pytest.mark.case_id("B1-T01.config-profile")
@pytest.mark.variant("boundary")
@pytest.mark.fixture_sha256(CONFIG_PROFILE_SHA256)
def test_config_profile_boundary_requires_positive_numeric_version() -> None:
    payload = config_profile_case("boundary")
    accepted = cast(dict[str, object], payload["accepted"])
    rejected = cast(dict[str, object], payload["rejected"])
    assert ServiceConfig.model_validate(accepted).guardrail_version == "1"
    with pytest.raises(ValidationError) as error:
        ServiceConfig.model_validate(rejected)
    assert ("guardrail_version",) in {item["loc"] for item in error.value.errors()}


@pytest.mark.case_id("B1-T01.config-profile")
@pytest.mark.variant("failure")
@pytest.mark.fixture_sha256(CONFIG_PROFILE_SHA256)
def test_config_profile_failure_rejects_fixture_signing_material_in_live_mode() -> None:
    payload = config_profile_case("failure")
    with pytest.raises(ValidationError) as error:
        ServiceConfig.model_validate(payload)
    assert any("fixture" in str(item["msg"]).lower() for item in error.value.errors())


def test_all_review_seams_are_constructible_and_typed() -> None:
    key = "a" * 64
    question_id = UUID("00000000-0000-4000-8000-000000000001")
    ack = AuditAck(event_id=question_id, delivery_id="fixture-delivery", accepted_at=ANCHOR)
    grant = AdmissionGrant(
        holder_id=question_id, slot_ids=("fixture-slot",), expires_at=ANCHOR, fence=1
    )
    recovery = RecoveryPage(after=None, examined=1, terminalized=1, errors=[ErrorCode.INTERNAL])
    topic_pack = TopicPromptPack(
        topic_id="ldap", language="en", content_sha="0" * 40, sha256=key, missing=["playbook"]
    )
    expectation = ExpectationDefinition(
        expectation_id="ldap_count",
        topic_id="ldap",
        field=FieldId.rule_id,
        op="eq",
        value="5710",
        source="content",
        version="1",
    )
    relation = FindingRelationAggregateScope(
        kind="aggregate_scope", count_binding="count", entity_bindings={"agent": FieldId.agent_id}
    )
    receipt = FeedbackReceipt(token="fixture-aead-token", status="issued")
    budget = QuestionBudget(
        question_id=question_id,
        token_limit=1000,
        reserved_tokens=0,
        charged_tokens=0,
        remaining_tokens=1000,
        version=1,
        overflow_tokens=0,
        state="open",
        owner_key=key,
        environment_id="alpha",
        created_at=ANCHOR,
    )
    idempotency = IdempotencyRecord(
        owner_key=key,
        environment_id="alpha",
        key=question_id,
        request_hash=key,
        question_id=question_id,
        status="active",
        expires_at=ANCHOR,
    )
    completion = CompletionCommand(
        question_id=question_id,
        owner_key=key,
        environment_id="alpha",
        answer_status=AnswerStatus.answered,
        followup=None,
        idempotency=idempotency,
        audit_ack=ack,
        metadata_sha256=key,
    )
    result = CompletionReceipt(
        completion_id=question_id,
        question_id=question_id,
        committed_at=ANCHOR,
        followup_id=None,
        followup_revision=None,
        answer_metadata_sha256=key,
    )
    ledger = FixtureCallLedger()
    execution = ExecutionContext(
        question_id=question_id,
        operation="ask",
        owner_key=key,
        environment_id="alpha",
        deadline_at=ANCHOR,
        cancel=FixtureCancellationToken(),
        calls=ledger,
        admission=grant,
        trace_context=TraceContext(trace_id="1" * 32, span_id="2" * 16, trace_flags=1),
    )
    execution.calls.claim(CallKind.audit)
    assert (
        recovery.terminalized,
        topic_pack.topic_id,
        expectation.version,
        relation.kind,
        receipt.status,
        budget.remaining_tokens,
        completion.audit_ack,
        result.completion_id,
    ) == (1, "ldap", "1", "aggregate_scope", "issued", 1000, ack, question_id)
    assert grant.fence == 1 and StageOutcome.cancelled.value == "cancelled"
    assert execution.operation == "ask" and ledger.claims == [CallKind.audit]
    assert Clock and CompletionStore and RecoveryStore and AdmissionStore


def test_async_port_boundaries_and_keyword_contracts() -> None:
    assert inspect.iscoroutinefunction(FetchExecutor.execute)
    assert inspect.iscoroutinefunction(FetchExecutor.page)
    assert (
        inspect.signature(FetchExecutor.execute).parameters["execution"].kind
        is inspect.Parameter.KEYWORD_ONLY
    )
    assert inspect.iscoroutinefunction(JudgmentProvider.count)
    assert inspect.iscoroutinefunction(JudgmentProvider.converse)
    assert inspect.signature(Telemetry.event).return_annotation == "AuditAck"
    assert inspect.signature(RecoveryStore.reconcile).parameters["page_size"].default == 100
    for port in (ReadAdmissionStore, ModelCountAdmissionStore, EmbeddingAdmissionStore):
        assert inspect.iscoroutinefunction(port.acquire)
        assert inspect.iscoroutinefunction(port.release)
        assert (
            inspect.signature(port.acquire).parameters["now"].kind is inspect.Parameter.KEYWORD_ONLY
        )


def test_physical_stage_grants_are_finite_fenced_and_bounded() -> None:
    question_id = UUID("00000000-0000-4000-8000-000000000010")
    holder_id = UUID("00000000-0000-4000-8000-000000000011")
    operation_id = UUID("00000000-0000-4000-8000-000000000012")
    read_deadline = ANCHOR + timedelta(seconds=10)
    read = ReadOperationGrant(
        question_id=question_id,
        environment_id="alpha",
        operation_id=operation_id,
        call="search",
        holder_id=holder_id,
        service_slot_id="read-service-00",
        site_slot_id="read-alpha-00",
        fence=1,
        acquired_at=ANCHOR,
        lease_expires_at=read_deadline,
        hard_deadline_at=read_deadline,
        recover_after=read_deadline + timedelta(seconds=35),
    )
    model_deadline = ANCHOR + timedelta(seconds=30)
    converse = ModelCountGrant(
        question_id=question_id,
        environment_id="alpha",
        operation_id=operation_id,
        call="converse",
        holder_id=holder_id,
        service_slot_id="model-service-00",
        site_slot_id="model-alpha-00",
        fence=2,
        acquired_at=ANCHOR,
        lease_expires_at=model_deadline,
        hard_deadline_at=model_deadline,
        recover_after=model_deadline + timedelta(seconds=35),
    )
    count_deadline = ANCHOR + timedelta(seconds=5)
    count = ModelCountGrant(
        question_id=question_id,
        environment_id="alpha",
        operation_id=operation_id,
        call="count",
        holder_id=holder_id,
        service_slot_id="model-service-01",
        site_slot_id="model-alpha-01",
        fence=3,
        acquired_at=ANCHOR,
        lease_expires_at=count_deadline,
        hard_deadline_at=count_deadline,
        recover_after=count_deadline + timedelta(seconds=35),
    )
    embedding_deadline = ANCHOR + timedelta(seconds=10)
    embedding = EmbeddingGrant(
        question_id=question_id,
        environment_id="alpha",
        operation_id=operation_id,
        holder_id=holder_id,
        fence=4,
        acquired_at=ANCHOR,
        lease_expires_at=embedding_deadline,
        hard_deadline_at=embedding_deadline,
        recover_after=embedding_deadline + timedelta(seconds=35),
    )
    rejected = StageCapacityRejection(
        question_id=question_id, operation_id=operation_id, call="count"
    )
    embedding_rejected = StageCapacityRejection(
        question_id=question_id, operation_id=operation_id, call="embedding"
    )
    assert read.call == "search" and read.site_slot_id == "read-alpha-00"
    assert (converse.call, count.call, embedding.call) == ("converse", "count", "embedding")
    assert rejected.code is ErrorCode.CAPACITY_LIMIT and rejected.outcome == "capacity"
    assert embedding_rejected.call == "embedding"
    assert embedding_rejected.code is ErrorCode.CAPACITY_LIMIT
    assert embedding_rejected.outcome == "capacity"
    for model, patch in (
        (read, {"call": "count"}),
        (read, {"hard_deadline_at": read_deadline - timedelta(microseconds=1)}),
        (converse, {"hard_deadline_at": ANCHOR + timedelta(seconds=5)}),
        (count, {"call": "wildcard"}),
        (embedding, {"recover_after": embedding_deadline + timedelta(seconds=34)}),
        (rejected, {"call": "wildcard"}),
        (embedding_rejected, {"call": "wildcard"}),
    ):
        with pytest.raises(ValidationError):
            type(model).model_validate({**model.model_dump(), **patch})


def test_independent_bilingual_planning_oracles_are_fixture_only() -> None:
    fixture = json.loads((FIXTURES / "planning_oracles.json").read_text("utf-8"))
    assert fixture["mode"] == "fixture"
    cases = {case["id"]: case for case in fixture["cases"]}
    assert (
        cases["oracle-en-ldap-failure-judgment"]["expected"]["topics"]
        == cases["oracle-es-ldap-failure-judgment"]["expected"]["topics"]
    )
    assert cases["oracle-en-document-only"]["expected"]["backend_calls"] == {
        "indexer": 0,
        "count": 0,
        "converse": 0,
    }
    assert cases["oracle-es-document-only"]["expected"]["backend_calls"] == {
        "indexer": 0,
        "count": 0,
        "converse": 0,
    }


def test_feedback_metadata_is_strict_and_scalar() -> None:
    value = {
        "feedback_id": "12345678-1234-5678-1234-567812345678",
        "status": "pending",
        "created_at": "2026-09-30T12:00:00Z",
        "ttl_epoch": 1_800_000_000,
    }
    record = FeedbackMetadata.model_validate_json(json.dumps(value))
    assert record.feedback_id == UUID(value["feedback_id"])
    assert record.status == "pending"
    assert record.ttl_epoch == 1_800_000_000
    for patch in (
        {"status": "sending"},
        {"schema_version": "2"},
        {"feedback_id": "invalid"},
        {"created_at": "not-a-time"},
        {"ttl_epoch": -1},
        {"ttl_epoch": True},
        {"note": "private"},
    ):
        with pytest.raises(ValidationError):
            FeedbackMetadata.model_validate_json(json.dumps({**value, **patch}))


def test_golden_case_positive_negative_boundary_and_failure_execute() -> None:
    registry = json.loads((FIXTURES / "contract_cases.json").read_text("utf-8"))
    assert registry["mode"] == "fixture"
    cases = [TypeAdapter(GoldenCase).validate_json(json.dumps(item)) for item in registry["cases"]]
    assert {case.variant for case in cases} == {"positive", "negative", "boundary", "failure"}
    by_id = {case.case_id: case for case in cases}
    positive = by_id["B1-T02.strict-positive"].input.payload
    AskRequest.model_validate(positive)
    negative = by_id["B1-T02.strict-negative"].input.payload
    with pytest.raises(ValidationError):
        AskRequest.model_validate(negative)
    AskRequest(question="x" * 16384, environment_id="alpha")
    with pytest.raises(ValidationError):
        AskRequest(question="x" * 16385, environment_id="alpha")
    failure = by_id["B1-T02.window-failure"].input.payload
    with pytest.raises(ValidationError):
        ResolvedWindow.model_validate_json(
            json.dumps(
                {**failure, "semantics": "absolute", "source_text": "empty", "timezone": "UTC"}
            )
        )


def test_record_age_step_is_strict_and_additive_in_playbook_union() -> None:
    step = {
        "kind": "record_age",
        "step_id": "auth_recency",
        "check_id": "auth_recency_check",
        "label": {"en": "Recent auth record", "es": "Registro reciente"},
        "fetch_id": "auth_rows",
        "max_age_seconds": 3600,
    }
    parsed = TypeAdapter(PlaybookStep).validate_python(step)
    assert isinstance(parsed, RecordAgeStep)
    assert parsed.max_age_seconds == 3600
    assert TypeAdapter(PlaybookStep).validate_json(json.dumps(step)) == parsed

    for bad in (
        {**step, "max_age_seconds": 0},
        {**step, "max_age_seconds": -1},
        {**step, "max_age_seconds": 3600.5},
        {**step, "max_age_seconds": "3600"},
        {**step, "test": "returned_record_age"},
        {key: value for key, value in step.items() if key != "max_age_seconds"},
    ):
        with pytest.raises(ValidationError):
            TypeAdapter(PlaybookStep).validate_python(bad)
