"""Strict immutable catalog snapshot barriers captured before the runner awaits."""

from __future__ import annotations

import json
from collections.abc import Callable
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID, uuid4

import pytest

from ai_soc.application.topic_judgment import QuestionBudgetHandle, TopicJudgment
from ai_soc.content.finding_catalog import TOPIC_CONTEXT_LABEL, catalog_bytes
from ai_soc.contracts.canonical import canonical_bytes
from ai_soc.contracts.models import (
    SHA256,
    AdmissionGrant,
    CallKind,
    CheckOutcome,
    CheckResult,
    Effort,
    EvidenceItem,
    EvidencePack,
    EvidenceSourceCheck,
    EvidenceSourceRow,
    ExecutionContext,
    FieldId,
    FindingRelationSameRecord,
    FindingTemplate,
    GuardrailPin,
    JudgmentRequest,
    JudgmentResult,
    JudgmentState,
    Lease,
    LeftOut,
    LeftOutReason,
    LocaleText,
    ModelCapability,
    RawJudgment,
    RemovedReason,
    RequiredCheckOutcome,
    Reservation,
    SnapshotKind,
    SnapshotRef,
    TopicId,
    TopicPromptPack,
    TraceContext,
    ValidationContext,
    Visibility,
)
from ai_soc.judgment.bedrock import BedrockJudgmentProvider
from ai_soc.judgment.catalog import CatalogUnavailable, capture_catalog_snapshot
from ai_soc.validation.findings import FindingValidator

NOW = datetime(2026, 1, 1, tzinfo=UTC)
OWNER = "a" * 64


def _model() -> ModelCapability:
    return ModelCapability(
        id="fixture-model",
        label="Fixture model",
        region="us-east-1",
        resource_arns=("arn:aws:bedrock:us-east-1:123456789012:inference-profile/fixture",),
        context_tokens=4096,
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
        primary_doc_url="https://docs.example.test/model",
    )


def _template(*, template_id: str = "ldap_observation", topic_id: str = "ldap") -> FindingTemplate:
    return FindingTemplate(
        template_id=template_id,
        topic_id=topic_id,
        kind="observation",
        required_bindings={"rule": (FieldId.rule_id,)},
        texts=LocaleText(en="Observed rule: {rule}", es="Regla observada: {rule}"),
        required_check_outcomes=[],
        allowed_evidence_kinds=["row"],
    )


def _triple(
    *,
    templates: tuple[FindingTemplate, ...] | None = None,
    context_templates: tuple[FindingTemplate, ...] | None = None,
    checks: tuple[CheckResult, ...] = (),
    items: tuple[EvidenceItem, ...] = (),
    language: str = "en",
    question: str = "Q",
) -> tuple[JudgmentRequest, EvidencePack, ValidationContext]:
    question_id = uuid4()
    chosen = (_template(),) if templates is None else templates
    context_chosen = chosen if context_templates is None else context_templates
    evidence = EvidencePack(
        question_id=question_id,
        environment_id="alpha",
        topic_id="ldap",
        policy_hash="2" * 64,
        content_sha="a" * 40,
        fetches=[],
        checks=list(checks),
        items=list(items),
        sha256="3" * 64,
    )
    pack = TopicPromptPack(
        topic_id="ldap",
        language=language,
        content_sha="a" * 40,
        sha256="4" * 64,
        document_section="DOC",
        internal_context="CTX",
        missing=[],
    )
    request = JudgmentRequest(
        question_id=question_id,
        topic_id="ldap",
        model=_model(),
        effort=Effort.low,
        language=language,
        standing_rules="RULES",
        topic_pack=pack,
        evidence=evidence,
        question=question,
        max_output_tokens=512,
        guardrail=GuardrailPin(identifier="gr-1", version="1"),
        finding_templates=chosen,
    )
    context = ValidationContext(
        topic_pack=pack,
        templates=context_chosen,
        policy_hash=evidence.policy_hash,
        content_sha=evidence.content_sha,
        language=language,
        expected_checks=checks,
    )
    return request, evidence, context


def test_snapshot_capture_preserves_catalog_bytes_against_post_capture_mutation() -> None:
    request, pack, context = _triple()
    original = request.finding_templates[0].texts.en
    snapshot = capture_catalog_snapshot(request, pack, context)

    request.finding_templates[0].texts.__dict__["en"] = "CORRUPTED"
    context.__dict__["templates"] = ()

    templates = snapshot.templates()
    assert templates[0].texts.en == original
    assert snapshot.request_view(request).finding_templates[0].texts.en == original
    assert snapshot.validation_context().templates[0].texts.en == original


def test_snapshot_templates_are_distinct_detached_reconstructions() -> None:
    request, pack, context = _triple()
    snapshot = capture_catalog_snapshot(request, pack, context)

    first = snapshot.templates()
    second = snapshot.templates()
    assert first == second
    assert first[0] is not second[0]
    first[0].texts.__dict__["en"] = "CORRUPTED"
    assert second[0].texts.en == "Observed rule: {rule}"
    assert snapshot.templates()[0].texts.en == "Observed rule: {rule}"


def test_snapshot_request_views_are_fresh_per_call_and_freeze_catalog() -> None:
    request, pack, context = _triple()
    snapshot = capture_catalog_snapshot(request, pack, context)

    count_view = snapshot.request_view(request)
    converse_view = snapshot.request_view(request)
    assert count_view is not converse_view
    assert count_view.evidence is not converse_view.evidence
    assert count_view.topic_pack is not converse_view.topic_pack
    assert count_view.finding_templates[0] is not converse_view.finding_templates[0]
    count_view.finding_templates[0].texts.__dict__["en"] = "CORRUPTED"
    assert converse_view.finding_templates[0].texts.en == "Observed rule: {rule}"
    assert snapshot.templates()[0].texts.en == "Observed rule: {rule}"


def test_snapshot_rejects_request_and_context_catalog_byte_mismatch() -> None:
    request, pack, context = _triple(
        templates=(_template(),),
        context_templates=(_template(template_id="ldap_other"),),
    )
    with pytest.raises(CatalogUnavailable, match="catalogs disagree"):
        capture_catalog_snapshot(request, pack, context)

    request, pack, context = _triple()
    changed = _template().model_copy(update={"allowed_evidence_kinds": ["check"]})
    context = context.model_copy(update={"templates": (changed,)})
    with pytest.raises(CatalogUnavailable, match="catalogs disagree"):
        capture_catalog_snapshot(request, pack, context)


@pytest.mark.parametrize("corruption", ["wrong_nested_model", "bool_as_field_id"])
def test_snapshot_rejects_nested_corruption_through_strict_reconstruction(
    corruption: str,
) -> None:
    request, pack, context = _triple()
    if corruption == "wrong_nested_model":
        request.finding_templates[0].__dict__["texts"] = "not-a-locale-text"
    else:
        request.finding_templates[0].required_bindings["rule"] = (True,)
    with pytest.raises(CatalogUnavailable):
        capture_catalog_snapshot(request, pack, context)


def test_snapshot_rejects_duplicate_catalog_ids_including_identical() -> None:
    template = _template()
    request, pack, context = _triple(templates=(template, template))
    with pytest.raises(CatalogUnavailable, match="shared strict rule"):
        capture_catalog_snapshot(request, pack, context)


def test_snapshot_rejects_empty_catalog() -> None:
    request, pack, context = _triple(templates=())
    with pytest.raises(CatalogUnavailable, match="shared strict rule"):
        capture_catalog_snapshot(request, pack, context)


def test_snapshot_rejects_oversized_catalog() -> None:
    overflow = tuple(_template(template_id=f"ldap_obs_{index:02d}") for index in range(21))
    request, pack, context = _triple(templates=overflow)
    with pytest.raises(CatalogUnavailable, match="shared strict rule"):
        capture_catalog_snapshot(request, pack, context)


def test_snapshot_rejects_foreign_topic_check_evidence() -> None:
    check = CheckResult(
        check_id="ldap_check",
        topic_id="vpn",
        label="check",
        outcome=CheckOutcome.passed,
        evidence_ids=[],
        message="passed",
    )
    request, pack, context = _triple(checks=(check,))
    with pytest.raises(CatalogUnavailable, match="foreign topic"):
        capture_catalog_snapshot(request, pack, context)


def test_snapshot_rejects_disagreeing_expected_checks() -> None:
    check = CheckResult(
        check_id="ldap_check",
        topic_id="ldap",
        label="check",
        outcome=CheckOutcome.passed,
        evidence_ids=[],
        message="passed",
    )
    request, pack, context = _triple()
    context = context.model_copy(update={"expected_checks": (check,)})
    with pytest.raises(CatalogUnavailable, match="expected checks disagree"):
        capture_catalog_snapshot(request, pack, context)


def test_snapshot_rejects_binding_disagreements() -> None:
    request, pack, context = _triple()
    with pytest.raises(CatalogUnavailable, match="question bindings disagree"):
        capture_catalog_snapshot(request.model_copy(update={"question_id": uuid4()}), pack, context)
    request, pack, context = _triple()
    with pytest.raises(CatalogUnavailable, match="language bindings disagree"):
        capture_catalog_snapshot(request.model_copy(update={"language": "es"}), pack, context)
    request, pack, context = _triple()
    changed_pack = request.topic_pack.model_copy(update={"content_sha": "b" * 40})
    with pytest.raises(CatalogUnavailable, match="content revisions disagree"):
        capture_catalog_snapshot(
            request.model_copy(update={"topic_pack": changed_pack}), pack, context
        )
    request, pack, context = _triple()
    with pytest.raises(CatalogUnavailable, match="policy bindings disagree"):
        capture_catalog_snapshot(
            request, pack, context.model_copy(update={"policy_hash": "9" * 64})
        )
    request, pack, context = _triple()
    with pytest.raises(CatalogUnavailable, match="topic bindings disagree"):
        capture_catalog_snapshot(request.model_copy(update={"topic_id": "vpn"}), pack, context)
    request, pack, context = _triple()
    changed_topic_pack = request.topic_pack.model_copy(update={"document_section": "changed"})
    with pytest.raises(CatalogUnavailable, match="topic prompt packs disagree"):
        capture_catalog_snapshot(
            request.model_copy(update={"topic_pack": changed_topic_pack}), pack, context
        )
    request, pack, context = _triple()
    changed_evidence = pack.model_copy(update={"sha256": "4" * 64})
    with pytest.raises(CatalogUnavailable, match="evidence packs disagree"):
        capture_catalog_snapshot(request, changed_evidence, context)


def test_snapshot_rejects_untyped_pack_or_context() -> None:
    request, _, _ = _triple()
    with pytest.raises(CatalogUnavailable, match="typed catalog authority"):
        capture_catalog_snapshot(request, object(), object())


class _Clock:
    def now(self) -> datetime:
        return NOW

    def monotonic(self) -> float:
        return 0.0


class _NeverCancelled:
    def is_cancelled(self) -> bool:
        return False

    def raise_if_cancelled(self) -> None:
        return None


class _Ledger:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def claim(self, kind: CallKind) -> None:
        self.calls.append(str(kind))


class _RecordingBudgetStore:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.before_blocked: Callable[[], None] | None = None

    async def daily_judgment_blocked(
        self,
        *,
        owner_key: str,
        now: datetime,
        owner_daily_limit: int,
        service_daily_limit: int,
    ) -> bool:
        self.calls.append("daily_judgment_blocked")
        if self.before_blocked is not None:
            self.before_blocked()
        return False

    async def daily_cannot_reserve(
        self,
        *,
        owner_key: str,
        tokens: int,
        now: datetime,
        owner_daily_limit: int,
        service_daily_limit: int,
    ) -> bool:
        self.calls.append("daily_cannot_reserve")
        return False

    async def question_budget_remaining(self, question_id: UUID) -> int | None:
        self.calls.append("question_budget_remaining")
        return None

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
        lease_supplier: object = None,
    ) -> Reservation:
        self.calls.append("reserve")
        return Reservation(
            reservation_id=uuid4(),
            operation_id=operation_id,
            question_id=question_id,
            topic_id=cast(TopicId, topic_id),
            owner_key=cast(SHA256, OWNER),
            environment_id="alpha",
            lease_id=lease.lease_id,
            holder_id=lease.holder_id,
            fence=lease.fence,
            reserved_tokens=tokens,
            state="reserved",
            created_at=now,
            hard_deadline_at=now + timedelta(minutes=5),
            recover_after=now + timedelta(minutes=6),
            version=1,
        )

    async def mark_started(
        self,
        reservation: Reservation,
        *,
        lease: Lease,
        operation_id: UUID,
        now: datetime,
        lease_supplier: object = None,
    ) -> Reservation:
        self.calls.append("mark_started")
        return reservation.model_copy(update={"state": "started"})

    async def settle(
        self,
        reservation: Reservation,
        *,
        charged_tokens: int | None,
        lease: Lease,
        operation_id: UUID,
        now: datetime,
        release: bool = False,
        lease_supplier: object = None,
    ) -> None:
        self.calls.append("settle")


class _RecordingProvider:
    def __init__(self) -> None:
        self.count_requests: list[JudgmentRequest] = []
        self.converse_requests: list[JudgmentRequest] = []

    async def count(self, request: JudgmentRequest, *, execution: ExecutionContext) -> int:
        self.count_requests.append(request)
        return 100

    async def converse(
        self, request: JudgmentRequest, *, execution: ExecutionContext
    ) -> RawJudgment:
        self.converse_requests.append(request)
        return RawJudgment(
            text='{"schema_version":"1","findings":[]}',
            stop_reason="end_turn",
            guardrail_intervened=False,
            provider_request_id="snapshot-fixture",
        )


def _execution(request: JudgmentRequest) -> ExecutionContext:
    return ExecutionContext(
        question_id=request.question_id,
        operation="ask",
        owner_key=OWNER,
        environment_id="alpha",
        deadline_at=NOW + timedelta(minutes=5),
        cancel=cast(Any, _NeverCancelled()),
        calls=cast(Any, _Ledger()),
        admission=AdmissionGrant(holder_id=uuid4(), slot_ids=("model",), expires_at=NOW, fence=1),
        trace_context=TraceContext(trace_id="1" * 32, span_id="2" * 16, trace_flags=1),
    )


def _lease(question_id: UUID) -> Lease:
    return Lease(
        lease_id=uuid4(),
        question_id=question_id,
        owner_key=cast(SHA256, OWNER),
        environment_id="alpha",
        holder_id=uuid4(),
        fence=1,
        expires_at=NOW + timedelta(minutes=10),
        last_renewed_at=NOW,
    )


async def _judge(
    request: JudgmentRequest,
    pack: EvidencePack,
    context: ValidationContext,
    provider: _RecordingProvider,
    budget: _RecordingBudgetStore,
) -> tuple[JudgmentResult, LeftOut | None]:
    handle = QuestionBudgetHandle(
        budgets=cast(Any, budget),
        clock=cast(Any, _Clock()),
        lease_holder=[_lease(request.question_id)],
        token_limit=100_000,
        owner_daily_limit=200_000,
        service_daily_limit=1_000_000,
    )
    runner = TopicJudgment(
        engine=cast(Any, None),
        provider=cast(Any, provider),
        validator=FindingValidator(),
        budget=handle,
        clock=cast(Any, _Clock()),
        stage=lambda _stage, _trace: nullcontext(),
        metrics=None,
    )
    return await runner.judge_ready(request, pack, context, _execution(request))


@pytest.mark.asyncio
async def test_runner_abstains_before_budget_and_provider_on_empty_catalog() -> None:
    request, pack, context = _triple(templates=())
    legacy_payload = request.model_dump(mode="json", exclude_none=False)
    legacy_payload.pop("finding_templates")
    request = JudgmentRequest.model_validate_json(json.dumps(legacy_payload), strict=True)
    assert request.finding_templates == ()
    provider = _RecordingProvider()
    budget = _RecordingBudgetStore()

    result, left = await _judge(request, pack, context, provider, budget)

    assert result.state == JudgmentState.evidence_unavailable
    assert left is not None
    assert left.stage == "judgment"
    assert left.reason == LeftOutReason.evidence_unavailable
    assert left.retryable is False
    assert budget.calls == []
    assert provider.count_requests == []
    assert provider.converse_requests == []


@pytest.mark.asyncio
async def test_runner_abstains_before_budget_and_provider_on_invalid_catalog() -> None:
    template = _template()
    request, pack, context = _triple(templates=(template, template))
    provider = _RecordingProvider()
    budget = _RecordingBudgetStore()

    result, left = await _judge(request, pack, context, provider, budget)

    assert result.state == JudgmentState.evidence_unavailable
    assert left is not None
    assert left.reason == LeftOutReason.evidence_unavailable
    assert left.retryable is False
    assert budget.calls == []
    assert provider.count_requests == []


@pytest.mark.asyncio
async def test_runner_abstains_before_budget_on_corrupt_prompt_binding() -> None:
    request, pack, context = _triple()
    corrupted_pack = request.topic_pack.model_copy(update={"missing": [False]})
    request = request.model_copy(update={"topic_pack": corrupted_pack})
    context = context.model_copy(update={"topic_pack": corrupted_pack})
    provider = _RecordingProvider()
    budget = _RecordingBudgetStore()

    result, left = await _judge(request, pack, context, provider, budget)

    assert result.state == JudgmentState.evidence_unavailable
    assert left is not None
    assert left.reason == LeftOutReason.evidence_unavailable
    assert left.retryable is False
    assert budget.calls == []
    assert provider.count_requests == []
    assert provider.converse_requests == []


@pytest.mark.asyncio
async def test_runner_count_and_converse_receive_detached_snapshot_views() -> None:
    request, pack, context = _triple()
    original = request.finding_templates[0].texts.en
    provider = _RecordingProvider()
    budget = _RecordingBudgetStore()

    def mutate_after_capture() -> None:
        request.finding_templates[0].texts.__dict__["en"] = "CORRUPTED"
        pack.__dict__["sha256"] = "f" * 64
        context.__dict__["templates"] = ()

    budget.before_blocked = mutate_after_capture

    result, left = await _judge(request, pack, context, provider, budget)

    assert left is None
    assert result.state == JudgmentState.no_findings
    count_request = provider.count_requests[0]
    converse_request = provider.converse_requests[0]
    assert count_request.finding_templates[0].texts.en == original
    assert converse_request.finding_templates[0].texts.en == original
    assert count_request.evidence.sha256 == "3" * 64
    assert converse_request.evidence.sha256 == "3" * 64
    assert count_request.reservation_id is None
    assert count_request.reserved_tokens == 0
    assert converse_request.reservation_id is not None
    assert converse_request.reserved_tokens > 0
    assert count_request.finding_templates[0] is not converse_request.finding_templates[0]


@pytest.mark.asyncio
@pytest.mark.parametrize("language", ["en", "es"])
async def test_runner_ignores_source_and_provider_mutations_at_count_and_invoke_barriers(
    language: str,
) -> None:
    def template(
        template_id: str,
        en: str,
        es: str,
        *,
        requires_check: bool = False,
        same_record: bool = False,
    ) -> FindingTemplate:
        return FindingTemplate(
            template_id=template_id,
            topic_id="ldap",
            kind="observation",
            required_bindings={
                "rule": (FieldId.rule_id,),
                "name": (FieldId.agent_name,),
            },
            texts=LocaleText(en=en, es=es),
            required_check_outcomes=(
                [RequiredCheckOutcome(check_id="ldap_check", outcome=CheckOutcome.passed)]
                if requires_check
                else []
            ),
            allowed_evidence_kinds=["row"],
            relations=(
                [FindingRelationSameRecord(kind="same_record", bindings=["rule", "name"])]
                if same_record
                else []
            ),
        )

    prerequisite = template(
        "ldap_prerequisite",
        "Gate approved {rule} for {name}.",
        "Control aprobado {rule} para {name}.",
        requires_check=True,
    )
    relation = template(
        "ldap_same_record",
        "Related approved {rule} for {name}.",
        "Relacionado aprobado {rule} para {name}.",
        same_record=True,
    )
    field_scope = template(
        "ldap_field_scope",
        "Field approved {rule} for {name}.",
        "Campo aprobado {rule} para {name}.",
    )
    independent = template(
        "ldap_independent",
        "Independent approved {rule} for {name}.",
        "Independiente aprobado {rule} para {name}.",
    )

    row_one_id = "ev1_" + "2" * 64
    row_two_id = "ev1_" + "3" * 64
    check_item_id = "ev1_" + "4" * 64
    snapshot = SnapshotRef(kind=SnapshotKind.pit, key="5" * 64, at=NOW)
    row_one = EvidenceItem(
        evidence_id=row_one_id,
        topic_id="ldap",
        fetch_id="alerts",
        kind="row",
        source=EvidenceSourceRow(index_alias="alerts-index", record_id="record-one"),
        snapshot=snapshot,
        values={FieldId.rule_id: "rule-17", FieldId.agent_name: "node-one"},
        visibility=Visibility.full,
        scope_hash="6" * 64,
    )
    row_two = EvidenceItem(
        evidence_id=row_two_id,
        topic_id="ldap",
        fetch_id="alerts",
        kind="row",
        source=EvidenceSourceRow(index_alias="alerts-index", record_id="record-two"),
        snapshot=snapshot,
        values={FieldId.rule_id: "rule-23", FieldId.agent_name: "node-two"},
        visibility=Visibility.full,
        scope_hash="7" * 64,
    )
    check = CheckResult(
        check_id="ldap_check",
        topic_id="ldap",
        label="LDAP prerequisite",
        outcome=CheckOutcome.failed,
        evidence_ids=[check_item_id],
        message="not passed",
    )
    check_item = EvidenceItem(
        evidence_id=check_item_id,
        topic_id="ldap",
        check_id="ldap_check",
        kind="check",
        source=EvidenceSourceCheck(step_id="ldap_check", operand_ids=[]),
        snapshot=snapshot,
        values={"outcome": CheckOutcome.failed.value},
        visibility=Visibility.full,
        scope_hash="8" * 64,
    )
    request, pack, context = _triple(
        templates=(prerequisite, relation, field_scope, independent),
        checks=(check,),
        items=(row_one, row_two, check_item),
        language=language,
    )
    baseline = catalog_bytes(request.finding_templates)

    def corrupt_source() -> None:
        prerequisite.required_check_outcomes.clear()
        relation.relations.clear()
        field_scope.required_bindings["rule"] = (FieldId.agent_name,)
        field_scope.allowed_evidence_kinds.append("check")
        for approved in (prerequisite, relation, field_scope, independent):
            approved.texts.__dict__["en"] = "source mutation"
            approved.texts.__dict__["es"] = "mutacion de origen"

    def mutate_provider_view(view: JudgmentRequest, suffix: str) -> None:
        view.finding_templates[0].required_check_outcomes.clear()
        view.finding_templates[1].relations.clear()
        view.finding_templates[2].required_bindings["rule"] = (FieldId.agent_name,)
        view.finding_templates[2].allowed_evidence_kinds.clear()
        view.finding_templates[3].texts.__dict__["en"] = suffix

    class MutatingProvider(_RecordingProvider):
        def __init__(self) -> None:
            super().__init__()
            self.serialized_catalogs: list[bytes] = []

        def serialize(self, view: JudgmentRequest) -> None:
            system, _ = BedrockJudgmentProvider._prompt(view)
            text = next(
                block["text"]
                for block in system
                if isinstance(block.get("text"), str)
                and cast(str, block["text"]).startswith(TOPIC_CONTEXT_LABEL)
            )
            payload = json.loads(cast(str, text)[len(TOPIC_CONTEXT_LABEL) :])
            self.serialized_catalogs.append(canonical_bytes(payload["finding_templates"]))

        async def count(
            self, count_request: JudgmentRequest, *, execution: ExecutionContext
        ) -> int:
            self.count_requests.append(count_request)
            self.serialize(count_request)
            mutate_provider_view(count_request, "count mutation")
            return 100

        async def converse(
            self, converse_request: JudgmentRequest, *, execution: ExecutionContext
        ) -> RawJudgment:
            self.converse_requests.append(converse_request)
            self.serialize(converse_request)
            corrupt_source()
            mutate_provider_view(converse_request, "invoke mutation")

            def candidate(
                finding_id: str,
                template_id: str,
                bindings: dict[str, tuple[str, str]],
                evidence_ids: tuple[str, ...],
            ) -> dict[str, object]:
                return {
                    "finding_id": finding_id,
                    "kind": "observation",
                    "template_id": template_id,
                    "evidence_ids": list(evidence_ids),
                    "bindings": {
                        name: {"evidence_id": evidence_id, "field": field}
                        for name, (evidence_id, field) in bindings.items()
                    },
                }

            findings = [
                candidate(
                    "candidate_prerequisite",
                    "ldap_prerequisite",
                    {
                        "rule": (row_one_id, FieldId.rule_id),
                        "name": (row_one_id, FieldId.agent_name),
                    },
                    (row_one_id,),
                ),
                candidate(
                    "candidate_relation",
                    "ldap_same_record",
                    {
                        "rule": (row_one_id, FieldId.rule_id),
                        "name": (row_two_id, FieldId.agent_name),
                    },
                    (row_one_id, row_two_id),
                ),
                candidate(
                    "candidate_field_scope",
                    "ldap_field_scope",
                    {
                        "rule": (row_one_id, FieldId.agent_name),
                        "name": (row_one_id, FieldId.agent_name),
                    },
                    (row_one_id,),
                ),
                candidate(
                    "candidate_independent",
                    "ldap_independent",
                    {
                        "rule": (row_one_id, FieldId.rule_id),
                        "name": (row_one_id, FieldId.agent_name),
                    },
                    (row_one_id,),
                ),
            ]
            return RawJudgment(
                text=json.dumps({"schema_version": "1", "findings": findings}),
                stop_reason="end_turn",
                guardrail_intervened=False,
                provider_request_id="mutation-fixture",
            )

    provider = MutatingProvider()
    budget = _RecordingBudgetStore()

    budget.before_blocked = corrupt_source
    validator = FindingValidator()
    runner = TopicJudgment(
        engine=cast(Any, None),
        provider=cast(Any, provider),
        validator=validator,
        budget=QuestionBudgetHandle(
            budgets=cast(Any, budget),
            clock=cast(Any, _Clock()),
            lease_holder=[_lease(request.question_id)],
            token_limit=100_000,
            owner_daily_limit=200_000,
            service_daily_limit=1_000_000,
        ),
        clock=cast(Any, _Clock()),
        stage=lambda _stage, _trace: nullcontext(),
        metrics=None,
    )
    execution = _execution(request)

    result, left = await runner.judge_ready(request, pack, context, execution)

    assert len(provider.count_requests) == 1, (left, budget.calls)
    assert left is None
    assert result.state == JudgmentState.validated
    assert len(result.sentences) == 1
    assert result.sentences[0].text == (
        "Independent approved rule-17 for \u27e6node-one\u27e7."
        if language == "en"
        else "Independiente aprobado rule-17 para \u27e6node-one\u27e7."
    )
    assert {item.finding_id: item.reason for item in result.removed} == {
        "candidate_prerequisite": RemovedReason.failed_prerequisite,
        "candidate_relation": RemovedReason.bad_relation,
        "candidate_field_scope": RemovedReason.bad_binding,
    }
    assert provider.serialized_catalogs == [baseline, baseline]
    assert provider.count_requests[0].finding_templates[0].required_check_outcomes == []
    assert provider.converse_requests[0].finding_templates[1].relations == []
    assert provider.converse_requests[0].finding_templates[2].required_bindings["rule"] == (
        FieldId.agent_name,
    )
    assert pack.checks == [check]

    corrupt_source()
    assert provider.serialized_catalogs == [baseline, baseline]
