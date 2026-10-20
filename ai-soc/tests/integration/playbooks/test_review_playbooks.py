from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import httpx
import pytest

from ai_soc.application.composition import compose_soc
from ai_soc.config import ServiceConfig
from ai_soc.contracts.models import (
    AskRequest,
    CompareCountStep,
    Effort,
    ExpectationDefinition,
    ExpectationMatchStep,
    FieldId,
    FieldPresentStep,
    IndexFamily,
    ModelCapability,
    Planned,
    RecordAgeStep,
    SiteConfig,
    TemplateId,
    VerifiedPrincipal,
    Visibility,
)
from ai_soc.identity.alb import AlbAssertionVerifier, McpBearerVerifier
from ai_soc.judgment.bedrock import BedrockJudgmentProvider
from ai_soc.planning.parser import DeterministicPlanner
from ai_soc.query.compiler import default_profile
from ai_soc.telemetry.metrics import MetricSample
from ai_soc.telemetry.tracing import TraceSpan
from tests.unit.content.content_fixture_support import build_seed


class _Clock:
    def now(self) -> datetime:
        return datetime(2026, 10, 19, 12, tzinfo=UTC)

    def monotonic(self) -> float:
        return 1.0


class _Kms:
    def sign(self, **kwargs: object) -> dict[str, object]:
        return {"Signature": b"x" * 256}


class _Queue:
    def send_message(self, **kwargs: object) -> dict[str, object]:
        return {"MessageId": str(uuid4())}

    def receive_message(self, **kwargs: object) -> dict[str, object]:
        return {"Messages": []}

    def delete_message(self, **kwargs: object) -> None:
        return None


class _Discard:
    def export(self, span: TraceSpan) -> None:
        return None

    def emit(self, sample: MetricSample) -> None:
        return None


class _Ready:
    def ready(self) -> bool:
        return True


class _ScriptedBedrock:
    def __init__(self, finding: dict[str, object] | None = None) -> None:
        self.finding = finding
        self.count_calls = 0
        self.converse_calls = 0

    def count_tokens(self, **kwargs: object) -> dict[str, object]:
        self.count_calls += 1
        return {"inputTokens": 128}

    def converse(self, **kwargs: object) -> dict[str, object]:
        self.converse_calls += 1
        messages = cast(list[dict[str, Any]], kwargs["messages"])
        evidence_text = next(
            text
            for message in messages
            for part in message["content"]
            if isinstance(part, dict)
            and isinstance(part.get("text"), str)
            and part["text"].startswith("UNTRUSTED TOPIC EVIDENCE DATA:\n")
            for text in [part["text"]]
        )
        evidence = json.loads(evidence_text.split("\n", 1)[1])
        findings = [] if self.finding is None else [self._candidate(evidence["items"])]
        output = json.dumps({"schema_version": "1", "findings": findings})
        return {
            "output": {"message": {"role": "assistant", "content": [{"text": output}]}},
            "stopReason": "end_turn",
            "usage": {"inputTokens": 128, "outputTokens": 16},
            "ResponseMetadata": {"RequestId": "scripted-review-test"},
        }

    def _candidate(self, items: list[dict[str, Any]]) -> dict[str, object]:
        assert self.finding is not None
        template_id = str(self.finding["template_id"])
        selections = cast(
            list[tuple[str, str | None, str | None, str, int]], self.finding["selections"]
        )
        bindings: dict[str, object] = {}
        evidence_ids: list[str] = []
        for binding_id, fetch_id, check_id, field, row_index in selections:
            matching = [
                item
                for item in items
                if item["kind"]
                == ("check" if check_id else "aggregate" if field == "count" else "row")
                and (fetch_id is None or item.get("fetch_id") == fetch_id)
                and (check_id is None or item.get("check_id") == check_id)
            ]
            item = matching[row_index]
            evidence_id = str(item["evidence_id"])
            bindings[binding_id] = {"evidence_id": evidence_id, "field": field}
            if evidence_id not in evidence_ids:
                evidence_ids.append(evidence_id)
        return {
            "finding_id": "scripted-review-finding",
            "kind": str(self.finding["kind"]),
            "template_id": template_id,
            "evidence_ids": evidence_ids,
            "bindings": bindings,
        }


def _site(*, expectations: tuple[ExpectationDefinition, ...] = ()) -> SiteConfig:
    return SiteConfig(
        environment_id="alpha",
        label="Alpha",
        enabled=True,
        indexer_origin="https://indexer.example.test",
        private_network_ref="fixture",
        jwt_issuer="https://issuer.example.test",
        jwt_audience="indexer",
        kms_signing_key_arn="arn:aws:kms:us-east-1:000000000000:key/fixture",
        ca_secret_arn="arn:aws:secretsmanager:us-east-1:000000000000:secret:ca",
        ca_secret_version="1",
        ca_sha256="d" * 64,
        group_role_map={"reviewers": ("analyst",)},
        role_visibility={"analyst": Visibility.full},
        allowed_index_patterns={
            IndexFamily.alerts: ("wazuh-alerts-*",),
            IndexFamily.vulnerabilities: ("wazuh-vulnerabilities-*",),
        },
        mapping_profile="wazuh-v4-fixture",
        policy_version="1",
        pit_supported=False,
        allowed_templates=(TemplateId.alerts_rows_v1, TemplateId.vulnerabilities_rows_v1),
        dls_attestation_version="1",
        composite_role_visibility={"analyst": Visibility.full},
        expectations=expectations,
    )


def _transport(
    count: int,
    rows: list[dict[str, object]],
    *,
    relation: str = "eq",
    denied: bool = False,
) -> tuple[httpx.AsyncClient, list[httpx.Request]]:
    requests: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if denied:
            return httpx.Response(403, json={"error": "denied"})
        if "_validate/query" in request.url.path:
            return httpx.Response(200, json={"valid": True})
        hits = [
            {"_id": str(index), "_source": source} for index, source in enumerate(rows, start=1)
        ]
        return httpx.Response(
            200,
            json={
                "hits": {
                    "total": {"value": count, "relation": relation},
                    "hits": [{**hit, "_index": request.url.path.split("/", 2)[1]} for hit in hits],
                }
            },
        )

    return (
        httpx.AsyncClient(
            base_url="https://indexer.example.test", transport=httpx.MockTransport(handle)
        ),
        requests,
    )


def _compose(
    built_catalog: Any,
    client: _ScriptedBedrock,
    transport: httpx.AsyncClient,
    *,
    site_expectations: tuple[ExpectationDefinition, ...] = (),
):
    clock = _Clock()
    site = _site(expectations=site_expectations)
    config = ServiceConfig(
        mode="fixture",
        guardrail_identifier="fixture-guardrail",
        guardrail_version="1",
        sites=(site,),
        models=(_model(),),
    )
    alb = AlbAssertionVerifier(
        region="us-east-1",
        signer_arn="arn:aws:elasticloadbalancing:us-east-1:000000000000:loadbalancer/app/test/0",
        issuer="https://issuer.example.test",
        client_id="review-test",
        groups_claim="groups",
        key_resolver=lambda key_id: "",
        now=clock.now,
    )
    mcp = McpBearerVerifier(
        issuer="https://issuer.example.test",
        resource="https://soc.example.test/mcp",
        jwks_uri="https://issuer.example.test/.well-known/jwks.json",
        key_resolver=lambda key_id: "",
        now=clock.now,
        allowed_origins=frozenset({"https://soc.example.test"}),
    )
    return compose_soc(
        config,
        clock=clock,
        catalog=built_catalog,
        state_client=None,
        state_table=None,
        kms=_Kms(),
        indexer_key_ids={"alpha": "fixture-key"},
        transport_for=lambda authorized_site: transport,
        mapping_profiles={"wazuh-v4-fixture": default_profile()},
        cursor_cipher=None,
        judgment_provider_factory=lambda admission: BedrockJudgmentProvider(
            client, admission_store=admission, clock=clock
        ),
        audit_client=_Queue(),
        audit_queue_url="https://queue.example.test/audit",
        feedback_client=_Queue(),
        feedback_queue_url="https://queue.example.test/feedback",
        span_exporter=_Discard(),
        metric_exporter=_Discard(),
        receipt_keys={"fixture": b"s" * 32},
        current_receipt_key="fixture",
        csrf_secret=b"c" * 32,
        browser_origin="https://soc.example.test",
        alb_verifier=alb,
        mcp_verifier=mcp,
        readiness=_Ready(),
        standing_rules="Return only catalog-grounded findings.",
        mcp_issuer_url="https://issuer.example.test",
        mcp_resource_url="https://soc.example.test/mcp",
    )


def _model() -> ModelCapability:
    return ModelCapability(
        id="review-fixture-model",
        label="Review fixture model",
        region="us-east-1",
        resource_arns=("arn:aws:bedrock:us-east-1:000000000000:inference-profile/review",),
        context_tokens=4096,
        max_output_tokens=512,
        count_tokens_model_id="review-count-model",
        efforts=(Effort.low,),
        effort_transport="additionalModelRequestFields",
        effort_parameters={Effort.low: {}},
        output_strategy="strict_json_messages",
        count_strategy="count_tokens_converse",
        count_contract_sha256="e" * 64,
        cache_min_tokens=0,
        cache_max_checkpoints=0,
        cache_ttl="5m",
        validated_at=datetime(2026, 10, 1, tzinfo=UTC),
        primary_doc_url="https://docs.example.test/model",
    )


async def _ask(
    built_catalog: Any,
    topic: str,
    count: int,
    rows: list[dict[str, object]],
    *,
    relation: str = "eq",
    denied: bool = False,
    finding: dict[str, object] | None = None,
    site_expectations: tuple[ExpectationDefinition, ...] = (),
    language_hint: str | None = None,
):
    transport, requests = _transport(count, rows, relation=relation, denied=denied)
    client = _ScriptedBedrock(finding)
    runtime = _compose(built_catalog, client, transport, site_expectations=site_expectations)
    question = _question(topic, language_hint)
    try:
        answer = await runtime.application.ask(
            AskRequest(
                question=question,
                environment_id="alpha",
                model_id="review-fixture-model",
                effort=Effort.low,
                timezone="UTC",
                language_hint=language_hint,
            ),
            _principal(),
        )
    finally:
        await transport.aclose()
    return answer, client, requests


def _question(topic: str, language_hint: str | None) -> str:
    if language_hint == "es":
        return (
            "Investiga revision de autenticacion y recomienda los siguientes pasos"
            if topic == "auth_review"
            else "Investiga revision de vulnerabilidades y recomienda los siguientes pasos"
        )
    return (
        "Investigate authentication review and recommend next steps"
        if topic == "auth_review"
        else "Investigate vulnerability review and recommend next steps"
    )


def _source(
    *,
    rule_level: int = 5,
    severity: str = "High",
    srcip: str | None = "192.0.2.1",
    version: str | None = "1.2.3",
    agent: str = "001",
    stamp: str | None = None,
) -> dict[str, object]:
    source: dict[str, object] = {
        "@timestamp": "2026-10-19T11:00:00Z",
        "agent": {"id": agent},
        "rule": {"id": "5710", "level": rule_level, "groups": ["authentication_failed"]},
        "vulnerability": {
            "id": "CVE-2025-1234",
            "severity": severity,
            "detected_at": "2026-10-19T10:00:00Z",
        },
        "package": {"name": "openssl"},
    }
    if srcip is not None:
        source["data"] = {"srcip": srcip}
    if version is not None:
        cast(dict[str, object], source["package"])["version"] = version
    if stamp is not None:
        source["@timestamp"] = stamp
        cast(dict[str, object], source["vulnerability"])["detected_at"] = stamp
    return source


def _check(answer: Any, check_id: str) -> str:
    block = next(
        block for block in answer.blocks if block.topic_id in ("auth_review", "vuln_review")
    )
    return str(next(check for check in block.checks if check.check_id == check_id).outcome)


def _judgment(answer: Any):
    return next(
        block for block in answer.blocks if block.topic_id in ("auth_review", "vuln_review")
    ).judgment


def _principal() -> VerifiedPrincipal:
    return VerifiedPrincipal(
        issuer="https://issuer.example.test",
        sub="reviewer",
        owner_key="a" * 64,
        groups=("reviewers",),
        edge="fixture",
        authenticated_at=datetime(2026, 10, 19, 11, tzinfo=UTC),
        expires_at=datetime(2026, 10, 19, 13, tzinfo=UTC),
        assertion_hash="b" * 64,
    )


@pytest.fixture(scope="module")
def built_catalog():
    checkout = Path(__file__).resolve().parents[3]
    work_dir = checkout / "build" / "test-review-playbooks"
    shutil.rmtree(work_dir, ignore_errors=True)
    return build_seed(work_dir).catalog


@pytest.mark.parametrize(
    ("topic_id", "question", "alias_only"),
    [
        ("auth_review", "Investigate authentication review", "authentication review"),
        ("vuln_review", "Investiga revision de vulnerabilidades", "revision de vulnerabilidades"),
    ],
)
def test_review_alias_routes_only_with_failure_cue(built_catalog, topic_id, question, alias_only):
    planner = DeterministicPlanner(built_catalog)
    principal = _principal()
    policy_hash = "c" * 64
    routed = planner.plan(
        AskRequest(question=question, environment_id="alpha", timezone="UTC"),
        principal,
        None,
        policy_hash=policy_hash,
        clock=_Clock(),
    )
    plain = planner.plan(
        AskRequest(question=alias_only, environment_id="alpha", timezone="UTC"),
        principal,
        None,
        policy_hash=policy_hash,
        clock=_Clock(),
    )
    assert isinstance(routed, Planned)
    assert routed.plan.topics[0].topic_id == topic_id
    assert routed.plan.topics[0].playbook_id == f"{topic_id}_playbook"
    assert isinstance(plain, Planned)
    assert plain.plan.topics[0].topic_id == topic_id
    assert plain.plan.topics[0].playbook_id is None


def test_review_topics_have_fixed_window_checks_and_no_fetch_bindings(built_catalog):
    for topic_id, fetch_id, expected_checks in (
        (
            "auth_review",
            "auth_rows",
            {"auth_nonzero", "auth_volume", "auth_sources", "auth_priority", "auth_recency"},
        ),
        ("vuln_review", "vuln_rows", {"vuln_nonzero", "vuln_versions", "vuln_priority"}),
    ):
        topic = built_catalog.topic(topic_id)
        playbook = built_catalog.playbook(topic.playbook_id)
        assert topic.fetch_bindings == []
        assert playbook is not None
        assert len(playbook.steps) == (6 if topic_id == "auth_review" else 4)
        fetch = playbook.steps[0]
        assert fetch.fetch_id == fetch_id
        assert fetch.window_default.unit == "hours"
        assert fetch.window_default.amount == 24
        assert {step.check_id for step in playbook.steps[1:]} == expected_checks


def test_auth_volume_referral_requires_ten_and_auth_check(built_catalog):
    playbook = built_catalog.playbook("auth_review_playbook")
    assert playbook is not None
    threshold = next(
        step
        for step in playbook.steps
        if isinstance(step, CompareCountStep) and step.check_id == "auth_volume"
    )
    assert threshold.op == "gte"
    assert threshold.right.value == 10
    template = next(
        item
        for item in built_catalog.finding_templates("auth_review")
        if item.template_id == "auth_volume_review"
    )
    assert [(item.check_id, item.outcome) for item in template.required_check_outcomes] == [
        ("auth_volume", "passed")
    ]


def test_auth_sample_requires_same_record_for_all_row_bindings(built_catalog):
    template = next(
        item
        for item in built_catalog.finding_templates("auth_review")
        if item.template_id == "auth_sample"
    )
    relation = next(item for item in template.relations if item.kind == "same_record")
    assert set(relation.bindings) == set(template.required_bindings)


def test_vulnerability_priority_check_references_its_expectation(built_catalog):
    playbook = built_catalog.playbook("vuln_review_playbook")
    assert playbook is not None
    step = next(
        step
        for step in playbook.steps
        if isinstance(step, ExpectationMatchStep) and step.check_id == "vuln_priority"
    )
    assert step.expectation_id == "vuln_priority"


def test_field_coverage_checks_require_every_returned_row(built_catalog):
    for topic_id, check_id in (("auth_review", "auth_sources"), ("vuln_review", "vuln_versions")):
        playbook = built_catalog.playbook(f"{topic_id}_playbook")
        assert playbook is not None
        step = next(
            step
            for step in playbook.steps
            if isinstance(step, FieldPresentStep) and step.check_id == check_id
        )
        assert step.quantifier == "all"


@pytest.mark.parametrize(("count", "expected"), [(9, "failed"), (10, "passed"), (11, "passed")])
@pytest.mark.asyncio
async def test_auth_volume_uses_exact_total_threshold(built_catalog, count, expected):
    answer, _, requests = await _ask(built_catalog, "auth_review", count, [_source()])
    assert _check(answer, "auth_volume") == expected
    assert _check(answer, "auth_nonzero") == "passed"
    assert any("/_search" in request.url.path for request in requests)


@pytest.mark.asyncio
async def test_auth_zero_is_not_rendered_as_absent_or_benign(built_catalog):
    answer, _, _ = await _ask(built_catalog, "auth_review", 0, [])
    assert _check(answer, "auth_nonzero") == "failed"
    rendered = " ".join(sentence.text.lower() for sentence in _judgment(answer).sentences)
    assert "no activity" not in rendered
    assert "benign" not in rendered
    assert "no hay actividad" not in rendered
    assert "benigna" not in rendered


@pytest.mark.parametrize(("level", "expected"), [(9, "failed"), (10, "passed")])
@pytest.mark.asyncio
async def test_auth_priority_uses_returned_rule_level(built_catalog, level, expected):
    answer, _, _ = await _ask(built_catalog, "auth_review", 1, [_source(rule_level=level)])
    assert _check(answer, "auth_priority") == expected


@pytest.mark.asyncio
async def test_auth_sources_fails_when_a_returned_row_lacks_srcip(built_catalog):
    answer, _, _ = await _ask(
        built_catalog,
        "auth_review",
        2,
        [_source(srcip=None), _source(srcip="192.0.2.2")],
    )
    assert _check(answer, "auth_sources") == "failed"


@pytest.mark.asyncio
async def test_approximate_auth_total_leaves_count_checks_unknown(built_catalog):
    answer, _, _ = await _ask(built_catalog, "auth_review", 10, [_source()], relation="gte")
    assert _check(answer, "auth_volume") == "unknown"
    assert _check(answer, "auth_nonzero") == "unknown"


@pytest.mark.parametrize(("count", "expected"), [(0, "failed"), (1, "passed")])
@pytest.mark.asyncio
async def test_vulnerability_nonzero_uses_total(built_catalog, count, expected):
    answer, _, _ = await _ask(
        built_catalog,
        "vuln_review",
        count,
        [] if count == 0 else [_source(severity="High")],
    )
    assert _check(answer, "vuln_nonzero") == expected


@pytest.mark.parametrize(("severity", "expected"), [("High", "failed"), ("Critical", "passed")])
@pytest.mark.asyncio
async def test_vulnerability_priority_requires_critical_returned_row(
    built_catalog, severity, expected
):
    answer, _, _ = await _ask(built_catalog, "vuln_review", 1, [_source(severity=severity)])
    assert _check(answer, "vuln_priority") == expected


@pytest.mark.asyncio
async def test_vulnerability_versions_fails_when_a_returned_row_lacks_version(built_catalog):
    answer, _, _ = await _ask(built_catalog, "vuln_review", 1, [_source(version=None)])
    assert _check(answer, "vuln_versions") == "failed"


@pytest.mark.asyncio
async def test_denied_fetch_has_denied_checks_and_does_not_call_model(built_catalog):
    answer, client, _ = await _ask(built_catalog, "auth_review", 1, [], denied=True)
    assert {str(check.outcome) for check in answer.blocks[0].checks} == {"denied"}
    assert client.count_calls == 0
    assert client.converse_calls == 0


@pytest.mark.parametrize(("count", "expected_state"), [(11, "validated"), (9, "all_removed")])
@pytest.mark.asyncio
async def test_auth_volume_finding_requires_passed_volume_check(
    built_catalog, count, expected_state
):
    finding = {
        "template_id": "auth_volume_review",
        "kind": "recommendation",
        "selections": [("n", "auth_rows", None, "count", 0)],
    }
    answer, _, _ = await _ask(built_catalog, "auth_review", count, [_source()], finding=finding)
    judgment = _judgment(answer)
    assert str(judgment.state) == expected_state
    if count == 11:
        assert "11" in judgment.sentences[0].text
    else:
        assert [str(item.reason) for item in judgment.removed] == ["failed_prerequisite"]


@pytest.mark.asyncio
async def test_vulnerability_priority_finding_renders_for_critical_row(built_catalog):
    finding = {
        "template_id": "vuln_priority_review",
        "kind": "recommendation",
        "selections": [("o", None, "vuln_priority", "outcome", 0)],
    }
    answer, _, _ = await _ask(
        built_catalog, "vuln_review", 1, [_source(severity="Critical")], finding=finding
    )
    judgment = _judgment(answer)
    assert str(judgment.state) == "validated"
    assert "configured priority severity check" in judgment.sentences[0].text


@pytest.mark.asyncio
async def test_vulnerability_priority_finding_describes_site_configured_high_check(built_catalog):
    finding = {
        "template_id": "vuln_priority_review",
        "kind": "recommendation",
        "selections": [("o", None, "vuln_priority", "outcome", 0)],
    }
    site_expectation = ExpectationDefinition(
        expectation_id="vuln_priority",
        topic_id="vuln_review",
        field=FieldId.vulnerability_severity,
        op="eq",
        value="High",
        source="site",
        version="site-1",
    )
    answer, _, _ = await _ask(
        built_catalog,
        "vuln_review",
        1,
        [_source(severity="High")],
        finding=finding,
        site_expectations=(site_expectation,),
    )
    judgment = _judgment(answer)

    assert str(judgment.state) == "validated"
    assert "Critical" not in judgment.sentences[0].text
    assert "configured priority severity check" in judgment.sentences[0].text


@pytest.mark.asyncio
async def test_vulnerability_priority_rejects_other_check_binding(built_catalog):
    finding = {
        "template_id": "vuln_priority_review",
        "kind": "recommendation",
        "selections": [("o", None, "vuln_versions", "outcome", 0)],
    }
    answer, _, _ = await _ask(
        built_catalog, "vuln_review", 1, [_source(severity="Critical")], finding=finding
    )
    judgment = _judgment(answer)

    assert str(judgment.state) == "all_removed"
    assert [str(item.reason) for item in judgment.removed] == ["bad_binding"]


@pytest.mark.asyncio
async def test_auth_sample_rejects_bindings_taken_from_different_rows(built_catalog):
    finding = {
        "template_id": "auth_sample",
        "kind": "observation",
        "selections": [
            ("agent", "auth_rows", None, "agent.id", 0),
            ("rule", "auth_rows", None, "rule.id", 0),
            ("source", "auth_rows", None, "data.srcip", 1),
            ("time", "auth_rows", None, "timestamp", 0),
        ],
    }
    answer, _, _ = await _ask(
        built_catalog,
        "auth_review",
        2,
        [_source(agent="001"), _source(agent="002", srcip="192.0.2.2")],
        finding=finding,
    )
    judgment = _judgment(answer)
    assert str(judgment.state) == "all_removed"
    assert [str(item.reason) for item in judgment.removed] == ["bad_relation"]


FRESH_AUTH = "2026-10-19T11:30:00Z"
STALE_AUTH = "2026-10-19T10:59:59Z"


def _recency_finding(template_id: str, check_id: str) -> dict[str, object]:
    return {
        "template_id": template_id,
        "kind": "observation",
        "selections": [("o", None, check_id, "outcome", 0)],
    }


@pytest.mark.asyncio
async def test_fresh_auth_rows_pass_recency_and_gap_finding_is_rejected(built_catalog):
    answer, _, _ = await _ask(
        built_catalog,
        "auth_review",
        1,
        [_source(stamp=FRESH_AUTH)],
        finding=_recency_finding("auth_recency_gap", "auth_recency"),
    )
    judgment = _judgment(answer)

    assert _check(answer, "auth_recency") == "passed"
    assert str(judgment.state) == "all_removed"
    assert [str(item.reason) for item in judgment.removed] == ["failed_prerequisite"]


def test_vulnerability_review_has_no_recency_check_and_findings_are_unchanged(built_catalog):
    topic = built_catalog.topic("vuln_review")
    playbook = built_catalog.playbook("vuln_review_playbook")
    assert topic is not None
    assert playbook is not None
    assert not any(isinstance(step, RecordAgeStep) for step in playbook.steps)
    assert topic.finding_template_ids == [
        "vuln_count",
        "vuln_sample",
        "vuln_priority_review",
        "vuln_version_gap",
    ]


@pytest.mark.parametrize(
    ("language", "phrase", "manual_check"),
    [
        (
            "en",
            "older than the configured synthetic limit",
            "confirm ingestion manually",
        ),
        (
            "es",
            "supera el límite de antigüedad sintético configurado",
            "confirme la ingesta manualmente",
        ),
    ],
)
@pytest.mark.asyncio
async def test_stale_auth_rows_fail_recency_and_render_gap_finding(
    built_catalog, language, phrase, manual_check
):
    answer, _, _ = await _ask(
        built_catalog,
        "auth_review",
        1,
        [_source(stamp=STALE_AUTH)],
        finding=_recency_finding("auth_recency_gap", "auth_recency"),
        language_hint=language,
    )
    judgment = _judgment(answer)

    assert _check(answer, "auth_recency") == "failed"
    assert str(judgment.state) == "validated"
    assert phrase in judgment.sentences[0].text
    assert manual_check in judgment.sentences[0].text


@pytest.mark.parametrize(
    "language",
    ["en", "es"],
    ids=["english", "spanish"],
)
@pytest.mark.asyncio
async def test_stale_valid_timestamp_with_window_end_and_malformed_rows_renders_qualified_gap(
    built_catalog, language
):
    answer, _, _ = await _ask(
        built_catalog,
        "auth_review",
        3,
        [
            _source(stamp=STALE_AUTH),
            _source(agent="002", stamp="2026-10-19T12:00:00Z"),
            _source(agent="003", stamp="not-a-timestamp"),
        ],
        finding=_recency_finding("auth_recency_gap", "auth_recency"),
        language_hint=language,
    )
    check = next(item for item in answer.blocks[0].checks if item.check_id == "auth_recency")
    judgment = _judgment(answer)
    assert str(check.outcome) == "failed"
    assert "2 returned rows have no valid timestamp inside the read window" in check.message
    assert str(judgment.state) == "validated"
    if language == "en":
        assert judgment.sentences[0].text == (
            "The newest returned record with a valid timestamp inside the read window is older "
            "than the configured synthetic limit; visible data may be delayed, filtered or "
            "incomplete; confirm ingestion manually. Outcome failed."
        )
    else:
        assert judgment.sentences[0].text == (
            "El registro devuelto más reciente con una marca de tiempo válida dentro de la "
            "ventana de lectura supera el límite de antigüedad sintético configurado; los "
            "datos visibles pueden estar retrasados, filtrados o incompletos; confirme la "
            "ingesta manualmente. Resultado failed."
        )


@pytest.mark.asyncio
async def test_stale_auth_rows_leave_volume_referral_unaffected(built_catalog):
    finding = {
        "template_id": "auth_volume_review",
        "kind": "recommendation",
        "selections": [("n", "auth_rows", None, "count", 0)],
    }
    answer, _, _ = await _ask(
        built_catalog,
        "auth_review",
        11,
        [_source(stamp=STALE_AUTH)],
        finding=finding,
    )
    judgment = _judgment(answer)

    assert _check(answer, "auth_recency") == "failed"
    assert _check(answer, "auth_volume") == "passed"
    assert str(judgment.state) == "validated"


@pytest.mark.asyncio
async def test_empty_auth_read_leaves_recency_unknown_and_gap_finding_absent(built_catalog):
    answer, _, _ = await _ask(
        built_catalog,
        "auth_review",
        0,
        [],
        finding=_recency_finding("auth_recency_gap", "auth_recency"),
    )
    judgment = _judgment(answer)

    assert _check(answer, "auth_recency") == "unknown"
    assert str(judgment.state) == "ingestion_unconfirmed"
    assert not any("older than" in sentence.text for sentence in judgment.sentences)


def test_auth_recency_gap_is_built_as_check_only_failed_disclosure(built_catalog):
    template = next(
        item
        for item in built_catalog.finding_templates("auth_review")
        if item.template_id == "auth_recency_gap"
    )
    assert [(item.check_id, item.outcome) for item in template.required_check_outcomes] == [
        ("auth_recency", "failed")
    ]
    assert template.kind == "observation"
    assert list(template.allowed_evidence_kinds) == ["check"]
    assert len(template.required_bindings) == 1


def test_auth_public_doc_separates_denied_from_unknown() -> None:
    document = Path("examples/content-seed/public-docs/en/auth_review.md").read_text(
        encoding="utf-8"
    )
    unknown_section = document.split("Unknown means", maxsplit=1)[1].split(
        "The check says", maxsplit=1
    )[0]
    assert "the read was unavailable" in unknown_section
    assert "A denied read is reported as denied." in unknown_section
    assert "the read was denied" not in unknown_section
    qualified_record = "newest returned record with a valid timestamp inside the read window"
    assert document.count("newest returned record") == document.count(qualified_record)
    capabilities = Path("docs/source-capabilities.md").read_text(encoding="utf-8")
    assert capabilities.count("newest returned record") == capabilities.count(qualified_record)
