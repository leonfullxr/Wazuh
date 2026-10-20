from __future__ import annotations

import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Literal, cast
from uuid import UUID, uuid4

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/e2e"))

import fixture_server  # noqa: E402
from pydantic import SecretStr  # noqa: E402

from ai_soc.contracts.canonical import owner_key  # noqa: E402
from ai_soc.contracts.models import (  # noqa: E402
    AdmissionGrant,
    Answer,
    AskRequest,
    AuthorizedSite,
    CallKind,
    ExecutionContext,
    FetchResult,
    FetchSpec,
    FieldId,
    HTTPSUrl,
    IndexerCredential,
    IndexFamily,
    ReadOperationGrant,
    ResolvedWindow,
    SiteConfig,
    TemplateId,
    TraceContext,
    VerifiedPrincipal,
    Visibility,
)
from ai_soc.contracts.ports import IndexerTokenBroker, ReadAdmissionStore  # noqa: E402
from ai_soc.identity.policy import MappedSitePolicy  # noqa: E402
from ai_soc.query.compiler import default_profile  # noqa: E402
from ai_soc.query.indexer import WazuhIndexer  # noqa: E402

G053_FIXTURE = ROOT / "tests/unit/application/data/g053_provider_token_cases.json"
GN01_FIXTURE = ROOT / "tests/integration/admission_runtime/data/query_no_reuse_cases.json"
GN01_FIXTURE_SHA256 = "21718df15af9bad38c8a6c3fa555c423a02d8c134a61370490403a4cd30f4527"
NOW = datetime(2026, 9, 30, 12, tzinfo=UTC)


class _CallLedger:
    def claim(self, call: CallKind) -> None:
        del call


class _NeverCancelled:
    def is_cancelled(self) -> bool:
        return False

    def raise_if_cancelled(self) -> None:
        return None

    async def wait(self) -> None:
        return None


class _ReadAdmission(ReadAdmissionStore):
    async def acquire(
        self,
        *,
        environment_id: str,
        question_id: UUID,
        operation_id: UUID,
        call: Literal["mapping", "validate", "pit", "search", "probe"],
        now: datetime,
    ) -> ReadOperationGrant:
        return ReadOperationGrant(
            question_id=question_id,
            environment_id=environment_id,
            operation_id=operation_id,
            call=call,
            holder_id=uuid4(),
            service_slot_id="read-service-00",
            site_slot_id="read-site-00",
            fence=1,
            acquired_at=now,
            lease_expires_at=now + timedelta(seconds=5),
            hard_deadline_at=now + timedelta(seconds=10),
            recover_after=now + timedelta(seconds=45),
        )

    async def release(self, grant: ReadOperationGrant) -> None:
        del grant


class _IsolationBroker(IndexerTokenBroker):
    async def issue(
        self,
        principal: VerifiedPrincipal,
        site: AuthorizedSite,
        *,
        execution: ExecutionContext,
    ) -> IndexerCredential:
        assert principal.owner_key == execution.owner_key
        assert site.config.environment_id == execution.environment_id == "alpha"
        return IndexerCredential(
            bearer_token=SecretStr(f"{principal.sub}:1:{site.config.policy_version}"),
            expires_at=NOW + timedelta(minutes=5),
            key_id=f"local-{principal.sub}",
        )


def _principal(subject: str) -> VerifiedPrincipal:
    issuer = "https://identity.fixture.example.test"
    return VerifiedPrincipal(
        issuer=cast(HTTPSUrl, issuer),
        sub=subject,
        owner_key=owner_key(issuer, subject),
        groups=("soc-alpha",),
        edge="fixture",
        authenticated_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
        assertion_hash="a" * 64,
    )


def _site_config() -> SiteConfig:
    return SiteConfig(
        environment_id="alpha",
        label="alpha local isolation fixture",
        enabled=True,
        indexer_origin="https://alpha.private.example.test",
        private_network_ref="fixture-private-alpha",
        jwt_issuer="soc-alpha",
        jwt_audience="wazuh-alpha",
        kms_signing_key_arn="arn:aws:kms:us-east-1:123456789012:key/fixture-alpha",
        ca_secret_arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:fixture-alpha",
        ca_secret_version="fixture-version",
        ca_sha256="b" * 64,
        group_role_map={"soc-alpha": ("analyst_read",)},
        role_visibility={"analyst_read": Visibility.full},
        allowed_index_patterns={IndexFamily.alerts: ("wazuh-alerts-alpha-*",)},
        mapping_profile="wazuh-v4-fixture",
        policy_version="policy-v1",
        pit_supported=False,
        allowed_templates=tuple(TemplateId),
        dls_attestation_version="fixture-attestation-v1",
        composite_role_visibility={"analyst_read": Visibility.full},
    )


def _execution(principal: VerifiedPrincipal, question_id: UUID) -> ExecutionContext:
    return ExecutionContext(
        question_id=question_id,
        operation="ask",
        owner_key=principal.owner_key,
        environment_id="alpha",
        deadline_at=NOW + timedelta(minutes=5),
        cancel=_NeverCancelled(),
        calls=_CallLedger(),
        admission=AdmissionGrant(
            holder_id=uuid4(),
            slot_ids=("fixture-owner",),
            expires_at=NOW + timedelta(minutes=5),
            fence=1,
        ),
        trace_context=TraceContext(trace_id="1" * 32, span_id="2" * 16, trace_flags=1),
    )


def _fetch() -> FetchSpec:
    return FetchSpec(
        fetch_id="fetch-00",
        template_id=TemplateId.alerts_rows_v1,
        window=ResolvedWindow(
            start=NOW - timedelta(days=1),
            end=NOW,
            semantics="rolling",
            source_text="last 24 hours",
            timezone="UTC",
            anchor_at=NOW,
        ),
        filters=[],
        page_size=1,
    )


def _assert_g052_evidence_present(answer: Answer) -> None:
    vpn = next(block for block in answer.blocks if block.topic_id == "vpn")
    assert len(vpn.tables) == 1
    table = vpn.tables[0]
    assert table.rows[0].values[FieldId.rule_id] == "Synthetic vpn alert"


@pytest.mark.asyncio
async def test_g052_publication_edge_evidence_drop_mutant_is_detected() -> None:
    identity = fixture_server.identity
    principal = await identity.verify(
        headers={"x-soc-fixture-token": "fixture-browser-token"}, edge="browser"
    )
    application = fixture_server.application
    answer = await application.ask(
        AskRequest(question="g053:positive", environment_id="alpha"), principal
    )
    _assert_g052_evidence_present(answer)
    application.mutate_drop_evidence = True
    try:
        mutated_answer = await application.ask(
            AskRequest(question="g053:positive", environment_id="alpha"), principal
        )
        with pytest.raises(AssertionError):
            _assert_g052_evidence_present(mutated_answer)
    finally:
        application.mutate_drop_evidence = False

    restored_answer = await application.ask(
        AskRequest(question="g053:positive", environment_id="alpha"), principal
    )
    _assert_g052_evidence_present(restored_answer)


@pytest.mark.asyncio
async def test_g053_raw_first_token_mutant_trips_test_side_rest_oracle() -> None:
    fixture = json.loads(G053_FIXTURE.read_text(encoding="utf-8"))
    application = fixture_server.application
    async with httpx.AsyncClient(
        base_url=fixture_server.ORIGIN,
        transport=httpx.ASGITransport(app=fixture_server.rest_app),
    ) as client:
        bootstrap = await client.get(
            "/v1/bootstrap", headers={"X-SOC-Fixture-Token": "fixture-browser-token"}
        )
        cookie = SimpleCookie()
        cookie.load(bootstrap.headers["set-cookie"])
        csrf_cookie = cookie["__Host-soc-csrf"].value
        headers = {
            "X-SOC-Fixture-Token": "fixture-browser-token",
            "X-SOC-CSRF": bootstrap.json()["csrf_token"],
            "Cookie": f"__Host-soc-csrf={csrf_cookie}",
            "Origin": fixture_server.ORIGIN,
        }
        payload = {"question": "g053:positive", "environment_id": "alpha"}

        baseline_response = await client.post("/v1/questions", json=payload, headers=headers)
        assert baseline_response.status_code == 200
        fixture_server.assert_g053_response_is_sanitized(baseline_response.text)

        application.mutate_raw_provider_token = True
        try:
            response = await client.post("/v1/questions", json=payload, headers=headers)
            assert response.status_code == 200
            assert fixture["hostile_first_token"] in response.text
            with pytest.raises(AssertionError, match="raw provider first token escaped"):
                fixture_server.assert_g053_response_is_sanitized(response.text)
        finally:
            application.mutate_raw_provider_token = False

        restored_response = await client.post("/v1/questions", json=payload, headers=headers)
        assert restored_response.status_code == 200
        fixture_server.assert_g053_response_is_sanitized(restored_response.text)


@pytest.mark.asyncio
async def test_gn01_cross_analyst_result_reuse_mutant_trips_expected_record_assertion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture_bytes = GN01_FIXTURE.read_bytes()
    assert hashlib.sha256(fixture_bytes).hexdigest() == GN01_FIXTURE_SHA256
    fixture = cast(dict[str, object], json.loads(fixture_bytes))
    variants = cast(dict[str, object], fixture["variants"])
    positive = cast(dict[str, object], variants["positive"])
    expected = cast(list[str], positive["expected_record_ids"])
    question_id = uuid4()
    responses: list[str] = []

    async def response(request: httpx.Request) -> httpx.Response:
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        subject = token.split(":", maxsplit=1)[0]
        if request.url.path.endswith("/_validate/query"):
            return httpx.Response(200, json={"valid": True})
        if request.url.path.endswith("/_search"):
            policy_version = token.split(":", maxsplit=2)[-1]
            record = f"{subject}-{policy_version}-private-row"
            responses.append(record)
            return httpx.Response(
                200,
                json={
                    "hits": {
                        "total": {"value": 1, "relation": "eq"},
                        "hits": [
                            {
                                "_index": "wazuh-alerts-alpha-2026.09.30",
                                "_id": record,
                                "_source": {
                                    "@timestamp": "2026-09-30T11:00:00Z",
                                    "agent": {"id": "007", "name": f"{subject}-agent"},
                                    "rule": {"id": "5710", "level": 5, "groups": ["auth"]},
                                    "data": {"srcip": "192.0.2.10", "dstip": "192.0.2.8"},
                                },
                            }
                        ],
                    }
                },
            )
        return httpx.Response(404, json={"error": "not found"})

    client = httpx.AsyncClient(
        base_url="http://127.0.0.1",
        trust_env=False,
        follow_redirects=False,
        transport=httpx.MockTransport(response),
    )
    broker = _IsolationBroker()
    indexer = WazuhIndexer(
        broker,
        _ReadAdmission(),
        lambda _site: client,
        profiles={"wazuh-v4-fixture": default_profile("wazuh-v4-fixture")},
        clock=lambda: NOW,
        content_sha="c" * 40,
    )
    policy = MappedSitePolicy((_site_config(),), now=lambda: NOW)

    async def read(subject: str) -> FetchResult:
        principal = _principal(subject)
        site = policy.authorize(principal, "alpha")
        execution = _execution(principal, question_id)
        return await indexer.execute(
            _fetch(),
            topic_id="ldap",
            question_id=question_id,
            principal=principal,
            site=site,
            execution=execution,
        )

    def record_id(result: FetchResult) -> str:
        assert len(result.rows) == 1 and result.rows[0].record_ref is not None
        return result.rows[0].record_ref.record_id

    try:
        assert [record_id(await read(subject)) for subject in ("alice", "bob")] == expected[:2]
        assert responses == expected[:2]

        original_execute = WazuhIndexer.execute
        first_by_question: dict[UUID, FetchResult] = {}
        mutation_hits = 0

        async def reuse_first_analyst_result(
            active_indexer: WazuhIndexer,
            fetch: FetchSpec,
            *,
            topic_id: str,
            question_id: UUID,
            principal: VerifiedPrincipal,
            site: AuthorizedSite,
            execution: ExecutionContext,
        ) -> FetchResult:
            nonlocal mutation_hits
            if principal.sub == "bob" and question_id in first_by_question:
                mutation_hits += 1
                return first_by_question[question_id]
            result = await original_execute(
                active_indexer,
                fetch,
                topic_id=topic_id,
                question_id=question_id,
                principal=principal,
                site=site,
                execution=execution,
            )
            if principal.sub == "alice":
                first_by_question.setdefault(question_id, result)
            return result

        with monkeypatch.context() as mutation:
            mutation.setattr(WazuhIndexer, "execute", reuse_first_analyst_result)
            alice_result = await read("alice")
            bob_result = await read("bob")
            assert record_id(alice_result) == expected[0]
            with pytest.raises(AssertionError, match="cross-analyst result reuse"):
                _assert_record_is_for_analyst(record_id(bob_result), "bob")
        assert mutation_hits == 1
        assert record_id(await read("bob")) == expected[1]
    finally:
        await client.aclose()


def _assert_record_is_for_analyst(record_id: str, subject: str) -> None:
    assert record_id.startswith(f"{subject}-"), "cross-analyst result reuse at WazuhIndexer.execute"
