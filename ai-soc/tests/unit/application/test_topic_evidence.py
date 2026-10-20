from __future__ import annotations

from contextlib import AbstractContextManager, nullcontext
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import uuid4

import pytest

from ai_soc.application.errors import ServiceFailure
from ai_soc.application.runtime import RequestCancellation, RequestCancelled
from ai_soc.application.topic_evidence import TopicEvidence, evidence_pack
from ai_soc.contracts.canonical import canonical_bytes
from ai_soc.contracts.models import (
    AdmissionGrant,
    AuthorizedSite,
    CheckOutcome,
    CheckResult,
    DomainError,
    ErrorCode,
    EvidenceItem,
    EvidenceSourceCheck,
    EvidenceSourceRow,
    ExecutionContext,
    FetchResult,
    FetchScope,
    FetchSpec,
    FetchState,
    FetchStep,
    FieldId,
    Filter,
    IndexFamily,
    LeftOutReason,
    LocaleText,
    PlanProvenance,
    PlaybookDefinition,
    PlaybookRun,
    QuestionPlan,
    ResolvedWindow,
    SiteConfig,
    SnapshotKind,
    SnapshotRef,
    StageName,
    TemplateId,
    TopicPlan,
    TraceContext,
    VerifiedPrincipal,
    Visibility,
    WindowDefault,
)
from ai_soc.query.playbooks import (
    DeclarativePlaybookExecutor,
    playbook_step_spec,
    resolve_default,
)

NOW = datetime(2026, 10, 13, 12, tzinfo=UTC)
_POLICY_HASH = "c" * 63 + "1"
_ROW_EVIDENCE = "ev1_" + "1" * 64
_CHECK_EVIDENCE = "ev1_" + "2" * 64


def _stage(stage: StageName, trace_context: TraceContext) -> AbstractContextManager[object]:
    return nullcontext(None)


class _Ledger:
    def claim(self, kind: object) -> None:
        return None


class _Clock:
    def now(self) -> datetime:
        return NOW


class _Playbooks:
    def __init__(self, run: PlaybookRun | None = None) -> None:
        self._run = run
        self.calls: list[TopicPlan] = []

    async def run(self, plan: TopicPlan, **kwargs: object) -> PlaybookRun:
        self.calls.append(plan)
        if self._run is None:
            raise AssertionError("playbook executor must not run")
        return self._run


class _Fetches:
    def __init__(self, results: dict[str, FetchResult]) -> None:
        self._results = results
        self.calls: list[FetchSpec] = []

    async def execute(self, fetch: FetchSpec, **kwargs: object) -> FetchResult:
        self.calls.append(fetch)
        return self._results[fetch.fetch_id]

    async def page(self, *args: object, **kwargs: object) -> FetchResult:
        raise AssertionError("evidence gathering never pages")


class _RecordingFetcher:
    def __init__(self, result: FetchResult) -> None:
        self._result = result
        self.specs: list[FetchSpec] = []

    async def execute(self, fetch: FetchSpec, **kwargs: object) -> FetchResult:
        self.specs.append(fetch)
        return self._result

    async def page(self, *args: object, **kwargs: object) -> FetchResult:
        raise AssertionError("playbook reads never page")


class _Catalog:
    def __init__(self, playbook: PlaybookDefinition) -> None:
        self._playbook = playbook

    def playbook(self, playbook_id: str) -> PlaybookDefinition | None:
        return self._playbook

    def expectation(self, expectation_id: str, *, topic_id: str) -> None:
        return None


def _window() -> ResolvedWindow:
    return ResolvedWindow(
        start=NOW - timedelta(days=1),
        end=NOW,
        semantics="rolling",
        source_text="last 24 hours",
        timezone="UTC",
        anchor_at=NOW,
    )


def _fetch_spec() -> FetchSpec:
    return FetchSpec(
        fetch_id="fetch_alerts",
        template_id=TemplateId.alerts_rows_v1,
        window=_window(),
        filters=[Filter(field=FieldId.agent_id, op="eq", value="007")],
    )


def _topic(
    *,
    fetches: list[FetchSpec] | None = None,
    failure: bool = False,
    playbook_id: str | None = None,
) -> TopicPlan:
    return TopicPlan(
        topic_id="ldap",
        ordinal=0,
        document=False,
        failure=failure,
        judgment=False,
        fetches=fetches if fetches is not None else [],
        playbook_id=playbook_id,
        playbook_window=None,
        cue_ids=[],
        alias_ids=[],
    )


def _plan(topic: TopicPlan) -> QuestionPlan:
    return QuestionPlan(
        question_id=uuid4(),
        environment_id="alpha",
        owner_key="a" * 64,
        content_sha="b" * 40,
        policy_hash=_POLICY_HASH,
        language="en",
        timezone="UTC",
        anchor_at=NOW,
        topics=[topic],
        provenance=PlanProvenance(
            cue_pack_sha="d" * 64,
            normalized_question_hash="e" * 64,
            origin="new",
            matched_spans=[],
        ),
    )


def _principal() -> VerifiedPrincipal:
    return VerifiedPrincipal(
        issuer="https://id.example.test",
        sub="analyst-007",
        owner_key="a" * 64,
        groups=("soc-alpha",),
        edge="fixture",
        authenticated_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
        assertion_hash="a" * 64,
    )


def _site() -> AuthorizedSite:
    config = SiteConfig(
        environment_id="alpha",
        label="alpha",
        enabled=True,
        indexer_origin="https://alpha.private.example.test",
        private_network_ref="vpn-alpha",
        jwt_issuer="soc-alpha",
        jwt_audience="wazuh-alpha",
        kms_signing_key_arn="arn:aws:kms:us-east-1:123456789012:key/alpha",
        ca_secret_arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:alpha",
        ca_secret_version="version-alpha",
        ca_sha256="b" * 64,
        group_role_map={"soc-alpha": ("analyst_read",)},
        role_visibility={"analyst_read": Visibility.full},
        allowed_index_patterns={
            IndexFamily.alerts: ("wazuh-alerts-alpha-*",),
            IndexFamily.vulnerabilities: ("wazuh-states-vulnerabilities-alpha-*",),
        },
        mapping_profile="wazuh-v4-fixture",
        policy_version="policy-1",
        pit_supported=True,
        allowed_templates=tuple(TemplateId),
        dls_attestation_version="dls-7",
        composite_role_visibility={"analyst_read": Visibility.full},
    )
    return AuthorizedSite(
        config=config,
        backend_roles=("analyst_read",),
        visibility=Visibility.full,
        config_hash="a" * 64,
        policy_hash=_POLICY_HASH,
    )


def _execution(
    plan: QuestionPlan, *, cancel: RequestCancellation | None = None
) -> ExecutionContext:
    return ExecutionContext(
        question_id=plan.question_id,
        operation="ask",
        owner_key=plan.owner_key,
        environment_id=plan.environment_id,
        deadline_at=NOW + timedelta(seconds=30),
        cancel=cancel if cancel is not None else RequestCancellation(),
        calls=_Ledger(),
        admission=AdmissionGrant(
            holder_id=uuid4(),
            slot_ids=("alpha-owner",),
            expires_at=NOW + timedelta(seconds=30),
            fence=1,
        ),
        trace_context=TraceContext(trace_id="1" * 32, span_id="1" * 16, trace_flags=1),
    )


def _row_item(evidence_id: str, *, topic_id: str = "ldap") -> EvidenceItem:
    return EvidenceItem(
        evidence_id=evidence_id,
        topic_id=topic_id,
        fetch_id="fetch_alerts",
        check_id=None,
        kind="row",
        source=EvidenceSourceRow(index_alias="wazuh-alerts-alpha-2026.10", record_id="fixture-1"),
        snapshot=SnapshotRef(kind=SnapshotKind.first_page_only, key="f" * 64, at=NOW),
        values={FieldId.rule_id: "Synthetic alert"},
        visibility=Visibility.full,
        scope_hash="a" * 64,
    )


def _check_item(evidence_id: str) -> EvidenceItem:
    return EvidenceItem(
        evidence_id=evidence_id,
        topic_id="ldap",
        fetch_id=None,
        check_id="check_alerts",
        kind="check",
        source=EvidenceSourceCheck(step_id="step_compare", operand_ids=[]),
        snapshot=SnapshotRef(kind=SnapshotKind.first_page_only, key="e" * 64, at=NOW),
        values={"outcome": "passed", "operand_ids": []},
        visibility=Visibility.full,
        scope_hash="a" * 64,
    )


def _check(check_id: str) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        topic_id="ldap",
        label="Alerts present",
        outcome=CheckOutcome.passed,
        evidence_ids=[],
        message="Check passed.",
    )


def _fetch_result(
    fetch_id: str,
    *,
    state: FetchState = FetchState.rows,
    items: list[EvidenceItem] | None = None,
) -> FetchResult:
    error = None
    if state == FetchState.unavailable:
        error = DomainError(
            code=ErrorCode.INDEXER_UNAVAILABLE,
            message="Synthetic fixture result.",
            retryable=True,
            trace_id="0" * 32,
        )
    return FetchResult(
        fetch_id=fetch_id,
        topic_id="ldap",
        state=state,
        scope=FetchScope(
            environment_id="alpha",
            template_id=TemplateId.alerts_rows_v1,
            index_family=IndexFamily.alerts,
            filters=[],
            visibility=Visibility.full,
            policy_hash=_POLICY_HASH,
            snapshot=SnapshotKind.first_page_only,
            displayed_rows=0,
        ),
        window=_window(),
        columns=[],
        rows=[],
        count=None,
        checks=[],
        snapshot=SnapshotRef(kind=SnapshotKind.first_page_only, key="1" * 64, at=NOW),
        items=items if items is not None else [],
        error=error,
    )


def _evidence(playbooks: object, fetches: object) -> TopicEvidence:
    return TopicEvidence(playbooks=playbooks, fetches=fetches, stage=_stage, metrics=None)


@pytest.mark.asyncio
async def test_gather_builds_pack_only_when_requested() -> None:
    topic = _topic(fetches=[_fetch_spec()])
    plan = _plan(topic)
    item = _row_item(_ROW_EVIDENCE)
    result = _fetch_result("fetch_alerts", items=[item])
    principal = _principal()
    site = _site()

    without_pack = await _evidence(_Playbooks(), _Fetches({"fetch_alerts": result})).gather(
        topic,
        plan=plan,
        principal=principal,
        site=site,
        build_pack=False,
        execution=_execution(plan),
    )

    assert without_pack.pack is None
    assert without_pack.tables == [result]
    assert without_pack.checks == []

    with_pack = await _evidence(_Playbooks(), _Fetches({"fetch_alerts": result})).gather(
        topic,
        plan=plan,
        principal=principal,
        site=site,
        build_pack=True,
        execution=_execution(plan),
    )

    assert with_pack.pack is not None
    assert with_pack.pack.sha256 == evidence_pack(plan, topic, [result], []).sha256
    assert with_pack.pack.items == [item]


@pytest.mark.asyncio
async def test_unavailable_fetch_reports_one_retryable_left_out() -> None:
    topic = _topic(fetches=[_fetch_spec()])
    plan = _plan(topic)
    unavailable = _fetch_result("fetch_alerts", state=FetchState.unavailable)
    fetches = _Fetches({"fetch_alerts": unavailable})

    gathered = await _evidence(_Playbooks(), fetches).gather(
        topic,
        plan=plan,
        principal=_principal(),
        site=_site(),
        build_pack=False,
        execution=_execution(plan),
    )

    assert len(gathered.left_out) == 1
    left = gathered.left_out[0]
    assert left.topic_id == "ldap"
    assert left.stage == "fetch"
    assert left.reason == LeftOutReason.evidence_unavailable
    assert left.retryable is True


@pytest.mark.asyncio
async def test_playbook_runs_only_for_failure_topics_and_keeps_check_items() -> None:
    check_item = _check_item(_CHECK_EVIDENCE)
    row_item = _row_item(_ROW_EVIDENCE)
    run = PlaybookRun(fetches=[], checks=[_check("check_alerts")], items=[check_item, row_item])
    principal = _principal()
    site = _site()

    topic = _topic(failure=True, playbook_id="ldap_checks")
    plan = _plan(topic)
    playbooks = _Playbooks(run)
    gathered = await _evidence(playbooks, _Fetches({})).gather(
        topic,
        plan=plan,
        principal=principal,
        site=site,
        build_pack=True,
        execution=_execution(plan),
    )

    assert [call.topic_id for call in playbooks.calls] == ["ldap"]
    assert gathered.checks == run.checks
    assert gathered.pack is not None
    assert gathered.pack.items == [check_item]

    topic = _topic(failure=True, playbook_id=None)
    plan = _plan(topic)
    playbooks = _Playbooks(run)
    gathered = await _evidence(playbooks, _Fetches({})).gather(
        topic,
        plan=plan,
        principal=principal,
        site=site,
        build_pack=True,
        execution=_execution(plan),
    )

    assert playbooks.calls == []
    assert gathered.checks == []

    topic = _topic(failure=False, playbook_id="ldap_checks")
    plan = _plan(topic)
    playbooks = _Playbooks(run)
    gathered = await _evidence(playbooks, _Fetches({})).gather(
        topic,
        plan=plan,
        principal=principal,
        site=site,
        build_pack=True,
        execution=_execution(plan),
    )

    assert playbooks.calls == []
    assert gathered.checks == []


def test_evidence_pack_rejects_foreign_topic_items() -> None:
    topic = _topic()
    plan = _plan(topic)
    foreign = _fetch_result("fetch_alerts", items=[_row_item(_ROW_EVIDENCE, topic_id="vpn")])

    with pytest.raises(ServiceFailure) as error:
        evidence_pack(plan, topic, [foreign], [])

    assert error.value.error.code == ErrorCode.EVIDENCE_INVALID
    assert error.value.error.message == "Evidence crossed topic boundaries."


@pytest.mark.asyncio
async def test_cancelled_execution_stops_before_first_fetch() -> None:
    topic = _topic(fetches=[_fetch_spec()])
    plan = _plan(topic)
    fetches = _Fetches({})
    cancel = RequestCancellation()
    cancel.cancel()

    with pytest.raises(RequestCancelled):
        await _evidence(_Playbooks(), fetches).gather(
            topic,
            plan=plan,
            principal=_principal(),
            site=_site(),
            build_pack=False,
            execution=_execution(plan, cancel=cancel),
        )

    assert fetches.calls == []


class _CancellingFetches(_Fetches):
    def __init__(self, results: dict[str, FetchResult], cancel: RequestCancellation) -> None:
        super().__init__(results)
        self._cancel = cancel

    async def execute(self, fetch: FetchSpec, **kwargs: object) -> FetchResult:
        result = await super().execute(fetch, **kwargs)
        self._cancel.cancel()
        return result


def _named_spec(fetch_id: str) -> FetchSpec:
    return _fetch_spec().model_copy(update={"fetch_id": fetch_id})


@pytest.mark.asyncio
async def test_cancellation_during_a_fetch_stops_the_next_fetch() -> None:
    topic = _topic(fetches=[_named_spec("fetch_a"), _named_spec("fetch_b")])
    plan = _plan(topic)
    cancel = RequestCancellation()
    fetches = _CancellingFetches(
        {"fetch_a": _fetch_result("fetch_a"), "fetch_b": _fetch_result("fetch_b")}, cancel
    )

    with pytest.raises(RequestCancelled):
        await _evidence(_Playbooks(), fetches).gather(
            topic,
            plan=plan,
            principal=_principal(),
            site=_site(),
            build_pack=False,
            execution=_execution(plan, cancel=cancel),
        )

    assert [call.fetch_id for call in fetches.calls] == ["fetch_a"]


@pytest.mark.asyncio
async def test_unavailable_fetch_does_not_stop_later_fetches() -> None:
    topic = _topic(fetches=[_named_spec(name) for name in ("fetch_a", "fetch_b", "fetch_c")])
    plan = _plan(topic)
    results = {
        "fetch_a": _fetch_result("fetch_a"),
        "fetch_b": _fetch_result("fetch_b", state=FetchState.unavailable),
        "fetch_c": _fetch_result("fetch_c"),
    }

    gathered = await _evidence(_Playbooks(), _Fetches(results)).gather(
        topic,
        plan=plan,
        principal=_principal(),
        site=_site(),
        build_pack=False,
        execution=_execution(plan),
    )

    assert [table.fetch_id for table in gathered.tables] == ["fetch_a", "fetch_b", "fetch_c"]
    assert len(gathered.left_out) == 1
    assert gathered.left_out[0].retryable is True


@pytest.mark.asyncio
async def test_playbook_step_spec_matches_executor_fetch_spec() -> None:
    step = FetchStep(
        kind="fetch",
        step_id="step_alerts",
        label=LocaleText(en="Alerts", es="Alertas"),
        fetch_id="fetch_alerts",
        template_id=TemplateId.alerts_rows_v1,
        window_default=WindowDefault(unit="hours", amount=24),
        filters=[Filter(field=FieldId.agent_id, op="eq", value="007")],
    )
    playbook = PlaybookDefinition(
        playbook_id="ldap_checks",
        topic_id="ldap",
        title=LocaleText(en="LDAP checks", es="Comprobaciones LDAP"),
        internal_context="Do not render this internal note.",
        steps=[step],
    )
    topic = _topic(failure=True, playbook_id="ldap_checks")
    plan = _plan(topic)
    fetcher = _RecordingFetcher(_fetch_result("fetch_alerts"))
    executor = DeclarativePlaybookExecutor(
        _Catalog(playbook), fetcher, _Clock(), content_sha="c" * 40
    )

    run = await executor.run(
        topic,
        principal=_principal(),
        site=_site(),
        question_id=plan.question_id,
        execution=_execution(plan),
    )

    assert [result.fetch_id for result in run.fetches] == ["fetch_alerts"]
    assert len(fetcher.specs) == 1
    executed = fetcher.specs[0]
    window = resolve_default(step.window_default, anchor=NOW)
    expected = FetchSpec(
        fetch_id=step.fetch_id,
        template_id=TemplateId(step.template_id),
        window=window,
        filters=step.filters,
    )
    assert executed == expected
    assert (
        sha256(canonical_bytes(executed)).hexdigest()
        == sha256(canonical_bytes(playbook_step_spec(step, window))).hexdigest()
    )
