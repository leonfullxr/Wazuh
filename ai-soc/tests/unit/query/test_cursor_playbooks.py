from __future__ import annotations

import base64
import hashlib
import json
from datetime import timedelta
from pathlib import Path
from uuid import UUID

import pytest

from ai_soc.contracts.models import (
    CheckOutcome,
    CompareCountStep,
    Count,
    CursorPayload,
    DomainError,
    ErrorCode,
    EvidenceRow,
    ExpectationDefinition,
    ExpectationMatchStep,
    FetchCountOperand,
    FetchResult,
    FetchScope,
    FetchSpec,
    FetchState,
    FetchStep,
    FieldId,
    IndexFamily,
    LocaleText,
    PlaybookDefinition,
    ReportConfigurationMissingStep,
    SnapshotKind,
    SnapshotRef,
    TemplateId,
    TopicPlan,
    Visibility,
)
from ai_soc.query.cursors import CursorCipher, CursorError
from ai_soc.query.playbooks import DeclarativePlaybookExecutor


def _tamper_token_payload_middle(token: str) -> str:
    prefix, key_id, payload_b64 = token.split(".", 2)
    raw = bytearray(base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)))
    mid = len(raw) // 2
    raw[mid] ^= 0xFF
    tampered_b64 = base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode("ascii")
    return f"{prefix}.{key_id}.{tampered_b64}"


def payload(principal, site, fetch, *, key_id: str = "old-key") -> CursorPayload:
    _, authorized = site
    return CursorPayload(
        key_id=key_id,
        owner_key=principal.owner_key,
        environment_id=authorized.config.environment_id,
        policy_hash=authorized.policy_hash,
        content_sha="c" * 40,
        question_id=UUID("00000000-0000-4000-8000-000000000001"),
        topic_id="ldap",
        fetch_id=fetch.fetch_id,
        template_id=TemplateId(fetch.template_id),
        filters=fetch.filters,
        window=fetch.window,
        projection_hash="d" * 64,
        sort_values=["2026-09-30T11:00:00Z", "record-1"],
        pit_id="private-pit-id",
        snapshot=SnapshotRef(
            kind=SnapshotKind.pit,
            key="e" * 64,
            at=fetch.window.anchor_at,
            expires_at=fetch.window.anchor_at + timedelta(minutes=5),
        ),
        page_size=2,
        expires_at=fetch.window.anchor_at + timedelta(seconds=299),
    )


def test_cursor_rotation_authentication_expiry_and_claim_binding(
    principal, site, fetch, cursor_cipher
):
    now = fetch.window.anchor_at
    old = CursorCipher(keys={"old-key": b"o" * 32}, current_key_id="old-key", now=lambda: now)
    token = old.seal(payload(principal, site, fetch))
    rotated = CursorCipher(
        keys={"old-key": b"o" * 32, "new-key": b"n" * 32},
        current_key_id="new-key",
        now=lambda: now,
    )
    decoded = rotated.open(
        token,
        owner_key=principal.owner_key,
        environment_id="alpha",
        policy_hash=site[1].policy_hash,
        content_sha="c" * 40,
    )
    assert decoded.pit_id == "private-pit-id"
    assert "private-pit-id" not in token

    for claim in (
        {"owner_key": "f" * 64},
        {"environment_id": "beta"},
        {"policy_hash": "a" * 64},
        {"content_sha": "b" * 40},
    ):
        with pytest.raises(CursorError) as error:
            rotated.open(
                token,
                owner_key=claim.get("owner_key", principal.owner_key),
                environment_id=claim.get("environment_id", "alpha"),
                policy_hash=claim.get("policy_hash", site[1].policy_hash),
                content_sha=claim.get("content_sha", "c" * 40),
            )
        assert error.value.code.value == "CURSOR_EXPIRED"

    with pytest.raises(CursorError):
        rotated.open(
            _tamper_token_payload_middle(token),
            owner_key=principal.owner_key,
            environment_id="alpha",
            policy_hash=site[1].policy_hash,
            content_sha="c" * 40,
        )
    expired = CursorCipher(
        keys={"old-key": b"o" * 32},
        current_key_id="old-key",
        now=lambda: now + timedelta(seconds=299),
    )
    with pytest.raises(CursorError):
        expired.open(
            token,
            owner_key=principal.owner_key,
            environment_id="alpha",
            policy_hash=site[1].policy_hash,
            content_sha="c" * 40,
        )


@pytest.mark.parametrize("variant", ["positive", "negative", "boundary", "failure"])
def test_cursor_case_variants_bind_owner_expiry_and_authentication(
    principal, site, fetch, variant, request
):
    fixture_path = Path(__file__).parent / "data/cursor_binding_cases.json"
    fixture_bytes = fixture_path.read_bytes()
    fixture_sha256 = hashlib.sha256(fixture_bytes).hexdigest()
    assert fixture_sha256 == "707cb5a283cc947aa0cacc73d8ec48a6ab3e596faa809598d161ac17e2067d8a"
    scenario = json.loads(fixture_bytes)["cases"][variant]
    request.node.user_properties.extend(
        [
            ("acceptance_ids", "GN03"),
            ("case_id", "B3-GN03.cursor-binding-component"),
            ("variant", variant),
            ("fixture_sha256", fixture_sha256),
        ]
    )
    now = fetch.window.anchor_at
    original = CursorCipher(keys={"old-key": b"o" * 32}, current_key_id="old-key", now=lambda: now)
    token = original.seal(payload(principal, site, fetch))
    rotated = CursorCipher(
        keys={"old-key": b"o" * 32, "new-key": b"n" * 32},
        current_key_id="new-key",
        now=lambda: now,
    )
    expected_claim = scenario.get("claim")
    if expected_claim == "matching":
        decoded = rotated.open(
            token,
            owner_key=principal.owner_key,
            environment_id="alpha",
            policy_hash=site[1].policy_hash,
            content_sha="c" * 40,
        )
        assert decoded.pit_id == "private-pit-id"
        assert "private-pit-id" not in token
    elif expected_claim == "foreign-owner":
        with pytest.raises(CursorError):
            rotated.open(
                token,
                owner_key="f" * 64,
                environment_id="alpha",
                policy_hash=site[1].policy_hash,
                content_sha="c" * 40,
            )
    elif "now_offset_seconds" in scenario:
        boundary = CursorCipher(
            keys={"old-key": b"o" * 32},
            current_key_id="old-key",
            now=lambda: now + timedelta(seconds=scenario["now_offset_seconds"]),
        )
        with pytest.raises(CursorError):
            boundary.open(
                token,
                owner_key=principal.owner_key,
                environment_id="alpha",
                policy_hash=site[1].policy_hash,
                content_sha="c" * 40,
            )
    else:
        with pytest.raises(CursorError):
            rotated.open(
                _tamper_token_payload_middle(token),
                owner_key=principal.owner_key,
                environment_id="alpha",
                policy_hash=site[1].policy_hash,
                content_sha="c" * 40,
            )


def test_cursor_open_rejects_short_invalid_base64_payload(principal, site, fetch):
    now = fetch.window.anchor_at
    cipher = CursorCipher(keys={"old-key": b"o" * 32}, current_key_id="old-key", now=lambda: now)
    with pytest.raises(CursorError):
        cipher.open(
            "v1.old-key.a",
            owner_key=principal.owner_key,
            environment_id="alpha",
            policy_hash=site[1].policy_hash,
            content_sha="c" * 40,
        )


def test_cursor_open_rejects_non_canonical_base64url_encoding(principal, site, fetch):
    now = fetch.window.anchor_at
    cipher = CursorCipher(keys={"old-key": b"o" * 32}, current_key_id="old-key", now=lambda: now)
    token = cipher.seal(payload(principal, site, fetch))
    prefix, key_id, payload_b64 = token.split(".", 2)
    padded = payload_b64 + "="
    with pytest.raises(CursorError):
        cipher.open(
            f"{prefix}.{key_id}.{padded}",
            owner_key=principal.owner_key,
            environment_id="alpha",
            policy_hash=site[1].policy_hash,
            content_sha="c" * 40,
        )


def test_cursor_token_and_key_rotation_resource_bounds(principal, site, fetch):
    now = fetch.window.anchor_at
    narrow = CursorCipher(
        keys={"old-key": b"o" * 32},
        current_key_id="old-key",
        now=lambda: now,
        max_token_bytes=64,
    )
    with pytest.raises(CursorError):
        narrow.seal(payload(principal, site, fetch))
    with pytest.raises(ValueError):
        CursorCipher(
            keys={"a": b"a" * 32, "b": b"b" * 32, "c": b"c" * 32},
            current_key_id="a",
            now=lambda: now,
        )


class Clock:
    def __init__(self, now):
        self._now = now

    def now(self):
        return self._now

    def monotonic(self):
        return 0.0


class Catalog:
    def __init__(self, playbook):
        self._playbook = playbook

    def playbook(self, playbook_id):
        return self._playbook if playbook_id == self._playbook.playbook_id else None

    def expectation(self, expectation_id, *, topic_id):
        return None


class UnusedFetcher:
    async def execute(self, *args, **kwargs):
        raise AssertionError("report-only playbook must not execute a fetch")

    async def page(self, *args, **kwargs):
        raise AssertionError("report-only playbook must not page")


class ResultFetcher:
    def __init__(self, by_fetch_id):
        self.by_fetch_id = by_fetch_id

    async def execute(self, fetch: FetchSpec, **kwargs):
        return self.by_fetch_id[fetch.fetch_id]

    async def page(self, *args, **kwargs):
        raise AssertionError("playbook checks never page")


def make_fetch_result(fetch, site, fetch_id, state, count_value):
    authorized = site[1]
    snapshot = SnapshotRef(
        kind=SnapshotKind.first_page_only,
        key=("1" if fetch_id == "left" else "2") * 64,
        at=fetch.window.anchor_at,
    )
    error = None
    if state in (FetchState.denied, FetchState.unavailable):
        error = DomainError(
            code=(
                ErrorCode.INDEXER_DENIED
                if state == FetchState.denied
                else ErrorCode.INDEXER_UNAVAILABLE
            ),
            message="Synthetic fixture result.",
            retryable=False,
            trace_id="0" * 32,
            details={},
        )
    return FetchResult(
        fetch_id=fetch_id,
        topic_id="ldap",
        state=state,
        scope=FetchScope(
            environment_id="alpha",
            template_id=TemplateId.alerts_count_v1,
            index_family=IndexFamily.alerts,
            filters=[],
            visibility=Visibility(authorized.visibility),
            policy_hash=authorized.policy_hash,
            snapshot=SnapshotKind.first_page_only,
            displayed_rows=0,
        ),
        window=fetch.window,
        columns=[],
        rows=[],
        count=(
            Count(
                value=count_value,
                relation="eq",
                scope="matching_visible_records",
                computed_by="indexer",
            )
            if count_value is not None
            else None
        ),
        checks=[],
        snapshot=snapshot,
        items=[],
        error=error,
    )


@pytest.mark.asyncio
async def test_playbook_reports_absent_expectation_as_not_configured(principal, site, execution):
    step = ReportConfigurationMissingStep(
        kind="report_configuration_missing",
        step_id="check_config",
        label=LocaleText(en="Configuration", es="Configuración"),
        check_id="configuration_check",
        expectation_id="approved_threshold",
    )
    playbook = PlaybookDefinition(
        playbook_id="ldap_checks",
        topic_id="ldap",
        title=LocaleText(en="LDAP checks", es="Comprobaciones LDAP"),
        internal_context="Do not render this internal note.",
        steps=[step],
    )
    executor = DeclarativePlaybookExecutor(
        Catalog(playbook), UnusedFetcher(), Clock(execution.deadline_at), content_sha="c" * 40
    )
    plan = TopicPlan(
        topic_id="ldap",
        ordinal=0,
        document=False,
        failure=True,
        judgment=False,
        fetches=[],
        playbook_id="ldap_checks",
        cue_ids=[],
        alias_ids=[],
    )
    result = await executor.run(
        plan,
        principal=principal,
        site=site[1],
        question_id=execution.question_id,
        execution=execution,
    )
    assert [check.outcome for check in result.checks] == [CheckOutcome.not_configured]
    assert result.items[0].values["outcome"] == "not_configured"
    assert "Do not render" not in repr(result)


@pytest.mark.asyncio
async def test_playbook_report_configuration_missing_passes_when_expectation_present(
    principal, site, execution
):
    step = ReportConfigurationMissingStep(
        kind="report_configuration_missing",
        step_id="check_config",
        label=LocaleText(en="Configuration", es="Configuración"),
        check_id="configuration_check",
        expectation_id="approved_threshold",
    )
    playbook = PlaybookDefinition(
        playbook_id="ldap_checks",
        topic_id="ldap",
        title=LocaleText(en="LDAP checks", es="Comprobaciones LDAP"),
        internal_context="Internal.",
        steps=[step],
    )
    expectation = ExpectationDefinition(
        expectation_id="approved_threshold",
        topic_id="ldap",
        field=FieldId.rule_level,
        op="gte",
        value=5,
        source="site",
        version="site-policy-8",
    )

    class CatalogWithExpectation(Catalog):
        def expectation(self, expectation_id, *, topic_id):
            if expectation_id == expectation.expectation_id and topic_id == expectation.topic_id:
                return expectation
            return None

    executor = DeclarativePlaybookExecutor(
        CatalogWithExpectation(playbook),
        UnusedFetcher(),
        Clock(execution.deadline_at),
        content_sha="c" * 40,
    )
    plan = TopicPlan(
        topic_id="ldap",
        ordinal=0,
        document=False,
        failure=True,
        judgment=False,
        fetches=[],
        playbook_id="ldap_checks",
        cue_ids=[],
        alias_ids=[],
    )
    result = await executor.run(
        plan,
        principal=principal,
        site=site[1],
        question_id=execution.question_id,
        execution=execution,
    )
    assert result.checks[0].outcome == CheckOutcome.passed


def test_expectation_uses_typed_field_and_site_source():
    expectation = ExpectationDefinition(
        expectation_id="approved_threshold",
        topic_id="ldap",
        field=FieldId.rule_level,
        op="gte",
        value=5,
        source="site",
        version="site-policy-8",
    )
    assert str(expectation.field) == FieldId.rule_level.value
    assert expectation.value == 5


@pytest.mark.asyncio
@pytest.mark.parametrize("variant", ["positive", "negative", "boundary", "failure"])
async def test_expectation_match_uses_typed_site_configuration(
    principal, site, execution, fetch, variant, request
):
    fixture_path = Path(__file__).parent / "data/g010_expectation_cases.json"
    fixture_bytes = fixture_path.read_bytes()
    fixture_sha256 = hashlib.sha256(fixture_bytes).hexdigest()
    assert fixture_sha256 == "23ddae4fd5b066383e0565eb4168bc8ea76e44f86bc6d6b989ec0a2320a463fa"
    scenario = json.loads(fixture_bytes)["cases"][variant]
    request.node.user_properties.extend(
        [
            ("acceptance_ids", "G010"),
            ("case_id", "B3-G010.expectation"),
            ("variant", variant),
            ("fixture_sha256", fixture_sha256),
        ]
    )
    expected_definition = scenario["expectation"]
    expectation = (
        ExpectationDefinition(
            expectation_id="approved_threshold",
            topic_id="ldap",
            field=FieldId(expected_definition["field"]),
            op=expected_definition["op"],
            value=expected_definition["value"],
            source="site",
            version=expected_definition["version"],
        )
        if expected_definition is not None
        else None
    )
    label = LocaleText(en="Threshold check", es="Comprobación del umbral")
    playbook = PlaybookDefinition(
        playbook_id="ldap_threshold",
        topic_id="ldap",
        title=label,
        internal_context="Never render this text.",
        steps=[
            FetchStep(
                kind="fetch",
                step_id="read_levels",
                label=label,
                fetch_id="levels",
                template_id=TemplateId.alerts_rows_v1,
                window_default={"unit": "hours", "amount": 24},
                filters=[],
            ),
            ExpectationMatchStep(
                kind="expectation_match",
                step_id="match_level",
                label=label,
                check_id="threshold_check",
                fetch_id="levels",
                field=FieldId.rule_level,
                expectation_id="approved_threshold",
                quantifier="any",
            ),
        ],
    )

    class CatalogWithExpectation(Catalog):
        def expectation(self, expectation_id, *, topic_id):
            if (
                expectation is not None
                and expectation_id == expectation.expectation_id
                and topic_id == expectation.topic_id
            ):
                return expectation
            return None

    fetch_spec = fetch.model_copy(
        update={"fetch_id": "levels", "template_id": TemplateId.alerts_rows_v1, "filters": []}
    )
    base_result = make_fetch_result(fetch_spec, site, "levels", FetchState.rows, None)
    row = EvidenceRow(
        evidence_id="ev1_" + "1" * 64,
        topic_id="ldap",
        fetch_id="levels",
        values={FieldId.rule_level: scenario["observed"]},
    )
    result = base_result.model_copy(
        update={
            "scope": base_result.scope.model_copy(
                update={"template_id": TemplateId.alerts_rows_v1}
            ),
            "rows": [row],
        }
    )
    executor = DeclarativePlaybookExecutor(
        CatalogWithExpectation(playbook),
        ResultFetcher({"levels": result}),
        Clock(execution.deadline_at),
        content_sha="c" * 40,
    )
    plan = TopicPlan(
        topic_id="ldap",
        ordinal=0,
        document=False,
        failure=True,
        judgment=False,
        fetches=[],
        playbook_id="ldap_threshold",
        cue_ids=[],
        alias_ids=[],
    )
    run = await executor.run(
        plan,
        principal=principal,
        site=site[1],
        question_id=execution.question_id,
        execution=execution,
    )
    assert run.checks[0].outcome == scenario["expected"]
    assert run.items[-1].values["expectation_id"] == (
        expectation.expectation_id if expectation is not None else None
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("variant", ["positive", "negative", "boundary", "failure"])
async def test_playbook_fetch_count_operands_produce_finite_outcomes(
    principal, site, execution, fetch, variant, request
):
    fixture_path = Path(__file__).parent / "data/playbook_count_cases.json"
    fixture_bytes = fixture_path.read_bytes()
    fixture_sha256 = hashlib.sha256(fixture_bytes).hexdigest()
    assert fixture_sha256 == "36798c43a45b010d0aea370bbee1506314f23ea059afa464a7178edf11eec6bb"
    scenario = json.loads(fixture_bytes)["cases"][variant]
    left_state = FetchState(scenario["left"]["state"])
    left_count = scenario["left"]["count"]
    right_state = FetchState(scenario["right"]["state"])
    right_count = scenario["right"]["count"]
    expected = CheckOutcome(scenario["expected"])
    request.node.user_properties.extend(
        [
            ("acceptance_ids", "G011,G037"),
            ("case_id", "ARCH-007.resolution"),
            ("variant", variant),
            ("fixture_sha256", fixture_sha256),
        ]
    )
    label = LocaleText(en="Compare counts", es="Comparar recuentos")
    steps = [
        FetchStep(
            kind="fetch",
            step_id="read_left",
            label=label,
            fetch_id="left",
            template_id=TemplateId.alerts_count_v1,
            window_default={"unit": "hours", "amount": 24},
            filters=[],
        ),
        FetchStep(
            kind="fetch",
            step_id="read_right",
            label=label,
            fetch_id="right",
            template_id=TemplateId.alerts_count_v1,
            window_default={"unit": "hours", "amount": 24},
            filters=[],
        ),
        CompareCountStep(
            kind="compare_count",
            step_id="count_compare",
            label=label,
            check_id="count_check",
            left_fetch_id="left",
            op="eq",
            right=FetchCountOperand(kind="fetch_count", fetch_id="right"),
        ),
    ]
    playbook = PlaybookDefinition(
        playbook_id="ldap_counts",
        topic_id="ldap",
        title=label,
        internal_context="Internal only.",
        steps=steps,
    )
    base_fetch = fetch.model_copy(update={"template_id": TemplateId.alerts_count_v1, "filters": []})
    results = {
        "left": make_fetch_result(base_fetch, site, "left", left_state, left_count),
        "right": make_fetch_result(base_fetch, site, "right", right_state, right_count),
    }
    executor = DeclarativePlaybookExecutor(
        Catalog(playbook),
        ResultFetcher(results),
        Clock(execution.deadline_at),
        content_sha="c" * 40,
    )
    plan = TopicPlan(
        topic_id="ldap",
        ordinal=0,
        document=False,
        failure=True,
        judgment=False,
        fetches=[],
        playbook_id="ldap_counts",
        cue_ids=[],
        alias_ids=[],
    )
    result = await executor.run(
        plan,
        principal=principal,
        site=site[1],
        question_id=execution.question_id,
        execution=execution,
    )
    assert len(result.fetches) == 2
    assert result.checks[0].outcome == expected
    assert result.items[-1].values["outcome"] == expected.value
