from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import cast

import httpx
import pytest

from ai_soc.contracts.models import (
    CheckOutcome,
    CheckResult,
    ErrorCode,
    FetchState,
    FetchStep,
    LocaleText,
    PlaybookDefinition,
    PlaybookRun,
    RecordAgeStep,
    ResolvedWindow,
    SnapshotKind,
    SnapshotRef,
    TemplateId,
    TopicPlan,
    WindowDefault,
)
from ai_soc.identity.policy import MappedSitePolicy
from ai_soc.query.playbooks import DeclarativePlaybookExecutor, _record_age_snapshot
from tests.unit.query.conftest import NOW, make_principal, make_site
from tests.unit.query.test_indexer_cursor import hit, make_indexer

ANCHOR = NOW
CHECK_ID = "auth_recency"


class _Clock:
    def __init__(self, now: datetime) -> None:
        self._now = now

    def now(self) -> datetime:
        return self._now

    def monotonic(self) -> float:
        return 1.0


class _Catalog:
    def __init__(self, playbook: PlaybookDefinition) -> None:
        self._playbook = playbook

    def playbook(self, playbook_id: str) -> PlaybookDefinition | None:
        return self._playbook if playbook_id == self._playbook.playbook_id else None

    def expectation(self, expectation_id: str, *, topic_id: str):
        return None


def _playbook(
    max_age_seconds: int = 300, template_id: TemplateId = TemplateId.alerts_rows_v1
) -> PlaybookDefinition:
    return PlaybookDefinition(
        playbook_id="auth_review",
        topic_id="ldap",
        title=LocaleText(en="Auth review", es="Revision de autenticacion"),
        internal_context="Synthetic fixture playbook for record age tests.",
        steps=[
            FetchStep(
                kind="fetch",
                step_id="auth_rows_step",
                label=LocaleText(en="Rows", es="Filas"),
                fetch_id="auth_rows",
                template_id=template_id,
                window_default=WindowDefault(unit="hours", amount=24),
                filters=[],
            ),
            RecordAgeStep(
                kind="record_age",
                step_id="auth_recency_step",
                check_id=CHECK_ID,
                label=LocaleText(en="Recent record", es="Registro reciente"),
                fetch_id="auth_rows",
                max_age_seconds=max_age_seconds,
            ),
        ],
    )


def _plan(window: ResolvedWindow | None = None) -> TopicPlan:
    return TopicPlan(
        topic_id="ldap",
        ordinal=0,
        document=False,
        failure=False,
        judgment=False,
        fetches=[],
        playbook_id="auth_review",
        playbook_window=window,
        cue_ids=[],
        alias_ids=[],
    )


def _window(
    *, end: datetime = ANCHOR, semantics: str = "rolling", start: datetime | None = None
) -> ResolvedWindow:
    return ResolvedWindow(
        start=start or end - timedelta(hours=1),
        end=end,
        semantics=semantics,
        source_text="fixture window",
        timezone="UTC",
        anchor_at=end,
    )


def _ts(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _row(record_id: str, timestamp: str | None) -> dict[str, object]:
    row = hit(record_id, "2026-09-30T11:00:00Z")
    source = cast(dict[str, object], row["_source"])
    if timestamp is None:
        del source["@timestamp"]
    else:
        source["@timestamp"] = timestamp
    return row


def _fresh_row(record_id: str, age_seconds: int, anchor: datetime = ANCHOR) -> dict[str, object]:
    return _row(record_id, _ts(anchor - timedelta(seconds=age_seconds)))


VULN_INDEX = "wazuh-states-vulnerabilities-alpha-2026.10"


def _vuln_row(
    record_id: str, detected_at: str | None, stamp: str | None = None
) -> dict[str, object]:
    vulnerability: dict[str, object] = {"id": "CVE-2025-1234", "severity": "High"}
    source: dict[str, object] = {
        "agent": {"id": "007"},
        "vulnerability": vulnerability,
        "package": {"name": "openssl", "version": "1.2.3"},
    }
    if detected_at is not None:
        vulnerability["detected_at"] = detected_at
    if stamp is not None:
        source["@timestamp"] = stamp
    return {
        "_index": VULN_INDEX,
        "_id": record_id,
        "sort": [detected_at or stamp, VULN_INDEX, record_id],
        "_source": source,
    }


def _handler(
    rows: list[dict[str, object]],
    *,
    status: int | None = None,
    relation: str = "eq",
    seen: list[httpx.Request] | None = None,
):
    def handle(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        if status is not None:
            return httpx.Response(status, json={"error": "fixture"})
        if request.url.path.endswith("/_validate/query"):
            return httpx.Response(200, json={"valid": True})
        if "point_in_time" in request.url.path:
            return httpx.Response(200, json={"pit_id": "record-age-pit"})
        return httpx.Response(
            200,
            json={
                "hits": {
                    "total": {"value": len(rows), "relation": relation},
                    "hits": rows,
                }
            },
        )

    return handle


@pytest.fixture
def run_playbook(mapping_profile, cursor_cipher, principal, execution):
    async def run(
        handler,
        *,
        window: ResolvedWindow | None = None,
        anchor: datetime = ANCHOR,
        max_age_seconds: int = 300,
        pit: bool = True,
        as_principal=None,
        template_id: TemplateId = TemplateId.alerts_rows_v1,
    ) -> PlaybookRun:
        verified = as_principal or principal
        config = make_site().model_copy(update={"pit_supported": pit})
        authorized = MappedSitePolicy((config,), now=lambda: NOW).authorize(verified, "alpha")
        indexer, _, client, _ = make_indexer(
            (config, authorized), mapping_profile, cursor_cipher, handler
        )
        executor = DeclarativePlaybookExecutor(
            _Catalog(_playbook(max_age_seconds, template_id)),
            indexer,
            _Clock(anchor),
            content_sha="c" * 40,
        )
        try:
            return await executor.run(
                _plan(window),
                principal=verified,
                site=authorized,
                question_id=execution.question_id,
                execution=replace(execution, owner_key=verified.owner_key),
            )
        finally:
            await client.aclose()

    return run


def _check(run: PlaybookRun) -> CheckResult:
    return next(check for check in run.checks if check.check_id == CHECK_ID)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("age_seconds", "outcome"),
    [(299, CheckOutcome.passed), (300, CheckOutcome.passed), (301, CheckOutcome.failed)],
)
async def test_age_limit_is_inclusive_at_max_age_seconds(run_playbook, age_seconds, outcome):
    run = await run_playbook(_handler([_fresh_row("row-1", age_seconds)]))

    check = _check(run)
    assert check.outcome == outcome
    assert f"is {age_seconds}.000 s before the read time; limit 300 s;" in check.message
    assert "0 returned rows have no valid timestamp" in check.message


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("detected_offset", "outcome"),
    [(60, CheckOutcome.passed), (7200, CheckOutcome.failed)],
    ids=["within-limit", "over-limit"],
)
async def test_vulnerability_recency_uses_detected_at(run_playbook, detected_offset, outcome):
    detected = _ts(ANCHOR - timedelta(seconds=detected_offset))
    run = await run_playbook(
        _handler([_vuln_row("vuln-1", detected)]),
        max_age_seconds=3600,
        template_id=TemplateId.vulnerabilities_rows_v1,
    )

    check = _check(run)
    assert check.outcome == outcome
    assert f"is {detected_offset}.000 s before the read time; limit 3600 s;" in check.message


@pytest.mark.asyncio
async def test_vulnerability_recency_ignores_timestamp_without_detected_at(run_playbook):
    run = await run_playbook(
        _handler([_vuln_row("vuln-1", None, stamp=_ts(ANCHOR - timedelta(seconds=60)))]),
        template_id=TemplateId.vulnerabilities_rows_v1,
    )

    check = _check(run)
    assert check.outcome == CheckOutcome.unknown
    assert check.message == (
        "Check could not be confirmed: none of the 1 returned rows has a valid timestamp "
        "inside the read window."
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(("lag_seconds", "outcome"), [(300, "passed"), (301, "unknown")])
async def test_window_end_tolerance_boundary(run_playbook, lag_seconds, outcome):
    end = ANCHOR - timedelta(seconds=lag_seconds)
    run = await run_playbook(
        _handler([_row("row-1", _ts(end - timedelta(seconds=10)))]),
        window=_window(end=end),
        max_age_seconds=3600,
    )

    assert _check(run).outcome == CheckOutcome(outcome)


@pytest.mark.asyncio
async def test_no_rows_is_unknown_and_says_so(run_playbook):
    run = await run_playbook(_handler([]))

    check = _check(run)
    assert check.outcome == CheckOutcome.unknown
    assert check.message == "Check could not be confirmed: no rows were returned."


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "timestamp",
    [
        None,
        "not-a-timestamp",
        "2026-09-30T11:59:00",
        _ts(ANCHOR + timedelta(seconds=1)),
        _ts(ANCHOR - timedelta(hours=24, seconds=1)),
        _ts(ANCHOR),
    ],
    ids=["missing", "malformed", "naive", "after-end", "before-start", "at-end"],
)
async def test_only_invalid_timestamps_is_unknown(run_playbook, timestamp):
    run = await run_playbook(_handler([_row("row-1", timestamp)]))

    check = _check(run)
    assert check.outcome == CheckOutcome.unknown
    assert check.message == (
        "Check could not be confirmed: none of the 1 returned rows has a valid timestamp "
        "inside the read window."
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "timestamp",
    ["0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"],
    ids=["below-utc-range", "above-utc-range"],
)
async def test_timestamp_utc_overflow_is_invalid_and_unknown(run_playbook, timestamp):
    run = await run_playbook(_handler([_row("extreme", timestamp)]))

    check = _check(run)
    assert check.outcome == CheckOutcome.unknown
    assert "none of the 1 returned rows has a valid timestamp" in check.message


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "timestamp",
    ["0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"],
    ids=["below-utc-range", "above-utc-range"],
)
async def test_timestamp_utc_overflow_is_counted_beside_valid_row(run_playbook, timestamp):
    run = await run_playbook(_handler([_fresh_row("valid", 60), _row("extreme", timestamp)]))

    check = _check(run)
    assert check.outcome == CheckOutcome.passed
    assert "1 returned rows have no valid timestamp inside the read window" in check.message


@pytest.mark.asyncio
async def test_numeric_age_comparison_accepts_very_large_limit(run_playbook):
    run = await run_playbook(
        _handler([_fresh_row("recent", 60)]), max_age_seconds=86_400_000_000_000
    )

    assert _check(run).outcome == CheckOutcome.passed


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("timestamp", "outcome"),
    [
        ("2026-09-30T09:30:00-02:00", CheckOutcome.passed),
        ("2026-09-30T12:30:00+02:00", CheckOutcome.failed),
    ],
    ids=["offset-within-age-limit", "offset-crosses-age-limit"],
)
async def test_nonzero_offset_timestamp_is_converted_before_window_and_age_checks(
    run_playbook, timestamp, outcome
):
    run = await run_playbook(_handler([_row("offset", timestamp)]), max_age_seconds=3600)

    assert _check(run).outcome == outcome


@pytest.mark.asyncio
async def test_valid_row_beside_invalid_rows_decides_and_counts_invalid(run_playbook):
    rows = [
        _fresh_row("valid", 60),
        _row("missing", None),
        _row("malformed", "yesterday"),
    ]
    run = await run_playbook(_handler(rows))

    check = _check(run)
    assert check.outcome == CheckOutcome.passed
    assert "is 60.000 s before the read time; limit 300 s; 2 returned rows" in check.message


@pytest.mark.asyncio
async def test_newest_row_is_used_even_when_not_first(run_playbook):
    rows = [_fresh_row("older", 3000), _fresh_row("newest", 60)]
    run = await run_playbook(_handler(rows))

    check = _check(run)
    assert check.outcome == CheckOutcome.passed
    assert "is 60.000 s before the read time" in check.message


@pytest.mark.asyncio
async def test_default_rolling_window_is_evaluable(run_playbook):
    run = await run_playbook(_handler([_fresh_row("row-1", 10)]))

    assert run.fetches[0].window.semantics == "rolling"
    assert _check(run).outcome == CheckOutcome.passed


@pytest.mark.asyncio
async def test_planned_fresh_window_inside_tolerance_is_evaluable(run_playbook):
    end = ANCHOR - timedelta(seconds=100)
    row_time = end - timedelta(seconds=10)
    run = await run_playbook(_handler([_row("row-1", _ts(row_time))]), window=_window(end=end))

    check = _check(run)
    assert check.outcome == CheckOutcome.passed
    assert "is 110.000 s before the read time" in check.message


@pytest.mark.asyncio
async def test_replayed_window_ended_beyond_tolerance_is_unknown(run_playbook):
    end = ANCHOR - timedelta(seconds=400)
    run = await run_playbook(
        _handler([_row("row-1", _ts(end - timedelta(seconds=10)))]),
        window=_window(end=end),
    )

    check = _check(run)
    assert check.outcome == CheckOutcome.unknown
    assert check.message == (
        "Check could not be confirmed: the read window ended more than 300 s before the read time."
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("semantics", ["calendar", "absolute"])
async def test_non_rolling_windows_are_unknown(run_playbook, semantics):
    run = await run_playbook(
        _handler([_fresh_row("row-1", 10)]), window=_window(semantics=semantics)
    )

    check = _check(run)
    assert check.outcome == CheckOutcome.unknown
    assert check.message == f"Check could not be confirmed: the read window is {semantics}."


@pytest.mark.asyncio
async def test_window_end_after_read_time_is_unknown(run_playbook):
    future = ANCHOR + timedelta(minutes=10)
    run = await run_playbook(_handler([_row("row-1", _ts(ANCHOR))]), window=_window(end=future))

    check = _check(run)
    assert check.outcome == CheckOutcome.unknown
    assert check.message == (
        "Check could not be confirmed: the read window ends after the read time."
    )


@pytest.mark.asyncio
async def test_denied_fetch_is_denied_even_with_ineligible_window(run_playbook):
    run = await run_playbook(_handler([], status=403), window=_window(semantics="calendar"))

    assert _check(run).outcome == CheckOutcome.denied


@pytest.mark.asyncio
async def test_denied_fetch_is_denied_with_default_window(run_playbook):
    run = await run_playbook(_handler([], status=403))

    assert _check(run).outcome == CheckOutcome.denied


@pytest.mark.asyncio
async def test_unavailable_fetch_is_unknown_and_names_the_error(run_playbook):
    run = await run_playbook(_handler([], status=500))

    check = _check(run)
    assert check.outcome == CheckOutcome.unknown
    assert check.message == (
        f"Check could not be confirmed: the source read was {ErrorCode.INDEXER_UNAVAILABLE.value}."
    )


@pytest.mark.asyncio
async def test_unsupported_mapping_is_unknown_and_names_the_error(run_playbook):
    run = await run_playbook(_handler([], status=404))

    check = _check(run)
    assert check.outcome == CheckOutcome.unknown
    assert check.message == (
        f"Check could not be confirmed: the source read was {ErrorCode.MAPPING_UNSUPPORTED.value}."
    )


@pytest.mark.asyncio
async def test_approximate_total_and_first_page_read_describe_returned_rows_only(run_playbook):
    run = await run_playbook(_handler([_fresh_row("row-1", 60)], relation="gte"), pit=False)

    check = _check(run)
    assert check.outcome == CheckOutcome.passed
    assert "Based on returned rows only" in check.message
    assert "first-page read" in check.message
    assert "total count is approximate and was not used" in check.message


@pytest.mark.asyncio
async def test_snapshot_identity_depends_on_anchor_and_source_stays_reachable(run_playbook):
    rows = [_fresh_row("row-1", 60)]
    first = await run_playbook(_handler(rows), anchor=ANCHOR)
    second = await run_playbook(_handler(rows), anchor=ANCHOR + timedelta(seconds=60))

    first_check = _check(first)
    second_check = _check(second)
    assert first_check.outcome == second_check.outcome == CheckOutcome.passed
    first_item = next(item for item in first.items if item.check_id == CHECK_ID)
    second_item = next(item for item in second.items if item.check_id == CHECK_ID)
    assert first_item.evidence_id != second_item.evidence_id
    assert first_item.snapshot.key != second_item.snapshot.key
    assert first_item.snapshot.at == ANCHOR
    assert second_item.snapshot.at == ANCHOR + timedelta(seconds=60)
    assert first_item.snapshot.kind == first.fetches[0].snapshot.kind
    operand_ids = set(first_item.source.operand_ids)
    fetch_item_ids = {item.evidence_id for item in first.fetches[0].items}
    assert operand_ids and operand_ids <= fetch_item_ids


def test_record_age_snapshot_key_depends_on_step_id():
    step = next(item for item in _playbook().steps if isinstance(item, RecordAgeStep))
    other_step = step.model_copy(update={"step_id": "different_recency_step"})
    source = SnapshotRef(kind=SnapshotKind.pit, key="a" * 64, at=ANCHOR)
    assert (
        _record_age_snapshot(source, anchor=ANCHOR, step=step).key
        != _record_age_snapshot(source, anchor=ANCHOR, step=other_step).key
    )


def _record_age_item(run: PlaybookRun):
    return next(item for item in run.items if item.check_id == CHECK_ID)


@pytest.mark.asyncio
async def test_changing_max_age_alone_changes_check_evidence_identity(run_playbook):
    rows = [_fresh_row("row-1", 60)]
    tight = await run_playbook(_handler(rows), max_age_seconds=300)
    loose = await run_playbook(_handler(rows), max_age_seconds=600)

    assert tight.fetches[0].snapshot.key == loose.fetches[0].snapshot.key
    assert _record_age_item(tight).evidence_id != _record_age_item(loose).evidence_id


@pytest.mark.asyncio
async def test_changing_source_snapshot_alone_changes_check_evidence_identity(run_playbook):
    rows = [_fresh_row("row-1", 60)]
    pit = await run_playbook(_handler(rows), pit=True)
    first_page = await run_playbook(_handler(rows), pit=False)

    assert pit.fetches[0].snapshot.key != first_page.fetches[0].snapshot.key
    assert pit.fetches[0].snapshot.kind != first_page.fetches[0].snapshot.kind
    assert _record_age_item(pit).evidence_id != _record_age_item(first_page).evidence_id


@pytest.mark.asyncio
async def test_record_age_snapshot_key_depends_on_source_key_alone(run_playbook):
    run = await run_playbook(_handler([_fresh_row("row-1", 60)]))
    source = run.fetches[0].snapshot
    other_source = source.model_copy(update={"key": "f" * 64})
    step = next(item for item in _playbook().steps if isinstance(item, RecordAgeStep))

    assert (
        _record_age_snapshot(source, anchor=ANCHOR, step=step).key
        != _record_age_snapshot(other_source, anchor=ANCHOR, step=step).key
    )


@pytest.mark.asyncio
async def test_filtered_visibility_with_fresh_rows_evaluates_and_says_returned_rows_only(
    run_playbook,
):
    beta = make_principal(sub="analyst-beta", groups=("soc-beta",))
    run = await run_playbook(_handler([_fresh_row("row-1", 60)]), as_principal=beta)

    assert run.fetches[0].state == FetchState.filtered
    check = _check(run)
    assert check.outcome == CheckOutcome.passed
    assert "Based on returned rows only" in check.message


@pytest.mark.asyncio
async def test_filtered_visibility_with_no_rows_is_unknown(run_playbook):
    beta = make_principal(sub="analyst-beta", groups=("soc-beta",))
    run = await run_playbook(_handler([]), as_principal=beta)

    assert run.fetches[0].state == FetchState.filtered
    assert _check(run).outcome == CheckOutcome.unknown
    assert _check(run).message == "Check could not be confirmed: no rows were returned."


@pytest.mark.asyncio
async def test_one_executor_gives_each_principal_only_its_backend_response(
    mapping_profile, cursor_cipher, principal, execution
):
    seen: list[httpx.Request] = []
    responses = {
        "fresh": [_fresh_row("sentinel-fresh", 30)],
        "stale": [_fresh_row("sentinel-stale", 2000)],
    }
    current = {"rows": responses["fresh"]}

    def handle(request: httpx.Request) -> httpx.Response:
        return _handler(current["rows"], seen=seen)(request)

    config = make_site()
    first_authorized = MappedSitePolicy((config,), now=lambda: NOW).authorize(principal, "alpha")
    indexer, _, client, _ = make_indexer(
        (config, first_authorized), mapping_profile, cursor_cipher, handle
    )
    executor = DeclarativePlaybookExecutor(
        _Catalog(_playbook()), indexer, _Clock(ANCHOR), content_sha="c" * 40
    )
    results: list[CheckResult] = []
    try:
        for label, sub in (("fresh", "analyst-fresh"), ("stale", "analyst-stale")):
            current["rows"] = responses[label]
            verified = make_principal(sub=sub)
            authorized = MappedSitePolicy((config,), now=lambda: NOW).authorize(verified, "alpha")
            run = await executor.run(
                _plan(),
                principal=verified,
                site=authorized,
                question_id=execution.question_id,
                execution=replace(execution, owner_key=verified.owner_key),
            )
            results.append(_check(run))
    finally:
        await client.aclose()

    assert results[0].outcome == CheckOutcome.passed
    assert results[1].outcome == CheckOutcome.failed
    assert "is 30.000 s" in results[0].message
    assert "is 2000.000 s" in results[1].message
    search_reads = [request for request in seen if request.url.path.endswith("/_search")]
    assert len(search_reads) == 2
