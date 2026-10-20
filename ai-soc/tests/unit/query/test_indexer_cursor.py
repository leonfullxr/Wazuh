from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import uuid4

import httpx
import pytest
from pydantic import SecretStr

from ai_soc.contracts.canonical import owner_key
from ai_soc.contracts.models import (
    CallKind,
    ErrorCode,
    FetchState,
    FieldId,
    IndexerCredential,
    IndexFamily,
    ReadOperationGrant,
    SnapshotKind,
    StageCapacityRejection,
    Visibility,
)
from ai_soc.identity.policy import MappedSitePolicy
from ai_soc.query.compiler import compile_fetch
from ai_soc.query.indexer import WazuhIndexer
from ai_soc.state.stage_admission import MemoryReadAdmissionStore
from tests.unit.query.conftest import NOW, make_principal, make_site


def record_case_metadata(
    request, *, acceptance_id: str, case_id: str, variant: str, fixture_sha256: str
) -> None:
    request.node.user_properties.extend(
        [
            ("acceptance_ids", acceptance_id),
            ("case_id", case_id),
            ("variant", variant),
            ("fixture_sha256", fixture_sha256),
        ]
    )


class Broker:
    def __init__(self, expires_at):
        self.expires_at = expires_at
        self.calls = 0

    async def issue(self, principal, site, *, execution):
        self.calls += 1
        assert site.config.environment_id == "alpha"
        return IndexerCredential(
            bearer_token=SecretStr("analyst-signed-token"),
            expires_at=self.expires_at,
            key_id="alpha-v2",
        )


class RecordingReadAdmission:
    def __init__(self, *, reject_calls: frozenset[tuple[str, str]] = frozenset()) -> None:
        self.reject_calls = reject_calls
        self.acquired: list[dict[str, object]] = []
        self.grants: list[ReadOperationGrant] = []
        self.released: list[ReadOperationGrant] = []
        self.released_event = asyncio.Event()

    async def acquire(
        self,
        *,
        environment_id,
        question_id,
        operation_id,
        call,
        now,
    ):
        request = {
            "environment_id": environment_id,
            "question_id": question_id,
            "operation_id": operation_id,
            "call": call,
            "now": now,
        }
        self.acquired.append(request)
        if (environment_id, call) in self.reject_calls:
            return StageCapacityRejection(
                question_id=question_id, operation_id=operation_id, call=call
            )
        deadline = now + timedelta(seconds=10)
        grant = ReadOperationGrant(
            question_id=question_id,
            environment_id=environment_id,
            operation_id=operation_id,
            call=call,
            holder_id=uuid4(),
            service_slot_id="read-service-00",
            site_slot_id=f"read-{environment_id}-00",
            fence=len(self.grants) + 1,
            acquired_at=now,
            lease_expires_at=deadline,
            hard_deadline_at=deadline,
            recover_after=deadline + timedelta(seconds=35),
        )
        self.grants.append(grant)
        return grant

    async def release(self, grant: ReadOperationGrant) -> None:
        self.released.append(grant)
        self.released_event.set()


def hit(record_id: str, sort_time: str, index_name: str = "alerts"):
    return {
        "_index": index_name,
        "_id": record_id,
        "sort": [sort_time, index_name, record_id],
        "_source": {
            "@timestamp": sort_time,
            "agent": {"id": "007", "name": "alpha-sentinel"},
            "rule": {"id": "5710", "level": 5, "groups": ["authentication"]},
            "data": {"srcip": "192.0.2.7", "dstip": "192.0.2.8"},
        },
    }


def make_indexer(
    site,
    mapping_profile,
    cursor_cipher,
    handler,
    *,
    response_bytes=262_144,
    admission=None,
):
    config, authorized = site
    client = httpx.AsyncClient(
        base_url=config.indexer_origin,
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
        trust_env=False,
    )
    broker = Broker(expires_at=datetime(2026, 9, 30, 12, 5, tzinfo=UTC))
    if admission is None:
        admission = RecordingReadAdmission()
    indexer = WazuhIndexer(
        broker,
        admission,
        lambda target: client,
        profiles={mapping_profile.profile_id: mapping_profile},
        clock=lambda: datetime(2026, 9, 30, 12, 0, tzinfo=UTC),
        content_sha="c" * 40,
        cursor_cipher=cursor_cipher,
        response_bytes=response_bytes,
    )
    return indexer, broker, client, admission


@pytest.mark.asyncio
async def test_indexer_sends_allowlisted_body_and_analyst_auth_with_pit_cursor(
    site, fetch, principal, execution, mapping_profile, cursor_cipher
):
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.headers["authorization"] == "Bearer analyst-signed-token"
        if request.url.path.endswith("/_validate/query"):
            return httpx.Response(200, json={"valid": True})
        if "point_in_time" in request.url.path:
            return httpx.Response(200, json={"pit_id": "fixture-pit-secret"})
        body = json.loads(request.content)
        assert body["pit"]["id"] == "fixture-pit-secret"
        assert body["query"]["bool"]["filter"][1] == {"term": {"agent.id": "007"}}
        return httpx.Response(
            200,
            json={
                "hits": {
                    "total": {"value": 2, "relation": "eq"},
                    "hits": [hit("row-1", "2026-09-30T11:00:00Z")],
                }
            },
        )

    indexer, broker, client, admission = make_indexer(site, mapping_profile, cursor_cipher, handler)
    _, authorized = site
    result = await indexer.execute(
        fetch,
        topic_id="ldap",
        question_id=execution.question_id,
        principal=principal,
        site=authorized,
        execution=execution,
    )
    assert [request.method for request in requests] == ["POST", "POST", "POST"]
    assert requests[0].url.path.endswith("/_search/point_in_time")
    assert requests[1].url.path.endswith("/_validate/query")
    validation_body = json.loads(requests[1].content)
    assert validation_body["query"] == json.loads(requests[2].content)["query"]
    assert requests[2].url.path == "/_search"
    assert broker.calls == 1
    assert execution.calls.claimed == [CallKind.pit, CallKind.validate, CallKind.search]
    assert [grant.call for grant in admission.grants] == ["pit", "validate", "search"]
    assert admission.released == admission.grants
    assert [request["call"] for request in admission.acquired] == [
        "pit",
        "validate",
        "search",
    ]
    assert all(request["environment_id"] == "alpha" for request in admission.acquired)
    assert all(request["question_id"] == execution.question_id for request in admission.acquired)
    assert len({request["operation_id"] for request in admission.acquired}) == len(requests)
    assert result.count is not None and result.count.value == 2
    assert result.rows[0].values[FieldId.agent_id] == "007"
    assert result.next_cursor is not None
    assert "fixture-pit-secret" not in result.next_cursor
    await client.aclose()


@pytest.mark.asyncio
async def test_failed_validate_closes_open_pit(
    site, fetch, principal, execution, mapping_profile, cursor_cipher
):
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if "point_in_time" in request.url.path:
            if request.method == "DELETE":
                return httpx.Response(200, json={"succeeded": True})
            return httpx.Response(200, json={"pit_id": "leak-pit"})
        if request.url.path.endswith("/_validate/query"):
            return httpx.Response(200, json={"valid": False})
        raise AssertionError("search must not run when validation fails")

    indexer, _, client, _ = make_indexer(site, mapping_profile, cursor_cipher, handler)
    _, authorized = site
    result = await indexer.execute(
        fetch,
        topic_id="ldap",
        question_id=execution.question_id,
        principal=principal,
        site=authorized,
        execution=execution,
    )
    assert str(result.state) == "unavailable"
    assert result.error.code == ErrorCode.MAPPING_UNSUPPORTED
    assert any(request.method == "DELETE" for request in requests)
    await client.aclose()


@pytest.mark.asyncio
async def test_unknown_visibility_execute_returns_valid_fetch_result(
    fetch, principal, execution, mapping_profile, cursor_cipher
):
    config = make_site("alpha")
    policy = MappedSitePolicy((config,), now=lambda: datetime(2026, 9, 30, 12, 0, tzinfo=UTC))
    unknown_site = policy.authorize(make_principal(groups=("soc-alpha", "soc-beta")), "alpha")
    assert unknown_site.visibility == Visibility.unknown

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/_validate/query"):
            return httpx.Response(200, json={"valid": True})
        if "point_in_time" in request.url.path:
            return httpx.Response(200, json={"pit_id": "unknown-vis-pit"})
        return httpx.Response(
            200,
            json={
                "hits": {
                    "total": {"value": 1, "relation": "eq"},
                    "hits": [hit("row-unknown", "2026-09-30T11:00:00Z")],
                }
            },
        )

    indexer, _, client, _ = make_indexer(
        (config, unknown_site), mapping_profile, cursor_cipher, handler
    )
    result = await indexer.execute(
        fetch,
        topic_id="ldap",
        question_id=execution.question_id,
        principal=principal.model_copy(update={"groups": ("soc-alpha", "soc-beta")}),
        site=unknown_site,
        execution=execution,
    )
    assert result.state == FetchState.rows
    assert str(result.scope.visibility) == "unknown"
    assert len(result.rows) == 1
    await client.aclose()


@pytest.mark.asyncio
async def test_execute_closes_pit_when_result_materialization_raises(
    site, fetch, principal, execution, mapping_profile, cursor_cipher
):
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if "point_in_time" in request.url.path:
            if request.method == "DELETE":
                return httpx.Response(200, json={"succeeded": True})
            return httpx.Response(200, json={"pit_id": "raise-pit"})
        if request.url.path.endswith("/_validate/query"):
            return httpx.Response(200, json={"valid": True})
        return httpx.Response(
            200,
            json={
                "hits": {
                    "total": {"value": 1, "relation": "eq"},
                    "hits": [hit("row-raise", "2026-09-30T11:00:00Z")],
                }
            },
        )

    indexer, _, client, _ = make_indexer(site, mapping_profile, cursor_cipher, handler)
    _, authorized = site
    original_result = indexer._result

    def broken_result(*args, **kwargs):
        raise RuntimeError("forced post-open failure")

    indexer._result = broken_result  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="forced post-open failure"):
        await indexer.execute(
            fetch,
            topic_id="ldap",
            question_id=execution.question_id,
            principal=principal,
            site=authorized,
            execution=execution,
        )
    indexer._result = original_result  # type: ignore[method-assign]
    assert any(request.method == "DELETE" for request in requests)
    await client.aclose()


@pytest.mark.asyncio
async def test_cursor_page_is_owner_site_policy_content_bound_and_reuses_snapshot(
    site, fetch, principal, execution, mapping_profile, cursor_cipher
):
    pages = 1

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal pages
        assert request.headers["authorization"] == "Bearer analyst-signed-token"
        body = json.loads(request.content)
        assert body["pit"]["id"] == "pit-stable"
        pages += 1
        if pages == 1:
            return httpx.Response(
                200, json={"hits": {"total": 2, "hits": [hit("row-1", "2026-09-30T11:00:00Z")]}}
            )
        assert body["search_after"] == ["2026-09-30T11:00:00Z", "alerts", "row-1"]
        return httpx.Response(
            200, json={"hits": {"total": 2, "hits": [hit("row-2", "2026-09-30T10:00:00Z")]}}
        )

    indexer, broker, client, admission = make_indexer(site, mapping_profile, cursor_cipher, handler)
    _, authorized = site
    first = indexer._result(
        {"hits": {"total": 2, "hits": [hit("row-1", "2026-09-30T11:00:00Z")]}},
        compile_fetch(fetch, authorized, mapping_profile),
        fetch,
        "ldap",
        execution.question_id,
        authorized,
        pit_id="pit-stable",
        profile=mapping_profile,
        principal=principal,
    )
    assert first.next_cursor
    second = await indexer.page(
        first.next_cursor, principal=principal, site=authorized, execution=execution
    )
    assert second.snapshot.key == first.snapshot.key
    assert second.rows[0].record_ref.record_id == "row-2"
    assert broker.calls == 1
    assert [grant.call for grant in admission.grants] == ["search"]
    assert [request["call"] for request in admission.acquired] == ["search"]
    assert admission.acquired[0]["question_id"] == execution.question_id
    assert all(grant.environment_id == "alpha" for grant in admission.grants)
    assert admission.released == admission.grants
    foreign = principal.model_copy(
        update={
            "sub": "other-analyst",
            "owner_key": owner_key(str(principal.issuer), "other-analyst"),
        }
    )
    from ai_soc.query.cursors import CursorError

    with pytest.raises(CursorError) as error:
        await indexer.page(
            first.next_cursor, principal=foreign, site=authorized, execution=execution
        )
    assert getattr(error.value, "code", None) == ErrorCode.CURSOR_EXPIRED
    await client.aclose()


@pytest.mark.asyncio
async def test_earliest_cursor_page_preserves_ascending_sort(
    site, fetch, principal, execution, mapping_profile, cursor_cipher
):
    earliest_fetch = fetch.model_copy(update={"order": "earliest"})
    search_calls = 0
    page_orders: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal search_calls
        if "point_in_time" in request.url.path:
            if request.method == "DELETE":
                return httpx.Response(200, json={"succeeded": True})
            return httpx.Response(200, json={"pit_id": "pit-earliest"})
        if request.url.path.endswith("/_validate/query"):
            return httpx.Response(200, json={"valid": True})
        body = json.loads(request.content)
        sort = body.get("sort", [])
        if sort:
            first = sort[0]
            if isinstance(first, dict):
                order_spec = next(iter(first.values()))
                if isinstance(order_spec, dict):
                    page_orders.append(order_spec.get("order", ""))
        search_calls += 1
        if search_calls == 1:
            return httpx.Response(
                200,
                json={
                    "hits": {
                        "total": {"value": 2, "relation": "eq"},
                        "hits": [hit("row-early-1", "2026-09-30T10:00:00Z")],
                    }
                },
            )
        assert body["search_after"] == [
            "2026-09-30T10:00:00Z",
            "alerts",
            "row-early-1",
        ]
        return httpx.Response(
            200,
            json={
                "hits": {
                    "total": {"value": 2, "relation": "eq"},
                    "hits": [hit("row-early-2", "2026-09-30T11:00:00Z")],
                }
            },
        )

    indexer, _, client, _ = make_indexer(site, mapping_profile, cursor_cipher, handler)
    _, authorized = site
    first = await indexer.execute(
        earliest_fetch,
        topic_id="ldap",
        question_id=execution.question_id,
        principal=principal,
        site=authorized,
        execution=execution,
    )
    assert first.next_cursor is not None
    assert page_orders[0] == "asc"
    second = await indexer.page(
        first.next_cursor,
        principal=principal,
        site=authorized,
        execution=execution,
    )
    assert page_orders[-1] == "asc"
    assert second.rows[0].record_ref.record_id == "row-early-2"
    await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("order", ["earliest", "latest"])
async def test_cursor_pages_use_total_composite_order_over_shuffled_records(
    site, fetch, principal, execution, mapping_profile, cursor_cipher, order
):
    requested_fetch = fetch.model_copy(update={"order": order})
    records: list[tuple[str, str, str]] = [
        (
            f"2026-09-30T00:{index:02d}:00Z",
            f"alerts-{(index * 7) % 4}",
            f"record-{index:03d}",
        )
        for index in range(19)
    ]
    records.extend(
        [
            ("2026-09-30T10:00:00Z", "alerts-a", "shared-id"),
            ("2026-09-30T10:00:00Z", "alerts-b", "shared-id"),
        ]
    )
    records.extend(
        (
            f"2026-09-30T10:{index + 1:02d}:00Z",
            f"alerts-{(index * 3) % 4}",
            f"record-{index + 19:03d}",
        )
        for index in range(39)
    )
    # The shuffled input forces the fake backend to honor the requested sort.
    records.reverse()
    dataset = [
        hit(record_id, timestamp, index_name) for timestamp, index_name, record_id in records
    ]
    seen_pit: str | None = None
    search_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal seen_pit, search_count
        if "point_in_time" in request.url.path:
            if request.method == "DELETE":
                return httpx.Response(200, json={"succeeded": True})
            seen_pit = "stable-composite-pit"
            return httpx.Response(200, json={"pit_id": seen_pit})
        if request.url.path.endswith("/_validate/query"):
            return httpx.Response(200, json={"valid": True})
        body = json.loads(request.content)
        assert body["pit"]["id"] == seen_pit == "stable-composite-pit"
        sort_fields = [next(iter(item)) for item in body["sort"]]
        sort_order = body["sort"][0][sort_fields[0]]["order"]
        assert sort_fields == ["@timestamp", "_index", "_id"]
        assert all(
            item[field]["order"] == sort_order
            for item, field in zip(body["sort"], sort_fields, strict=True)
        )
        ordered = sorted(
            dataset,
            key=lambda item: tuple(
                item["_index"]
                if field == "_index"
                else item["_id"]
                if field == "_id"
                else item["sort"][0]
                for field in sort_fields
            ),
            reverse=sort_order == "desc",
        )
        after = body.get("search_after")
        if after is not None:
            after_tuple = tuple(after)
            keys = [
                (
                    item["sort"][0],
                    item["_index"],
                    item["_id"],
                )
                for item in ordered
            ]
            boundary = keys.index(after_tuple)
            ordered = ordered[boundary + 1 :]
        page = ordered[: body["size"]]
        search_count += 1
        return httpx.Response(
            200,
            json={"hits": {"total": {"value": len(dataset), "relation": "eq"}, "hits": page}},
        )

    indexer, broker, client, _ = make_indexer(site, mapping_profile, cursor_cipher, handler)
    _, authorized = site
    first = await indexer.execute(
        requested_fetch,
        topic_id="ldap",
        question_id=execution.question_id,
        principal=principal,
        site=authorized,
        execution=execution,
    )
    all_rows = list(first.rows)
    current = first
    while current.next_cursor is not None:
        current = await indexer.page(
            current.next_cursor,
            principal=principal,
            site=authorized,
            execution=execution,
        )
        assert current.snapshot.key == first.snapshot.key
        all_rows.extend(current.rows)
    expected = sorted(
        records,
        key=lambda item: item,
        reverse=order == "latest",
    )
    actual = [
        (row.values[FieldId.timestamp], row.record_ref.index_alias, row.record_ref.record_id)
        for row in all_rows
    ]
    assert actual == expected
    assert len(actual) == len(set(actual)) == 60
    assert broker.calls == search_count
    assert search_count > 25
    await client.aclose()


@pytest.mark.asyncio
async def test_cursor_boundary_uses_last_raw_duplicate_hit(
    site, fetch, principal, execution, mapping_profile, cursor_cipher
):
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        if "point_in_time" in request.url.path:
            if request.method == "DELETE":
                return httpx.Response(200, json={"succeeded": True})
            return httpx.Response(200, json={"pit_id": "duplicate-boundary-pit"})
        if request.url.path.endswith("/_validate/query"):
            return httpx.Response(200, json={"valid": True})
        calls += 1
        body = json.loads(request.content)
        if calls == 1:
            duplicate_at_later_sort_value = hit("repeated", "2026-09-30T10:00:00Z")
            duplicate_at_later_sort_value["sort"] = [
                "2026-09-30T11:00:00Z",
                "alerts",
                "repeated",
            ]
            return httpx.Response(
                200,
                json={
                    "hits": {
                        "total": 3,
                        "hits": [
                            hit("repeated", "2026-09-30T10:00:00Z"),
                            duplicate_at_later_sort_value,
                        ],
                    }
                },
            )
        assert body["search_after"] == ["2026-09-30T11:00:00Z", "alerts", "repeated"]
        return httpx.Response(
            200,
            json={"hits": {"total": 3, "hits": [hit("next", "2026-09-30T11:00:00Z")]}},
        )

    indexer, _, client, _ = make_indexer(site, mapping_profile, cursor_cipher, handler)
    _, authorized = site
    first = await indexer.execute(
        fetch,
        topic_id="ldap",
        question_id=execution.question_id,
        principal=principal,
        site=authorized,
        execution=execution,
    )
    assert len(first.rows) == 1
    assert [check.code for check in first.checks] == ["identical_source_rows_deduplicated"]
    assert first.scope.displayed_rows == 1
    assert first.count is not None and first.count.value == 3
    second = await indexer.page(
        first.next_cursor, principal=principal, site=authorized, execution=execution
    )
    assert [row.record_ref.record_id for row in second.rows] == ["next"]
    await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "legacy_sort_values",
    [
        ["2026-09-30T10:00:00Z", "first"],
        ["2026-09-30T10:00:00Z", 1, "first"],
        ["2026-09-30T10:00:00Z", "", "first"],
        ["2026-09-30T10:00:00Z", "alerts", 1],
        ["2026-09-30T10:00:00Z", "alerts", ""],
    ],
)
async def test_legacy_or_malformed_cursor_is_rejected_before_reading(
    site, fetch, principal, execution, mapping_profile, cursor_cipher, legacy_sort_values
):
    def handler(request: httpx.Request) -> httpx.Response:
        if "point_in_time" in request.url.path:
            if request.method == "DELETE":
                return httpx.Response(200, json={"succeeded": True})
            return httpx.Response(200, json={"pit_id": "legacy-pit"})
        if request.url.path.endswith("/_validate/query"):
            return httpx.Response(200, json={"valid": True})
        return httpx.Response(
            200, json={"hits": {"total": 2, "hits": [hit("first", "2026-09-30T10:00:00Z")]}}
        )

    indexer, broker, client, admission = make_indexer(site, mapping_profile, cursor_cipher, handler)
    _, authorized = site
    first = indexer._result(
        {"hits": {"total": 2, "hits": [hit("first", "2026-09-30T10:00:00Z")]}},
        compile_fetch(fetch, authorized, mapping_profile),
        fetch,
        "ldap",
        execution.question_id,
        authorized,
        pit_id="legacy-pit",
        profile=mapping_profile,
        principal=principal,
    )
    assert first.next_cursor
    payload = cursor_cipher.open(
        first.next_cursor,
        owner_key=principal.owner_key,
        environment_id=authorized.config.environment_id,
        policy_hash=authorized.policy_hash,
        content_sha="c" * 40,
    )
    legacy_payload = payload.model_copy(update={"sort_values": legacy_sort_values})
    legacy_cursor = cursor_cipher.seal(legacy_payload)
    from ai_soc.query.cursors import CursorError

    with pytest.raises(CursorError):
        await indexer.page(legacy_cursor, principal=principal, site=authorized, execution=execution)
    assert broker.calls == 0
    assert admission.acquired == []
    await client.aclose()


@pytest.mark.parametrize(
    "sort_values",
    [
        ["2026-09-30T10:00:00Z", "alerts", "row", "extra"],
        ["2026-09-30T10:00:00Z", "alerts"],
        [True, "alerts", "row"],
        [{"time": "2026-09-30T10:00:00Z"}, "alerts", "row"],
        [1.5, "alerts", "row"],
        [None, "alerts", "row"],
        ("2026-09-30T10:00:00Z", "alerts", "row"),
        ["2026-09-30T10:00:00Z", "", "row"],
        ["2026-09-30T10:00:00Z", 7, "row"],
        ["2026-09-30T10:00:00Z", "alerts", ""],
        ["2026-09-30T10:00:00Z", "alerts", 7],
        ["2026-09-30T10:00:00Z", "other-index", "row"],
        ["2026-09-30T10:00:00Z", "alerts", "other-id"],
    ],
)
def test_malformed_hit_sort_never_creates_cursor(
    site, fetch, principal, execution, mapping_profile, cursor_cipher, sort_values
):
    _, authorized = site
    malformed = hit("row", "2026-09-30T10:00:00Z")
    malformed["sort"] = sort_values
    indexer = WazuhIndexer(
        Broker(expires_at=datetime(2026, 9, 30, 12, 5, tzinfo=UTC)),
        RecordingReadAdmission(),
        lambda target: None,
        profiles={mapping_profile.profile_id: mapping_profile},
        clock=lambda: datetime(2026, 9, 30, 12, 0, tzinfo=UTC),
        content_sha="c" * 40,
        cursor_cipher=cursor_cipher,
    )
    result = indexer._result(
        {"hits": {"total": 1, "hits": [malformed]}},
        compile_fetch(fetch, authorized, mapping_profile),
        fetch,
        "ldap",
        execution.question_id,
        authorized,
        pit_id="malformed-pit",
        profile=mapping_profile,
        principal=principal,
    )
    assert result.rows
    assert result.next_cursor is None
    assert result.message == (
        "Paging is unavailable because a stable three-part cursor boundary was not available."
    )


def test_malformed_nonfinal_sort_prevents_cursor_creation(
    site, fetch, principal, execution, mapping_profile, cursor_cipher
):
    _, authorized = site
    malformed = hit("before", "2026-09-30T10:00:00Z")
    malformed["sort"] = ["2026-09-30T10:00:00Z", "alerts", "wrong-id"]
    valid_last = hit("last", "2026-09-30T11:00:00Z")
    indexer = WazuhIndexer(
        Broker(expires_at=datetime(2026, 9, 30, 12, 5, tzinfo=UTC)),
        RecordingReadAdmission(),
        lambda target: None,
        profiles={mapping_profile.profile_id: mapping_profile},
        clock=lambda: datetime(2026, 9, 30, 12, 0, tzinfo=UTC),
        content_sha="c" * 40,
        cursor_cipher=cursor_cipher,
    )
    result = indexer._result(
        {"hits": {"total": 2, "hits": [malformed, valid_last]}},
        compile_fetch(fetch, authorized, mapping_profile),
        fetch,
        "ldap",
        execution.question_id,
        authorized,
        pit_id="malformed-nonfinal-pit",
        profile=mapping_profile,
        principal=principal,
    )
    assert result.rows
    assert result.next_cursor is None


@pytest.mark.asyncio
@pytest.mark.parametrize("raw_value", [None, "not-an-object", 7])
@pytest.mark.parametrize("position", ["first", "middle", "final"])
async def test_non_object_raw_hit_keeps_rows_but_never_issues_cursor(
    site, fetch, principal, execution, mapping_profile, cursor_cipher, raw_value, position
):
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if "point_in_time" in request.url.path:
            if request.method == "DELETE":
                return httpx.Response(200, json={"succeeded": True})
            return httpx.Response(200, json={"pit_id": "non-object-pit"})
        if request.url.path.endswith("/_validate/query"):
            return httpx.Response(200, json={"valid": True})
        raw_hits: list[object] = [
            hit("row-a", "2026-09-30T11:00:00Z"),
            hit("row-b", "2026-09-30T10:00:00Z"),
        ]
        raw_hits.insert({"first": 0, "middle": 1, "final": 2}[position], raw_value)
        return httpx.Response(
            200,
            json={"hits": {"total": {"value": 2, "relation": "eq"}, "hits": raw_hits}},
        )

    indexer, _, client, _ = make_indexer(site, mapping_profile, cursor_cipher, handler)
    _, authorized = site
    result = await indexer.execute(
        fetch,
        topic_id="ldap",
        question_id=execution.question_id,
        principal=principal,
        site=authorized,
        execution=execution,
    )
    assert result.state == FetchState.rows
    assert result.error is None
    assert [row.record_ref.record_id for row in result.rows] == ["row-a", "row-b"]
    assert result.next_cursor is None
    assert result.message == (
        "Paging is unavailable because a stable three-part cursor boundary was not available."
    )
    assert [request.method for request in requests] == ["POST", "POST", "POST", "DELETE"]
    assert requests[-1].url.path == "/_search/point_in_time"
    await client.aclose()


def test_oversized_cursor_has_bounded_paging_limitation(
    site, fetch, principal, execution, mapping_profile
):
    from ai_soc.query.cursors import CursorCipher

    _, authorized = site
    narrow_cipher = CursorCipher(
        keys={"small": b"s" * 32},
        current_key_id="small",
        now=lambda: datetime(2026, 9, 30, 12, 0, tzinfo=UTC),
        max_token_bytes=64,
    )
    indexer = WazuhIndexer(
        Broker(expires_at=datetime(2026, 9, 30, 12, 5, tzinfo=UTC)),
        RecordingReadAdmission(),
        lambda target: None,
        profiles={mapping_profile.profile_id: mapping_profile},
        clock=lambda: datetime(2026, 9, 30, 12, 0, tzinfo=UTC),
        content_sha="c" * 40,
        cursor_cipher=narrow_cipher,
    )
    result = indexer._result(
        {"hits": {"total": 2, "hits": [hit("row", "2026-09-30T10:00:00Z")]}},
        compile_fetch(fetch, authorized, mapping_profile),
        fetch,
        "ldap",
        execution.question_id,
        authorized,
        pit_id="oversized-pit",
        profile=mapping_profile,
        principal=principal,
    )
    assert result.next_cursor is None
    assert result.message == (
        "Paging is unavailable because a stable three-part cursor boundary was not available."
    )


def test_paging_limitation_preserves_empty_ingestion_message(
    site, fetch, principal, execution, mapping_profile, cursor_cipher
):
    _, authorized = site
    indexer = WazuhIndexer(
        Broker(expires_at=datetime(2026, 9, 30, 12, 5, tzinfo=UTC)),
        RecordingReadAdmission(),
        lambda target: None,
        profiles={mapping_profile.profile_id: mapping_profile},
        clock=lambda: datetime(2026, 9, 30, 12, 0, tzinfo=UTC),
        content_sha="c" * 40,
        cursor_cipher=cursor_cipher,
    )
    result = indexer._result(
        {"hits": {"total": 0, "hits": []}},
        compile_fetch(fetch, authorized, mapping_profile),
        fetch,
        "ldap",
        execution.question_id,
        authorized,
        pit_id=None,
        profile=mapping_profile,
        principal=principal,
    )
    assert result.message is not None
    assert "No matching visible records; ingestion status is unconfirmed." in result.message
    assert "Paging is unavailable" in result.message


@pytest.mark.asyncio
async def test_existing_cursor_is_rejected_when_current_profile_loses_tie_capability(
    site, fetch, principal, execution, mapping_profile, cursor_cipher
):
    _, authorized = site
    broker = Broker(expires_at=datetime(2026, 9, 30, 12, 5, tzinfo=UTC))
    admission = RecordingReadAdmission()
    indexer = WazuhIndexer(
        broker,
        admission,
        lambda target: None,
        profiles={mapping_profile.profile_id: mapping_profile},
        clock=lambda: datetime(2026, 9, 30, 12, 0, tzinfo=UTC),
        content_sha="c" * 40,
        cursor_cipher=cursor_cipher,
    )
    first = indexer._result(
        {"hits": {"total": 2, "hits": [hit("first", "2026-09-30T10:00:00Z")]}},
        compile_fetch(fetch, authorized, mapping_profile),
        fetch,
        "ldap",
        execution.question_id,
        authorized,
        pit_id="capability-change-pit",
        profile=mapping_profile,
        principal=principal,
    )
    assert first.next_cursor
    no_tie_profile = mapping_profile.__class__(
        profile_id=mapping_profile.profile_id,
        fields=mapping_profile.fields,
        alert_projection=mapping_profile.alert_projection,
        vulnerability_projection=mapping_profile.vulnerability_projection,
        tie_break_field=None,
    )
    indexer._profiles = {no_tie_profile.profile_id: no_tie_profile}
    from ai_soc.query.cursors import CursorError

    with pytest.raises(CursorError):
        await indexer.page(
            first.next_cursor, principal=principal, site=authorized, execution=execution
        )
    assert broker.calls == 0
    assert admission.acquired == []


@pytest.mark.asyncio
async def test_cross_index_id_reuse_is_not_reported_as_duplicate(
    site, fetch, principal, execution, mapping_profile, cursor_cipher
):
    _, authorized = site
    first_hit = hit("shared", "2026-09-30T10:00:00Z", "alerts-a")
    second_hit = hit("shared", "2026-09-30T10:00:00Z", "alerts-b")
    second_source = cast(dict[str, object], second_hit["_source"])
    second_agent = cast(dict[str, object], second_source["agent"])
    second_agent["name"] = "other-index-agent"

    def handler(request: httpx.Request) -> httpx.Response:
        if "point_in_time" in request.url.path:
            if request.method == "DELETE":
                return httpx.Response(200, json={"succeeded": True})
            return httpx.Response(200, json={"pit_id": "cross-index-pit"})
        if request.url.path.endswith("/_validate/query"):
            return httpx.Response(200, json={"valid": True})
        return httpx.Response(
            200,
            json={"hits": {"total": 2, "hits": [first_hit, second_hit]}},
        )

    indexer, _, client, _ = make_indexer(site, mapping_profile, cursor_cipher, handler)
    result = await indexer.execute(
        fetch,
        topic_id="ldap",
        question_id=execution.question_id,
        principal=principal,
        site=authorized,
        execution=execution,
    )
    assert len(result.rows) == 2
    assert result.scope.displayed_rows == 2
    assert result.count is not None and result.count.value == 2
    assert result.checks == []
    assert [row.record_ref.index_alias for row in result.rows] == ["alerts-a", "alerts-b"]
    assert [row.values[FieldId.agent_name] for row in result.rows] == [
        "alpha-sentinel",
        "other-index-agent",
    ]
    await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("first_level", "second_level", "second_agent_name", "conflicting"),
    [
        pytest.param(5, 5, "conflicting-agent", True, id="distinct-agent-name"),
        pytest.param(1, True, "alpha-sentinel", True, id="integer-then-boolean-level"),
        pytest.param(True, 1, "alpha-sentinel", True, id="boolean-then-integer-level"),
        pytest.param(0, False, "alpha-sentinel", True, id="zero-then-false-level"),
        pytest.param(False, 0, "alpha-sentinel", True, id="false-then-zero-level"),
        pytest.param(True, True, "alpha-sentinel", False, id="identical-boolean-level"),
        pytest.param(1, 1, "alpha-sentinel", False, id="identical-integer-level"),
    ],
)
async def test_conflicting_same_index_source_is_evidence_invalid_at_runtime(
    site,
    fetch,
    principal,
    execution,
    mapping_profile,
    cursor_cipher,
    first_level,
    second_level,
    second_agent_name,
    conflicting,
):
    first_hit = hit("conflict", "2026-09-30T10:00:00Z")
    first_source = cast(dict[str, object], first_hit["_source"])
    first_rule = cast(dict[str, object], first_source["rule"])
    first_rule["level"] = first_level
    second_hit = hit("conflict", "2026-09-30T10:00:00Z")
    second_source = cast(dict[str, object], second_hit["_source"])
    second_rule = cast(dict[str, object], second_source["rule"])
    second_rule["level"] = second_level
    second_agent = cast(dict[str, object], second_source["agent"])
    second_agent["name"] = second_agent_name

    def handler(request: httpx.Request) -> httpx.Response:
        if "point_in_time" in request.url.path:
            if request.method == "DELETE":
                return httpx.Response(200, json={"succeeded": True})
            return httpx.Response(200, json={"pit_id": "conflict-pit"})
        if request.url.path.endswith("/_validate/query"):
            return httpx.Response(200, json={"valid": True})
        return httpx.Response(
            200,
            json={"hits": {"total": 2, "hits": [first_hit, second_hit]}},
        )

    indexer, _, client, _ = make_indexer(site, mapping_profile, cursor_cipher, handler)
    _, authorized = site
    result = await indexer.execute(
        fetch,
        topic_id="ldap",
        question_id=execution.question_id,
        principal=principal,
        site=authorized,
        execution=execution,
    )
    if not conflicting:
        assert result.state == FetchState.rows
        assert result.error is None
        assert len(result.rows) == 1
        assert result.rows[0].values[FieldId.rule_level] is first_level
        assert [check.code for check in result.checks] == ["identical_source_rows_deduplicated"]
        await client.aclose()
        return
    assert result.state == FetchState.unavailable
    assert result.error is not None and result.error.code == ErrorCode.EVIDENCE_INVALID
    await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status, expected_state, expected_code",
    [
        (401, "unavailable", ErrorCode.INDEXER_AUTH_REJECTED),
        (403, "denied", ErrorCode.INDEXER_DENIED),
    ],
)
async def test_indexer_auth_and_dls_denial_are_not_empty_or_retried(
    site,
    fetch,
    principal,
    execution,
    mapping_profile,
    cursor_cipher,
    status,
    expected_state,
    expected_code,
):
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(status, json={"error": "private backend detail"})

    indexer, broker, client, _ = make_indexer(site, mapping_profile, cursor_cipher, handler)
    _, authorized = site
    result = await indexer.execute(
        fetch,
        topic_id="ldap",
        question_id=execution.question_id,
        principal=principal,
        site=authorized,
        execution=execution,
    )
    assert str(result.state) == expected_state
    assert result.error.code == expected_code
    assert result.count is None and result.rows == []
    assert calls == 1
    assert broker.calls == 1
    assert "private backend detail" not in repr(result)
    await client.aclose()


@pytest.mark.asyncio
async def test_streamed_response_bytes_are_bounded(
    site, fetch, principal, execution, mapping_profile, cursor_cipher
):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"{" + b" " * 80 + b"}")

    indexer, _, client, admission = make_indexer(
        site, mapping_profile, cursor_cipher, handler, response_bytes=32
    )
    _, authorized = site
    result = await indexer.execute(
        fetch,
        topic_id="ldap",
        question_id=execution.question_id,
        principal=principal,
        site=authorized,
        execution=execution,
    )
    assert str(result.state) == "unavailable"
    assert result.error.code == ErrorCode.EVIDENCE_LIMIT
    assert admission.released == admission.grants
    await client.aclose()


@pytest.mark.asyncio
async def test_empty_result_probes_are_bounded_to_same_pit(
    site, fetch, principal, execution, mapping_profile, cursor_cipher
):
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("/_validate/query"):
            return httpx.Response(200, json={"valid": True})
        if "point_in_time" in request.url.path:
            if request.method == "DELETE":
                return httpx.Response(200, json={"succeeded": True})
            return httpx.Response(200, json={"pit_id": "empty-pit"})
        if request.url.path.startswith("/_resolve/index/"):
            return httpx.Response(200, json={"indices": [{"name": "alerts-alpha-2026.09.30"}]})
        body = json.loads(request.content)
        assert body["pit"]["id"] == "empty-pit"
        if body["size"] == 2:
            return httpx.Response(
                200, json={"hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}}
            )
        filters = body["query"]["bool"]["filter"]
        total = 5 if len(filters) == 1 else 0 if filters[1]["term"]["agent.id"] == "007" else 5
        return httpx.Response(
            200, json={"hits": {"total": {"value": total, "relation": "eq"}, "hits": []}}
        )

    indexer, _, client, admission = make_indexer(site, mapping_profile, cursor_cipher, handler)
    _, authorized = site
    result = await indexer.execute(
        fetch,
        topic_id="ldap",
        question_id=execution.question_id,
        principal=principal,
        site=authorized,
        execution=execution,
    )
    assert len(requests) == 8  # PIT, validate, search, index/window/filter/combination, close
    assert execution.calls.claimed == [
        CallKind.pit,
        CallKind.validate,
        CallKind.search,
        CallKind.mapping,
        CallKind.probe,
        CallKind.probe,
        CallKind.probe,
        CallKind.pit,
    ]
    assert [grant.call for grant in admission.grants] == [
        "pit",
        "validate",
        "search",
        "mapping",
        "probe",
        "probe",
        "probe",
        "pit",
    ]
    assert admission.released == admission.grants
    assert len({grant.operation_id for grant in admission.grants}) == len(requests)
    assert result.empty_proof is not None
    assert result.empty_proof.consistency == "coherent"
    assert result.empty_proof.matched_nothing == [FieldId.agent_id]
    assert result.empty_proof.snapshot.key == result.snapshot.key
    await client.aclose()


@pytest.mark.asyncio
async def test_pit_unavailable_serves_first_page_without_cursor(
    site, fetch, principal, execution, mapping_profile, cursor_cipher
):
    config, authorized = site
    site_without_pit = authorized.model_copy(
        update={"config": config.model_copy(update={"pit_supported": False})}
    )
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("/_validate/query"):
            return httpx.Response(200, json={"valid": True})
        assert request.url.path.endswith("/_search")
        body = json.loads(request.content)
        assert "pit" not in body
        return httpx.Response(
            200,
            json={
                "hits": {
                    "total": {"value": 1, "relation": "eq"},
                    "hits": [hit("first-page-row", "2026-09-30T11:00:00Z")],
                }
            },
        )

    indexer, _, client, admission = make_indexer(site, mapping_profile, cursor_cipher, handler)
    result = await indexer.execute(
        fetch,
        topic_id="ldap",
        question_id=execution.question_id,
        principal=principal,
        site=site_without_pit,
        execution=execution,
    )
    assert len(requests) == 2
    assert result.snapshot.kind == SnapshotKind.first_page_only
    assert result.next_cursor is None
    assert result.message == (
        "Paging is unavailable because a stable three-part cursor boundary was not available."
    )
    assert [grant.call for grant in admission.grants] == ["validate", "search"]
    assert admission.released == admission.grants
    await client.aclose()


@pytest.mark.asyncio
async def test_missing_tie_capability_keeps_first_page_and_discloses_limit(
    site, fetch, principal, execution, mapping_profile, cursor_cipher
):
    profile_without_tie = mapping_profile.__class__(
        profile_id=mapping_profile.profile_id,
        fields=mapping_profile.fields,
        alert_projection=mapping_profile.alert_projection,
        vulnerability_projection=mapping_profile.vulnerability_projection,
        tie_break_field=None,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if "point_in_time" in request.url.path:
            if request.method == "DELETE":
                return httpx.Response(200, json={"succeeded": True})
            return httpx.Response(200, json={"pit_id": "without-tie-pit"})
        if request.url.path.endswith("/_validate/query"):
            return httpx.Response(200, json={"valid": True})
        body = json.loads(request.content)
        assert body["sort"] == [{"@timestamp": {"order": "desc"}}]
        return httpx.Response(
            200,
            json={"hits": {"total": 1, "hits": [hit("first", "2026-09-30T11:00:00Z")]}},
        )

    config, authorized = site
    client = httpx.AsyncClient(
        base_url=config.indexer_origin,
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
        trust_env=False,
    )
    indexer = WazuhIndexer(
        Broker(expires_at=datetime(2026, 9, 30, 12, 5, tzinfo=UTC)),
        RecordingReadAdmission(),
        lambda target: client,
        profiles={profile_without_tie.profile_id: profile_without_tie},
        clock=lambda: datetime(2026, 9, 30, 12, 0, tzinfo=UTC),
        content_sha="c" * 40,
        cursor_cipher=cursor_cipher,
    )
    result = await indexer.execute(
        fetch,
        topic_id="ldap",
        question_id=execution.question_id,
        principal=principal,
        site=authorized,
        execution=execution,
    )
    assert len(result.rows) == 1
    assert result.next_cursor is None
    assert result.message == (
        "Paging is unavailable because a stable three-part cursor boundary was not available."
    )
    await client.aclose()


@pytest.mark.asyncio
async def test_filtered_visible_zero_is_never_qualified_as_full_empty(
    site, fetch, principal, execution, mapping_profile, cursor_cipher
):
    beta_analyst = principal.model_copy(update={"groups": ("soc-beta",)})
    from ai_soc.identity.policy import MappedSitePolicy

    filtered_site = MappedSitePolicy(
        (site[0],), now=lambda: datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
    ).authorize(beta_analyst, "alpha")
    filtered_config = filtered_site.config.model_copy(update={"pit_supported": False})
    filtered_site = filtered_site.model_copy(update={"config": filtered_config})

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/_validate/query"):
            return httpx.Response(200, json={"valid": True})
        return httpx.Response(200, json={"hits": {"total": 0, "hits": []}})

    indexer, _, client, _ = make_indexer(site, mapping_profile, cursor_cipher, handler)
    result = await indexer.execute(
        fetch,
        topic_id="ldap",
        question_id=execution.question_id,
        principal=beta_analyst,
        site=filtered_site,
        execution=execution,
    )
    assert str(result.state) == "filtered"
    assert result.empty_proof is not None
    assert result.empty_proof.consistency == "unconfirmed"
    assert str(result.empty_proof.visibility) == "filtered"
    await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "validation_status,expected_state,expected_calls",
    [(404, "rows", [CallKind.validate, CallKind.search]), (403, "denied", [CallKind.validate])],
)
async def test_query_validation_is_optional_only_when_endpoint_is_unsupported(
    site,
    fetch,
    principal,
    execution,
    mapping_profile,
    cursor_cipher,
    validation_status,
    expected_state,
    expected_calls,
):
    config, authorized = site
    no_pit = authorized.model_copy(
        update={"config": config.model_copy(update={"pit_supported": False})}
    )
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.path)
        if request.url.path.endswith("/_validate/query"):
            return httpx.Response(validation_status, json={"valid": False})
        return httpx.Response(
            200,
            json={
                "hits": {
                    "total": {"value": 1, "relation": "eq"},
                    "hits": [hit("validated-row", "2026-09-30T11:00:00Z")],
                }
            },
        )

    indexer, _, client, _ = make_indexer(site, mapping_profile, cursor_cipher, handler)
    result = await indexer.execute(
        fetch,
        topic_id="ldap",
        question_id=execution.question_id,
        principal=principal,
        site=no_pit,
        execution=execution,
    )
    assert str(result.state) == expected_state
    assert execution.calls.claimed == expected_calls
    assert len(requests) == (2 if validation_status == 404 else 1)
    if validation_status == 403:
        assert result.error.code == ErrorCode.INDEXER_DENIED
    await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "rejected_call,expected_calls,expected_requests",
    [
        ("pit", ["pit"], 0),
        ("validate", ["pit", "validate", "pit"], 2),
        ("search", ["pit", "validate", "search", "pit"], 3),
    ],
)
async def test_read_capacity_rejection_is_typed_and_never_falls_back(
    site,
    fetch,
    principal,
    execution,
    mapping_profile,
    cursor_cipher,
    rejected_call,
    expected_calls,
    expected_requests,
):
    requests: list[httpx.Request] = []
    admission = RecordingReadAdmission(reject_calls=frozenset({("alpha", rejected_call)}))

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if "point_in_time" in request.url.path:
            if request.method == "DELETE":
                return httpx.Response(200, json={"succeeded": True})
            return httpx.Response(200, json={"pit_id": "capacity-pit"})
        if request.url.path.endswith("/_validate/query"):
            return httpx.Response(200, json={"valid": True})
        return httpx.Response(200, json={"hits": {"total": 0, "hits": []}})

    indexer, _, client, _ = make_indexer(
        site, mapping_profile, cursor_cipher, handler, admission=admission
    )
    result = await indexer.execute(
        fetch,
        topic_id="ldap",
        question_id=execution.question_id,
        principal=principal,
        site=site[1],
        execution=execution,
    )
    assert str(result.state) == "unavailable"
    assert result.error.code == ErrorCode.CAPACITY_LIMIT
    assert [request["call"] for request in admission.acquired] == expected_calls
    assert [grant.call for grant in admission.grants] == [
        call for call in expected_calls if call != rejected_call
    ]
    assert admission.released == admission.grants
    assert len(requests) == expected_requests
    assert len(execution.calls.claimed) == expected_requests
    await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "rejected_call,expected_calls,expected_requests",
    [
        ("mapping", ["pit", "validate", "search", "mapping", "pit"], 4),
        ("probe", ["pit", "validate", "search", "mapping", "probe", "pit"], 5),
    ],
)
async def test_empty_diagnostic_capacity_is_not_silently_downgraded(
    site,
    fetch,
    principal,
    execution,
    mapping_profile,
    cursor_cipher,
    rejected_call,
    expected_calls,
    expected_requests,
):
    requests: list[httpx.Request] = []
    admission = RecordingReadAdmission(reject_calls=frozenset({("alpha", rejected_call)}))

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if "point_in_time" in request.url.path:
            if request.method == "DELETE":
                return httpx.Response(200, json={"succeeded": True})
            return httpx.Response(200, json={"pit_id": "diagnostic-pit"})
        if request.url.path.endswith("/_validate/query"):
            return httpx.Response(200, json={"valid": True})
        if request.url.path.startswith("/_resolve/index/"):
            return httpx.Response(200, json={"indices": [{"name": "alerts-alpha"}]})
        return httpx.Response(200, json={"hits": {"total": 0, "hits": []}})

    indexer, _, client, _ = make_indexer(
        site, mapping_profile, cursor_cipher, handler, admission=admission
    )
    result = await indexer.execute(
        fetch,
        topic_id="ldap",
        question_id=execution.question_id,
        principal=principal,
        site=site[1],
        execution=execution,
    )
    assert str(result.state) == "unavailable"
    assert result.error.code == ErrorCode.CAPACITY_LIMIT
    assert result.empty_proof is None
    assert [request["call"] for request in admission.acquired] == expected_calls
    assert [grant.call for grant in admission.grants] == [
        call for call in expected_calls if call != rejected_call
    ]
    assert admission.released == admission.grants
    assert len(requests) == expected_requests
    assert len(execution.calls.claimed) == expected_requests
    await client.aclose()


@pytest.mark.asyncio
async def test_page_capacity_rejection_is_a_typed_cursor_error_without_transport(
    site, fetch, principal, execution, mapping_profile, cursor_cipher
):
    from ai_soc.query.cursors import CursorError

    requests: list[httpx.Request] = []
    admission = RecordingReadAdmission(reject_calls=frozenset({("alpha", "search")}))

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"hits": {"total": 2, "hits": []}})

    indexer, _, client, _ = make_indexer(
        site, mapping_profile, cursor_cipher, handler, admission=admission
    )
    first = indexer._result(
        {"hits": {"total": 2, "hits": [hit("row-1", "2026-09-30T11:00:00Z")]}},
        compile_fetch(fetch, site[1], mapping_profile),
        fetch,
        "ldap",
        execution.question_id,
        site[1],
        pit_id="page-capacity-pit",
        profile=mapping_profile,
        principal=principal,
    )
    assert first.next_cursor is not None
    with pytest.raises(CursorError) as error:
        await indexer.page(
            first.next_cursor, principal=principal, site=site[1], execution=execution
        )
    assert error.value.code == ErrorCode.CAPACITY_LIMIT
    assert [request["call"] for request in admission.acquired] == ["search"]
    assert requests == []
    assert execution.calls.claimed == []
    await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_value", ["not-a-grant", None])
async def test_malformed_admission_union_fails_closed_without_transport(
    site, fetch, principal, execution, mapping_profile, cursor_cipher, bad_value
):
    class MalformedAdmission(RecordingReadAdmission):
        async def acquire(self, **kwargs):
            self.acquired.append(kwargs)
            return cast(ReadOperationGrant | StageCapacityRejection, bad_value)

    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"pit_id": "must-not-be-created"})

    admission = MalformedAdmission()
    indexer, _, client, _ = make_indexer(
        site, mapping_profile, cursor_cipher, handler, admission=admission
    )
    result = await indexer.execute(
        fetch,
        topic_id="ldap",
        question_id=execution.question_id,
        principal=principal,
        site=site[1],
        execution=execution,
    )
    assert result.error.code == ErrorCode.DEPENDENCY_UNAVAILABLE
    assert requests == []
    assert execution.calls.claimed == []
    await client.aclose()


@pytest.mark.asyncio
async def test_alpha_capacity_does_not_consume_beta_site_read_permit(
    site, fetch, principal, execution, mapping_profile, cursor_cipher
):
    from ai_soc.identity.policy import MappedSitePolicy

    config, alpha = site
    alpha_config = config.model_copy(update={"pit_supported": False})
    alpha = alpha.model_copy(update={"config": alpha_config})
    beta_config = config.model_copy(
        update={
            "environment_id": "beta",
            "label": "beta",
            "indexer_origin": "https://beta.private.example.test",
            "private_network_ref": "vpn-beta",
            "jwt_issuer": "soc-beta",
            "jwt_audience": "wazuh-beta",
            "kms_signing_key_arn": "arn:aws:kms:us-east-1:123456789012:key/beta",
            "ca_secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:beta",
            "ca_secret_version": "version-beta",
            "pit_supported": False,
            "allowed_index_patterns": {
                IndexFamily.alerts: ("wazuh-alerts-beta-*",),
                IndexFamily.vulnerabilities: ("wazuh-states-vulnerabilities-beta-*",),
            },
        }
    )
    beta = MappedSitePolicy(
        (beta_config,), now=lambda: datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
    ).authorize(principal, "beta")
    beta_execution = replace(execution, environment_id="beta")
    admission = RecordingReadAdmission(reject_calls=frozenset({("alpha", "validate")}))
    hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        hosts.append(request.url.host)
        if request.url.path.endswith("/_validate/query"):
            return httpx.Response(200, json={"valid": True})
        return httpx.Response(
            200,
            json={
                "hits": {
                    "total": {"value": 1, "relation": "eq"},
                    "hits": [hit("beta-row", "2026-09-30T11:00:00Z")],
                }
            },
        )

    clients = {
        "alpha": httpx.AsyncClient(
            base_url="https://alpha.private.example.test",
            transport=httpx.MockTransport(handler),
            trust_env=False,
        ),
        "beta": httpx.AsyncClient(
            base_url="https://beta.private.example.test",
            transport=httpx.MockTransport(handler),
            trust_env=False,
        ),
    }

    class MultiSiteBroker:
        async def issue(self, principal, site, *, execution):
            return IndexerCredential(
                bearer_token=SecretStr("site-scoped-token"),
                expires_at=datetime(2026, 9, 30, 12, 5, tzinfo=UTC),
                key_id=site.config.environment_id,
            )

    indexer = WazuhIndexer(
        MultiSiteBroker(),
        admission,
        lambda target: clients[target.config.environment_id],
        profiles={mapping_profile.profile_id: mapping_profile},
        clock=lambda: datetime(2026, 9, 30, 12, 0, tzinfo=UTC),
        content_sha="c" * 40,
        cursor_cipher=cursor_cipher,
    )
    alpha_result = await indexer.execute(
        fetch,
        topic_id="ldap",
        question_id=execution.question_id,
        principal=principal,
        site=alpha,
        execution=execution,
    )
    beta_result = await indexer.execute(
        fetch,
        topic_id="ldap",
        question_id=beta_execution.question_id,
        principal=principal,
        site=beta,
        execution=beta_execution,
    )
    assert alpha_result.error.code == ErrorCode.CAPACITY_LIMIT
    assert str(beta_result.state) == "rows"
    assert [request["environment_id"] for request in admission.acquired] == [
        "alpha",
        "beta",
        "beta",
    ]
    assert [request["call"] for request in admission.acquired] == [
        "validate",
        "validate",
        "search",
    ]
    assert [grant.environment_id for grant in admission.released] == ["beta", "beta"]
    assert hosts == ["beta.private.example.test", "beta.private.example.test"]
    await clients["alpha"].aclose()
    await clients["beta"].aclose()


@pytest.mark.asyncio
async def test_cancelled_awaiter_retains_read_permit_until_transport_finishes(
    site, fetch, principal, execution, mapping_profile, cursor_cipher
):
    started = asyncio.Event()
    finish = asyncio.Event()
    transport_finished = asyncio.Event()

    class BlockingTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            started.set()
            await finish.wait()
            transport_finished.set()
            return httpx.Response(200, json={"pit_id": "blocked-physical-call"}, request=request)

    client = httpx.AsyncClient(
        base_url=site[0].indexer_origin,
        transport=BlockingTransport(),
        follow_redirects=False,
        trust_env=False,
    )
    admission = RecordingReadAdmission()
    broker = Broker(expires_at=datetime(2026, 9, 30, 12, 5, tzinfo=UTC))
    indexer = WazuhIndexer(
        broker,
        admission,
        lambda target: client,
        profiles={mapping_profile.profile_id: mapping_profile},
        clock=lambda: datetime(2026, 9, 30, 12, 0, tzinfo=UTC),
        content_sha="c" * 40,
        cursor_cipher=cursor_cipher,
    )
    request = asyncio.create_task(
        indexer.execute(
            fetch,
            topic_id="ldap",
            question_id=execution.question_id,
            principal=principal,
            site=site[1],
            execution=execution,
        )
    )
    await asyncio.wait_for(started.wait(), timeout=1)
    request.cancel()
    with pytest.raises(asyncio.CancelledError):
        await request
    assert len(admission.grants) == 1
    assert admission.released == []
    assert not transport_finished.is_set()
    finish.set()
    await asyncio.wait_for(transport_finished.wait(), timeout=1)
    await asyncio.wait_for(admission.released_event.wait(), timeout=1)
    assert admission.released == admission.grants
    assert execution.calls.claimed == [CallKind.pit]
    await client.aclose()


@pytest.mark.asyncio
async def test_read_at_hard_deadline_boundary_releases_grant_without_transport(
    site, execution, mapping_profile, cursor_cipher
):
    from ai_soc.query.indexer import _IndexerFailure

    now = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
    clock_values = iter((now, now + timedelta(seconds=10)))
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"hits": {"total": 0, "hits": []}})

    client = httpx.AsyncClient(
        base_url=site[0].indexer_origin,
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
        trust_env=False,
    )
    admission = RecordingReadAdmission()
    credential = IndexerCredential(
        bearer_token=SecretStr("analyst-signed-token"),
        expires_at=now + timedelta(minutes=5),
        key_id="alpha-v2",
    )
    indexer = WazuhIndexer(
        Broker(expires_at=credential.expires_at),
        admission,
        lambda target: client,
        profiles={mapping_profile.profile_id: mapping_profile},
        clock=lambda: next(clock_values),
        content_sha="c" * 40,
        cursor_cipher=cursor_cipher,
    )

    with pytest.raises(_IndexerFailure) as failure:
        await indexer._admitted_request_json(
            client,
            "POST",
            "/_search",
            {"query": {"match_all": {}}},
            credential,
            call="search",
            question_id=execution.question_id,
            site=site[1],
            execution=execution,
        )

    assert failure.value.code == ErrorCode.DEADLINE_EXCEEDED
    assert requests == []
    assert len(admission.grants) == 1
    assert admission.released == admission.grants
    assert execution.calls.claimed == []
    await client.aclose()


@pytest.mark.asyncio
async def test_indexer_conforms_to_concrete_memory_read_admission_store(
    site, fetch, principal, execution, mapping_profile, cursor_cipher
):
    store = MemoryReadAdmissionStore()
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.path)
        if request.url.path.endswith("/_validate/query"):
            return httpx.Response(200, json={"valid": True})
        return httpx.Response(
            200,
            json={
                "hits": {
                    "total": {"value": 1, "relation": "eq"},
                    "hits": [hit("concrete-store-row", "2026-09-30T11:00:00Z")],
                }
            },
        )

    config, authorized = site
    no_pit_site = authorized.model_copy(
        update={"config": config.model_copy(update={"pit_supported": False})}
    )
    indexer, _, client, _ = make_indexer(
        site, mapping_profile, cursor_cipher, handler, admission=store
    )
    result = await indexer.execute(
        fetch,
        topic_id="ldap",
        question_id=execution.question_id,
        principal=principal,
        site=no_pit_site,
        execution=execution,
    )
    assert str(result.state) == "rows"
    assert requests == [
        "/wazuh-alerts-alpha-*/_validate/query",
        "/wazuh-alerts-alpha-*/_search",
    ]
    assert execution.calls.claimed == [CallKind.validate, CallKind.search]

    now = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)

    async def fill_site(environment_id: str) -> list[ReadOperationGrant]:
        grants: list[ReadOperationGrant] = []
        for _ in range(8):
            question_id = uuid4()
            operation_id = uuid4()
            grant = await store.acquire(
                environment_id=environment_id,
                question_id=question_id,
                operation_id=operation_id,
                call="search",
                now=now,
            )
            assert type(grant) is ReadOperationGrant
            grants.append(grant)
        return grants

    alpha_grants = await fill_site("alpha")
    beta_grants = await fill_site("beta")
    rejected = await store.acquire(
        environment_id="alpha",
        question_id=uuid4(),
        operation_id=uuid4(),
        call="search",
        now=now,
    )
    assert isinstance(rejected, StageCapacityRejection)
    for grant in (*alpha_grants, *beta_grants):
        await store.release(grant)
    await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("variant", ["positive", "negative", "boundary", "failure"])
async def test_repeated_reads_do_not_cache_rows_or_credentials_across_owner_or_site(
    site, fetch, principal, execution, mapping_profile, cursor_cipher, variant, request
):
    from ai_soc.identity.policy import MappedSitePolicy

    fixture_path = Path(__file__).parent / "data/b3_read_isolation.json"
    fixture_bytes = fixture_path.read_bytes()
    fixture_sha256 = hashlib.sha256(fixture_bytes).hexdigest()
    assert fixture_sha256 == "3f96f3077835d5cabc4b0655a09da974d5db44c5487b49f156607631e606fb01"
    record_case_metadata(
        request,
        acceptance_id="GP1",
        case_id="B3-READ-001.resolution",
        variant=variant,
        fixture_sha256=fixture_sha256,
    )
    fixture = json.loads(fixture_bytes)
    variant_fixture = fixture["variants"][variant]
    assert fetch.fetch_id == fixture["request"]["fetch_id"]
    assert fixture["request"]["filter"] == {"field": "agent.id", "op": "eq", "value": "007"}
    assert fixture["backend_fixture"]["calls_per_successful_read"] == ["validate", "search"]

    config, _ = site
    site_fixtures = {entry["environment_id"]: entry for entry in fixture["sites"]}
    alpha_fixture = site_fixtures["alpha"]
    beta_fixture = site_fixtures["beta"]
    alpha_config = config.model_copy(
        update={
            "pit_supported": False,
            "indexer_origin": alpha_fixture["origin"],
            "allowed_index_patterns": {
                IndexFamily.alerts: (alpha_fixture["index"],),
                IndexFamily.vulnerabilities: ("wazuh-states-vulnerabilities-alpha-*",),
            },
        }
    )
    beta_config = config.model_copy(
        update={
            "environment_id": "beta",
            "label": "beta",
            "indexer_origin": beta_fixture["origin"],
            "private_network_ref": "vpn-beta",
            "jwt_issuer": "soc-beta",
            "jwt_audience": "wazuh-beta",
            "kms_signing_key_arn": "arn:aws:kms:us-east-1:123456789012:key/beta",
            "ca_secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:beta",
            "ca_secret_version": "version-beta",
            "pit_supported": False,
            "allowed_index_patterns": {
                IndexFamily.alerts: (beta_fixture["index"],),
                IndexFamily.vulnerabilities: ("wazuh-states-vulnerabilities-beta-*",),
            },
        }
    )
    policy = MappedSitePolicy(
        (alpha_config, beta_config), now=lambda: datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
    )
    alpha = policy.authorize(principal, "alpha")
    beta = policy.authorize(principal, "beta")
    other_owner = principal.model_copy(
        update={
            "sub": fixture["principals"][1],
            "owner_key": owner_key(str(principal.issuer), fixture["principals"][1]),
        }
    )
    requests: list[tuple[str, str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        token = request.headers["authorization"].removeprefix("Bearer ")
        environment_id, subject = token.split(":", maxsplit=1)
        requests.append((request.url.host, request.url.path, token))
        if request.url.path.endswith("/_validate/query"):
            return httpx.Response(200, json=fixture["backend_fixture"]["validate"])
        return httpx.Response(
            200,
            json={
                "hits": {
                    "total": {"value": fixture["backend_fixture"]["total"], "relation": "eq"},
                    "hits": [
                        hit(
                            fixture["backend_fixture"]["record_id"].format(
                                environment_id=environment_id, principal=subject
                            ),
                            "2026-09-30T11:00:00Z",
                        )
                    ],
                }
            },
        )

    clients = {
        environment_id: httpx.AsyncClient(
            base_url=site_config.indexer_origin,
            transport=httpx.MockTransport(handler),
            follow_redirects=False,
            trust_env=False,
        )
        for environment_id, site_config in (("alpha", alpha_config), ("beta", beta_config))
    }

    class OwnerSiteBroker:
        def __init__(self) -> None:
            self.issued: list[tuple[str, str]] = []

        async def issue(self, requested_principal, requested_site, *, execution):
            environment_id = requested_site.config.environment_id
            self.issued.append((requested_principal.sub, environment_id))
            return IndexerCredential(
                bearer_token=SecretStr(f"{environment_id}:{requested_principal.sub}"),
                expires_at=datetime(2026, 9, 30, 12, 5, tzinfo=UTC),
                key_id=f"{environment_id}-fixture-key",
            )

    broker = OwnerSiteBroker()
    store = MemoryReadAdmissionStore()
    indexer = WazuhIndexer(
        broker,
        store,
        lambda target: clients[target.config.environment_id],
        profiles={mapping_profile.profile_id: mapping_profile},
        clock=lambda: datetime(2026, 9, 30, 12, 0, tzinfo=UTC),
        content_sha="c" * 40,
        cursor_cipher=cursor_cipher,
    )

    async def execute_for(requested_principal, requested_site, requested_execution):
        return await indexer.execute(
            fetch,
            topic_id="ldap",
            question_id=execution.question_id,
            principal=requested_principal,
            site=requested_site,
            execution=requested_execution,
        )

    expected_runs = [tuple(run) for run in variant_fixture["runs"]]
    expected_ids = variant_fixture.get("expected_record_ids")
    if variant == "positive":
        result = await execute_for(principal, alpha, execution)
        assert result.rows[0].record_ref.record_id == expected_ids[0]
    elif variant == "negative":
        alice = await execute_for(principal, alpha, execution)
        bob = await execute_for(
            other_owner, alpha, replace(execution, owner_key=other_owner.owner_key)
        )
        assert [
            alice.rows[0].record_ref.record_id,
            bob.rows[0].record_ref.record_id,
        ] == expected_ids
    elif variant == "boundary":
        alice_alpha = await execute_for(principal, alpha, execution)
        alice_beta = await execute_for(principal, beta, replace(execution, environment_id="beta"))
        assert [
            alice_alpha.rows[0].record_ref.record_id,
            alice_beta.rows[0].record_ref.record_id,
        ] == expected_ids
    else:
        initial = await execute_for(principal, alpha, execution)
        expected_initial = fixture["backend_fixture"]["record_id"].format(
            environment_id="alpha", principal=fixture["principals"][0]
        )
        assert initial.rows[0].record_ref.record_id == expected_initial
        held_alpha: list[ReadOperationGrant] = []
        for _ in range(fixture["admission"]["per_site_capacity"]):
            grant = await store.acquire(
                environment_id="alpha",
                question_id=uuid4(),
                operation_id=uuid4(),
                call="search",
                now=datetime(2026, 9, 30, 12, 0, tzinfo=UTC),
            )
            assert type(grant) is ReadOperationGrant
            held_alpha.append(grant)
        rejected = await execute_for(principal, alpha, execution)
        assert str(rejected.state) == "unavailable"
        assert str(rejected.error.code) == variant_fixture["expected_alpha_error"]
        beta_after_rejection = await execute_for(
            principal, beta, replace(execution, environment_id="beta")
        )
        assert (
            beta_after_rejection.rows[0].record_ref.record_id
            == variant_fixture["expected_beta_record_id"]
        )
        for grant in held_alpha:
            await store.release(grant)

    assert broker.issued == expected_runs
    calls_per_read = fixture["backend_fixture"]["calls_per_successful_read"]
    expected_requests = [
        (environment_id, phase) for _, environment_id in expected_runs for phase in calls_per_read
    ]
    if variant == "failure":
        expected_requests = [
            tuple(item.split(".", maxsplit=1)) for item in variant_fixture["expected_transport"]
        ]
    actual_requests: list[tuple[str, str]] = []
    for host, path, _ in requests:
        phase = "validate" if path.endswith("/_validate/query") else "search"
        actual_requests.append((host.split(".", maxsplit=1)[0], phase))
    assert actual_requests == expected_requests
    expected_tokens = [
        f"{environment_id}:{subject}"
        for subject, environment_id in expected_runs
        for _ in calls_per_read
    ]
    if variant == "failure":
        expected_tokens = [
            f"{item.split('.', maxsplit=1)[0]}:{fixture['principals'][0]}"
            for item in variant_fixture["expected_transport"]
        ]
    assert [token for _, _, token in requests] == expected_tokens
    for client in clients.values():
        await client.aclose()


@pytest.mark.asyncio
async def test_indexer_credential_marks_broker_unavailable_for_expired_token(
    site, execution, mapping_profile, cursor_cipher, principal
) -> None:
    from typing import cast

    from ai_soc.contracts.models import StageName, StageOutcome
    from ai_soc.query.indexer import WazuhIndexer, _IndexerFailure
    from ai_soc.telemetry.audit_delivery import AuditTelemetry, SqsClient
    from ai_soc.telemetry.events import TelemetryAdapter
    from ai_soc.telemetry.metrics import FixtureMetricExporter, MetricName
    from ai_soc.telemetry.tracing import FixtureSpanExporter

    class _Clock:
        def now(self) -> datetime:
            return NOW

    class _Sqs:
        def send_message(self, *, QueueUrl: str, MessageBody: str) -> dict[str, object]:
            return {"MessageId": "delivery-1"}

    class ExpiredBroker:
        async def issue(self, principal_arg, site_arg, *, execution):
            return IndexerCredential(
                bearer_token=SecretStr("analyst-signed-token"),
                expires_at=NOW,
                key_id="alpha-v2",
            )

    config, authorized = site
    client = httpx.AsyncClient(
        base_url=config.indexer_origin,
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={})),
        follow_redirects=False,
        trust_env=False,
    )
    spans = FixtureSpanExporter()
    metrics = FixtureMetricExporter()
    telemetry = TelemetryAdapter(
        audit=AuditTelemetry(
            cast(SqsClient, _Sqs()), queue_url="https://sqs.example.test/audit", clock=_Clock()
        ),
        spans=spans,
        metrics=metrics,
    )
    indexer = WazuhIndexer(
        ExpiredBroker(),
        RecordingReadAdmission(),
        lambda target: client,
        profiles={mapping_profile.profile_id: mapping_profile},
        clock=lambda: NOW,
        content_sha="c" * 40,
        cursor_cipher=cursor_cipher,
        telemetry=telemetry,
        metrics=metrics,
    )

    with pytest.raises(_IndexerFailure) as failure:
        await indexer._credential(principal, authorized, execution)

    assert failure.value.code is ErrorCode.TOKEN_BROKER_UNAVAILABLE
    broker_spans = [span for span in spans.spans if span.stage is StageName.broker]
    assert broker_spans
    assert broker_spans[-1].outcome == StageOutcome.unavailable
    assert any(sample.name is MetricName.token_broker_failure for sample in metrics.samples)
    await client.aclose()
