from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from ai_soc.application.errors import ServiceFailure
from ai_soc.application.runtime import (
    BoundedCallLedger,
    RequestCancellation,
    RequestCancelled,
    RequestRuntime,
)
from ai_soc.contracts.models import AdmissionGrant, CallKind

_DEADLINE_BYTES = (
    Path(__file__).with_name("data").joinpath("execution_deadline_cases.json").read_bytes()
)
_DEADLINE_SHA256 = "dc0d10c05d50e01a346977929661158232e6dafd9db7f56977a967d4fe6ddba1"
assert hashlib.sha256(_DEADLINE_BYTES).hexdigest() == _DEADLINE_SHA256
_DEADLINE_CASES = json.loads(_DEADLINE_BYTES)["cases"]


class FixedClock:
    def now(self) -> datetime:
        return datetime(2026, 9, 30, tzinfo=UTC)

    def monotonic(self) -> float:
        return 0.0


def grant() -> AdmissionGrant:
    return AdmissionGrant(
        holder_id=uuid4(),
        slot_ids=("SLOT#0000",),
        expires_at=datetime(2026, 9, 30, 0, 1, tzinfo=UTC),
        fence=1,
    )


def test_runtime_creates_valid_trace_and_bounded_execution_context() -> None:
    scenario = _DEADLINE_CASES["positive"]
    context = RequestRuntime(FixedClock(), deadline_seconds=scenario["deadline_seconds"]).create(
        question_id=uuid4(),
        operation="ask",
        owner_key="a" * 64,
        environment_id="alpha",
        admission=grant(),
    )

    assert context.trace_context.trace_id != "0" * 32
    assert context.trace_context.span_id != "0" * 16
    assert (context.deadline_at - FixedClock().now()).total_seconds() == scenario[
        "expected_offset_seconds"
    ]
    context.calls.claim(CallKind.search)
    assert context.calls.attempts(CallKind.search) == 1


def test_call_ledger_denies_attempt_before_transport_limit() -> None:
    ledger = BoundedCallLedger({CallKind.search: 1})
    ledger.claim(CallKind.search)

    with pytest.raises(ServiceFailure) as error:
        ledger.claim(CallKind.search)

    assert error.value.error.code == "CAPACITY_LIMIT"
    assert ledger.attempts(CallKind.search) == 1


def test_l3_indexer_attempt_cap_is_shared_across_probe_and_search_kinds() -> None:
    ledger = BoundedCallLedger(indexer_attempt_cap=2)
    ledger.claim(CallKind.probe)
    ledger.claim(CallKind.search)
    with pytest.raises(ServiceFailure) as error:
        ledger.claim(CallKind.mapping)
    assert error.value.error.code == "CAPACITY_LIMIT"


def test_l3_page_requests_use_eight_indexer_attempts_total() -> None:
    context = RequestRuntime(FixedClock()).create(
        question_id=uuid4(),
        operation="page",
        owner_key="a" * 64,
        environment_id="alpha",
        admission=grant(),
    )
    for _ in range(8):
        context.calls.claim(CallKind.probe)
    with pytest.raises(ServiceFailure):
        context.calls.claim(CallKind.search)


@pytest.mark.asyncio
async def test_cancellation_is_idempotent_and_waitable() -> None:
    cancellation = RequestCancellation()
    assert not cancellation.is_cancelled()
    cancellation.cancel()
    await cancellation.wait()
    assert cancellation.is_cancelled()
    with pytest.raises(RequestCancelled):
        cancellation.raise_if_cancelled()


def test_execution_deadline_accepts_exact_contract_bounds() -> None:
    case = _DEADLINE_CASES["boundary"]
    for seconds in case["deadline_seconds"]:
        context = RequestRuntime(FixedClock(), deadline_seconds=seconds).create(
            question_id=uuid4(),
            operation="ask",
            owner_key="a" * 64,
            environment_id="alpha",
            admission=grant(),
        )
        assert (context.deadline_at - FixedClock().now()).total_seconds() == seconds


def test_execution_deadline_rejects_out_of_contract_values() -> None:
    case = _DEADLINE_CASES["negative"]
    for seconds in case["invalid_deadline_seconds"]:
        with pytest.raises(ValueError, match="between 1 and 120"):
            RequestRuntime(FixedClock(), deadline_seconds=seconds)


@pytest.mark.asyncio
async def test_cancelled_execution_does_not_start_a_dependency_attempt() -> None:
    case = _DEADLINE_CASES["failure"]
    context = RequestRuntime(FixedClock()).create(
        question_id=uuid4(),
        operation="ask",
        owner_key="a" * 64,
        environment_id="alpha",
        admission=grant(),
    )
    context.cancel.cancel()

    with pytest.raises(RequestCancelled):
        context.cancel.raise_if_cancelled()
    assert context.calls.attempts(CallKind.search) == case["expected_attempts"]
