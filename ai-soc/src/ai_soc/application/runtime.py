"""Request-local execution metadata with explicit cancellation and call bounds."""

from __future__ import annotations

import asyncio
import secrets
from collections import Counter
from collections.abc import Mapping
from datetime import timedelta
from typing import Literal
from uuid import UUID

from ai_soc.application.errors import ServiceFailure
from ai_soc.contracts.errors import public_error
from ai_soc.contracts.models import (
    AdmissionGrant,
    CallKind,
    ErrorCode,
    ExecutionContext,
    TraceContext,
)
from ai_soc.contracts.ports import Clock


class RequestCancelled(Exception):
    """Raised when a disconnected or cancelled request tries to start more work."""


class RequestCancellation:
    def __init__(self) -> None:
        self._event = asyncio.Event()

    def cancel(self) -> None:
        self._event.set()

    def is_cancelled(self) -> bool:
        return self._event.is_set()

    def raise_if_cancelled(self) -> None:
        if self.is_cancelled():
            raise RequestCancelled

    async def wait(self) -> None:
        await self._event.wait()


class BoundedCallLedger:
    """Atomically accounts SDK attempts before a transport call is made."""

    _INDEXER_KINDS = frozenset(
        {
            CallKind.mapping,
            CallKind.validate,
            CallKind.pit,
            CallKind.search,
            CallKind.probe,
        }
    )

    def __init__(
        self,
        limits: Mapping[CallKind, int] | None = None,
        *,
        indexer_attempt_cap: int | None = None,
    ) -> None:
        self._limits = dict(
            limits
            or {
                CallKind.identity: 4,
                CallKind.kms: 160,
                CallKind.mapping: 160,
                CallKind.validate: 160,
                CallKind.pit: 160,
                CallKind.search: 160,
                CallKind.probe: 160,
                CallKind.COUNT: 100,
                CallKind.converse: 100,
                CallKind.embedding: 1,
                CallKind.state: 32,
                CallKind.feedback: 1,
                CallKind.audit: 2,
            }
        )
        self._indexer_attempt_cap = indexer_attempt_cap
        self._counts: Counter[CallKind] = Counter()

    def claim(self, kind: CallKind) -> None:
        """Reserve an attempt synchronously before dispatching SDK work."""
        if (
            self._indexer_attempt_cap is not None
            and kind in self._INDEXER_KINDS
            and sum(self._counts[item] for item in self._INDEXER_KINDS) >= self._indexer_attempt_cap
        ):
            raise ServiceFailure(
                public_error(
                    ErrorCode.CAPACITY_LIMIT,
                    "The request reached its bounded dependency-call limit.",
                    trace_id=secrets.token_hex(16),
                    stage=kind.value,
                    limit=self._indexer_attempt_cap,
                )
            )
        limit = self._limits.get(kind, 0)
        if self._counts[kind] >= limit:
            raise ServiceFailure(
                public_error(
                    ErrorCode.CAPACITY_LIMIT,
                    "The request reached its bounded dependency-call limit.",
                    trace_id=secrets.token_hex(16),
                    stage=kind.value,
                    limit=limit,
                )
            )
        self._counts[kind] += 1

    def attempts(self, kind: CallKind) -> int:
        return self._counts[kind]


class RequestRuntime:
    def __init__(
        self,
        clock: Clock,
        *,
        deadline_seconds: int = 120,
        call_limits: Mapping[CallKind, int] | None = None,
    ) -> None:
        if deadline_seconds < 1 or deadline_seconds > 120:
            raise ValueError("request deadline must be between 1 and 120 seconds")
        self._clock = clock
        self._deadline_seconds = deadline_seconds
        self._call_limits = call_limits

    def create(
        self,
        *,
        question_id: UUID,
        operation: Literal["ask", "page", "feedback", "semantic"],
        owner_key: str,
        environment_id: str,
        admission: AdmissionGrant,
        trace_context: TraceContext | None = None,
    ) -> ExecutionContext:
        if operation not in {"ask", "page", "feedback", "semantic"}:
            raise ValueError("unsupported request operation")
        indexer_attempt_cap = 8 if operation == "page" else 160 if operation == "ask" else None
        resolved_trace = trace_context or TraceContext(
            trace_id=secrets.token_hex(16), span_id=secrets.token_hex(8), trace_flags=1
        )
        return ExecutionContext(
            question_id=question_id,
            operation=operation,
            owner_key=owner_key,
            environment_id=environment_id,
            deadline_at=self._clock.now() + timedelta(seconds=self._deadline_seconds),
            cancel=RequestCancellation(),
            calls=BoundedCallLedger(self._call_limits, indexer_attempt_cap=indexer_attempt_cap),
            admission=admission,
            trace_context=resolved_trace,
        )
