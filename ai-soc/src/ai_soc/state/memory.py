"""Semantically strict, concurrent in-memory state adapters for fixtures."""

from __future__ import annotations

import asyncio
import hashlib
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID, uuid4

from ai_soc.contracts.canonical import canonical_bytes
from ai_soc.contracts.errors import public_error
from ai_soc.contracts.models import (
    SHA256,
    AdmissionGrant,
    CompletionCommand,
    CompletionReceipt,
    ContentId,
    ErrorCode,
    FeedbackControlContext,
    FeedbackMetadata,
    FollowupRecord,
    GitSHA40,
    IdempotencyRecord,
    Lease,
    OperationRecord,
    PolicyHash,
    QuestionBudget,
    QuestionRecord,
    RecoveryPage,
    RecoveryTicket,
    Reservation,
)
from ai_soc.state.daily_tokens import utc_day_start_epoch
from ai_soc.state.errors import StateFailure
from ai_soc.telemetry.metrics import MetricExporter
from ai_soc.telemetry.operational import (
    emit_content_provenance_failure,
    emit_recovery_backlog,
    emit_recovery_lag_seconds,
)


def _epoch(value: datetime) -> int:
    if value.tzinfo is None:
        raise ValueError("state times must be timezone-aware")
    return int(value.astimezone(UTC).timestamp())


def _hash(value: object) -> str:
    def normalize(item: object) -> object:
        if isinstance(item, UUID):
            return str(item)
        if isinstance(item, dict):
            values = cast(dict[object, object], item)
            return {str(key): normalize(entry) for key, entry in values.items()}
        if isinstance(item, (list, tuple)):
            values = cast(list[object] | tuple[object, ...], item)
            return [normalize(entry) for entry in values]
        return item

    return hashlib.sha256(canonical_bytes(normalize(value))).hexdigest()


def _conflict(code: ErrorCode, message: str) -> StateFailure:
    return StateFailure(public_error(code, message, trace_id=str(uuid4())))


@dataclass(slots=True)
class _LeaseFence:
    lease_id: UUID
    fence: int
    active: Lease | None = None


@dataclass(slots=True)
class _BudgetState:
    budget: QuestionBudget
    lease: Lease


class MemoryState:
    """One lock models each fixture transaction's atomic serialization point."""

    def __init__(
        self,
        *,
        plan_ttl_seconds: int = 1800,
        lease_seconds: int = 60,
        metrics: MetricExporter | None = None,
    ) -> None:
        self._lock = asyncio.Lock()
        self._plan_ttl = plan_ttl_seconds
        self._lease_seconds = lease_seconds
        self._metrics = metrics
        self.plans: dict[UUID, FollowupRecord] = {}
        self.leases: dict[tuple[str, str], _LeaseFence] = {}
        self.questions: dict[UUID, QuestionRecord] = {}
        self.idempotency: dict[tuple[str, str, UUID], IdempotencyRecord] = {}
        self.budgets: dict[UUID, _BudgetState] = {}
        self.reservations: dict[UUID, Reservation] = {}
        self.tickets: dict[tuple[int, UUID, UUID], RecoveryTicket] = {}
        self.operations: dict[UUID, OperationRecord] = {}
        self.completions: dict[UUID, CompletionReceipt] = {}
        self.admissions: dict[tuple[str, str, str], dict[str, tuple[AdmissionGrant, int]]] = {}
        self._admission_fences: dict[tuple[str, str, str], int] = {}
        self._daily_tokens: dict[tuple[str, int], int] = {}
        self._feedback_lock = threading.Lock()
        self.feedback_records: dict[tuple[UUID, SHA256], FeedbackMetadata] = {}

    @staticmethod
    def _feedback_control(control: FeedbackControlContext) -> None:
        control.cancel.raise_if_cancelled()
        if control.monotonic() + 5.0 > control.deadline_monotonic:
            raise StateFailure(
                public_error(
                    ErrorCode.FEEDBACK_UNAVAILABLE,
                    "Feedback is temporarily unavailable.",
                    trace_id=uuid4().hex,
                    retryable=True,
                )
            )

    @staticmethod
    def _feedback_unavailable() -> StateFailure:
        return StateFailure(
            public_error(
                ErrorCode.FEEDBACK_UNAVAILABLE,
                "Feedback is temporarily unavailable.",
                trace_id=uuid4().hex,
                retryable=True,
            )
        )

    def _feedback_acquire(self) -> None:
        if not self._feedback_lock.acquire(blocking=False):
            raise self._feedback_unavailable()

    async def read_feedback(
        self,
        *,
        receipt_id: UUID,
        note_hash: SHA256,
        now: datetime,
        control: FeedbackControlContext,
    ) -> FeedbackMetadata | None:
        self._feedback_control(control)
        self._feedback_acquire()
        try:
            self._feedback_control(control)
            record = self.feedback_records.get((receipt_id, note_hash))
            if record is None or record.ttl_epoch <= _epoch(now):
                return None
            return record
        finally:
            self._feedback_lock.release()

    async def try_create_feedback(
        self,
        *,
        receipt_id: UUID,
        note_hash: SHA256,
        now: datetime,
        control: FeedbackControlContext,
    ) -> FeedbackMetadata | None:
        self._feedback_control(control)
        self._feedback_acquire()
        try:
            self._feedback_control(control)
            key = receipt_id, note_hash
            current = self.feedback_records.get(key)
            now_epoch = _epoch(now)
            if current is not None and current.ttl_epoch > now_epoch:
                return None
            candidate = FeedbackMetadata(
                feedback_id=uuid4(),
                status="pending",
                created_at=now,
                ttl_epoch=now_epoch + 604800,
            )
            self.feedback_records[key] = candidate
            return candidate
        finally:
            self._feedback_lock.release()

    async def mark_feedback_queued(
        self,
        *,
        receipt_id: UUID,
        note_hash: SHA256,
        feedback_id: UUID,
        now: datetime,
        control: FeedbackControlContext,
    ) -> bool:
        self._feedback_control(control)
        self._feedback_acquire()
        try:
            self._feedback_control(control)
            key = receipt_id, note_hash
            current = self.feedback_records.get(key)
            if (
                current is None
                or current.feedback_id != feedback_id
                or current.status != "pending"
                or current.ttl_epoch <= _epoch(now)
            ):
                return False
            self.feedback_records[key] = current.model_copy(update={"status": "queued"})
            return True
        finally:
            self._feedback_lock.release()

    async def question_budget_remaining(self, question_id: UUID) -> int | None:
        async with self._lock:
            state = self.budgets.get(question_id)
            if state is None:
                return None
            return state.budget.remaining_tokens

    async def daily_judgment_blocked(
        self,
        *,
        owner_key: str,
        now: datetime,
        owner_daily_limit: int,
        service_daily_limit: int,
    ) -> bool:
        async with self._lock:
            day = utc_day_start_epoch(now)
            owner_used = self._daily_tokens.get((f"owner:{owner_key}", day), 0)
            service_used = self._daily_tokens.get(("service", day), 0)
            return owner_used >= owner_daily_limit or service_used >= service_daily_limit

    async def daily_cannot_reserve(
        self,
        *,
        owner_key: str,
        tokens: int,
        now: datetime,
        owner_daily_limit: int,
        service_daily_limit: int,
    ) -> bool:
        async with self._lock:
            day = utc_day_start_epoch(now)
            owner_used = self._daily_tokens.get((f"owner:{owner_key}", day), 0)
            service_used = self._daily_tokens.get(("service", day), 0)
            return (
                owner_used + tokens > owner_daily_limit
                or service_used + tokens > service_daily_limit
            )

    def _claim_daily_tokens(
        self,
        owner_key: str,
        tokens: int,
        now: datetime,
        owner_daily_limit: int,
        service_daily_limit: int,
    ) -> None:
        day = utc_day_start_epoch(now)
        owner_keyed = (f"owner:{owner_key}", day)
        service_keyed = ("service", day)
        owner_used = self._daily_tokens.get(owner_keyed, 0)
        service_used = self._daily_tokens.get(service_keyed, 0)
        if owner_used + tokens > owner_daily_limit or service_used + tokens > service_daily_limit:
            raise _conflict(ErrorCode.BUDGET_EXCEEDED, "Daily token budget is exhausted.")
        self._daily_tokens[owner_keyed] = owner_used + tokens
        self._daily_tokens[service_keyed] = service_used + tokens

    def _refund_daily_tokens(self, owner_key: str, refund: int, day_epoch: int) -> None:
        if refund <= 0:
            return
        owner_keyed = (f"owner:{owner_key}", day_epoch)
        service_keyed = ("service", day_epoch)
        self._daily_tokens[owner_keyed] = max(0, self._daily_tokens.get(owner_keyed, 0) - refund)
        self._daily_tokens[service_keyed] = max(
            0, self._daily_tokens.get(service_keyed, 0) - refund
        )

    async def load(
        self,
        followup_id: UUID,
        *,
        owner_key: SHA256,
        environment_id: ContentId,
        revision: int,
        policy_hash: PolicyHash,
        content_sha: GitSHA40,
        now: datetime,
    ) -> FollowupRecord:
        return await self.load_plan(
            followup_id,
            owner_key=owner_key,
            environment_id=environment_id,
            revision=revision,
            policy_hash=policy_hash,
            content_sha=content_sha,
            now=now,
        )

    async def acquire(
        self,
        *,
        owner_key: SHA256,
        environment_id: str,
        question_id: UUID,
        holder_id: UUID,
        now: datetime,
    ) -> Lease:
        return await self.acquire_lease(
            owner_key=owner_key,
            environment_id=environment_id,
            question_id=question_id,
            holder_id=holder_id,
            now=now,
        )

    async def renew(self, lease: Lease, *, now: datetime) -> Lease:
        return await self.renew_lease(lease, now=now)

    async def release(self, lease: Lease) -> None:
        await self.release_lease(lease)

    async def load_plan(
        self,
        followup_id: UUID,
        *,
        owner_key: SHA256,
        environment_id: ContentId,
        revision: int,
        policy_hash: PolicyHash,
        content_sha: GitSHA40,
        now: datetime,
    ) -> FollowupRecord:
        async with self._lock:
            record = self.plans.get(followup_id)
            if (
                record is None
                or record.owner_key != owner_key
                or record.environment_id != environment_id
                or _epoch(record.expires_at) <= _epoch(now)
            ):
                raise _conflict(ErrorCode.FOLLOWUP_EXPIRED, "Follow-up is unavailable.")
            if revision != record.revision:
                raise _conflict(
                    ErrorCode.FOLLOWUP_CONFLICT, "Follow-up changed; ask a new question."
                )
            if record.plan.policy_hash != policy_hash:
                raise _conflict(
                    ErrorCode.POLICY_CHANGED, "Authorization changed; ask a new question."
                )
            if record.plan.content_sha != content_sha:
                if self._metrics is not None:
                    emit_content_provenance_failure(self._metrics)
                raise _conflict(ErrorCode.CONTENT_CHANGED, "Content changed; ask a new question.")
            return record

    async def acquire_lease(
        self,
        *,
        owner_key: str,
        environment_id: str,
        question_id: UUID,
        holder_id: UUID,
        now: datetime,
    ) -> Lease:
        key = owner_key, environment_id
        async with self._lock:
            row = self.leases.get(key)
            epoch = _epoch(now)
            if row and row.active and _epoch(row.active.expires_at) > epoch:
                raise _conflict(ErrorCode.BUSY, "Another request is active.")
            if row is None:
                row = _LeaseFence(lease_id=uuid4(), fence=1)
                self.leases[key] = row
            else:
                row.lease_id = uuid4()
                row.fence += 1
            lease = Lease(
                lease_id=row.lease_id,
                question_id=question_id,
                owner_key=owner_key,
                environment_id=environment_id,
                holder_id=holder_id,
                fence=row.fence,
                expires_at=now + timedelta(seconds=self._lease_seconds),
                last_renewed_at=now,
            )
            row.active = lease
            return lease

    async def renew_lease(self, lease: Lease, *, now: datetime) -> Lease:
        async with self._lock:
            row = self.leases.get((lease.owner_key, lease.environment_id))
            if not self._same_live(row, lease, now):
                raise _conflict(ErrorCode.LEASE_LOST, "Request lease was lost.")
            updated = lease.model_copy(
                update={
                    "expires_at": now + timedelta(seconds=self._lease_seconds),
                    "last_renewed_at": now,
                }
            )
            if row is None:
                raise _conflict(ErrorCode.LEASE_LOST, "Request lease was lost.")
            row.active = updated
            return updated

    async def release_lease(self, lease: Lease) -> None:
        async with self._lock:
            row = self.leases.get((lease.owner_key, lease.environment_id))
            if row and row.active and self._same_identity(row.active, lease):
                row.active = None

    async def open_budget(
        self,
        *,
        question_id: UUID,
        owner_key: str,
        environment_id: str,
        token_limit: int,
        expires_at: datetime,
        lease: Lease,
        operation_id: UUID,
        lease_supplier: Callable[[], Lease] | None = None,
    ) -> None:
        async with self._lock:
            lease = lease_supplier() if lease_supplier is not None else lease
            self._assert_live(lease, lease.last_renewed_at)
            op = self.operations.get(operation_id)
            digest = _hash({"question_id": question_id, "token_limit": token_limit})
            if op:
                if op.input_hash != digest:
                    raise _conflict(
                        ErrorCode.IDEMPOTENCY_CONFLICT, "Operation identity was reused."
                    )
                return
            if question_id in self.budgets:
                raise _conflict(ErrorCode.IDEMPOTENCY_CONFLICT, "Budget already exists.")
            budget = QuestionBudget(
                question_id=question_id,
                token_limit=token_limit,
                reserved_tokens=0,
                charged_tokens=0,
                remaining_tokens=token_limit,
                version=1,
                overflow_tokens=0,
                state="open",
                owner_key=owner_key,
                environment_id=environment_id,
                created_at=lease.last_renewed_at,
                expires_at=expires_at,
            )
            self.budgets[question_id] = _BudgetState(budget, lease)
            self.operations[operation_id] = OperationRecord(
                operation_id=operation_id,
                kind="budget_open",
                input_hash=digest,
                state="completed",
                terminal_result_hash=_hash(budget),
                expires_at=expires_at,
            )

    async def open(
        self,
        *,
        question_id: UUID,
        owner_key: str,
        environment_id: str,
        token_limit: int,
        expires_at: datetime,
        lease: Lease,
        operation_id: UUID,
        lease_supplier: Callable[[], Lease] | None = None,
    ) -> None:
        await self.open_budget(
            question_id=question_id,
            owner_key=owner_key,
            environment_id=environment_id,
            token_limit=token_limit,
            expires_at=expires_at,
            lease=lease,
            operation_id=operation_id,
            lease_supplier=lease_supplier,
        )

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
        lease_supplier: Callable[[], Lease] | None = None,
    ) -> Reservation:
        if tokens <= 0:
            raise ValueError("reservation must be positive")
        async with self._lock:
            lease = lease_supplier() if lease_supplier is not None else lease
            self._assert_live(lease, now)
            digest = _hash({"question_id": question_id, "topic_id": topic_id, "tokens": tokens})
            prior = self.operations.get(operation_id)
            if prior:
                if prior.input_hash != digest:
                    raise _conflict(
                        ErrorCode.IDEMPOTENCY_CONFLICT, "Operation identity was reused."
                    )
                for reservation in self.reservations.values():
                    if reservation.operation_id == operation_id:
                        return reservation
                raise _conflict(
                    ErrorCode.DEPENDENCY_UNAVAILABLE, "Reservation operation is incomplete."
                )
            state = self.budgets.get(question_id)
            if state is None:
                raise _conflict(ErrorCode.BUDGET_EXCEEDED, "Question budget is unavailable.")
            budget = state.budget
            self._assert_budget_lease(state, lease, now)
            if budget.state != "open" or budget.remaining_tokens < tokens:
                raise _conflict(ErrorCode.BUDGET_EXCEEDED, "Question budget is exhausted.")
            charge_day = utc_day_start_epoch(now)
            self._claim_daily_tokens(
                lease.owner_key,
                tokens,
                now,
                owner_daily_limit,
                service_daily_limit,
            )
            reservation = Reservation(
                reservation_id=uuid4(),
                operation_id=operation_id,
                question_id=question_id,
                topic_id=topic_id,
                owner_key=lease.owner_key,
                environment_id=lease.environment_id,
                lease_id=lease.lease_id,
                holder_id=lease.holder_id,
                fence=lease.fence,
                reserved_tokens=tokens,
                state="reserved",
                created_at=now,
                hard_deadline_at=lease.last_renewed_at + timedelta(seconds=120),
                recover_after=max(lease.last_renewed_at + timedelta(seconds=120), lease.expires_at)
                + timedelta(seconds=35),
                daily_token_day_epoch=charge_day,
                version=1,
            )
            state.budget = budget.model_copy(
                update={
                    "reserved_tokens": budget.reserved_tokens + tokens,
                    "remaining_tokens": budget.remaining_tokens - tokens,
                    "version": budget.version + 1,
                }
            )
            self.reservations[reservation.reservation_id] = reservation
            ticket = self._ticket(reservation)
            self.tickets[(ticket.bucket, question_id, reservation.reservation_id)] = ticket
            self.operations[operation_id] = OperationRecord(
                operation_id=operation_id,
                kind="reserve",
                input_hash=digest,
                state="completed",
                terminal_result_hash=_hash(reservation),
                expires_at=reservation.recover_after + timedelta(hours=24),
            )
            return reservation

    async def mark_started(
        self,
        reservation: Reservation,
        *,
        lease: Lease,
        operation_id: UUID,
        now: datetime,
        lease_supplier: Callable[[], Lease] | None = None,
    ) -> Reservation:
        async with self._lock:
            lease = lease_supplier() if lease_supplier is not None else lease
            self._assert_live(lease, now)
            current = self.reservations.get(reservation.reservation_id)
            digest = _hash({"reservation_id": reservation.reservation_id, "fence": lease.fence})
            prior = self.operations.get(operation_id)
            if prior:
                if prior.input_hash != digest:
                    raise _conflict(
                        ErrorCode.IDEMPOTENCY_CONFLICT, "Operation identity was reused."
                    )
                if current is not None and current.state == "started":
                    return current
            if (
                current is None
                or current.state != "reserved"
                or not self._reservation_fence(current, lease)
            ):
                raise _conflict(ErrorCode.LEASE_LOST, "Reservation lease was lost.")
            started = current.model_copy(
                update={"state": "started", "started_at": now, "version": current.version + 1}
            )
            self.reservations[current.reservation_id] = started
            old_ticket = self._ticket(current)
            self.tickets.pop((old_ticket.bucket, current.question_id, current.reservation_id), None)
            ticket = self._ticket(started)
            self.tickets[(ticket.bucket, started.question_id, started.reservation_id)] = ticket
            self.operations[operation_id] = OperationRecord(
                operation_id=operation_id,
                kind="mark_started",
                input_hash=digest,
                state="completed",
                terminal_result_hash=_hash(started),
                expires_at=started.recover_after + timedelta(hours=24),
            )
            return started

    async def settle(
        self,
        reservation: Reservation,
        *,
        charged_tokens: int | None,
        lease: Lease,
        operation_id: UUID,
        now: datetime,
        release: bool = False,
        lease_supplier: Callable[[], Lease] | None = None,
    ) -> None:
        async with self._lock:
            lease = lease_supplier() if lease_supplier is not None else lease
            self._assert_live(lease, now)
            current = self.reservations.get(reservation.reservation_id)
            if current is None:
                raise _conflict(ErrorCode.LEASE_LOST, "Reservation is unavailable.")
            if current.state in {"settled", "released", "unknown_charged"}:
                if release or current.state == "released":
                    expected = 0
                elif charged_tokens is not None:
                    expected = charged_tokens
                elif current.state == "unknown_charged":
                    expected = current.reserved_tokens
                else:
                    expected = current.charged_tokens
                if current.charged_tokens != expected:
                    raise _conflict(
                        ErrorCode.IDEMPOTENCY_CONFLICT,
                        "Reservation was already settled with different usage.",
                    )
                return
            if current.state != "started" or not self._reservation_fence(current, lease):
                raise _conflict(ErrorCode.LEASE_LOST, "Reservation lease was lost.")
            self._terminalize(current, charged_tokens, now, operation_id, released=release)

    async def reconcile(
        self, *, now: datetime, bucket: int, after: str | None = None, page_size: int = 100
    ) -> RecoveryPage:
        if not 0 <= bucket < 128 or not 1 <= page_size <= 1000:
            raise ValueError("invalid recovery page")
        async with self._lock:
            rows = sorted(
                (ticket for key, ticket in self.tickets.items() if key[0] == bucket),
                key=lambda item: str(item.reservation_id),
            )
            if after:
                rows = [ticket for ticket in rows if str(ticket.reservation_id) > after]
            page = rows[:page_size]
            terminalized = 0
            for ticket in page:
                reservation = self.reservations.get(ticket.reservation_id)
                if reservation is None or reservation.state in {
                    "settled",
                    "released",
                    "unknown_charged",
                }:
                    self.tickets.pop((bucket, ticket.question_id, ticket.reservation_id), None)
                    continue
                if _epoch(ticket.due_at) > _epoch(now):
                    continue
                lease_row = self.leases.get((reservation.owner_key, reservation.environment_id))
                active = lease_row.active if lease_row else None
                if (
                    active
                    and self._reservation_fence(reservation, active)
                    and _epoch(active.expires_at) > _epoch(now)
                ):
                    continue
                if reservation.state == "reserved":
                    self._terminalize(reservation, 0, now, uuid4(), released=True)
                else:
                    self._terminalize(reservation, None, now, uuid4())
                terminalized += 1
            next_after = str(page[-1].reservation_id) if len(rows) > len(page) and page else None
            return RecoveryPage(
                after=next_after, examined=len(page), terminalized=terminalized, errors=[]
            )

    async def due_recovery_gauges(self, now: datetime) -> tuple[int, float]:
        async with self._lock:
            backlog = 0
            max_lag = 0.0
            now_epoch = _epoch(now)
            for ticket in self.tickets.values():
                due = _epoch(ticket.due_at)
                if due > now_epoch:
                    continue
                reservation = self.reservations.get(ticket.reservation_id)
                if reservation is None or reservation.state in {
                    "settled",
                    "released",
                    "unknown_charged",
                }:
                    continue
                backlog += 1
                max_lag = max(max_lag, float(now_epoch - due))
            return backlog, max_lag

    async def publish_recovery_gauges(self, now: datetime) -> None:
        backlog, max_lag = await self.due_recovery_gauges(now)
        if self._metrics is None:
            return
        emit_recovery_backlog(self._metrics, backlog)
        emit_recovery_lag_seconds(self._metrics, max_lag)

    async def commit_completion(
        self,
        command: CompletionCommand,
        *,
        lease: Lease,
        now: datetime,
        operation_id: UUID,
        lease_supplier: Callable[[], Lease] | None = None,
    ) -> CompletionReceipt:
        async with self._lock:
            lease = lease_supplier() if lease_supplier is not None else lease
            input_hash = _hash(command)
            operation = self.operations.get(operation_id)
            if operation is not None:
                if operation.input_hash != input_hash:
                    raise _conflict(
                        ErrorCode.IDEMPOTENCY_CONFLICT, "Operation identity was reused."
                    )
                result = self.completions.get(command.question_id)
                if result is None or operation.terminal_result_hash != _hash(result):
                    raise _conflict(
                        ErrorCode.DEPENDENCY_UNAVAILABLE, "Completion result is unavailable."
                    )
                return result
            existing = self.completions.get(command.question_id)
            if existing:
                # A previously committed answer may be redelivered only by retrying
                # its original durable operation ID (handled above). A new operation
                # must still prove the current lease, even when its answer hash matches.
                self._assert_live(lease, now)
                raise _conflict(ErrorCode.LEASE_LOST, "Request lease was lost.")
            self._assert_live(lease, now)
            question = self.questions.get(command.question_id)
            if (
                question is None
                or question.state != "active"
                or question.owner_key != command.owner_key
                or question.environment_id != command.environment_id
                or question.lease_id != lease.lease_id
                or question.holder_id != lease.holder_id
                or question.fence != lease.fence
            ):
                raise _conflict(ErrorCode.LEASE_LOST, "Request lease was lost.")
            if command.idempotency is not None:
                entry = command.idempotency
                stored = self.idempotency.get((entry.owner_key, entry.environment_id, entry.key))
                if (
                    entry.owner_key != command.owner_key
                    or entry.environment_id != command.environment_id
                    or entry.question_id != command.question_id
                    or stored is None
                    or stored.status != "active"
                    or stored.request_hash != entry.request_hash
                    or stored.question_id != command.question_id
                ):
                    raise _conflict(ErrorCode.LEASE_LOST, "Request lease was lost.")
            if command.followup:
                record = command.followup
                if (
                    record.owner_key != command.owner_key
                    or record.environment_id != command.environment_id
                    or record.plan.question_id != command.question_id
                    or record.plan.owner_key != command.owner_key
                    or record.plan.environment_id != command.environment_id
                    or _epoch(record.expires_at) <= _epoch(now)
                ):
                    raise _conflict(ErrorCode.INVALID_CONTINUATION, "Follow-up binding is invalid.")
                if record.followup_id in self.plans:
                    raise _conflict(
                        ErrorCode.IDEMPOTENCY_CONFLICT, "Follow-up identity already exists."
                    )
                self.plans[record.followup_id] = record
            completion_id = uuid4()
            receipt = CompletionReceipt(
                completion_id=completion_id,
                question_id=command.question_id,
                committed_at=now,
                followup_id=command.followup.followup_id if command.followup else None,
                followup_revision=command.followup.revision if command.followup else None,
                answer_metadata_sha256=command.metadata_sha256,
            )
            self.completions[command.question_id] = receipt
            self.operations[operation_id] = OperationRecord(
                operation_id=operation_id,
                kind="complete",
                input_hash=input_hash,
                terminal_result_hash=_hash(receipt),
                state="completed",
                expires_at=now + timedelta(hours=24),
            )
            self.questions[question.question_id] = question.model_copy(
                update={
                    "state": "completed",
                    "completion_id": completion_id,
                    "answer_status": command.answer_status,
                }
            )
            for key, entry in list(self.idempotency.items()):
                if entry.question_id == question.question_id and entry.status == "active":
                    self.idempotency[key] = entry.model_copy(
                        update={"status": "completed", "completion_id": completion_id}
                    )
            return receipt

    async def commit(
        self,
        command: CompletionCommand,
        *,
        lease: Lease,
        now: datetime,
        operation_id: UUID,
        lease_supplier: Callable[[], Lease] | None = None,
    ) -> CompletionReceipt:
        return await self.commit_completion(
            command,
            lease=lease,
            now=now,
            operation_id=operation_id,
            lease_supplier=lease_supplier,
        )

    async def acquire_admission(
        self,
        owner_key: str,
        environment_id: str,
        operation: str,
        question_id: UUID,
        now: datetime,
        *,
        capacity: int = 1,
        ttl_seconds: int = 60,
    ) -> AdmissionGrant:
        key = owner_key, environment_id, operation
        async with self._lock:
            rows = self.admissions.setdefault(key, {})
            now_epoch = _epoch(now)
            for slot, (_grant, expiry) in list(rows.items()):
                if expiry <= now_epoch:
                    del rows[slot]
            if len(rows) >= capacity:
                raise _conflict(ErrorCode.BUSY, "Service capacity is busy.")
            fence = self._admission_fences.get(key, 0) + 1
            self._admission_fences[key] = fence
            holder = uuid4()
            slot_id = f"SLOT#{len(rows):04d}"
            grant = AdmissionGrant(
                holder_id=holder,
                slot_ids=(slot_id,),
                expires_at=now + timedelta(seconds=ttl_seconds),
                fence=fence,
            )
            rows[slot_id] = (grant, _epoch(grant.expires_at))
            return grant

    async def release_admission(
        self, owner_key: str, environment_id: str, operation: str, grant: AdmissionGrant
    ) -> None:
        key = owner_key, environment_id, operation
        async with self._lock:
            rows = self.admissions.get(key, {})
            for slot_id in grant.slot_ids:
                current = rows.get(slot_id)
                if (
                    current
                    and current[0].holder_id == grant.holder_id
                    and current[0].fence == grant.fence
                ):
                    del rows[slot_id]

    async def create_question(
        self, question: QuestionRecord, idem: IdempotencyRecord | None
    ) -> None:
        async with self._lock:
            if question.question_id in self.questions:
                raise _conflict(ErrorCode.IDEMPOTENCY_CONFLICT, "Question identity already exists.")
            key = (idem.owner_key, idem.environment_id, idem.key) if idem else None
            if (
                key
                and key in self.idempotency
                and _epoch(self.idempotency[key].expires_at) > _epoch(question.created_at)
            ):
                prior = self.idempotency[key]
                code = (
                    ErrorCode.QUESTION_ACTIVE
                    if prior.status == "active"
                    else ErrorCode.REQUEST_COMPLETED
                    if prior.status == "completed"
                    else ErrorCode.REQUEST_ABANDONED
                )
                raise _conflict(code, "This request key was already used.")
            self.questions[question.question_id] = question
            if key and idem is not None:
                self.idempotency[key] = idem

    async def admit_question(
        self, question: QuestionRecord, idem: IdempotencyRecord | None, *, now: datetime
    ) -> Lease:
        """Atomically claim the owner/site lease and persist request identity."""
        key = (question.owner_key, question.environment_id)
        async with self._lock:
            active = self.leases.get(key)
            if active and active.active and _epoch(active.active.expires_at) > _epoch(now):
                raise _conflict(ErrorCode.BUSY, "Another request is active.")
            if question.question_id in self.questions:
                raise _conflict(ErrorCode.IDEMPOTENCY_CONFLICT, "Question identity already exists.")
            idem_key = (idem.owner_key, idem.environment_id, idem.key) if idem else None
            if idem_key:
                existing = self.idempotency.get(idem_key)
                if existing and _epoch(existing.expires_at) > _epoch(now):
                    code = {
                        "active": ErrorCode.QUESTION_ACTIVE,
                        "completed": ErrorCode.REQUEST_COMPLETED,
                        "abandoned": ErrorCode.REQUEST_ABANDONED,
                    }[existing.status]
                    raise _conflict(code, "This request key was already used.")
            fence = (active.fence + 1) if active else 1
            lease = Lease(
                lease_id=question.lease_id,
                question_id=question.question_id,
                owner_key=question.owner_key,
                environment_id=question.environment_id,
                holder_id=question.holder_id,
                fence=fence,
                expires_at=now + timedelta(seconds=self._lease_seconds),
                last_renewed_at=now,
            )
            if question.fence != fence:
                raise _conflict(ErrorCode.LEASE_LOST, "Question lease fence is stale.")
            self.leases[key] = _LeaseFence(lease_id=lease.lease_id, fence=fence, active=lease)
            self.questions[question.question_id] = question
            if idem_key and idem is not None:
                self.idempotency[idem_key] = idem
            return lease

    async def begin_request(
        self,
        *,
        owner_key: str,
        environment_id: str,
        question_id: UUID,
        request_hash: str,
        idempotency_key: UUID | None,
        now: datetime,
    ) -> Lease:
        async with self._lock:
            key = (owner_key, environment_id)
            prior_lease = self.leases.get(key)
            if (
                prior_lease
                and prior_lease.active
                and _epoch(prior_lease.active.expires_at) > _epoch(now)
            ):
                raise _conflict(ErrorCode.BUSY, "Another request is active.")
            idem_key = (owner_key, environment_id, idempotency_key) if idempotency_key else None
            if idem_key:
                previous = self.idempotency.get(idem_key)
                if previous and _epoch(previous.expires_at) > _epoch(now):
                    if previous.request_hash != request_hash:
                        code = ErrorCode.IDEMPOTENCY_CONFLICT
                    else:
                        code = {
                            "active": ErrorCode.QUESTION_ACTIVE,
                            "completed": ErrorCode.REQUEST_COMPLETED,
                            "abandoned": ErrorCode.REQUEST_ABANDONED,
                        }[previous.status]
                    raise _conflict(code, "This request key was already used.")
            fence = prior_lease.fence + 1 if prior_lease else 1
            lease = Lease(
                lease_id=uuid4(),
                question_id=question_id,
                owner_key=owner_key,
                environment_id=environment_id,
                holder_id=uuid4(),
                fence=fence,
                expires_at=now + timedelta(seconds=self._lease_seconds),
                last_renewed_at=now,
            )
            question = QuestionRecord(
                question_id=question_id,
                owner_key=owner_key,
                environment_id=environment_id,
                lease_id=lease.lease_id,
                holder_id=lease.holder_id,
                fence=fence,
                request_hash=request_hash,
                state="active",
                created_at=now,
                expires_at=now + timedelta(hours=24),
            )
            idem = (
                IdempotencyRecord(
                    owner_key=owner_key,
                    environment_id=environment_id,
                    key=idempotency_key,
                    request_hash=request_hash,
                    question_id=question_id,
                    status="active",
                    expires_at=now + timedelta(minutes=10),
                )
                if idempotency_key
                else None
            )
            self.leases[key] = _LeaseFence(lease.lease_id, fence, lease)
            self.questions[question_id] = question
            if idem_key and idem is not None:
                self.idempotency[idem_key] = idem
            return lease

    def _terminalize(
        self,
        current: Reservation,
        charged: int | None,
        now: datetime,
        operation_id: UUID,
        *,
        released: bool = False,
    ) -> None:
        state = self.budgets.get(current.question_id)
        if state is None:
            return
        budget = state.budget
        actual = 0 if released else current.reserved_tokens if charged is None else charged
        overflow = max(0, actual - current.reserved_tokens)
        refund = max(0, current.reserved_tokens - actual)
        charge_day = current.daily_token_day_epoch or utc_day_start_epoch(current.created_at)
        self._refund_daily_tokens(current.owner_key, refund, charge_day)
        terminal_state = (
            "released" if released else "unknown_charged" if charged is None else "settled"
        )
        state.budget = budget.model_copy(
            update={
                "reserved_tokens": max(0, budget.reserved_tokens - current.reserved_tokens),
                "charged_tokens": budget.charged_tokens + actual,
                "remaining_tokens": 0 if overflow else budget.remaining_tokens + refund,
                "overflow_tokens": budget.overflow_tokens + overflow,
                "state": "closed" if overflow else budget.state,
                "version": budget.version + 1,
            }
        )
        updated = current.model_copy(
            update={
                "charged_tokens": actual,
                "state": terminal_state,
                "version": current.version + 1,
            }
        )
        self.reservations[current.reservation_id] = updated
        self.tickets.pop(
            (self._ticket(current).bucket, current.question_id, current.reservation_id), None
        )
        self.operations[operation_id] = OperationRecord(
            operation_id=operation_id,
            kind="settle",
            input_hash=_hash({"reservation_id": current.reservation_id, "charged": charged}),
            state="completed",
            terminal_result_hash=_hash(updated),
            expires_at=now + timedelta(hours=24),
        )

    @staticmethod
    def _ticket(reservation: Reservation) -> RecoveryTicket:
        due = _epoch(reservation.recover_after)
        return RecoveryTicket(
            bucket=(due // 30) % 128,
            due_at=reservation.recover_after,
            question_id=reservation.question_id,
            reservation_id=reservation.reservation_id,
            version=reservation.version,
        )

    @staticmethod
    def _same_identity(a: Lease, b: Lease) -> bool:
        return (a.lease_id, a.holder_id, a.fence, a.question_id, a.owner_key, a.environment_id) == (
            b.lease_id,
            b.holder_id,
            b.fence,
            b.question_id,
            b.owner_key,
            b.environment_id,
        )

    def _same_live(self, row: _LeaseFence | None, lease: Lease, now: datetime) -> bool:
        return bool(
            row
            and row.active
            and row.lease_id == lease.lease_id
            and row.fence == lease.fence
            and self._same_identity(row.active, lease)
            and _epoch(row.active.expires_at) > _epoch(now)
        )

    def _assert_live(self, lease: Lease, now: datetime) -> None:
        row = self.leases.get((lease.owner_key, lease.environment_id))
        if not self._same_live(row, lease, now):
            raise _conflict(ErrorCode.LEASE_LOST, "Request lease was lost.")

    def _assert_budget_lease(self, state: _BudgetState, lease: Lease, now: datetime) -> None:
        if not self._same_identity(state.lease, lease):
            raise _conflict(ErrorCode.LEASE_LOST, "Budget belongs to another lease.")
        self._assert_live(lease, now)

    @staticmethod
    def _reservation_fence(reservation: Reservation, lease: Lease) -> bool:
        return (
            reservation.lease_id,
            reservation.holder_id,
            reservation.fence,
            reservation.owner_key,
            reservation.environment_id,
            reservation.question_id,
        ) == (
            lease.lease_id,
            lease.holder_id,
            lease.fence,
            lease.owner_key,
            lease.environment_id,
            lease.question_id,
        )
