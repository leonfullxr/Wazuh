"""In-memory admission stores for adapter unit tests."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Literal, overload
from uuid import UUID, uuid4

from ai_soc.contracts.models import (
    ContentId,
    EmbeddingGrant,
    ModelCountGrant,
    StageCapacityRejection,
)


class FakeStageAdmissionStore:
    def __init__(self) -> None:
        self.grants: list[ModelCountGrant | EmbeddingGrant] = []
        self.released: list[ModelCountGrant | EmbeddingGrant] = []
        self.requests: list[tuple[ContentId, UUID, UUID, str]] = []
        self.reject = False

    @overload
    async def acquire(
        self,
        *,
        environment_id: ContentId,
        question_id: UUID,
        operation_id: UUID,
        call: Literal["count", "converse"],
        now: datetime,
    ) -> ModelCountGrant | StageCapacityRejection: ...

    @overload
    async def acquire(
        self,
        *,
        environment_id: ContentId,
        question_id: UUID,
        operation_id: UUID,
        now: datetime,
    ) -> EmbeddingGrant | StageCapacityRejection: ...

    async def acquire(
        self,
        *,
        environment_id: ContentId,
        question_id: UUID,
        operation_id: UUID,
        now: datetime,
        call: Literal["count", "converse"] | None = None,
    ) -> ModelCountGrant | EmbeddingGrant | StageCapacityRejection:
        self.requests.append((environment_id, question_id, operation_id, call or "embedding"))
        actual_call = call or "embedding"
        if self.reject:
            return StageCapacityRejection(
                question_id=question_id, operation_id=operation_id, call=actual_call
            )
        acquired_at = now
        duration = 10 if actual_call == "embedding" else 5 if actual_call == "count" else 30
        hard_deadline = acquired_at + timedelta(seconds=duration)
        if call is None:
            grant: ModelCountGrant | EmbeddingGrant = EmbeddingGrant(
                question_id=question_id,
                environment_id=environment_id,
                operation_id=operation_id,
                holder_id=uuid4(),
                fence=1,
                acquired_at=acquired_at,
                lease_expires_at=acquired_at + timedelta(seconds=1),
                hard_deadline_at=hard_deadline,
                recover_after=hard_deadline + timedelta(seconds=35),
            )
        else:
            grant = ModelCountGrant(
                call=call,
                question_id=question_id,
                environment_id=environment_id,
                operation_id=operation_id,
                holder_id=uuid4(),
                service_slot_id="service-slot",
                site_slot_id="site-slot",
                fence=1,
                acquired_at=acquired_at,
                lease_expires_at=acquired_at + timedelta(seconds=1),
                hard_deadline_at=hard_deadline,
                recover_after=hard_deadline + timedelta(seconds=35),
            )
        self.grants.append(grant)
        return grant

    async def release(self, grant: ModelCountGrant | EmbeddingGrant) -> None:
        self.released.append(grant)
