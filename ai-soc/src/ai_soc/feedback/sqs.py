"""Bounded SQS delivery for human reviewed feedback events."""

from __future__ import annotations

import asyncio
import json
from typing import Protocol
from uuid import UUID, uuid4

from ai_soc.application.errors import ServiceFailure
from ai_soc.contracts.errors import public_error
from ai_soc.contracts.models import CallKind, ErrorCode, ExecutionContext, FeedbackEvent


class SqsClient(Protocol):
    def send_message(self, **kwargs: object) -> dict[str, object]: ...


class SqsFeedbackSink:
    def __init__(
        self,
        client: SqsClient,
        queue_url: str,
        *,
        timeout_seconds: float = 5.0,
        max_concurrency: int = 8,
    ) -> None:
        if not queue_url.startswith("https://"):
            raise ValueError("feedback queue URL must use HTTPS")
        if not 0 < timeout_seconds <= 5:
            raise ValueError("feedback timeout must be between zero and five seconds")
        if not 1 <= max_concurrency <= 8:
            raise ValueError("feedback concurrency must be between one and eight")
        self._client = client
        self._queue_url = queue_url
        self._slots = asyncio.Semaphore(max_concurrency)
        self._timeout = timeout_seconds

    async def enqueue(self, event: FeedbackEvent, *, execution: ExecutionContext) -> UUID:
        execution.calls.claim(CallKind.feedback)
        if self._slots.locked():
            raise self._unavailable(execution)
        await self._slots.acquire()
        task = asyncio.create_task(
            asyncio.to_thread(
                self._client.send_message,
                QueueUrl=self._queue_url,
                MessageBody=json.dumps(
                    event.model_dump(mode="json"),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            )
        )
        release_deferred = False
        try:
            response = await asyncio.wait_for(asyncio.shield(task), timeout=self._timeout)
            if not isinstance(response.get("MessageId"), str):
                raise ValueError("queue acknowledgment missing")
            return event.feedback_id
        except TimeoutError:
            self._defer_release(task)
            release_deferred = True
            raise self._unavailable(execution) from None
        except asyncio.CancelledError:
            self._defer_release(task)
            release_deferred = True
            raise
        except Exception:
            raise self._unavailable(execution) from None
        finally:
            if not release_deferred:
                self._slots.release()

    def _unavailable(self, execution: ExecutionContext) -> ServiceFailure:
        return ServiceFailure(
            public_error(
                ErrorCode.FEEDBACK_UNAVAILABLE,
                "Feedback could not be queued. Please retry.",
                trace_id=uuid4().hex,
                retryable=True,
            )
        )

    def _defer_release(self, task: asyncio.Task[dict[str, object]]) -> None:
        def release(_: asyncio.Task[dict[str, object]]) -> None:
            try:
                task.exception()
            except BaseException:
                pass
            self._slots.release()

        task.add_done_callback(release)
