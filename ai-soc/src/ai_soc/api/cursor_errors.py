"""Map cursor domain failures to public HTTP errors."""

from __future__ import annotations

from uuid import uuid4

from ai_soc.application.errors import ServiceFailure
from ai_soc.contracts.errors import public_error
from ai_soc.contracts.models import ErrorCode
from ai_soc.query.cursors import CursorError

_MESSAGES: dict[ErrorCode, str] = {
    ErrorCode.BAD_REQUEST: "The cursor is malformed.",
    ErrorCode.CURSOR_EXPIRED: "The cursor has expired.",
    ErrorCode.SITE_DENIED: "Access to this site is denied.",
    ErrorCode.DEPENDENCY_UNAVAILABLE: "A dependency is temporarily unavailable.",
    ErrorCode.INDEXER_UNAVAILABLE: "The indexer is temporarily unavailable.",
    ErrorCode.CAPACITY_LIMIT: "The request reached its bounded dependency-call limit.",
    ErrorCode.AUTH_EXPIRED: "The session has expired.",
    ErrorCode.POLICY_CHANGED: "Site policy changed since this cursor was issued.",
    ErrorCode.CONTENT_CHANGED: "Content changed since this cursor was issued.",
}

_RETRYABLE = frozenset({ErrorCode.INDEXER_UNAVAILABLE, ErrorCode.DEPENDENCY_UNAVAILABLE})


def service_failure_from_cursor(error: CursorError) -> ServiceFailure:
    code = error.code
    message = _MESSAGES.get(code, "The request could not be completed.")
    return ServiceFailure(
        public_error(
            code,
            message,
            trace_id=uuid4().hex,
            retryable=code in _RETRYABLE,
        )
    )
