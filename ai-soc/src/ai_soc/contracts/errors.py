"""Stable public error construction and sanitized transport mapping."""

from __future__ import annotations

from uuid import UUID

from .models import DomainError, ErrorCode

_STATUS: dict[ErrorCode, int] = {
    ErrorCode.BAD_REQUEST: 400,
    ErrorCode.FEEDBACK_INVALID: 400,
    ErrorCode.INVALID_CONTINUATION: 422,
    ErrorCode.REQUEST_TOO_LARGE: 413,
    ErrorCode.REQUEST_COMPLEXITY: 422,
    ErrorCode.UNAUTHENTICATED: 401,
    ErrorCode.AUTH_REQUIRED: 401,
    ErrorCode.AUTH_INVALID: 401,
    ErrorCode.AUTH_EXPIRED: 401,
    ErrorCode.FORBIDDEN: 403,
    ErrorCode.SITE_DENIED: 403,
    ErrorCode.ORIGIN_DENIED: 403,
    ErrorCode.CSRF_DENIED: 403,
    ErrorCode.SCOPE_DENIED: 403,
    ErrorCode.FOLLOWUP_EXPIRED: 410,
    ErrorCode.CURSOR_EXPIRED: 410,
    ErrorCode.FOLLOWUP_CONFLICT: 409,
    ErrorCode.QUESTION_ACTIVE: 409,
    ErrorCode.IDEMPOTENCY_CONFLICT: 409,
    ErrorCode.POLICY_CHANGED: 409,
    ErrorCode.CONTENT_CHANGED: 409,
    ErrorCode.BUSY: 429,
    ErrorCode.RATE_LIMITED: 429,
    ErrorCode.CAPACITY_LIMIT: 429,
    ErrorCode.INDEXER_UNAVAILABLE: 503,
    ErrorCode.UNSUPPORTED_MODEL: 422,
    ErrorCode.UNSUPPORTED_EFFORT: 422,
    ErrorCode.INVALID_WINDOW: 422,
    ErrorCode.INVALID_FILTER: 422,
    ErrorCode.INVALID_SCHEMA: 422,
    ErrorCode.DEPENDENCY_UNAVAILABLE: 503,
    ErrorCode.SERVICE_DISABLED: 503,
    ErrorCode.CONFIG_INVALID: 503,
    ErrorCode.REQUEST_COMPLETED: 409,
    ErrorCode.REQUEST_ABANDONED: 409,
    ErrorCode.AUDIT_UNAVAILABLE: 503,
    ErrorCode.LEASE_LOST: 503,
    ErrorCode.FEEDBACK_UNAVAILABLE: 503,
    ErrorCode.INTERNAL: 500,
}


def public_error(
    code: ErrorCode,
    message: str,
    *,
    trace_id: str,
    retryable: bool = False,
    question_id: UUID | None = None,
    stage: str | None = None,
    limit: int | None = None,
) -> DomainError:
    """Build an allowlisted error envelope; backend text must never be passed here."""
    details: dict[str, str | int | list[str]] = {}
    if question_id is not None:
        details["question_id"] = str(question_id)
    if stage is not None:
        details["stage"] = stage
    if limit is not None:
        details["limit"] = limit
    return DomainError(
        code=code, message=message, retryable=retryable, trace_id=trace_id, details=details
    )


def status_for(code: ErrorCode) -> int:
    return _STATUS.get(code, 422)


def error_for_status(status: int) -> ErrorCode:
    for code, candidate in _STATUS.items():
        if candidate == status:
            return code
    return ErrorCode.INTERNAL if status >= 500 else ErrorCode.BAD_REQUEST
