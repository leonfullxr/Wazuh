"""Shared strict authorization, error, and signed-cursor helpers for workspace APIs."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse
from pydantic import TypeAdapter

from ai_soc.contracts.models import AuthorizedSite, VerifiedPrincipal, Visibility
from ai_soc.identity.policy import SiteAuthorizationError
from ai_soc.workspace.api.models import ErrorResponse
from ai_soc.workspace.api.runtime import WorkspaceRuntime

ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    status: {"model": ErrorResponse} for status in (400, 401, 403, 404, 409, 422, 503)
}
_CURSOR_PAYLOAD: TypeAdapter[dict[str, object]] = TypeAdapter(dict[str, object])
_CURSOR_FILTERS: TypeAdapter[dict[str, object]] = TypeAdapter(dict[str, object])
_CURSOR_VALUES: TypeAdapter[list[object]] = TypeAdapter(list[object])

CURSOR_VALUES = _CURSOR_VALUES


class WorkspaceApiError(Exception):
    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        *,
        retryable: bool = False,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.status, self.code, self.message = status, code, message
        self.retryable, self.details = retryable, details


class WorkspaceJSONResponse(JSONResponse):
    def __init__(
        self,
        content: Any = None,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
        media_type: str | None = None,
        background: Any = None,
    ) -> None:
        response_headers = dict(headers or {})
        response_headers.setdefault("Cache-Control", "no-store")
        super().__init__(
            content=content,
            status_code=status_code,
            headers=response_headers,
            media_type=media_type,
            background=background,
        )


def authorize_site(
    runtime: WorkspaceRuntime, principal: VerifiedPrincipal, site_id: str
) -> AuthorizedSite:
    try:
        site = runtime.site_policy.authorize(principal, site_id)
    except SiteAuthorizationError:
        raise WorkspaceApiError(
            403, "WORKSPACE_DENIED", "Full site visibility is required"
        ) from None
    if site.visibility != Visibility.full:
        raise WorkspaceApiError(403, "WORKSPACE_DENIED", "Full site visibility is required")
    return site


def validate_query(
    request: Request, allowed: set[str], *, repeatable: set[str] | None = None
) -> None:
    keys = [key for key, _ in request.query_params.multi_items()]
    unsupported = sorted(set(keys) - allowed)
    duplicate = sorted(
        key for key in set(keys) if keys.count(key) > 1 and key not in (repeatable or set())
    )
    if unsupported or duplicate:
        field = unsupported[0] if unsupported else duplicate[0]
        raise WorkspaceApiError(
            422,
            "BAD_FILTER",
            "query contains an unsupported or repeated parameter",
            details={"field": field},
        )


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def cursor_encode(secret: bytes, payload: dict[str, object]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    mac = hmac.new(secret, raw, hashlib.sha256).digest()
    return b64(raw) + "." + b64(mac)


def cursor_decode(secret: bytes, token: str, now: datetime) -> dict[str, object]:
    try:
        encoded, signature = token.split(".", 1)
        raw, mac = unb64(encoded), unb64(signature)
        if not hmac.compare_digest(mac, hmac.new(secret, raw, hashlib.sha256).digest()):
            raise ValueError
        payload = _CURSOR_PAYLOAD.validate_json(raw, strict=True)
        expiry = payload.get("exp", 0)
        if (
            not isinstance(expiry, int | float)
            or isinstance(expiry, bool)
            or expiry < now.timestamp()
        ):
            raise ValueError
        return payload
    except Exception:
        raise WorkspaceApiError(400, "CURSOR_INVALID", "cursor is invalid or expired") from None


def cursor_filters(payload: dict[str, object]) -> dict[str, object]:
    filters = payload.get("filters")
    if not isinstance(filters, dict):
        raise WorkspaceApiError(400, "CURSOR_INVALID", "cursor is invalid or expired")
    try:
        return _CURSOR_FILTERS.validate_python(filters, strict=True)
    except Exception:
        raise WorkspaceApiError(400, "CURSOR_INVALID", "cursor is invalid or expired") from None


def cursor_pair(payload: dict[str, object]) -> tuple[object, object]:
    after = payload.get("after")
    if not isinstance(after, list):
        raise WorkspaceApiError(400, "CURSOR_INVALID", "cursor does not match this request")
    try:
        values = _CURSOR_VALUES.validate_python(after, strict=True)
    except Exception:
        raise WorkspaceApiError(
            400, "CURSOR_INVALID", "cursor does not match this request"
        ) from None
    if len(values) != 2:
        raise WorkspaceApiError(400, "CURSOR_INVALID", "cursor does not match this request")
    return values[0], values[1]


def cursor_datetime(value: object) -> datetime:
    if not isinstance(value, str):
        raise WorkspaceApiError(400, "CURSOR_INVALID", "cursor does not match this request")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise WorkspaceApiError(
            400, "CURSOR_INVALID", "cursor does not match this request"
        ) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise WorkspaceApiError(400, "CURSOR_INVALID", "cursor does not match this request")
    return parsed.astimezone(UTC)


def mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    try:
        return _CURSOR_FILTERS.validate_python(value, strict=True)
    except Exception:
        return {}


def count(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def optional_datetime(value: object) -> datetime | None:
    return value if isinstance(value, datetime) else None


def aware(value: datetime | None, name: str) -> datetime | None:
    if value is not None and (value.tzinfo is None or value.utcoffset() is None):
        raise WorkspaceApiError(
            422, "BAD_FILTER", f"{name} must include a timezone offset", details={"field": name}
        )
    return value.astimezone(UTC) if value is not None else None


def window(
    now: datetime,
    from_: datetime | None,
    to: datetime | None,
    preset: str | None,
    *,
    max_span: timedelta = timedelta(days=30),
) -> tuple[datetime, datetime, str | None]:
    if now.tzinfo is None or now.utcoffset() is None:
        raise RuntimeError("workspace clock must be timezone-aware")
    now = now.astimezone(UTC)
    start, end = aware(from_, "from"), aware(to, "to")
    durations = {
        "1h": timedelta(hours=1),
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30),
    }
    if preset is not None:
        if preset not in durations:
            raise WorkspaceApiError(
                422, "BAD_FILTER", "range is unsupported", details={"field": "range"}
            )
        if start is not None or end is not None:
            raise WorkspaceApiError(
                422,
                "BAD_FILTER",
                "range cannot be combined with from or to",
                details={"field": "range"},
            )
        end, start = now, now - durations[preset]
    elif start is None and end is None:
        end, start, preset = now, now - timedelta(hours=24), "24h"
    elif start is None:
        end = end or now
        start = end - timedelta(hours=24)
    elif end is None:
        end = now
    assert start is not None and end is not None
    if end - start <= timedelta(0) or end - start > max_span or end > now + timedelta(seconds=1):
        raise WorkspaceApiError(
            422,
            "BAD_FILTER",
            "time range must be positive, at most 30 days, and not in the future",
            details={"field": "from"},
        )
    return start, end, preset
