from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ai_soc.api.csrf import CsrfTokens
from ai_soc.application.errors import ServiceFailure


def test_nonce_token_is_bound_to_origin_owner_and_expiry() -> None:
    now = datetime(2026, 9, 30, tzinfo=UTC)
    csrf = CsrfTokens(b"s" * 32, origin="https://soc.example.test")
    cookie, token = csrf.issue(
        owner_key="a" * 64, assertion_expires_at=now + timedelta(hours=1), now=now
    )
    csrf.verify(
        token,
        cookie,
        owner_key="a" * 64,
        origin="https://soc.example.test",
        now=now + timedelta(seconds=1),
    )
    with pytest.raises(ServiceFailure):
        csrf.verify(
            token,
            cookie,
            owner_key="b" * 64,
            origin="https://soc.example.test",
            now=now + timedelta(seconds=1),
        )
    with pytest.raises(ServiceFailure):
        csrf.verify(
            token,
            cookie,
            owner_key="a" * 64,
            origin="https://evil.test",
            now=now,
        )


def test_nonce_cookie_is_required_and_assertion_expiry_caps_token() -> None:
    now = datetime(2026, 9, 30, tzinfo=UTC)
    csrf = CsrfTokens(b"s" * 32, origin="https://soc.example.test")
    cookie, token = csrf.issue(
        owner_key="a" * 64, assertion_expires_at=now + timedelta(seconds=3), now=now
    )
    csrf.verify(
        token,
        cookie,
        owner_key="a" * 64,
        origin="https://soc.example.test",
        now=now + timedelta(seconds=2),
    )
    with pytest.raises(ServiceFailure):
        csrf.verify(
            token,
            cookie,
            owner_key="a" * 64,
            origin="https://soc.example.test",
            now=now + timedelta(seconds=4),
        )
