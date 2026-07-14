"""HTTP error mapping for chat surfaces (B0)."""
from unittest.mock import patch

import httpx
import pytest

from app.main import _llm_unreachable_error


def test_llm_unreachable_maps_to_503_and_audits():
    exc = httpx.ConnectError("connection refused")
    with patch("app.main.audit.emit") as emit:
        err = _llm_unreachable_error(exc)
    assert err.status_code == 503
    assert "inference backend unreachable" in str(err.detail)
    emit.assert_called_once()
    assert emit.call_args.args[0] == "llm_unreachable"
