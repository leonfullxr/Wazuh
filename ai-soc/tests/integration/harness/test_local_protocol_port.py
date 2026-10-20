from __future__ import annotations

import importlib.util
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "soc_b6_local_protocol_check", ROOT / "scripts/local_protocol_check.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("local protocol runner module could not be loaded")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
_published_loopback_port = cast(Callable[..., int], MODULE._published_loopback_port)


def test_parse_compose_published_loopback_port_format() -> None:
    assert _published_loopback_port("127.0.0.1:32768", expected=32768) == 32768


@pytest.mark.parametrize(
    "value",
    [
        "invalid IP:0",
        "127.0.0.1:0",
        "127.0.0.1:32768/tcp",
        "0.0.0.0:32768",
        "192.0.2.1:32768",
        "[::1]:32768",
        "127.0.0.1:32768/udp",
    ],
)
def test_reject_non_loopback_or_non_ephemeral_compose_port_output(value: str) -> None:
    with pytest.raises(RuntimeError, match="selected nonzero loopback"):
        _published_loopback_port(value, expected=32768)


def test_reject_compose_output_for_a_different_selected_port() -> None:
    with pytest.raises(RuntimeError, match="selected nonzero loopback"):
        _published_loopback_port("127.0.0.1:32769", expected=32768)
