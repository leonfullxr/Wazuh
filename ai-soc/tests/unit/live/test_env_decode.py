from __future__ import annotations

import base64

import pytest

from ai_soc.live.env import _decode_key_material


def test_decode_key_material_requires_base64() -> None:
    raw = _decode_key_material(base64.b64encode(b"k" * 32).decode())
    assert len(raw) == 32
    with pytest.raises(ValueError, match="valid base64"):
        _decode_key_material("not-valid-base64!!!")
