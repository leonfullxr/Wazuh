from __future__ import annotations

import pytest
from pydantic import ValidationError

from ai_soc.live.sealed import QualificationResourceMapPin


def test_qualification_resource_map_pin_requires_exact_version_and_digest() -> None:
    pin = QualificationResourceMapPin(
        bucket="ai-soc-live-123456789012-audit",
        key="qualification-maps/resource-map.json",
        version_id="3HL4kqtJlcpXroDTDmjVBH40Nrjfkd",
        sha256="a" * 64,
    )

    assert pin.version_id != "null"
    assert len(pin.sha256) == 64


@pytest.mark.parametrize("version_id", ["", "null"])
def test_qualification_resource_map_pin_rejects_unversioned_objects(version_id: str) -> None:
    with pytest.raises(ValidationError):
        QualificationResourceMapPin(
            bucket="ai-soc-live-123456789012-audit",
            key="qualification-maps/resource-map.json",
            version_id=version_id,
            sha256="a" * 64,
        )


def test_qualification_resource_map_pin_rejects_malformed_digest() -> None:
    with pytest.raises(ValidationError):
        QualificationResourceMapPin(
            bucket="ai-soc-live-123456789012-audit",
            key="qualification-maps/resource-map.json",
            version_id="3HL4kqtJlcpXroDTDmjVBH40Nrjfkd",
            sha256="A" * 64,
        )
