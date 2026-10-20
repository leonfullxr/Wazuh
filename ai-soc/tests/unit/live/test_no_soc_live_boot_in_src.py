from __future__ import annotations

from pathlib import Path


def test_src_has_no_soc_live_boot_strings() -> None:
    root = Path(__file__).resolve().parents[3] / "src"
    offenders = [
        path.relative_to(root)
        for path in root.rglob("*.py")
        if "SOC_LIVE_BOOT" in path.read_text(encoding="utf-8")
    ]
    assert offenders == []
