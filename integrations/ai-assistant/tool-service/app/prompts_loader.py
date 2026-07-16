"""Versioned prompt modules (V3.7b) — loaded at startup, byte-stable per build."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

_DIR = Path(__file__).resolve().parent / "prompts"


@lru_cache(maxsize=8)
def load_prompt(name: str) -> str:
    path = _DIR / f"{name}.md"
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8").strip()


def domain_module() -> str:
    text = load_prompt("domain")
    return f"\n{text}\n" if text else ""


def reporting_module() -> str:
    text = load_prompt("reporting")
    return f"\n{text}\n" if text else ""


def dashboards_module() -> str:
    text = load_prompt("dashboards")
    return f"\n{text}\n" if text else ""


def build_system_prelude(
    *,
    now_line: str,
    include_reporting: bool,
    include_dashboards: bool,
    actions_suffix: str,
) -> str:
    parts = [now_line, domain_module()]
    if include_reporting:
        parts.append(reporting_module())
    if include_dashboards:
        parts.append(dashboards_module())
    if actions_suffix:
        parts.append(actions_suffix)
    return "".join(parts)
