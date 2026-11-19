"""Zero-argument live ASGI factory for container entry."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi.staticfiles import StaticFiles
from starlette.types import ASGIApp

from ai_soc.application.composition import runtime_asgi_app
from ai_soc.live.env import assert_no_disallowed_environ, load_sealed_document
from ai_soc.live.runtime import LiveRuntime, build_live_runtime, shutdown_live_runtime

_UI_DIST = Path(__file__).resolve().parents[3] / "web/dist"
_runtime_state: LiveRuntime | None = None


def create_app() -> ASGIApp:
    """Uvicorn factory entry for live ECS tasks."""
    global _runtime_state
    assert_no_disallowed_environ()
    configured_assets = os.environ.get("SOC_WEB_DIST")
    assets = Path(configured_assets) if configured_assets is not None else _UI_DIST
    if configured_assets is not None and (not assets.is_absolute() or not assets.is_dir()):
        raise ValueError("SOC_WEB_DIST must identify an existing absolute directory")
    document = load_sealed_document()
    _runtime_state = build_live_runtime(document)
    rest = _runtime_state.runtime.rest
    if assets.is_dir():
        rest.mount("/", StaticFiles(directory=assets, html=True), name="ui")

    async def shutdown() -> None:
        if _runtime_state is not None:
            await shutdown_live_runtime(_runtime_state)

    return runtime_asgi_app(_runtime_state.runtime, shutdown=shutdown)
