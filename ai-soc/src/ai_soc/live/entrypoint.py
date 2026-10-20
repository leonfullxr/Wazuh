"""Zero-argument live ASGI factory for container entry."""

from __future__ import annotations

from pathlib import Path

from fastapi.staticfiles import StaticFiles
from starlette.types import ASGIApp

from ai_soc.application.composition import runtime_asgi_app
from ai_soc.live.env import load_sealed_document
from ai_soc.live.runtime import LiveRuntime, build_live_runtime, shutdown_live_runtime

_UI_DIST = Path("/service/ui/dist")
_runtime_state: LiveRuntime | None = None


def create_app() -> ASGIApp:
    """Uvicorn factory entry for live ECS tasks."""
    global _runtime_state
    document = load_sealed_document()
    _runtime_state = build_live_runtime(document)
    rest = _runtime_state.runtime.rest
    if _UI_DIST.is_dir():
        rest.mount("/", StaticFiles(directory=_UI_DIST, html=True), name="ui")

    async def shutdown() -> None:
        if _runtime_state is not None:
            await shutdown_live_runtime(_runtime_state)

    return runtime_asgi_app(_runtime_state.runtime, shutdown=shutdown)
