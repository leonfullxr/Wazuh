from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from starlette.testclient import TestClient

from ai_soc.live.entrypoint import create_app
from ai_soc.live.runtime import LiveRuntime, shutdown_live_runtime
from ai_soc.state.feedback_control import FeedbackControlPool
from tests.unit.application.test_composition import _compose_fixture_runtime
from tests.unit.live.live_boot_fixture import _sealed


@pytest.fixture
def entrypoint_app(monkeypatch: pytest.MonkeyPatch):
    document = _sealed()
    runtime = replace(_compose_fixture_runtime(), feedback_control_pool=FeedbackControlPool())
    runtime.recovery.run_forever = AsyncMock()
    readiness = type("Ready", (), {"ready": lambda self: True, "close": lambda self: None})()
    live = LiveRuntime(
        runtime=runtime,
        readiness=readiness,
        pack_dir=Path("/tmp"),
    )
    monkeypatch.setattr("ai_soc.live.entrypoint.load_sealed_document", lambda: document)
    monkeypatch.setattr("ai_soc.live.entrypoint.build_live_runtime", lambda _doc: live)
    return create_app(), runtime, live


def test_entrypoint_shutdown_completes_only_after_runtime_cleanup(
    entrypoint_app, monkeypatch: pytest.MonkeyPatch
) -> None:
    app, runtime, live = entrypoint_app
    order: list[str] = []
    runtime.recovery.stop = lambda: order.append("recovery_stop")

    def track_lifespan(router, label: str) -> None:
        original = router.lifespan_context

        @asynccontextmanager
        async def wrapped(instance):
            try:
                async with original(instance):
                    yield
            finally:
                order.append(label)

        monkeypatch.setattr(router, "lifespan_context", wrapped)

    track_lifespan(runtime.rest.router, "rest_exit")
    sdk_app = runtime.mcp._app
    track_lifespan(sdk_app.router, "mcp_exit")

    pool = runtime.feedback_control_pool
    assert pool is not None
    original_close = pool.close

    def track_pool_close() -> None:
        order.append("feedback_pool_close")
        original_close()

    monkeypatch.setattr(pool, "close", track_pool_close)
    monkeypatch.setattr(live.readiness, "close", lambda: order.append("readiness_close"))

    async def track_shutdown(target: LiveRuntime) -> None:
        await shutdown_live_runtime(target)
        order.append("runtime_shutdown")

    monkeypatch.setattr("ai_soc.live.entrypoint.shutdown_live_runtime", track_shutdown)

    async def observe(scope, receive, send):
        async def observed_send(message):
            if message.get("type") == "lifespan.shutdown.complete":
                order.append("shutdown_complete")
            await send(message)

        await app(scope, receive, observed_send)

    with TestClient(observe, base_url="https://soc.example.test") as client:
        client.get("/health/live")
    assert order == [
        "recovery_stop",
        "feedback_pool_close",
        "readiness_close",
        "runtime_shutdown",
        "mcp_exit",
        "rest_exit",
        "shutdown_complete",
    ]


def test_entrypoint_combined_lifespan_starts_recovery_and_mcp_session(entrypoint_app) -> None:
    app, runtime, _live = entrypoint_app
    with TestClient(app, base_url="https://soc.example.test") as client:
        client.get("/health/live")
        response = client.post(
            "/mcp",
            headers={
                "Authorization": "Bearer not-a-real-token",
                "Origin": "https://soc.example.test",
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
            },
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "entrypoint-test", "version": "1"},
                },
            },
        )
    runtime.recovery.run_forever.assert_awaited()
    assert response.status_code in {401, 403}
    assert "Task group is not initialized" not in response.text
