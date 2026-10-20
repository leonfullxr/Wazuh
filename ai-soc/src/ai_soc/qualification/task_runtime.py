"""Shared parsing and absolute-deadline handling for packaged probe tasks."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

from ai_soc.qualification.models import TaskLaunchConfig


def load_task_config(raw: str, *, entrypoint: str) -> TaskLaunchConfig:
    config = TaskLaunchConfig.model_validate_json(raw)
    if config.scenario.entrypoint != entrypoint:
        raise ValueError("qualification task entrypoint differs from its typed scenario")
    return config


def execution_deadline(config: TaskLaunchConfig) -> tuple[int, float]:
    """Return the bounded execution seconds and process-local monotonic deadline."""
    remaining = min(
        float(config.scenario.execution_seconds),
        (
            config.deadline_utc.astimezone(UTC)
            - datetime.now(UTC)
            - timedelta(seconds=config.scenario.collection_seconds)
        ).total_seconds(),
    )
    if remaining < 1:
        raise TimeoutError("qualification execution deadline expired")
    seconds = min(config.scenario.execution_seconds, int(remaining))
    return seconds, time.monotonic() + seconds
