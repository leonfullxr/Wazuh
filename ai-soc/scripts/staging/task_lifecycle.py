"""Shared description, ownership and stop confirmation for qualification tasks."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

TaskPredicate = Callable[[dict[str, Any]], bool]


@dataclass(frozen=True, slots=True)
class CleanupResult:
    task_arns: tuple[str, ...]
    confirmed_stopped: bool
    ownership_ambiguous: bool
    reason: str | None = None


def describe_owned_tasks(
    ecs: Any,
    *,
    cluster_arn: str,
    task_arns: tuple[str, ...],
    ownership_check: TaskPredicate,
) -> tuple[tuple[dict[str, Any], ...], bool]:
    """Describe an exact task set and retain only positively owned tasks."""
    response = ecs.describe_tasks(cluster=cluster_arn, tasks=list(task_arns), include=["TAGS"])
    requested = set(task_arns)
    rows = response.get("tasks", [])
    by_arn = {
        row.get("taskArn"): row
        for row in rows
        if isinstance(row, dict) and row.get("taskArn") in requested
    }
    owned = tuple(
        row
        for row in by_arn.values()
        if isinstance(row.get("taskArn"), str) and ownership_check(row)
    )
    ambiguous = (
        bool(response.get("failures")) or set(by_arn) != requested or len(owned) != len(by_arn)
    )
    return owned, ambiguous


def stop_owned_and_confirm(
    ecs: Any,
    *,
    cluster_arn: str,
    task_arns: tuple[str, ...],
    ownership_check: TaskPredicate,
    identity_check: TaskPredicate,
    timeout_seconds: float,
    stop_reason: str,
) -> CleanupResult:
    """Stop owned tasks and confirm the same identities are terminal."""
    if not task_arns or not 0 < timeout_seconds <= 900:
        return CleanupResult((), False, True, "task set or cleanup timeout is invalid")
    deadline = time.monotonic() + timeout_seconds
    owned_arns: tuple[str, ...] = ()
    try:
        owned, ambiguous = describe_owned_tasks(
            ecs,
            cluster_arn=cluster_arn,
            task_arns=task_arns,
            ownership_check=ownership_check,
        )
        owned_arns = tuple(sorted(str(row["taskArn"]) for row in owned))
        if not owned_arns:
            return CleanupResult((), False, True, "no positively owned task could be described")
        for row in owned:
            if row.get("lastStatus") != "STOPPED":
                try:
                    ecs.stop_task(cluster=cluster_arn, task=row["taskArn"], reason=stop_reason)
                except Exception:
                    # Stop is idempotent; the terminality poll decides the outcome.
                    pass
        while time.monotonic() < deadline:
            response = ecs.describe_tasks(
                cluster=cluster_arn, tasks=list(owned_arns), include=["TAGS"]
            )
            tasks = response.get("tasks", [])
            if (
                not response.get("failures")
                and {row.get("taskArn") for row in tasks} == set(owned_arns)
                and all(ownership_check(row) and identity_check(row) for row in tasks)
                and all(row.get("lastStatus") == "STOPPED" for row in tasks)
            ):
                return CleanupResult(
                    owned_arns,
                    True,
                    ambiguous,
                    "task ownership is ambiguous" if ambiguous else None,
                )
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(0.25, remaining))
    except Exception:
        return CleanupResult((), False, True, "task cleanup observation failed")
    return CleanupResult(owned_arns, False, True, "task cleanup is not confirmed")
