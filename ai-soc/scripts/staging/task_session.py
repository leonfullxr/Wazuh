from __future__ import annotations

import time
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any, Self

from scripts.staging.journal import RunIntent
from scripts.staging.qualification_context import TaskCompletion
from scripts.staging.run_recovery import RunEvent, apply_cleanup_result, reduce_run_event
from scripts.staging.task_lifecycle import stop_owned_and_confirm

_KEEP = object()


class SessionTaskMixin:
    def _update_journal_state(
        self,
        *,
        runs: tuple[RunIntent, ...] | object = _KEEP,
        session_fault: str | None | object = _KEEP,
    ) -> None:
        """Persist run transitions and explicit session-wide faults."""
        changes: dict[str, Any] = {}
        if runs is not _KEEP:
            changes["runs"] = runs
        if session_fault is not _KEEP:
            changes["session_fault"] = session_fault
        self._journal = replace(self._journal, **changes)

    def stop_and_wait(self, run_id: str, *, timeout_seconds: float) -> bool:
        """Request stop and confirm every positively owned task reached STOPPED."""
        run = next((item for item in self._journal.runs if item.run_id == run_id), None)
        if not 0 < timeout_seconds <= 900:
            raise ValueError("cleanup timeout is outside the approved bound")
        if run is None:
            self._update_journal_state(session_fault="cleanup has no persisted owned task set")
            self._persist()
            return False
        if not run.task_arns:
            self._replace_run(reduce_run_event(run, RunEvent.UNCERTAIN))
            self._persist()
            return False
        run = reduce_run_event(run, RunEvent.CLEANUP_STARTED)
        self._replace_run(run)
        try:
            self._persist()
        except (OSError, ValueError):
            # Cleanup is a safety action and must continue even if recording
            # the stopping state cannot fit in the journal.
            self._update_journal_state(
                session_fault="qualification journal could not record cleanup"
            )
        try:
            result = stop_owned_and_confirm(
                self.clients.client("ecs"),
                cluster_arn=self.binding.cluster_arn,
                task_arns=run.task_arns,
                ownership_check=lambda task: self._task_owned(task, run),
                identity_check=lambda task: self._task_identity(task, run)[0],
                timeout_seconds=timeout_seconds,
                stop_reason="qualification deadline cleanup",
            )
            if result.task_arns or result.confirmed_stopped or result.ownership_ambiguous:
                updated = apply_cleanup_result(
                    run,
                    task_arns=result.task_arns,
                    confirmed_stopped=result.confirmed_stopped,
                    ownership_ambiguous=result.ownership_ambiguous,
                )
                self._replace_run(updated)
            updated_run = next(item for item in self._journal.runs if item.run_id == run_id)
            if (
                result.confirmed_stopped
                and not result.ownership_ambiguous
                and updated_run.state == "stopped"
            ):
                all_stopped = all(item.state == "stopped" for item in self._journal.runs)
                if all_stopped:
                    self._update_journal_state(session_fault=None)
                try:
                    self._persist()
                except (OSError, ValueError):
                    pass
                return True
        except Exception:
            result = None
        if result is None or not result.confirmed_stopped or result.ownership_ambiguous:
            current = next(item for item in self._journal.runs if item.run_id == run_id)
            self._replace_run(reduce_run_event(current, RunEvent.UNCERTAIN))
        try:
            self._persist()
        except (OSError, ValueError):
            pass
        return False

    def wait_for_completion(self, run_id: str) -> tuple[TaskCompletion, ...]:
        """Wait under the persisted execution budget, then clean up immediately."""
        run = next((item for item in self._journal.runs if item.run_id == run_id), None)
        if run is None or run.state != "launched" or len(run.task_arns) != len(run.task_slots):
            raise RuntimeError("qualification run does not have a complete authenticated task set")
        if run.probe_spec is None:
            raise RuntimeError("qualification execution budget is missing or invalid")
        execution_seconds = run.probe_spec.execution_seconds
        collection_seconds = run.probe_spec.collection_seconds
        if (
            not isinstance(execution_seconds, int)
            or not 1 <= execution_seconds <= 900
            or not isinstance(collection_seconds, int)
            or not 1 <= collection_seconds <= 86_400
        ):
            raise RuntimeError("qualification execution budget is missing or invalid")
        ecs = self.clients.client("ecs")
        delivery_deadline = datetime.fromisoformat(run.deadline_utc.replace("Z", "+00:00"))
        execution_deadline = delivery_deadline.timestamp() - collection_seconds
        remaining = max(0.0, execution_deadline - datetime.now(UTC).timestamp())
        deadline = time.monotonic() + min(float(execution_seconds), remaining)
        while True:
            try:
                response = ecs.describe_tasks(
                    cluster=self.binding.cluster_arn,
                    tasks=list(run.task_arns),
                    include=["TAGS"],
                )
            except Exception:
                self.stop_and_wait(run_id, timeout_seconds=60)
                raise
            if time.monotonic() >= deadline:
                self.stop_and_wait(run_id, timeout_seconds=60)
                raise TimeoutError("qualification execution deadline expired")
            tasks = response.get("tasks", [])
            if (
                response.get("failures")
                or {row.get("taskArn") for row in tasks} != set(run.task_arns)
                or len(tasks) != len(run.task_arns)
                or any(
                    not self._task_identity(row, run)[0] or not self._task_runtime_binding(row, run)
                    for row in tasks
                )
            ):
                self.stop_and_wait(run_id, timeout_seconds=60)
                self._update_journal_state(
                    session_fault="qualification task observation is incomplete or ambiguous"
                )
                self._persist()
                raise RuntimeError("qualification task observation is incomplete or ambiguous")
            if all(row.get("lastStatus") == "STOPPED" for row in tasks):
                containers_by_task: list[TaskCompletion] = []
                for task in tasks:
                    containers = task.get("containers", [])
                    app = next((item for item in containers if item.get("name") == "ai-soc"), None)
                    if app is None or app.get("exitCode") != 0:
                        self.stop_and_wait(run_id, timeout_seconds=60)
                        raise RuntimeError("qualification application container did not exit 0")
                    stopped_at = task.get("stoppedAt")
                    if isinstance(stopped_at, str):
                        stopped_at = datetime.fromisoformat(stopped_at.replace("Z", "+00:00"))
                    if not isinstance(stopped_at, datetime):
                        stopped_at = None
                    containers_by_task.append(
                        TaskCompletion(
                            task_arn=task["taskArn"],
                            last_status=task["lastStatus"],
                            exit_code=app["exitCode"],
                            stopped_at=stopped_at,
                        )
                    )
                if not self.stop_and_wait(run_id, timeout_seconds=60):
                    raise RuntimeError("qualification task cleanup could not be confirmed")
                return tuple(containers_by_task)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.stop_and_wait(run_id, timeout_seconds=60)
                raise TimeoutError("qualification execution deadline expired")
            time.sleep(min(1.0, remaining))

    def _replace_run(self, updated: RunIntent) -> None:
        self._update_journal_state(
            runs=tuple(
                updated if item.run_id == updated.run_id else item for item in self._journal.runs
            )
        )

    def _task_identity(self, task: dict[str, Any], run: RunIntent) -> tuple[bool, str | None]:
        tags = {
            row.get("key"): row.get("value")
            for row in task.get("tags", [])
            if isinstance(row, dict)
        }
        expected = {
            "qualification": "true",
            "qualification-session": self.session_id,
            "qualification-invocation": run.invocation_id,
            "qualification-run": run.run_id,
            "qualification-gate": run.gate_id,
            "qualification-contributor": run.contributor_id,
        }
        slot = tags.get("qualification-slot")
        valid = (
            task.get("clusterArn") == self.binding.cluster_arn
            and task.get("taskDefinitionArn") == self.binding.task_definition_arn
            and task.get("startedBy") == run.started_by
            and all(tags.get(key) == value for key, value in expected.items())
            and isinstance(slot, str)
            and slot in run.task_slots
        )
        return valid, slot if isinstance(slot, str) else None

    def _task_owned(self, task: dict[str, Any], run: RunIntent) -> bool:
        """Identify tasks safe to stop even when their slot is unexpected."""
        tags = {
            row.get("key"): row.get("value")
            for row in task.get("tags", [])
            if isinstance(row, dict)
        }
        expected = {
            "qualification": "true",
            "qualification-session": self.session_id,
            "qualification-invocation": run.invocation_id,
            "qualification-run": run.run_id,
            "qualification-gate": run.gate_id,
            "qualification-contributor": run.contributor_id,
        }
        return bool(
            task.get("clusterArn") == self.binding.cluster_arn
            and task.get("taskDefinitionArn") == self.binding.task_definition_arn
            and task.get("startedBy") == run.started_by
            and all(tags.get(key) == value for key, value in expected.items())
            and isinstance(tags.get("qualification-slot"), str)
            and bool(tags["qualification-slot"])
        )

    def _stop_owned_tasks(
        self, run: RunIntent, task_arns: tuple[str, ...], *, timeout_seconds: float
    ) -> bool:
        result = stop_owned_and_confirm(
            self.clients.client("ecs"),
            cluster_arn=self.binding.cluster_arn,
            task_arns=task_arns,
            ownership_check=lambda task: self._task_owned(task, run),
            identity_check=lambda task: self._task_identity(task, run)[0],
            timeout_seconds=timeout_seconds,
            stop_reason="qualification owned-task reconciliation",
        )
        return result.confirmed_stopped and not result.ownership_ambiguous

    def _task_runtime_binding(self, task: dict[str, Any], run: RunIntent) -> bool:
        """Reject effective image or override changes in real DescribeTasks shapes."""
        app_containers = [row for row in task.get("containers", []) if row.get("name") == "ai-soc"]
        if (
            len(app_containers) != 1
            or app_containers[0].get("imageDigest") != self.binding.image_digest
        ):
            return False
        _valid, slot = self._task_identity(task, run)
        if slot is None or len(run.launch_requests) != len(run.task_slots):
            return False
        expected_request = run.launch_requests[run.task_slots.index(slot)]
        expected_override = expected_request["overrides"]
        observed_override = task.get("overrides")
        if not isinstance(observed_override, dict):
            return False
        # ECS may include empty role/CPU fields in its response. Any non-empty
        # non-container override could alter the deployed task identity.
        if any(
            key != "containerOverrides" and value not in (None, "", [], {})
            for key, value in observed_override.items()
        ):
            return False
        rows = observed_override.get("containerOverrides")
        if not isinstance(rows, list) or not rows:
            return False
        expected_row = expected_override["containerOverrides"][0]
        named_rows: dict[str, dict[str, Any]] = {}
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("name"), str):
                return False
            if row["name"] in named_rows:
                return False
            named_rows[row["name"]] = row
        observed = named_rows.get(expected_row["name"])
        if observed is None:
            return False
        sidecars = [row for name, row in named_rows.items() if name != expected_row["name"]]
        if any(set(row) != {"name"} for row in sidecars):
            return False
        return bool(
            observed.get("command") == expected_row["command"]
            and observed.get("environment") == expected_row["environment"]
            and all(
                key == "name" or value in (None, "", [], {})
                for key, value in observed.items()
                if key not in {"command", "environment"}
            )
        )

    def close(self) -> None:
        if not self._closed:
            for run in tuple(self._journal.runs):
                if run.task_arns and run.state != "stopped":
                    self.stop_and_wait(run.run_id, timeout_seconds=60)
            self._lock.__exit__(None, None, None)
            self._closed = True

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
