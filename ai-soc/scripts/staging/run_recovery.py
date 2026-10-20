"""Pure recovery decisions for journaled qualification task runs."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from scripts.staging.attributed_probe import RunIntent


class RunEvent(StrEnum):
    LAUNCH_PARTIAL = "launch_partial"
    LAUNCH_COMPLETE = "launch_complete"
    UNCERTAIN = "uncertain"
    CLEANUP_STARTED = "cleanup_started"
    CLEANUP_CONFIRMED = "cleanup_confirmed"
    RECONCILED_LIVE = "reconciled_live"
    RECONCILED_TERMINAL = "reconciled_terminal"


_RUN_TRANSITIONS = {
    ("intent", RunEvent.LAUNCH_PARTIAL): "ambiguous",
    ("intent", RunEvent.LAUNCH_COMPLETE): "launched",
    ("intent", RunEvent.UNCERTAIN): "ambiguous",
    ("intent", RunEvent.CLEANUP_STARTED): "stopping",
    ("intent", RunEvent.RECONCILED_LIVE): "stopping",
    ("intent", RunEvent.RECONCILED_TERMINAL): "stopped",
    ("launched", RunEvent.LAUNCH_COMPLETE): "launched",
    ("launched", RunEvent.LAUNCH_PARTIAL): "ambiguous",
    ("launched", RunEvent.UNCERTAIN): "ambiguous",
    ("launched", RunEvent.CLEANUP_STARTED): "stopping",
    ("launched", RunEvent.RECONCILED_LIVE): "stopping",
    ("launched", RunEvent.RECONCILED_TERMINAL): "stopped",
    ("stopping", RunEvent.CLEANUP_CONFIRMED): "stopped",
    ("stopping", RunEvent.CLEANUP_STARTED): "stopping",
    ("stopping", RunEvent.UNCERTAIN): "ambiguous",
    ("stopping", RunEvent.RECONCILED_TERMINAL): "stopped",
    ("stopping", RunEvent.RECONCILED_LIVE): "stopping",
    ("ambiguous", RunEvent.LAUNCH_COMPLETE): "launched",
    ("ambiguous", RunEvent.LAUNCH_PARTIAL): "ambiguous",
    ("ambiguous", RunEvent.UNCERTAIN): "ambiguous",
    ("ambiguous", RunEvent.CLEANUP_STARTED): "stopping",
    ("ambiguous", RunEvent.CLEANUP_CONFIRMED): "stopped",
    ("ambiguous", RunEvent.RECONCILED_LIVE): "stopping",
    ("ambiguous", RunEvent.RECONCILED_TERMINAL): "stopped",
    ("stopped", RunEvent.RECONCILED_TERMINAL): "stopped",
    ("stopped", RunEvent.UNCERTAIN): "ambiguous",
}


def reduce_run_event(
    run: RunIntent,
    event: RunEvent,
    **updates: Any,
) -> RunIntent:
    """Apply the sole event-to-state table for launch, recovery and cleanup."""
    state = _RUN_TRANSITIONS.get((run.state, event))
    if state is None:
        raise ValueError(f"invalid qualification run event: {run.state} + {event.value}")
    updated = replace(run, **updates, state=state)
    if event in {RunEvent.CLEANUP_CONFIRMED, RunEvent.RECONCILED_TERMINAL}:
        if not run_identity_set_resolved(updated):
            updated = replace(updated, state="ambiguous")
    return updated


def apply_cleanup_result(
    run: RunIntent,
    *,
    task_arns: tuple[str, ...],
    confirmed_stopped: bool,
    ownership_ambiguous: bool,
) -> RunIntent:
    """Persist cleanup evidence through the reducer's identity policy."""
    discovered = run.discovered_arns
    if ownership_ambiguous:
        discovered = tuple(sorted(set(discovered) | set(run.task_arns) | set(task_arns)))
    event = (
        RunEvent.CLEANUP_CONFIRMED
        if confirmed_stopped and not ownership_ambiguous
        else RunEvent.UNCERTAIN
    )
    return reduce_run_event(
        run,
        event,
        task_arns=task_arns,
        discovered_arns=discovered,
    )


def run_identity_set_resolved(run: RunIntent) -> bool:
    """Require every launch slot and discovered task to have an owned identity."""
    return (
        len(run.task_arns) == len(run.task_slots)
        and len(set(run.task_arns)) == len(run.task_arns)
        and set(run.discovered_arns).issubset(run.task_arns)
    )


def derive_launch_barrier(runs: tuple[RunIntent, ...], session_fault: str | None) -> str | None:
    """Keep launches closed until session faults and unresolved task identities clear."""
    if session_fault:
        return session_fault
    for run in runs:
        if run.state in {"intent", "stopping", "ambiguous"}:
            return "qualification run identity or cleanup is unresolved"
        if run.state in {"launched", "stopped"} and not run_identity_set_resolved(run):
            return "qualification run has unresolved recorded or discovered task identities"
    return None


@dataclass(frozen=True, slots=True)
class ReconciliationDecision:
    run: RunIntent
    cleanup_task_arns: tuple[str, ...] = ()
    cleanup_run: bool = False


def apply_reconciliation(
    run: RunIntent,
    *,
    discovered_arns: tuple[str, ...],
    described_tasks: tuple[dict[str, Any], ...],
    describe_complete: bool,
    identity_valid: bool,
    observed_slots: frozenset[str],
    owned_task_arns: tuple[str, ...],
) -> ReconciliationDecision:
    """Apply one run's observed task state and derive its safety barrier."""
    if run.state == "stopped":
        if run_identity_set_resolved(run):
            return ReconciliationDecision(run)
    discovered = set(discovered_arns)
    owned_arns = tuple(sorted(set(run.task_arns) | set(owned_task_arns)))
    if discovered:
        described_arns = {item.get("taskArn") for item in described_tasks}
        if not describe_complete or described_arns != discovered:
            updated = reduce_run_event(
                run,
                RunEvent.UNCERTAIN,
                task_arns=owned_arns,
                discovered_arns=tuple(sorted(discovered)),
            )
            return ReconciliationDecision(
                updated,
                owned_arns,
            )
        if (
            not identity_valid
            or observed_slots != set(run.task_slots)
            or len(discovered) != len(run.task_slots)
        ):
            updated = reduce_run_event(
                run,
                RunEvent.UNCERTAIN,
                task_arns=owned_arns,
                discovered_arns=tuple(sorted(discovered)),
            )
            return ReconciliationDecision(
                updated,
                owned_arns,
            )
        terminal = all(item.get("lastStatus") == "STOPPED" for item in described_tasks)
        updated = reduce_run_event(
            run,
            RunEvent.RECONCILED_TERMINAL if terminal else RunEvent.RECONCILED_LIVE,
            task_arns=tuple(sorted(discovered)),
            discovered_arns=tuple(sorted(discovered)),
        )
        return ReconciliationDecision(
            updated,
            cleanup_run=not terminal,
        )
    if run.state in {"intent", "ambiguous"}:
        return ReconciliationDecision(reduce_run_event(run, RunEvent.UNCERTAIN))
    return ReconciliationDecision(reduce_run_event(run, RunEvent.UNCERTAIN))
