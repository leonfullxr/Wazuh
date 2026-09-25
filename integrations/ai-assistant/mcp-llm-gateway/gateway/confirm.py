"""In-memory pending action state and CONFIRM / NO handling."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .routing import ACTION_DASHBOARD, ACTION_REPORT, ACTION_RESTART


@dataclass
class PendingAction:
    intent: str
    params: dict


class PendingActionStore:
    def __init__(self) -> None:
        self._pending: dict[str, PendingAction] = {}

    def set(self, session_id: str, intent: str, params: dict) -> None:
        self._pending[session_id] = PendingAction(intent=intent, params=params)

    def get(self, session_id: str) -> PendingAction | None:
        return self._pending.get(session_id)

    def clear(self, session_id: str) -> None:
        self._pending.pop(session_id, None)

    def has(self, session_id: str) -> bool:
        return session_id in self._pending


def _action_label(intent: str) -> str:
    return {
        ACTION_RESTART: "Restart Wazuh agent",
        ACTION_DASHBOARD: "Create custom dashboard",
        ACTION_REPORT: "Email PDF report",
    }.get(intent, intent)


def format_pending_block(intent: str, params: dict) -> str:
    lines = [
        "--- Pending Action ---",
        f"Type: {_action_label(intent)}",
        f"Details: {params}",
        "Reply with the exact token CONFIRM to execute.",
        "Reply with NO to cancel.",
        "--- End Pending Action ---",
    ]
    return "\n".join(lines)


def handle_confirm(
    session_id: str,
    store: PendingActionStore,
    executor: Callable[[PendingAction], str],
) -> str:
    pending = store.get(session_id)
    if pending is None:
        return "No pending action to confirm."
    store.clear(session_id)
    return executor(pending)


def handle_no(session_id: str, store: PendingActionStore) -> str:
    if not store.has(session_id):
        return "No pending action to cancel."
    store.clear(session_id)
    return "Pending action cancelled."
