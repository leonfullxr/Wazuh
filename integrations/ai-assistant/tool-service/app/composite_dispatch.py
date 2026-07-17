"""Single dispatch path for composite tools (F5 / Round 7).

loop.py, playbooks.invoke_tool, and main.py /v1/tools all share this helper so
a new composite is registered in one place.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from .brute_force import brute_force_summary
from .correlation import agent_posture, compare_windows, related_alerts
from .principal import Principal


async def dispatch_composite(
    name: str, params: BaseModel, principal: Principal
) -> dict[str, Any]:
    """Execute a composite tool by name. Raises ValueError for unknown names."""
    if name == "brute_force_summary":
        return await brute_force_summary(principal, params)
    if name == "related_alerts":
        return await related_alerts(principal, params)
    if name == "compare_windows":
        return await compare_windows(principal, params)
    if name == "agent_posture":
        return await agent_posture(principal, params)
    raise ValueError(f"unknown composite tool '{name}'")
