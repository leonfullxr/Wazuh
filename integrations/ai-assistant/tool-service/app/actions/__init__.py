"""Actions v1.5 (D20/D35): propose → confirm write operations.

The model only ever calls propose_* tools. Execution requires a verified
operator JWT via POST /v1/actions/{id}/confirm.
"""
from .proposals import (
    confirm_proposal,
    create_proposal,
    create_proposal_by_action,
    get_proposal,
    reject_proposal,
)
from .registry import ACTION_REGISTRY, action_tool_specs, get_action

__all__ = [
    "ACTION_REGISTRY",
    "action_tool_specs",
    "confirm_proposal",
    "create_proposal",
    "create_proposal_by_action",
    "get_action",
    "get_proposal",
    "reject_proposal",
]
