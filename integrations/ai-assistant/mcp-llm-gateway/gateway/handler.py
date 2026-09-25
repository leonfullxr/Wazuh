"""Core /analyze request handling (testable without FastAPI)."""
from __future__ import annotations

from typing import Any, Callable

from .actions import action_executor
from .confirm import (
    PendingActionStore,
    format_pending_block,
    handle_confirm,
    handle_no,
)
from .llm import LLMConfigError, call_llm, provider_ready
from .mcp_client import call_mcp
from .routing import (
    ACTION_INTENTS,
    ANALYSIS,
    classify_intent,
    extract_action_params,
)

_store = PendingActionStore()


def get_store() -> PendingActionStore:
    return _store


def extract_message(parameters: dict[str, Any]) -> str:
    for key in ("question", "prompt", "input", "message"):
        value = parameters.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def extract_session_id(parameters: dict[str, Any]) -> str:
    for key in ("conversation_id", "session_id", "thread_id"):
        value = parameters.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "default"


def maybe_enhance_with_llm(question: str, mcp_answer: str) -> str:
    if not provider_ready():
        return mcp_answer
    try:
        return call_llm(
            prompt=(
                f"User question: {question}\n\n"
                f"Indexer data:\n{mcp_answer}\n\n"
                "Write a concise analyst-facing answer."
            ),
            system="You are a Wazuh SOC assistant.",
        )
    except LLMConfigError as exc:
        return f"{mcp_answer}\n\n(LLM unavailable: {exc})"


def process_analyze(
    parameters: dict[str, Any],
    *,
    classifier: Callable[[str], str] | None = None,
    mcp_fn: Callable[[str], str] | None = None,
    executor: Callable | None = None,
    store: PendingActionStore | None = None,
) -> dict[str, Any]:
    message = extract_message(parameters)
    session_id = extract_session_id(parameters)
    pending_store = store or _store
    mcp_call = mcp_fn or call_mcp
    run_action = executor or action_executor

    if message == "CONFIRM":
        text = handle_confirm(session_id, pending_store, run_action)
        return {"output": {"message": text}}

    if message.upper() == "NO":
        text = handle_no(session_id, pending_store)
        return {"output": {"message": text}}

    intent = classify_intent(message, classifier=classifier)

    if intent in ACTION_INTENTS:
        params = extract_action_params(intent, message)
        pending_store.set(session_id, intent, params)
        block = format_pending_block(intent, params)
        return {"output": {"message": block}}

    if intent == ANALYSIS:
        try:
            raw = mcp_call(message)
        except Exception as exc:  # noqa: BLE001 - surface MCP errors to caller
            return {"output": {"message": f"MCP query failed: {exc}"}}
        answer = maybe_enhance_with_llm(message, raw)
        return {"output": {"message": answer}}

    return {"output": {"message": f"Unhandled intent: {intent}"}}
