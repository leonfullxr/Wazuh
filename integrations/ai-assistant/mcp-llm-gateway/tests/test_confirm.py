"""CONFIRM / NO gate tests — no network calls."""
from gateway.confirm import PendingAction, PendingActionStore
from gateway.handler import process_analyze
from gateway.routing import ACTION_RESTART


def test_restart_creates_pending_without_manager_call():
    store = PendingActionStore()
    manager_calls: list[str] = []

    def fake_executor(action: PendingAction) -> str:
        manager_calls.append(action.params.get("agent_id", ""))
        return "done"

    result = process_analyze(
        {
            "question": "restart agent host-001",
            "conversation_id": "sess-confirm",
        },
        store=store,
        executor=fake_executor,
    )

    assert manager_calls == []
    assert "Pending Action" in result["output"]["message"]
    assert store.has("sess-confirm")


def test_confirm_executes_pending_action():
    store = PendingActionStore()
    executed: list[str] = []

    def fake_executor(action: PendingAction) -> str:
        executed.append(action.params["agent_id"])
        return f"restarted {action.params['agent_id']}"

    process_analyze(
        {"question": "restart agent host-001", "conversation_id": "sess-2"},
        store=store,
        executor=fake_executor,
    )
    result = process_analyze(
        {"question": "CONFIRM", "conversation_id": "sess-2"},
        store=store,
        executor=fake_executor,
    )

    assert executed == ["host-001"]
    assert "restarted host-001" in result["output"]["message"]
    assert not store.has("sess-2")


def test_no_cancels_pending_action():
    store = PendingActionStore()

    process_analyze(
        {"question": "restart agent host-002", "conversation_id": "sess-3"},
        store=store,
    )
    result = process_analyze(
        {"question": "NO", "conversation_id": "sess-3"},
        store=store,
    )

    assert "cancelled" in result["output"]["message"].lower()
    assert not store.has("sess-3")


def test_unrelated_question_does_not_execute_stale_pending():
    store = PendingActionStore()
    manager_calls: list[str] = []
    mcp_calls: list[str] = []

    def fake_executor(action: PendingAction) -> str:
        manager_calls.append(action.params.get("agent_id", ""))
        return "restarted"

    def fake_mcp(question: str) -> str:
        mcp_calls.append(question)
        return "alert summary"

    process_analyze(
        {"question": "restart agent host-003", "conversation_id": "sess-4"},
        store=store,
        executor=fake_executor,
        mcp_fn=fake_mcp,
    )

    result = process_analyze(
        {
            "question": "What vulnerabilities affect agent host-003?",
            "conversation_id": "sess-4",
        },
        store=store,
        executor=fake_executor,
        mcp_fn=fake_mcp,
    )

    assert manager_calls == []
    assert mcp_calls == ["What vulnerabilities affect agent host-003?"]
    assert result["output"]["message"] == "alert summary"
    assert store.has("sess-4")
