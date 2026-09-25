"""Routing tests — no network calls."""
from gateway.confirm import PendingActionStore
from gateway.handler import process_analyze
from gateway.routing import ANALYSIS, ACTION_RESTART, keyword_classify


def test_alert_question_routes_to_mcp():
    store = PendingActionStore()
    mcp_calls: list[str] = []

    def fake_mcp(question: str) -> str:
        mcp_calls.append(question)
        return "3 critical alerts in the last 24 hours."

    result = process_analyze(
        {
            "question": "How many critical alerts in the last 24 hours?",
            "conversation_id": "sess-1",
        },
        mcp_fn=fake_mcp,
        store=store,
    )

    assert mcp_calls == ["How many critical alerts in the last 24 hours?"]
    assert "3 critical alerts" in result["output"]["message"]


def test_keyword_classifier_marks_alerts_as_analysis():
    assert keyword_classify("Show me recent alert activity") == ANALYSIS


def test_restart_classified_as_action():
    assert keyword_classify("Please restart agent host-001") == ACTION_RESTART
