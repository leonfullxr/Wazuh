"""Conversational confirm intent (D54)."""
from app.actions.confirm_intent import extract_confirm_target, parse_intent


def test_parse_affirm_bare():
    assert parse_intent("yes") == "affirm"
    assert parse_intent("sí") == "affirm"
    assert parse_intent("confirm") == "affirm"


def test_parse_negate():
    assert parse_intent("no") == "negate"
    assert parse_intent("cancel") == "negate"


def test_parse_other_for_substantive_question():
    assert parse_intent("How many alerts in the last 24 hours?") == "other"


def test_extract_high_risk_target():
    target = extract_confirm_target("yes restart-ossec on 001", "active_response")
    assert target == {"command": "restart-ossec", "agent_id": "001"}
