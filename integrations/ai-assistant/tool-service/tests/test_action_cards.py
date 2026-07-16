"""Action card embedding for dashboard UI (V3.5c)."""
from app.actions.cards import (
    card_from_proposal,
    embed_action_cards,
    parse_action_markers,
    strip_action_markers,
)


def test_card_from_proposal_includes_ui_url():
    card = card_from_proposal(
        {
            "proposal_id": "abc123",
            "action": "create_dashboard",
            "preview": "Create dashboard **Test**",
            "tier": "dashboard",
            "risk": "low",
            "status": "pending",
            "confirm_path": "/v1/actions/abc123/confirm",
            "expires_in_s": 900,
        },
        ui_base="http://localhost:8080",
    )
    assert card["ui_url"] == "http://localhost:8080/v1/actions/ui/abc123"


def test_embed_and_parse_roundtrip():
    proposals = [
        {
            "proposal_id": "deadbeef",
            "action": "create_dashboard",
            "preview": "Preview text",
            "tier": "dashboard",
            "risk": "low",
            "status": "pending",
            "confirm_path": "/v1/actions/deadbeef/confirm",
            "expires_in_s": 600,
        }
    ]
    text = embed_action_cards("Answer body", proposals, ui_base="http://localhost:8080")
    assert "Answer body" in text
    assert "WAZUH_AI_ACTIONS" in text
    cards = parse_action_markers(text)
    assert len(cards) == 1
    assert cards[0]["proposal_id"] == "deadbeef"
    assert strip_action_markers(text).startswith("Answer body")
