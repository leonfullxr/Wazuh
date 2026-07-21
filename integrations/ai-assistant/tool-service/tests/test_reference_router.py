"""Round 8 F6/F7: deterministic reference_router recognition."""
from __future__ import annotations

from app.reference_router import match


def test_rule_id_route():
    hit = match("What does Wazuh rule 5710 mean?")
    assert hit is not None
    assert hit.tool == "rule_reference"
    assert hit.params == {"rule_id": "5710"}


def test_rule_group_route():
    hit = match("What does the authentication_failed rule group mean?")
    assert hit is not None
    assert hit.tool == "rule_reference"
    assert hit.params == {"rule_group": "authentication_failed"}


def test_field_route():
    hit = match("What does the rule.level field mean?")
    assert hit is not None
    assert hit.tool == "field_dictionary"
    assert hit.params["field"] == "rule.level"


def test_capabilities_route():
    hit = match("What can you do?")
    assert hit is not None
    assert hit.tool == "describe_capabilities"


def test_brute_force_route():
    hit = match(
        "Give me a brute force attack summary for the last 24 hours "
        "with top source IPs and targeted users."
    )
    assert hit is not None
    assert hit.tool == "brute_force_summary"


def test_howto_fails_open_to_knowledge_search():
    assert match("how do I configure Wazuh active response?") is None
    assert match(
        "Use knowledge_search with source wazuh-docs: how do I configure AR?"
    ) is None


def test_rule_render_cites_kb():
    import asyncio

    from app.principal import EnvPrincipal
    from app.reference_router import execute, match

    hit = match("What does Wazuh rule 5710 mean?")
    assert hit is not None
    principal = EnvPrincipal(env_id="lab")
    result = asyncio.run(execute(hit, principal, "What does Wazuh rule 5710 mean?"))
    assert "[kb:rule-5710]" in result.answer
    assert result.tool == "rule_reference"
    assert "reference_router" in result.checks


def test_short_fails_open():
    assert match("hello") is None
