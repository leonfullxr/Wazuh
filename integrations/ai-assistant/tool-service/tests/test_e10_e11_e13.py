"""Unit tests for E10/E11/E13: reference lookups, capabilities, tool subsetting."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.capabilities import DescribeCapabilitiesParams, describe_capabilities
from app.config import CFG
from app.knowledge import (
    FieldDictionaryParams,
    RuleReferenceParams,
    corpus_ids,
    field_dictionary,
    reload_corpora,
    rule_reference,
)
from app.tool_router import classify_intent, subset_tool_names, tool_specs_for_turn
from app.tools import REGISTRY, converse_tool_specs


def test_rule_reference_by_id():
    out = rule_reference(RuleReferenceParams(rule_id="5710"))
    assert out["found"] is True
    assert out["id"] == "rule-5710"
    assert "non-existent" in out["meaning"].lower() or "SSH" in out["meaning"]


def test_rule_reference_by_group():
    out = rule_reference(RuleReferenceParams(rule_group="authentication_failed"))
    assert out["found"] is True
    assert out["id"] == "group-authentication_failed"


def test_rule_reference_unknown_fails_closed():
    out = rule_reference(RuleReferenceParams(rule_id="999999"))
    assert out["found"] is False
    assert "not in local" in out["error"]


def test_rule_reference_requires_exactly_one_key():
    with pytest.raises(ValidationError):
        RuleReferenceParams(rule_id="5710", rule_group="sshd")
    with pytest.raises(ValidationError):
        RuleReferenceParams()


def test_field_dictionary_and_alias():
    out = field_dictionary(FieldDictionaryParams(field="rule.level"))
    assert out["found"] is True
    assert "severity" in out["meaning"].lower()
    alias = field_dictionary(FieldDictionaryParams(field="severity"))
    assert alias["found"] is True
    assert alias["field"] == "rule.level"


def test_field_dictionary_unknown():
    out = field_dictionary(FieldDictionaryParams(field="not.a.real.field"))
    assert out["found"] is False


def test_corpus_ids_include_references():
    reload_corpora()
    ids = corpus_ids()
    assert "kb-ssh-bruteforce" in ids
    assert "rule-5710" in ids
    assert "field-rule-level" in ids
    assert any(i.startswith("doc-") for i in ids)


def test_describe_capabilities_from_registry():
    out = describe_capabilities(DescribeCapabilitiesParams())
    names = {t["name"] for t in out["tools"]}
    assert "count_alerts" in names
    assert "rule_reference" in names
    assert "describe_capabilities" in names
    assert "lanes" in out
    assert "data_families" in out


def test_tools_registered():
    for name in (
        "rule_reference",
        "field_dictionary",
        "describe_capabilities",
    ):
        assert name in REGISTRY
        assert REGISTRY[name].knowledge is True


def test_classify_intent_docs_and_ops():
    assert classify_intent("how do I configure active response") == "docs"
    assert classify_intent("what can you do for me today") == "ops"
    assert classify_intent("???") is None


def test_tool_subset_reduces_catalog(monkeypatch):
    monkeypatch.setattr(CFG, "tool_subset_enabled", True)
    allowed = subset_tool_names("docs")
    assert allowed is not None
    assert "knowledge_search" in allowed
    assert "rule_reference" in allowed
    full = converse_tool_specs(None)
    subset = converse_tool_specs(allowed)
    assert len(subset) < len(full)
    assert len(subset) >= 4


def test_tool_subset_fail_open(monkeypatch):
    monkeypatch.setattr(CFG, "tool_subset_enabled", True)
    specs, meta = tool_specs_for_turn("hello")
    assert meta["subset"] is False
    assert meta["offered_tool_count"] == meta["full_tool_count"]
    assert len(specs) == len(converse_tool_specs(None))
