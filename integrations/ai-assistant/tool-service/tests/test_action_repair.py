"""Tests for action repair when the model prints JSON instead of tools."""
from __future__ import annotations

import json

import pytest

from app.actions.repair import try_repair_dashboard_action
from app.config import CFG
from app.principal import EnvPrincipal


@pytest.fixture
def principal():
    return EnvPrincipal("lab")


def test_repair_dashboard_json_executes_direct(monkeypatch, principal):
    monkeypatch.setattr(CFG, "actions_enabled", True)
    monkeypatch.setattr(CFG, "actions_direct", True)
    text = json.dumps(
        {
            "description": "Panel con mapa GeoIP de intentos de autenticacion fallidos.",
            "folder": "Security/Brute Force",
            "template": "brute_force_geoip",
            "title": "Brute Force Attack Dashboard – GeoIP",
        }
    )
    answer, result = try_repair_dashboard_action(
        text,
        principal,
        tools_called=[],
        ui_base="http://localhost:8080",
    )
    assert result is not None
    assert "status" in result
    assert "{" not in answer


def test_repair_skips_when_tool_already_called(monkeypatch, principal):
    monkeypatch.setattr(CFG, "actions_enabled", True)
    monkeypatch.setattr(CFG, "actions_direct", True)
    text = '{"title": "X", "template": "brute_force_geoip"}'
    answer, result = try_repair_dashboard_action(
        text,
        principal,
        tools_called=["create_dashboard"],
        ui_base="http://localhost:8080",
    )
    assert result is None
    assert answer == text


def test_repair_ignores_unrelated_json(monkeypatch, principal):
    monkeypatch.setattr(CFG, "actions_enabled", True)
    monkeypatch.setattr(CFG, "actions_direct", True)
    text = '{"foo": "bar", "template": "brute_force_geoip"}'
    answer, result = try_repair_dashboard_action(
        text,
        principal,
        tools_called=[],
        ui_base="http://localhost:8080",
    )
    assert result is None
    assert answer == text
