"""Index-pattern scripted field registration."""
import asyncio
import json

import httpx

from app.actions.dashboard_templates import build_dashboard_bundle
from app.actions.fields import FIELD_COUNTRY_ISO2
from app.actions.index_pattern_fields import (
    bundle_has_region_map,
    ensure_country_iso2_scripted_field,
    parse_index_pattern_field_sets,
)
from app.actions.schemas import CreateDashboardParams
from app.env_registry import EnvConfig


class _Resp:
    def __init__(self, status_code: int, payload: dict | None = None) -> None:
        self.status_code = status_code
        self._payload = payload or {}

    def json(self) -> dict:
        return self._payload


def test_ensure_country_iso2_adds_scripted_field(monkeypatch):
    env = EnvConfig(
        env_id="lab",
        gateway_key="k",
        indexer_url="https://indexer:9200",
        dashboard_api_url="https://dashboard:5601",
        dashboard_executor_basic="writer:secret",
    )
    fields = [{"name": "GeoLocation.country_name", "aggregatable": True}]
    put_body: dict = {}
    get_calls = {"n": 0}

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, url, headers=None):
            get_calls["n"] += 1
            if get_calls["n"] == 1:
                return _Resp(200, {"version": "v1", "attributes": {"fields": json.dumps(fields)}})
            saved = json.loads(put_body["attributes"]["fields"])
            return _Resp(200, {"attributes": {"fields": json.dumps(saved)}})

        async def put(self, url, headers=None, json=None):
            put_body.update(json or {})
            return _Resp(200, {"id": "wazuh-alerts-*"})

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: _Client())

    assert asyncio.run(ensure_country_iso2_scripted_field(env)) is True
    assert put_body.get("version") == "v1"
    saved_fields = json.loads(put_body["attributes"]["fields"])
    iso = next(f for f in saved_fields if f["name"] == FIELD_COUNTRY_ISO2)
    assert iso["scripted"] is True
    assert iso["aggregatable"] is True


def test_ensure_country_iso2_idempotent_when_present(monkeypatch):
    env = EnvConfig(
        env_id="lab",
        gateway_key="k",
        indexer_url="https://indexer:9200",
        dashboard_api_url="https://dashboard:5601",
        dashboard_executor_basic="writer:secret",
    )
    fields = [
        {"name": "GeoLocation.country_name"},
        {"name": FIELD_COUNTRY_ISO2, "scripted": True},
    ]
    put_called = False

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, url, headers=None):
            return _Resp(200, {"attributes": {"fields": json.dumps(fields)}})

        async def put(self, url, headers=None, json=None):
            nonlocal put_called
            put_called = True
            return _Resp(200, {})

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: _Client())

    assert asyncio.run(ensure_country_iso2_scripted_field(env)) is True
    assert put_called is False


def test_parse_index_pattern_field_sets_includes_scripted():
    names, agg = parse_index_pattern_field_sets(
        {
            "fields": json.dumps(
                [
                    {"name": "GeoLocation.country_name", "aggregatable": True},
                    {
                        "name": FIELD_COUNTRY_ISO2,
                        "scripted": True,
                        "aggregatable": True,
                    },
                ]
            )
        }
    )
    assert FIELD_COUNTRY_ISO2 in names
    assert FIELD_COUNTRY_ISO2 in agg


def test_brute_force_bundle_triggers_region_map_detection():
    objects = build_dashboard_bundle(
        CreateDashboardParams(title="BF", template="brute_force_geoip")
    )
    assert bundle_has_region_map(objects)


def test_degrade_region_maps_substitutes_country_table():
    from app.actions.index_pattern_fields import degrade_region_maps_in_bundle
    from app.actions.fields import FIELD_COUNTRY

    objects = build_dashboard_bundle(
        CreateDashboardParams(title="BF", template="brute_force_geoip")
    )
    notes = degrade_region_maps_in_bundle(objects)
    assert notes
    assert not bundle_has_region_map(objects)
    joined = json.dumps(objects)
    assert FIELD_COUNTRY in joined
    assert "table fallback" in joined
