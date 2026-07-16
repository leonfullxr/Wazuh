"""Field resolver unit tests."""
import json

from app.actions.field_resolver import (
    resolve_field,
    validate_and_resolve_bundle_fields,
)
from app.actions.fields import FIELD_COUNTRY_ISO2


def test_resolve_field_prefers_exact_match():
    known = {"data.dstuser", "GeoLocation.country_name", "data.srcip.keyword"}
    assert resolve_field("data.dstuser", known) == "data.dstuser"
    assert resolve_field("data.srcip", known) == "data.srcip.keyword"


def test_resolve_field_rejects_unknown():
    try:
        resolve_field("data.missing", {"data.dstuser"})
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "data.missing" in str(exc)


def test_validate_rewrites_keyword_suffix_in_bundle():
    objects = [
        {
            "document": {
                "type": "visualization",
                "visualization": {
                    "visState": (
                        '{"aggs":[{"params":{"field":"GeoLocation.country_name.keyword"}}]}'
                    ),
                },
            }
        }
    ]
    known = {"GeoLocation.country_name", "data.dstuser"}
    resolved = validate_and_resolve_bundle_fields(objects, known)
    assert resolved == {"GeoLocation.country_name.keyword": "GeoLocation.country_name"}
    state = objects[0]["document"]["visualization"]["visState"]
    assert "GeoLocation.country_name.keyword" not in state
    assert "GeoLocation.country_name" in state


def test_region_map_uses_iso_join_when_code2_aggregatable():
    from app.actions.dashboard_templates import build_dashboard_bundle
    from app.actions.schemas import CreateDashboardParams

    objects = build_dashboard_bundle(
        CreateDashboardParams(title="BF", template="brute_force_geoip")
    )
    known = {
        "GeoLocation.country_code2",
        "GeoLocation.country_name",
        FIELD_COUNTRY_ISO2,
        "data.dstuser",
        "data.srcip",
        "timestamp",
        "rule.level",
        "rule.id",
        "rule.mitre.id",
        "agent.name",
    }
    aggregatable = known | {"GeoLocation.country_code2"}
    validate_and_resolve_bundle_fields(objects, known, aggregatable)
    vis = json.loads(
        next(
            o["document"]["visualization"]["visState"]
            for o in objects
            if json.loads(o["document"]["visualization"]["visState"]).get("type")
            == "region_map"
        )
    )
    assert vis["aggs"][0]["params"]["field"] == "GeoLocation.country_code2"
    assert vis["params"]["selectedJoinField"]["name"] == "iso2"
    assert "script" not in vis["aggs"][0]["params"]


def test_region_map_uses_scripted_iso2_on_stock_wazuh():
    from app.actions.dashboard_templates import build_dashboard_bundle
    from app.actions.schemas import CreateDashboardParams

    objects = build_dashboard_bundle(
        CreateDashboardParams(title="BF", template="brute_force_geoip")
    )
    known = {
        "GeoLocation.country_code2",
        "GeoLocation.country_name",
        FIELD_COUNTRY_ISO2,
        "data.dstuser",
        "data.srcip",
        "timestamp",
        "rule.level",
        "rule.id",
        "rule.mitre.id",
        "agent.name",
    }
    aggregatable = {
        FIELD_COUNTRY_ISO2,
        "GeoLocation.country_name",
        "data.dstuser",
        "data.srcip",
        "timestamp",
        "rule.level",
        "rule.id",
        "rule.mitre.id",
        "agent.name",
    }
    validate_and_resolve_bundle_fields(objects, known, aggregatable)
    vis = json.loads(
        next(
            o["document"]["visualization"]["visState"]
            for o in objects
            if json.loads(o["document"]["visualization"]["visState"]).get("type")
            == "region_map"
        )
    )
    assert vis["params"]["selectedJoinField"]["name"] == "iso2"
    params = vis["aggs"][0]["params"]
    assert params["field"] == FIELD_COUNTRY_ISO2
    assert "script" not in params


def test_region_map_uses_code2_keyword_when_aggregatable():
    from app.actions.dashboard_templates import build_dashboard_bundle
    from app.actions.schemas import CreateDashboardParams

    objects = build_dashboard_bundle(
        CreateDashboardParams(title="BF", template="brute_force_geoip")
    )
    known = {
        "GeoLocation.country_code2",
        "GeoLocation.country_code2.keyword",
        "GeoLocation.country_name",
        FIELD_COUNTRY_ISO2,
        "data.dstuser",
        "data.srcip",
        "timestamp",
        "rule.level",
        "rule.id",
        "rule.mitre.id",
        "agent.name",
    }
    aggregatable = {
        "GeoLocation.country_code2.keyword",
        "GeoLocation.country_name",
        "data.dstuser",
        "data.srcip",
        "timestamp",
        "rule.level",
        "rule.id",
        "rule.mitre.id",
        "agent.name",
    }
    validate_and_resolve_bundle_fields(objects, known, aggregatable)
    vis = json.loads(
        next(
            o["document"]["visualization"]["visState"]
            for o in objects
            if json.loads(o["document"]["visualization"]["visState"]).get("type")
            == "region_map"
        )
    )
    assert vis["aggs"][0]["params"]["field"] == "GeoLocation.country_code2.keyword"
    assert vis["params"]["selectedJoinField"]["name"] == "iso2"
    assert "script" not in vis["aggs"][0]["params"]
