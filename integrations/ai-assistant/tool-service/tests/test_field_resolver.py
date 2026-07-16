"""Field resolver unit tests."""
from app.actions.field_resolver import (
    resolve_field,
    validate_and_resolve_bundle_fields,
)


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
