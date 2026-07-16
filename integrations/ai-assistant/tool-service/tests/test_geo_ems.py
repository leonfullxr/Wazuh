"""EMS / GeoIP country name alignment for region maps."""
from app.actions.fields import FIELD_COUNTRY_ISO2
from app.actions.geo_ems import (
    country_iso2_index_pattern_field_row,
    country_name_to_iso2_painless_source,
    pick_geo_country_field,
)


def test_iso_script_maps_united_states():
    source = country_name_to_iso2_painless_source()
    assert "United States" in source
    assert "return 'US'" in source


def test_index_pattern_field_row_is_scripted_aggregatable():
    row = country_iso2_index_pattern_field_row()
    assert row["name"] == FIELD_COUNTRY_ISO2
    assert row["scripted"] is True
    assert row["aggregatable"] is True
    assert row["script"]


def test_pick_geo_prefers_scripted_iso2_on_stock_wazuh():
    agg = {"GeoLocation.country_name", FIELD_COUNTRY_ISO2}
    field, join = pick_geo_country_field(agg, agg)
    assert field == FIELD_COUNTRY_ISO2
    assert join == "iso2"
