"""Citation allowlist — metadata JSON keys must not be citable."""
from app.loop import NON_CITABLE_AGG_NAMES, _is_citable_agg, _normalize_agg_ref


def test_metadata_fields_not_citable():
    for name in NON_CITABLE_AGG_NAMES:
        assert not _is_citable_agg(name)


def test_data_agg_keys_remain_citable():
    assert _is_citable_agg("total_matching")
    assert _is_citable_agg("by")
    assert _is_citable_agg("timeline")
    assert _is_citable_agg("count_alerts")


def test_normalize_agg_ref_still_aliases_total_matching():
    assert _normalize_agg_ref("total_matching=301") == "total_matching"
