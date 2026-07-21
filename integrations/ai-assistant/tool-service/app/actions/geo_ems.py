"""Map GeoLocation.country_name values to ISO-3166 alpha-2 for EMS region maps.

OSD region maps always join EMS World Countries on ``iso2``. Stock Wazuh cannot
aggregate on ``country_code2`` (text). We register a scripted index-pattern field
``GeoLocation.country_iso2`` and aggregate on that — inline visState scripts are
not viable (OSD requires ``field``; field+script is value-script mode).
"""
from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import Any

from .fields import FIELD_COUNTRY, FIELD_COUNTRY_ISO2

_MAP_PATH = "country_name_to_iso2.json"


@lru_cache(maxsize=1)
def _country_name_to_iso2() -> dict[str, str]:
    raw = resources.files(__package__).joinpath(_MAP_PATH).read_text(encoding="utf-8")
    data: dict[str, str] = json.loads(raw)
    return data


def country_name_to_iso2_painless_source(field: str = FIELD_COUNTRY) -> str:
    """Painless source: keyword country_name -> ISO2 (index-pattern scripted field)."""
    lines = [
        f"if (doc['{field}'].size() == 0) return '';",
        f"def n = doc['{field}'].value;",
    ]
    for name, iso2 in sorted(
        _country_name_to_iso2().items(), key=lambda item: len(item[0]), reverse=True
    ):
        if not iso2 or iso2 == "-99":
            continue
        name_esc = name.replace("\\", "\\\\").replace("'", "\\'")
        iso_esc = iso2.replace("\\", "\\\\").replace("'", "\\'")
        lines.append(f"if (n == '{name_esc}') return '{iso_esc}';")
    lines.append("return '';")
    return " ".join(lines)


def country_iso2_index_pattern_field_row() -> dict[str, Any]:
    """OSD index-pattern scripted field row for wazuh-alerts-*."""
    return {
        "count": 0,
        "name": FIELD_COUNTRY_ISO2,
        "type": "string",
        "esTypes": ["keyword"],
        "scripted": True,
        "searchable": True,
        "aggregatable": True,
        "readFromDocValues": False,
        "lang": "painless",
        "script": country_name_to_iso2_painless_source(),
    }


def pick_geo_country_field(
    known: set[str] | None = None,
    aggregatable: set[str] | None = None,
) -> tuple[str, str]:
    """Return (terms_field, ems_join_field) for region maps."""
    agg = aggregatable if aggregatable is not None else set()
    for candidate in (
        "GeoLocation.country_code2",
        "GeoLocation.country_code2.keyword",
    ):
        if candidate in agg:
            return candidate, "iso2"
    if FIELD_COUNTRY_ISO2 in agg:
        return FIELD_COUNTRY_ISO2, "iso2"
    raise ValueError(
        f"{FIELD_COUNTRY_ISO2!r} is not on the wazuh-alerts-* index pattern — "
        "region maps require the scripted ISO2 field"
    )
