"""Wazuh alerts index-pattern field names (wazuh-alerts-*, OSD 2.19).

These are keyword/geo fields on the stock template — do not append `.keyword`.
"""
from __future__ import annotations

FIELD_TIMESTAMP = "timestamp"
FIELD_COUNTRY = "GeoLocation.country_name"
FIELD_COUNTRY_CODE2 = "GeoLocation.country_code2"
FIELD_COUNTRY_CODE2_KEYWORD = "GeoLocation.country_code2.keyword"
FIELD_COUNTRY_ISO2 = "GeoLocation.country_iso2"
FIELD_GEO_POINT = "GeoLocation.location"
FIELD_DST_USER = "data.dstuser"
FIELD_SRC_IP = "data.srcip"
FIELD_AGENT = "agent.name"
FIELD_RULE_ID = "rule.id"
FIELD_RULE_LEVEL = "rule.level"
FIELD_RULE_MITRE = "rule.mitre.id"
