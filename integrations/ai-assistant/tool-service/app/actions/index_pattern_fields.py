"""Index-pattern helpers for dashboard visualizations."""
from __future__ import annotations

import base64
import json
from typing import Any

import httpx

from ..config import CFG
from ..env_registry import EnvConfig
from .fields import FIELD_COUNTRY_ISO2
from .geo_ems import country_iso2_index_pattern_field_row


def _basic_header(user_pass: str) -> dict[str, str]:
    token = base64.b64encode(user_pass.encode()).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def _dashboard_headers(env: EnvConfig) -> dict[str, str] | None:
    if not env.dashboard_executor_basic:
        return None
    return {
        **_basic_header(env.dashboard_executor_basic),
        "osd-xsrf": "true",
        "Content-Type": "application/json",
    }


def _dashboard_verify(env: EnvConfig) -> object:
    return env.indexer_ca_path or CFG.indexer_verify_ssl


def parse_index_pattern_field_sets(
    attributes: dict[str, Any],
) -> tuple[set[str], set[str]]:
    """Return (all field names, aggregatable field names) from index-pattern attrs."""
    raw_fields = attributes.get("fields", "[]")
    try:
        field_rows = json.loads(raw_fields) if isinstance(raw_fields, str) else raw_fields
    except json.JSONDecodeError:
        return set(), set()
    names: set[str] = set()
    aggregatable: set[str] = set()
    for row in field_rows:
        if not isinstance(row, dict):
            continue
        name = row.get("name")
        if not name:
            continue
        names.add(name)
        if row.get("aggregatable"):
            aggregatable.add(name)
    return names, aggregatable


async def load_index_pattern_fields_from_dashboard(
    env: EnvConfig,
    pattern_id: str = "wazuh-alerts-*",
) -> tuple[set[str], set[str]]:
    """Load index-pattern fields via the Dashboards API (includes scripted fields)."""
    base = (env.dashboard_api_url or "").rstrip("/")
    headers = _dashboard_headers(env)
    if not base or not headers:
        return set(), set()

    async with httpx.AsyncClient(verify=_dashboard_verify(env), timeout=30.0) as client:
        try:
            r = await client.get(
                f"{base}/api/saved_objects/index-pattern/{pattern_id}",
                headers=headers,
            )
        except httpx.HTTPError:
            return set(), set()
        if r.status_code not in (200, 201):
            return set(), set()
        return parse_index_pattern_field_sets(r.json().get("attributes", {}))


def bundle_has_region_map(objects: list[dict[str, Any]]) -> bool:
    for obj in objects:
        doc = obj.get("document", {})
        if doc.get("type") != "visualization":
            continue
        try:
            state = json.loads(doc.get("visualization", {}).get("visState", "{}"))
        except json.JSONDecodeError:
            continue
        if state.get("type") == "region_map":
            return True
    return False


async def ensure_country_iso2_scripted_field(
    env: EnvConfig,
    pattern_id: str = "wazuh-alerts-*",
) -> bool:
    """Register GeoLocation.country_iso2 on the OSD index pattern (idempotent).

    Region maps need ISO2 bucket keys for the EMS join. Stock Wazuh has
    country_name (keyword) and country_code2 (text). A scripted index-pattern
    field is the reliable path — inline visState scripts cannot omit ``field``
    (OSD requires it) and field+script is value-script mode.
    """
    base = (env.dashboard_api_url or "").rstrip("/")
    headers = _dashboard_headers(env)
    if not base or not headers:
        return False

    async with httpx.AsyncClient(verify=_dashboard_verify(env), timeout=30.0) as client:
        try:
            r = await client.get(
                f"{base}/api/saved_objects/index-pattern/{pattern_id}",
                headers=headers,
            )
        except httpx.HTTPError:
            return False
        if r.status_code == 404:
            return False
        if r.status_code not in (200, 201):
            return False

        saved = r.json()
        attrs = dict(saved.get("attributes", {}))
        names, _agg = parse_index_pattern_field_sets(attrs)
        if FIELD_COUNTRY_ISO2 in names:
            return True

        raw_fields = attrs.get("fields", "[]")
        try:
            fields = json.loads(raw_fields) if isinstance(raw_fields, str) else list(raw_fields)
        except json.JSONDecodeError:
            return False

        fields.append(country_iso2_index_pattern_field_row())
        attrs["fields"] = json.dumps(fields)
        payload: dict[str, Any] = {"attributes": attrs}
        version = saved.get("version")
        if version:
            payload["version"] = version

        try:
            put = await client.put(
                f"{base}/api/saved_objects/index-pattern/{pattern_id}",
                headers=headers,
                json=payload,
            )
        except httpx.HTTPError:
            return False
        if put.status_code not in (200, 201):
            return False

        try:
            verify = await client.get(
                f"{base}/api/saved_objects/index-pattern/{pattern_id}",
                headers=headers,
            )
        except httpx.HTTPError:
            return False
        if verify.status_code not in (200, 201):
            return False
        verify_names, _ = parse_index_pattern_field_sets(verify.json().get("attributes", {}))
        return FIELD_COUNTRY_ISO2 in verify_names
