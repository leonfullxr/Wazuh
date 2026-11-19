"""Prepare workspace sites and alert partitions with the maintenance identity."""

from __future__ import annotations

import argparse
import os
import sys
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import psycopg

from ai_soc.workspace.runtime import PipelineSite, load_pipeline_config


def ensure_partitions(conn: psycopg.Connection[Any], start: date, end: date) -> int:
    """Provision a bounded half-open date interval before ingestion/backfill."""
    if not 0 < (end - start).days <= 366:
        raise ValueError("partition maintenance requires a range of 1..366 days")
    owns = conn.execute(
        "SELECT c.relowner = r.oid OR r.rolsuper FROM pg_class c "
        "JOIN pg_roles r ON r.rolname = current_user WHERE c.oid = 'public.alerts'::regclass"
    ).fetchone()
    if owns is None or not owns[0]:
        raise PermissionError("partition maintenance requires the separate schema owner")
    for offset in range((end - start).days):
        conn.execute("SELECT public.ensure_alert_partition(%s)", (start + timedelta(days=offset),))
    return (end - start).days


def _register_site(conn: psycopg.Connection[Any], site: PipelineSite) -> None:
    conn.execute("SELECT set_config('app.site_id', %s, true)", (site.site_id,))
    row = conn.execute(
        """
        INSERT INTO public.sites (site_id, label, wazuh_version) VALUES (%s, %s, %s)
        ON CONFLICT (site_id) DO UPDATE
        SET label = excluded.label, wazuh_version = excluded.wazuh_version
        WHERE sites.wazuh_version IS NULL OR sites.wazuh_version = excluded.wazuh_version
        RETURNING site_id
        """,
        (site.site_id, site.label, site.wazuh_version),
    ).fetchone()
    if row is None:
        raise ValueError("registered site has a different Wazuh version")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from", dest="start", type=date.fromisoformat, required=True)
    parser.add_argument("--to", dest="end", type=date.fromisoformat, required=True)
    parser.add_argument("--site", help="register this site from WS_WORKER_CONFIG")
    args = parser.parse_args()
    dsn = os.environ.get("WS_DATABASE_URL")
    if not dsn:
        parser.error("WS_DATABASE_URL must reference the maintenance identity")
    site = None
    try:
        if args.site is not None:
            config_path = os.environ.get("WS_WORKER_CONFIG")
            if not config_path:
                parser.error("--site requires WS_WORKER_CONFIG")
            config = load_pipeline_config(Path(config_path))
            site = next((item for item in config.sites if item.site_id == args.site), None)
            if site is None:
                parser.error("site is absent from WS_WORKER_CONFIG")
        with psycopg.connect(dsn) as conn:
            count = ensure_partitions(conn, args.start, args.end)
            if site is not None:
                _register_site(conn, site)
    except (ValueError, PermissionError) as error:
        print(f"workspace maintenance failed: {error}", file=sys.stderr)
        return 2
    except psycopg.Error as error:
        print(f"workspace maintenance failed: {type(error).__name__}", file=sys.stderr)
        return 2
    print(f"provisioned {count} daily partition(s)")
    if site is not None:
        print("workspace site registered")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
