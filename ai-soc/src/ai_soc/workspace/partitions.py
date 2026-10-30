"""Create alert partitions with the separate database maintenance identity."""

from __future__ import annotations

import argparse
import os
from datetime import date, timedelta
from typing import Any

import psycopg


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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from", dest="start", type=date.fromisoformat, required=True)
    parser.add_argument("--to", dest="end", type=date.fromisoformat, required=True)
    args = parser.parse_args()
    dsn = os.environ.get("WS_DATABASE_URL")
    if not dsn:
        parser.error("WS_DATABASE_URL must reference the maintenance identity")
    with psycopg.connect(dsn) as conn:
        count = ensure_partitions(conn, args.start, args.end)
    print(f"provisioned {count} daily partition(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
