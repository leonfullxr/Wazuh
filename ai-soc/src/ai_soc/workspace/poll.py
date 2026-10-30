"""Run the configured read-only sources through the durable fixed-window poller."""

from __future__ import annotations

import argparse
import json
import os
import time
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ai_soc.workspace.ingest.poller import poll_once
from ai_soc.workspace.ingest.reconcile import reconcile_hour
from ai_soc.workspace.runtime import PipelineRuntime, load_pipeline_config


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site", help="one configured site; defaults to all configured sites")
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--interval", type=int, default=60)
    parser.add_argument(
        "--reconcile", action="store_true", help="also reconcile the last closed hour"
    )
    args = parser.parse_args()
    source = os.environ.get("WS_WORKER_CONFIG")
    if not source:
        parser.error("WS_WORKER_CONFIG must reference the protected site configuration")
    if not 10 <= args.interval <= 3600:
        parser.error("poll interval must be in10..3600 seconds")
    config = load_pipeline_config(Path(source))
    configured = frozenset(site.site_id for site in config.sites)
    selected = configured if args.site is None else frozenset({args.site})
    if not selected <= configured:
        parser.error("poll site is not explicitly configured for this worker")
    last_reconciled: dict[str, datetime] = {}
    with PipelineRuntime(config) as runtime, runtime.connect() as conn:
        while True:
            now = datetime.now(UTC)
            for site_id in sorted(selected):
                site = runtime.resolve_site(site_id)
                result = poll_once(
                    conn,
                    site_id=site.site_id,
                    authorized_sites=site.authorized_sites,
                    reader=site.reader,
                    index_pattern=site.index_pattern,
                    profile=site.profile,
                    now=now,
                )
                print(json.dumps(asdict(result), default=str), flush=True)
                hour = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
                if args.reconcile and last_reconciled.get(site_id) != hour:
                    reconciliation = reconcile_hour(
                        conn,
                        site_id=site.site_id,
                        authorized_sites=site.authorized_sites,
                        reader=site.reader,
                        index_pattern=site.index_pattern,
                        profile=site.profile,
                        hour=hour,
                    )
                    print(json.dumps(asdict(reconciliation), default=str), flush=True)
                    if reconciliation.alarm:
                        return 1
                    last_reconciled[site_id] = hour
            if not args.watch:
                return 0
            time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
