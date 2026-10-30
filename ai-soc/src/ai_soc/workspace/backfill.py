"""Explicit-site backfill entry point over the normal poller insert path.

Runtime wiring supplies an authorized site, worker-only reader and database
connection. This module never discovers sites or credentials implicitly.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

import psycopg

from ai_soc.workspace.ingest.indexer_reader import Reader
from ai_soc.workspace.ingest.poller import IngestResult, backfill
from ai_soc.workspace.normalize.models import MappingProfile


@dataclass(frozen=True, slots=True)
class BackfillSite:
    site_id: str
    authorized_sites: frozenset[str]
    index_pattern: str
    profile: MappingProfile
    reader: Reader


class BackfillRuntime(Protocol):
    def resolve_site(self, site_id: str) -> BackfillSite: ...

    def connect(self) -> AbstractContextManager[psycopg.Connection[Any]]:
        """Yield a dedicated connection with autocommit enabled for page commits."""
        ...


def run_backfill(
    *,
    runtime: BackfillRuntime,
    site_id: str,
    start: datetime,
    end: datetime,
    page_size: int = 500,
) -> IngestResult:
    site = runtime.resolve_site(site_id)
    if site.site_id != site_id or site_id not in site.authorized_sites:
        raise PermissionError("backfill runtime did not authorize the explicit site")
    with runtime.connect() as conn:
        return backfill(
            conn,
            site_id=site.site_id,
            authorized_sites=site.authorized_sites,
            reader=site.reader,
            index_pattern=site.index_pattern,
            profile=site.profile,
            start=start,
            end=end,
            page_size=page_size,
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Backfill alerts for one explicit Wazuh site")
    parser.add_argument("--site", required=True, help="configured site id")
    parser.add_argument("--from", dest="start", required=True, type=parse_datetime)
    parser.add_argument("--to", dest="end", required=True, type=parse_datetime)
    parser.add_argument("--page-size", type=int, default=500)
    return parser


def run_cli(
    argv: Sequence[str] | None,
    *,
    runtime: BackfillRuntime,
    write: Callable[[str], None] = print,
) -> int:
    args = build_parser().parse_args(argv)
    result = run_backfill(
        runtime=runtime,
        site_id=args.site,
        start=args.start,
        end=args.end,
        page_size=args.page_size,
    )
    write(
        " ".join(
            (
                f"run_id={result.run_id}",
                f"site_id={args.site}",
                f"read={result.read_count}",
                f"inserted={result.inserted_count}",
                f"duplicates={result.duplicate_count}",
                f"mutations={result.mutation_count}",
                f"outcome={result.outcome}",
            )
        )
    )
    return 0


def parse_datetime(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timestamp must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise argparse.ArgumentTypeError("timestamp must include an explicit timezone")
    return parsed.astimezone(UTC)


def main() -> int:
    import os
    from pathlib import Path

    from ai_soc.workspace.runtime import PipelineRuntime, load_pipeline_config

    source = os.environ.get("WS_WORKER_CONFIG")
    if not source:
        build_parser().error("WS_WORKER_CONFIG must reference an explicit pipeline configuration")
    with PipelineRuntime(load_pipeline_config(Path(source))) as runtime:
        return run_cli(None, runtime=runtime)


if __name__ == "__main__":
    raise SystemExit(main())
