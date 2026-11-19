"""Bounded operator command for loading live-approved knowledge into one site."""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

from ai_soc.workspace.db import site_transaction
from ai_soc.workspace.knowledge import load_knowledge_pack, verify_live_knowledge_pack
from ai_soc.workspace.runtime import PipelineRuntime, load_pipeline_config


def _instant(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an ISO 8601 timestamp with an offset") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise argparse.ArgumentTypeError("must be an ISO 8601 timestamp with an offset")
    return parsed.astimezone(UTC)


def _absolute_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("must be an absolute path")
    return path


def _digest(value: str) -> str:
    if (
        len(value) != 64
        or not value.isascii()
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise argparse.ArgumentTypeError("must be a lowercase SHA-256 digest")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ai-soc-knowledge")
    commands = parser.add_subparsers(dest="command", required=True)
    load = commands.add_parser("load", help="load a verified live-approved content pack")
    load.add_argument("--config", type=_absolute_path, required=True)
    load.add_argument("--site", required=True)
    load.add_argument("--pack", type=_absolute_path, required=True)
    load.add_argument("--expected-pack-sha256", type=_digest, required=True)
    load.add_argument(
        "--loaded-at",
        type=_instant,
        help="explicit replay cutoff; defaults to the current UTC instant",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    loaded_at = args.loaded_at or datetime.now(UTC)
    try:
        verified_pack = verify_live_knowledge_pack(
            args.pack, expected_pack_sha256=args.expected_pack_sha256
        )
        config = load_pipeline_config(args.config)
        sites = frozenset(site.site_id for site in config.sites)
        if args.site not in sites:
            raise PermissionError("site is not authorized by the protected workspace config")
        with PipelineRuntime(config, trust_env=False) as runtime, runtime.connect() as conn:
            with site_transaction(conn, args.site, sites):
                chunks = load_knowledge_pack(
                    conn,
                    site_id=args.site,
                    pack=args.pack,
                    loaded_at=loaded_at,
                    verified_pack=verified_pack,
                )
        print(
            f"LOADED site={args.site} chunks={chunks} "
            f"content_sha={verified_pack.manifest.content_sha} "
            f"pack_sha256={verified_pack.manifest.pack_sha256}"
        )
    except (OSError, PermissionError, ValueError):
        print("ERROR: live-approved knowledge load failed", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
