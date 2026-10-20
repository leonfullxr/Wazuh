"""Command line interface for validating and building external content."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ai_soc.content.builder import (
    ContentBuildError,
    build_content_pack,
    validate_git_content,
    verify_content_pack,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ai-soc-content")
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("validate", "build"):
        child = commands.add_parser(command)
        child.add_argument("--source", type=Path, required=True)
        child.add_argument("--commit", required=True)
        child.add_argument("--attestation", type=Path, required=True)
        child.add_argument("--trust-root", type=Path, required=True)
        child.add_argument(
            "--fixture", action="store_true", help="accept an explicitly fixture-only approval"
        )
        if command == "build":
            child.add_argument("--out", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--pack", type=Path, required=True)
    verify.add_argument("--contract-version", default="1")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "validate":
            manifest, _, approval = validate_git_content(
                args.source,
                args.commit,
                args.attestation,
                args.trust_root,
                allow_fixture=args.fixture,
            )
            print(f"VALID content_sha={args.commit} repository={manifest.repository}")
            print(f"approval_key={approval.key_id}")
        elif args.command == "build":
            manifest = build_content_pack(
                args.source,
                args.commit,
                args.attestation,
                args.trust_root,
                args.out,
                allow_fixture=args.fixture,
            )
            print(f"BUILT content_sha={manifest.content_sha} pack_sha256={manifest.pack_sha256}")
            print(f"out={args.out}")
        else:
            verify_content_pack(args.pack, args.contract_version)
            print(f"VERIFIED pack={args.pack} contract_version={args.contract_version}")
    except (ContentBuildError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
