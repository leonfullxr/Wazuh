#!/usr/bin/env python3
"""Aggregate compatible, independently observed staging gate evidence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from scripts.staging.aggregation import aggregate_results, load_gate_result
from scripts.staging.reload import reload_qualification


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", nargs="+", type=Path, help="per-gate evidence JSON files")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--reload-clients-config", type=Path)
    parser.add_argument("--session-id")
    parser.add_argument("--invocation-id")
    parser.add_argument("--run-id", action="append", default=[])
    args = parser.parse_args(argv)
    try:
        results = tuple(load_gate_result(path) for path in args.evidence)
        reload_requested = any(
            (args.reload_clients_config, args.session_id, args.invocation_id, args.run_id)
        )
        if reload_requested:
            if not all(
                (args.reload_clients_config, args.session_id, args.invocation_id, args.run_id)
            ):
                raise ValueError(
                    "reload requires --reload-clients-config, --session-id, "
                    "--invocation-id and one or more --run-id values"
                )
            results = reload_qualification(
                results,
                clients_config=args.reload_clients_config,
                session_id=args.session_id,
                invocation_id=args.invocation_id,
                run_ids=tuple(args.run_id),
            )
        summary = aggregate_results(results)
        output = args.output
        if output is None:
            parents = {path.parent.resolve() for path in args.evidence}
            if len(parents) != 1:
                raise ValueError(
                    "--output is required when evidence files use different directories"
                )
            output = next(iter(parents)) / "lv1-summary.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        document = {
            "schema_version": "1",
            "qualification": "LV-1",
            **summary.to_dict(),
        }
        with output.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(document, indent=2, sort_keys=True) + "\n")
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(f"{summary.status}: LV-1 summary written to {output}", file=sys.stderr)
    return 0 if summary.status == "PASS" else (1 if summary.status == "FAIL" else 2)


if __name__ == "__main__":
    raise SystemExit(main())
