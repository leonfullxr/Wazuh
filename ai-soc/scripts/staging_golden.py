#!/usr/bin/env python3
"""Fail-closed staging gate and deterministic nightly golden aggregation."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import uuid4

from botocore.exceptions import BotoCoreError
from pydantic import ValidationError

from scripts.staging.adapters import build_gate_adapters, run_live_gate
from scripts.staging.aws_clients import build_explicit_staging_aws, load_aws_client_config
from scripts.staging.clients import StagingClients
from scripts.staging.evidence import write_evidence
from scripts.staging.manifest import manifest_sha256, parse_manifest
from scripts.staging.models import exit_code_for
from scripts.staging.nightly_eval import (
    CaseOutcome,
    CaseResult,
    NightlyResult,
    ReviewedBaseline,
    evaluate_nightly,
)

ROOT = Path(__file__).resolve().parents[1]

__all__ = [
    "CaseOutcome",
    "CaseResult",
    "NightlyResult",
    "ReviewedBaseline",
    "evaluate_nightly",
    "main",
    "run_live_gate",
]


def _manifest_label(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.name


def _runner_commands(
    manifest_label: str, evidence_label: str, run_id: str, client_config_label: str | None
) -> tuple[str, ...]:
    command = (
        "uv run --locked python scripts/staging_golden.py "
        f"--manifest {manifest_label} --evidence {evidence_label} --run-id {run_id}"
    )
    if client_config_label is not None:
        command += f" --clients-config {client_config_label}"
    return (command,)


def main(argv: list[str] | None = None, *, clients: StagingClients | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--clients-config", type=Path)
    parser.add_argument("--run-id")
    args = parser.parse_args(argv)
    manifest = args.manifest if args.manifest.is_absolute() else ROOT / args.manifest
    run_id = args.run_id or (datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{7,95}", run_id):
        parser.error("--run-id must be 8-96 safe filename characters")
    run_dir = ROOT / "build/evidence/live" / run_id
    evidence_was_explicit = args.evidence is not None
    evidence = args.evidence
    if evidence is None:
        evidence = run_dir / "unconfigured.json"
    elif not evidence.is_absolute():
        evidence = ROOT / evidence
    client_config = args.clients_config
    if client_config is not None and not client_config.is_absolute():
        client_config = ROOT / client_config
    manifest_label = _manifest_label(manifest)
    evidence_label = _manifest_label(evidence)
    config_label = _manifest_label(client_config) if client_config is not None else None
    if not manifest.is_file():
        write_evidence(
            evidence,
            status="NOT_CONFIGURED",
            reason=f"required protected staging manifest is absent: {manifest_label}",
            result=None,
        )
        print(f"NOT_CONFIGURED: {manifest_label} is absent", file=sys.stderr)
        return 2

    try:
        raw: object = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        write_evidence(
            evidence,
            status="FAIL",
            reason=f"manifest unreadable: {type(exc).__name__}",
            result=None,
        )
        print("FAIL: staging manifest is unreadable", file=sys.stderr)
        return 1

    try:
        schema_version, parsed = parse_manifest(raw)
    except ValidationError as exc:
        issues = exc.errors(include_input=False)
        details = "; ".join(
            f"{'.'.join(str(part) for part in issue['loc'])}: {issue['msg']}" for issue in issues
        )
        reason = f"manifest validation failed: {details}"
        write_evidence(evidence, status="FAIL", reason=reason, result=None)
        print(f"FAIL: {reason}", file=sys.stderr)
        return 1
    except ValueError as exc:
        write_evidence(evidence, status="FAIL", reason=str(exc), result=None)
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    if schema_version in {"1", "2"}:
        write_evidence(
            evidence,
            status="NOT_RUN",
            reason=(
                f"staging manifest schema {schema_version} is legacy and cannot certify live gates"
            ),
            result=None,
        )
        print(f"NOT_RUN: staging manifest schema {schema_version} is legacy", file=sys.stderr)
        return 2

    if parsed is None:
        write_evidence(
            evidence,
            status="FAIL",
            reason="unsupported staging manifest schema",
            result=None,
        )
        print("FAIL: unsupported staging manifest schema", file=sys.stderr)
        return 1

    if not evidence_was_explicit:
        evidence = run_dir / f"{parsed.gate_id.value}.json"
        evidence_label = _manifest_label(evidence)
    if evidence.exists():
        print(f"FAIL: refusing to overwrite evidence output {evidence_label}", file=sys.stderr)
        return 1

    manifest_hash = manifest_sha256(cast(dict[str, object], raw))
    active_clients = clients or StagingClients()
    if clients is None and client_config is not None:
        try:
            config = load_aws_client_config(client_config)
            configured = build_explicit_staging_aws(config)
            active_clients = StagingClients(
                observer=configured.observer,
                aws=configured.clients,
                nightly=configured.nightly,
                network=configured.network,
                adapters=build_gate_adapters(config.adapters),
            )
        except (
            OSError,
            ValueError,
            BotoCoreError,
            ImportError,
            AttributeError,
            TypeError,
            json.JSONDecodeError,
        ) as exc:
            write_evidence(
                evidence,
                status="NOT_CONFIGURED",
                reason=f"AWS client configuration is unavailable: {type(exc).__name__}",
                result=None,
            )
            print("NOT_CONFIGURED: explicit AWS client configuration is invalid", file=sys.stderr)
            return 2
    gate_result = run_live_gate(
        parsed,
        manifest_hash=manifest_hash,
        runner_commands=_runner_commands(manifest_label, evidence_label, run_id, config_label),
        clients=active_clients,
    )
    reason = (
        gate_result.results.get(
            "reason", gate_result.results.get("certification_error", gate_result.status)
        )
        if isinstance(
            gate_result.results.get("reason", gate_result.results.get("certification_error")),
            str,
        )
        else gate_result.status
    )
    write_evidence(
        evidence,
        status=gate_result.status,
        reason=str(reason),
        result=gate_result,
    )
    print(f"{gate_result.status}: {reason}", file=sys.stderr)
    return exit_code_for(gate_result.status)


if __name__ == "__main__":
    raise SystemExit(main())
