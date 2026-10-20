"""Run a bounded, synthetic Bedrock capability probe and write its evidence."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import boto3
from botocore.client import BaseClient
from botocore.config import Config

CAPABILITY_LABEL = "capability evidence only; does not qualify any live gate"
BENIGN_PROMPT = "Reply with the single word READY. This is a synthetic capability probe."
MAX_OUTPUT_TOKENS = 32
MAX_BLOCKED_PROMPT_CHARS = 512


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _request_id(response: dict[str, Any]) -> str | None:
    metadata = response.get("ResponseMetadata")
    if not isinstance(metadata, dict):
        return None
    request_id = metadata.get("RequestId")
    return request_id if isinstance(request_id, str) else None


def _usage(response: dict[str, Any]) -> dict[str, int] | None:
    raw = response.get("usage")
    if not isinstance(raw, dict):
        return None
    fields = ("inputTokens", "outputTokens", "totalTokens")
    if any(
        not isinstance(raw.get(field), int) or isinstance(raw.get(field), bool) or raw[field] < 0
        for field in fields
    ):
        return None
    return {field: raw[field] for field in fields}


def _usable_text(response: dict[str, Any]) -> bool:
    output = response.get("output")
    if not isinstance(output, dict):
        return False
    message = output.get("message")
    if not isinstance(message, dict):
        return False
    content = message.get("content")
    return isinstance(content, list) and any(
        isinstance(item, dict) and isinstance(item.get("text"), str) and bool(item["text"].strip())
        for item in content
    )


def _write_evidence(path: Path, evidence: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def run_probe(
    *,
    sts_client: BaseClient,
    runtime_client: BaseClient,
    region: str,
    model_id: str,
    count_model_id: str,
    guardrail_arn: str,
    guardrail_version: str,
    blocked_prompt: str,
    evidence_path: Path,
) -> tuple[dict[str, Any], bool]:
    """Call CountTokens, a guarded tiny Converse, and a configured block probe once each."""
    evidence: dict[str, Any] = {
        "evidence_type": CAPABILITY_LABEL,
        "started_at": utc_now(),
        "finished_at": None,
        "account_id": None,
        "caller_arn": None,
        "region": region,
        "model_id": model_id,
        "count_model_id": count_model_id,
        "guardrail_arn": guardrail_arn,
        "guardrail_version": guardrail_version,
        "calls": {},
        "outcome": "incomplete",
        "live_gates": "NOT_RUN",
    }
    succeeded = False
    try:
        identity = sts_client.get_caller_identity()
        evidence["account_id"] = identity.get("Account")
        evidence["caller_arn"] = identity.get("Arn")

        count_started = utc_now()
        count_response = runtime_client.count_tokens(
            modelId=count_model_id,
            input={
                "converse": {"messages": [{"role": "user", "content": [{"text": BENIGN_PROMPT}]}]}
            },
        )
        evidence["calls"]["count_tokens"] = {
            "started_at": count_started,
            "finished_at": utc_now(),
            "request_id": _request_id(count_response),
            "input_tokens": count_response.get("inputTokens"),
        }

        normal_started = utc_now()
        normal_response = runtime_client.converse(
            modelId=model_id,
            messages=[{"role": "user", "content": [{"text": BENIGN_PROMPT}]}],
            inferenceConfig={"maxTokens": MAX_OUTPUT_TOKENS, "temperature": 0},
            guardrailConfig={
                "guardrailIdentifier": guardrail_arn,
                "guardrailVersion": guardrail_version,
            },
        )
        normal_usage = _usage(normal_response)
        evidence["calls"]["guarded_converse"] = {
            "started_at": normal_started,
            "finished_at": utc_now(),
            "request_id": _request_id(normal_response),
            "stop_reason": normal_response.get("stopReason"),
            "usable_output": _usable_text(normal_response),
            "usage": normal_usage,
        }

        blocked_started = utc_now()
        blocked_response = runtime_client.converse(
            modelId=model_id,
            messages=[{"role": "user", "content": [{"text": blocked_prompt}]}],
            inferenceConfig={"maxTokens": 1, "temperature": 0},
            guardrailConfig={
                "guardrailIdentifier": guardrail_arn,
                "guardrailVersion": guardrail_version,
            },
        )
        blocked_usage = _usage(blocked_response)
        evidence["calls"]["guardrail_block"] = {
            "started_at": blocked_started,
            "finished_at": utc_now(),
            "request_id": _request_id(blocked_response),
            "stop_reason": blocked_response.get("stopReason"),
            "usage": blocked_usage,
        }

        succeeded = (
            isinstance(evidence["account_id"], str)
            and bool(evidence["account_id"])
            and bool(evidence["calls"]["count_tokens"]["request_id"])
            and isinstance(evidence["calls"]["count_tokens"]["input_tokens"], int)
            and not isinstance(evidence["calls"]["count_tokens"]["input_tokens"], bool)
            and evidence["calls"]["count_tokens"]["input_tokens"] >= 0
            and evidence["calls"]["guarded_converse"]["stop_reason"]
            in {"end_turn", "stop_sequence"}
            and evidence["calls"]["guarded_converse"]["usable_output"]
            and bool(evidence["calls"]["guarded_converse"]["request_id"])
            and evidence["calls"]["guarded_converse"]["usage"] is not None
            and evidence["calls"]["guardrail_block"]["stop_reason"] == "guardrail_intervened"
            and evidence["calls"]["guardrail_block"]["usage"]
            == {"inputTokens": 0, "outputTokens": 0, "totalTokens": 0}
            and bool(evidence["calls"]["guardrail_block"]["request_id"])
        )
        evidence["outcome"] = "passed" if succeeded else "failed"
        if not succeeded:
            evidence["failure"] = (
                "required response, request ID, or zero-token guardrail block was absent"
            )
    except (
        Exception
    ) as exc:  # Preserve partial evidence while keeping SDK errors out of the artifact.
        evidence["outcome"] = "failed"
        evidence["failure"] = type(exc).__name__
    finally:
        evidence["finished_at"] = utc_now()
        _write_evidence(evidence_path, evidence)
    return evidence, succeeded


def _positive_int(value: str) -> str:
    if not value.isdigit() or int(value) <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return value


def create_clients(region: str, profile: str | None = None) -> tuple[BaseClient, BaseClient]:
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    config = Config(
        connect_timeout=3,
        read_timeout=15,
        retries={"total_max_attempts": 1, "mode": "standard"},
        max_pool_connections=1,
    )
    return (
        session.client("sts", region_name=region, config=config),
        session.client("bedrock-runtime", region_name=region, config=config),
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", required=True)
    parser.add_argument(
        "--model-arn", required=True, help="exact account-scoped inference-profile ARN for Converse"
    )
    parser.add_argument(
        "--count-model-arn",
        required=True,
        help="regional foundation-model ARN (empty account segment) for native CountTokens",
    )
    parser.add_argument("--guardrail-arn", required=True)
    parser.add_argument("--guardrail-version", required=True, type=_positive_int)
    parser.add_argument(
        "--blocked-prompt",
        required=True,
        help="synthetic text that the published guardrail version is configured to block",
    )
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument(
        "--profile",
        help="optional AWS CLI profile; its credentials must already assume the probe role",
    )
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[a-z0-9-]+", args.region):
        parser.error("--region must be an AWS region name")
    if (
        not args.model_arn.strip()
        or not args.guardrail_arn.strip()
        or not args.blocked_prompt.strip()
    ):
        parser.error("model, guardrail, and blocked prompt must be non-empty")
    if len(args.blocked_prompt) > MAX_BLOCKED_PROMPT_CHARS:
        parser.error(f"--blocked-prompt must be at most {MAX_BLOCKED_PROMPT_CHARS} characters")
    profile_arn = re.fullmatch(
        rf"arn:aws[a-z-]*:bedrock:{re.escape(args.region)}:[0-9]{{12}}:(?:inference-profile|application-inference-profile)/.+",
        args.model_arn,
    )
    count_model_arn = re.fullmatch(
        rf"arn:aws[a-z-]*:bedrock:{re.escape(args.region)}::foundation-model/.+",
        args.count_model_arn,
    )
    if profile_arn is None:
        parser.error("--model-arn must be an account-scoped inference-profile ARN in --region")
    if count_model_arn is None:
        parser.error(
            "--count-model-arn must be a regional foundation-model ARN with an empty account"
        )
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    identity, runtime = create_clients(args.region, args.profile)
    evidence, succeeded = run_probe(
        sts_client=identity,
        runtime_client=runtime,
        region=args.region,
        model_id=args.model_arn,
        count_model_id=args.count_model_arn,
        guardrail_arn=args.guardrail_arn,
        guardrail_version=args.guardrail_version,
        blocked_prompt=args.blocked_prompt,
        evidence_path=args.evidence,
    )
    print(json.dumps({"outcome": evidence["outcome"], "evidence": str(args.evidence)}))
    return 0 if succeeded else 1


if __name__ == "__main__":
    sys.exit(main())
