from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import boto3
import pytest
from botocore.client import BaseClient
from botocore.stub import Stubber

from scripts.qualification.model_probe import (
    BENIGN_PROMPT,
    CAPABILITY_LABEL,
    MAX_BLOCKED_PROMPT_CHARS,
    MAX_OUTPUT_TOKENS,
    create_clients,
    parse_args,
    run_probe,
)

REGION = "eu-central-1"
PROFILE_ARN = "arn:aws:bedrock:eu-central-1:123456789012:inference-profile/probe"
COUNT_ARN = "arn:aws:bedrock:eu-central-1::foundation-model/anthropic.claude-probe"
GUARDRAIL_ARN = "arn:aws:bedrock:eu-central-1:123456789012:guardrail/probe"
BLOCK_PROMPT = "Synthetic phrase this guardrail denies."


def _client(service: str) -> BaseClient:
    return boto3.client(
        service,
        region_name=REGION,
        aws_access_key_id="offline-test",
        aws_secret_access_key="offline-test-only",
    )


def _response(
    *,
    request_id: str,
    stop_reason: str,
    text: str | None,
    usage: tuple[int, int, int],
) -> dict[str, Any]:
    content = [] if text is None else [{"text": text}]
    return {
        "output": {"message": {"role": "assistant", "content": content}},
        "stopReason": stop_reason,
        "usage": {"inputTokens": usage[0], "outputTokens": usage[1], "totalTokens": usage[2]},
        "metrics": {"latencyMs": 5},
        "ResponseMetadata": {"RequestId": request_id, "HTTPStatusCode": 200},
    }


def _run_probe(
    tmp_path: Path,
    *,
    normal_reason: str = "end_turn",
    normal_text: str | None = "READY",
    block_reason: str = "guardrail_intervened",
    block_usage: tuple[int, int, int] = (0, 0, 0),
) -> tuple[dict[str, Any], bool, Path]:
    sts = _client("sts")
    runtime = _client("bedrock-runtime")
    evidence_path = tmp_path / "probe.json"
    identity_stubber = Stubber(sts)
    runtime_stubber = Stubber(runtime)
    identity_stubber.add_response(
        "get_caller_identity",
        {
            "Account": "123456789012",
            "Arn": "arn:aws:sts::123456789012:assumed-role/probe/operator",
            "ResponseMetadata": {"RequestId": "identity-1", "HTTPStatusCode": 200},
        },
    )
    count_input = {
        "converse": {"messages": [{"role": "user", "content": [{"text": BENIGN_PROMPT}]}]}
    }
    runtime_stubber.add_response(
        "count_tokens",
        {"inputTokens": 14, "ResponseMetadata": {"RequestId": "count-1", "HTTPStatusCode": 200}},
        {"modelId": COUNT_ARN, "input": count_input},
    )
    guardrail_config = {"guardrailIdentifier": GUARDRAIL_ARN, "guardrailVersion": "3"}
    normal_request = {
        "modelId": PROFILE_ARN,
        "messages": [{"role": "user", "content": [{"text": BENIGN_PROMPT}]}],
        "inferenceConfig": {"maxTokens": MAX_OUTPUT_TOKENS, "temperature": 0},
        "guardrailConfig": guardrail_config,
    }
    runtime_stubber.add_response(
        "converse",
        _response(
            request_id="converse-1",
            stop_reason=normal_reason,
            text=normal_text,
            usage=(14, 1, 15),
        ),
        normal_request,
    )
    blocked_request = {
        **normal_request,
        "messages": [{"role": "user", "content": [{"text": BLOCK_PROMPT}]}],
        "inferenceConfig": {"maxTokens": 1, "temperature": 0},
    }
    runtime_stubber.add_response(
        "converse",
        _response(
            request_id="block-1",
            stop_reason=block_reason,
            text="Blocked.",
            usage=block_usage,
        ),
        blocked_request,
    )

    with identity_stubber, runtime_stubber:
        evidence, succeeded = run_probe(
            sts_client=sts,
            runtime_client=runtime,
            region=REGION,
            model_id=PROFILE_ARN,
            count_model_id=COUNT_ARN,
            guardrail_arn=GUARDRAIL_ARN,
            guardrail_version="3",
            blocked_prompt=BLOCK_PROMPT,
            evidence_path=evidence_path,
        )
    return evidence, succeeded, evidence_path


def test_probe_clients_pin_region_timeouts_single_attempt_and_one_connection() -> None:
    sts, runtime = create_clients(REGION)
    assert sts.meta.region_name == runtime.meta.region_name == REGION
    for client in (sts, runtime):
        assert client.meta.config.connect_timeout == 3
        assert client.meta.config.read_timeout == 15
        assert client.meta.config.retries == {"total_max_attempts": 1, "mode": "standard"}
        assert client.meta.config.max_pool_connections == 1


def test_probe_rejects_unbounded_block_prompt() -> None:
    with pytest.raises(SystemExit):
        parse_args(
            [
                "--region",
                REGION,
                "--model-arn",
                PROFILE_ARN,
                "--count-model-arn",
                COUNT_ARN,
                "--guardrail-arn",
                GUARDRAIL_ARN,
                "--guardrail-version",
                "3",
                "--blocked-prompt",
                "x" * (MAX_BLOCKED_PROMPT_CHARS + 1),
                "--evidence",
                "evidence.json",
            ]
        )


def test_probe_persists_capability_only_evidence_for_three_exact_bedrock_calls(
    tmp_path: Path,
) -> None:
    evidence, succeeded, evidence_path = _run_probe(tmp_path)

    assert succeeded
    assert evidence["outcome"] == "passed"
    assert evidence["evidence_type"] == CAPABILITY_LABEL
    assert evidence["live_gates"] == "NOT_RUN"
    assert evidence["account_id"] == "123456789012"
    assert evidence["region"] == REGION
    assert evidence["model_id"] == PROFILE_ARN
    assert evidence["count_model_id"] == COUNT_ARN
    assert set(evidence["calls"]) == {"count_tokens", "guarded_converse", "guardrail_block"}
    assert evidence["calls"]["guarded_converse"]["usable_output"]
    assert evidence["calls"]["guardrail_block"]["usage"] == {
        "inputTokens": 0,
        "outputTokens": 0,
        "totalTokens": 0,
    }
    written = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert written == evidence
    assert evidence_path.stat().st_mode & 0o777 == 0o600
    assert BLOCK_PROMPT not in evidence_path.read_text(encoding="utf-8")


def test_probe_accepts_stop_sequence_with_non_empty_text(tmp_path: Path) -> None:
    evidence, succeeded, _ = _run_probe(tmp_path, normal_reason="stop_sequence")
    assert succeeded
    assert evidence["calls"]["guarded_converse"]["stop_reason"] == "stop_sequence"


@pytest.mark.parametrize(
    ("stop_reason", "text"),
    [
        ("max_tokens", "READY"),
        ("content_filtered", "READY"),
        ("other", "READY"),
        ("end_turn", None),
        ("end_turn", ""),
        ("end_turn", "   "),
    ],
)
def test_probe_rejects_incomplete_or_unusable_benign_converse(
    tmp_path: Path, stop_reason: str, text: str | None
) -> None:
    evidence, succeeded, _ = _run_probe(tmp_path, normal_reason=stop_reason, normal_text=text)
    assert not succeeded
    assert evidence["outcome"] == "failed"


def test_block_probe_requires_guardrail_intervention_stop_reason(tmp_path: Path) -> None:
    evidence, succeeded, _ = _run_probe(tmp_path, block_reason="end_turn", block_usage=(0, 0, 0))
    assert not succeeded
    assert evidence["calls"]["guardrail_block"]["stop_reason"] == "end_turn"


def test_block_probe_requires_zero_usage_independently_of_intervention_reason(
    tmp_path: Path,
) -> None:
    evidence, succeeded, _ = _run_probe(
        tmp_path, block_reason="guardrail_intervened", block_usage=(1, 0, 1)
    )
    assert not succeeded
    assert evidence["calls"]["guardrail_block"]["stop_reason"] == "guardrail_intervened"
    assert evidence["calls"]["guardrail_block"]["usage"]["totalTokens"] == 1
