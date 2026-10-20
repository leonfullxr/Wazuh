# ruff: noqa: F401
from __future__ import annotations

import gzip
import hashlib
import json
import subprocess
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from io import BytesIO
from types import SimpleNamespace
from typing import Any

import boto3
import pytest
from botocore.config import Config
from botocore.response import StreamingBody
from botocore.stub import Stubber
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from ai_soc.qualification.evidence import ProbeEnvelope
from ai_soc.qualification.mcp_models import LvMcpInputs
from scripts.staging.artifact_verification import AuthenticatedEvidenceVerifier
from scripts.staging.attributed_probe import ProbeSpec, QualificationSession, _binding_dict
from scripts.staging.cloudtrail import CloudTrailDigestVerifier
from scripts.staging.journal import RunIntent
from scripts.staging.launch_requests import build_probe_config, resource_arns_for_probe
from scripts.staging.models import DeploymentBinding, GateId
from scripts.staging.state_adapter import StateGateInputs
from scripts.staging.verifier import (
    EvidenceContradiction,
    EvidenceIncomplete,
    FactRequirement,
    LaunchExpectation,
    canonical_request_digest,
)
from tests.unit.staging.authenticated_evidence_support import (
    ACCOUNT,
    NOW,
    REGION,
    TASK_ID,
    TASK_ROLE,
    _authenticated_verifier,
    binding,
    expectation,
    launch_event,
)


def test_direct_fact_chain_requires_exact_task_request_and_resource() -> None:
    s3 = boto3.client(
        "s3",
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 1, "mode": "standard"}),
    )
    event = {
        "eventVersion": "1.08",
        "eventID": "ddb-event-1",
        "requestID": "ddb-request-1",
        "eventSource": "dynamodb.amazonaws.com",
        "eventName": "DescribeTable",
        "awsRegion": REGION,
        "recipientAccountId": ACCOUNT,
        "eventTime": (NOW + timedelta(seconds=10)).isoformat().replace("+00:00", "Z"),
        "requestParameters": {"tableName": "qualification-state"},
        "resources": [{"ARN": f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/qualification-state"}],
        "userIdentity": {
            "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/application/{TASK_ID}",
            "principalId": f"AROAAPP:{TASK_ID}",
            "sessionContext": {"sessionIssuer": {"arn": TASK_ROLE}},
        },
    }
    logs = _authenticated_verifier(s3, events=[launch_event(), event])
    verifier = AuthenticatedEvidenceVerifier(logs)
    with pytest.raises(EvidenceIncomplete, match="registered fact selectors"):
        verifier.verify_facts(
            verifier.authenticate_launch(expectation()),
            (
                FactRequirement(
                    fact_id="state.table_read",
                    event_source="dynamodb.amazonaws.com",
                    event_names=("DescribeTable",),
                    resource_arn=f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/qualification-state",
                    request_id_field="tableName",
                    request_id_value="qualification-state",
                ),
            ),
        )
    bad_requirement = FactRequirement(
        fact_id="state.table_read",
        event_source="dynamodb.amazonaws.com",
        event_names=("DescribeTable",),
        resource_arn=f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/other",
        request_id_field="tableName",
        request_id_value="qualification-state",
    )
    with pytest.raises(EvidenceIncomplete, match="registered fact selectors"):
        verifier.verify_facts(verifier.authenticate_launch(expectation()), (bad_requirement,))


def test_registered_fact_chain_matches_sdk_request_id_and_registered_resource() -> None:
    s3 = boto3.client(
        "s3",
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 1, "mode": "standard"}),
    )
    state_event = launch_event()
    state_request = state_event["requestParameters"]
    assert isinstance(state_request, dict)
    state_inputs = StateGateInputs(
        table_name="qualification-state", evidence_bucket="qualification-evidence"
    )
    state_spec = ProbeSpec(
        entrypoint="state",
        parameters={"inputs": state_inputs.model_dump(mode="json"), "container_name": "ai-soc"},
        execution_seconds=360,
        collection_seconds=3600,
    )
    state_request["tags"] = [
        {
            "key": row["key"],
            "value": (
                "LV-STATE"
                if row["key"] == "qualification-gate"
                else "state"
                if row["key"] == "qualification-contributor"
                else row["value"]
            ),
        }
        for row in state_request["tags"]
    ]
    state_expectation = replace(
        expectation(),
        gate_id=GateId.LV_STATE,
        contributor_id="state",
        resource_arns=resource_arns_for_probe("state", state_spec, binding()),
        launch_request_digest=canonical_request_digest(state_request),
    )
    event = {
        "eventVersion": "1.08",
        "eventID": "ddb-event-1",
        "requestID": "ddb-sdk-request-1",
        "eventSource": "dynamodb.amazonaws.com",
        "eventName": "UpdateItem",
        "awsRegion": REGION,
        "recipientAccountId": ACCOUNT,
        "eventTime": (NOW + timedelta(seconds=10)).isoformat().replace("+00:00", "Z"),
        "requestParameters": {"tableName": "qualification-state"},
        "resources": [{"ARN": f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/qualification-state"}],
        "userIdentity": {
            "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/application/{TASK_ID}",
            "principalId": f"AROAAPP:{TASK_ID}",
            "sessionContext": {"sessionIssuer": {"arn": TASK_ROLE}},
        },
    }
    logs = _authenticated_verifier(s3, events=[state_event, event])
    verifier = AuthenticatedEvidenceVerifier(logs)
    launch = verifier.authenticate_launch(state_expectation)
    chain = verifier.verify_registered_facts(
        launch,
        {
            "fact_requests": [
                {
                    "fact_id": "state_contender_a",
                    "operation": "UpdateItem",
                    "request_id": "ddb-sdk-request-1",
                }
            ]
        },
    )
    assert [fact.fact_id for fact in chain.facts] == ["state_contender_a"]


def test_mcp_secret_read_alone_cannot_certify_client_obligations() -> None:
    s3 = boto3.client(
        "s3",
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 1, "mode": "standard"}),
    )
    secret_event = {
        "eventVersion": "1.08",
        "eventID": "secret-read-event",
        "requestID": "secret-read-request",
        "eventSource": "secretsmanager.amazonaws.com",
        "eventName": "GetSecretValue",
        "awsRegion": REGION,
        "recipientAccountId": ACCOUNT,
        "eventTime": (NOW + timedelta(seconds=10)).isoformat().replace("+00:00", "Z"),
        "requestParameters": {"secretId": f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:mcp"},
        "userIdentity": {
            "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/application/{TASK_ID}",
            "principalId": f"AROAAPP:{TASK_ID}",
            "sessionContext": {"sessionIssuer": {"arn": TASK_ROLE}},
        },
    }
    verifier = AuthenticatedEvidenceVerifier(
        _authenticated_verifier(s3, events=[launch_event(), secret_event])
    )
    launch = verifier.authenticate_launch(expectation())
    with pytest.raises(EvidenceIncomplete, match="registered fact selectors"):
        verifier.verify_registered_facts(
            launch,
            {
                "fact_requests": [
                    {
                        "fact_id": "mcp_official_client_flows",
                        "operation": "GetSecretValue",
                        "request_id": "secret-read-request",
                    }
                ]
            },
        )


def test_registered_fact_chain_rejects_unregistered_claim_and_duplicate_request() -> None:
    s3 = boto3.client(
        "s3",
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 1, "mode": "standard"}),
    )
    state_expectation = replace(
        expectation(),
        gate_id=GateId.LV_STATE,
        contributor_id="state",
        resource_arns=(
            ("state_table", f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/qualification-state"),
        ),
    )
    event = {
        "eventVersion": "1.08",
        "eventID": "ddb-event-1",
        "requestID": "ddb-sdk-request-1",
        "eventSource": "dynamodb.amazonaws.com",
        "eventName": "UpdateItem",
        "awsRegion": REGION,
        "recipientAccountId": ACCOUNT,
        "eventTime": (NOW + timedelta(seconds=10)).isoformat().replace("+00:00", "Z"),
        "requestParameters": {"tableName": "qualification-state"},
        "resources": [{"ARN": f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/qualification-state"}],
        "userIdentity": {
            "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/application/{TASK_ID}",
            "principalId": f"AROAAPP:{TASK_ID}",
            "sessionContext": {"sessionIssuer": {"arn": TASK_ROLE}},
        },
    }
    state_event = launch_event()
    state_request = state_event["requestParameters"]
    assert isinstance(state_request, dict)
    state_request["tags"] = [
        {
            "key": row["key"],
            "value": (
                "LV-STATE"
                if row["key"] == "qualification-gate"
                else "state"
                if row["key"] == "qualification-contributor"
                else row["value"]
            ),
        }
        for row in state_request["tags"]
    ]
    state_expectation = replace(
        state_expectation,
        launch_request_digest=canonical_request_digest(state_request),
    )
    verifier = AuthenticatedEvidenceVerifier(
        _authenticated_verifier(s3, events=[state_event, event])
    )
    launch = verifier.authenticate_launch(state_expectation)
    with pytest.raises(EvidenceContradiction, match="unregistered fact"):
        verifier.verify_registered_facts(
            launch,
            {
                "fact_requests": [
                    {
                        "fact_id": "caller.invented",
                        "operation": "UpdateItem",
                        "request_id": "ddb-sdk-request-1",
                    }
                ]
            },
        )
    with pytest.raises(EvidenceIncomplete, match="ambiguous"):
        verifier.verify_registered_facts(
            launch,
            {
                "fact_requests": [
                    {
                        "fact_id": "state_contender_a",
                        "operation": "UpdateItem",
                        "request_id": "ddb-sdk-request-1",
                    },
                    {
                        "fact_id": "state_contender_a",
                        "operation": "UpdateItem",
                        "request_id": "ddb-sdk-request-1",
                    },
                ]
            },
        )
