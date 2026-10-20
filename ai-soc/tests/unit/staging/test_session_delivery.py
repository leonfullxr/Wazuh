from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import boto3
import pytest
from botocore.config import Config
from botocore.response import StreamingBody
from botocore.stub import Stubber

from ai_soc.qualification.evidence import EvidencePaths
from ai_soc.qualification.models import ProbeInvocationConfig
from scripts.staging.artifact_verification import AuthenticatedEvidenceVerifier
from scripts.staging.attributed_probe import (
    QualificationSession,
)
from scripts.staging.journal import DeliveryMeasurement
from scripts.staging.models import GateId
from scripts.staging.resource_map import QualificationResourceMap
from scripts.staging.verifier import EvidenceIncomplete, LaunchExpectation, canonical_request_digest
from tests.unit.staging.authenticated_evidence_support import (
    ACCOUNT,
    EVIDENCE_BUCKET,
    LAUNCH_ROLE,
    REGION,
    TASK_ROLE,
    _authenticated_verifier,
    launch_event,
    mcp_probe_inputs,
)
from tests.unit.staging.session_test_support import _binding


def test_delivery_budget_rejects_caller_fabricated_receipts(
    tmp_path: Path,
) -> None:
    binding = _binding()
    ecs = boto3.client(
        "ecs",
        region_name=binding.region,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 1, "mode": "standard"}),
    )

    class Clients:
        def client(self, service_name: str):
            assert service_name == "ecs"
            return ecs

    run_id = str(UUID(int=501))
    started = datetime.now(UTC) - timedelta(seconds=120)
    finished = started + timedelta(seconds=10)
    receipts = []
    for placement in ("service", "public-isolated"):
        event_time = finished - timedelta(seconds=2)
        digest_time = finished + timedelta(seconds=100)
        receipts.append(
            {
                "verified": "true",
                "placement": placement,
                "session_id": "",
                "run_id": run_id,
                "event_id": f"event-{placement}",
                "version_id": f"version-{placement}",
                "task_arn": f"arn:aws:ecs:{binding.region}:{binding.account_id}:task/q/{placement}",
                "object_sha256": "a" * 64,
                "task_finished_at": finished.isoformat(),
                "task_started_at": started.isoformat(),
                "event_time": event_time.isoformat(),
                "digest_file_uri": "s3://trail/AWSLogs/account/digest.json.gz",
                "digest_version_id": "digest-version-1",
                "digest_validated_at": digest_time.isoformat(),
                "digest_availability_seconds": str((digest_time - event_time).total_seconds()),
                "digest_file_sha256": "b" * 64,
            }
        )
    with Stubber(ecs) as stubber:
        stubber.add_response("list_tasks", {"taskArns": []}, {"cluster": binding.cluster_arn})
        session = QualificationSession.open(Clients(), binding, journal_root=tmp_path)
        try:
            with pytest.raises(RuntimeError, match="requires the sealed resource map"):
                _ = session.measured_delivery_budget
            for receipt in receipts:
                receipt["session_id"] = session.session_id
            with pytest.raises(ValueError, match="authenticated canary proof"):
                session.record_delivery_measurement(receipts)
            with pytest.raises(RuntimeError, match="requires the sealed resource map"):
                _ = session.measured_delivery_budget
        finally:
            session.close()

    with QualificationSession.open(Clients(), binding, journal_root=tmp_path) as resumed:
        with pytest.raises(RuntimeError, match="requires the sealed resource map"):
            _ = resumed.measured_delivery_budget


def test_resume_reauthenticates_calibration_identity_without_replacing_original_timing() -> None:
    now = datetime.now(UTC)
    run_id = str(UUID(int=502))
    recorded_receipts = []
    authenticated_receipts = []
    for placement in ("service", "public-isolated"):
        event_time = now - timedelta(seconds=105)
        recorded_digest_time = now - timedelta(seconds=45)
        identity = {
            "verified": "true",
            "placement": placement,
            "session_id": str(UUID(int=503)),
            "run_id": run_id,
            "event_id": f"event-{placement}",
            "version_id": f"version-{placement}",
            "task_arn": f"arn:aws:ecs:eu-central-1:123456789012:task/q/{placement}",
            "object_sha256": "a" * 64,
            "task_finished_at": (now - timedelta(seconds=100)).isoformat(),
            "task_started_at": (now - timedelta(seconds=160)).isoformat(),
            "event_time": event_time.isoformat(),
            "digest_file_uri": "s3://trail/AWSLogs/account/digest.json.gz",
            "digest_version_id": "digest-version-1",
            "digest_file_sha256": "b" * 64,
        }
        recorded_receipts.append(
            {
                **identity,
                "digest_validated_at": recorded_digest_time.isoformat(),
                "digest_availability_seconds": "60.0",
            }
        )
        authenticated_receipts.append(
            {
                **identity,
                "digest_validated_at": now.isoformat(),
                "digest_availability_seconds": "105.0",
            }
        )
    measurement = DeliveryMeasurement.model_validate(
        {
            "schema": "ai-soc.qualification-delivery-measurement.v1",
            "session_id": str(UUID(int=503)),
            "run_id": run_id,
            "receipts": recorded_receipts,
            "budget_seconds": 75,
            "margin_seconds": 20,
            "session_remaining_seconds": 500,
            "recorded_at": (now - timedelta(seconds=40)).isoformat(),
        }
    )
    session = object.__new__(QualificationSession)
    session.session_id = measurement.session_id
    session._journal = SimpleNamespace(
        delivery_measurement=measurement,
        runs=(
            SimpleNamespace(
                run_id=run_id,
                probe_spec=ProbeInvocationConfig(
                    entrypoint="canary",
                    parameters={
                        "inputs": {
                            "evidence_bucket": "ai-soc-qualification-audit",
                            "kms_key_arn": "arn:aws:kms:eu-central-1:123456789012:key/key",
                            "evidence_paths": EvidencePaths(
                                app_prefix="qualification/",
                                consumer_prefix="events/qualification/",
                                map_key="qualification-maps/resource-map.json",
                                input_prefix="qualification-inputs/",
                            ).model_dump(mode="json"),
                        }
                    },
                    execution_seconds=120,
                    collection_seconds=300,
                ),
                state="stopped",
            ),
        ),
    )

    def authenticate_canary_run(observed_run_id: str):
        assert observed_run_id == run_id
        return [SimpleNamespace(receipt=receipt) for receipt in authenticated_receipts]

    session.authenticate_canary_run = authenticate_canary_run

    assert session._authenticate_delivery_measurement() == 75

    authenticated_receipts[0]["digest_version_id"] = "replacement-digest-version"
    with pytest.raises(EvidenceIncomplete, match="canary reauthentication"):
        session._authenticate_delivery_measurement()
    authenticated_receipts[0]["digest_version_id"] = "digest-version-1"
    authenticated_receipts[0]["object_sha256"] = "c" * 64
    with pytest.raises(EvidenceIncomplete, match="canary reauthentication"):
        session._authenticate_delivery_measurement()


def test_canary_receipts_are_journaled_before_a_real_probe_launch(tmp_path: Path) -> None:
    binding = _binding()
    ecs = boto3.client(
        "ecs",
        region_name=binding.region,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 1, "mode": "standard"}),
    )
    s3 = boto3.client(
        "s3",
        region_name=binding.region,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        config=Config(retries={"max_attempts": 1, "mode": "standard"}),
    )

    class Clients:
        def client(self, name: str):
            return {"ecs": ecs, "s3": s3}[name]

    kms_key = f"arn:aws:kms:{binding.region}:{binding.account_id}:key/qualification"
    resource_map = QualificationResourceMap.model_validate(
        {
            "schema_version": 1,
            "account_id": binding.account_id,
            "region": binding.region,
            "evidence": {
                "bucket": EVIDENCE_BUCKET,
                "app_prefix": "qualification/",
                "input_prefix": "qualification-inputs/",
                "consumer_prefix": "events/qualification/",
                "map_key": "qualification-maps/resource-map.json",
                "kms_key_arn": kms_key,
            },
            "cloudtrail": {
                "arn": (
                    f"arn:aws:cloudtrail:{binding.region}:{binding.account_id}:trail/qualification"
                ),
                "bucket": "cloudtrail-bucket",
                "log_validation_enabled": True,
            },
            "invocation_logs": {
                "bucket": "invocation-bucket",
                "prefix": "bedrock-invocations/",
                "writer": "bedrock.amazonaws.com",
            },
            "network": {
                "vpc_id": "vpc-0123456789abcdef0",
                "service_subnet_ids": ["subnet-0123456789abcdef0"],
                "service_route_table_ids": ["rtb-service"],
                "public_isolated_subnet_ids": ["subnet-isolated"],
                "public_isolated_route_table_ids": ["rtb-isolated"],
                "s3_gateway_endpoint_id": "vpce-s3",
                "storage_kms_key_arn": kms_key,
            },
            "archive_consumer": {
                "task_definition_arn": None,
                "container_name": "audit-archive",
                "image": "ai-soc@sha256:" + "f" * 64,
                "task_role_arn": None,
            },
            "service": {
                "cluster_arn": binding.cluster_arn,
                "task_security_group_id": "sg-0123456789abcdef0",
                "endpoint_security_group_id": None,
                "application_role_arn": f"arn:aws:iam::{binding.account_id}:role/application",
            },
            "certification_enabled": True,
        }
    )
    with Stubber(ecs) as stubber:
        stubber.add_response("list_tasks", {"taskArns": []}, {"cluster": binding.cluster_arn})
        with QualificationSession.open(
            Clients(),
            binding,
            journal_root=tmp_path,
            resource_map=resource_map,
            launcher_role_arn=LAUNCH_ROLE,
        ) as session:
            spec = ProbeInvocationConfig(
                entrypoint="canary",
                parameters={
                    "inputs": {
                        "evidence_bucket": resource_map.evidence.bucket,
                        "kms_key_arn": resource_map.evidence.kms_key_arn,
                        "evidence_paths": EvidencePaths(
                            app_prefix="qualification/",
                            consumer_prefix="events/qualification/",
                            map_key="qualification-maps/resource-map.json",
                            input_prefix="qualification-inputs/",
                        ).model_dump(mode="json"),
                    },
                    "container_name": "ai-soc",
                },
                network="canary_pair",
                execution_seconds=120,
                collection_seconds=300,
            )
            service = {
                "status": "ACTIVE",
                "networkConfiguration": {
                    "awsvpcConfiguration": {
                        "subnets": ["subnet-0123456789abcdef0"],
                        "securityGroups": ["sg-0123456789abcdef0"],
                        "assignPublicIp": "DISABLED",
                    }
                },
                "launchType": "FARGATE",
                "platformVersion": "LATEST",
            }
            stubber.add_response(
                "describe_services",
                {"services": [service]},
                {"cluster": binding.cluster_arn, "services": [binding.service_arn]},
            )
            canary_arns = tuple(
                f"arn:aws:ecs:{binding.region}:{binding.account_id}:task/qualification/{n:032x}"
                for n in (801, 802)
            )
            for arn in canary_arns:
                stubber.add_response(
                    "run_task",
                    {
                        "tasks": [
                            {
                                "taskArn": arn,
                                "clusterArn": binding.cluster_arn,
                                "taskDefinitionArn": binding.task_definition_arn,
                            }
                        ]
                    },
                )
            canary_run, _ = session.launch_probe(
                spec,
                gate_id=GateId.LV_MCP,
                contributor_id="mcp",
                slots=("service", "public-isolated"),
                _calibration=True,
            )
            assert canary_run.probe_spec == spec
            assert len(canary_run.launch_requests) == 2

            started = datetime.now(UTC)
            stopped = started - timedelta(seconds=2)
            task_rows = []
            for arn, request in zip(canary_arns, canary_run.launch_requests, strict=True):
                task_rows.append(
                    {
                        "taskArn": arn,
                        "clusterArn": binding.cluster_arn,
                        "taskDefinitionArn": binding.task_definition_arn,
                        "startedBy": canary_run.started_by,
                        "lastStatus": "STOPPED",
                        "stoppedAt": stopped,
                        "tags": request["tags"],
                        "containers": [
                            {"name": "ai-soc", "imageDigest": binding.image_digest, "exitCode": 0}
                        ],
                        "overrides": request["overrides"],
                    }
                )
            for _ in range(3):
                stubber.add_response(
                    "describe_tasks",
                    {"tasks": task_rows},
                    {
                        "cluster": binding.cluster_arn,
                        "tasks": list(canary_arns),
                        "include": ["TAGS"],
                    },
                )
            completions = session.wait_for_completion(canary_run.run_id)
            assert len(completions) == 2

            events: list[dict[str, object]] = []
            put_rows: list[tuple[str, str, str]] = []
            s3_stubber = Stubber(s3)
            for index, (slot, arn, request) in enumerate(
                zip(canary_run.task_slots, canary_arns, canary_run.launch_requests, strict=True)
            ):
                task_id = arn.rsplit("/", 1)[-1]
                event = launch_event()
                event["eventID"] = f"canary-launch-{index}"
                event["eventTime"] = (
                    (started - timedelta(seconds=10)).isoformat().replace("+00:00", "Z")
                )
                event["requestParameters"] = request
                event["responseElements"] = {
                    "tasks": [
                        {
                            "taskArn": arn,
                            "clusterArn": binding.cluster_arn,
                            "taskDefinitionArn": binding.task_definition_arn,
                            "startedBy": canary_run.started_by,
                        }
                    ]
                }
                events.append(event)
                key = (
                    f"qualification/{session.session_id}/canary/{slot}/"
                    f"{canary_run.run_id}/{hashlib.sha256(arn.encode()).hexdigest()[:24]}.json"
                )
                version_id = f"canary-version-{index}"
                event_time = started - timedelta(seconds=3)
                put = {
                    "eventVersion": "1.08",
                    "eventID": f"canary-put-{index}",
                    "requestID": f"canary-put-request-{index}",
                    "eventSource": "s3.amazonaws.com",
                    "eventName": "PutObject",
                    "awsRegion": binding.region,
                    "recipientAccountId": binding.account_id,
                    "eventTime": event_time.isoformat().replace("+00:00", "Z"),
                    "userIdentity": {
                        "type": "AssumedRole",
                        "arn": (
                            f"arn:aws:sts::{binding.account_id}:assumed-role/application/{task_id}"
                        ),
                        "principalId": f"AROAAPP:{task_id}",
                        "sessionContext": {"sessionIssuer": {"arn": TASK_ROLE}},
                    },
                    "requestParameters": {"bucketName": resource_map.evidence.bucket, "key": key},
                    "responseElements": {"x-amz-version-id": version_id},
                }
                events.append(put)
                body = json.dumps(
                    {
                        "schema": "ai-soc.qualification-canary.v1",
                        "session_id": session.session_id,
                        "run_id": canary_run.run_id,
                        "placement": slot,
                        "task_arn": arn,
                        "nonce": f"nonce-{index}",
                        "started_at": (started - timedelta(seconds=5)).isoformat(),
                        "written_at": (started - timedelta(seconds=4)).isoformat(),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
                digest = hashlib.sha256(body).hexdigest()
                s3_stubber.add_response(
                    "list_object_versions",
                    {
                        "Versions": [{"Key": key, "VersionId": version_id, "IsLatest": True}],
                        "IsTruncated": False,
                    },
                    None,
                )
                s3_stubber.add_response(
                    "get_object",
                    {
                        "Body": StreamingBody(BytesIO(body), len(body)),
                        "VersionId": version_id,
                        "ServerSideEncryption": "aws:kms",
                        "SSEKMSKeyId": kms_key,
                        "Metadata": {"sha256": digest, "task-arn": arn},
                    },
                    None,
                )
                s3_stubber.add_response(
                    "get_object_tagging",
                    {
                        "TagSet": [
                            {"Key": k, "Value": v}
                            for k, v in {
                                "session": session.session_id,
                                "run": canary_run.run_id,
                                "placement": slot,
                            }.items()
                        ]
                    },
                    None,
                )
                s3_stubber.add_response(
                    "list_object_versions",
                    {
                        "Versions": [{"Key": key, "VersionId": version_id, "IsLatest": True}],
                        "IsTruncated": False,
                    },
                    None,
                )
                put_rows.append((slot, arn, key))

            logs = _authenticated_verifier(s3, events=events, now=datetime.now(UTC))
            verifier = AuthenticatedEvidenceVerifier(logs)
            s3_stubber.activate()
            proofs = []
            for index, (slot, _arn, _key) in enumerate(put_rows):
                request = canary_run.launch_requests[index]
                expectation = LaunchExpectation(
                    account_id=ACCOUNT,
                    region=REGION,
                    launcher_role_arn=LAUNCH_ROLE,
                    cluster_arn=binding.cluster_arn,
                    task_definition_arn=binding.task_definition_arn,
                    started_by=canary_run.started_by,
                    client_token=canary_run.client_tokens[index],
                    session_id=session.session_id,
                    invocation_id=canary_run.invocation_id,
                    run_id=canary_run.run_id,
                    gate_id=GateId.LV_MCP,
                    contributor_id="mcp",
                    slot=slot,
                    task_role_arn=TASK_ROLE,
                    binding=binding,
                    deadline_utc=canary_run.deadline_utc,
                    launch_request_digest=canonical_request_digest(request),
                    required_request_fields=tuple(request),
                    execution_seconds=spec.execution_seconds,
                    collection_seconds=spec.collection_seconds,
                )
                launch = verifier.authenticate_launch(expectation)
                proofs.append(
                    verifier.authenticate_canary_delivery(
                        launch,
                        event_id=f"canary-put-{index}",
                        bucket=resource_map.evidence.bucket,
                        key=put_rows[index][2],
                        placement=slot,
                        task_finished_at=stopped,
                        expected_bucket_owner=binding.account_id,
                        s3_client=s3,
                    )
                )
            measured_budget = session.record_delivery_measurement(proofs, margin_seconds=0)
            assert measured_budget > 0
            assert session._journal.delivery_measurement is not None
            assert len(session._journal.delivery_measurement.receipts) == 2
            s3_stubber.assert_no_pending_responses()

            stubber.add_response(
                "describe_services",
                {"services": [service]},
                {"cluster": binding.cluster_arn, "services": [binding.service_arn]},
            )
            normal_arn = (
                f"arn:aws:ecs:{binding.region}:{binding.account_id}:task/qualification/{803:032x}"
            )
            stubber.add_response(
                "run_task",
                {
                    "tasks": [
                        {
                            "taskArn": normal_arn,
                            "clusterArn": binding.cluster_arn,
                            "taskDefinitionArn": binding.task_definition_arn,
                        }
                    ]
                },
            )
            normal_spec = ProbeInvocationConfig(
                entrypoint="mcp",
                parameters={"inputs": mcp_probe_inputs().model_dump(mode="json")},
                execution_seconds=60,
                collection_seconds=measured_budget,
            )
            normal_run, _ = session.launch_probe(
                normal_spec,
                gate_id=GateId.LV_MCP,
                contributor_id="mcp",
                slots=("probe",),
            )
            assert normal_run.probe_spec.collection_seconds == measured_budget
            normal_task = {
                "taskArn": normal_arn,
                "clusterArn": binding.cluster_arn,
                "taskDefinitionArn": binding.task_definition_arn,
                "startedBy": normal_run.started_by,
                "lastStatus": "STOPPED",
                "stoppedAt": datetime.now(UTC),
                "tags": normal_run.launch_requests[0]["tags"],
                "containers": [
                    {"name": "ai-soc", "imageDigest": binding.image_digest, "exitCode": 0}
                ],
                "overrides": normal_run.launch_requests[0]["overrides"],
            }
            for _ in range(3):
                stubber.add_response(
                    "describe_tasks",
                    {"tasks": [normal_task]},
                    {
                        "cluster": binding.cluster_arn,
                        "tasks": [normal_arn],
                        "include": ["TAGS"],
                    },
                )
            assert len(session.wait_for_completion(normal_run.run_id)) == 1
            stubber.assert_no_pending_responses()
