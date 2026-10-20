"""Strict loader for the sealed, version-pinned qualification resource map."""

from __future__ import annotations

import hashlib
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai_soc.live.sealed import QualificationMapPin
from scripts.staging.models import DeploymentBinding
from scripts.staging.s3_evidence import read_version_bytes


class _MapModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class EvidenceResources(_MapModel):
    bucket: str = Field(min_length=3, max_length=63)
    app_prefix: str
    consumer_prefix: str
    map_key: str
    input_prefix: str
    kms_key_arn: str

    @field_validator("app_prefix")
    @classmethod
    def app_namespace(cls, value: str) -> str:
        if value != "qualification/":
            raise ValueError("app evidence prefix must be qualification/")
        return value

    @field_validator("consumer_prefix")
    @classmethod
    def consumer_namespace(cls, value: str) -> str:
        if value != "events/qualification/":
            raise ValueError("consumer evidence prefix must be events/qualification/")
        return value

    @field_validator("input_prefix")
    @classmethod
    def input_namespace(cls, value: str) -> str:
        if value != "qualification-inputs/":
            raise ValueError("qualification input prefix must be qualification-inputs/")
        return value


class CloudTrailResources(_MapModel):
    arn: str | None
    bucket: str | None
    log_validation_enabled: bool


class InvocationLogResources(_MapModel):
    bucket: str | None
    prefix: str | None
    writer: str

    @field_validator("writer")
    @classmethod
    def service_writer(cls, value: str) -> str:
        if value != "bedrock.amazonaws.com":
            raise ValueError("invocation log writer must be the Bedrock service principal")
        return value

    @field_validator("prefix")
    @classmethod
    def exact_prefix(cls, value: str | None) -> str | None:
        if value is not None and value != "bedrock-invocations/":
            raise ValueError("Bedrock invocation log prefix does not match the sealed contract")
        return value


class NetworkResources(_MapModel):
    vpc_id: str
    service_subnet_ids: tuple[str, ...] | list[str]
    service_route_table_ids: tuple[str, ...] | list[str]
    public_isolated_subnet_ids: tuple[str, ...] | list[str]
    public_isolated_route_table_ids: tuple[str, ...] | list[str]
    s3_gateway_endpoint_id: str | None
    storage_kms_key_arn: str


class ArchiveConsumerResources(_MapModel):
    task_definition_arn: str | None
    container_name: str
    image: str
    task_role_arn: str | None

    @field_validator("container_name")
    @classmethod
    def fixed_container(cls, value: str) -> str:
        if value != "audit-archive":
            raise ValueError("archive consumer container name is not the registered one")
        return value


class ServiceResources(_MapModel):
    cluster_arn: str
    task_security_group_id: str | None
    endpoint_security_group_id: str | None
    application_role_arn: str


class QualificationResourceMap(_MapModel):
    schema_version: int = Field(ge=1, le=1)
    account_id: str = Field(pattern=r"^[0-9]{12}$")
    region: str = Field(min_length=1, max_length=64)
    evidence: EvidenceResources
    cloudtrail: CloudTrailResources
    invocation_logs: InvocationLogResources
    network: NetworkResources
    archive_consumer: ArchiveConsumerResources
    service: ServiceResources
    certification_enabled: bool


def load_pinned_resource_map(
    pin: QualificationMapPin,
    *,
    binding: DeploymentBinding,
    s3_client: Any,
) -> QualificationResourceMap:
    """Fetch exactly the sealed map version and validate its digest and identity."""
    if not binding.deployment_id:
        raise ValueError("qualification resource map requires a nonempty deployment ID")
    response, raw = read_version_bytes(
        s3_client,
        bucket=pin.bucket,
        key=pin.key,
        version_id=pin.version_id,
        expected_bucket_owner=binding.account_id,
        maximum_bytes=64 * 1024,
    )
    if response.get("ServerSideEncryption") != "aws:kms":
        raise ValueError("qualification map must use the sealed KMS encryption mode")
    if response.get("SSEKMSKeyId") is None:
        raise ValueError("qualification map response omits its KMS key identity")
    if hashlib.sha256(raw).hexdigest() != pin.sha256:
        raise ValueError("qualification resource map does not match its sealed SHA-256 pin")
    from scripts.staging.verifier import strict_json

    document = strict_json(raw, maximum=64 * 1024)
    resource_map = QualificationResourceMap.model_validate(document)
    if resource_map.account_id != binding.account_id or resource_map.region != binding.region:
        raise ValueError("qualification resource map account or Region differs from live binding")
    if resource_map.evidence.bucket != pin.bucket or resource_map.evidence.map_key != pin.key:
        raise ValueError("qualification resource map self-reference differs from sealed pin")
    if resource_map.service.cluster_arn != binding.cluster_arn:
        raise ValueError("qualification resource map cluster differs from live binding")
    if response.get("SSEKMSKeyId") != resource_map.evidence.kms_key_arn:
        raise ValueError("qualification map uses a different KMS key than its own map entry")
    if not resource_map.cloudtrail.log_validation_enabled or not resource_map.cloudtrail.arn:
        raise ValueError("CloudTrail integrity validation is not enabled in the resource map")
    if not resource_map.cloudtrail.bucket:
        raise ValueError("CloudTrail digest sink is not configured in the resource map")
    return resource_map
