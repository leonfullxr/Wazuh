from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai_soc.live.sealed import LiveSealedDocument
from scripts.staging.clients import (
    AdapterConfig,
    AWSServiceClientFactory,
    DeploymentObserver,
    NetworkProbeClient,
    NightlyResultsClient,
)
from scripts.staging.models import DeploymentBinding


class CollectorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    factory: str
    options: dict[str, Any] = Field(default_factory=dict)


class AWSClientConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_profile: str
    role_arn: str
    account_id: str
    region: str
    cluster: str
    service_name: str
    app_container_name: str
    adapters: tuple[AdapterConfig, ...] = ()
    nightly: CollectorConfig | None = None
    network: CollectorConfig | None = None

    @field_validator("source_profile")
    @classmethod
    def _profile_is_explicit(cls, value: str) -> str:
        if not value.strip() or value == "default":
            raise ValueError("source_profile must name an explicit non-default AWS profile")
        return value

    @field_validator("role_arn")
    @classmethod
    def _role_arn(cls, value: str) -> str:
        if not re.fullmatch(r"arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+", value):
            raise ValueError("role_arn must be an IAM role ARN")
        return value

    @field_validator("account_id")
    @classmethod
    def _account(cls, value: str) -> str:
        if not re.fullmatch(r"[0-9]{12}", value):
            raise ValueError("account_id must be a 12-digit AWS account ID")
        return value

    @field_validator("region", "cluster", "service_name", "app_container_name")
    @classmethod
    def _nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("AWS client configuration values must be nonempty")
        return value


@dataclass(frozen=True, slots=True)
class ExplicitBotoClients(AWSServiceClientFactory):
    session: Any

    def client(self, service_name: str) -> Any:
        return self.session.client(
            service_name,
            config=Config(
                connect_timeout=5,
                read_timeout=5,
                retries={"total_max_attempts": 1, "mode": "standard"},
            ),
        )


@dataclass(frozen=True, slots=True)
class DeploymentSnapshot:
    binding: DeploymentBinding
    sealed_document: LiveSealedDocument
    service: dict[str, Any]
    service_networking: dict[str, Any]
    task_observations: tuple[dict[str, Any], ...]
    task_environment: dict[str, str]


@dataclass(frozen=True, slots=True)
class ECSDeploymentObserver(DeploymentObserver):
    config: AWSClientConfig
    sts: Any
    ecs: Any

    @property
    def qualification_launcher_role_arn(self) -> str:
        return self.config.role_arn

    def observe_deployment_snapshot(
        self, binding: DeploymentBinding | None = None
    ) -> DeploymentSnapshot:
        """Observe identity, service, task and sealed config through one owner."""
        identity = self.sts.get_caller_identity()
        account_id = identity.get("Account")
        if account_id != self.config.account_id:
            raise ValueError("AWS caller account differs from configured account")
        services_response = self.ecs.describe_services(
            cluster=self.config.cluster, services=[self.config.service_name]
        )
        services = services_response.get("services", [])
        if services_response.get("failures") or len(services) != 1:
            raise ValueError("configured ECS service is absent or ambiguous")
        service = services[0]
        primary = [row for row in service.get("deployments", []) if row.get("status") == "PRIMARY"]
        task_definition_arn = service.get("taskDefinition")
        deployment_id = primary[0].get("id") if len(primary) == 1 else None
        cluster_arn = service.get("clusterArn")
        service_arn = service.get("serviceArn")
        if (
            service.get("status") != "ACTIVE"
            or not isinstance(cluster_arn, str)
            or not isinstance(service_arn, str)
            or not isinstance(task_definition_arn, str)
            or not isinstance(deployment_id, str)
            or not deployment_id
            or primary[0].get("taskDefinition") != task_definition_arn
        ):
            raise ValueError("configured ECS service deployment is incomplete")
        network = service.get("networkConfiguration")
        if not isinstance(network, dict) or not isinstance(
            network.get("awsvpcConfiguration"), dict
        ):
            raise ValueError("bound ECS service networking is unavailable")
        task_arns = self.ecs.list_tasks(
            cluster=cluster_arn,
            serviceName=self.config.service_name,
            desiredStatus="RUNNING",
        ).get("taskArns", [])
        if not task_arns:
            raise ValueError("bound ECS service has no running tasks")
        task_response = self.ecs.describe_tasks(cluster=cluster_arn, tasks=task_arns)
        tasks = task_response.get("tasks", [])
        if task_response.get("failures") or len(tasks) != len(task_arns):
            raise ValueError("bound ECS task observation is incomplete")
        digests: set[str] = set()
        for task in tasks:
            app = next(
                (
                    row
                    for row in task.get("containers", [])
                    if row.get("name") == self.config.app_container_name
                ),
                None,
            )
            digest = app.get("imageDigest") if app else None
            if (
                task.get("lastStatus") != "RUNNING"
                or task.get("startedBy") != deployment_id
                or task.get("taskDefinitionArn") != task_definition_arn
                or not isinstance(digest, str)
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
            ):
                raise ValueError("bound ECS tasks differ from the primary deployment")
            digests.add(digest)
        if len(digests) != 1:
            raise ValueError("bound ECS service tasks have inconsistent image digests")
        definition = self.ecs.describe_task_definition(
            taskDefinition=task_definition_arn, include=["TAGS"]
        ).get("taskDefinition", {})
        if (
            definition.get("taskDefinitionArn") != task_definition_arn
            or definition.get("networkMode") != "awsvpc"
        ):
            raise ValueError("qualification task definition identity or networking is invalid")
        app_container = next(
            (
                row
                for row in definition.get("containerDefinitions", [])
                if row.get("name") == self.config.app_container_name
            ),
            None,
        )
        if app_container is None:
            raise ValueError("qualification task definition has no application container")
        image = app_container.get("image")
        if not isinstance(image, str) or image.rsplit("@", 1)[-1] != next(iter(digests)):
            raise ValueError("task definition image differs from running tasks")
        environment = {
            row.get("name"): row.get("value")
            for row in app_container.get("environment", [])
            if isinstance(row.get("name"), str)
        }
        sealed_json = environment.get("SOC_SERVICE_CONFIG_JSON")
        service_sha = environment.get("SOC_SERVICE_SHA")
        content_sha = environment.get("SOC_CONTENT_SHA")
        config_sha = environment.get("SOC_CONFIGURATION_SHA256")
        if (
            not isinstance(sealed_json, str)
            or not isinstance(service_sha, str)
            or not isinstance(content_sha, str)
            or not isinstance(config_sha, str)
            or hashlib.sha256(sealed_json.encode("utf-8")).hexdigest() != config_sha
        ):
            raise ValueError("bound ECS task definition omits valid configuration pins")
        sealed = LiveSealedDocument.model_validate_json(sealed_json)
        observed = DeploymentBinding(
            account_id=account_id,
            region=self.config.region,
            cluster_arn=cluster_arn,
            service_arn=service_arn,
            task_definition_arn=task_definition_arn,
            deployment_name=self.config.service_name,
            deployment_id=deployment_id,
            image_digest=next(iter(digests)),
            service_sha=service_sha,
            content_sha=content_sha,
            configuration_sha256=config_sha,
        )
        if binding is not None and binding != observed:
            raise ValueError("live deployment differs from the requested binding")
        return DeploymentSnapshot(observed, sealed, service, network, tuple(tasks), environment)

    def observe_deployment(self) -> DeploymentBinding | None:
        """Return only complete observations; API failures remain unobserved."""
        try:
            return self.observe_deployment_snapshot().binding
        except (BotoCoreError, ClientError, KeyError, TypeError, ValueError):
            return None


@dataclass(frozen=True, slots=True)
class ConfiguredStagingAWS:
    clients: ExplicitBotoClients
    observer: ECSDeploymentObserver
    nightly: NightlyResultsClient | None = None
    network: NetworkProbeClient | None = None


def observe_deployment_snapshot(
    observer: ECSDeploymentObserver, binding: DeploymentBinding
) -> DeploymentSnapshot:
    """Return one live-validated deployment snapshot for all gate consumers."""
    return observer.observe_deployment_snapshot(binding)


def _build_collector(config: CollectorConfig | None, clients: ExplicitBotoClients):
    if config is None:
        return None
    module_name, separator, symbol_name = config.factory.partition(":")
    if not separator or not module_name or not symbol_name:
        raise ValueError("collector factory must use module:Symbol syntax")
    factory = getattr(import_module(module_name), symbol_name)
    return factory(clients=clients, **config.options)


def load_aws_client_config(path: Path) -> AWSClientConfig:
    """Load nonsecret AWS target/profile selection from an explicit JSON file."""
    raw: object = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("AWS client configuration must be a JSON object")
    return AWSClientConfig.model_validate(raw)


def build_explicit_staging_aws(config: AWSClientConfig) -> ConfiguredStagingAWS:
    """Assume the configured role from credentials explicitly loaded by source profile."""
    source = boto3.Session(profile_name=config.source_profile, region_name=config.region)
    credentials = source.get_credentials()
    if credentials is None or credentials.method not in {"shared-credentials-file", "sso", "login"}:
        raise ValueError(
            "source profile did not resolve to an allowed explicit credential provider"
        )
    source_sts = source.client("sts", region_name=config.region)
    assumed = source_sts.assume_role(
        RoleArn=config.role_arn, RoleSessionName="soc-live-qualification"
    )
    assumed_arn = assumed.get("AssumedRoleUser", {}).get("Arn", "")
    if not assumed_arn.startswith(
        f"arn:aws:sts::{config.account_id}:assumed-role/{config.role_arn.rsplit('/', 1)[-1]}/"
    ):
        raise ValueError("assumed role identity does not match configured account and role")
    key = assumed.get("Credentials", {})
    if not all(key.get(name) for name in ("AccessKeyId", "SecretAccessKey", "SessionToken")):
        raise ValueError("STS AssumeRole returned incomplete temporary credentials")
    session = boto3.Session(
        aws_access_key_id=key["AccessKeyId"],
        aws_secret_access_key=key["SecretAccessKey"],
        aws_session_token=key["SessionToken"],
        region_name=config.region,
    )
    sts = session.client("sts", region_name=config.region)
    verified = sts.get_caller_identity()
    if verified.get("Account") != config.account_id or verified.get("Arn") != assumed_arn:
        raise ValueError("GetCallerIdentity does not match the configured assumed role")
    clients = ExplicitBotoClients(session=session)
    observer = ECSDeploymentObserver(
        config=config,
        sts=sts,
        ecs=clients.client("ecs"),
    )
    return ConfiguredStagingAWS(
        clients=clients,
        observer=observer,
        nightly=_build_collector(config.nightly, clients),
        network=_build_collector(config.network, clients),
    )
