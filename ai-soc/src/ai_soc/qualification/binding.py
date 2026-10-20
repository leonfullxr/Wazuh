"""Canonical immutable binding embedded in every qualification task envelope."""

from __future__ import annotations

import re

from pydantic import Field, model_validator

from ai_soc.contracts.models import StrictModel


class DeploymentBinding(StrictModel):
    account_id: str = Field(pattern=r"^[0-9]{12}$")
    region: str = Field(min_length=1, max_length=64)
    cluster_arn: str = Field(min_length=1, max_length=512)
    service_arn: str = Field(min_length=1, max_length=512)
    task_definition_arn: str = Field(min_length=1, max_length=512)
    deployment_name: str = Field(min_length=1, max_length=128)
    deployment_id: str = Field(min_length=1, max_length=256)
    image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    service_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    content_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    configuration_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def arns_match_deployment(self) -> DeploymentBinding:
        prefix = f"arn:aws(?:-[a-z0-9-]+)?:ecs:{re.escape(self.region)}:{self.account_id}:"
        for arn, resource in (
            (self.cluster_arn, "cluster"),
            (self.service_arn, "service"),
            (self.task_definition_arn, "task-definition"),
        ):
            if re.fullmatch(prefix + resource + r"/.+", arn) is None:
                raise ValueError(f"qualification {resource} ARN differs from its binding")
        return self
