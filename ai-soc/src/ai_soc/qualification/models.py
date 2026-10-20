"""Strict typed requests for shared qualification probes."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Annotated, Literal, cast
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ai_soc.qualification.binding import DeploymentBinding
from ai_soc.qualification.evidence import EvidencePaths
from ai_soc.qualification.mcp_models import LvMcpInputs
from ai_soc.qualification.state_models import StateProbeInputs


class _TaskProbeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    container_name: Literal["ai-soc"] = "ai-soc"


class McpTaskProbeConfig(_TaskProbeConfig):
    entrypoint: Literal["mcp"]
    inputs: LvMcpInputs


class StateTaskProbeConfig(_TaskProbeConfig):
    entrypoint: Literal["state"]
    inputs: StateProbeInputs


class CanaryInputs(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_bucket: str
    kms_key_arn: str
    evidence_paths: EvidencePaths


class CanaryTaskProbeConfig(_TaskProbeConfig):
    entrypoint: Literal["canary"]
    inputs: CanaryInputs


TaskProbeConfig = Annotated[
    McpTaskProbeConfig | StateTaskProbeConfig | CanaryTaskProbeConfig,
    Field(discriminator="entrypoint"),
]


class ProbeInvocationConfig(BaseModel):
    """Closed scenario request persisted in the coordinator's run journal."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    parameters: TaskProbeConfig
    input_pins: tuple[dict[str, str], ...] = ()
    network: Literal["service", "public_isolated", "canary_pair"] = "service"
    execution_seconds: int = Field(ge=1, le=900)
    collection_seconds: int = Field(ge=1, le=86_400)

    @model_validator(mode="before")
    @classmethod
    def bind_entrypoint_to_parameters(cls, value: object) -> object:
        if not isinstance(value, dict):
            return value
        raw_data = cast(dict[object, object], value)
        if "entrypoint" not in raw_data:
            return raw_data
        data = dict(raw_data)
        entrypoint = data.pop("entrypoint")
        parameters = data.get("parameters")
        if not isinstance(parameters, dict):
            raise ValueError("qualification parameters must be a scenario object")
        raw_parameters = cast(dict[object, object], parameters)
        data["parameters"] = {**raw_parameters, "entrypoint": entrypoint}
        return data

    @property
    def entrypoint(self) -> Literal["mcp", "state", "canary"]:
        return self.parameters.entrypoint

    @field_validator("parameters")
    @classmethod
    def _bounded_parameters(cls, value: TaskProbeConfig) -> TaskProbeConfig:
        encoded = json.dumps(
            value.model_dump(mode="json"), allow_nan=False, sort_keys=True, separators=(",", ":")
        )
        if len(encoded.encode()) > 4096:
            raise ValueError("qualification parameters exceed 4 KiB")
        return value

    @field_validator("input_pins")
    @classmethod
    def _bounded_pins(cls, value: object) -> tuple[dict[str, str], ...]:
        if not isinstance(value, tuple):
            raise ValueError("qualification input pins are malformed or exceed their bound")
        pins = cast(tuple[object, ...], value)
        if len(pins) > 64:
            raise ValueError("qualification input pins are malformed or exceed their bound")
        for raw_pin in pins:
            if not isinstance(raw_pin, dict):
                raise ValueError("qualification input pins are malformed or exceed their bound")
            pin = cast(dict[object, object], raw_pin)
            for key, item in pin.items():
                if not isinstance(key, str) or not isinstance(item, str):
                    raise ValueError("qualification input pins are malformed or exceed their bound")
        return cast(tuple[dict[str, str], ...], value)


class TaskLaunchConfig(BaseModel):
    """Typed launch payload packaged with each bounded qualification task."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scenario: ProbeInvocationConfig
    binding: DeploymentBinding
    run_id: UUID
    session_id: UUID
    invocation_id: UUID
    slot: str = Field(min_length=1, max_length=64)
    deadline_utc: datetime

    @field_validator("deadline_utc")
    @classmethod
    def _aware_deadline(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("task deadline must include a UTC offset")
        return value
