from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from scripts.staging.manifest import NetworkGateInput, NightlyCaseInput
from scripts.staging.models import (
    DeploymentBinding,
    GateId,
    ObligationResult,
    QualificationReceipt,
)

if TYPE_CHECKING:
    from scripts.staging.qualification_context import QualificationContext


class DeploymentObserver(Protocol):
    def observe_deployment(self) -> DeploymentBinding | None: ...


class NightlyResultsClient(Protocol):
    def collect_case_results(self) -> NightlyResultsReport: ...


@dataclass(frozen=True, slots=True)
class NightlyResultsReport:
    binding: DeploymentBinding
    cases: tuple[NightlyCaseInput, ...]
    obligations: tuple[ObligationResult, ...]


@dataclass(frozen=True, slots=True)
class NetworkProbeReport:
    binding: DeploymentBinding
    site_id: str
    obligations: tuple[ObligationResult, ...]


class NetworkProbeClient(Protocol):
    def probe_network(self, spec: NetworkGateInput) -> NetworkProbeReport: ...


class AWSServiceClientFactory(Protocol):
    """Creates service clients from an explicitly configured session."""

    def client(self, service_name: str) -> Any: ...


@dataclass(frozen=True, slots=True)
class GateAdapterReport:
    binding: DeploymentBinding
    obligations: tuple[ObligationResult, ...]
    results: dict[str, Any]
    verified_observations: tuple[Any, ...] = ()
    qualification_receipt: QualificationReceipt | None = None

    def __post_init__(self) -> None:
        if self.qualification_receipt is not None and not isinstance(
            self.qualification_receipt, QualificationReceipt
        ):
            raise ValueError("gate adapter qualification receipt must use the strict model")


InputT = TypeVar("InputT", bound=BaseModel)


class EmptyAdapterInput(BaseModel):
    model_config = ConfigDict(extra="forbid")


@dataclass(frozen=True, slots=True)
class GateAdapterRegistration:
    contributor_id: str
    gate_id: GateId
    adapter: GateAdapter[Any]
    input_model: type[BaseModel] = EmptyAdapterInput


class AdapterConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contributor_id: str
    gate_id: GateId
    factory: str
    input_model: str
    options: dict[str, Any] = Field(default_factory=dict)


class GateAdapter(Protocol[InputT]):
    """Frozen runner interface implemented by each gate owner."""

    gate_id: GateId

    def evaluate(
        self,
        *,
        inputs: InputT,
        clients: AWSServiceClientFactory,
        binding: DeploymentBinding,
        qualification_context: QualificationContext | None = None,
    ) -> GateAdapterReport: ...


@dataclass(frozen=True, slots=True)
class StagingClients:
    observer: DeploymentObserver | None = None
    nightly: NightlyResultsClient | None = None
    network: NetworkProbeClient | None = None
    aws: AWSServiceClientFactory | None = None
    adapters: dict[GateId, tuple[GateAdapterRegistration, ...]] | None = None
    qualification_context: QualificationContext | None = None
