"""Explicit, read-only AWS and bound-probe access for qualification adapters."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from ai_soc.qualification.models import ProbeInvocationConfig
from scripts.staging.journal import RunIntent
from scripts.staging.models import DeploymentBinding, GateId, QualificationReceipt
from scripts.staging.registry import ProbeRegistration

if TYPE_CHECKING:
    from scripts.staging.aws_clients import DeploymentSnapshot
    from scripts.staging.resource_map import QualificationResourceMap
    from scripts.staging.verifier import VerifiedArtifact


class BoundProbe(Protocol):
    @property
    def measured_delivery_budget(self) -> int: ...

    def run(self, spec: ProbeInvocationConfig) -> ProbeOutcome: ...


@dataclass(frozen=True, slots=True)
class ProbeOutcome:
    receipt: QualificationReceipt
    finished_tasks: tuple[TaskCompletion, ...]


@dataclass(frozen=True, slots=True)
class TaskCompletion:
    task_arn: str
    last_status: str
    exit_code: int
    stopped_at: datetime | None


@dataclass(slots=True)
class RegisteredBoundProbe:
    coordinator: QualificationCoordinator
    registration: ProbeRegistration

    @property
    def measured_delivery_budget(self) -> int:
        return self.coordinator.measured_delivery_budget

    def run(self, spec: ProbeInvocationConfig) -> ProbeOutcome:
        if spec.entrypoint != self.registration.entrypoint:
            raise ValueError("probe spec does not match its bound registration")
        run, _launched = self.coordinator.launch_probe(
            spec,
            gate_id=self.registration.gate_id,
            contributor_id=self.registration.contributor_id,
            slots=self.registration.slots,
        )
        finished = self.coordinator.wait_for_completion(run.run_id)
        return ProbeOutcome(self.coordinator.run_receipt(run.run_id), finished)


class AWSClientAccess(Protocol):
    def client(self, service_name: str) -> Any: ...


class QualificationCoordinator(Protocol):
    binding: DeploymentBinding

    def bind(self, gate_id: GateId, contributor_id: str) -> BoundProbe: ...

    def launch_probe(
        self,
        spec: ProbeInvocationConfig,
        *,
        gate_id: GateId,
        contributor_id: str,
        slots: tuple[str, ...],
    ) -> tuple[RunIntent, bool]: ...

    def close(self) -> None: ...

    def resume_invocation(
        self, *, session_id: str, invocation_id: str, run_ids: tuple[str, ...]
    ) -> tuple[RunIntent, ...]: ...

    def authenticate_run(self, run_id: str) -> tuple[VerifiedArtifact, ...]: ...

    def wait_for_completion(self, run_id: str) -> tuple[TaskCompletion, ...]: ...

    def run_receipt(self, run_id: str) -> QualificationReceipt: ...

    def run_diagnostics(self, run_id: str) -> tuple[str, ...]: ...

    def require_run_deadlines(self, run_ids: tuple[str, ...]) -> None: ...


@runtime_checkable
class QualificationMapObserver(Protocol):
    qualification_launcher_role_arn: str

    def observe_deployment_snapshot(self, binding: DeploymentBinding) -> DeploymentSnapshot: ...


class _GuardedEcsClient:
    def __init__(self, delegate: Any) -> None:
        self._delegate = delegate

    def run_task(self, **_: Any) -> Any:
        raise RuntimeError("ECS RunTask must go through the qualification coordinator")

    def stop_task(self, **_: Any) -> Any:
        raise RuntimeError("ECS StopTask must go through the qualification coordinator")

    def __getattr__(self, name: str) -> Any:
        return getattr(self._delegate, name)


@dataclass(slots=True)
class QualificationContext:
    _aws: AWSClientAccess
    coordinator: QualificationCoordinator
    resource_map: QualificationResourceMap
    _owns_coordinator: bool
    deployment_snapshot: DeploymentSnapshot | None = None

    def client(self, service_name: str) -> Any:
        client = self._aws.client(service_name)
        return _GuardedEcsClient(client) if service_name == "ecs" else client

    def close(self) -> None:
        if self._owns_coordinator:
            self.coordinator.close()
            self._owns_coordinator = False

    def bind_probe(self, gate_id: GateId, contributor_id: str) -> BoundProbe:
        return self.coordinator.bind(gate_id, contributor_id)


def require_qualification_context(value: object) -> QualificationContext:
    if not isinstance(value, QualificationContext):
        raise RuntimeError("adapter requires the shared qualification context")
    return value


def open_qualification_context(
    *,
    aws: AWSClientAccess,
    binding: Any,
    observer: QualificationMapObserver,
    context: QualificationContext | None = None,
    resource_map: QualificationResourceMap | None = None,
    deployment_snapshot: DeploymentSnapshot | None = None,
    journal_root: Any = None,
) -> QualificationContext:
    """Open one sealed resource map and one journal owner for a gate invocation."""
    if context is not None:
        if context.coordinator.binding != binding:
            raise ValueError("existing qualification context has a different deployment binding")
        return context
    if not isinstance(getattr(observer, "qualification_launcher_role_arn", None), str):
        raise ValueError("deployment observer has no approved qualification launcher role")
    if deployment_snapshot is None and not callable(
        getattr(observer, "observe_deployment_snapshot", None)
    ):
        raise ValueError("deployment observer cannot provide a validated snapshot")
    snapshot = deployment_snapshot or observer.observe_deployment_snapshot(binding)
    if snapshot.binding != binding:
        raise ValueError("deployment snapshot changed the requested binding")
    if resource_map is None:
        from scripts.staging.resource_map import load_pinned_resource_map

        pin = snapshot.sealed_document.qualification
        if pin is None:
            raise ValueError("live sealed configuration has no qualification map pin")
        resource_map = load_pinned_resource_map(pin, binding=binding, s3_client=aws.client("s3"))
    from scripts.staging.attributed_probe import QualificationSession

    coordinator = QualificationSession.open(
        aws,
        binding,
        resource_map=resource_map,
        launcher_role_arn=observer.qualification_launcher_role_arn,
        journal_root=journal_root,
    )
    return QualificationContext(aws, coordinator, resource_map, True, snapshot)
