"""Central qualification coordinator and evidence capability boundary.

The coordinator owns persistent launch intent and cleanup reconciliation. Gate
code never receives an ECS task ARN or a callback that can mint a PASS result.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import tempfile
import time
from contextlib import AbstractContextManager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import ValidationError

from ai_soc.qualification.models import ProbeInvocationConfig
from scripts.staging.certification import normalize_live_result
from scripts.staging.journal import (
    _JOURNAL_SCHEMA,
    QualificationJournal,
    RunIntent,
    _configured_journal_root,
    _journal_dict,
    _no_duplicate_keys,
    _parse_journal,
    _parse_time,
)
from scripts.staging.journal import (
    _binding_dict as _binding_dict,
)
from scripts.staging.launch_requests import build_launch_request, build_probe_config
from scripts.staging.models import DeploymentBinding, GateId
from scripts.staging.registry import PROBE_REGISTRY, probe_registrations
from scripts.staging.run_recovery import (
    RunEvent,
    apply_reconciliation,
    reduce_run_event,
    run_identity_set_resolved,
)
from scripts.staging.session_delivery import SessionDeliveryMixin
from scripts.staging.task_session import SessionTaskMixin

__all__ = ["QualificationSession", "ProbeSpec", "normalize_live_result"]

_MAX_JOURNAL_BYTES = 1024 * 1024
_LAUNCH_JOURNAL_RESERVE_BYTES = 16 * 1024


ProbeSpec = ProbeInvocationConfig


class _SessionLock(AbstractContextManager[None]):
    def __init__(self, lock_path: Path) -> None:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        self._file = lock_path.open("a+b")

    def __enter__(self) -> None:
        fcntl.flock(self._file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return None

    def __exit__(self, *_: object) -> None:
        fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
        self._file.close()


class QualificationSession(SessionDeliveryMixin, SessionTaskMixin):
    """One locked, persistent session for a deterministic account/cluster path."""

    def __init__(
        self,
        clients: Any,
        binding: DeploymentBinding,
        path: Path,
        lock: _SessionLock,
        resource_map: Any | None = None,
        launcher_role_arn: str | None = None,
    ):
        self.clients = clients
        self.binding = binding
        self.resource_map = resource_map
        self.launcher_role_arn = launcher_role_arn
        self.path = path
        self._lock = lock
        self._closed = False
        self._authentication_diagnostics: dict[str, tuple[str, ...]] = {}
        self._journal = self._load_or_initialize()
        self.session_id = self._journal.session_id
        self.invocation_id = str(uuid4())

    @classmethod
    def open(
        cls,
        clients: Any,
        binding: DeploymentBinding,
        *,
        journal_root: Path | None = None,
        resource_map: Any | None = None,
        launcher_role_arn: str | None = None,
    ) -> QualificationSession:
        root = journal_root if journal_root is not None else _configured_journal_root()
        cluster_hash = hashlib.sha256(binding.cluster_arn.encode()).hexdigest()[:24]
        path = root / binding.account_id / binding.region / f"{cluster_hash}.json"
        lock = _SessionLock(path.with_suffix(".lock"))
        lock.__enter__()
        try:
            return cls(clients, binding, path, lock, resource_map, launcher_role_arn)
        except BaseException:
            lock.__exit__(None, None, None)
            raise

    def bind(self, gate_id: GateId, contributor_id: str) -> Any:
        """Return a probe API bound to the sole registered scenario for a contributor."""
        from scripts.staging.qualification_context import RegisteredBoundProbe

        registrations = tuple(
            item
            for item in probe_registrations(gate_id, contributor_id)
            if item.obligation_evaluators
        )
        if len(registrations) != 1:
            raise ValueError("gate contributor does not have one registered qualification probe")
        return RegisteredBoundProbe(self, registrations[0])

    def _load_or_initialize(self) -> QualificationJournal:
        if self.path.exists():
            raw_bytes = self.path.read_bytes()
            if len(raw_bytes) > _MAX_JOURNAL_BYTES:
                return self._closed_journal("qualification journal exceeds size limit")
            try:
                raw = json.loads(raw_bytes, object_pairs_hook=_no_duplicate_keys)
                journal = _parse_journal(raw)
            except (ValueError, TypeError, KeyError, ValidationError, json.JSONDecodeError):
                return self._closed_journal("qualification journal is malformed or ambiguous")
            if (
                journal.account_id != self.binding.account_id
                or journal.region != self.binding.region
                or journal.cluster_arn != self.binding.cluster_arn
                or journal.binding != self.binding
            ):
                prior_binding = journal.binding
                current_binding = self.binding
                self.binding = prior_binding
                self._journal = journal
                self.session_id = journal.session_id
                try:
                    self.reconcile()
                finally:
                    self.binding = current_binding
                if self._journal.barrier_reason is not None:
                    self._update_journal_state(
                        session_fault=(
                            "deployment binding changed while qualification tasks need recovery"
                        )
                    )
                    self._persist()
                    return self._journal
                # Old task identities have now been reconciled. Start a fresh
                # session for the new deployment so old pins cannot authorize
                # a probe against the changed binding.
                self.session_id = str(uuid4())
                journal = QualificationJournal(
                    schema_version=_JOURNAL_SCHEMA,
                    account_id=current_binding.account_id,
                    region=current_binding.region,
                    cluster_arn=current_binding.cluster_arn,
                    session_id=self.session_id,
                    binding=current_binding,
                    runs=(),
                    session_expires_at=(datetime.now(UTC) + timedelta(hours=24))
                    .isoformat()
                    .replace("+00:00", "Z"),
                )
                self._journal = journal
                self._persist()
                return journal
            if journal.session_expires_at is None:
                self._journal = journal
                self.session_id = journal.session_id
                self.reconcile()
                self._update_journal_state(
                    session_fault="qualification journal lacks an absolute session expiry"
                )
                self._persist()
                return self._journal
            self._journal = journal
            self.session_id = journal.session_id
            if datetime.now(UTC) >= _parse_time(journal.session_expires_at):
                return self._closed_journal("qualification session absolute expiry has passed")
            if any(
                _parse_time(run.deadline_utc) > _parse_time(journal.session_expires_at)
                for run in journal.runs
            ):
                self.reconcile()
                self._update_journal_state(
                    session_fault="a persisted run deadline exceeds its session expiry"
                )
                self._persist()
                return self._journal
            self.reconcile()
            return self._journal
        if self.path.with_suffix(".known").exists():
            return self._closed_journal("qualification journal is missing after prior use")

        # First use still inspects active tasks before opening the barrier. A
        # tagged task without a matching journal is lost state, never ignored.
        try:
            active = self._discover_unjournaled_tasks()
        except Exception:
            return self._closed_journal(
                "active qualification task discovery is incomplete or ambiguous"
            )
        if active:
            return self._closed_journal("active qualification task found without its journal")
        journal = QualificationJournal(
            schema_version=_JOURNAL_SCHEMA,
            account_id=self.binding.account_id,
            region=self.binding.region,
            cluster_arn=self.binding.cluster_arn,
            session_id=str(uuid4()),
            binding=self.binding,
            runs=(),
            delivery_measurement=None,
            session_expires_at=(datetime.now(UTC) + timedelta(hours=24))
            .isoformat()
            .replace("+00:00", "Z"),
        )
        self._journal = journal
        self._persist()
        return journal

    def _closed_journal(self, reason: str) -> QualificationJournal:
        previous = getattr(self, "_journal", None)
        journal = QualificationJournal(
            schema_version=_JOURNAL_SCHEMA,
            account_id=self.binding.account_id,
            region=self.binding.region,
            cluster_arn=self.binding.cluster_arn,
            session_id=previous.session_id if previous else str(uuid4()),
            binding=self.binding,
            runs=previous.runs if previous else (),
            session_fault=reason,
            delivery_measurement=previous.delivery_measurement if previous else None,
            session_expires_at=(
                previous.session_expires_at
                if previous and previous.session_expires_at
                else datetime.now(UTC).isoformat().replace("+00:00", "Z")
            ),
        )
        self._journal = journal
        self._persist()
        return journal

    def _discover_unjournaled_tasks(self) -> tuple[str, ...]:
        ecs = self.clients.client("ecs")
        found: list[str] = []
        paginator = ecs.get_paginator("list_tasks")
        for page in paginator.paginate(cluster=self.binding.cluster_arn):
            arns = page.get("taskArns", [])
            for start in range(0, len(arns), 100):
                requested = arns[start : start + 100]
                described = ecs.describe_tasks(
                    cluster=self.binding.cluster_arn,
                    tasks=requested,
                    include=["TAGS"],
                )
                rows = described.get("tasks", [])
                failures = described.get("failures", [])
                described_arns = [row.get("taskArn") for row in rows if isinstance(row, dict)]
                if (
                    failures
                    or not isinstance(rows, list)
                    or len(described_arns) != len(requested)
                    or set(described_arns) != set(requested)
                ):
                    raise ValueError("qualification task discovery could not describe every task")
                for task in rows:
                    task_tags = task.get("tags")
                    if not isinstance(task_tags, list) or any(
                        not isinstance(tag, dict)
                        or not isinstance(tag.get("key"), str)
                        or not isinstance(tag.get("value"), str)
                        for tag in task_tags
                    ):
                        raise ValueError("qualification task discovery returned incomplete tags")
                    tags = {tag["key"]: tag["value"] for tag in task_tags}
                    if tags.get("qualification") == "true":
                        found.append(task["taskArn"])
        return tuple(found)

    def _persist(self, *, reserve_bytes: int = 0) -> None:
        payload = _journal_dict(self._journal)
        encoded = json.dumps(
            payload, allow_nan=False, sort_keys=True, separators=(",", ":")
        ).encode()
        if reserve_bytes < 0 or len(encoded) + reserve_bytes > _MAX_JOURNAL_BYTES:
            raise ValueError("qualification journal exceeds size limit")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        marker = self.path.with_suffix(".known")
        marker_fd = os.open(marker, os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            os.write(marker_fd, b"qualification journal initialized\n")
            os.fsync(marker_fd)
        finally:
            os.close(marker_fd)
        fd, temporary = tempfile.mkstemp(prefix=self.path.name + ".", dir=self.path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            directory_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def reconcile(self) -> None:
        """Refresh every startedBy run and keep the launch barrier closed on ambiguity."""
        ecs = self.clients.client("ecs")
        reconciled: list[RunIntent] = []
        cleanup_ids: list[str] = []
        cleanup_owned: dict[str, tuple[str, ...]] = {}
        for run in self._journal.runs:
            if run.state == "stopped" and run_identity_set_resolved(run):
                reconciled.append(run)
                continue
            discovered: set[str] = set(run.task_arns) | set(run.discovered_arns)
            paginator = ecs.get_paginator("list_tasks")
            for page in paginator.paginate(
                cluster=self.binding.cluster_arn,
                startedBy=run.started_by,
            ):
                discovered.update(page.get("taskArns", []))
            described: list[dict[str, Any]] = []
            describe_complete = True
            if discovered:
                response = ecs.describe_tasks(
                    cluster=self.binding.cluster_arn,
                    tasks=sorted(discovered),
                    include=["TAGS"],
                )
                described = response.get("tasks", [])
                failures = response.get("failures", [])
                describe_complete = (
                    not failures and {item.get("taskArn") for item in described} == discovered
                )
            observed_slots: set[str] = set()
            identity_valid = True
            for task in described:
                valid_task, slot = self._task_identity(task, run)
                if not valid_task:
                    identity_valid = False
                if isinstance(slot, str):
                    observed_slots.add(slot)
            owned_arns = tuple(
                sorted(
                    {
                        item["taskArn"]
                        for item in described
                        if isinstance(item.get("taskArn"), str) and self._task_owned(item, run)
                    }
                )
            )
            decision = apply_reconciliation(
                run,
                discovered_arns=tuple(sorted(discovered)),
                described_tasks=tuple(described),
                describe_complete=describe_complete,
                identity_valid=identity_valid,
                observed_slots=frozenset(observed_slots),
                owned_task_arns=owned_arns,
            )
            reconciled.append(decision.run)
            if decision.cleanup_task_arns:
                cleanup_owned[run.run_id] = decision.cleanup_task_arns
            if decision.cleanup_run:
                cleanup_ids.append(run.run_id)
        self._update_journal_state(runs=tuple(reconciled))
        try:
            self._persist()
        except (OSError, ValueError):
            # A full journal must not prevent cleanup of ARNs already proven
            # to belong to this run in the current reconciliation.
            self._update_journal_state(
                session_fault="qualification journal could not persist reconciliation"
            )
        for run_id, task_arns in cleanup_owned.items():
            run = next(item for item in self._journal.runs if item.run_id == run_id)
            if not self._stop_owned_tasks(run, task_arns, timeout_seconds=60):
                try:
                    self._persist()
                except (OSError, ValueError):
                    pass
        for run_id in cleanup_ids:
            self.stop_and_wait(run_id, timeout_seconds=60)

    def record_intent(
        self,
        *,
        gate_id: GateId,
        contributor_id: str,
        slots: tuple[str, ...],
        deadline_utc: str,
        probe_spec: ProbeSpec | None = None,
        persist: bool = True,
    ) -> RunIntent:
        self.require_launch_allowed()
        deadline = _parse_time(deadline_utc)
        if deadline <= datetime.now(UTC):
            raise ValueError("qualification run deadline must be in the future")
        if deadline > _parse_time(self._journal.session_expires_at or ""):
            raise ValueError("qualification run deadline exceeds its absolute session expiry")
        if not slots or len(slots) > 2 or len(set(slots)) != len(slots):
            raise ValueError("only registered one- or two-slot scenarios are allowed")
        run_id = str(uuid4())
        intent = RunIntent(
            invocation_id=self.invocation_id,
            run_id=run_id,
            started_by=run_id,
            client_tokens=tuple(str(uuid4()) for _ in slots),
            gate_id=gate_id.value,
            contributor_id=contributor_id,
            task_slots=slots,
            task_arns=(),
            probe_spec=probe_spec,
            launch_requests=(),
            deadline_utc=deadline_utc,
            state="intent",
        )
        if persist:
            self._update_journal_state(runs=self._journal.runs + (intent,))
            self._persist()
        return intent

    def launch_probe(
        self,
        spec: ProbeSpec,
        *,
        gate_id: GateId,
        contributor_id: str,
        slots: tuple[str, ...],
        _calibration: bool = False,
    ) -> tuple[RunIntent, tuple[dict[str, Any], ...]]:
        """Persist and launch only registered same-image qualification tasks."""
        registration = PROBE_REGISTRY.get((gate_id, contributor_id, spec.entrypoint))
        if registration is None:
            raise ValueError("qualification task entrypoint is not registered for this gate")
        if (spec.entrypoint == "canary") != _calibration:
            raise ValueError("canary entrypoint is reserved for the session calibration path")
        if spec.network == "canary_pair" and spec.entrypoint != "canary":
            raise ValueError("paired networking is reserved for the session canary")
        if self.resource_map is None:
            raise RuntimeError("sealed qualification resource map is unavailable")
        is_canary = spec.entrypoint == "canary" and _calibration
        if not self.resource_map.certification_enabled and not is_canary:
            raise RuntimeError("qualification certification is disabled by the sealed resource map")
        if spec.entrypoint != "canary":
            try:
                measured_budget = self.measured_delivery_budget
            except RuntimeError as exc:
                raise ValueError("probe requires a fresh session canary measurement") from exc
            if spec.collection_seconds != measured_budget:
                raise ValueError(
                    "probe collection budget differs from the session canary measurement"
                )
        expected_slots = registration.slots
        if slots != expected_slots:
            raise ValueError("qualification task slots do not match the registered scenario")
        ecs = self.clients.client("ecs")
        services = ecs.describe_services(
            cluster=self.binding.cluster_arn, services=[self.binding.service_arn]
        ).get("services", [])
        if len(services) != 1 or services[0].get("status") != "ACTIVE":
            raise RuntimeError("bound ECS service network could not be observed")
        service = services[0]
        observed_network = service.get("networkConfiguration")
        if not isinstance(observed_network, dict) or not isinstance(
            observed_network.get("awsvpcConfiguration"), dict
        ):
            raise RuntimeError("bound ECS service has no awsvpc network configuration")
        map_network = self.resource_map.network
        task_sg = self.resource_map.service.task_security_group_id
        if not isinstance(task_sg, str) or not task_sg:
            raise RuntimeError("sealed map omits the qualification task security group")
        if spec.network == "service" or spec.network == "canary_pair":
            network = observed_network
            awsvpc = network["awsvpcConfiguration"]
            if (
                not set(awsvpc.get("subnets", ())).issubset(set(map_network.service_subnet_ids))
                or set(awsvpc.get("securityGroups", ())) != {task_sg}
                or awsvpc.get("assignPublicIp") != "DISABLED"
            ):
                raise RuntimeError("bound service network differs from sealed qualification map")
        else:
            subnets = list(map_network.public_isolated_subnet_ids)
            if not subnets:
                raise RuntimeError("sealed map omits public-isolated subnets")
            network = {
                "awsvpcConfiguration": {
                    "subnets": subnets,
                    "securityGroups": [task_sg],
                    "assignPublicIp": "DISABLED",
                }
            }
        launch_type = service.get("launchType")
        strategy = service.get("capacityProviderStrategy") or []
        if bool(launch_type) == bool(strategy):
            raise RuntimeError("bound ECS service launch mode is ambiguous")
        container_name = spec.parameters.container_name
        if container_name != "ai-soc":
            raise RuntimeError("qualification container differs from the registered app container")
        if spec.parameters.inputs.evidence_bucket != self.resource_map.evidence.bucket:
            raise RuntimeError("qualification evidence bucket differs from sealed map")
        deadline = (
            datetime.fromtimestamp(
                time.time() + spec.execution_seconds + spec.collection_seconds, tz=UTC
            )
            .isoformat()
            .replace("+00:00", "Z")
        )
        if _parse_time(deadline) > _parse_time(self._journal.session_expires_at or ""):
            raise ValueError("qualification run deadline exceeds its absolute session expiry")
        run = self.record_intent(
            gate_id=gate_id,
            contributor_id=contributor_id,
            slots=slots,
            deadline_utc=deadline,
            probe_spec=spec,
            persist=False,
        )
        requests: list[dict[str, Any]] = []
        for index, slot in enumerate(slots):
            slot_network = (
                "service"
                if slot == "service"
                else "public_isolated"
                if spec.network == "canary_pair"
                else spec.network
            )
            if slot_network == "service":
                slot_launch_network = network
            elif spec.network == "canary_pair":
                subnets = list(map_network.public_isolated_subnet_ids)
                if not subnets:
                    raise RuntimeError("sealed map omits public-isolated subnets")
                slot_launch_network = {
                    "awsvpcConfiguration": {
                        "subnets": subnets,
                        "securityGroups": [task_sg],
                        "assignPublicIp": "DISABLED",
                    }
                }
            else:
                slot_launch_network = network
            config = build_probe_config(
                registration,
                scenario=spec,
                binding=self.binding,
                run_id=run.run_id,
                session_id=self.session_id,
                invocation_id=self.invocation_id,
                slot=slot,
                deadline_utc=deadline,
                evidence_bucket=self.resource_map.evidence.bucket,
                kms_key_arn=self.resource_map.evidence.kms_key_arn,
                account_id=self.binding.account_id,
            )
            requests.append(
                build_launch_request(
                    registration,
                    config=config,
                    container_name=container_name,
                    cluster_arn=self.binding.cluster_arn,
                    task_definition_arn=self.binding.task_definition_arn,
                    started_by=run.started_by,
                    client_token=run.client_tokens[index],
                    network_configuration=slot_launch_network,
                    session_id=self.session_id,
                    invocation_id=self.invocation_id,
                    run_id=run.run_id,
                    slot=slot,
                    launch_type=launch_type,
                    capacity_provider_strategy=strategy,
                    platform_version=service.get("platformVersion"),
                )
            )
        self._set_launch_requests(run.run_id, tuple(requests), initial=run)
        # A task is recorded immediately after each successful API response. If
        # a later slot fails, cleanup still owns every earlier returned ARN.
        launched: list[dict[str, Any]] = []
        try:
            for request in requests:
                response = ecs.run_task(**request)
                tasks = response.get("tasks", [])
                if response.get("failures") or len(tasks) != 1:
                    raise RuntimeError("ECS did not launch exactly one registered probe task")
                task = tasks[0]
                if not isinstance(task, dict) or not isinstance(task.get("taskArn"), str):
                    raise RuntimeError("ECS RunTask response omitted a task ARN")
                self._record_launched_task(run.run_id, task["taskArn"])
                launched.append(task)
            updated = next(item for item in self._journal.runs if item.run_id == run.run_id)
            return updated, tuple(launched)
        except Exception:
            updated = next(item for item in self._journal.runs if item.run_id == run.run_id)
            if updated.task_arns:
                self.stop_and_wait(run.run_id, timeout_seconds=min(60, spec.execution_seconds))
            updated = next(item for item in self._journal.runs if item.run_id == run.run_id)
            # A timeout/exception may hide a successful RunTask response. Keep
            # the barrier closed even when every ARN already known was stopped.
            self._mark_ambiguous(updated)
            raise

    def _set_launch_requests(
        self,
        run_id: str,
        requests: tuple[dict[str, Any], ...],
        *,
        initial: RunIntent | None = None,
    ) -> None:
        run = next((item for item in self._journal.runs if item.run_id == run_id), initial)
        if run is None:
            raise ValueError("launch request has no durable intent")
        updated = replace(run, launch_requests=requests)
        if any(item.run_id == run_id for item in self._journal.runs):
            self._replace_run(updated)
        else:
            self._update_journal_state(runs=self._journal.runs + (updated,))
        self._persist(reserve_bytes=_LAUNCH_JOURNAL_RESERVE_BYTES * len(run.task_slots))

    def _record_launched_task(self, run_id: str, task_arn: str) -> None:
        run = next(item for item in self._journal.runs if item.run_id == run_id)
        if run.state not in {"intent", "launched", "ambiguous"}:
            raise ValueError("task response does not match an active launch intent")
        if not task_arn.startswith("arn:") or task_arn in run.task_arns:
            raise ValueError("RunTask returned a malformed or duplicate task ARN")
        arns = run.task_arns + (task_arn,)
        complete = len(arns) == len(run.task_slots)
        event = RunEvent.LAUNCH_COMPLETE if complete else RunEvent.LAUNCH_PARTIAL
        self._replace_run(reduce_run_event(run, event, task_arns=arns))
        self._persist()

    def _mark_ambiguous(self, run: RunIntent) -> None:
        self._replace_run(reduce_run_event(run, RunEvent.UNCERTAIN))
        self._persist()

    def record_task_arns(self, run_id: str, task_arns: tuple[str, ...]) -> None:
        """Persist every RunTask ARN before any result collection or cleanup."""
        run = next((item for item in self._journal.runs if item.run_id == run_id), None)
        if run is None or run.state != "intent":
            raise ValueError("RunTask response does not match a durable launch intent")
        if not task_arns or len(set(task_arns)) != len(task_arns):
            raise ValueError("RunTask response task set is empty or duplicated")
        if any(not arn.startswith("arn:") for arn in task_arns):
            raise ValueError("RunTask response contains a malformed task ARN")
        complete = len(task_arns) == len(run.task_slots)
        event = RunEvent.LAUNCH_COMPLETE if complete else RunEvent.LAUNCH_PARTIAL
        updated = reduce_run_event(run, event, task_arns=task_arns)
        self._replace_run(updated)
        self._persist()
