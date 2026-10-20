from __future__ import annotations

import hashlib
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from uuid import UUID

from ai_soc.qualification.evidence import EvidencePaths
from ai_soc.qualification.models import ProbeInvocationConfig
from scripts.staging.journal import (
    DeliveryMeasurement,
    DeliveryReceipt,
    RunIntent,
    _delivery_budget_seconds,
    _parse_time,
    _same_delivery_receipt_identities,
    _validate_delivery_measurement,
)
from scripts.staging.models import GateId, QualificationReceipt

ProbeSpec = ProbeInvocationConfig

if TYPE_CHECKING:
    from scripts.staging.verifier import VerifiedArtifact, VerifiedCanaryReceipt


class SessionDeliveryMixin:
    @property
    def launch_allowed(self) -> bool:
        expiry = self._journal.session_expires_at
        return (
            self._journal.barrier_reason is None
            and expiry is not None
            and datetime.now(UTC) < _parse_time(expiry)
        )

    @property
    def session_remaining_seconds(self) -> int:
        expiry = self._journal.session_expires_at
        if expiry is None:
            return 0
        return max(0, int((_parse_time(expiry) - datetime.now(UTC)).total_seconds()))

    @property
    def measured_delivery_budget(self) -> int:
        """Return this session's fresh canary measurement or abstain."""
        if self.session_remaining_seconds <= 0:
            raise RuntimeError("qualification session absolute expiry has passed")
        measurement = self._journal.delivery_measurement
        if measurement is None:
            return self.bootstrap_delivery_measurement()
        budget = _validate_delivery_measurement(
            measurement,
            session_id=self.session_id,
            now=datetime.now(UTC),
        )
        if budget is None:
            raise RuntimeError(
                "qualification session canary delivery measurement is stale or invalid"
            )
        return budget

    def record_delivery_measurement(
        self,
        receipts: list[VerifiedCanaryReceipt],
        *,
        margin_seconds: int = 900,
    ) -> int:
        """Persist only verifier-sealed canary receipts from this journaled session."""
        from scripts.staging.verifier import is_verified_canary_receipt

        if not receipts or any(not is_verified_canary_receipt(item) for item in receipts):
            raise ValueError("delivery measurement requires authenticated canary proof objects")
        receipt_values: list[DeliveryReceipt] = []
        for proof in receipts:
            launch = proof.launch
            canary_run = next(
                (row for row in self._journal.runs if row.run_id == launch.expectation.run_id),
                None,
            )
            if (
                launch.expectation.session_id != self.session_id
                or canary_run is None
                or canary_run.state != "stopped"
                or launch.task_arn not in canary_run.task_arns
            ):
                raise ValueError("canary launch is not a stopped task in this session journal")
            receipt_values.append(DeliveryReceipt.model_validate(dict(proof.receipt)))
        budget = _delivery_budget_seconds(
            tuple(receipt_values),
            session_id=self.session_id,
            session_remaining_seconds=self.session_remaining_seconds,
            margin_seconds=margin_seconds,
        )
        if budget is None:
            raise ValueError("canary delivery receipts are missing, mismatched or out of budget")
        run_ids = {receipt.run_id for receipt in receipt_values}
        measurement = {
            "schema": "ai-soc.qualification-delivery-measurement.v1",
            "session_id": self.session_id,
            "run_id": next(iter(run_ids)),
            "receipts": tuple(receipt_values),
            "budget_seconds": budget,
            "margin_seconds": margin_seconds,
            "session_remaining_seconds": self.session_remaining_seconds,
            "recorded_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }
        typed_measurement = DeliveryMeasurement.model_validate(measurement)
        if (
            _validate_delivery_measurement(
                typed_measurement, session_id=self.session_id, now=datetime.now(UTC)
            )
            != budget
        ):
            raise ValueError("canary delivery measurement failed strict journal validation")
        self._journal = replace(self._journal, delivery_measurement=typed_measurement)
        self._persist()
        return budget

    def bootstrap_delivery_measurement(self, *, margin_seconds: int = 900) -> int:
        """Run and authenticate the session's service and isolated canaries."""
        if self.resource_map is None:
            raise RuntimeError("session delivery calibration requires the sealed resource map")
        if self.session_remaining_seconds <= 150:
            raise RuntimeError("qualification session cannot fit the canary calibration run")
        existing = next(
            (
                run
                for run in reversed(self._journal.runs)
                if run.probe_spec is not None and run.probe_spec.entrypoint == "canary"
            ),
            None,
        )
        if existing is None:
            execution_seconds = 120
            collection_seconds = min(
                86_400 - execution_seconds,
                self.session_remaining_seconds - execution_seconds - 30,
            )
            if collection_seconds < 1:
                raise RuntimeError("qualification session cannot fit bounded canary delivery")
            spec = ProbeSpec(
                entrypoint="canary",
                parameters={
                    "inputs": {
                        "evidence_bucket": self.resource_map.evidence.bucket,
                        "kms_key_arn": self.resource_map.evidence.kms_key_arn,
                        "evidence_paths": EvidencePaths(
                            app_prefix=self.resource_map.evidence.app_prefix,
                            consumer_prefix=self.resource_map.evidence.consumer_prefix,
                            map_key=self.resource_map.evidence.map_key,
                            input_prefix=self.resource_map.evidence.input_prefix,
                        ).model_dump(mode="json"),
                    },
                    "container_name": "ai-soc",
                },
                network="canary_pair",
                execution_seconds=execution_seconds,
                collection_seconds=collection_seconds,
            )
            existing, _ = self.launch_probe(
                spec,
                gate_id=GateId.LV_MCP,
                contributor_id="mcp",
                slots=("service", "public-isolated"),
                _calibration=True,
            )
        elif existing.state == "ambiguous":
            raise RuntimeError("prior canary launch is ambiguous; launch barrier remains closed")
        if existing.state != "stopped":
            self.wait_for_completion(existing.run_id)
        proofs = self.authenticate_canary_run(existing.run_id)
        return self.record_delivery_measurement(proofs, margin_seconds=margin_seconds)

    def authenticate_canary_run(self, run_id: str) -> list[VerifiedCanaryReceipt]:
        """Revalidate a journaled canary's launches and exact output versions."""
        from scripts.staging.artifact_verification import AuthenticatedEvidenceVerifier
        from scripts.staging.cloudtrail import validate_session_logs
        from scripts.staging.verifier import (
            EvidenceIncomplete,
            LaunchExpectation,
            canonical_request_digest,
        )

        run = next((item for item in self._journal.runs if item.run_id == run_id), None)
        if run is None or run.probe_spec is None or run.probe_spec.entrypoint != "canary":
            raise ValueError("canary run is not present in the session journal")
        deadline = _parse_time(run.deadline_utc)
        remaining = (deadline - datetime.now(UTC)).total_seconds()
        if remaining <= 0:
            raise EvidenceIncomplete("canary delivery deadline expired")
        monotonic_deadline = time.monotonic() + remaining
        start_time = deadline - timedelta(
            seconds=run.probe_spec.execution_seconds + run.probe_spec.collection_seconds
        )
        for _attempt in range(1_000):
            remaining = monotonic_deadline - time.monotonic()
            if remaining <= 0:
                raise EvidenceIncomplete("canary delivery deadline expired")
            now = datetime.now(UTC)
            try:
                stop_response = self.clients.client("ecs").describe_tasks(
                    cluster=self.binding.cluster_arn,
                    tasks=list(run.task_arns),
                    include=["TAGS"],
                )
                stop_tasks = stop_response.get("tasks", [])
                stop_times: dict[str, datetime] = {}
                if (
                    stop_response.get("failures")
                    or not isinstance(stop_tasks, list)
                    or len(stop_tasks) != len(run.task_arns)
                    or {row.get("taskArn") for row in stop_tasks if isinstance(row, dict)}
                    != set(run.task_arns)
                ):
                    raise EvidenceIncomplete("canary task stop-time observation is incomplete")
                for task in stop_tasks:
                    task_arn = task.get("taskArn")
                    stopped_at = task.get("stoppedAt")
                    if (
                        task.get("lastStatus") != "STOPPED"
                        or not isinstance(task_arn, str)
                        or not self._task_identity(task, run)[0]
                        or not self._task_runtime_binding(task, run)
                    ):
                        raise EvidenceIncomplete("canary task has no authenticated stop time")
                    try:
                        stop_times[task_arn] = _parse_time(stopped_at)
                    except (TypeError, ValueError) as exc:
                        raise EvidenceIncomplete("canary task stop time is malformed") from exc
                logs = validate_session_logs(
                    resource_map=self.resource_map,
                    binding=self.binding,
                    s3_client=self.clients.client("s3"),
                    cloudtrail_client=self.clients.client("cloudtrail"),
                    credentials=getattr(
                        getattr(self.clients, "session", None), "get_credentials", lambda: None
                    )(),
                    start_time=start_time,
                    end_time=min(now, deadline),
                    timeout_seconds=max(1, min(120, int(remaining))),
                    deadline_monotonic=monotonic_deadline,
                )
                verifier = AuthenticatedEvidenceVerifier(logs)
                proofs: list[VerifiedCanaryReceipt] = []
                for index, placement in enumerate(run.task_slots):
                    request = run.launch_requests[index]
                    expectation = LaunchExpectation(
                        account_id=self.binding.account_id,
                        region=self.binding.region,
                        launcher_role_arn=self.launcher_role_arn,
                        cluster_arn=self.binding.cluster_arn,
                        task_definition_arn=self.binding.task_definition_arn,
                        started_by=run.started_by,
                        client_token=run.client_tokens[index],
                        session_id=self.session_id,
                        invocation_id=run.invocation_id,
                        run_id=run.run_id,
                        gate_id=GateId(run.gate_id),
                        contributor_id=run.contributor_id,
                        slot=placement,
                        task_role_arn=self.resource_map.service.application_role_arn,
                        binding=self.binding,
                        deadline_utc=run.deadline_utc,
                        launch_request_digest=canonical_request_digest(request),
                        required_request_fields=tuple(request),
                        execution_seconds=run.probe_spec.execution_seconds,
                        collection_seconds=run.probe_spec.collection_seconds,
                    )
                    launch = verifier.authenticate_launch(expectation)
                    task_token = hashlib.sha256(launch.task_arn.encode()).hexdigest()[:24]
                    key = (
                        f"qualification/{self.session_id}/canary/{placement}/"
                        f"{run.run_id}/{task_token}.json"
                    )
                    event = next(
                        (
                            row
                            for row in logs.events
                            if row.get("eventSource") == "s3.amazonaws.com"
                            and row.get("eventName") == "PutObject"
                            and isinstance(row.get("requestParameters"), dict)
                            and row["requestParameters"].get("bucketName")
                            == self.resource_map.evidence.bucket
                            and row["requestParameters"].get("key") == key
                        ),
                        None,
                    )
                    if event is None or not isinstance(event.get("eventID"), str):
                        raise EvidenceIncomplete("canary object writer event is not delivered")
                    proofs.append(
                        verifier.authenticate_canary_delivery(
                            launch,
                            event_id=event["eventID"],
                            bucket=self.resource_map.evidence.bucket,
                            key=key,
                            placement=placement,
                            task_finished_at=stop_times[launch.task_arn],
                            expected_bucket_owner=self.binding.account_id,
                            s3_client=self.clients.client("s3"),
                        )
                    )
                return proofs
            except EvidenceIncomplete:
                remaining = monotonic_deadline - time.monotonic()
                if remaining <= 0:
                    raise
                time.sleep(min(30.0, remaining))
        raise EvidenceIncomplete("canary proof polling exceeded its bounded attempt count")

    def require_launch_allowed(self) -> None:
        if not self.launch_allowed:
            raise RuntimeError(
                self._journal.barrier_reason or "qualification launch barrier is closed"
            )

    def resume_invocation(
        self, *, session_id: str, invocation_id: str, run_ids: tuple[str, ...]
    ) -> tuple[RunIntent, ...]:
        """Resume only caller-authorized runs from this journal and invocation."""
        try:
            UUID(session_id)
            UUID(invocation_id)
            for run_id in run_ids:
                UUID(run_id)
        except ValueError as exc:
            raise ValueError("resume identities must be canonical UUIDs") from exc
        if not run_ids or len(set(run_ids)) != len(run_ids):
            raise ValueError("resume requires a unique nonempty run allowlist")
        if self.session_id != session_id:
            raise ValueError("resume session ID differs from the durable journal")
        by_id = {run.run_id: run for run in self._journal.runs}
        selected = tuple(by_id.get(run_id) for run_id in run_ids)
        if any(run is None for run in selected):
            raise ValueError("resume run allowlist includes a foreign run")
        runs = tuple(run for run in selected if run is not None)
        if any(run.invocation_id != invocation_id for run in runs):
            raise ValueError("resume invocation differs from durable launch intent")
        if any(run.state != "stopped" for run in runs):
            raise RuntimeError("resume run cleanup is not confirmed")
        self.invocation_id = invocation_id
        self._authenticate_delivery_measurement()
        return runs

    def _authenticate_delivery_measurement(self) -> int:
        """Require the journaled canary calibration to survive full reauthentication."""
        from scripts.staging.verifier import EvidenceIncomplete

        measurement = self._journal.delivery_measurement
        if not isinstance(measurement, DeliveryMeasurement):
            raise EvidenceIncomplete(
                "resume requires an authenticated session delivery measurement"
            )
        budget = _validate_delivery_measurement(
            measurement, session_id=self.session_id, now=datetime.now(UTC)
        )
        if budget is None:
            raise EvidenceIncomplete("resume delivery measurement is missing, stale or malformed")
        run_id = measurement.run_id
        canary = next(
            (
                run
                for run in self._journal.runs
                if run.run_id == run_id
                and run.probe_spec is not None
                and run.probe_spec.entrypoint == "canary"
            ),
            None,
        )
        if canary is None or canary.state != "stopped":
            raise EvidenceIncomplete("resume delivery measurement has no stopped journaled canary")
        proofs = self.authenticate_canary_run(canary.run_id)
        authenticated = tuple(
            DeliveryReceipt.model_validate(dict(proof.receipt)) for proof in proofs
        )
        recorded = measurement.receipts
        if not _same_delivery_receipt_identities(authenticated, recorded):
            raise EvidenceIncomplete("resume delivery measurement failed canary reauthentication")
        return budget

    def require_run_deadlines(self, run_ids: tuple[str, ...]) -> None:
        """Fail closed when reload reaches any original run or session deadline."""
        from scripts.staging.verifier import EvidenceIncomplete

        now = datetime.now(UTC)
        expiry = _parse_time(self._journal.session_expires_at or "")
        if now >= expiry:
            raise EvidenceIncomplete("qualification session absolute expiry has passed")
        by_id = {run.run_id: run for run in self._journal.runs}
        for run_id in run_ids:
            run = by_id.get(run_id)
            if run is None or now >= _parse_time(run.deadline_utc):
                raise EvidenceIncomplete("original qualification delivery deadline expired")

    def run_receipt(self, run_id: str) -> QualificationReceipt:
        """Return durable launch identity for an untrusted wire receipt to reference."""
        run = next((item for item in self._journal.runs if item.run_id == run_id), None)
        if run is None:
            raise ValueError("qualification run is absent from the durable journal")
        return QualificationReceipt(
            session_id=self.session_id,
            invocation_id=run.invocation_id,
            run_id=run.run_id,
            started_by=run.started_by,
            gate_id=GateId(run.gate_id),
            contributor_id=run.contributor_id,
            task_slots=run.task_slots,
            task_arns=run.task_arns,
            deadline_utc=run.deadline_utc,
            probe_spec=run.probe_spec,
            launch_requests=run.launch_requests,
            state=run.state,
        )

    def run_diagnostics(self, run_id: str) -> tuple[str, ...]:
        """Return safe reload diagnostics without exposing provider error bodies."""
        return self._authentication_diagnostics.get(run_id, ())

    def authenticate_run(self, run_id: str) -> tuple[VerifiedArtifact, ...]:
        """Reauthenticate every task launch and exact output version from trail logs."""
        from scripts.staging.run_authentication import authenticate_run

        return authenticate_run(self, run_id)
