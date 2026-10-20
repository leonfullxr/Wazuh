from __future__ import annotations

import json
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict, ValidationError

from scripts.staging.adapters import run_live_gate
from scripts.staging.aggregation import aggregate_results, load_gate_result
from scripts.staging.aws_clients import (
    AWSClientConfig,
    ECSDeploymentObserver,
    build_explicit_staging_aws,
)
from scripts.staging.clients import GateAdapterRegistration, GateAdapterReport, StagingClients
from scripts.staging.evidence import write_evidence
from scripts.staging.manifest import parse_manifest
from scripts.staging.models import (
    AcceptanceId,
    DeploymentBinding,
    EvidenceKind,
    EvidenceReference,
    GateId,
    ObligationResult,
    ObligationStatus,
    matches_expected_binding,
)
from scripts.staging.registry import ACCEPTANCE_GATE, GATE_REGISTRY
from scripts.staging_aggregate import main as aggregate_cli
from tests.unit.live.live_boot_fixture import _sealed


def _binding(**overrides: str | None) -> DeploymentBinding:
    values = {
        "account_id": "123456789012",
        "region": "eu-central-1",
        "cluster_arn": "arn:aws:ecs:eu-central-1:123456789012:cluster/qualification",
        "service_arn": (
            "arn:aws:ecs:eu-central-1:123456789012:service/qualification/synthetic-staging"
        ),
        "task_definition_arn": "arn:aws:ecs:eu-central-1:123456789012:task-definition/ai-soc:7",
        "deployment_name": "synthetic-staging",
        "deployment_id": "ecs-svc/1234567890123456789",
        "image_digest": "c" * 64,
        "service_sha": "a" * 40,
        "content_sha": "b" * 40,
        "configuration_sha256": "d" * 64,
    }
    values.update(overrides)
    if "cluster_arn" not in overrides:
        values["cluster_arn"] = (
            f"arn:aws:ecs:{values['region']}:{values['account_id']}:cluster/qualification"
        )
    if "service_arn" not in overrides:
        values["service_arn"] = (
            f"arn:aws:ecs:{values['region']}:{values['account_id']}:service/qualification/synthetic-staging"
        )
    if "task_definition_arn" not in overrides:
        values["task_definition_arn"] = (
            f"arn:aws:ecs:{values['region']}:{values['account_id']}:task-definition/ai-soc:7"
        )
    return DeploymentBinding(**values)


def _manifest(gate_id: GateId = GateId.LV_PLATFORM) -> dict[str, Any]:
    return {
        "schema_version": "3",
        "gate_id": gate_id.value,
        "acceptance_ids": [],
        "owners": ["framework test"],
        "artifacts": {
            "service_sha": "a" * 40,
            "content_sha": "b" * 40,
            "artifact_digest": "c" * 64,
        },
        "expected_deployment": {
            "account_id": "123456789012",
            "region": "eu-central-1",
            "cluster_arn": "arn:aws:ecs:eu-central-1:123456789012:cluster/qualification",
            "service_arn": (
                "arn:aws:ecs:eu-central-1:123456789012:service/qualification/synthetic-staging"
            ),
            "task_definition_arn": "arn:aws:ecs:eu-central-1:123456789012:task-definition/ai-soc:7",
            "deployment_name": "synthetic-staging",
            "deployment_id": "ecs-svc/1234567890123456789",
            "image_digest": "c" * 64,
            "service_sha": "a" * 40,
            "content_sha": "b" * 40,
            "configuration_sha256": "d" * 64,
        },
        "commands": ["pytest framework seam"],
        "inputs": {},
    }


class _Observer:
    def __init__(self, value: DeploymentBinding | None):
        self.value = value

    def observe_deployment(self) -> DeploymentBinding | None:
        return self.value


class _AWSFactory:
    def client(self, service_name: str) -> object:
        return service_name


def _all_obligations(gate_id: GateId) -> tuple[ObligationResult, ...]:
    return tuple(
        ObligationResult(
            item.obligation_id,
            ObligationStatus.PASS,
            "observed",
            (EvidenceReference(EvidenceKind.CLOUDTRAIL_EVENT, "event-123"),),
        )
        for item in GATE_REGISTRY[gate_id].obligations
    )


class _ConfiguredInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_ref: str


class _ConfiguredAdapter:
    gate_id = GateId.LV_PLATFORM

    def evaluate(self, *, inputs, clients, binding):
        assert isinstance(inputs, _ConfiguredInput)
        assert inputs.target_ref == "platform/config"
        return GateAdapterReport(
            binding, _all_obligations(GateId.LV_PLATFORM), {"configured": True}
        )


class _ConfiguredCollector:
    def __init__(self, *, clients, marker):
        self.clients = clients
        self.marker = marker


def _configured_nightly_client(*, clients, marker):
    return _ConfiguredCollector(clients=clients, marker=marker)


def _configured_network_client(*, clients, marker):
    return _ConfiguredCollector(clients=clients, marker=marker)


def _passing_result(gate_id: GateId, binding: DeploymentBinding):
    from scripts.staging.models import LiveAcceptanceResult, LiveGateResult

    obligations = _all_obligations(gate_id)
    accepts = tuple(
        LiveAcceptanceResult(
            acceptance_id=acceptance_id,
            gate_id=gate_id,
            status="PASS",
            binding=binding,
            obligation=ObligationResult(
                acceptance_id.value,
                ObligationStatus.PASS,
                "observed",
                (EvidenceReference(EvidenceKind.CLOUDTRAIL_EVENT, "event-123"),),
            ),
            evidence_refs=(EvidenceReference(EvidenceKind.CLOUDTRAIL_EVENT, "event-123"),),
        )
        for acceptance_id, producer in ACCEPTANCE_GATE.items()
        if producer == gate_id
    )
    return LiveGateResult(
        gate_id=gate_id,
        owners=("framework test",),
        inputs_manifest_sha256="e" * 64,
        service_sha=binding.service_sha,
        content_sha=binding.content_sha,
        artifact_digest="c" * 64,
        status="PASS",
        commands=("test",),
        results={},
        evidence_refs=(EvidenceReference(EvidenceKind.CLOUDTRAIL_EVENT, "event-123"),),
        checked_at="2026-10-07T00:00:00Z",
        binding=binding,
        expected_binding=binding,
        obligations=obligations,
        acceptance_results=accepts,
    )


def test_registry_covers_all_eleven_continuity_gates_and_both_acceptances() -> None:
    assert set(GATE_REGISTRY) == set(GateId)
    assert set(ACCEPTANCE_GATE) == {AcceptanceId.GP3, AcceptanceId.GP4}
    assert ACCEPTANCE_GATE[AcceptanceId.GP3] == GateId.LV_NIGHTLY
    assert ACCEPTANCE_GATE[AcceptanceId.GP4] == GateId.LV_NETWORK
    assert len(GATE_REGISTRY[GateId.LV_NETWORK].obligations) == 7


def test_manifest_rejects_unknown_gate_input_fields() -> None:
    raw = _manifest()
    raw["inputs"] = {"unexpected_gate": {"should_not_be_ignored": True}}
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        parse_manifest(raw)


def test_missing_observation_stays_not_run_and_unbound(tmp_path: Path) -> None:
    _, manifest = parse_manifest(_manifest())
    assert manifest is not None
    result = run_live_gate(
        manifest,
        manifest_hash="f" * 64,
        runner_commands=("test",),
        clients=StagingClients(observer=_Observer(None)),
    )
    assert result.status == "NOT_RUN"
    assert result.binding is None
    assert len(result.obligations) == len(GATE_REGISTRY[GateId.LV_PLATFORM].obligations)
    assert "no complete AWS observation" in result.results["reason"]


def test_observation_without_ecs_deployment_id_stays_not_run() -> None:
    _, manifest = parse_manifest(_manifest())
    assert manifest is not None
    result = run_live_gate(
        manifest,
        manifest_hash="f" * 64,
        runner_commands=("test",),
        clients=StagingClients(observer=_Observer(_binding(deployment_id=None))),
    )
    assert result.status == "NOT_RUN"
    assert result.binding is None
    assert result.results["reason"] == "deployment observer returned no ECS deployment ID"


@pytest.mark.parametrize(
    ("field", "expected_reason"),
    (
        ("account_id", "account_id, cluster_arn, service_arn, task_definition_arn"),
        (
            "cluster_arn",
            "cluster_arn",
        ),
        ("service_arn", "service_arn"),
        ("task_definition_arn", "task_definition_arn"),
    ),
)
def test_observed_pin_mismatch_fails_with_the_observed_binding(
    field: str, expected_reason: str
) -> None:
    _, manifest = parse_manifest(_manifest())
    assert manifest is not None
    alternatives = {
        "account_id": "999999999999",
        "cluster_arn": "arn:aws:ecs:eu-central-1:123456789012:cluster/other",
        "service_arn": "arn:aws:ecs:eu-central-1:123456789012:service/other/synthetic-staging",
        "task_definition_arn": "arn:aws:ecs:eu-central-1:123456789012:task-definition/other:8",
    }
    observed = _binding(**{field: alternatives[field]})
    result = run_live_gate(
        manifest,
        manifest_hash="f" * 64,
        runner_commands=("test",),
        clients=StagingClients(observer=_Observer(observed)),
    )
    assert result.status == "FAIL"
    assert result.binding == observed
    assert result.results["reason"] == f"observed deployment does not match pins: {expected_reason}"


def test_frozen_adapter_receives_observed_binding_and_typed_inputs() -> None:
    raw = _manifest()
    raw["inputs"] = {"adapter": {"platform": {"issuer_ref": "idp/issuer"}}}
    _, manifest = parse_manifest(raw)
    assert manifest is not None
    binding = _binding()

    class _Input(BaseModel):
        model_config = ConfigDict(extra="forbid")

        issuer_ref: str

    class _Adapter:
        gate_id = GateId.LV_PLATFORM

        def evaluate(self, *, inputs, clients, binding):
            assert isinstance(inputs, _Input)
            assert inputs.issuer_ref == "idp/issuer"
            assert clients.client("ecs") == "ecs"
            assert binding == _binding()
            return GateAdapterReport(
                binding=binding,
                obligations=_all_obligations(GateId.LV_PLATFORM),
                results={"source": "observed"},
            )

    result = run_live_gate(
        manifest,
        manifest_hash="f" * 64,
        runner_commands=("test",),
        clients=StagingClients(
            observer=_Observer(binding),
            aws=_AWSFactory(),
            adapters={
                GateId.LV_PLATFORM: (
                    GateAdapterRegistration("platform", GateId.LV_PLATFORM, _Adapter(), _Input),
                )
            },
        ),
    )
    assert result.status == "NOT_RUN"
    assert all(row.status == ObligationStatus.NOT_RUN for row in result.obligations)
    assert result.binding == binding
    assert len(result.obligations) == len(GATE_REGISTRY[GateId.LV_PLATFORM].obligations)


def test_registered_contributors_compose_gate_obligations() -> None:
    raw = _manifest()
    raw["inputs"] = {
        "adapter": {
            "platform-core": {"archive_bucket_ref": "s3/archive"},
            "platform-endpoints": {"alarm_topic_ref": "sns/alarms"},
        }
    }
    _, manifest = parse_manifest(raw)
    assert manifest is not None
    binding = _binding()
    definitions = GATE_REGISTRY[GateId.LV_PLATFORM].obligations

    class _ArchiveInput(BaseModel):
        model_config = ConfigDict(extra="forbid")

        archive_bucket_ref: str

    class _AlarmInput(BaseModel):
        model_config = ConfigDict(extra="forbid")

        alarm_topic_ref: str

    class _Adapter:
        gate_id = GateId.LV_PLATFORM

        def __init__(self, rows):
            self.rows = rows

        def evaluate(self, *, inputs, clients, binding):
            return GateAdapterReport(binding, self.rows, {"count": len(self.rows)})

    refs = (EvidenceReference(EvidenceKind.CLOUDTRAIL_EVENT, "compose-event"),)
    first = tuple(
        ObligationResult(row.obligation_id, ObligationStatus.PASS, "seen", refs)
        for row in definitions[:3]
    )
    second = tuple(
        ObligationResult(row.obligation_id, ObligationStatus.PASS, "seen", refs)
        for row in definitions[3:]
    )
    adapters = {
        GateId.LV_PLATFORM: (
            GateAdapterRegistration(
                "platform-core", GateId.LV_PLATFORM, _Adapter(first), _ArchiveInput
            ),
            GateAdapterRegistration(
                "platform-endpoints", GateId.LV_PLATFORM, _Adapter(second), _AlarmInput
            ),
        )
    }
    result = run_live_gate(
        manifest,
        manifest_hash="f" * 64,
        runner_commands=("test",),
        clients=StagingClients(observer=_Observer(binding), aws=_AWSFactory(), adapters=adapters),
    )
    assert result.status == "NOT_RUN"
    assert all(row.status == ObligationStatus.NOT_RUN for row in result.obligations)
    assert len(result.obligations) == len(definitions)


def test_cli_builds_configured_adapter_and_typed_input(monkeypatch, tmp_path: Path) -> None:
    import scripts.staging_golden as staging_cli

    raw = _manifest()
    raw["inputs"] = {"adapter": {"platform-core": {"target_ref": "platform/config"}}}
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(raw), encoding="utf-8")
    evidence = tmp_path / "evidence.json"
    client_config = tmp_path / "clients.json"
    client_config.write_text(
        json.dumps(
            {
                "source_profile": "qualification-source",
                "role_arn": "arn:aws:iam::123456789012:role/qualification",
                "account_id": "123456789012",
                "region": "eu-central-1",
                "cluster": "qualification",
                "service_name": "synthetic-staging",
                "app_container_name": "ai-soc",
                "adapters": [
                    {
                        "contributor_id": "platform-core",
                        "gate_id": "LV-PLATFORM",
                        "factory": f"{__name__}:_ConfiguredAdapter",
                        "input_model": f"{__name__}:_ConfiguredInput",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        staging_cli,
        "build_explicit_staging_aws",
        lambda config: SimpleNamespace(
            observer=_Observer(_binding()), clients=_AWSFactory(), nightly=None, network=None
        ),
    )
    assert (
        staging_cli.main(
            [
                "--manifest",
                str(manifest),
                "--evidence",
                str(evidence),
                "--clients-config",
                str(client_config),
            ]
        )
        == 2
    )
    assert json.loads(evidence.read_text(encoding="utf-8"))["result"]["status"] == "NOT_RUN"


def test_runner_fails_when_observed_deployment_changes_during_collection() -> None:
    _, manifest = parse_manifest(_manifest())
    assert manifest is not None
    before = _binding()
    after = _binding(
        task_definition_arn="arn:aws:ecs:eu-central-1:123456789012:task-definition/ai-soc:8"
    )

    class _ChangingObserver:
        observations = iter((before, after))

        def observe_deployment(self):
            return next(self.observations)

    class _Adapter:
        gate_id = GateId.LV_PLATFORM

        def evaluate(self, *, inputs, clients, binding):
            return GateAdapterReport(binding, _all_obligations(GateId.LV_PLATFORM), {})

    result = run_live_gate(
        manifest,
        manifest_hash="f" * 64,
        runner_commands=("test",),
        clients=StagingClients(
            observer=_ChangingObserver(),
            aws=_AWSFactory(),
            adapters={
                GateId.LV_PLATFORM: (
                    GateAdapterRegistration("platform", GateId.LV_PLATFORM, _Adapter()),
                )
            },
        ),
    )
    assert result.status == "FAIL"
    assert result.results["reason"] == "deployment binding changed during gate evaluation"


@pytest.mark.parametrize(
    "field,value",
    (
        ("cluster_arn", "arn:aws:ecs:eu-central-1:123456789012:cluster/other"),
        ("service_arn", "arn:aws:ecs:eu-central-1:123456789012:service/other/synthetic-staging"),
        ("task_definition_arn", "arn:aws:ecs:eu-central-1:123456789012:task-definition/other:8"),
        ("deployment_id", "ecs-svc/another-deployment"),
    ),
)
def test_runner_rejects_adapter_report_from_another_deployment(field: str, value: str) -> None:
    _, manifest = parse_manifest(_manifest())
    assert manifest is not None
    binding = _binding()
    other = _binding(**{field: value})

    class _Adapter:
        gate_id = GateId.LV_PLATFORM

        def evaluate(self, *, inputs, clients, binding, qualification_context=None):
            return GateAdapterReport(other, _all_obligations(GateId.LV_PLATFORM), {})

    result = run_live_gate(
        manifest,
        manifest_hash="f" * 64,
        runner_commands=("test",),
        clients=StagingClients(
            observer=_Observer(binding),
            aws=_AWSFactory(),
            adapters={
                GateId.LV_PLATFORM: (
                    GateAdapterRegistration("platform", GateId.LV_PLATFORM, _Adapter()),
                )
            },
        ),
    )
    assert result.status == "FAIL"
    assert result.results["binding_error"] is True


def test_lv1_aggregation_requires_all_compatible_rows_and_observed_evidence() -> None:
    binding = _binding()
    complete = tuple(_passing_result(gate_id, binding) for gate_id in GateId)
    summary = aggregate_results(complete)
    assert summary.status == "NOT_RUN"
    assert summary.binding == binding
    partial = aggregate_results(complete[:1])
    assert partial.status == "NOT_RUN"
    assert partial.gates[0] is not None
    assert partial.gates[1] is None

    different_binding = _binding(deployment_id="ecs-svc/another-deployment")
    mismatched = replace(complete[1], binding=different_binding, expected_binding=different_binding)
    with pytest.raises(ValueError, match="mismatched deployment bindings"):
        aggregate_results((complete[0], mismatched))

    forged = replace(complete[0], expected_binding=_binding(account_id="999999999999"))
    assert aggregate_results((forged,)).status == "NOT_RUN"


def test_acceptance_pass_requires_matching_gp_obligation_and_evidence() -> None:
    binding = _binding()
    complete = tuple(_passing_result(gate_id, binding) for gate_id in GateId)
    nightly = complete[list(GateId).index(GateId.LV_NIGHTLY)]
    acceptance = nightly.acceptance_results[0]
    forged = replace(
        acceptance,
        obligation=replace(
            acceptance.obligation, status=ObligationStatus.NOT_RUN, evidence_refs=()
        ),
        evidence_refs=(),
    )
    without_embedded = replace(nightly, acceptance_results=())
    rows = tuple(without_embedded if row.gate_id == GateId.LV_NIGHTLY else row for row in complete)
    with pytest.raises(ValueError, match="acceptance status differs"):
        aggregate_results(rows, (forged,))


def test_aggregation_rejects_acceptance_claimed_by_wrong_containing_gate() -> None:
    binding = _binding()
    complete = tuple(_passing_result(gate_id, binding) for gate_id in GateId)
    nightly = complete[list(GateId).index(GateId.LV_NIGHTLY)]
    platform = complete[list(GateId).index(GateId.LV_PLATFORM)]
    forged = replace(platform, acceptance_results=nightly.acceptance_results)
    with pytest.raises(ValueError, match="embedded in the wrong producer result"):
        aggregate_results(
            tuple(forged if row.gate_id == GateId.LV_PLATFORM else row for row in complete)
        )


def test_bound_lv1_summary_exports_and_exclusively_creates_complete_json(tmp_path: Path) -> None:
    binding = _binding()
    evidence_paths = []
    for gate_id in GateId:
        path = tmp_path / f"{gate_id.value}.json"
        write_evidence(path, status="PASS", reason="PASS", result=_passing_result(gate_id, binding))
        evidence_paths.append(path)
    output = tmp_path / "lv1-summary.json"
    assert aggregate_cli([*(str(path) for path in evidence_paths), "--output", str(output)]) == 2
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["status"] == "NOT_RUN"
    assert document["binding"]["cluster_arn"] == binding.cluster_arn
    assert document["binding"]["service_arn"] == binding.service_arn
    assert document["binding"]["task_definition_arn"] == binding.task_definition_arn
    assert aggregate_cli([*(str(path) for path in evidence_paths), "--output", str(output)]) == 1


def test_secret_values_and_sensitive_keys_are_redacted_from_gate_json() -> None:
    result = _passing_result(GateId.LV_PLATFORM, _binding())
    exposed = replace(
        result,
        results={
            "password": "sentinel",
            "detail": "token eyJabc.def",
            "header": "Bearer abc.def.secret",
            "safe": "ordinary",
        },
    )
    dumped = json.dumps(exposed.to_dict())
    assert "sentinel" not in dumped
    assert "eyJabc.def" not in dumped
    assert "abc.def.secret" not in dumped
    assert "[REDACTED]" in dumped
    assert "ordinary" in dumped


def test_evidence_writer_refuses_to_overwrite_a_gate_file(tmp_path: Path) -> None:
    path = tmp_path / "gate.json"
    write_evidence(path, status="NOT_RUN", reason="no observation", result=None)
    with pytest.raises(FileExistsError):
        write_evidence(path, status="PASS", reason="changed", result=None)


def test_gate_evidence_round_trips_the_expected_and_observed_bindings(tmp_path: Path) -> None:
    result = _passing_result(GateId.LV_PLATFORM, _binding())
    path = tmp_path / "LV-PLATFORM.json"
    write_evidence(path, status="PASS", reason="PASS", result=result)
    loaded = load_gate_result(path)
    assert loaded.status == "NOT_RUN"
    assert loaded.binding is not None
    assert matches_expected_binding(loaded.binding, loaded.expected_binding)


def test_explicit_boto_session_assumes_and_verifies_configured_role(monkeypatch) -> None:
    calls: list[dict[str, str]] = []

    class _Session:
        def __init__(self, **kwargs: str):
            calls.append(kwargs)

        def get_credentials(self):
            return type("Credentials", (), {"method": "shared-credentials-file"})()

        def client(self, service_name: str, **kwargs):
            if service_name == "sts":
                return type(
                    "STS",
                    (),
                    {
                        "assume_role": lambda self, **kw: {
                            "AssumedRoleUser": {
                                "Arn": "arn:aws:sts::123456789012:assumed-role/qualification/"
                                "qualification"
                            },
                            "Credentials": {
                                "AccessKeyId": "key",
                                "SecretAccessKey": "secret",
                                "SessionToken": "token",
                            },
                        },
                        "get_caller_identity": lambda self: {
                            "Account": "123456789012",
                            "Arn": "arn:aws:sts::123456789012:assumed-role/qualification/"
                            "qualification",
                        },
                    },
                )()
            return service_name

    monkeypatch.setattr("scripts.staging.aws_clients.boto3.Session", _Session)
    configured = build_explicit_staging_aws(
        AWSClientConfig(
            source_profile="soc-qualification",
            role_arn="arn:aws:iam::123456789012:role/qualification",
            account_id="123456789012",
            region="eu-central-1",
            cluster="qualification",
            service_name="synthetic-staging",
            app_container_name="ai-soc",
            nightly={
                "factory": f"{__name__}:_configured_nightly_client",
                "options": {"marker": "nightly"},
            },
            network={
                "factory": f"{__name__}:_configured_network_client",
                "options": {"marker": "network"},
            },
        )
    )
    assert len(calls) == 2
    assert calls[0] == {"profile_name": "soc-qualification", "region_name": "eu-central-1"}
    assert calls[1]["aws_access_key_id"] == "key"
    assert configured.clients.client("s3") == "s3"
    assert configured.observer.sts is not None
    assert configured.observer.ecs == "ecs"
    assert configured.nightly.marker == "nightly"
    assert configured.network.marker == "network"
    assert configured.nightly.clients is configured.clients
    assert configured.network.clients is configured.clients
    with pytest.raises(ValidationError, match="non-default"):
        AWSClientConfig(
            source_profile="default",
            role_arn="arn:aws:iam::123456789012:role/qualification",
            account_id="123456789012",
            region="eu-central-1",
            cluster="qualification",
            service_name="synthetic-staging",
            app_container_name="ai-soc",
        )


def test_explicit_aws_builder_rejects_ambient_credential_provider(monkeypatch) -> None:
    class _Session:
        def __init__(self, **kwargs):
            pass

        def get_credentials(self):
            return type("Credentials", (), {"method": "container-role"})()

        def client(self, service_name: str, **kwargs):
            raise AssertionError("ambient credentials must be rejected before STS calls")

    monkeypatch.setattr("scripts.staging.aws_clients.boto3.Session", _Session)
    config = AWSClientConfig(
        source_profile="soc-source",
        role_arn="arn:aws:iam::123456789012:role/qualification",
        account_id="123456789012",
        region="eu-central-1",
        cluster="qualification",
        service_name="synthetic-staging",
        app_container_name="ai-soc",
    )
    with pytest.raises(ValueError, match="allowed explicit credential provider"):
        build_explicit_staging_aws(config)


def test_ecs_observer_binds_caller_account_running_image_and_deployed_hashes() -> None:
    config = AWSClientConfig(
        source_profile="soc-qualification",
        role_arn="arn:aws:iam::123456789012:role/qualification",
        account_id="123456789012",
        region="eu-central-1",
        cluster="qualification",
        service_name="synthetic-staging",
        app_container_name="ai-soc",
    )

    class _STS:
        def get_caller_identity(self):
            return {"Account": "123456789012"}

    class _ECS:
        def describe_services(self, **kwargs):
            assert kwargs == {"cluster": "qualification", "services": ["synthetic-staging"]}
            task_definition = "arn:aws:ecs:eu-central-1:123456789012:task-definition/ai-soc:7"
            return {
                "services": [
                    {
                        "status": "ACTIVE",
                        "clusterArn": "arn:aws:ecs:eu-central-1:123456789012:cluster/qualification",
                        "serviceArn": (
                            "arn:aws:ecs:eu-central-1:123456789012:service/qualification/"
                            "synthetic-staging"
                        ),
                        "taskDefinition": task_definition,
                        "networkConfiguration": {
                            "awsvpcConfiguration": {
                                "subnets": ["subnet-12345678"],
                                "securityGroups": ["sg-12345678"],
                                "assignPublicIp": "DISABLED",
                            }
                        },
                        "deployments": [
                            {
                                "status": "PRIMARY",
                                "taskDefinition": task_definition,
                                "id": "ecs-svc/1234567890123456789",
                            }
                        ],
                    }
                ]
            }

        def list_tasks(self, **kwargs):
            assert kwargs["desiredStatus"] == "RUNNING"
            return {"taskArns": ["task:1"]}

        def describe_tasks(self, **kwargs):
            return {
                "tasks": [
                    {
                        "lastStatus": "RUNNING",
                        "startedBy": "ecs-svc/1234567890123456789",
                        "taskDefinitionArn": (
                            "arn:aws:ecs:eu-central-1:123456789012:task-definition/ai-soc:7"
                        ),
                        "containers": [{"name": "ai-soc", "imageDigest": "sha256:" + "c" * 64}],
                    }
                ]
            }

        def describe_task_definition(self, **kwargs):
            assert kwargs["include"] == ["TAGS"]
            sealed_json = _sealed().model_dump_json()
            configuration_sha = sha256(sealed_json.encode("utf-8")).hexdigest()
            return {
                "taskDefinition": {
                    "taskDefinitionArn": (
                        "arn:aws:ecs:eu-central-1:123456789012:task-definition/ai-soc:7"
                    ),
                    "networkMode": "awsvpc",
                    "containerDefinitions": [
                        {
                            "name": "ai-soc",
                            "image": (
                                "123456789012.dkr.ecr.eu-central-1.amazonaws.com/ai-soc@sha256:"
                                + "c" * 64
                            ),
                            "environment": [
                                {"name": "SOC_SERVICE_SHA", "value": "a" * 40},
                                {"name": "SOC_CONTENT_SHA", "value": "b" * 40},
                                {
                                    "name": "SOC_CONFIGURATION_SHA256",
                                    "value": configuration_sha,
                                },
                                {"name": "SOC_SERVICE_CONFIG_JSON", "value": sealed_json},
                            ],
                        }
                    ],
                }
            }

    observed = ECSDeploymentObserver(config, _STS(), _ECS()).observe_deployment()
    assert observed == _binding(
        image_digest="sha256:" + "c" * 64,
        task_definition_arn="arn:aws:ecs:eu-central-1:123456789012:task-definition/ai-soc:7",
        configuration_sha256=sha256(_sealed().model_dump_json().encode("utf-8")).hexdigest(),
    )

    class _WrongDeploymentTasks(_ECS):
        def describe_tasks(self, **kwargs):
            response = super().describe_tasks(**kwargs)
            response["tasks"][0]["startedBy"] = "ecs-svc/another-deployment"
            return response

    assert (
        ECSDeploymentObserver(config, _STS(), _WrongDeploymentTasks()).observe_deployment() is None
    )


def test_terraform_task_metadata_exports_observed_configuration_hash() -> None:
    source = (Path(__file__).parents[3] / "infra/main.tf").read_text(encoding="utf-8")
    assert '{ name = "SOC_SERVICE_CONFIG_JSON", value = local.service_sealed_config }' in source
    assert (
        '{ name = "SOC_CONFIGURATION_SHA256", value = sha256(local.service_sealed_config) }'
        in source
    )
