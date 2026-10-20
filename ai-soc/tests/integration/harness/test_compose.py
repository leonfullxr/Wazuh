from __future__ import annotations

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]
LOCK = json.loads((ROOT / "dev/toolchain.lock.json").read_text())
COMPOSE = yaml.safe_load((ROOT / "compose.yaml").read_text())


def test_fixture_compose_is_private_read_only_and_digest_pinned() -> None:
    services = COMPOSE["services"]
    network = COMPOSE["networks"]["soc-fixture"]
    assert network["driver"] == "bridge"
    assert network["internal"] is False
    assert network["driver_opts"] == {"com.docker.network.bridge.enable_ip_masquerade": "false"}
    locked_images = {entry["name"]: entry["reference"] for entry in LOCK["images"]}
    for service_name in ("dynamodb-local", "adot-collector"):
        service = services[service_name]
        image = service["image"]
        assert "@sha256:" in image
        assert image == locked_images[service_name]
        assert service["read_only"] is True
        assert "soc-fixture" in service["networks"]
        assert service["labels"]["com.ai-soc.owner"] == "soc-local-compose"
        assert service["labels"]["com.ai-soc.scope"] == "fixture-protocol"
    assert services["dynamodb-local"]["command"] == [
        "-Djava.library.path=/home/dynamodblocal/DynamoDBLocal_lib",
        "-jar",
        "DynamoDBLocal.jar",
        "-sharedDb",
        "-inMemory",
        "-disableTelemetry",
    ]
    assert services["dynamodb-local"]["tmpfs"] == ["/tmp:exec,size=64m,nosuid"]
    assert "healthcheck" not in services["dynamodb-local"]
    assert services["app"]["depends_on"]["dynamodb-local"]["condition"] == "service_started"
    assert not services["adot-collector"].get("ports")
    _assert_loopback_ephemeral_mapping(
        services["dynamodb-local"]["ports"],
        "${DYNAMODB_LOCAL_PORT:?DYNAMODB_LOCAL_PORT must be selected dynamically}",
    )

    app = services["app"]
    assert app["environment"]["SOC_MODE"] == "fixture"
    assert app["environment"]["AWS_EC2_METADATA_DISABLED"] == "true"
    assert app["environment"]["OTEL_EXPORTER_OTLP_ENDPOINT"] == "http://adot-collector:4317"
    assert app["read_only"] is True
    _assert_loopback_ephemeral_mapping(
        app["ports"], "${APP_LOCAL_PORT:?APP_LOCAL_PORT must be selected dynamically}"
    )


def _assert_loopback_ephemeral_mapping(ports: list[object], published: str) -> None:
    assert len(ports) == 1
    mapping = ports[0]
    assert isinstance(mapping, dict)
    assert mapping == {
        "target": 8000,
        "published": published,
        "host_ip": "127.0.0.1",
        "protocol": "tcp",
    }


def test_fixture_adot_pipeline_receives_grpc_and_never_exports_to_cloud() -> None:
    collector = yaml.safe_load((ROOT / "dev/adot-collector-fixture.yaml").read_text())
    assert collector["receivers"]["otlp"]["protocols"]["grpc"]["endpoint"] == "0.0.0.0:4317"
    assert collector["service"]["pipelines"]["traces"]["exporters"] == ["debug"]
    assert "awsxray" not in collector["exporters"]
