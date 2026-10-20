from __future__ import annotations

import base64
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest

from ai_soc.contracts.canonical import owner_key as make_owner_key
from ai_soc.contracts.models import VerifiedPrincipal, Visibility
from ai_soc.identity.ca import SiteTransport
from ai_soc.identity.policy import MappedSitePolicy
from ai_soc.live.runtime import build_live_runtime, shutdown_live_runtime
from tests.unit.live.live_boot_fixture import _catalog, _provenance, _sealed, site_config


def test_dynamodb_sdk_has_no_retries_beyond_transaction_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: list[tuple[str, dict[str, object]]] = []

    def fake_client(service: str, **kwargs: object) -> object:
        created.append((service, kwargs))
        return object()

    monkeypatch.setattr("ai_soc.live.runtime.boto3.client", fake_client)
    from ai_soc.live.runtime import _client

    _client("dynamodb", "us-east-1", None)
    _client("sqs", "us-east-1", None)

    dynamodb_config = created[0][1]["config"]
    sqs_config = created[1][1]["config"]
    assert dynamodb_config.retries["total_max_attempts"] == 1  # type: ignore[attr-defined]
    assert sqs_config.retries["total_max_attempts"] == 2  # type: ignore[attr-defined]


def _configure_live_boot_env(
    monkeypatch: pytest.MonkeyPatch,
    *,
    site_ca_pem: str,
) -> None:
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4317")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
    monkeypatch.setenv("SOC_CLOUDWATCH_NAMESPACE", "AISOC/Test")
    monkeypatch.setenv("SOC_CURSOR_KEY_ID_CURRENT", "current")
    monkeypatch.setenv("SOC_CURSOR_KEY_ID_PREVIOUS", "previous")
    key_material = base64.b64encode(b"k" * 32).decode()
    monkeypatch.setenv("SOC_CURSOR_AEAD_CURRENT", key_material)
    monkeypatch.setenv("SOC_CURSOR_AEAD_PREVIOUS", key_material)
    monkeypatch.setenv("SOC_RECEIPT_KEY_ID_CURRENT", "current")
    monkeypatch.setenv("SOC_RECEIPT_KEY_ID_PREVIOUS", "previous")
    monkeypatch.setenv("SOC_FEEDBACK_RECEIPT_CURRENT", key_material)
    monkeypatch.setenv("SOC_FEEDBACK_RECEIPT_PREVIOUS", key_material)
    monkeypatch.setenv("SOC_CSRF_SECRET", key_material)
    monkeypatch.setenv("SOC_SITE_ALPHA_CA", site_ca_pem)


@pytest.mark.asyncio
async def test_build_live_runtime_without_soc_group_and_shutdown_closes_lazy_clients(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    base = _sealed()
    site = site_config().model_copy(
        update={
            "group_role_map": {"soc-alpha": ("analyst_read",)},
            "role_visibility": {"analyst_read": Visibility.full},
            "composite_role_visibility": {"analyst_read": Visibility.full},
        }
    )
    document = base.model_copy(
        update={"service": base.service.model_copy(update={"sites": (site,)})}
    )
    provenance = _provenance()
    catalog = _catalog(provenance)
    pack_dir = tmp_path / "pack"
    pack_dir.mkdir()
    created: list[httpx.AsyncClient] = []

    def fake_build_site_transport(site, secrets, **kwargs) -> SiteTransport:
        client = httpx.AsyncClient(base_url=site.config.indexer_origin)
        created.append(client)
        return SiteTransport(site.config.environment_id, site.policy_hash, client)

    dynamodb = MagicMock()
    dynamodb.get_item.return_value = {"Item": {}}

    def fake_client(service: str, region: str, endpoint: str | None) -> object:
        if service == "dynamodb":
            return dynamodb
        return MagicMock()

    def fake_acquire_content_pack(*_args, **_kwargs):
        return pack_dir, catalog

    monkeypatch.setattr("ai_soc.live.runtime.acquire_content_pack", fake_acquire_content_pack)
    monkeypatch.setattr("ai_soc.live.runtime.build_site_transport", fake_build_site_transport)
    monkeypatch.setattr("ai_soc.live.runtime._client", fake_client)
    _configure_live_boot_env(monkeypatch, site_ca_pem=document.ca_bundle_pem or "")

    with caplog.at_level(logging.WARNING, logger="ai_soc.live.runtime"):
        live = build_live_runtime(document)
    assert live.runtime.application.semantic_suggester is None
    assert "semantic topic suggestions are disabled" in caplog.text
    assert isinstance(live.runtime.application.clock.monotonic(), float)
    assert live.runtime.feedback_control_pool is not None
    assert len(created) == 0
    assert len(live.indexer_client_cache) == 0

    now = datetime.now(UTC)
    policy = MappedSitePolicy(document.service.sites, now=lambda: now)
    principal = VerifiedPrincipal(
        issuer=document.alb.issuer,
        sub="indexer-shutdown-test",
        owner_key=make_owner_key(document.alb.issuer, "indexer-shutdown-test"),
        groups=("soc-alpha",),
        edge="fixture",
        authenticated_at=now,
        expires_at=now + timedelta(hours=1),
        assertion_hash="a" * 64,
    )
    authorized = policy.authorize(principal, site.environment_id)
    live.runtime.application.fetches._transport_for(authorized)
    assert len(created) == 1
    assert len(live.indexer_client_cache) == 1

    flushed: list[object] = []
    monkeypatch.setattr(
        "ai_soc.live.runtime.OtlpTraceExporter.shutdown", lambda self: flushed.append(self)
    )
    await shutdown_live_runtime(live)
    assert live.runtime.feedback_control_pool._closed
    for client in created:
        assert client.is_closed
    assert flushed == [live.trace_exporter]


def test_build_live_runtime_rejects_model_outside_deployment_region(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    base = _sealed()
    model = base.service.models[0].model_copy(update={"region": "eu-west-1"})
    document = base.model_copy(
        update={"service": base.service.model_copy(update={"models": (model,)})}
    )
    provenance = _provenance()
    catalog = _catalog(provenance)
    pack_dir = tmp_path / "pack"
    pack_dir.mkdir()

    monkeypatch.setattr(
        "ai_soc.live.runtime.acquire_content_pack", lambda *_args, **_kwargs: (pack_dir, catalog)
    )
    monkeypatch.setattr("ai_soc.live.runtime.build_site_transport", lambda *_args, **_kwargs: None)
    created: list[str] = []

    def recording_client(service: str, *_args: object, **_kwargs: object) -> object:
        created.append(service)
        return object()

    monkeypatch.setattr("ai_soc.live.runtime._client", recording_client)
    _configure_live_boot_env(monkeypatch, site_ca_pem=document.ca_bundle_pem or "")

    with pytest.raises(ValueError, match="differs from deployment region us-east-1"):
        build_live_runtime(document)
    assert created == []
