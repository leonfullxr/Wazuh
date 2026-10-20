"""Construct the live SocRuntime from sealed inputs and explicit clients."""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import cast

import boto3
import httpx
from botocore.config import Config
from cryptography import x509

from ai_soc.application.composition import SocRuntime, compose_soc
from ai_soc.contracts.models import AuthorizedSite, SiteConfig
from ai_soc.contracts.ports import ModelCountAdmissionStore
from ai_soc.identity.alb import AlbAssertionVerifier, McpBearerVerifier
from ai_soc.identity.ca import build_site_transport
from ai_soc.judgment.bedrock import BedrockJudgmentProvider, SystemClock
from ai_soc.live.env import (
    csrf_secret,
    cursor_keys,
    merge_audit_urls,
    optional_endpoint,
    receipt_keys,
    require_region,
)
from ai_soc.live.keys import alb_key_resolver, mcp_key_resolver
from ai_soc.live.pack import acquire_content_pack
from ai_soc.live.readiness import LiveReadiness
from ai_soc.live.sealed import LiveSealedDocument, MappingProfileRecord
from ai_soc.live.secrets import BoundSiteCaSecretReader
from ai_soc.query.compiler import MappingProfile
from ai_soc.query.cursors import CursorCipher
from ai_soc.state.dynamodb import DynamoClient
from ai_soc.telemetry.metrics import BatchedCloudWatchMetricExporter, MetricExporter
from ai_soc.telemetry.tracing import OtlpTraceExporter, SpanExporter, TraceSpan

_LOGGER = logging.getLogger(__name__)

_READINESS_PK = "soc#readiness"
_READINESS_SK = "probe"


@dataclass(frozen=True, slots=True)
class _LiveSpanExporter:
    exporter: OtlpTraceExporter

    def export(self, span: TraceSpan) -> None:
        self.exporter.export(span)


@dataclass(frozen=True, slots=True)
class LiveRuntime:
    runtime: SocRuntime
    readiness: LiveReadiness
    pack_dir: Path
    indexer_client_cache: dict[str, httpx.AsyncClient] = field(
        default_factory=dict[str, httpx.AsyncClient]
    )
    metric_exporter: MetricExporter | None = None
    trace_exporter: OtlpTraceExporter | None = None


async def shutdown_live_runtime(live: LiveRuntime) -> None:
    live.runtime.close_feedback_control()
    live.readiness.close()
    for client in live.indexer_client_cache.values():
        try:
            await asyncio.wait_for(client.aclose(), timeout=5.0)
        except Exception:
            continue
    exporter = live.metric_exporter
    if isinstance(exporter, BatchedCloudWatchMetricExporter):
        try:
            await asyncio.wait_for(asyncio.to_thread(exporter.shutdown), timeout=11.0)
        except Exception:
            pass
    if live.trace_exporter is not None:
        try:
            await asyncio.wait_for(asyncio.to_thread(live.trace_exporter.shutdown), timeout=11.0)
        except Exception:
            pass


def mapping_profile_from_record(record: MappingProfileRecord) -> MappingProfile:
    from ai_soc.contracts.models import FieldId

    fields = {FieldId(key): value for key, value in record.fields.items()}
    alert = tuple(FieldId(value) for value in record.alert_projection)
    vuln = tuple(FieldId(value) for value in record.vulnerability_projection)
    return MappingProfile(record.profile_id, fields, alert, vuln, record.tie_break_field)


def _boto_config(*, total_max_attempts: int = 2, **timeouts: int) -> Config:
    return Config(
        connect_timeout=timeouts.get("connect", 3),
        read_timeout=timeouts.get("read", 10),
        retries={"total_max_attempts": total_max_attempts, "mode": "standard"},
        max_pool_connections=8,
    )


def _client(service: str, region: str, endpoint: str | None) -> object:
    factory = cast(Callable[..., object], boto3.client)  # type: ignore[reportUnknownMemberType]
    attempts = 1 if service == "dynamodb" else 2
    kwargs: dict[str, object] = {
        "region_name": region,
        "config": _boto_config(total_max_attempts=attempts),
    }
    if endpoint is not None:
        kwargs["endpoint_url"] = endpoint
    return factory(service, **kwargs)


def _dynamodb_probe(client: object, table_name: str) -> Callable[[], bool]:
    def probe() -> bool:
        try:
            client.get_item(  # type: ignore[attr-defined]
                TableName=table_name,
                Key={"pk": {"S": _READINESS_PK}, "sk": {"S": _READINESS_SK}},
                ConsistentRead=True,
            )
            return True
        except Exception:
            return False

    return probe


def _parse_ca_pem(pem: str) -> None:
    try:
        certs = x509.load_pem_x509_certificates(pem.encode("utf-8"))
    except ValueError as exc:
        raise ValueError("CA bundle is not valid PEM") from exc
    if not certs:
        raise ValueError("CA bundle is empty")


def _materialize_ca_bundle(document: LiveSealedDocument) -> LiveSealedDocument:
    if document.ca_bundle_pem is None or not document.ca_bundle_pem.strip():
        raise ValueError("live mode requires injected CA bundle PEM")
    path = Path("/tmp/ca-bundle.pem")
    encoded = document.ca_bundle_pem.encode("utf-8")
    if sha256(encoded).hexdigest() != document.service.ca_bundle_sha256:
        raise ValueError("CA bundle digest mismatch")
    _parse_ca_pem(document.ca_bundle_pem)
    path.write_bytes(encoded)
    service = document.service.model_copy(update={"ca_bundle_path": str(path)})
    return document.model_copy(update={"service": service})


def _verify_site_ca_secrets(sites: tuple[SiteConfig, ...], reader: BoundSiteCaSecretReader) -> None:
    for site in sites:
        if not site.enabled:
            continue
        pem = reader.get_secret_value(
            secret_id=site.ca_secret_arn,
            version_id=site.ca_secret_version,
        )
        _parse_ca_pem(pem)


def build_live_runtime(document: LiveSealedDocument) -> LiveRuntime:
    document = merge_audit_urls(_materialize_ca_bundle(document))
    region = require_region()
    for model in document.service.models:
        if model.region != region:
            raise ValueError(
                f"judgment model {model.id} region {model.region} differs from "
                f"deployment region {region}"
            )
    pack_dir, catalog = acquire_content_pack(document.content_pack, document.provenance)
    dynamodb = _client("dynamodb", region, optional_endpoint("SOC_DYNAMODB_ENDPOINT_URL"))
    table_name = document.dynamodb_table
    dynamodb_probe = _dynamodb_probe(dynamodb, table_name)
    clock = SystemClock()
    cursor_key_map, cursor_current = cursor_keys()
    cursor = CursorCipher(keys=cursor_key_map, current_key_id=cursor_current, now=clock.now)
    receipt_key_map, receipt_current = receipt_keys()
    secrets = BoundSiteCaSecretReader(document.service.sites)
    _verify_site_ca_secrets(document.service.sites, secrets)
    profiles = {
        record.profile_id: mapping_profile_from_record(record)
        for record in document.mapping_profiles
    }
    indexer_key_ids = {
        site.environment_id: site.kms_signing_key_arn.rsplit("/", 1)[-1]
        for site in document.service.sites
        if site.enabled
    }

    indexer_clients: dict[str, httpx.AsyncClient] = {}

    def transport_for(site: AuthorizedSite) -> httpx.AsyncClient:
        site_id = site.config.environment_id
        cached = indexer_clients.get(site_id)
        if cached is not None:
            return cached
        transport = build_site_transport(site, secrets)
        indexer_clients[site_id] = transport.client
        return transport.client

    kms = _client("kms", region, optional_endpoint("SOC_KMS_ENDPOINT_URL"))
    sqs = _client("sqs", region, optional_endpoint("SOC_SQS_ENDPOINT_URL"))
    cloudwatch = _client("cloudwatch", region, None)
    otlp_endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not otlp_endpoint:
        raise ValueError("OTEL_EXPORTER_OTLP_ENDPOINT is required")
    otlp_protocol = os.environ.get("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
    if otlp_protocol != "grpc":
        raise ValueError("live boot supports only grpc OTLP export")
    trace_exporter = OtlpTraceExporter(
        otlp_endpoint,
        service_version=document.provenance.service_sha,
    )
    span_exporter: SpanExporter = _LiveSpanExporter(trace_exporter)
    namespace = os.environ.get("SOC_CLOUDWATCH_NAMESPACE")
    if not namespace:
        raise ValueError("SOC_CLOUDWATCH_NAMESPACE is required")
    ca_bundle_path = document.service.ca_bundle_path
    metric_exporter = BatchedCloudWatchMetricExporter(
        cloudwatch,  # type: ignore[arg-type]
        namespace=namespace,
    )
    origins = document.mcp_allowed_origins or (document.browser_origin,)
    alb = AlbAssertionVerifier(
        region=region,
        signer_arn=document.alb.signer_arn,
        issuer=document.alb.issuer,
        client_id=document.alb.client_id,
        groups_claim=document.alb.groups_claim,
        key_resolver=alb_key_resolver(region, ca_bundle_path=ca_bundle_path),
        now=clock.now,
    )
    mcp = McpBearerVerifier(
        issuer=document.mcp.issuer,
        resource=document.mcp.resource,
        jwks_uri=document.mcp.jwks_uri,
        key_resolver=mcp_key_resolver(document.mcp.jwks_uri, ca_bundle_path=ca_bundle_path),
        now=clock.now,
        allowed_origins=frozenset(origins),
    )

    def judgment_factory(admission: ModelCountAdmissionStore) -> BedrockJudgmentProvider:
        model = document.service.models[0]
        return BedrockJudgmentProvider.from_boto3(
            model,
            admission_store=admission,
            clock=clock,
        )

    readiness = LiveReadiness(
        document=document,
        catalog=catalog,
        pack_dir=pack_dir,
        dynamodb_probe=dynamodb_probe,
    )
    runtime = compose_soc(
        document.service,
        clock=clock,
        catalog=catalog,
        state_client=cast(DynamoClient, dynamodb),
        state_table=table_name,
        kms=kms,  # type: ignore[arg-type]
        indexer_key_ids=indexer_key_ids,
        transport_for=transport_for,
        mapping_profiles=profiles,
        cursor_cipher=cursor,
        judgment_provider_factory=judgment_factory,
        audit_client=sqs,  # type: ignore[arg-type]
        audit_queue_url=document.audit_queue_url,
        feedback_client=sqs,  # type: ignore[arg-type]
        feedback_queue_url=document.feedback_queue_url,
        span_exporter=span_exporter,
        metric_exporter=metric_exporter,
        receipt_keys=receipt_key_map,
        current_receipt_key=receipt_current,
        csrf_secret=csrf_secret(),
        browser_origin=document.browser_origin,
        alb_verifier=alb,
        mcp_verifier=mcp,
        readiness=readiness,
        standing_rules=document.standing_rules,
        mcp_issuer_url=document.mcp.issuer,
        mcp_resource_url=document.mcp.resource,
    )
    if runtime.application.semantic_suggester is None:
        _LOGGER.warning(
            "semantic topic suggestions are disabled: the live configuration has no embedding "
            "capability; deterministic routing is unaffected"
        )
    return LiveRuntime(
        runtime=runtime,
        readiness=readiness,
        pack_dir=pack_dir,
        indexer_client_cache=indexer_clients,
        metric_exporter=metric_exporter,
        trace_exporter=trace_exporter,
    )
