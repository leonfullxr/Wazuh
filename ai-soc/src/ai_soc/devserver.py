"""Loopback-only synthetic runtime for `make dev`: the real composed app with fixture adapters."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import uuid4

import httpx
import jwt
import uvicorn
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from pydantic import TypeAdapter

from ai_soc.application.composition import SocRuntime, compose_soc, runtime_asgi_app
from ai_soc.config import ServiceConfig
from ai_soc.content.builder import verify_content_pack
from ai_soc.content.catalog import load_content_catalog
from ai_soc.contracts.models import (
    AuthorizedSite,
    BuildProvenance,
    HTTPSUrl,
    IndexFamily,
    ModelCapability,
    PackManifest,
    SiteConfig,
    TemplateId,
    Visibility,
)
from ai_soc.contracts.ports import ModelCountAdmissionStore
from ai_soc.identity.alb import AlbAssertionVerifier, IdentityError, KeyMaterial, McpBearerVerifier
from ai_soc.judgment.bedrock import BedrockJudgmentProvider
from ai_soc.query.compiler import default_profile
from ai_soc.query.cursors import CursorCipher
from ai_soc.telemetry.metrics import MetricSample
from ai_soc.telemetry.tracing import TraceSpan

_HOST = "127.0.0.1"
_ISSUER = "https://issuer.example.test"
_CLIENT_ID = "synthetic-client"
_SUBJECT = "synthetic-analyst"
_ALB_KID = "synthetic-alb-key"
_MCP_KID = "synthetic-mcp-key"
_ALB_SIGNER = (
    "arn:aws:elasticloadbalancing:us-east-1:000000000000:"
    "loadbalancer/app/synthetic/0000000000000000"
)
_KMS_KEY = "arn:aws:kms:us-east-1:000000000000:key/synthetic"
_INDEXER = "https://indexer.synthetic.example.test"
_INDEX = "/wazuh-alerts-synthetic-*"
_VULN_INDEX = "/wazuh-vulnerabilities-synthetic-*"
_HIT_INDEX = "wazuh-alerts-synthetic-000001"
_VULN_HIT_INDEX = "wazuh-vulnerabilities-synthetic-000001"
_VALIDATE = f"{_INDEX}/_validate/query"
_COUNT = f"{_INDEX}/_count"
_SEARCH = f"{_INDEX}/_search"
_VULN_VALIDATE = f"{_VULN_INDEX}/_validate/query"
_VULN_COUNT = f"{_VULN_INDEX}/_count"
_VULN_SEARCH = f"{_VULN_INDEX}/_search"
_BODY_KEYS = {
    **{path: frozenset({"query"}) for path in (_VALIDATE, _COUNT, _VULN_VALIDATE, _VULN_COUNT)},
    **{
        path: frozenset({"query", "size", "_source", "sort", "track_total_hits"})
        for path in (_SEARCH, _VULN_SEARCH)
    },
}
_LIVE_VARIABLES = (
    "SOC_SERVICE_CONFIG_PATH",
    "SOC_SERVICE_CONFIG_JSON",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_PROFILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
)
_TOPIC_PREFIX = "APPROVED TOPIC CONTEXT (data): "
_EVIDENCE_PREFIX = "UNTRUSTED TOPIC EVIDENCE DATA:\n"
# (hit id, hours before the request, source). Only the 24 hour window matches.
_ALERTS: tuple[tuple[str, int, dict[str, object]], ...] = (
    (
        "synthetic-1",
        1,
        {
            "agent": {"id": "001", "name": "ldap-1.example.test"},
            "rule": {"id": "5710", "level": 5, "groups": ["ldap", "authentication"]},
            "data": {"srcip": "192.0.2.14", "dstip": "198.51.100.8"},
        },
    ),
    (
        "synthetic-2",
        3,
        {
            "agent": {"id": "002", "name": "ldap-2.example.test"},
            "rule": {"id": "5711", "level": 7, "groups": ["ldap", "authentication"]},
            "data": {"srcip": "192.0.2.25", "dstip": "198.51.100.19"},
        },
    ),
    (
        "synthetic-3",
        30,
        {
            "agent": {"id": "003", "name": "ldap-3.example.test"},
            "rule": {"id": "5710", "level": 5, "groups": ["ldap"]},
            "data": {"srcip": "192.0.2.37", "dstip": "198.51.100.30"},
        },
    ),
)


class _Clock:
    def now(self) -> datetime:
        return datetime.now(UTC)

    def monotonic(self) -> float:
        return time.monotonic()


class _Kms:
    def __init__(self) -> None:
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def sign(self, **kwargs: object) -> dict[str, object]:
        message = kwargs.get("Message")
        if (
            kwargs.get("KeyId") != _KMS_KEY
            or kwargs.get("MessageType") != "DIGEST"
            or kwargs.get("SigningAlgorithm") != "RSASSA_PKCS1_V1_5_SHA_256"
            or not isinstance(message, bytes)
        ):
            raise ValueError("unsupported synthetic signing request")
        signature = self._key.sign(message, padding.PKCS1v15(), Prehashed(hashes.SHA256()))
        return {"Signature": signature}


class _Queue:
    """In-memory SQS stand-in: sends are kept in a bounded buffer and nothing is received."""

    def __init__(self) -> None:
        self._messages: deque[str] = deque(maxlen=1000)

    def send_message(self, **kwargs: object) -> dict[str, object]:
        self._messages.append(str(kwargs["MessageBody"]))
        return {"MessageId": str(uuid4())}

    def receive_message(self, **_kwargs: object) -> dict[str, object]:
        return {"Messages": []}

    def delete_message(self, **_kwargs: object) -> None:
        return None


class _Discard:
    """Drops telemetry so that samples never accumulate in memory."""

    def export(self, span: TraceSpan) -> None:
        return None

    def emit(self, sample: MetricSample) -> None:
        return None


class _Ready:
    def ready(self) -> bool:
        return True


class _ModelClient:
    """Deterministic Bedrock stand-in; it is not a quality signal."""

    def count_tokens(self, **_kwargs: object) -> dict[str, object]:
        return {"inputTokens": 128}

    def converse(self, **kwargs: object) -> dict[str, object]:
        return {
            "output": {
                "message": {
                    "content": [
                        {"text": json.dumps({"schema_version": "1", "findings": _findings(kwargs)})}
                    ]
                }
            },
            "stopReason": "end_turn",
            "usage": {
                "inputTokens": 128,
                "outputTokens": 16,
                "cacheReadInputTokens": 0,
                "cacheWriteInputTokens": 0,
            },
            "ResponseMetadata": {"RequestId": str(uuid4())},
        }


def _findings(request: dict[str, object]) -> list[object]:
    """Ground one observation in the first evidence item the prompt allows."""
    try:
        system = cast(list[dict[str, object]], request["system"])
        texts = [str(part["text"]) for part in system if "text" in part]
        topic = next(text for text in texts if text.startswith(_TOPIC_PREFIX))
        template = json.loads(topic.removeprefix(_TOPIC_PREFIX))["finding_templates"][0]
        messages = cast(list[dict[str, object]], request["messages"])
        content = cast(list[dict[str, object]], messages[0]["content"])
        evidence = json.loads(str(content[0]["text"]).removeprefix(_EVIDENCE_PREFIX))
        allowed = set(template["allowed_evidence_kinds"])
        item = next(item for item in evidence["items"] if item["kind"] in allowed)
        binding, fields = next(iter(template["required_bindings"].items()))
        field = next(name for name in fields if name in item["values"])
        return [
            {
                "finding_id": "synthetic-grounded-finding",
                "kind": template["kind"],
                "template_id": template["template_id"],
                "evidence_ids": [item["evidence_id"]],
                "bindings": {
                    binding: {"evidence_id": item["evidence_id"], "field": field},
                },
            }
        ]
    except (KeyError, IndexError, StopIteration, TypeError, ValueError):
        return []


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _alerts(now: datetime) -> list[tuple[str, dict[str, object]]]:
    base: list[tuple[str, dict[str, object]]] = [
        (hit_id, {"@timestamp": _iso(now - timedelta(hours=hours)), **source})
        for hit_id, hours, source in _ALERTS
    ]
    auth_review: list[tuple[str, dict[str, object]]] = [
        (
            "synthetic-auth-1",
            {
                "@timestamp": _iso(now - timedelta(minutes=30)),
                "agent": {"id": "201", "name": "auth-1.example.test"},
                "rule": {"id": "5710", "level": 10, "groups": ["authentication_failed"]},
                "data": {"srcip": "192.0.2.41"},
            },
        ),
        (
            "synthetic-auth-2",
            {
                "@timestamp": _iso(now - timedelta(hours=6)),
                "agent": {"id": "202", "name": "auth-2.example.test"},
                "rule": {"id": "5711", "level": 7, "groups": ["authentication_failed"]},
                "data": {"srcip": "192.0.2.42"},
            },
        ),
    ]
    return base + auth_review


def _vulnerabilities(now: datetime) -> list[tuple[str, dict[str, object]]]:
    return [
        (
            "synthetic-vuln-1",
            {
                "vulnerability": {
                    "detected_at": _iso(now - timedelta(hours=2)),
                    "id": "CVE-2099-0001",
                    "severity": "Critical",
                },
                "agent": {"id": "101", "name": "host-1.example.test"},
                "package": {"name": "synthetic-package", "version": "1.0"},
            },
        ),
        (
            "synthetic-vuln-2",
            {
                "vulnerability": {
                    "detected_at": _iso(now - timedelta(hours=5)),
                    "id": "CVE-2099-0002",
                    "severity": "High",
                },
                "agent": {"id": "102", "name": "host-2.example.test"},
                "package": {"name": "synthetic-package", "version": "2.0"},
            },
        ),
    ]


def _mapping(value: object) -> dict[str, object] | None:
    return cast(dict[str, object], value) if isinstance(value, dict) else None


def _items(value: object) -> list[object] | None:
    return cast(list[object], value) if isinstance(value, list) else None


def _field(source: dict[str, object], path: str) -> object:
    value: object = source
    for part in path.split("."):
        mapping = _mapping(value)
        if mapping is None:
            return None
        value = mapping.get(part)
    return value


def _contains(value: object, expected: object) -> bool:
    if isinstance(value, list):
        return expected in cast(list[object], value)
    return value == expected


def _predicate(clause: object, family: IndexFamily) -> Callable[[dict[str, object]], bool] | None:
    """Return a check only for a compiler-supported family field and operator."""
    clause_map = _mapping(clause)
    if clause_map is None or len(clause_map) != 1:
        return None
    kind, spec = next(iter(clause_map.items()))
    spec_map = _mapping(spec)
    if spec_map is None or len(spec_map) != 1:
        return None
    field, value = next(iter(spec_map.items()))
    if kind == "exists":
        if set(spec_map) != {"field"} or not isinstance(value, str):
            return None
        exists_fields = (
            {
                "agent.id",
                "agent.name",
                "vulnerability.id",
                "vulnerability.severity",
                "package.name",
                "package.version",
            }
            if family == IndexFamily.vulnerabilities
            else {
                "agent.id",
                "agent.name",
                "rule.id",
                "rule.level",
                "rule.groups",
                "data.srcip",
                "data.dstip",
            }
        )
        if value not in exists_fields:
            return None
        return lambda source: _field(source, value) is not None
    bounds = _mapping(value)
    alert_fields = {
        "@timestamp",
        "agent.id",
        "agent.name",
        "rule.id",
        "rule.level",
        "rule.groups",
        "data.srcip",
        "data.dstip",
    }
    vulnerability_fields = {
        "agent.id",
        "agent.name",
        "vulnerability.id",
        "vulnerability.severity",
        "vulnerability.detected_at",
        "package.name",
        "package.version",
    }
    allowed_fields = vulnerability_fields if family == IndexFamily.vulnerabilities else alert_fields
    if field not in allowed_fields:
        return None
    if kind == "range" and bounds is not None:
        time_field = (
            "vulnerability.detected_at" if family == IndexFamily.vulnerabilities else "@timestamp"
        )
        if field == time_field:
            if set(bounds) != {"gte", "lt"}:
                return None
            try:
                start = datetime.fromisoformat(str(bounds["gte"]))
                end = datetime.fromisoformat(str(bounds["lt"]))
            except ValueError:
                return None
            if start.tzinfo is None or end.tzinfo is None:
                return None
            return lambda source: start <= datetime.fromisoformat(str(_field(source, field))) < end
        if family == IndexFamily.alerts and field == "rule.level" and len(bounds) == 1:
            operator, expected_value = next(iter(bounds.items()))
            if (
                operator not in {"gte", "lte"}
                or type(expected_value) is not int
                or not 0 <= expected_value <= 16
            ):
                return None
            expected_level = expected_value

            def matches_rule_level(source: dict[str, object]) -> bool:
                actual = _field(source, field)
                if not isinstance(actual, int):
                    return False
                if operator == "gte":
                    return actual >= expected_level
                return actual <= expected_level

            return matches_rule_level
        return None
    if field in {"@timestamp", "vulnerability.detected_at"}:
        return None
    values = _items(value)
    if bounds is not None:
        return None
    if kind == "term" and values is None:
        expected: list[object] = [value]
    elif kind == "terms" and values is not None:
        expected = values
    else:
        return None
    if field == "rule.level" and (kind != "term" or type(value) is not int or not 0 <= value <= 16):
        return None
    return lambda source: any(_contains(_field(source, field), item) for item in expected)


def _matches(
    query: object, alerts: list[tuple[str, dict[str, object]]], family: IndexFamily
) -> list[tuple[str, dict[str, object]]] | None:
    query_map = _mapping(query)
    bool_map = _mapping(query_map.get("bool")) if query_map is not None else None
    if query_map is None or bool_map is None or set(query_map) != {"bool"}:
        return None
    if set(bool_map) != {"filter"}:
        return None
    clauses = _items(bool_map["filter"])
    if clauses is None or not 1 <= len(clauses) <= 10:
        return None
    predicates: list[Callable[[dict[str, object]], bool]] = []
    for clause in clauses:
        predicate = _predicate(clause, family)
        if predicate is None:
            return None
        predicates.append(predicate)
    return [alert for alert in alerts if all(predicate(alert[1]) for predicate in predicates)]


def _indexer(clock: _Clock) -> httpx.AsyncClient:
    """Answer only the validate, count and search requests of the two allowed templates."""

    def handle(request: httpx.Request) -> httpx.Response:
        if not request.headers.get("authorization", "").startswith("Bearer "):
            return httpx.Response(401)
        keys = _BODY_KEYS.get(request.url.path)
        if request.method != "POST" or keys is None:
            return httpx.Response(400)
        try:
            body = _mapping(json.loads(request.content))
        except ValueError:
            return httpx.Response(400)
        if body is None or frozenset(body) != keys:
            return httpx.Response(400)
        is_vulnerability = request.url.path.startswith(_VULN_INDEX)
        family = IndexFamily.vulnerabilities if is_vulnerability else IndexFamily.alerts
        data = _vulnerabilities(clock.now()) if is_vulnerability else _alerts(clock.now())
        matches = _matches(body["query"], data, family)
        if matches is None:
            return httpx.Response(400)
        if request.url.path in {_VALIDATE, _VULN_VALIDATE}:
            return httpx.Response(200, json={"valid": True})
        if request.url.path in {_COUNT, _VULN_COUNT}:
            return httpx.Response(200, json={"count": len(matches)})
        size = body["size"]
        sort = _items(body["sort"])
        first = _mapping(sort[0]) if sort else None
        if (
            not isinstance(size, int)
            or not 1 <= size <= 50
            or first
            != {
                "vulnerability.detected_at" if is_vulnerability else "@timestamp": {"order": "desc"}
            }
        ):
            return httpx.Response(400)
        timestamp_field = "vulnerability.detected_at" if is_vulnerability else "@timestamp"
        hit_index = _VULN_HIT_INDEX if is_vulnerability else _HIT_INDEX
        return httpx.Response(
            200,
            json={
                "took": 1,
                "timed_out": False,
                "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
                "hits": {
                    "total": {"value": len(matches), "relation": "eq"},
                    "hits": [
                        {
                            "_index": hit_index,
                            "_id": hit_id,
                            "_source": source,
                            "sort": [_field(source, timestamp_field), hit_index, hit_id],
                        }
                        for hit_id, source in matches[:size]
                    ],
                },
            },
        )

    return httpx.AsyncClient(base_url=_INDEXER, transport=httpx.MockTransport(handle))


def _pem(key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _resolve(key_id: str, expected: str, key: KeyMaterial) -> KeyMaterial:
    if key_id != expected:
        raise IdentityError()
    return key


def _identity(
    clock: _Clock, port: int
) -> tuple[AlbAssertionVerifier, McpBearerVerifier, dict[str, str]]:
    alb_key = ec.generate_private_key(ec.SECP256R1())
    mcp_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = clock.now()
    expires = now + timedelta(hours=8)
    origin = f"https://{_HOST}:{port}"
    resource = f"{origin}/mcp"
    alb_token = jwt.encode(
        {"sub": _SUBJECT, "groups": ["soc"]},
        _pem(alb_key),
        algorithm="ES256",
        headers={
            "kid": _ALB_KID,
            "signer": _ALB_SIGNER,
            "iss": _ISSUER,
            "client": _CLIENT_ID,
            "exp": int(expires.timestamp()),
        },
    )
    mcp_token = jwt.encode(
        {
            "iss": _ISSUER,
            "aud": resource,
            "sub": _SUBJECT,
            "groups": ["soc"],
            "scope": "soc:ask",
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()) - 5,
            "exp": int(expires.timestamp()),
        },
        _pem(mcp_key),
        algorithm="RS256",
        headers={"kid": _MCP_KID},
    )
    alb = AlbAssertionVerifier(
        region="us-east-1",
        signer_arn=_ALB_SIGNER,
        issuer=_ISSUER,
        client_id=_CLIENT_ID,
        groups_claim="groups",
        key_resolver=lambda key_id: _resolve(key_id, _ALB_KID, alb_key.public_key()),
        now=clock.now,
    )
    mcp = McpBearerVerifier(
        issuer=_ISSUER,
        resource=resource,
        jwks_uri=f"{_ISSUER}/.well-known/jwks.json",
        key_resolver=lambda key_id: _resolve(key_id, _MCP_KID, mcp_key.public_key()),
        now=clock.now,
        allowed_origins=frozenset({origin}),
    )
    tokens = {
        "alb_assertion": alb_token,
        "mcp_bearer": mcp_token,
        "mcp_origin": origin,
        "mcp_resource": resource,
        "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return alb, mcp, tokens


def _compose(pack: Path, port: int) -> tuple[SocRuntime, httpx.AsyncClient, dict[str, str]]:
    verify_content_pack(pack)
    manifest = PackManifest.model_validate_json((pack / "manifest.json").read_bytes())
    provenance_record = cast(dict[str, object], json.loads((pack / "provenance.json").read_bytes()))
    if provenance_record.get("mode") != "fixture":
        raise ValueError("content pack provenance mode must be fixture")
    catalog = load_content_catalog(
        pack,
        provenance=BuildProvenance(
            service_sha="0" * 40,
            content_repository=str(manifest.source_repository),
            content_sha=manifest.content_sha,
            pack_sha256=manifest.pack_sha256,
            image_digest="sha256:" + "0" * 64,
            docs_origin="https://docs.example.test",
            docs_manifest_sha256=manifest.docs_manifest_sha256,
        ),
    )
    clock = _Clock()
    alb, mcp, tokens = _identity(clock, port)
    indexer = _indexer(clock)
    site = SiteConfig(
        environment_id="synthetic",
        label="Synthetic site",
        enabled=True,
        indexer_origin=_INDEXER,
        private_network_ref="synthetic-loopback-only",
        jwt_issuer="synthetic-soc",
        jwt_audience="synthetic-indexer",
        kms_signing_key_arn=_KMS_KEY,
        ca_secret_arn="arn:aws:secretsmanager:us-east-1:000000000000:secret:synthetic",
        ca_secret_version="synthetic",
        ca_sha256="a" * 64,
        group_role_map={"soc": ("analyst",)},
        role_visibility={"analyst": Visibility.full},
        allowed_index_patterns={
            IndexFamily.alerts: ("wazuh-alerts-synthetic-*",),
            IndexFamily.vulnerabilities: ("wazuh-vulnerabilities-synthetic-*",),
        },
        mapping_profile="wazuh-v4-fixture",
        policy_version="synthetic-v1",
        pit_supported=False,
        allowed_templates=(
            TemplateId.alerts_count_v1,
            TemplateId.alerts_rows_v1,
            TemplateId.vulnerabilities_rows_v1,
        ),
        dls_attestation_version="synthetic-v1",
        composite_role_visibility={"analyst": Visibility.full},
    )
    model = ModelCapability(
        id="synthetic-model",
        label="Synthetic deterministic model",
        region="us-east-1",
        resource_arns=("arn:aws:bedrock:us-east-1:000000000000:inference-profile/synthetic",),
        context_tokens=8192,
        max_output_tokens=1024,
        count_tokens_model_id="synthetic-count-model",
        efforts=(),
        effort_transport="none",
        effort_parameters={},
        output_strategy="strict_json_messages",
        count_strategy="count_tokens_converse",
        count_contract_sha256="b" * 64,
        cache_min_tokens=0,
        cache_max_checkpoints=0,
        cache_ttl="5m",
        validated_at=clock.now(),
        primary_doc_url=cast(
            HTTPSUrl,
            TypeAdapter(HTTPSUrl).validate_python("https://docs.example.test/model"),
        ),
    )
    config = ServiceConfig(
        mode="fixture",
        guardrail_identifier="synthetic-guardrail",
        guardrail_version="1",
        sites=(site,),
        models=(model,),
    )

    def transport_for(site: AuthorizedSite) -> httpx.AsyncClient:
        return indexer

    def judgment_factory(admission: ModelCountAdmissionStore) -> BedrockJudgmentProvider:
        return BedrockJudgmentProvider(_ModelClient(), admission_store=admission, clock=clock)

    runtime = compose_soc(
        config,
        clock=clock,
        catalog=catalog,
        state_client=None,
        state_table=None,
        kms=_Kms(),
        indexer_key_ids={"synthetic": "synthetic-indexer-key"},
        transport_for=transport_for,
        mapping_profiles={"wazuh-v4-fixture": default_profile()},
        cursor_cipher=CursorCipher(
            keys={"synthetic": os.urandom(32)}, current_key_id="synthetic", now=clock.now
        ),
        judgment_provider_factory=judgment_factory,
        audit_client=_Queue(),
        audit_queue_url="https://queue.example.test/audit",
        feedback_client=_Queue(),
        feedback_queue_url="https://queue.example.test/feedback",
        span_exporter=_Discard(),
        metric_exporter=_Discard(),
        receipt_keys={"synthetic": os.urandom(32)},
        current_receipt_key="synthetic",
        csrf_secret=os.urandom(32),
        browser_origin=f"http://{_HOST}:{port}",
        alb_verifier=alb,
        mcp_verifier=mcp,
        readiness=_Ready(),
        standing_rules="Return only catalog-grounded observations.",
        mcp_issuer_url=_ISSUER,
        mcp_resource_url=tokens["mcp_resource"],
    )
    credentials = {
        "base_url": f"http://{_HOST}:{port}",
        "browser_origin": f"http://{_HOST}:{port}",
        "alb_header_name": "x-amzn-oidc-data",
        "alb_assertion": tokens["alb_assertion"],
        "mcp_url": f"http://{_HOST}:{port}/mcp",
        "mcp_bearer": tokens["mcp_bearer"],
        "mcp_origin": tokens["mcp_origin"],
        "expires_at": tokens["expires_at"],
        "principal_sub": _SUBJECT,
    }
    return runtime, indexer, credentials


def _serve(pack: Path, credentials: Path, port: int) -> None:
    descriptor = os.open(credentials, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            runtime, indexer, values = _compose(pack, port)
            handle.write(json.dumps(values, sort_keys=True) + "\n")
    except BaseException:
        credentials.unlink(missing_ok=True)
        raise

    async def shutdown() -> None:
        runtime.close_feedback_control()
        await indexer.aclose()
        credentials.unlink(missing_ok=True)

    print(
        f"AI SOC synthetic fixture server on http://{_HOST}:{port} (credentials: {credentials})",
        flush=True,
    )
    try:
        uvicorn.run(
            runtime_asgi_app(runtime, shutdown=shutdown),
            host=_HOST,
            port=port,
            lifespan="on",
            log_level="warning",
        )
    finally:
        credentials.unlink(missing_ok=True)


def _live_variable() -> str | None:
    for name in _LIVE_VARIABLES:
        if os.environ.get(name):
            return name
    for name, value in os.environ.items():
        if name.startswith("SOC_") and name.endswith("_ENDPOINT_URL") and value:
            return name
    mode = os.environ.get("SOC_MODE")
    if mode is not None and mode != "fixture":
        return "SOC_MODE"
    return None


def main() -> int:
    offending = _live_variable()
    if offending is not None:
        print(f"ERROR: refusing live configuration in {offending}", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack", required=True, type=Path)
    parser.add_argument("--credentials", required=True, type=Path)
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        print("ERROR: --port must be between 1 and 65535", file=sys.stderr)
        return 2
    try:
        _serve(args.pack, args.credentials, args.port)
    except FileExistsError:
        print(
            "ERROR: credentials file already exists; remove it if no dev server is running",
            file=sys.stderr,
        )
        return 2
    except KeyboardInterrupt:
        return 0
    except Exception as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
