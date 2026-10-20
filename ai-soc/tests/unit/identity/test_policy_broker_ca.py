from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.x509.oid import NameOID

from ai_soc.contracts.models import (
    AdmissionGrant,
    CallKind,
    ErrorCode,
    ExecutionContext,
    IndexFamily,
    SiteConfig,
    TemplateId,
    TraceContext,
    VerifiedPrincipal,
    Visibility,
)
from ai_soc.identity.alb import AlbAssertionVerifier, IdentityError
from ai_soc.identity.broker import KmsIndexerTokenBroker
from ai_soc.identity.ca import CAConfigurationError, build_site_transport
from ai_soc.identity.policy import MappedSitePolicy, SiteAuthorizationError

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)


def record_case_metadata(
    request, *, acceptance_id: str, case_id: str, variant: str, fixture_sha256: str
) -> None:
    request.node.user_properties.extend(
        [
            ("acceptance_ids", acceptance_id),
            ("case_id", case_id),
            ("variant", variant),
            ("fixture_sha256", fixture_sha256),
        ]
    )


def make_site(site_id: str, role: str = "analyst_read", ca_pem: str = "unused") -> SiteConfig:
    return SiteConfig(
        environment_id=site_id,
        label=site_id,
        enabled=True,
        indexer_origin=f"https://{site_id}.private.example.test",
        private_network_ref=f"vpn-{site_id}",
        jwt_issuer=f"soc-{site_id}",
        jwt_audience=f"wazuh-{site_id}",
        kms_signing_key_arn=f"arn:aws:kms:us-east-1:123456789012:key/{site_id}",
        ca_secret_arn=f"arn:aws:secretsmanager:us-east-1:123456789012:secret:{site_id}",
        ca_secret_version=f"version-{site_id}",
        ca_sha256=hashlib.sha256(ca_pem.encode()).hexdigest(),
        group_role_map={"soc-alpha": (role,), "soc-beta": ("beta_read",)},
        role_visibility={role: Visibility.full, "beta_read": Visibility.filtered},
        allowed_index_patterns={IndexFamily.alerts: (f"wazuh-alerts-{site_id}-*",)},
        mapping_profile="wazuh-v4-fixture",
        policy_version="policy-1",
        pit_supported=True,
        allowed_templates=(
            TemplateId.alerts_rows_v1,
            TemplateId.alerts_count_v1,
            TemplateId.alerts_group_v1,
        ),
        dls_attestation_version="dls-7",
        composite_role_visibility={role: Visibility.full, "beta_read": Visibility.filtered},
    )


def principal(groups=("soc-alpha",), expires=NOW + timedelta(minutes=10)) -> VerifiedPrincipal:
    from ai_soc.contracts.canonical import owner_key

    return VerifiedPrincipal(
        issuer="https://id.example.test",
        sub="analyst-007",
        owner_key=owner_key("https://id.example.test", "analyst-007"),
        groups=groups,
        edge="browser",
        authenticated_at=NOW,
        expires_at=expires,
        assertion_hash="a" * 64,
    )


def test_policy_maps_each_site_independently_and_hashes_effective_roles():
    alpha = make_site("alpha")
    beta = make_site("beta")
    policy = MappedSitePolicy((alpha, beta), now=lambda: NOW)
    authorized = policy.authorize(principal(), "alpha")
    assert authorized.backend_roles == ("analyst_read",)
    assert authorized.visibility == Visibility.full
    assert policy.authorized_sites(principal()) == (alpha, beta)
    with pytest.raises(SiteAuthorizationError) as error:
        policy.authorize(principal(("unknown-group",)), "alpha")
    assert error.value.code == ErrorCode.SITE_DENIED
    assert policy.authorize(principal(("soc-beta",)), "beta").backend_roles == ("beta_read",)

    changed_role = make_site("alpha", role="changed_read")
    changed = MappedSitePolicy((changed_role,), now=lambda: NOW).authorize(principal(), "alpha")
    assert changed.policy_hash != authorized.policy_hash
    unknown_combo = make_site("alpha")
    unknown_combo = unknown_combo.model_copy(update={"composite_role_visibility": {}})
    assert (
        MappedSitePolicy((unknown_combo,), now=lambda: NOW)
        .authorize(principal(), "alpha")
        .visibility
        == Visibility.unknown
    )
    with pytest.raises(SiteAuthorizationError) as error:
        policy.authorize(principal(expires=NOW - timedelta(seconds=1)), "alpha")
    assert error.value.code == ErrorCode.AUTH_EXPIRED
    assert policy.authorized_sites(principal(expires=NOW - timedelta(seconds=1))) == ()


@pytest.mark.asyncio
@pytest.mark.parametrize("variant", ["positive", "negative", "boundary", "failure"])
async def test_verified_alb_identity_maps_through_policy_to_site_kms_token(variant, request):
    fixture_path = Path(__file__).parent / "data/identity_pipeline_cases.json"
    fixture_bytes = fixture_path.read_bytes()
    fixture_sha256 = hashlib.sha256(fixture_bytes).hexdigest()
    assert fixture_sha256 == "0c1b54007e698db9df7ff163e4d66d4dff08f198b11c2537365998ff59e57876"
    scenario = json.loads(fixture_bytes)["cases"][variant]
    record_case_metadata(
        request,
        acceptance_id="G056",
        case_id="SEC-003.resolution",
        variant=variant,
        fixture_sha256=fixture_sha256,
    )

    assertion_key = ec.generate_private_key(ec.SECP256R1())
    token_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = "https://id.example.test"
    signer = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/soc/abc"
    alb_header = {
        "signer": signer,
        "iss": issuer,
        "client": "browser-client",
        "exp": int((NOW + timedelta(seconds=scenario["exp_offset_seconds"])).timestamp()),
    }
    claims = {"sub": "analyst-007", "groups": scenario["groups"]}
    assertion = jwt.encode(
        claims,
        assertion_key,
        algorithm="ES256",
        headers={"kid": "local-alb-key", **alb_header},
    )
    verifier = AlbAssertionVerifier(
        region="us-east-1",
        signer_arn=signer,
        issuer=issuer,
        client_id="browser-client",
        groups_claim="groups",
        key_resolver=lambda kid: (
            assertion_key.public_key()
            if kid == "local-alb-key"
            else pytest.fail("unexpected key identifier")
        ),
        now=lambda: NOW,
    )
    try:
        verified = verifier.verify(assertion)
    except IdentityError as error:
        assert scenario["error"] == error.code.value
        return

    policy = MappedSitePolicy((make_site("alpha"), make_site("beta")), now=lambda: NOW)
    try:
        authorized = policy.authorize(verified, "alpha")
    except SiteAuthorizationError as error:
        assert scenario["error"] == error.code.value
        return
    assert authorized.backend_roles == (scenario["role"],)
    assert authorized.visibility == scenario["visibility"]

    class Kms:
        def __init__(self):
            self.requests = []

        def sign(self, **kwargs):
            self.requests.append(kwargs)
            return {
                "Signature": token_key.sign(
                    kwargs["Message"],
                    padding.PKCS1v15(),
                    utils.Prehashed(hashes.SHA256()),
                )
            }

    class Cancellation:
        def is_cancelled(self):
            return False

        def raise_if_cancelled(self):
            return None

        async def wait(self):
            return None

    class Ledger:
        def claim(self, kind: CallKind):
            self.kind = kind

    execution = ExecutionContext(
        question_id=uuid4(),
        operation="ask",
        owner_key=verified.owner_key,
        environment_id="alpha",
        deadline_at=NOW + timedelta(seconds=30),
        cancel=Cancellation(),
        calls=Ledger(),
        admission=AdmissionGrant(
            holder_id=uuid4(),
            slot_ids=("alpha-owner",),
            expires_at=NOW + timedelta(seconds=30),
            fence=1,
        ),
        trace_context=TraceContext(trace_id="3" * 32, span_id="3" * 16, trace_flags=1),
    )
    kms = Kms()
    broker = KmsIndexerTokenBroker(kms, key_ids={"alpha": "alpha-key-v4"}, now=lambda: NOW)
    credential = await broker.issue(verified, authorized, execution=execution)
    assert execution.calls.kind == CallKind.kms
    signed = kms.requests[0]
    assert set(signed) == {"KeyId", "Message", "MessageType", "SigningAlgorithm"}
    assert signed["KeyId"] == make_site("alpha").kms_signing_key_arn
    assert signed["MessageType"] == "DIGEST"
    assert signed["SigningAlgorithm"] == "RSASSA_PKCS1_V1_5_SHA_256"
    token = credential.bearer_token.get_secret_value()
    issued_claims = jwt.decode(
        token,
        token_key.public_key(),
        algorithms=["RS256"],
        audience="wazuh-alpha",
        issuer="soc-alpha",
        options={"verify_exp": False},
    )
    assert issued_claims["sub"] == verified.sub
    assert issued_claims["backend_roles"] == [scenario["role"]]
    assert issued_claims["exp"] - issued_claims["iat"] == 120
    assert jwt.get_unverified_header(token)["kid"] == "alpha-key-v4"


class FakeKms:
    def __init__(self, private):
        self.private = private
        self.requests = []

    def sign(self, **kwargs):
        self.requests.append(kwargs)
        assert kwargs["KeyId"].endswith("/alpha")
        assert kwargs["MessageType"] == "DIGEST"
        assert kwargs["SigningAlgorithm"] == "RSASSA_PKCS1_V1_5_SHA_256"
        from cryptography.hazmat.primitives.asymmetric import padding, utils

        signature = self.private.sign(
            kwargs["Message"], padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())
        )
        return {"Signature": signature}


@pytest.mark.asyncio
async def test_kms_broker_signs_exact_analyst_claims_for_one_site():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    kms = FakeKms(private)
    config = make_site("alpha")
    site = MappedSitePolicy((config,), now=lambda: NOW).authorize(principal(), "alpha")
    broker = KmsIndexerTokenBroker(kms, key_ids={"alpha": "alpha-key-v4"}, now=lambda: NOW)

    class Cancellation:
        def is_cancelled(self):
            return False

        def raise_if_cancelled(self):
            return None

        async def wait(self):
            return None

    class Ledger:
        def claim(self, kind: CallKind):
            self.kind = kind

    execution = ExecutionContext(
        question_id=uuid4(),
        operation="ask",
        owner_key=principal().owner_key,
        environment_id="alpha",
        deadline_at=NOW + timedelta(seconds=30),
        cancel=Cancellation(),
        calls=Ledger(),
        admission=AdmissionGrant(
            holder_id=uuid4(),
            slot_ids=("alpha-owner",),
            expires_at=NOW + timedelta(seconds=30),
            fence=1,
        ),
        trace_context=TraceContext(trace_id="2" * 32, span_id="2" * 16, trace_flags=1),
    )
    credential = await broker.issue(principal(), site, execution=execution)
    assert execution.calls.kind == CallKind.kms
    token = credential.bearer_token.get_secret_value()
    claims = jwt.decode(
        token,
        private.public_key(),
        algorithms=["RS256"],
        audience="wazuh-alpha",
        issuer="soc-alpha",
        options={"verify_exp": False},
    )
    assert claims["sub"] == "analyst-007"
    assert claims["backend_roles"] == ["analyst_read"]
    assert claims["exp"] - claims["iat"] == 120
    assert jwt.get_unverified_header(token)["kid"] == "alpha-key-v4"
    request = kms.requests[0]
    assert set(request) == {"KeyId", "Message", "MessageType", "SigningAlgorithm"}
    assert request["Message"] == hashlib.sha256(".".join(token.split(".")[:2]).encode()).digest()
    assert "analyst-007" not in repr(credential)
    from ai_soc.identity.broker import BrokerError

    with pytest.raises(BrokerError) as error:
        await broker.issue(
            principal(),
            site,
            execution=replace(execution, environment_id="beta"),
        )
    assert error.value.code == ErrorCode.FORBIDDEN


@pytest.mark.asyncio
async def test_unknown_composite_visibility_still_brokers_indexer_credentials():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    kms = FakeKms(private)
    authorized = MappedSitePolicy((make_site("alpha"),), now=lambda: NOW).authorize(
        principal(groups=("soc-alpha", "soc-beta")), "alpha"
    )
    assert authorized.visibility == Visibility.unknown
    assert authorized.backend_roles == ("analyst_read", "beta_read")
    broker = KmsIndexerTokenBroker(kms, key_ids={"alpha": "alpha-key-v4"}, now=lambda: NOW)

    class Cancellation:
        def is_cancelled(self):
            return False

        def raise_if_cancelled(self):
            return None

        async def wait(self):
            return None

    class Ledger:
        def claim(self, kind: CallKind):
            self.kind = kind

    execution = ExecutionContext(
        question_id=uuid4(),
        operation="ask",
        owner_key=principal().owner_key,
        environment_id="alpha",
        deadline_at=NOW + timedelta(seconds=30),
        cancel=Cancellation(),
        calls=Ledger(),
        admission=AdmissionGrant(
            holder_id=uuid4(),
            slot_ids=("alpha-owner",),
            expires_at=NOW + timedelta(seconds=30),
            fence=1,
        ),
        trace_context=TraceContext(trace_id="4" * 32, span_id="4" * 16, trace_flags=1),
    )
    credential = await broker.issue(
        principal(groups=("soc-alpha", "soc-beta")), authorized, execution=execution
    )
    assert credential.bearer_token.get_secret_value()


class FakeSecret:
    def __init__(self, text):
        self.text = text
        self.calls = []

    def get_secret_value(self, *, secret_id: str, version_id: str) -> str:
        self.calls.append((secret_id, version_id))
        return self.text


def ca_bundle() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fixture SOC CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_site_transport_requires_exact_version_hash_and_hostname_verification():
    pem = ca_bundle()
    config = make_site("alpha", ca_pem=pem)
    authorized = MappedSitePolicy((config,), now=lambda: NOW).authorize(principal(), "alpha")
    secrets = FakeSecret(pem)
    transport = build_site_transport(authorized, secrets)
    assert secrets.calls == [(config.ca_secret_arn, config.ca_secret_version)]
    assert transport.environment_id == "alpha"
    assert transport.policy_hash == authorized.policy_hash
    assert transport.client.follow_redirects is False
    assert transport.client._trust_env is False
    context = transport.client._transport._pool._ssl_context
    assert context.check_hostname is True
    assert context.verify_mode == 2
    import asyncio

    asyncio.run(transport.client.aclose())

    bad_hash_site = MappedSitePolicy(
        (config.model_copy(update={"ca_sha256": "0" * 64}),), now=lambda: NOW
    ).authorize(principal(), "alpha")
    with pytest.raises(CAConfigurationError) as error:
        build_site_transport(bad_hash_site, FakeSecret(pem))
    assert error.value.code == ErrorCode.CA_UNTRUSTED


@pytest.mark.parametrize("variant", ["positive", "boundary"])
def test_site_transport_enforces_site_hostname_with_local_tls(tmp_path, request, variant):
    import asyncio
    import json
    import socket
    import ssl
    from pathlib import Path
    from threading import Thread

    from cryptography.x509 import SubjectAlternativeName
    from cryptography.x509.oid import ExtendedKeyUsageOID

    fixture_path = Path(__file__).parent / "data/gp4_ca_cases.json"
    fixture_bytes = fixture_path.read_bytes()
    fixture_sha256 = hashlib.sha256(fixture_bytes).hexdigest()
    assert fixture_sha256 == "e0c5667a08f7e66b4e703a8c6f3381dc251a37d3aa71f3dead45524a849f0c16"
    record_case_metadata(
        request,
        acceptance_id="GP4",
        case_id="B3-GP4.ca-trust",
        variant=variant,
        fixture_sha256=fixture_sha256,
    )
    gp4 = json.loads(fixture_bytes)
    variant_fixture = gp4["variants"][variant]
    assert variant_fixture["hostname_matches"] is (variant == "positive")

    now = datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Generated fixture CA")])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_hostname = variant_fixture["certificate_hostname"]
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, server_hostname)])
    server_certificate = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(SubjectAlternativeName([x509.DNSName(server_hostname)]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    ca_pem = ca_certificate.public_bytes(serialization.Encoding.PEM).decode()
    server_cert_path = tmp_path / "server.pem"
    server_key_path = tmp_path / "server-key.pem"
    server_cert_path.write_bytes(server_certificate.public_bytes(serialization.Encoding.PEM))
    server_key_path.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(server_cert_path, server_key_path)
    server_socket = socket.socket()
    server_socket.bind(("127.0.0.1", 0))
    server_socket.listen(1)
    port = server_socket.getsockname()[1]
    handshake_errors: list[Exception] = []

    def serve_one_connection() -> None:
        try:
            connection, _ = server_socket.accept()
            with connection:
                with server_context.wrap_socket(connection, server_side=True):
                    pass
        except (OSError, ssl.SSLError) as error:
            handshake_errors.append(error)
        finally:
            server_socket.close()

    server_thread = Thread(target=serve_one_connection, daemon=True)
    server_thread.start()
    config = make_site("alpha", ca_pem=ca_pem).model_copy(
        update={"ca_secret_version": variant_fixture["secret_version"]}
    )
    authorized = MappedSitePolicy((config,), now=lambda: NOW).authorize(principal(), "alpha")
    secrets = FakeSecret(ca_pem)
    transport = build_site_transport(authorized, secrets)
    assert secrets.calls == [(config.ca_secret_arn, variant_fixture["secret_version"])]
    client_context = transport.client._transport._pool._ssl_context

    if variant == "positive":
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw_socket:
            with client_context.wrap_socket(raw_socket, server_hostname=gp4["hostname"]):
                pass
    else:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw_socket:
            with pytest.raises(ssl.SSLCertVerificationError):
                client_context.wrap_socket(raw_socket, server_hostname=gp4["hostname"])

    server_thread.join(timeout=5)
    assert not server_thread.is_alive()
    assert bool(handshake_errors) is not variant_fixture["hostname_matches"]
    asyncio.run(transport.client.aclose())


@pytest.mark.parametrize("variant", ["positive", "negative", "boundary", "failure"])
def test_private_route_selection_uses_frozen_site_config(variant, request):
    import json
    from pathlib import Path

    from pydantic import ValidationError

    fixture_path = Path(__file__).parents[2] / "fixtures/v1/b3_private_route_cases.json"
    fixture_bytes = fixture_path.read_bytes()
    fixture_sha256 = hashlib.sha256(fixture_bytes).hexdigest()
    assert fixture_sha256 == "a480b9f8dd937ebbfe3d384f0aa19f40de62bbd64bfea9f50d38d8afd00ebaf6"
    record_case_metadata(
        request,
        acceptance_id="G057",
        case_id="B3-G057.private-route",
        variant=variant,
        fixture_sha256=fixture_sha256,
    )
    fixture = json.loads(fixture_bytes)["cases"][variant]
    assert fixture["route_mode"] == "private_only"
    assert fixture["public_indexer_ingress"] is False

    if variant == "negative":
        configured = make_site("alpha")
        policy = MappedSitePolicy((configured,), now=lambda: NOW)
        with pytest.raises(SiteAuthorizationError) as error:
            policy.authorize(principal(), fixture["requested_site"])
        assert error.value.code == ErrorCode.SITE_DENIED
        assert fixture["expected"] == {"refused": True, "client_created": False}
        return

    if variant == "failure":
        broken = fixture["sites"][0]
        valid = make_site(broken["environment_id"], ca_pem=ca_bundle())
        invalid_config = valid.model_dump(mode="python")
        invalid_config.update(
            {
                "indexer_origin": broken["indexer_origin"],
                "private_network_ref": broken["private_network_ref"],
            }
        )
        with pytest.raises(ValidationError):
            SiteConfig.model_validate(invalid_config)
        assert fixture["expected"]["standing_reader_fallback"] is False
        return

    pem = ca_bundle()
    configured_sites = []
    expected_routes = fixture["expected"].get("routes")
    for site_data in fixture["sites"]:
        config = make_site(site_data["environment_id"], ca_pem=pem).model_copy(
            update={
                "indexer_origin": site_data["indexer_origin"],
                "private_network_ref": site_data["private_network_ref"],
            }
        )
        configured_sites.append(config)

    policy = MappedSitePolicy(configured_sites, now=lambda: NOW)
    requested = expected_routes or [
        {
            "requested_site": fixture["requested_site"],
            "selected_origin": fixture["expected"]["selected_origin"],
            "private_network_ref": fixture["expected"]["private_network_ref"],
        }
    ]
    transports = []
    observed_routes = []
    secrets = FakeSecret(pem)
    for expected in requested:
        authorized = policy.authorize(principal(), expected["requested_site"])
        transport = build_site_transport(authorized, secrets)
        transports.append(transport)
        observed_routes.append(
            {
                "requested_site": expected["requested_site"],
                "selected_origin": str(authorized.config.indexer_origin),
                "private_network_ref": authorized.config.private_network_ref,
            }
        )
        assert transport.environment_id == expected["requested_site"]
        assert transport.client.base_url.host == expected["selected_origin"].split("//", 1)[1]

    assert observed_routes == requested
    if variant == "positive":
        assert fixture["expected"]["client_created"] is True
    sites_by_id = {site.environment_id: site for site in configured_sites}
    assert secrets.calls == [
        (
            sites_by_id[route["requested_site"]].ca_secret_arn,
            sites_by_id[route["requested_site"]].ca_secret_version,
        )
        for route in requested
    ]
    for transport in transports:
        import asyncio

        asyncio.run(transport.client.aclose())


@pytest.mark.parametrize("variant", ["negative", "failure"])
def test_site_ca_trust_variants_use_frozen_fixture(variant, request):
    import json
    from pathlib import Path

    fixture_path = Path(__file__).parent / "data/gp4_ca_cases.json"
    fixture_bytes = fixture_path.read_bytes()
    fixture_sha256 = hashlib.sha256(fixture_bytes).hexdigest()
    assert fixture_sha256 == "e0c5667a08f7e66b4e703a8c6f3381dc251a37d3aa71f3dead45524a849f0c16"
    record_case_metadata(
        request,
        acceptance_id="GP4",
        case_id="B3-GP4.ca-trust",
        variant=variant,
        fixture_sha256=fixture_sha256,
    )
    fixture = json.loads(fixture_bytes)
    variant_fixture = fixture["variants"][variant]
    pem = ca_bundle()
    config = make_site(fixture["environment_id"], ca_pem=pem)
    config = config.model_copy(
        update={
            "ca_secret_version": variant_fixture.get("secret_version", fixture["secret_version"])
        }
    )
    if variant == "negative":
        config = config.model_copy(update={"ca_sha256": "0" * 64})

    authorized = MappedSitePolicy((config,), now=lambda: NOW).authorize(principal(), "alpha")

    if variant == "failure":
        assert variant_fixture["secret_present"] is False
        assert variant_fixture["fallback"] is False

        class MissingSecret:
            def __init__(self) -> None:
                self.calls: list[tuple[str, str]] = []

            def get_secret_value(self, *, secret_id: str, version_id: str) -> str:
                self.calls.append((secret_id, version_id))
                raise LookupError("version unavailable")

        missing = MissingSecret()
        with pytest.raises(CAConfigurationError) as error:
            build_site_transport(authorized, missing)
        assert error.value.code == ErrorCode(variant_fixture["expected"])
        assert missing.calls == [(fixture["secret_id"], fixture["secret_version"])]
        return

    secrets = FakeSecret(pem)
    if variant == "negative":
        assert variant_fixture["sha256_matches"] is False
        with pytest.raises(CAConfigurationError) as error:
            build_site_transport(authorized, secrets)
        assert error.value.code == ErrorCode(variant_fixture["expected"])
        assert secrets.calls == [(fixture["secret_id"], fixture["secret_version"])]
        return

    raise AssertionError(f"unhandled frozen CA variant: {variant}")
