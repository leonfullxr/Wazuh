from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from ai_soc.contracts.canonical import owner_key
from ai_soc.contracts.models import (
    AdmissionGrant,
    CallKind,
    ExecutionContext,
    FetchSpec,
    IndexFamily,
    ResolvedWindow,
    SiteConfig,
    TemplateId,
    TraceContext,
    VerifiedPrincipal,
    Visibility,
)
from ai_soc.identity.policy import MappedSitePolicy
from ai_soc.query.compiler import default_profile
from ai_soc.query.cursors import CursorCipher

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)


class Cancellation:
    def is_cancelled(self) -> bool:
        return False

    def raise_if_cancelled(self) -> None:
        return None

    async def wait(self) -> None:
        return None


class Ledger:
    def __init__(self) -> None:
        self.claimed: list[CallKind] = []

    def claim(self, kind: CallKind) -> None:
        self.claimed.append(kind)


def make_principal(
    sub: str = "analyst-007", groups: tuple[str, ...] = ("soc-alpha",)
) -> VerifiedPrincipal:
    issuer = "https://id.example.test"
    return VerifiedPrincipal(
        issuer=issuer,
        sub=sub,
        owner_key=owner_key(issuer, sub),
        groups=groups,
        edge="fixture",
        authenticated_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
        assertion_hash="a" * 64,
    )


def make_site(site_id: str = "alpha") -> SiteConfig:
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
        ca_sha256="b" * 64,
        group_role_map={"soc-alpha": ("analyst_read",), "soc-beta": ("beta_read",)},
        role_visibility={"analyst_read": Visibility.full, "beta_read": Visibility.filtered},
        allowed_index_patterns={
            IndexFamily.alerts: (f"wazuh-alerts-{site_id}-*",),
            IndexFamily.vulnerabilities: (f"wazuh-states-vulnerabilities-{site_id}-*",),
        },
        mapping_profile="wazuh-v4-fixture",
        policy_version="policy-1",
        pit_supported=True,
        allowed_templates=tuple(TemplateId),
        dls_attestation_version="dls-7",
        composite_role_visibility={
            "analyst_read": Visibility.full,
            "beta_read": Visibility.filtered,
        },
    )


@pytest.fixture
def principal() -> VerifiedPrincipal:
    return make_principal()


@pytest.fixture
def site():
    config = make_site()
    authorized = MappedSitePolicy((config,), now=lambda: NOW).authorize(make_principal(), "alpha")
    return config, authorized


@pytest.fixture
def window() -> ResolvedWindow:
    return ResolvedWindow(
        start=NOW - timedelta(days=1),
        end=NOW,
        semantics="rolling",
        source_text="last 24 hours",
        timezone="UTC",
        anchor_at=NOW,
    )


@pytest.fixture
def fetch(window: ResolvedWindow) -> FetchSpec:
    from ai_soc.contracts.models import FieldId, Filter

    return FetchSpec(
        fetch_id="fetch_alerts",
        template_id=TemplateId.alerts_rows_v1,
        window=window,
        filters=[Filter(field=FieldId.agent_id, op="eq", value="007")],
        page_size=2,
    )


@pytest.fixture
def execution(principal: VerifiedPrincipal) -> ExecutionContext:
    return ExecutionContext(
        question_id=uuid4(),
        operation="ask",
        owner_key=principal.owner_key,
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
        trace_context=TraceContext(trace_id="1" * 32, span_id="1" * 16, trace_flags=1),
    )


@pytest.fixture
def cursor_cipher():
    return CursorCipher(keys={"key-1": b"k" * 32}, current_key_id="key-1", now=lambda: NOW)


@pytest.fixture
def mapping_profile():
    return default_profile("wazuh-v4-fixture")
