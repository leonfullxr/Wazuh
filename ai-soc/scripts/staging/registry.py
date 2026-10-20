from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

from scripts.staging.models import AcceptanceId, GateId, GateObligation
from scripts.staging.network_obligations import LV_NETWORK_OBLIGATION_IDS


@dataclass(frozen=True, slots=True)
class GateDefinition:
    gate_id: GateId
    title: str
    obligations: tuple[GateObligation, ...]
    acceptance_ids: tuple[AcceptanceId, ...] = ()


@dataclass(frozen=True, slots=True)
class FactSelector:
    fact_id: str
    event_source: str
    event_names: tuple[str, ...]
    resource_key: str
    outcome: str = "any"


@dataclass(frozen=True, slots=True)
class ProbeRegistration:
    gate_id: GateId
    contributor_id: str
    entrypoint: str
    command: tuple[str, ...]
    config_environment: str | None
    slots: tuple[str, ...]
    input_model: str | None
    obligation_evaluators: tuple[tuple[str, str], ...]
    obligation_facts: tuple[tuple[str, tuple[str, ...]], ...]

    def evaluator_version(self, obligation_id: str) -> str | None:
        return dict(self.obligation_evaluators).get(obligation_id)

    def required_facts(self, obligation_id: str) -> frozenset[str] | None:
        facts = dict(self.obligation_facts).get(obligation_id)
        return frozenset(facts) if facts is not None else None


GATE_REGISTRY: dict[GateId, GateDefinition] = {
    GateId.LV_PLATFORM: GateDefinition(
        GateId.LV_PLATFORM,
        "Platform topology and deployment pins",
        (
            GateObligation("internal_alb", "ALB is internal and tasks are private"),
            GateObligation("task_count", "At least two healthy service tasks run"),
            GateObligation("endpoint_policies", "Required endpoint and resource policies match"),
            GateObligation("image_digest", "Running image digest matches the approved pin"),
            GateObligation("drain_timing", "ALB idle, target drain and request deadlines match"),
            GateObligation("public_invoke_denied", "Public Bedrock invocation is denied by policy"),
        ),
    ),
    GateId.LV_IDENTITY: GateDefinition(
        GateId.LV_IDENTITY,
        "Identity assertions, revocation and ingress",
        (
            GateObligation(
                "assertion_claims",
                "ALB assertion signer, issuer, client, expiry and groups validate",
            ),
            GateObligation("revocation", "Identity revocation completes within fifteen minutes"),
            GateObligation("direct_task_ingress_denied", "Direct task ingress is denied"),
        ),
    ),
    GateId.LV_MCP: GateDefinition(
        GateId.LV_MCP,
        "MCP client flows and transport negatives",
        (
            GateObligation(
                "official_client_flows",
                "Official client initialize, list, ask, page and feedback work",
            ),
            GateObligation(
                "mcp_auth_negatives",
                "Wrong resource, issuer, scope, token type, cookie, version and Origin are denied",
            ),
            GateObligation("frozen_output_parity", "Structured output matches the frozen contract"),
        ),
    ),
    GateId.LV_SITE: GateDefinition(
        GateId.LV_SITE,
        "Wazuh site authorization and isolation",
        (
            GateObligation("site_read_isolation", "Analyst and site sentinel isolation holds"),
            GateObligation("site_write_denied", "Forbidden writes are denied"),
            GateObligation(
                "site_result_distinctions",
                "Unauthorized, forbidden and empty results remain distinct",
            ),
            GateObligation(
                "site_snapshot_pagination", "Snapshot and stable pagination are coherent"
            ),
            GateObligation("site_token_rotation", "JWT claims and signing-key rotation validate"),
        ),
    ),
    GateId.LV_NETWORK: GateDefinition(
        GateId.LV_NETWORK,
        "Private site, indexer and inference paths",
        (
            GateObligation(
                "site_private_pinned_ca_hostname", "Site TLS uses the pinned CA and hostname"
            ),
            GateObligation(
                "indexer_transport_without_public_fallback",
                "Indexer transport has no redirect, proxy, system-CA or public fallback",
            ),
            GateObligation(
                "bedrock_invoke_via_vpce_allowed",
                "Bedrock invocation succeeds through the configured VPC endpoint",
            ),
            GateObligation(
                "bedrock_invoke_public_denied",
                "The same application identity is denied on the public Bedrock path",
            ),
            GateObligation("gp4_missing_pin_denied", "A missing CA pin fails closed"),
            GateObligation("gp4_wrong_pin_denied", "A wrong CA pin fails closed"),
            GateObligation(
                "gp4_rotation_invalidates_hash",
                "CA rotation invalidates continuation state and configuration hashes",
            ),
        ),
        (AcceptanceId.GP4,),
    ),
    GateId.LV_STATE: GateDefinition(
        GateId.LV_STATE,
        "State transactions, admission and recovery",
        (
            GateObligation(
                "ddb_replica_transactions", "Two-replica DDB transactions and consistency hold"
            ),
            GateObligation("stage_admission", "Service and site admission limits hold"),
            GateObligation(
                "cancellation_recovery",
                "Cancellation, crash recovery and ambiguous outcomes remain fenced",
            ),
            GateObligation(
                "exactly_once_settlement", "Budget settlement and completion are not duplicated"
            ),
        ),
    ),
    GateId.LV_MODEL: GateDefinition(
        GateId.LV_MODEL,
        "Model, guardrail and usage controls",
        (
            GateObligation(
                "model_request_pins",
                "Exact model/profile, guardrail version and tool-free request are observed",
            ),
            GateObligation(
                "count_context_usage", "Count, context and usage accounting are bounded"
            ),
            GateObligation(
                "model_failure_handling", "Timeout, failure and output validation fail closed"
            ),
            GateObligation(
                "unsupported_features_disabled",
                "Unsupported cache and embedding features remain disabled",
            ),
        ),
    ),
    GateId.LV_CONTENT: GateDefinition(
        GateId.LV_CONTENT,
        "Approved content publication and rollback",
        (
            GateObligation(
                "detached_content_approval", "Detached content approval and immutable pack validate"
            ),
            GateObligation(
                "published_content_bytes",
                "S3 and CloudFront bytes and anchors match approved hashes",
            ),
            GateObligation("content_mismatch_blocks_promotion", "Mismatched promotion is blocked"),
            GateObligation(
                "paired_content_rollback", "Rollback restores paired service and content hashes"
            ),
        ),
    ),
    GateId.LV_OBSERVABILITY: GateDefinition(
        GateId.LV_OBSERVABILITY,
        "Audit archive, alarms and logging inventory",
        (
            GateObligation(
                "audit_archive_delivery",
                "Audit events are acknowledged into encrypted retained archive",
            ),
            GateObligation("audit_dlq_lag_alarms", "DLQ and queue-lag alarm behavior is observed"),
            GateObligation(
                "cloudtrail_invocation_logs",
                "CloudTrail and invocation logging configuration and delivery are inspected",
            ),
            GateObligation(
                "telemetry_secret_sentinel", "Telemetry excludes prompts, credentials and secrets"
            ),
        ),
    ),
    GateId.LV_NIGHTLY: GateDefinition(
        GateId.LV_NIGHTLY,
        "Nightly golden denominator and usage",
        (
            GateObligation(
                "nightly_required_cases",
                "Every required bilingual golden case has an observed result",
            ),
            GateObligation(
                "nightly_router_accuracy",
                "Deterministic routing is correct for the full denominator",
            ),
            GateObligation(
                "nightly_drop_alarm", "Candidate denominator and reviewed drop alarm are evaluated"
            ),
            GateObligation("nightly_usage_cost", "Per-run model and inference cost is observed"),
            GateObligation("nightly_usage_latency", "Per-run latency distribution is observed"),
            GateObligation(
                "nightly_cache_behavior", "Cache behavior and disabled features are observed"
            ),
            GateObligation(
                "nightly_missing_run_behavior", "Scheduled missing-run behavior is observed"
            ),
        ),
        (AcceptanceId.GP3,),
    ),
    GateId.LV_UI: GateDefinition(
        GateId.LV_UI,
        "Authenticated browser and accessibility flows",
        (
            GateObligation(
                "ui_authenticated_flows",
                "Authenticated CSRF, paging, continuation, feedback and cancellation flows work",
            ),
            GateObligation("ui_language_layout", "EN/ES and 320px layouts work"),
            GateObligation(
                "ui_keyboard_screenreader",
                "Keyboard and manual screen-reader findings are recorded",
            ),
            GateObligation(
                "ui_accessibility_report", "Automated accessibility findings are attached"
            ),
        ),
    ),
}

# CloudTrail selectors are core-owned and keyed by the fact names consumed by
# the fixed evaluator. Task envelopes may identify request IDs, but cannot
# choose an operation, resource, or evidence source.
FACT_SELECTOR_REGISTRY = MappingProxyType(
    {
        (GateId.LV_STATE, "state", "state_contender_a"): FactSelector(
            "state_contender_a", "dynamodb.amazonaws.com", ("UpdateItem",), "state_table"
        ),
        (GateId.LV_STATE, "state", "state_contender_b"): FactSelector(
            "state_contender_b", "dynamodb.amazonaws.com", ("UpdateItem",), "state_table"
        ),
        (GateId.LV_STATE, "state", "state_stage_admission"): FactSelector(
            "state_stage_admission",
            "dynamodb.amazonaws.com",
            ("TransactWriteItems",),
            "state_table",
        ),
        (GateId.LV_STATE, "state", "state_stale_fence"): FactSelector(
            "state_stale_fence", "dynamodb.amazonaws.com", ("UpdateItem",), "state_table"
        ),
        (GateId.LV_STATE, "state", "state_terminal_recovery"): FactSelector(
            "state_terminal_recovery",
            "dynamodb.amazonaws.com",
            ("TransactWriteItems", "UpdateItem"),
            "state_table",
        ),
        (GateId.LV_STATE, "state", "state_exactly_once_settlement"): FactSelector(
            "state_exactly_once_settlement",
            "dynamodb.amazonaws.com",
            ("TransactWriteItems",),
            "state_table",
        ),
    }
)


PROBE_REGISTRY = MappingProxyType(
    {
        (GateId.LV_MCP, "mcp", "mcp"): ProbeRegistration(
            gate_id=GateId.LV_MCP,
            contributor_id="mcp",
            entrypoint="mcp",
            command=("python", "-m", "ai_soc.qualification.mcp_probe"),
            config_environment="LV_MCP_PROBE_CONFIG",
            slots=("probe",),
            input_model="ai_soc.qualification.mcp_models:LvMcpInputs",
            obligation_evaluators=tuple(
                (obligation, "mcp.v1")
                for obligation in (
                    "official_client_flows",
                    "mcp_auth_negatives",
                    "frozen_output_parity",
                )
            ),
            obligation_facts=(
                ("official_client_flows", ("mcp_official_client_flows",)),
                ("mcp_auth_negatives", ("mcp_auth_negatives",)),
                ("frozen_output_parity", ("mcp_output_parity",)),
            ),
        ),
        (GateId.LV_STATE, "state", "state"): ProbeRegistration(
            gate_id=GateId.LV_STATE,
            contributor_id="state",
            entrypoint="state",
            command=("python", "-m", "ai_soc.qualification.state_probe"),
            config_environment="LV_STATE_PROBE_CONFIG",
            slots=("A", "B"),
            input_model="ai_soc.qualification.state_models:StateProbeInputs",
            obligation_evaluators=tuple(
                (obligation, "state.v1")
                for obligation in (
                    "ddb_replica_transactions",
                    "stage_admission",
                    "cancellation_recovery",
                    "exactly_once_settlement",
                )
            ),
            obligation_facts=(
                ("ddb_replica_transactions", ("state_contender_a", "state_contender_b")),
                ("stage_admission", ("state_stage_admission",)),
                ("cancellation_recovery", ("state_stale_fence", "state_terminal_recovery")),
                ("exactly_once_settlement", ("state_exactly_once_settlement",)),
            ),
        ),
        (GateId.LV_MCP, "mcp", "canary"): ProbeRegistration(
            gate_id=GateId.LV_MCP,
            contributor_id="mcp",
            entrypoint="canary",
            command=("python", "-m", "ai_soc.qualification.network_canary"),
            config_environment=None,
            slots=("service", "public-isolated"),
            input_model=None,
            obligation_evaluators=(),
            obligation_facts=(),
        ),
    }
)


def probe_registrations(gate_id: GateId, contributor_id: str) -> tuple[ProbeRegistration, ...]:
    return tuple(
        registration
        for (
            registered_gate,
            registered_contributor,
            _entrypoint,
        ), registration in PROBE_REGISTRY.items()
        if registered_gate == gate_id and registered_contributor == contributor_id
    )


def registered_contributors(gate_id: GateId) -> frozenset[str]:
    return frozenset(
        registration.contributor_id
        for (registered_gate, _contributor_id, _entrypoint), registration in PROBE_REGISTRY.items()
        if registered_gate == gate_id and registration.obligation_evaluators
    )


def evaluator_version_for(gate_id: GateId, contributor_id: str, obligation_id: str) -> str | None:
    versions = {
        version
        for registration in probe_registrations(gate_id, contributor_id)
        if (version := registration.evaluator_version(obligation_id)) is not None
    }
    return next(iter(versions)) if len(versions) == 1 else None


def required_facts_for(
    gate_id: GateId, contributor_id: str, obligation_id: str
) -> frozenset[str] | None:
    fact_sets = {
        facts
        for registration in probe_registrations(gate_id, contributor_id)
        if (facts := registration.required_facts(obligation_id)) is not None
    }
    return next(iter(fact_sets)) if len(fact_sets) == 1 else None


ACCEPTANCE_GATE: dict[AcceptanceId, GateId] = {
    AcceptanceId.GP3: GateId.LV_NIGHTLY,
    AcceptanceId.GP4: GateId.LV_NETWORK,
}

if set(GATE_REGISTRY) != set(GateId):  # pragma: no cover - import-time invariant
    raise RuntimeError("gate registry must cover every continuity gate exactly once")
if tuple(item.obligation_id for item in GATE_REGISTRY[GateId.LV_NETWORK].obligations) != (
    LV_NETWORK_OBLIGATION_IDS
):  # pragma: no cover - import-time invariant
    raise RuntimeError("network registry obligations must match the exported network contract")
