"""Validation for finite, deployment supplied Bedrock capabilities."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from ai_soc.contracts.models import Effort, GuardrailPin, ModelCapability


class CapabilityError(ValueError):
    """A model capability or guardrail is not safe to invoke."""


@dataclass(frozen=True, slots=True)
class EmbeddingCapability:
    model_id: str
    region: str
    resource_arns: tuple[str, ...]
    dimensions: int
    purpose: str
    normalization: str
    provider_mode: str
    query_mode: str
    document_mode: str
    guardrail: GuardrailPin
    source_vpce: str
    request_bytes: int
    max_tokens: int
    max_calls_per_question: int
    requests_per_minute: int
    validated_at: datetime
    primary_doc_url: str
    validated: bool = False


def validate_model_capability(model: ModelCapability) -> ModelCapability:
    """Reject internally inconsistent capabilities before any SDK call."""
    if not model.id.strip() or not model.region.strip() or not model.resource_arns:
        raise CapabilityError("model capability identity and resource allowlist are required")
    if any(not arn.startswith("arn:") for arn in model.resource_arns):
        raise CapabilityError("model capability contains a non-ARN resource")
    if len(set(model.resource_arns)) != len(model.resource_arns):
        raise CapabilityError("model capability resource allowlist contains duplicates")
    if len(set(model.efforts)) != len(model.efforts):
        raise CapabilityError("model effort list contains duplicates")
    if model.effort_transport == "none" and model.effort_parameters:
        raise CapabilityError("effort parameters require a declared transport")
    if model.effort_transport == "additionalModelRequestFields":
        if set(model.effort_parameters) != set(model.efforts):
            raise CapabilityError("every supported effort must have one fixed parameter map")
        if not model.efforts:
            raise CapabilityError("effort transport requires at least one supported effort")
    elif model.effort_parameters:
        raise CapabilityError("effort parameter map is not supported")
    if model.max_output_tokens >= model.context_tokens:
        raise CapabilityError("maximum output must be smaller than model context")
    if (
        model.output_strategy != "strict_json_messages"
        or model.count_strategy != "count_tokens_converse"
    ):
        raise CapabilityError("unsupported judgment transport strategy")
    return model


def validate_guardrail(guardrail: GuardrailPin) -> GuardrailPin:
    if not guardrail.identifier.strip() or guardrail.identifier.strip().casefold() in {
        "draft",
        "none",
        "null",
    }:
        raise CapabilityError("a configured numbered guardrail is required")
    if not guardrail.version.isdecimal() or int(guardrail.version) < 1:
        raise CapabilityError("a positive numbered guardrail version is required")
    return guardrail


def validate_selection(model: ModelCapability | None, effort: Effort | None) -> ModelCapability:
    if model is None:
        raise CapabilityError("model selection is required for judgment")
    validate_model_capability(model)
    if model.efforts and effort is None:
        raise CapabilityError("effort selection is required for this model")
    if effort is not None and effort not in model.efforts:
        raise CapabilityError("selected effort is not supported by this model")
    if not model.efforts and effort is not None:
        raise CapabilityError("selected effort is not supported by this model")
    return model


def validate_embedding_capability(capability: EmbeddingCapability) -> EmbeddingCapability:
    if not capability.validated:
        raise CapabilityError("embedding capability has not passed live validation")
    if (
        not capability.model_id.strip()
        or not capability.region.strip()
        or not capability.resource_arns
    ):
        raise CapabilityError("embedding model, region, and resource allowlist are required")
    if any(not arn.startswith("arn:") for arn in capability.resource_arns):
        raise CapabilityError("embedding capability contains a non-ARN resource")
    if len(set(capability.resource_arns)) != len(capability.resource_arns):
        raise CapabilityError("embedding resource allowlist contains duplicates")
    if capability.dimensions <= 0:
        raise CapabilityError("embedding dimensions must be positive")
    if capability.purpose != "topic_cards" or capability.normalization != "l2":
        raise CapabilityError("only normalized topic-card embeddings are supported")
    if capability.provider_mode not in {"titan_v2", "cohere_v3"}:
        raise CapabilityError("unsupported embedding provider mode")
    expected_modes = (
        ("single_text", "single_text")
        if capability.provider_mode == "titan_v2"
        else ("search_query", "search_document")
    )
    if (capability.query_mode, capability.document_mode) != expected_modes:
        raise CapabilityError("embedding query/document modes do not match provider")
    if not capability.source_vpce.startswith("vpce-"):
        raise CapabilityError("embedding capability requires an approved VPCE identifier")
    if capability.request_bytes <= 0 or capability.max_tokens <= 0:
        raise CapabilityError("embedding request and token bounds must be positive")
    if capability.max_calls_per_question != 1 or capability.requests_per_minute <= 0:
        raise CapabilityError("embedding call and rate policy is outside the supported bounds")
    if capability.validated_at.tzinfo is None or not capability.primary_doc_url.startswith(
        "https://"
    ):
        raise CapabilityError(
            "embedding validation timestamp and primary HTTPS documentation are required"
        )
    validate_guardrail(capability.guardrail)
    return capability


def finite_models(models: Iterable[ModelCapability]) -> tuple[ModelCapability, ...]:
    result = tuple(validate_model_capability(model) for model in models)
    if len({model.id for model in result}) != len(result):
        raise CapabilityError("model capability identifiers must be unique")
    return result
