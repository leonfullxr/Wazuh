"""One-call Codex adapter for validated frozen incident narratives."""

from __future__ import annotations

import hashlib
import json
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID

from ai_soc.workspace.model.cli_broker import BrokerFailure, InferenceBroker, Transport
from ai_soc.workspace.model.cli_process import ProcessFailure, run_bounded
from ai_soc.workspace.model.cli_profile import (
    CodexProfile,
    ProfileError,
    ProfileProvenance,
)
from ai_soc.workspace.model.schemas import (
    FrozenIncidentPack,
    ValidatedNarrative,
    narrative_output_json_schema,
)
from ai_soc.workspace.model.validation import validate_incident_narrative

if TYPE_CHECKING:
    from ai_soc.workspace.model.bundle import FrozenExecution


@dataclass(frozen=True, slots=True)
class TokenUsage:
    input_tokens: int | None
    cached_input_tokens: int | None
    output_tokens: int | None


@dataclass(frozen=True, slots=True)
class GenerationRequest:
    pack: FrozenIncidentPack
    expected_site_id: str
    expected_incident_id: UUID
    expected_revision_id: UUID


@dataclass(frozen=True, slots=True)
class GenerationProvenance:
    profile: ProfileProvenance
    request_sha256: str
    schema_sha256: str
    stdout_sha256: str
    stderr_sha256: str
    stdout_truncated: bool = False
    stderr_truncated: bool = False


@dataclass(frozen=True, slots=True)
class GenerationResult:
    narrative: ValidatedNarrative
    usage: TokenUsage
    provenance: GenerationProvenance


UNKNOWN_USAGE = TokenUsage(None, None, None)


class ProviderUnavailable(RuntimeError):
    """Safe static provider failure, with no model or process text retained."""

    def __init__(
        self,
        code: str,
        *,
        provenance: GenerationProvenance | None = None,
        usage: TokenUsage = UNKNOWN_USAGE,
    ):
        super().__init__(code)
        self.code = code
        self.provenance = provenance
        self.usage = usage


class CodexCLIProvider:
    """Runs exactly one physical call through the qualified restricted profile."""

    def __init__(
        self, profile: CodexProfile | None = None, *, broker_transport: Transport | None = None
    ):
        self.profile = profile or CodexProfile()
        self.broker_transport = broker_transport

    def generate(
        self,
        request: GenerationRequest,
        *,
        frozen: FrozenExecution | None = None,
        slot_fds: tuple[int, ...] = (),
        cancel_event: threading.Event | None = None,
    ) -> GenerationResult:
        try:
            profile_provenance = self.profile.verify()
        except ProfileError as error:
            raise ProviderUnavailable(error.args[0]) from None
        if (
            request.pack.site_id != request.expected_site_id
            or request.pack.incident_id != request.expected_incident_id
            or request.pack.incident_revision_id != request.expected_revision_id
        ):
            raise ProviderUnavailable("request_identity_mismatch")
        payload = _request_payload(request.pack)
        schema = _canonical_json(provider_wire_schema())
        prompt = (
            b"Frozen incident evidence JSON follows. Return only the schema-conforming "
            b"JSON object.\n" + payload
        )
        if frozen is not None:
            prompt, schema = frozen.prompt, frozen.schema
            if prompt != (
                b"Frozen incident evidence JSON follows. Return only the schema-conforming "
                b"JSON object.\n" + payload
            ):
                raise ProviderUnavailable("request_identity_mismatch")
        request_hash = hashlib.sha256(prompt).hexdigest()
        schema_hash = hashlib.sha256(schema).hexdigest()
        temp_parent: Path | None = None
        try:
            temp_parent = Path(tempfile.mkdtemp(prefix="ai-soc-codex-"))
            input_dir = temp_parent / "inputs"
            inputs = (
                self.profile.prepare_inputs(input_dir, prompt, schema)
                if frozen is None
                else self.profile.prepare_inputs(
                    input_dir,
                    prompt,
                    schema,
                    instructions=frozen.instructions,
                    catalog=frozen.catalog,
                )
            )
            argv = (
                self.profile.argv(inputs)
                if not slot_fds
                else self.profile.argv(inputs, slot_fds=slot_fds)
            )
            if self.broker_transport is None:
                broker_context = InferenceBroker(
                    schema,
                    auth_path=self.profile.auth_path,
                    auth_deadline_seconds=self.profile.timeout_seconds,
                    pass_fds=slot_fds,
                )
            else:
                broker_context = InferenceBroker(schema, self.broker_transport)
            with broker_context as broker:
                broker_url_config = f'model_providers.ai_soc_workspace.base_url="{broker.base_url}"'
                argv = (*argv[:-1], "-c", broker_url_config, argv[-1])
                process_options: dict[str, Any] = {}
                if slot_fds:
                    process_options["pass_fds"] = slot_fds
                if cancel_event is not None:
                    process_options["cancel_event"] = cancel_event
                try:
                    capture = run_bounded(
                        argv,
                        prompt,
                        timeout_seconds=self.profile.timeout_seconds,
                        stdout_limit=self.profile.stdout_limit,
                        stderr_limit=self.profile.stderr_limit,
                        stdin_limit=self.profile.stdin_limit,
                        **process_options,
                    )
                except ProcessFailure as error:
                    failed_provenance = GenerationProvenance(
                        profile_provenance,
                        request_hash,
                        schema_hash,
                        error.stdout_sha256,
                        error.stderr_sha256,
                        error.stdout_truncated,
                        error.stderr_truncated,
                    )
                    raise ProviderUnavailable(
                        error.code,
                        provenance=failed_provenance,
                        usage=TokenUsage(
                            broker.receipt.input_tokens,
                            broker.receipt.cached_input_tokens,
                            broker.receipt.output_tokens,
                        ),
                    ) from None
                receipt = broker.receipt
            provenance = GenerationProvenance(
                profile_provenance,
                request_hash,
                schema_hash,
                capture.stdout_sha256,
                capture.stderr_sha256,
            )
            parse_error: ValueError | None = None
            final_json = b""
            usage = TokenUsage(
                receipt.input_tokens, receipt.cached_input_tokens, receipt.output_tokens
            )
            try:
                final_json, _cli_usage = parse_codex_jsonl(capture.stdout)
            except ValueError as error:
                parse_error = error
            if receipt.reason == "account_limit" or (
                parse_error is not None and str(parse_error) == "account_limit"
            ):
                raise ProviderUnavailable(
                    "account_limit", provenance=provenance, usage=usage
                ) from None
            if receipt.reason == "upstream_tool_event_rejected" or receipt.requests > 1:
                raise ProviderUnavailable("tool_attempt", provenance=provenance, usage=usage)
            if receipt.reason == "upstream_auth_rejected":
                raise ProviderUnavailable("auth_rejected", provenance=provenance, usage=usage)
            if receipt.reason == "upstream_rate_limited":
                raise ProviderUnavailable("rate_limited", provenance=provenance, usage=usage)
            if receipt.reason in {
                "upstream_transport_failed",
                "upstream_timeout",
                "upstream_server_error",
            }:
                raise ProviderUnavailable(receipt.reason, provenance=provenance, usage=usage)
            if capture.returncode != 0:
                raise ProviderUnavailable(
                    "process_exit_nonzero", provenance=provenance, usage=usage
                )
            if not receipt.accepted:
                raise ProviderUnavailable(receipt.reason, provenance=provenance, usage=usage)
            if receipt.requests != 1:
                raise ProviderUnavailable(
                    "inference_request_count_invalid", provenance=provenance, usage=usage
                )
            if parse_error is not None:
                raise ProviderUnavailable(
                    str(parse_error), provenance=provenance, usage=usage
                ) from None
            narrative = validate_incident_narrative(
                final_json,
                expected_site_id=request.expected_site_id,
                expected_incident_id=request.expected_incident_id,
                expected_revision_id=request.expected_revision_id,
                pack=request.pack,
            )
            if narrative.status == "invalid_structure":
                raise ProviderUnavailable(
                    "invalid_structured_output", provenance=provenance, usage=usage
                )
            return GenerationResult(narrative, usage, provenance)
        except ProfileError as error:
            raise ProviderUnavailable(error.args[0]) from None
        except BrokerFailure as error:
            raise ProviderUnavailable(error.code) from None
        except OSError:
            raise ProviderUnavailable("temporary_storage_unavailable") from None
        finally:
            if temp_parent is not None:
                import shutil

                shutil.rmtree(temp_parent, ignore_errors=True)


def parse_codex_jsonl(raw: bytes) -> tuple[bytes, TokenUsage]:
    """Require clean Codex JSONL with one final agent message and completed usage."""
    if not raw or len(raw) > 262144:
        raise ValueError("invalid_provider_output")
    messages: list[bytes] = []
    completed = False
    usage: TokenUsage | None = None
    try:
        lines = raw.splitlines()
        if not lines or len(lines) > 256:
            raise ValueError
        for line in lines:
            if not line:
                continue
            decoded: object = json.loads(
                line, object_pairs_hook=_unique_pairs, parse_constant=_reject_constant
            )
            if not isinstance(decoded, dict):
                raise ValueError
            event = cast(dict[str, Any], decoded)
            if not isinstance(event.get("type"), str):
                raise ValueError
            kind = event["type"]
            if completed:
                raise ValueError
            if kind in {"turn.failed", "error", "model_error"}:
                error_data = event.get("error", event.get("message"))
                if _is_account_limit(error_data):
                    raise ValueError("account_limit")
                raise ValueError("provider_unavailable")
            if kind == "item.completed":
                item_value = event.get("item")
                if not isinstance(item_value, dict):
                    raise ValueError
                item = cast(dict[str, Any], item_value)
                item_type = item.get("type")
                if item_type != "agent_message":
                    raise ValueError("provider_tool_event")
                text = item.get("text")
                if not isinstance(text, str):
                    raise ValueError
                messages.append(text.encode("utf-8"))
            elif kind == "item.started":
                item_value = event.get("item")
                if not isinstance(item_value, dict):
                    raise ValueError("provider_tool_event")
                item = cast(dict[str, Any], item_value)
                if item.get("type") != "agent_message":
                    raise ValueError("provider_tool_event")
            elif kind == "turn.completed":
                if completed:
                    raise ValueError
                completed = True
                usage = _usage(event.get("usage"))
            elif kind == "item.updated":
                item_value = event.get("item")
                if not isinstance(item_value, dict):
                    raise ValueError("provider_tool_event")
                item = cast(dict[str, Any], item_value)
                if item.get("type") != "agent_message":
                    raise ValueError("provider_tool_event")
            elif kind not in {"thread.started", "turn.started"}:
                raise ValueError("provider_event_rejected")
        if not completed or len(messages) != 1:
            raise ValueError
        return messages[0], usage or TokenUsage(None, None, None)
    except ValueError as error:
        message = str(error)
        if message in {
            "account_limit",
            "provider_unavailable",
            "provider_tool_event",
            "provider_event_rejected",
        }:
            raise
        raise ValueError("invalid_provider_output") from None
    except (TypeError, UnicodeError, RecursionError):
        raise ValueError("invalid_provider_output") from None


def _usage(data: object) -> TokenUsage | None:
    if data is None:
        return None
    if not isinstance(data, dict):
        raise ValueError
    data = cast(dict[str, Any], data)
    fields = ("input_tokens", "cached_input_tokens", "output_tokens")
    result: list[int | None] = []
    for key in fields:
        value = data.get(key)
        if value is not None and (type(value) is not int or value < 0):
            raise ValueError
        result.append(value)
    if not any(value is not None for value in result):
        return None
    return TokenUsage(*result)


def _request_payload(pack: FrozenIncidentPack) -> bytes:
    return pack.canonical_bytes()


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite number")


def _is_account_limit(value: object) -> bool:
    if isinstance(value, dict):
        typed = cast(dict[str, Any], value)
        for key, item in typed.items():
            if key in {"code", "type", "message", "codexErrorInfo"} and _is_account_limit(item):
                return True
            if key == "codexErrorInfo" and isinstance(item, str):
                if "usage limit" in item.lower() or "spend limit" in item.lower():
                    return True
        return False
    if isinstance(value, str):
        normalized = value.lower().replace("_", " ").replace("-", " ")
        return "usage limit" in normalized or "spend limit" in normalized
    if isinstance(value, list):
        return any(_is_account_limit(item) for item in cast(list[Any], value))
    return False


def select_cli_provider(name: str, profile: CodexProfile | None = None) -> CodexCLIProvider:
    """Return the qualified provider; other local CLIs remain explicitly unsupported."""
    if name != "codex":
        raise ProviderUnavailable("provider_unsupported")
    return CodexCLIProvider(profile)


def provider_wire_schema() -> dict[str, Any]:
    """Normalize Pydantic's discriminated union for the strict Responses schema subset."""
    source = narrative_output_json_schema()
    normalized = _normalize_schema(source)
    if not isinstance(normalized, dict):
        raise ProviderUnavailable("schema_invalid")
    return cast(dict[str, Any], normalized)


def _normalize_schema(value: object) -> object:
    if isinstance(value, dict):
        source = cast(dict[str, Any], value)
        result: dict[str, Any] = {}
        for key, item in source.items():
            if key == "discriminator":
                continue
            result["anyOf" if key == "oneOf" else key] = _normalize_schema(item)
        return result
    if isinstance(value, list):
        return [_normalize_schema(item) for item in cast(list[Any], value)]
    return value
