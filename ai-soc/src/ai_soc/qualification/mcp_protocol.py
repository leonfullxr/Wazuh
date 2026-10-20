from __future__ import annotations

import asyncio
import hashlib
import re
import time
from contextlib import AbstractContextManager
from datetime import UTC, datetime
from typing import Any, Protocol

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from pydantic import ValidationError

from ai_soc.contracts.models import Answer, FeedbackReceipt, FetchResult
from ai_soc.qualification.evidence import ProbeEnvelope, emit_probe_envelope
from ai_soc.qualification.mcp_models import (
    DeploymentBinding,
    GateId,
    LvMcpInputs,
    ProbeContractError,
)
from ai_soc.qualification.mcp_oauth import (
    AUTH_NEGATIVES,
    canonical_json,
    discover_auth_metadata,
    origin_header,
    probe_negatives,
    secret_string,
    test_transport,
    verify_access_token,
    verify_id_token,
    verify_negative_tokens,
)

_TOOLS = {"soc_ask", "soc_page", "soc_feedback"}
SUPPORTED_PROTOCOL = "2025-11-25"


class ProbeClientFactory(Protocol):
    fact_requests: list[dict[str, str]]

    def client(self, service_name: str) -> Any: ...

    def fact_scope(self, fact_id: str) -> AbstractContextManager[None]: ...


def _has_untrusted_evidence_instructions(instructions: str) -> bool:
    normalized = " ".join(instructions.lower().split())
    return "untrusted" in normalized and "host-supplied evidence" in normalized


def _answer_matches_binding(answer: Answer, binding: DeploymentBinding) -> bool:
    provenance = answer.provenance
    return (
        provenance.service_sha == binding.service_sha
        and provenance.content_sha == binding.content_sha
        and provenance.image_digest == binding.image_digest
    )


def _answer_parity_payload(answer: Answer) -> dict[str, Any]:
    value = answer.model_dump(mode="json")
    for volatile in ("question_id", "trace_id", "feedback_receipt"):
        value.pop(volatile, None)
    return value


async def _rest_ask(inputs: LvMcpInputs, browser_cookie: str, csrf_token: str) -> Answer:
    async with httpx.AsyncClient(
        timeout=inputs.timeout_seconds,
        trust_env=False,
        follow_redirects=False,
        transport=test_transport(),
    ) as client:
        response = await client.post(
            str(inputs.rest_endpoint),
            json=inputs.ask_request.model_dump(mode="json", exclude_none=True),
            headers={
                "Cookie": browser_cookie,
                "X-CSRF-Token": csrf_token,
                "Origin": origin_header(inputs.origin),
            },
        )
    if response.status_code != 200:
        raise ValueError("REST ask did not return an authenticated answer")
    try:
        return Answer.model_validate_json(response.content)
    except ValidationError as exc:
        raise ProbeContractError("rest_ask", exc) from None


async def run_mcp_protocol_probe(
    *,
    inputs: LvMcpInputs,
    clients: ProbeClientFactory,
    binding: DeploymentBinding,
) -> dict[str, Any]:
    discovery = await discover_auth_metadata(inputs)
    secrets = clients.client("secretsmanager")
    with clients.fact_scope("mcp_official_client_flows"):
        access_token = secret_string(secrets, inputs.access_token_ref)
    with clients.fact_scope("mcp_output_parity"):
        id_token = secret_string(secrets, inputs.id_token_ref)
    browser_cookie = secret_string(secrets, inputs.browser_cookie_ref)
    csrf_token = secret_string(secrets, inputs.csrf_token_ref)
    if not re.fullmatch(
        r"(?:AWSELBAuthSessionCookie-[01]=[^;]+)(?:; AWSELBAuthSessionCookie-[01]=[^;]+)?",
        browser_cookie,
    ):
        raise ValueError("browser cookie reference does not contain an ALB session cookie")
    negative_tokens: dict[str, str] = {}
    for key in AUTH_NEGATIVES:
        if key == "wrong_resource":
            with clients.fact_scope("mcp_auth_negatives"):
                negative_tokens[key] = secret_string(
                    secrets, getattr(inputs.negative_token_refs, key)
                )
        else:
            negative_tokens[key] = secret_string(secrets, getattr(inputs.negative_token_refs, key))
    negative_claims = await verify_negative_tokens(inputs, discovery, negative_tokens)
    id_token_claims = await verify_id_token(inputs, discovery, id_token)
    access_token_claims = await verify_access_token(inputs, discovery, access_token)
    token = access_token
    timeout = httpx.Timeout(inputs.timeout_seconds)
    headers = {
        "Authorization": f"Bearer {token}",
        "Origin": origin_header(inputs.origin),
    }
    async with httpx.AsyncClient(
        timeout=timeout,
        trust_env=False,
        headers=headers,
        transport=test_transport(),
    ) as client:
        async with streamable_http_client(str(inputs.endpoint), http_client=client) as (
            read_stream,
            write_stream,
            _session_id,
        ):
            async with ClientSession(read_stream, write_stream) as session:
                initialized = await session.initialize()
                instructions = initialized.instructions or ""
                if not _has_untrusted_evidence_instructions(instructions):
                    raise ValueError(
                        "MCP initialize instructions omit the untrusted evidence boundary"
                    )
                tools = await session.list_tools()
                listed = {item.name for item in tools.tools}
                if listed != _TOOLS:
                    raise ValueError("MCP tool listing does not match the frozen tool set")
                ask = await session.call_tool(
                    "soc_ask",
                    {
                        "request": inputs.ask_request.model_dump(mode="json", exclude_none=True),
                        "idempotency_key": None,
                    },
                )
                if ask.isError or not isinstance(ask.structuredContent, dict):
                    raise ValueError("soc_ask did not return structured content")
                answer_payload = ask.structuredContent
                page = await session.call_tool(
                    "soc_page", {"request": inputs.page_request.model_dump(mode="json")}
                )
                if page.isError or not isinstance(page.structuredContent, dict):
                    raise ValueError("soc_page did not return structured content")
                feedback = await session.call_tool(
                    "soc_feedback",
                    {
                        "request": {
                            "question_id": str(answer_payload["question_id"]),
                            "environment_id": answer_payload["environment_id"],
                            "feedback_receipt": answer_payload["feedback_receipt"],
                            "kind": "wrong",
                        }
                    },
                )
                if feedback.isError or not isinstance(feedback.structuredContent, dict):
                    raise ValueError("soc_feedback did not return structured content")

        try:
            answer = Answer.model_validate_json(canonical_json(answer_payload))
        except ValidationError as exc:
            raise ProbeContractError("ask", exc) from None
        try:
            page_result = FetchResult.model_validate_json(canonical_json(page.structuredContent))
        except ValidationError as exc:
            raise ProbeContractError("page", exc) from None
        try:
            feedback_result = FeedbackReceipt.model_validate_json(
                canonical_json(feedback.structuredContent)
            )
        except ValidationError as exc:
            raise ProbeContractError("feedback", exc) from None

        provenance_matches = _answer_matches_binding(answer, binding)

        flows = {
            "passed": (
                discovery["passed"] is True
                and initialized.protocolVersion == SUPPORTED_PROTOCOL
                and provenance_matches
            ),
            "deployment_provenance_matches": provenance_matches,
            "synthetic_user_access_token_claims_verified": access_token_claims,
            "protocol_version": initialized.protocolVersion,
            "untrusted_evidence_instructions": True,
            "tools": sorted(listed),
            "ask_sha256": hashlib.sha256(
                canonical_json(answer.model_dump(mode="json"))
            ).hexdigest(),
            "page_sha256": hashlib.sha256(
                canonical_json(page_result.model_dump(mode="json"))
            ).hexdigest(),
            "feedback_sha256": hashlib.sha256(
                canonical_json(feedback_result.model_dump(mode="json"))
            ).hexdigest(),
            "page_request_validated": (
                inputs.page_request.environment_id == page_result.scope.environment_id
            ),
        }
        if not flows["page_request_validated"]:
            raise ValueError("page result environment differs from the requested environment")

    cases = await probe_negatives(inputs, token, negative_tokens, id_token, browser_cookie)
    for name, claim_observation in negative_claims.items():
        cases[name]["token_claims_verified"] = claim_observation
    cases["wrong_type"]["id_token_claims_verified"] = id_token_claims
    rest_answer = await _rest_ask(inputs, browser_cookie, csrf_token)
    parity = {
        "passed": _answer_parity_payload(rest_answer) == _answer_parity_payload(answer),
        "answer_contract": "Answer",
        "page_contract": "FetchResult",
        "feedback_contract": "FeedbackReceipt",
        "rest_answer_sha256": hashlib.sha256(
            canonical_json(_answer_parity_payload(rest_answer))
        ).hexdigest(),
        "mcp_answer_sha256": hashlib.sha256(
            canonical_json(_answer_parity_payload(answer))
        ).hexdigest(),
        "page_sha256": hashlib.sha256(
            canonical_json(page_result.model_dump(mode="json"))
        ).hexdigest(),
        "feedback_sha256": hashlib.sha256(
            canonical_json(feedback_result.model_dump(mode="json"))
        ).hexdigest(),
    }
    return {
        "oauth_discovery": discovery,
        "official_client_flows": flows,
        "mcp_auth_negatives": {"cases": cases},
        "frozen_output_parity": parity,
    }


def run_probe_task_body(
    *,
    inputs: LvMcpInputs,
    clients: ProbeClientFactory,
    binding: DeploymentBinding,
    task_arn: str,
    run_id: str,
    session_id: str,
    invocation_id: str,
    wall_limit_seconds: int = 900,
) -> None:
    if type(wall_limit_seconds) is not int or not 1 <= wall_limit_seconds <= 900:
        raise ValueError("MCP qualification execution budget is invalid")
    deadline = time.monotonic() + wall_limit_seconds
    started = datetime.now(UTC)
    observations = asyncio.run(
        asyncio.wait_for(
            run_mcp_protocol_probe(inputs=inputs, clients=clients, binding=binding),
            timeout=wall_limit_seconds,
        )
    )
    if time.monotonic() >= deadline:
        raise TimeoutError("MCP qualification execution deadline expired")
    completed = datetime.now(UTC)
    scenario = canonical_json(inputs.model_dump(mode="json"))
    envelope = ProbeEnvelope(
        schema_version=1,
        session_id=session_id,
        invocation_id=invocation_id,
        run_id=run_id,
        gate_id=GateId.LV_MCP.value,
        contributor_id="mcp",
        binding=binding,
        scenario_sha256=hashlib.sha256(scenario).hexdigest(),
        started_at=started,
        completed_at=completed,
        measurements={
            **dict(observations),
            "fact_requests": list(clients.fact_requests),
        },
    )
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("MCP qualification execution deadline expired")
    emit_probe_envelope(envelope, timeout_seconds=min(10.0, remaining))
    if time.monotonic() >= deadline:
        raise TimeoutError("MCP qualification execution deadline expired")
