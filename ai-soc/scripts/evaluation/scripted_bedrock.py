"""Scripted Bedrock client for the offline replay runner: no network and no real model."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, cast

from ai_soc.contracts.canonical import sha256_hex

if TYPE_CHECKING:
    from scripts.evaluation.replay_eval import ScriptBody, ScriptFinding, ScriptSelector

EVIDENCE_PREFIX = "UNTRUSTED TOPIC EVIDENCE DATA:\n"
QUESTION_MARKER = "guardContent"


class ScriptError(RuntimeError):
    """A scripted selector could not be resolved against the request it received."""


def prompt_digest(system: object, messages: object) -> str:
    """Hash one call's system and messages with the frozen question left out."""
    kept: list[dict[str, object]] = []
    for message in cast(list[dict[str, object]], messages):
        parts = cast(list[dict[str, object]], message["content"])
        kept.append({**message, "content": [part for part in parts if QUESTION_MARKER not in part]})
    return sha256_hex({"system": system, "messages": kept})


def _evidence_items(messages: object) -> list[dict[str, object]]:
    first = cast(list[dict[str, object]], messages)[0]
    parts = cast(list[dict[str, object]], first["content"])
    payload = json.loads(str(parts[0]["text"]).removeprefix(EVIDENCE_PREFIX))
    return cast(list[dict[str, object]], payload["items"])


class ScriptedBedrockClient:
    """BedrockClient driven by one scripts.json behaviour, resolved against the live request."""

    def __init__(self, *, case_id: str, script: ScriptBody, count_tokens: int) -> None:
        self._case_id = case_id
        self._script = script
        self._count_tokens = count_tokens
        self.count_calls = 0
        self.converse_calls = 0
        self.prompt_digests: list[str] = []
        self.converse_texts: list[str] = []

    def count_tokens(self, **kwargs: object) -> dict[str, object]:
        self.count_calls += 1
        counted = cast(dict[str, object], kwargs["input"])["converse"]
        counted_map = cast(dict[str, object], counted)
        self.prompt_digests.append(prompt_digest(counted_map["system"], counted_map["messages"]))
        return {"inputTokens": self._count_tokens}

    def converse(self, **kwargs: object) -> dict[str, object]:
        self.converse_calls += 1
        self.prompt_digests.append(prompt_digest(kwargs["system"], kwargs["messages"]))
        script = self._script
        if script.kind == "raise":
            raise RuntimeError(script.message)
        if script.kind == "raw":
            text = script.text
            stop_reason = script.stop_reason
            intervened = script.guardrail_intervened
        else:
            items = _evidence_items(kwargs["messages"])
            findings = [self._finding(spec, items) for spec in script.findings]
            text = json.dumps({"schema_version": "1", "findings": findings})
            stop_reason = script.stop_reason
            intervened = script.guardrail_intervened
        self.converse_texts.append(text)
        return self._response(text, stop_reason, intervened)

    def _finding(self, spec: ScriptFinding, items: list[dict[str, object]]) -> dict[str, object]:
        bindings: dict[str, object] = {}
        evidence_ids: list[str] = []
        for binding_id, binding in spec.bindings.items():
            evidence_id = self._resolve(items, binding.select)
            bindings[binding_id] = {"evidence_id": evidence_id, "field": binding.select.field}
            if evidence_id not in evidence_ids:
                evidence_ids.append(evidence_id)
        return {
            "finding_id": spec.finding_id,
            "kind": spec.kind,
            "template_id": spec.template_id,
            "evidence_ids": evidence_ids,
            "bindings": bindings,
        }

    def _resolve(self, items: list[dict[str, object]], selector: ScriptSelector) -> str:
        for item in items:
            if selector.fetch_id is not None and item.get("fetch_id") != selector.fetch_id:
                continue
            if selector.check_id is not None and item.get("check_id") != selector.check_id:
                continue
            if item.get("kind") != selector.kind:
                continue
            values = cast(dict[str, object], item.get("values", {}))
            if selector.field not in values:
                continue
            return str(item["evidence_id"])
        raise ScriptError(f"{self._case_id}: no evidence item matches {selector!r}")

    def _response(self, text: str, stop_reason: str, intervened: bool) -> dict[str, object]:
        response: dict[str, object] = {
            "output": {"message": {"role": "assistant", "content": [{"text": text}]}},
            "stopReason": stop_reason,
            "usage": {
                "inputTokens": self._count_tokens,
                "outputTokens": 16,
                "cacheReadInputTokens": 0,
                "cacheWriteInputTokens": 0,
            },
            "ResponseMetadata": {"RequestId": f"scripted-{self._case_id}"},
        }
        if intervened:
            response["trace"] = {"guardrail": {"action": "INTERVENED"}}
        return response
