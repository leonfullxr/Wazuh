"""Pluggable inference providers (README s3) with real streaming.

The loop speaks the Bedrock Converse shape everywhere: messages are
[{"role", "content": [{"text"|"toolUse"|"toolResult": ...}]}] and every
provider returns {"output": {"message": ...}, "usage": {"inputTokens",
"outputTokens"}}. Swapping providers changes nothing above this module:
same loop, same tools, same veracity pipeline, same identity chain.

Providers, selected with WAI_LLM_PROVIDER (globally) and the D39 per-tier
overrides:

  bedrock   boto3 Converse/ConverseStream (default). Production semantics:
            the tenant's inference-profile ids, Guardrails attach per
            invocation (D37/D38), optional prompt cachePoint on the system
            prelude (WAI_PROMPT_CACHE, verify the block shape at build time).
  openai    any endpoint speaking the OpenAI chat-completions dialect with
            tool calling: Ollama (local), Groq, LiteLLM, vLLM, LM Studio,
            and the airllm-shim.

Streaming: converse_stream() is an async generator yielding {"text": delta}
events as tokens arrive and one final {"response": <converse shape>}. With
WAI_STREAMING=false, or against a backend that answers plain JSON instead of
an event stream (the airllm shim does), it degrades gracefully to a single
final event, so no backend can break the loop.
"""
from __future__ import annotations

import asyncio
import json
import threading
from typing import Any, AsyncIterator

import anyio
import boto3
import httpx

from . import audit
from .config import CFG


class BedrockProvider:
    """boto3 Converse/ConverseStream, bridged into the async loop."""

    def __init__(self) -> None:
        self.client = boto3.client("bedrock-runtime")  # region from env

    def _kwargs(
        self,
        model_id: str,
        messages: list[dict],
        system: str,
        tool_specs: list[dict],
    ) -> dict[str, Any]:
        system_blocks: list[dict] = [{"text": system}]
        if CFG.prompt_cache:
            # Prompt caching on the static system prelude (verify how cached tokens are billed).
            # verify: cachePoint block shape and model support on your models.
            system_blocks.append({"cachePoint": {"type": "default"}})
        kwargs: dict[str, Any] = {
            "modelId": model_id,
            "messages": messages,
            "system": system_blocks,
            "inferenceConfig": {"maxTokens": CFG.max_output_tokens},
        }
        if tool_specs:
            kwargs["toolConfig"] = {"tools": tool_specs}
        if CFG.guardrail_id:
            kwargs["guardrailConfig"] = {
                "guardrailIdentifier": CFG.guardrail_id,
                "guardrailVersion": CFG.guardrail_version,
            }
        return kwargs

    async def converse(
        self, model_id: str, messages: list[dict], system: str, tool_specs: list[dict]
    ) -> dict:
        kwargs = self._kwargs(model_id, messages, system, tool_specs)
        return await anyio.to_thread.run_sync(lambda: self.client.converse(**kwargs))

    async def converse_stream(
        self, model_id: str, messages: list[dict], system: str, tool_specs: list[dict]
    ) -> AsyncIterator[dict]:
        if not CFG.streaming:
            yield {"response": await self.converse(model_id, messages, system, tool_specs)}
            return

        kwargs = self._kwargs(model_id, messages, system, tool_specs)
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue = asyncio.Queue()

        def worker() -> None:
            try:
                resp = self.client.converse_stream(**kwargs)
                for event in resp["stream"]:
                    loop.call_soon_threadsafe(queue.put_nowait, ("event", event))
                loop.call_soon_threadsafe(queue.put_nowait, ("end", None))
            except Exception as exc:  # surfaced on the async side
                loop.call_soon_threadsafe(queue.put_nowait, ("error", exc))

        threading.Thread(target=worker, daemon=True).start()

        blocks: list[dict] = []
        text_buf: str | None = None
        tool_buf: dict | None = None
        usage = {"inputTokens": 0, "outputTokens": 0}

        while True:
            kind, payload = await queue.get()
            if kind == "error":
                raise payload
            if kind == "end":
                break
            ev = payload
            if "contentBlockStart" in ev:
                start = ev["contentBlockStart"].get("start", {})
                if "toolUse" in start:
                    tool_buf = {
                        "toolUseId": start["toolUse"]["toolUseId"],
                        "name": start["toolUse"]["name"],
                        "_json": "",
                    }
            elif "contentBlockDelta" in ev:
                delta = ev["contentBlockDelta"]["delta"]
                if "text" in delta:
                    text_buf = (text_buf or "") + delta["text"]
                    yield {"text": delta["text"]}
                elif "toolUse" in delta and tool_buf is not None:
                    tool_buf["_json"] += delta["toolUse"].get("input", "")
            elif "contentBlockStop" in ev:
                if tool_buf is not None:
                    try:
                        parsed = json.loads(tool_buf["_json"] or "{}")
                    except json.JSONDecodeError:
                        parsed = {"_malformed_arguments": tool_buf["_json"]}
                    blocks.append(
                        {
                            "toolUse": {
                                "toolUseId": tool_buf["toolUseId"],
                                "name": tool_buf["name"],
                                "input": parsed,
                            }
                        }
                    )
                    tool_buf = None
                elif text_buf is not None:
                    blocks.append({"text": text_buf})
                    text_buf = None
            elif "metadata" in ev:
                u = ev["metadata"].get("usage", {})
                usage = {
                    "inputTokens": u.get("inputTokens", 0),
                    "outputTokens": u.get("outputTokens", 0),
                }

        if text_buf:
            blocks.append({"text": text_buf})
        yield {
            "response": {
                "output": {"message": {"role": "assistant", "content": blocks}},
                "usage": usage,
            }
        }


class OpenAICompatProvider:
    """One adapter for every OpenAI-compatible endpoint. Translates the
    Converse message shape to chat-completions and back, so the loop never
    knows the difference."""

    def __init__(self, base_url: str, api_key: str = "") -> None:
        # Generous read timeout: a 14b model on CPU legitimately takes minutes,
        # and a layer-streamed batch backend (README s3.4) takes longer still.
        self.http = httpx.AsyncClient(timeout=httpx.Timeout(600.0, connect=10.0))
        self.base_url = base_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}

    def _payload(
        self, model_id: str, messages: list[dict], system: str, tool_specs: list[dict]
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": model_id,
            "messages": [{"role": "system", "content": system}]
            + _converse_to_openai(messages),
            "max_tokens": CFG.max_output_tokens,
        }
        if tool_specs:
            payload["tools"] = [_spec_to_openai(s) for s in tool_specs]
        return payload

    async def converse(
        self, model_id: str, messages: list[dict], system: str, tool_specs: list[dict]
    ) -> dict:
        payload = self._payload(model_id, messages, system, tool_specs)
        r = await self.http.post(
            f"{self.base_url}/chat/completions", json=payload, headers=self.headers
        )
        r.raise_for_status()
        return _openai_to_converse(r.json())

    async def converse_stream(
        self, model_id: str, messages: list[dict], system: str, tool_specs: list[dict]
    ) -> AsyncIterator[dict]:
        if not CFG.streaming:
            yield {"response": await self.converse(model_id, messages, system, tool_specs)}
            return

        payload = self._payload(model_id, messages, system, tool_specs)
        payload["stream"] = True
        content_parts: list[str] = []
        tools_by_index: dict[int, dict] = {}
        usage = {"prompt_tokens": 0, "completion_tokens": 0}

        async with self.http.stream(
            "POST",
            f"{self.base_url}/chat/completions",
            json=payload,
            headers=self.headers,
        ) as r:
            ctype = r.headers.get("content-type", "")
            if r.status_code != 200 or not ctype.startswith("text/event-stream"):
                # Backend cannot stream (the airllm shim answers plain JSON):
                # degrade to one final event instead of failing the turn.
                body = await r.aread()
                r.raise_for_status()
                yield {"response": _openai_to_converse(json.loads(body))}
                return
            async for line in r.aiter_lines():
                if not line or not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    break
                chunk = json.loads(data)
                if chunk.get("usage"):
                    usage = chunk["usage"]
                choices = chunk.get("choices") or []
                if not choices:
                    continue
                delta = choices[0].get("delta") or {}
                if delta.get("content"):
                    content_parts.append(delta["content"])
                    yield {"text": delta["content"]}
                for tc in delta.get("tool_calls") or []:
                    slot = tools_by_index.setdefault(
                        tc.get("index", 0), {"id": None, "name": "", "args": ""}
                    )
                    if tc.get("id"):
                        slot["id"] = tc["id"]
                    fn = tc.get("function") or {}
                    if fn.get("name"):
                        slot["name"] += fn["name"]
                    if fn.get("arguments"):
                        slot["args"] += fn["arguments"]

        content: list[dict] = []
        text = "".join(content_parts)
        if text:
            content.append({"text": text})
        for i in sorted(tools_by_index):
            slot = tools_by_index[i]
            try:
                args = json.loads(slot["args"] or "{}")
            except json.JSONDecodeError:
                args = {"_malformed_arguments": slot["args"]}
            content.append(
                {
                    "toolUse": {
                        "toolUseId": slot["id"] or f"call_{i}",
                        "name": slot["name"],
                        "input": args,
                    }
                }
            )
        yield {
            "response": {
                "output": {"message": {"role": "assistant", "content": content}},
                "usage": {
                    "inputTokens": usage.get("prompt_tokens", 0),
                    "outputTokens": usage.get("completion_tokens", 0),
                },
            }
        }


# ---------------------------------------------------------------------------
# Converse <-> chat-completions translation
# ---------------------------------------------------------------------------
def _spec_to_openai(spec: dict) -> dict:
    ts = spec["toolSpec"]
    return {
        "type": "function",
        "function": {
            "name": ts["name"],
            "description": ts["description"],
            "parameters": ts["inputSchema"]["json"],
        },
    }


def _converse_to_openai(messages: list[dict]) -> list[dict]:
    out: list[dict] = []
    for m in messages:
        texts, tool_uses, tool_results = [], [], []
        for block in m["content"]:
            if "text" in block:
                texts.append(block["text"])
            elif "toolUse" in block:
                tool_uses.append(block["toolUse"])
            elif "toolResult" in block:
                tool_results.append(block["toolResult"])

        if m["role"] == "assistant":
            msg: dict[str, Any] = {
                "role": "assistant",
                "content": "\n".join(texts) or None,
            }
            if tool_uses:
                msg["tool_calls"] = [
                    {
                        "id": tu["toolUseId"],
                        "type": "function",
                        "function": {
                            "name": tu["name"],
                            "arguments": json.dumps(tu["input"]),
                        },
                    }
                    for tu in tool_uses
                ]
            out.append(msg)
        else:
            for tr in tool_results:
                parts = []
                for c in tr["content"]:
                    if "json" in c:
                        parts.append(json.dumps(c["json"], default=str))
                    elif "text" in c:
                        parts.append(c["text"])
                out.append(
                    {
                        "role": "tool",
                        "tool_call_id": tr["toolUseId"],
                        "content": "\n".join(parts),
                    }
                )
            if texts:
                out.append({"role": "user", "content": "\n".join(texts)})
    return out


def _openai_to_converse(resp: dict) -> dict:
    msg = resp["choices"][0]["message"]
    content: list[dict] = []
    if msg.get("content"):
        content.append({"text": msg["content"]})
    for i, tc in enumerate(msg.get("tool_calls") or []):
        raw_args = tc["function"].get("arguments") or "{}"
        try:
            args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
        except json.JSONDecodeError:
            args = {"_malformed_arguments": raw_args}
        content.append(
            {
                "toolUse": {
                    "toolUseId": tc.get("id") or f"call_{i}",
                    "name": tc["function"]["name"],
                    "input": args,
                }
            }
        )
    usage = resp.get("usage") or {}
    return {
        "output": {"message": {"role": "assistant", "content": content}},
        "usage": {
            "inputTokens": usage.get("prompt_tokens", 0),
            "outputTokens": usage.get("completion_tokens", 0),
        },
    }


_bedrock_singleton: BedrockProvider | None = None


def _make_provider(provider: str, base_url: str, api_key: str):
    global _bedrock_singleton
    if provider == "openai":
        if CFG.guardrail_id:
            audit.emit(
                "guardrail_ignored",
                reason="Bedrock Guardrails do not apply on the openai provider",
            )
        return OpenAICompatProvider(base_url, api_key)
    if _bedrock_singleton is None:
        _bedrock_singleton = BedrockProvider()
    return _bedrock_singleton


# Per-tier bindings (D39): empty per-tier settings inherit the globals, so a
# single-backend deployment configures nothing new, while a split deployment
# routes on one endpoint and analyzes on another.
ROUTER_LLM = _make_provider(
    CFG.router_provider or CFG.llm_provider,
    CFG.router_base_url or CFG.llm_base_url,
    CFG.router_api_key or CFG.llm_api_key,
)
ANALYSIS_LLM = _make_provider(
    CFG.analysis_provider or CFG.llm_provider,
    CFG.analysis_base_url or CFG.llm_base_url,
    CFG.analysis_api_key or CFG.llm_api_key,
)
