"""LLM provider calls (optional). Routing works without a live model."""
from __future__ import annotations

from typing import Any

from .config import CFG


class LLMConfigError(Exception):
    """Raised when the selected provider is not configured."""


def _missing(provider: str, field: str) -> LLMConfigError:
    return LLMConfigError(
        f"LLM provider '{provider}' is selected but {field} is not set."
    )


def provider_ready() -> bool:
    provider = CFG.llm_provider
    if provider == "openai":
        return bool(CFG.openai_api_key)
    if provider == "gemini":
        return bool(CFG.gemini_api_key)
    if provider == "claude_bedrock":
        return bool(
            CFG.aws_access_key_id
            and CFG.aws_secret_access_key
            and CFG.bedrock_model_id
        )
    if provider == "openai_compatible":
        return bool(CFG.openai_compatible_base_url and CFG.openai_compatible_model)
    return False


def call_llm(prompt: str, system: str | None = None) -> str:
    """Call the configured LLM provider. Raises LLMConfigError when misconfigured."""
    provider = CFG.llm_provider

    if provider == "openai":
        if not CFG.openai_api_key:
            raise _missing(provider, "OPENAI_API_KEY")
        import httpx

        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        resp = httpx.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {CFG.openai_api_key}"},
            json={"model": CFG.openai_model, "messages": messages},
            timeout=120.0,
        )
        resp.raise_for_status()
        data: dict[str, Any] = resp.json()
        return data["choices"][0]["message"]["content"]

    if provider == "gemini":
        if not CFG.gemini_api_key:
            raise _missing(provider, "GEMINI_API_KEY")
        import httpx

        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{CFG.gemini_model}:generateContent?key={CFG.gemini_api_key}"
        )
        resp = httpx.post(
            url,
            json={"contents": [{"parts": [{"text": prompt}]}]},
            timeout=120.0,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]

    if provider == "claude_bedrock":
        if not CFG.aws_access_key_id or not CFG.aws_secret_access_key:
            raise _missing(provider, "AWS credentials")
        if not CFG.bedrock_model_id:
            raise _missing(provider, "BEDROCK_MODEL_ID")
        import json

        import httpx

        url = (
            f"https://bedrock-runtime.{CFG.aws_region}.amazonaws.com/"
            f"model/{CFG.bedrock_model_id}/invoke"
        )
        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}],
        }
        resp = httpx.post(
            url,
            auth=(CFG.aws_access_key_id, CFG.aws_secret_access_key),
            headers={"content-type": "application/json"},
            content=json.dumps(body),
            timeout=120.0,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["content"][0]["text"]

    if provider == "openai_compatible":
        if not CFG.openai_compatible_base_url:
            raise _missing(provider, "OPENAI_COMPATIBLE_BASE_URL")
        if not CFG.openai_compatible_model:
            raise _missing(provider, "OPENAI_COMPATIBLE_MODEL")
        import httpx

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if CFG.openai_compatible_api_key:
            headers["Authorization"] = f"Bearer {CFG.openai_compatible_api_key}"
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        base = CFG.openai_compatible_base_url.rstrip("/")
        resp = httpx.post(
            f"{base}/v1/chat/completions",
            headers=headers,
            json={"model": CFG.openai_compatible_model, "messages": messages},
            timeout=120.0,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]

    raise LLMConfigError(f"Unknown LLM_PROVIDER: {provider}")
