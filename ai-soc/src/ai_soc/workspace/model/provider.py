"""Tool-free provider boundary for workspace assessments."""

from __future__ import annotations

import asyncio
import json
import math
import os
import stat
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Protocol, cast
from urllib.parse import urlsplit

import httpx

UnavailableReason = Literal["credential", "timeout", "transport", "http_status", "rate_limit"]
InvalidReason = Literal["response_size", "response_format"]


class ProviderUnavailable(Exception):
    """A provider call could not be made; the reason contains no provider data."""

    def __init__(self, reason: UnavailableReason) -> None:
        if reason not in {"credential", "timeout", "transport", "http_status", "rate_limit"}:
            raise ValueError("invalid provider unavailable reason")
        self.reason = reason
        super().__init__(reason)


class ProviderInvalidResponse(Exception):
    """The provider envelope could not safely yield a complete response."""

    def __init__(self, reason: InvalidReason) -> None:
        if reason not in {"response_size", "response_format"}:
            raise ValueError("invalid provider response reason")
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class ProviderResult:
    raw_json: bytes
    input_tokens: int | None
    output_tokens: int | None
    latency_ms: int


class AssessmentProvider(Protocol):
    provider_id: str
    model_id: str

    def complete(self, prompt: bytes, output_schema: Mapping[str, object]) -> ProviderResult: ...


class ScriptedProvider:
    def __init__(
        self,
        callback: Callable[[bytes, Mapping[str, object]], ProviderResult],
        *,
        provider_id: str = "scripted",
        model_id: str = "scripted",
    ) -> None:
        self.provider_id = provider_id
        self.model_id = model_id
        self._callback = callback

    def complete(self, prompt: bytes, output_schema: Mapping[str, object]) -> ProviderResult:
        return self._callback(prompt, output_schema)


class OpenAICompatibleProvider:
    """Chat completions adapter; the caller validates the returned JSON content."""

    def __init__(
        self,
        base_url: str,
        model_id: str,
        credential_file: str | Path | None,
        *,
        provider_id: str = "openai-compatible",
        timeout_seconds: float = 30.0,
        max_response_bytes: int = 1_048_576,
    ) -> None:
        parsed = urlsplit(base_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or (
                parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
            )
        ):
            raise ValueError("invalid provider base URL")
        if credential_file is None and (
            parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1"}
        ):
            raise ValueError("provider credentials may be omitted only for HTTP loopback")
        if not model_id or not provider_id:
            raise ValueError("provider and model IDs are required")
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0 or max_response_bytes <= 0:
            raise ValueError("invalid provider bounds")
        self.provider_id = provider_id
        self.model_id = model_id
        self._url = base_url.rstrip("/") + "/chat/completions"
        self._credential_file = Path(credential_file) if credential_file is not None else None
        self._timeout = timeout_seconds
        self._max_response_bytes = max_response_bytes

    def _bearer_key(self) -> str | None:
        if self._credential_file is None:
            return None
        try:
            fd = os.open(self._credential_file, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as credential_file:
                mode = os.fstat(credential_file.fileno()).st_mode
                if not stat.S_ISREG(mode) or mode & 0o077:
                    raise ValueError
                credential = credential_file.read(16_385)
            if len(credential) > 16_384:
                raise ValueError
            key = credential.decode("utf-8").strip()
            if not key or any(ord(char) < 33 or ord(char) > 126 for char in key):
                raise ValueError
            return key
        except (OSError, UnicodeError, ValueError):
            raise ProviderUnavailable("credential") from None

    def validate_credentials(self) -> None:
        """Check the configured credential locally before submitting any evidence."""
        self._bearer_key()

    def complete(self, prompt: bytes, output_schema: Mapping[str, object]) -> ProviderResult:
        start = time.monotonic()
        key = self._bearer_key()
        body: dict[str, object] = {
            "model": self.model_id,
            "messages": [{"role": "user", "content": prompt.decode("utf-8")}],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "assessment", "strict": True, "schema": output_schema},
            },
        }
        # A separate daemon thread permits a synchronous interface even inside an event loop.
        # The waiting thread enforces a wall-clock deadline, including DNS resolution.
        result: list[ProviderResult | ProviderUnavailable | ProviderInvalidResponse] = []
        done = threading.Event()

        def run() -> None:
            try:
                result.append(asyncio.run(self._request(body, key, start)))
            except (ProviderUnavailable, ProviderInvalidResponse) as exc:
                result.append(exc)
            except Exception:
                result.append(ProviderUnavailable("transport"))
            finally:
                done.set()

        threading.Thread(target=run, daemon=True).start()
        remaining = max(0.0, self._timeout - (time.monotonic() - start))
        if not done.wait(remaining):
            raise ProviderUnavailable("timeout")
        if not result:
            raise ProviderUnavailable("transport")
        outcome = result[0]
        if isinstance(outcome, (ProviderUnavailable, ProviderInvalidResponse)):
            raise outcome from None
        return outcome

    async def _request(
        self, body: dict[str, object], key: str | None, start: float
    ) -> ProviderResult:
        headers = {"Accept-Encoding": "identity"}
        if key is not None:
            headers["Authorization"] = f"Bearer {key}"
        try:
            async with asyncio.timeout(max(0.0, self._timeout - (time.monotonic() - start))):
                async with httpx.AsyncClient(
                    verify=True, trust_env=False, follow_redirects=False, timeout=self._timeout
                ) as client:
                    async with client.stream(
                        "POST",
                        self._url,
                        json=body,
                        headers=headers,
                    ) as response:
                        if response.status_code == 429:
                            raise ProviderUnavailable("rate_limit")
                        if response.status_code != 200:
                            raise ProviderUnavailable("http_status")
                        encoding = response.headers.get("content-encoding", "identity").lower()
                        if encoding != "identity":
                            raise ProviderInvalidResponse("response_format")
                        content = bytearray()
                        async for chunk in response.aiter_raw():
                            content.extend(chunk)
                            if len(content) > self._max_response_bytes:
                                raise ProviderInvalidResponse("response_size")
        except (TimeoutError, httpx.TimeoutException):
            raise ProviderUnavailable("timeout") from None
        except httpx.HTTPError:
            raise ProviderUnavailable("transport") from None
        try:
            envelope = cast(dict[str, Any], json.loads(content))
            choices: object = envelope["choices"]
            if not isinstance(choices, list):
                raise ValueError
            choice_list = cast(list[Any], choices)
            if len(choice_list) != 1:
                raise ValueError
            choice = cast(dict[str, Any], choice_list[0])
            message = cast(dict[str, Any], choice["message"])
            text = message["content"]
            if (
                choice["finish_reason"] != "stop"
                or not isinstance(text, str)
                or message.get("refusal")
                or message.get("tool_calls")
            ):
                raise ValueError
            usage = envelope.get("usage")
            input_tokens = _usage(usage, "prompt_tokens")
            output_tokens = _usage(usage, "completion_tokens")
            raw_json = text.encode("utf-8")
        except (
            AttributeError,
            KeyError,
            TypeError,
            ValueError,
            UnicodeError,
            json.JSONDecodeError,
        ):
            raise ProviderInvalidResponse("response_format") from None
        return ProviderResult(
            raw_json, input_tokens, output_tokens, int((time.monotonic() - start) * 1000)
        )


def _usage(usage: object, field: str) -> int | None:
    if usage is None:
        return None
    if not isinstance(usage, dict):
        raise ValueError
    value = cast(dict[str, Any], usage).get(field)
    if value is not None and (type(value) is not int or not 0 <= value < (1 << 63)):
        raise ValueError
    return value
