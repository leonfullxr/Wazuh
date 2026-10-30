"""Killable, fixed-destination HTTPS transport used by the local CLI broker."""

from __future__ import annotations

import base64
import http.client
import json
import signal
import sys
from types import FrameType
from typing import Any, cast

HOST = "chatgpt.com"
PATH = "/backend-api/codex/responses"
MAX_REQUEST = 1_200_000
MAX_RESPONSE = 1_000_000


def _wall_timeout(_signal: int, _frame: FrameType | None) -> None:
    raise SystemExit(3)


def main() -> int:
    # Independent of the guardian: a slowly progressing peer cannot keep the slot forever.
    signal.signal(signal.SIGALRM, _wall_timeout)
    signal.setitimer(signal.ITIMER_REAL, 25.0)
    raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
    if len(raw) > MAX_REQUEST:
        return 2
    try:
        envelope = json.loads(raw)
        if not isinstance(envelope, dict):
            return 2
        value = cast(dict[str, Any], envelope)
        request_body = base64.b64decode(value["body"], validate=True)
        auth_headers_value = value["headers"]
        if not isinstance(auth_headers_value, dict):
            return 2
        headers = cast(dict[str, Any], auth_headers_value)
        if set(headers) != {
            "Authorization",
            "ChatGPT-Account-ID",
        }:
            return 2
        authorization = headers["Authorization"]
        account_id = headers["ChatGPT-Account-ID"]
        if (
            not isinstance(authorization, str)
            or not authorization.startswith("Bearer ")
            or len(authorization) > 8200
            or not isinstance(account_id, str)
            or not account_id
            or len(account_id) > 256
        ):
            return 2
    except (KeyError, TypeError, ValueError):
        return 2

    connection = http.client.HTTPSConnection(HOST, timeout=20, context=None)
    try:
        connection.request(
            "POST",
            PATH,
            body=request_body,
            headers={
                "Authorization": authorization,
                "ChatGPT-Account-ID": account_id,
                "Content-Type": "application/json",
                "Accept": "text/event-stream",
                "originator": "codex_exec",
                "x-openai-internal-codex-responses-lite": "true",
            },
        )
        response = connection.getresponse()
        body = response.read(MAX_RESPONSE + 1)
        if len(body) > MAX_RESPONSE:
            status = 502
            body = b""
        else:
            status = response.status
        result = json.dumps(
            {"status": status, "body": base64.b64encode(body).decode("ascii")},
            separators=(",", ":"),
        ).encode()
        sys.stdout.buffer.write(result)
        return 0
    except (OSError, http.client.HTTPException):
        return 3
    finally:
        connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
