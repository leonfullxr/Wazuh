"""One-inference loopback broker for the pinned Codex CLI invocation."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast

from ai_soc.workspace.model.cli_credentials import (
    BrokerCredentials,
    CredentialError,
    load_credentials,
)
from ai_soc.workspace.model.cli_profile import MODEL_ID

MAX_REQUEST_BYTES = 1_200_000
MAX_RESPONSE_BYTES = 1_000_000
UPSTREAM_TIMEOUT_SECONDS = 25.0
LOCAL_REQUEST_TIMEOUT_SECONDS = 10.0
MAX_BROKER_HANDLER_THREADS = 4

Transport = Callable[[bytes, dict[str, str]], tuple[int, bytes]]


class _BoundedHTTPServer(ThreadingHTTPServer):
    """Bound handler threads and close accepted sockets before joining them."""

    def __init__(self, server_address: tuple[str, int], handler: type[BaseHTTPRequestHandler]):
        self._worker_slots = threading.BoundedSemaphore(MAX_BROKER_HANDLER_THREADS)
        self._active_lock = threading.Lock()
        self._active_sockets: set[socket.socket] = set()
        super().__init__(server_address, handler)
        self.daemon_threads = False
        self.block_on_close = True

    def get_request(self) -> tuple[socket.socket, tuple[str, int]]:
        request, client_address = super().get_request()
        request.settimeout(LOCAL_REQUEST_TIMEOUT_SECONDS)
        with self._active_lock:
            self._active_sockets.add(request)
        return request, cast(tuple[str, int], client_address)

    def process_request(self, request: Any, client_address: tuple[str, int]) -> None:
        if not self._worker_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._worker_slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: tuple[str, int]) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._worker_slots.release()

    def shutdown_request(self, request: Any) -> None:
        request_socket = cast(socket.socket, request)
        with self._active_lock:
            self._active_sockets.discard(request_socket)
        super().shutdown_request(request)

    def close_active_requests(self) -> None:
        with self._active_lock:
            sockets = tuple(self._active_sockets)
        for request in sockets:
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            request.close()


@dataclass(frozen=True, slots=True)
class BrokerReceipt:
    requests: int
    accepted: bool
    reason: str
    response_sha256: str
    input_tokens: int | None
    cached_input_tokens: int | None
    output_tokens: int | None


class BrokerFailure(RuntimeError):
    """Static broker failure without request, response, or authentication text."""

    def __init__(
        self, code: str, *, usage: tuple[int | None, int | None, int | None] = (None, None, None)
    ):
        super().__init__(code)
        self.code = code
        self.usage = usage


class InferenceBroker:
    """Serves one local CLI POST and releases only a validated complete SSE reply."""

    def __init__(
        self,
        expected_schema: bytes,
        transport: Transport | None = None,
        *,
        auth_path: str | None = None,
        auth_deadline_seconds: float = 120.0,
        credentials: BrokerCredentials | None = None,
        pass_fds: tuple[int, ...] = (),
    ):
        self._expected_schema = _decode_json(expected_schema)
        self._credentials = credentials
        if self._credentials is None and auth_path is not None:
            try:
                self._credentials = load_credentials(
                    auth_path, deadline_seconds=auth_deadline_seconds
                )
            except CredentialError as error:
                raise BrokerFailure(error.code) from None
        self._test_without_credentials = (
            transport is not None and credentials is None and auth_path is None
        )
        self._transport = (
            transport if transport is not None else _BoundedHTTPSTransport(pass_fds=pass_fds)
        )
        self._lock = threading.Lock()
        self._requests = 0
        self._capability = secrets.token_urlsafe(32)
        self._receipt = BrokerReceipt(0, False, "no_inference_request", "", None, None, None)
        broker = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: object) -> None:
                del format, args
                return

            def do_POST(self) -> None:
                broker._handle(self)

            def do_GET(self) -> None:
                self.send_error(404)

        self._server = _BoundedHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = False
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        host, port = cast(tuple[str, int], self._server.server_address)
        return f"http://{host}:{port}/v1/{self._capability}"

    @property
    def receipt(self) -> BrokerReceipt:
        with self._lock:
            return self._receipt

    def start(self) -> InferenceBroker:
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def close(self) -> None:
        cancel = getattr(self._transport, "cancel", None)
        if callable(cancel):
            cancel()
        self._server.shutdown()
        self._server.close_active_requests()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None

    def __enter__(self) -> InferenceBroker:
        return self.start()

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _handle(self, handler: BaseHTTPRequestHandler) -> None:
        # Spend the one-shot permit before inspecting or forwarding any request.
        with self._lock:
            self._requests += 1
            request_number = self._requests
            previous = self._receipt
            self._receipt = BrokerReceipt(
                request_number,
                False,
                "request_rejected",
                previous.response_sha256,
                previous.input_tokens,
                previous.cached_input_tokens,
                previous.output_tokens,
            )
        if request_number != 1:
            self._reply(handler, 409, b"")
            return
        if handler.path != f"/v1/{self._capability}/responses" or handler.command != "POST":
            self._record(False, "request_target_rejected")
            self._reply(handler, 404, b"")
            return
        length = handler.headers.get("Content-Length")
        if length is None or not length.isdecimal() or int(length) > MAX_REQUEST_BYTES:
            self._record(False, "request_size_rejected")
            self._reply(handler, 413, b"")
            return
        try:
            body = handler.rfile.read(int(length))
            if "Authorization" in handler.headers or "ChatGPT-Account-ID" in handler.headers:
                raise ValueError
            request = _decode_json(body)
            _validate_request(request, self._expected_schema)
        except (ValueError, UnicodeError, RecursionError):
            self._record(False, "request_contract_rejected")
            self._reply(handler, 400, b"")
            return
        try:
            if self._credentials is None and not self._test_without_credentials:
                self._record(False, "auth_unavailable")
                self._reply(handler, 502, b"")
                return
            auth_headers = self._credentials.headers if self._credentials is not None else {}
            status, upstream_body = self._transport(body, auth_headers)
            if status != 200:
                reason = _classify_upstream_failure(status, upstream_body)
                self._record(False, reason)
                self._reply(handler, 502, b"")
                return
            usage = _validate_sse(upstream_body)
        except BrokerFailure as error:
            self._record(False, error.code, usage=error.usage)
            self._reply(handler, 502, b"")
            return
        except BaseException:
            self._record(False, "upstream_transport_failed")
            self._reply(handler, 502, b"")
            return
        digest = hashlib.sha256(upstream_body).hexdigest()
        with self._lock:
            if self._requests == 1:
                self._receipt = BrokerReceipt(1, True, "accepted", digest, *usage)
            else:
                self._receipt = BrokerReceipt(
                    self._requests, False, "request_rejected", digest, *usage
                )
        self._reply(handler, 200, upstream_body, "text/event-stream")

    def _record(
        self,
        accepted: bool,
        reason: str,
        *,
        usage: tuple[int | None, int | None, int | None] = (None, None, None),
    ) -> None:
        with self._lock:
            self._receipt = BrokerReceipt(self._requests, accepted, reason, "", *usage)

    @staticmethod
    def _reply(
        handler: BaseHTTPRequestHandler,
        status: int,
        body: bytes,
        content_type: str = "application/json",
    ) -> None:
        handler.send_response(status)
        handler.send_header("Content-Type", content_type)
        handler.send_header("Content-Length", str(len(body)))
        handler.send_header("Connection", "close")
        handler.end_headers()
        if body:
            handler.wfile.write(body)


def _validate_request(value: object, expected_schema: object) -> None:
    if not isinstance(value, dict):
        raise ValueError
    request = cast(dict[str, Any], value)
    if request.get("model") != MODEL_ID or request.get("tools") not in (None, []):
        raise ValueError
    if request.get("tool_choice", "auto") not in {"auto", "none"}:
        raise ValueError
    text = request.get("text")
    if not isinstance(text, dict):
        raise ValueError
    text_value = cast(dict[str, Any], text)
    format_value = text_value.get("format")
    if not isinstance(format_value, dict):
        raise ValueError
    format_object = cast(dict[str, Any], format_value)
    schema = format_object.get("schema")
    if schema != expected_schema:
        raise ValueError
    if format_object.get("type") != "json_schema" or format_object.get("strict") is not True:
        raise ValueError
    if _contains_tool_metadata(request):
        raise ValueError


def _contains_tool_metadata(value: object) -> bool:
    if isinstance(value, dict):
        for key, item in cast(dict[str, Any], value).items():
            if key == "additional_tools" and item not in (None, []):
                return True
            if key == "tools" and item not in (None, []):
                return True
            if (
                key == "type"
                and isinstance(item, str)
                and item
                in {
                    "function_call",
                    "function_call_output",
                    "tool_call",
                }
            ):
                return True
            if _contains_tool_metadata(item):
                return True
    elif isinstance(value, list):
        return any(_contains_tool_metadata(item) for item in cast(list[Any], value))
    return False


def _validate_sse(raw: bytes) -> tuple[int | None, int | None, int | None]:
    if not raw or len(raw) > MAX_RESPONSE_BYTES:
        raise BrokerFailure("upstream_response_size_rejected")
    try:
        events: list[tuple[str, dict[str, Any]]] = []
        current_event = ""
        data: list[str] = []
        for line in raw.decode("utf-8", "strict").splitlines():
            if not line:
                if data:
                    decoded = _decode_json("\n".join(data).encode())
                    if not current_event or not isinstance(decoded, dict):
                        raise ValueError
                    events.append((current_event, cast(dict[str, Any], decoded)))
                current_event, data = "", []
            elif line.startswith("event:"):
                current_event = line[6:].strip()
            elif line.startswith("data:"):
                data.append(line[5:].lstrip())
        if data:
            raise ValueError
        if not events or events[-1][0] != "response.completed":
            raise ValueError
        completed = events[-1][1]
        response = completed.get("response")
        if not isinstance(response, dict):
            raise ValueError
        response_value = cast(dict[str, Any], response)
        if response_value.get("status") != "completed":
            raise ValueError
        usage = _usage(response_value.get("usage"))
        for event_name, event_data in events:
            if "tool" in event_name or "function_call" in event_name:
                raise BrokerFailure("upstream_tool_event_rejected", usage=usage)
            if _contains_output_tool(event_data):
                raise BrokerFailure("upstream_tool_event_rejected", usage=usage)
        return usage
    except BrokerFailure:
        raise
    except (ValueError, UnicodeError, RecursionError, TypeError):
        raise BrokerFailure("upstream_response_invalid") from None


def _contains_output_tool(value: object) -> bool:
    if isinstance(value, dict):
        typed = cast(dict[str, Any], value)
        item = typed.get("item")
        if isinstance(item, dict) and cast(dict[str, Any], item).get("type") != "message":
            return True
        for key, nested in typed.items():
            if key == "output" and isinstance(nested, list):
                outputs = cast(list[Any], nested)
                for element in outputs:
                    if (
                        not isinstance(element, dict)
                        or cast(dict[str, Any], element).get("type") != "message"
                    ):
                        return True
            if _contains_output_tool(cast(object, nested)):
                return True
    elif isinstance(value, list):
        for item in cast(list[Any], value):
            if _contains_output_tool(item):
                return True
    return False


def _usage(value: object) -> tuple[int | None, int | None, int | None]:
    if value is None:
        return None, None, None
    if not isinstance(value, dict):
        raise BrokerFailure("upstream_usage_invalid")
    usage = cast(dict[str, Any], value)
    input_tokens = usage.get("input_tokens")
    output_tokens = usage.get("output_tokens")
    details = usage.get("input_tokens_details")
    cached = (
        cast(dict[str, Any], details).get("cached_tokens") if isinstance(details, dict) else None
    )
    for number in (input_tokens, cached, output_tokens):
        if number is not None and (type(number) is not int or number < 0):
            raise BrokerFailure("upstream_usage_invalid")
    return input_tokens, cached, output_tokens


def _classify_upstream_failure(status: int, raw: bytes) -> str:
    try:
        value = _decode_json(raw[:65536])
        mapping = cast(dict[str, Any], value) if isinstance(value, dict) else {}
        error = mapping.get("error")
        details = cast(dict[str, Any], error) if isinstance(error, dict) else mapping
        code = details.get("code", details.get("type"))
        if isinstance(code, str) and code.lower() in {
            "usage_limit_reached",
            "account_limit_reached",
            "insufficient_quota",
            "billing_hard_limit_reached",
        }:
            return "account_limit"
    except (ValueError, TypeError, RecursionError):
        pass
    if status == 401:
        return "upstream_auth_rejected"
    if status == 429:
        return "upstream_rate_limited"
    if 500 <= status <= 599:
        return "upstream_server_error"
    return "upstream_status_rejected"


def _decode_json(raw: bytes) -> object:
    return json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=_reject_constant)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError


class _BoundedHTTPSTransport:
    def __init__(self, *, pass_fds: tuple[int, ...] = ()) -> None:
        self._pass_fds = pass_fds
        self._lock = threading.Lock()
        self._cancelled = threading.Event()
        self._process: subprocess.Popen[bytes] | None = None

    def __call__(self, body: bytes, auth_headers: dict[str, str]) -> tuple[int, bytes]:
        envelope = json.dumps(
            {"body": base64.b64encode(body).decode("ascii"), "headers": auth_headers},
            separators=(",", ":"),
        ).encode()
        command = [sys.executable, "-m", "ai_soc.workspace.model.cli_transport"]
        with self._lock:
            if self._cancelled.is_set():
                raise BrokerFailure("upstream_cancelled")
            try:
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                    pass_fds=self._pass_fds,
                    start_new_session=True,
                    env={
                        "PATH": "/usr/bin:/bin",
                        "LANG": "C.UTF-8",
                        "PYTHONPATH": os.pathsep.join(sys.path),
                    },
                )
            except OSError:
                raise BrokerFailure("upstream_transport_failed") from None
            self._process = process
        try:
            output, _ = process.communicate(envelope, timeout=UPSTREAM_TIMEOUT_SECONDS)
            if process.returncode != 0 or len(output) > MAX_RESPONSE_BYTES * 2:
                raise BrokerFailure("upstream_transport_failed")
            result = _decode_json(output)
            if not isinstance(result, dict):
                raise BrokerFailure("upstream_transport_failed")
            decoded = cast(dict[str, Any], result)
            status, response_body = decoded.get("status"), decoded.get("body")
            if type(status) is not int or not isinstance(response_body, str):
                raise BrokerFailure("upstream_transport_failed")
            response = base64.b64decode(response_body, validate=True)
            if len(response) > MAX_RESPONSE_BYTES:
                raise BrokerFailure("upstream_response_size_rejected")
            return status, response
        except subprocess.TimeoutExpired:
            self._kill(process)
            raise BrokerFailure("upstream_timeout") from None
        except (OSError, ValueError, TypeError):
            self._kill(process)
            raise BrokerFailure("upstream_transport_failed") from None
        finally:
            with self._lock:
                if self._process is process:
                    self._process = None

    def cancel(self) -> None:
        with self._lock:
            self._cancelled.set()
            process = self._process
        if process is not None:
            self._kill(process)

    @staticmethod
    def _kill(process: subprocess.Popen[bytes]) -> None:
        _kill_transport(process)


def _kill_transport(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
