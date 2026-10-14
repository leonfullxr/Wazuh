"""HTTP transport: the /, /sse and /mcp routes and modern and legacy request handling."""

import asyncio
import json
import logging
import uuid
from typing import Any, Dict, Optional, Union

from fastapi import APIRouter, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import ValidationError

from wazuh_mcp import __version__
from wazuh_mcp.monitoring import ACTIVE_CONNECTIONS
from wazuh_mcp.security import MAX_JSON_DEPTH, parse_json_body_safe
from wazuh_mcp.session_store import SessionStoreUnavailable

from . import sessions, state
from .constants import (
    CACHEABLE_METHOD_TTLS,
    LEGACY_PROTOCOL_VERSIONS,
    MAX_BATCH_SIZE,
    MCP_ERRORS,
    MCP_NAME_SOURCE_FIELDS,
    META_CLIENT_CAPABILITIES,
    META_CLIENT_INFO,
    META_PROTOCOL_VERSION,
    META_SERVER_INFO,
    MODERN_PROTOCOL_VERSIONS,
    MODERN_REMOVED_METHODS,
    SUPPORTED_PROTOCOL_VERSIONS,
)
from .dispatch import MCP_METHODS, process_mcp_notification, process_mcp_request
from .http_security import _authenticate, _rate_limit_key, _rate_limited_response, validate_origin_header
from .jsonrpc import (
    MCPRequest,
    _echo_id,
    _normalize_jsonrpc_id,
    create_error_response,
    is_json_rpc_notification,
    is_json_rpc_response,
    validate_protocol_version,
)
from .sessions import MCPSession, _bounded_capabilities, _bounded_client_info, _is_initialize, _principal_of

logger = logging.getLogger(__name__)

router = APIRouter()


def _decode_mcp_header_value(value: str) -> str:
    """Decode the Base64 sentinel format (=?base64?...?=) used for non-ASCII Mcp-Name values."""
    if value.startswith("=?base64?") and value.endswith("?="):
        import base64

        try:
            return base64.b64decode(value[len("=?base64?") : -len("?=")]).decode("utf-8")
        except Exception:
            return value
    return value


def _modern_error_response(
    request_id: Optional[Union[str, int]],
    code: int,
    message: str,
    data: Any = None,
    status_code: int = 400,
    headers: Optional[Dict[str, str]] = None,
) -> JSONResponse:
    """Build an HTTP JSON-RPC error response for the modern (2026-07-28) request path."""
    return JSONResponse(
        content=create_error_response(request_id, code, message, data=data).dict(),
        status_code=status_code,
        headers=headers or {},
    )


def extract_modern_meta(body: Any) -> Optional[Dict[str, Any]]:
    """Return the request's _meta dict only when it declares a *modern* protocol version.

    A legacy client's `_meta` is an open bag and may carry an
    `io.modelcontextprotocol/protocolVersion` key with a legacy value (e.g. "2025-11-25").
    Routing that onto the modern, stateless path would reject it with
    UnsupportedProtocolVersionError whose `supported` list still contains that version -
    a spec-compliant client then retries the same version forever instead of falling back
    to `initialize`. So a request is treated as modern only when the declared version is
    not a known legacy revision; legacy-declared _meta flows to the legacy handler.
    """
    if not isinstance(body, dict):
        return None
    params = body.get("params")
    if not isinstance(params, dict):
        return None
    meta = params.get("_meta")
    if not isinstance(meta, dict):
        return None
    declared = meta.get(META_PROTOCOL_VERSION)
    if declared is not None and declared not in LEGACY_PROTOCOL_VERSIONS:
        return meta
    return None


def is_modern_request(body: Any, header_version: Optional[str]) -> bool:
    """Decide whether a POST belongs on the modern (2026-07-28) stateless path.

    Either signal is enough: a modern MCP-Protocol-Version header, or a modern
    _meta protocol version in the body (including inside a batch). Keying on _meta
    alone let a request carrying only the modern header fall through to the legacy
    handler, which minted a session and returned a result without resultType while
    echoing MCP-Protocol-Version: 2026-07-28 back to the client.
    """
    if header_version in MODERN_PROTOCOL_VERSIONS:
        return True
    if isinstance(body, list):
        return any(extract_modern_meta(item) is not None for item in body)
    return extract_modern_meta(body) is not None


async def handle_modern_request(
    body: Any,
    meta: Optional[Dict[str, Any]],
    request: Request,
    auth_token: Any,
    header_version: Optional[str],
    origin: Optional[str],
) -> Response:
    """
    Serve a modern (2026-07-28) stateless request.

    Modern requests carry their protocol version, client info, and capabilities in
    params._meta on every request. There is no initialize handshake and no
    protocol-level session: no Mcp-Session-Id is minted or echoed, and header/body
    metadata (MCP-Protocol-Version, Mcp-Method, Mcp-Name) is validated per the
    Streamable HTTP transport rules.
    """
    # JSON-RPC batching does not exist in modern revisions
    if not isinstance(body, dict):
        return _modern_error_response(
            None,
            MCP_ERRORS["INVALID_REQUEST"],
            "Batch requests are not supported by modern protocol revisions; send one request per POST",
        )

    request_id = _normalize_jsonrpc_id(body.get("id"))
    requested_version = meta.get(META_PROTOCOL_VERSION) if meta else None

    # A modern header without the matching _meta is a header/body mismatch - never
    # downgrade it to the legacy path
    if requested_version is None:
        return _modern_error_response(
            request_id,
            MCP_ERRORS["HEADER_MISMATCH"],
            f"Header mismatch: MCP-Protocol-Version header {header_version!r} requires "
            f"params._meta[{META_PROTOCOL_VERSION!r}] on every request",
            headers={"MCP-Protocol-Version": str(header_version)},
        )

    response_headers = {"MCP-Protocol-Version": str(requested_version)}

    if requested_version not in MODERN_PROTOCOL_VERSIONS:
        return _modern_error_response(
            request_id,
            MCP_ERRORS["UNSUPPORTED_PROTOCOL_VERSION"],
            "Unsupported protocol version",
            data={"supported": SUPPORTED_PROTOCOL_VERSIONS, "requested": requested_version},
        )

    method = body.get("method", "")

    # Header <-> body validation (2026-07-28 Streamable HTTP transport)
    if header_version != requested_version:
        return _modern_error_response(
            request_id,
            MCP_ERRORS["HEADER_MISMATCH"],
            f"Header mismatch: MCP-Protocol-Version header {header_version!r} "
            f"does not match _meta protocol version {requested_version!r}",
            headers=response_headers,
        )
    mcp_method_header = request.headers.get("mcp-method")
    if mcp_method_header != method:
        return _modern_error_response(
            request_id,
            MCP_ERRORS["HEADER_MISMATCH"],
            f"Header mismatch: Mcp-Method header {mcp_method_header!r} does not match body method {method!r}",
            headers=response_headers,
        )
    name_field = MCP_NAME_SOURCE_FIELDS.get(method)
    if name_field:
        body_name = (body.get("params") or {}).get(name_field)
        raw_header_name = request.headers.get("mcp-name")
        decoded_name = _decode_mcp_header_value(raw_header_name) if raw_header_name is not None else None
        if body_name is None or decoded_name != str(body_name):
            return _modern_error_response(
                request_id,
                MCP_ERRORS["HEADER_MISMATCH"],
                f"Header mismatch: Mcp-Name header {raw_header_name!r} does not match body {name_field!r} value",
                headers=response_headers,
            )

    # The core protocol defines no client-to-server notifications over Streamable HTTP
    if is_json_rpc_notification(body):
        return Response(status_code=202, headers=response_headers)

    # Method availability: methods removed in 2026-07-28 (initialize, ping,
    # logging/setLevel) are not served on the modern path
    if method in MODERN_REMOVED_METHODS or method not in MCP_METHODS:
        return _modern_error_response(
            request_id,
            MCP_ERRORS["METHOD_NOT_FOUND"],
            f"Method '{method}' not found",
            status_code=404,
            headers=response_headers,
        )

    # Ephemeral session object for handler compatibility - never stored or echoed
    session = MCPSession(f"stateless-{uuid.uuid4()}", origin)
    session.authenticated = True
    session._auth_token = auth_token
    session.client_info = _bounded_client_info(meta.get(META_CLIENT_INFO))
    session.capabilities = _bounded_capabilities(meta.get(META_CLIENT_CAPABILITIES))

    try:
        mcp_request = MCPRequest(**body)
    except ValidationError as e:
        return _modern_error_response(
            request_id,
            MCP_ERRORS["INVALID_REQUEST"],
            f"Invalid MCP request: {e}",
            headers=response_headers,
        )

    mcp_response = await process_mcp_request(mcp_request, session)
    payload = mcp_response.dict()

    result = payload.get("result")
    if isinstance(result, dict):
        # Every 2026-07-28 result carries resultType; list/read results also carry
        # CacheableResult freshness hints, and serverInfo identifies the server
        result.setdefault("resultType", "complete")
        ttl_ms = CACHEABLE_METHOD_TTLS.get(method)
        if ttl_ms is not None:
            result.setdefault("ttlMs", ttl_ms)
            result.setdefault("cacheScope", "private")
        result_meta = result.setdefault("_meta", {})
        if isinstance(result_meta, dict):
            result_meta.setdefault(META_SERVER_INFO, {"name": "Wazuh MCP", "version": __version__})

    return JSONResponse(content=payload, headers=response_headers)


async def generate_sse_events(session: MCPSession, event_id_counter: int = 0, track_connection: bool = False):
    """
    Generate Server-Sent Events for MCP Streamable HTTP transport.

    Per MCP 2025-11-25 spec:
    - SSE events MUST include an 'id' field for resumability
    - Server SHOULD immediately send a priming event with event ID and empty data
    - Server SHOULD send retry field to indicate reconnection delay

    Args:
        session: The MCP session
        event_id_counter: Starting event ID
        track_connection: If True, decrement ACTIVE_CONNECTIONS when stream ends
    """
    # Event ids must be unique across every stream of a session (spec), so prefix them with a
    # per-stream id instead of restarting at 1 on each GET.
    stream_id = uuid.uuid4().hex[:12]
    event_id = event_id_counter

    try:
        # Per 2025-11-25 spec: "The server SHOULD immediately send an SSE event
        # consisting of an event ID and an empty data field in order to prime
        # the client to reconnect (using that event ID as Last-Event-ID)"
        event_id += 1
        yield f"id: {stream_id}-{event_id}\nretry: 3000\ndata: \n\n"

        # Keepalive as an SSE comment: clients ignore it by definition. The previous
        # notifications/session|capabilities|ping messages aren't MCP methods.
        while True:
            await asyncio.sleep(30)
            yield ": keepalive\n\n"
    except (asyncio.CancelledError, GeneratorExit):
        logger.debug(f"SSE connection closed for session {session.session_id}")
    finally:
        if track_connection:
            ACTIVE_CONNECTIONS.dec()


@router.get("/")
@router.post("/")
async def mcp_endpoint(
    request: Request,
    authorization: str = Header(None),
    origin: Optional[str] = Header(None),
    accept: Optional[str] = Header(None),
    mcp_session_id: Optional[str] = Header(None, alias="MCP-Session-Id"),
    last_event_id: Optional[str] = Header(None, alias="Last-Event-ID"),
    mcp_protocol_version: Optional[str] = Header(None, alias="MCP-Protocol-Version"),
):
    """Root alias of /mcp: same transport, sessions, headers and errors.

    It is a thin alias and must not drift: it never mints session ids for sessions it does
    not store, never replies with JSON (or stores a session) to a non-SSE GET, and always sends
    the MCP-Protocol-Version response header."""
    return await mcp_streamable_http_endpoint(
        request,
        authorization=authorization,
        origin=origin,
        mcp_protocol_version=mcp_protocol_version,
        mcp_session_id=mcp_session_id,
        accept=accept if accept is not None else "application/json",
        last_event_id=last_event_id,
    )


# The legacy HTTP+SSE transport (2024-11-05) was never functional here: it sent no
# `endpoint` event and had no POST message route, so every client that connected hung.
# Answer with a clear pointer instead of an endless stream.
@router.api_route("/sse", methods=["GET", "POST"])
async def mcp_sse_removed():
    return JSONResponse(
        status_code=410,
        content={
            "error": "The legacy /sse transport is not supported. Use the Streamable HTTP endpoint /mcp.",
            "endpoint": "/mcp",
        },
    )


# Standard MCP Endpoint - Streamable HTTP Transport (2025-11-25 Specification)
@router.post("/mcp")
@router.get("/mcp")
async def mcp_streamable_http_endpoint(
    request: Request,
    authorization: str = Header(None),
    origin: Optional[str] = Header(None),
    mcp_protocol_version: Optional[str] = Header(None, alias="MCP-Protocol-Version"),
    mcp_session_id: Optional[str] = Header(None, alias="MCP-Session-Id"),
    accept: Optional[str] = Header("application/json"),
    last_event_id: Optional[str] = Header(None, alias="Last-Event-ID"),
):
    """
    Standard MCP endpoint using Streamable HTTP transport (2025-11-25 spec).

    Supports:
    - POST: JSON-RPC requests (single message per 2025-11-25 spec)
    - GET: SSE stream initiation (requires Accept: text/event-stream)
    - DELETE: Session termination (see separate endpoint)

    This is the MCP endpoint for all clients (the legacy /sse transport answers 410).
    Supports authentication modes: bearer (default), oauth, none (authless)
    """
    # Validate protocol version header. Unknown versions get a JSON-RPC
    # UnsupportedProtocolVersionError body (-32022) so modern (2026-07-28) clients
    # can pick a mutually supported version and retry.
    if mcp_protocol_version and mcp_protocol_version not in SUPPORTED_PROTOCOL_VERSIONS:
        return _modern_error_response(
            None,
            MCP_ERRORS["UNSUPPORTED_PROTOCOL_VERSION"],
            "Unsupported protocol version",
            data={"supported": SUPPORTED_PROTOCOL_VERSIONS, "requested": mcp_protocol_version},
        )
    protocol_version = validate_protocol_version(mcp_protocol_version)

    # Verify authentication based on configured mode
    auth_token = await _authenticate(request, authorization)

    # Origin validation per 2025-11-25 spec
    # Only validate if Origin is present; if present and invalid, return 403
    validate_origin_header(origin, state.config.ALLOWED_ORIGINS)

    # Rate limiting - key on the authenticated principal + trusted-proxy IP
    allowed, retry_after = state.rate_limiter.is_allowed(_rate_limit_key(request, auth_token))
    if not allowed:
        raise _rate_limited_response(retry_after)

    # Track active connections (metrics tracked after processing)
    ACTIVE_CONNECTIONS.inc()
    _sse_returned = False  # Track if SSE stream was returned (generator handles decrement)
    _status_code = 200  # Track actual status code for metrics

    try:
        # Parse POST bodies first: modern (2026-07-28) requests are stateless and
        # bypass legacy session handling entirely
        body = None
        if request.method == "POST":
            try:
                # Depth-capped parse: a deeply nested payload otherwise raises RecursionError
                # (not JSONDecodeError), which would escape as a 500 and burn CPU per request.
                body = parse_json_body_safe(await request.body(), max_depth=MAX_JSON_DEPTH)
            except (json.JSONDecodeError, ValueError):
                return JSONResponse(
                    content=create_error_response(None, MCP_ERRORS["PARSE_ERROR"], "Invalid JSON").dict(),
                    status_code=400,
                )
            if is_modern_request(body, mcp_protocol_version):
                # Modern era: no session is minted or echoed; Mcp-Session-Id is ignored
                return await handle_modern_request(
                    body, extract_modern_meta(body), request, auth_token, mcp_protocol_version, origin
                )

        # Legacy era - session validation per MCP Streamable HTTP spec:
        # If client provides session ID but session doesn't exist, return 404
        if mcp_session_id:
            existing_session = await state.sessions.get(mcp_session_id)
            if not existing_session:
                raise HTTPException(
                    status_code=404, detail="Session not found. Please start a new session with InitializeRequest."
                )
            if existing_session.is_expired():
                await state.sessions.remove(mcp_session_id)
                state._initialized_sessions.pop(mcp_session_id, None)
                raise HTTPException(
                    status_code=404, detail="Session expired. Please start a new session with InitializeRequest."
                )
            session = existing_session
            session.update_activity()
            await state.sessions.set(mcp_session_id, session)
        else:
            # Only an initialize (or a GET stream) starts a stored session
            persist = request.method == "GET" or _is_initialize(body)
            session = await sessions.get_or_create_session(None, origin, persist=persist, principal=_principal_of(auth_token))

        session.authenticated = True  # Mark as authenticated
        session._auth_token = auth_token  # Store token for scope checks in tool handlers

        # Common response headers
        response_headers = {
            "MCP-Protocol-Version": protocol_version,
            "Access-Control-Expose-Headers": "MCP-Session-Id, MCP-Protocol-Version",
        }
        if mcp_session_id or persist:
            response_headers["MCP-Session-Id"] = session.session_id

        # Handle GET request per MCP Streamable HTTP spec
        if request.method == "GET":
            # Per spec: server MUST return text/event-stream OR HTTP 405
            if accept and "text/event-stream" in accept:
                # track_connection=True: decrement happens when stream closes
                _sse_returned = True
                response = StreamingResponse(
                    generate_sse_events(session, track_connection=True),
                    media_type="text/event-stream",
                    headers={**response_headers, "Cache-Control": "no-cache", "Connection": "keep-alive"},
                )
                return response
            else:
                # Per MCP spec: GET without Accept: text/event-stream MUST return 405
                raise HTTPException(
                    status_code=405, detail="GET requires Accept: text/event-stream header for SSE stream"
                )

        # Handle POST request (JSON-RPC) - body already parsed above
        elif request.method == "POST":
            # Handle batch messages per MCP Streamable HTTP spec
            if isinstance(body, list):
                if not body:
                    return JSONResponse(
                        content=create_error_response(
                            None, MCP_ERRORS["INVALID_REQUEST"], "Empty batch request"
                        ).dict(),
                        status_code=400,
                        headers=response_headers,
                    )
                if len(body) > MAX_BATCH_SIZE:
                    return JSONResponse(
                        content=create_error_response(
                            None, MCP_ERRORS["INVALID_REQUEST"], f"Batch too large (max {MAX_BATCH_SIZE})"
                        ).dict(),
                        status_code=400,
                        headers=response_headers,
                    )

                # Check if batch contains any requests
                # Anything that isn't a well-formed notification/response is answered, not dropped:
                # [1, 2] or [{"jsonrpc": "2.0", "id": 1}] must get Invalid Request errors (JSON-RPC 2.0)
                has_requests = any(
                    not (isinstance(item, dict) and (is_json_rpc_notification(item) or is_json_rpc_response(item)))
                    for item in body
                )

                if not has_requests:
                    # Process all notifications before returning 202
                    for item in body:
                        if isinstance(item, dict) and is_json_rpc_notification(item):
                            method = item.get("method", "")
                            params = item.get("params", {})
                            await process_mcp_notification(method, params, session)
                    return Response(status_code=202, headers=response_headers)

                # Process requests in batch
                responses = []
                for item in body:
                    # Process notifications but don't add to responses
                    if isinstance(item, dict) and is_json_rpc_notification(item):
                        method = item.get("method", "")
                        params = item.get("params", {})
                        await process_mcp_notification(method, params, session)
                        continue
                    # Skip responses
                    if isinstance(item, dict) and is_json_rpc_response(item):
                        continue
                    try:
                        if not isinstance(item, dict):
                            raise TypeError(f"Expected dict, got {type(item).__name__}")
                        mcp_request = MCPRequest(**item)
                        resp = await process_mcp_request(mcp_request, session)
                        responses.append(resp.dict())
                    except (ValidationError, TypeError) as e:
                        responses.append(
                            create_error_response(
                                _echo_id(item),
                                MCP_ERRORS["INVALID_REQUEST"],
                                f"Invalid request format: {e}",
                            ).dict()
                        )

                return JSONResponse(content=responses, headers=response_headers)

            # Handle single message
            if isinstance(body, dict):
                # Notifications and responses return 202 Accepted
                if is_json_rpc_notification(body):
                    # Process the notification (no response)
                    method = body.get("method", "")
                    params = body.get("params", {})
                    await process_mcp_notification(method, params, session)
                    logger.debug(f"Processed notification: {method}")
                    return Response(status_code=202, headers=response_headers)
                elif is_json_rpc_response(body):
                    # Client sending a response - just acknowledge
                    return Response(status_code=202, headers=response_headers)

            # Validate JSON-RPC request
            try:
                mcp_request = MCPRequest(**body) if isinstance(body, dict) else None
            except ValidationError as e:
                return JSONResponse(
                    content=create_error_response(
                        _echo_id(body), MCP_ERRORS["INVALID_REQUEST"], f"Invalid MCP request: {str(e)}"
                    ).dict(),
                    status_code=400,
                    headers=response_headers,
                )

            # Process the request
            if mcp_request:
                mcp_response = await process_mcp_request(mcp_request, session)
                # The header must name the version initialize actually negotiated, not the
                # request-header default (2025-03-26) it would otherwise echo
                negotiated = (
                    (mcp_response.result or {}).get("protocolVersion") if mcp_request.method == "initialize" else None
                )
                if negotiated:
                    response_headers["MCP-Protocol-Version"] = negotiated

                # Check if client accepts SSE for streaming response
                # (For long-running operations, we could upgrade to SSE here)
                if accept and "text/event-stream" in accept:
                    # Optional: Stream the response via SSE for long operations
                    # For now, return JSON response
                    return JSONResponse(content=mcp_response.dict(), headers=response_headers)
                else:
                    # Standard JSON response
                    return JSONResponse(content=mcp_response.dict(), headers=response_headers)
            else:
                return JSONResponse(
                    content=create_error_response(None, MCP_ERRORS["INVALID_REQUEST"], "Invalid request format").dict(),
                    status_code=400,
                    headers=response_headers,
                )

        else:
            raise HTTPException(status_code=405, detail="Method not allowed")

    except HTTPException as exc:
        _status_code = exc.status_code
        raise
    except SessionStoreUnavailable:
        _status_code = 503
        raise  # -> 503 via the app exception handler
    except Exception as e:
        _status_code = 500
        logger.error(f"MCP endpoint error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

    finally:
        # REQUEST_COUNT is already tracked by the monitoring middleware - no need to duplicate here.
        # Only decrement for non-SSE responses; SSE generator handles its own decrement.
        if not _sse_returned:
            ACTIVE_CONNECTIONS.dec()


@router.delete("/mcp")
async def close_mcp_session(
    request: Request,
    mcp_session_id: str = Header(..., alias="MCP-Session-Id"),
    authorization: str = Header(None),
    origin: Optional[str] = Header(None),
):
    """
    Close MCP session explicitly (2025-11-25 spec).
    Allows clients to cleanly terminate sessions.
    """
    # Use the same auth logic as other endpoints (respects authless mode)
    auth_token = await _authenticate(request, authorization)
    # Same Origin (DNS-rebinding) and rate-limit checks as POST/GET: a hostile page could
    # otherwise end sessions cross-origin
    validate_origin_header(origin, state.config.ALLOWED_ORIGINS)
    allowed, retry_after = state.rate_limiter.is_allowed(_rate_limit_key(request, auth_token))
    if not allowed:
        raise _rate_limited_response(retry_after)

    # Remove session
    existing = await state.sessions.get(mcp_session_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Session not found")
    await state.sessions.remove(mcp_session_id)
    state._initialized_sessions.pop(mcp_session_id, None)
    logger.info(f"Session {mcp_session_id} closed via DELETE")
    return Response(status_code=204)  # No content
