"""JSON-RPC 2.0 request, response and error models and envelope helpers."""

import logging
import math
from typing import Any, Dict, Literal, Optional, Union

from fastapi import HTTPException
from pydantic import BaseModel, Field, field_validator

from .constants import SUPPORTED_PROTOCOL_VERSIONS

logger = logging.getLogger(__name__)


# MCP Protocol Models
class MCPRequest(BaseModel):
    """MCP JSON-RPC 2.0 Request."""

    jsonrpc: Literal["2.0"] = Field(description="JSON-RPC version (must be exactly 2.0)")
    # JSON-RPC 2.0 permits a Number id, including a non-integral one; float must be allowed
    # or a spec-valid `id: 1.5` fails validation and the error path itself 500s.
    id: Optional[Union[str, int, float]] = Field(default=None, description="Request ID")
    method: str = Field(description="Method name")
    params: Optional[Dict[str, Any]] = Field(default=None, description="Method parameters")

    @field_validator("id")
    @classmethod
    def _id_not_null(cls, value):
        # MCP basic protocol: "the ID MUST NOT be null" (requests without an id are
        # notifications and never reach this model)
        if value is None:
            raise ValueError("request id must not be null")
        return value

    @field_validator("id", mode="before")
    @classmethod
    def _id_not_bool(cls, value):
        # Lax int parsing turned `"id": true` into 1, so the reply answered a different id
        if isinstance(value, bool):
            raise ValueError("request id must be a string or number")
        return value


class MCPResponse(BaseModel):
    """
    MCP JSON-RPC 2.0 Response.

    Compliant with JSON-RPC 2.0 specification:
    - On success: includes 'result', excludes 'error'
    - On error: includes 'error', excludes 'result'
    """

    jsonrpc: str = Field(default="2.0", description="JSON-RPC version")
    id: Optional[Union[str, int, float]] = Field(default=None, description="Request ID")
    result: Optional[Any] = Field(default=None, description="Result data")
    error: Optional[Dict[str, Any]] = Field(default=None, description="Error object")

    def model_dump(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Override model_dump() to comply with JSON-RPC 2.0 specification.

        Per JSON-RPC 2.0 spec:
        - "result" and "error" MUST NOT both exist in the same response
        - On success: include 'result', exclude 'error'
        - On error: include 'error', exclude 'result'
        """
        d = super().model_dump(*args, **kwargs)

        # Determine which field was explicitly set.
        # error takes precedence: if error is set, this is an error response.
        if d.get("error") is not None:
            d.pop("result", None)
        else:
            # Success response: result may be any JSON value including None, 0, "", [].
            # Remove the error field since it's not an error response.
            d.pop("error", None)

        return d

    def dict(self, *args, **kwargs) -> Dict[str, Any]:
        """Backwards-compatible wrapper for model_dump()."""
        return self.model_dump(*args, **kwargs)


class MCPError(BaseModel):
    """MCP JSON-RPC 2.0 Error object."""

    code: int = Field(description="Error code")
    message: str = Field(description="Error message")
    data: Optional[Any] = Field(default=None, description="Additional error data")


def _normalize_jsonrpc_id(value: Any) -> Optional[Union[str, int, float]]:
    """JSON-RPC ids must be string, number, or null. A Number may be a float, so preserve
    finite floats (echoing a mismatched id back breaks the client's request/response
    correlation). Coerce anything else - list, object, or a non-finite float that isn't
    valid JSON - to None so building an error response can't itself raise and 500."""
    if isinstance(value, bool):  # bool is an int subclass; not a valid id
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return value
    return None


def create_error_response(
    request_id: Optional[Union[str, int]], code: int, message: str, data: Any = None
) -> MCPResponse:
    """Create MCP error response with correlation ID for tracing."""
    from wazuh_mcp.monitoring import get_correlation_id

    # Include correlation ID in error data for request tracing
    error_data = data if data else {}
    if isinstance(error_data, dict):
        error_data = {**error_data, "correlation_id": get_correlation_id()}
    elif data is None:
        error_data = {"correlation_id": get_correlation_id()}
    error = MCPError(code=code, message=message, data=error_data)
    # Normalize the id defensively: legacy error paths pass the raw body id, which may be a
    # list/object/non-finite float. Coercing to a valid JSON-RPC id here means building the
    # error response can never itself raise and turn a client mistake into an HTTP 500.
    return MCPResponse(id=_normalize_jsonrpc_id(request_id), error=error.model_dump())


def create_success_response(request_id: Optional[Union[str, int]], result: Any) -> MCPResponse:
    """Create MCP success response."""
    return MCPResponse(id=_normalize_jsonrpc_id(request_id), result=result)


def validate_protocol_version(version: Optional[str], strict: bool = False) -> str:
    """
    Validate and normalize MCP protocol version.

    Per MCP 2025-11-25 spec:
    - If no header provided, assume 2025-03-26 for backwards compatibility
    - If invalid/unsupported version, MUST return 400 Bad Request (when strict=True)

    Args:
        version: The protocol version from MCP-Protocol-Version header
        strict: If True, raise HTTPException for invalid versions (2025-11-25 behavior)

    Returns:
        The validated protocol version string
    """
    if not version:
        # Per spec: assume 2025-03-26 if no header provided (backwards compatibility)
        return "2025-03-26"

    if version in SUPPORTED_PROTOCOL_VERSIONS:
        return version

    # Per 2025-11-25 spec: "If the server receives a request with an invalid or
    # unsupported MCP-Protocol-Version, it MUST respond with 400 Bad Request"
    if strict:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported protocol version: {version}. Supported versions: {', '.join(SUPPORTED_PROTOCOL_VERSIONS)}",
        )

    # For backwards compatibility (non-strict mode), try to handle gracefully
    logger.warning(f"Unsupported protocol version {version}, falling back to 2025-03-26")
    return "2025-03-26"


def is_json_rpc_notification(message: Dict[str, Any]) -> bool:
    """Check if a JSON-RPC message is a notification (no 'id' field)."""
    return "method" in message and "id" not in message


def is_json_rpc_response(message: Dict[str, Any]) -> bool:
    """Check if a JSON-RPC message is a response (has 'result' or 'error', no 'method')."""
    return ("result" in message or "error" in message) and "method" not in message


def _echo_id(message: Any) -> Optional[Union[str, int, float]]:
    """The id to answer an invalid request with: its own id when that is a usable JSON-RPC id."""
    msg_id = message.get("id") if isinstance(message, dict) else None
    return msg_id if isinstance(msg_id, (str, int, float)) and not isinstance(msg_id, bool) else None


def is_json_rpc_request(message: Dict[str, Any]) -> bool:
    """Check if a JSON-RPC message is a request (has 'method' and 'id')."""
    return "method" in message and "id" in message
