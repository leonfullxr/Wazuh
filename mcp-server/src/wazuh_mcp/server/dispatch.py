"""Routes JSON-RPC methods and notifications to their handlers."""

import logging
from typing import Any, Dict

from .constants import MCP_ERRORS
from .handlers import (
    ResourceNotFound,
    handle_cancelled_notification,
    handle_completion_complete,
    handle_initialize,
    handle_initialized_notification,
    handle_logging_set_level,
    handle_ping,
    handle_prompts_get,
    handle_prompts_list,
    handle_resources_list,
    handle_resources_read,
    handle_resources_templates_list,
    handle_server_discover,
)
from .jsonrpc import MCPRequest, MCPResponse, create_error_response, create_success_response
from .sessions import MCPSession
from .tool_calls import handle_tools_call
from .tool_catalog import handle_tools_list

logger = logging.getLogger(__name__)


# MCP Method Registry - legacy revisions (2024-11-05 through 2025-11-25) plus
# the modern methods shared with 2026-07-28 (server/discover, tools, prompts, resources)
MCP_METHODS = {
    # Lifecycle methods
    "initialize": handle_initialize,
    "ping": handle_ping,
    # Discovery (2026-07-28) - also answered for legacy-era clients probing for era
    "server/discover": handle_server_discover,
    # Tools methods
    "tools/list": handle_tools_list,
    "tools/call": handle_tools_call,
    # Prompts methods
    "prompts/list": handle_prompts_list,
    "prompts/get": handle_prompts_get,
    # Resources methods
    "resources/list": handle_resources_list,
    "resources/read": handle_resources_read,
    "resources/templates/list": handle_resources_templates_list,
    # Logging methods
    "logging/setLevel": handle_logging_set_level,
    # Completion methods
    "completion/complete": handle_completion_complete,
}


MCP_NOTIFICATIONS = {
    "notifications/initialized": handle_initialized_notification,
    "notifications/cancelled": handle_cancelled_notification,
}


async def process_mcp_notification(method: str, params: Dict[str, Any], session: MCPSession) -> None:
    """
    Process MCP notification (no response expected).
    Per MCP spec, notifications MUST NOT receive responses.
    """
    # A non-string method (e.g. a list) is unhashable; guard the type before the lookup
    if isinstance(method, str) and method in MCP_NOTIFICATIONS:
        handler = MCP_NOTIFICATIONS[method]
        try:
            await handler(params, session)
        except Exception as e:
            # Log but don't return error - notifications don't get responses
            logger.error(f"Error processing notification {method}: {e}")
    else:
        logger.debug(f"Received unknown notification: {method}")


async def process_mcp_request(request: MCPRequest, session: MCPSession) -> MCPResponse:
    """Process individual MCP request per JSON-RPC 2.0 specification."""
    try:
        # Check if method exists
        if request.method not in MCP_METHODS:
            # Check if it's a notification method being called as request
            if request.method in MCP_NOTIFICATIONS:
                return create_error_response(
                    request.id,
                    MCP_ERRORS["INVALID_REQUEST"],
                    f"'{request.method}' is a notification, not a request method",
                )
            return create_error_response(
                request.id, MCP_ERRORS["METHOD_NOT_FOUND"], f"Method '{request.method}' not found"
            )

        # Execute method handler
        handler = MCP_METHODS[request.method]
        result = await handler(request.params or {}, session)

        return create_success_response(request.id, result)

    except ResourceNotFound as e:
        return create_error_response(request.id, MCP_ERRORS["RESOURCE_NOT_FOUND"], str(e))
    except ValueError as e:
        return create_error_response(request.id, MCP_ERRORS["INVALID_PARAMS"], str(e))
    except Exception as e:
        from wazuh_mcp.monitoring import structured_logger

        structured_logger.error(
            f"Internal error processing {request.method}",
            exc_info=True,
            method=request.method,
            request_id=str(request.id) if request.id else None,
            error_type=type(e).__name__,
            error_message=str(e),
        )
        return create_error_response(request.id, MCP_ERRORS["INTERNAL_ERROR"], "Internal server error")
