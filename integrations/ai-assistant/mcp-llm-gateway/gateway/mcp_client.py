"""MCP client wrapper for OpenSearch tool calls."""
from __future__ import annotations

import asyncio
import json
from typing import Any

from mcp import Client
from mcp.types import TextContent

from .config import CFG


def _mcp_endpoint_url() -> str:
    """Return the streamable HTTP endpoint for opensearch-mcp-server-py --transport stream."""
    url = CFG.mcp_sse_url.rstrip("/")
    if url.endswith("/sse"):
        return url.rsplit("/sse", 1)[0] + "/mcp"
    return url


def _format_tool_result(result: Any) -> str:
    if hasattr(result, "content") and result.content:
        parts: list[str] = []
        for block in result.content:
            if isinstance(block, TextContent):
                parts.append(block.text)
            elif isinstance(block, dict) and block.get("type") == "text":
                parts.append(str(block.get("text", "")))
            elif hasattr(block, "text"):
                parts.append(str(block.text))
        if parts:
            return "\n".join(parts)
    return json.dumps(result, indent=2, default=str)


def _tool_arguments(tool_name: str, question: str) -> dict[str, Any]:
    if tool_name == "SearchIndexTool":
        return {
            "index": "wazuh-alerts-*",
            "query_dsl": {
                "query": {
                    "query_string": {"query": question, "default_field": "*"},
                },
            },
            "size": 10,
        }
    return {"question": question}


async def _call_mcp_async(question: str, tool_name: str = "SearchIndexTool") -> str:
    """Open a streamable HTTP MCP session and call an OpenSearch tool."""
    url = _mcp_endpoint_url()
    async with Client(url, read_timeout_seconds=120.0) as client:
        listed = await client.list_tools()
        available = {tool.name for tool in listed.tools}
        name = tool_name if tool_name in available else "SearchIndexTool"
        if name not in available:
            if "GenericOpenSearchApiTool" in available:
                name = "GenericOpenSearchApiTool"
            elif available:
                name = sorted(available)[0]
            else:
                raise RuntimeError("MCP server returned no tools")

        if name == "GenericOpenSearchApiTool":
            arguments: dict[str, Any] = {
                "path": "/wazuh-alerts-*/_search",
                "method": "POST",
                "body": {
                    "size": 10,
                    "query": {"query_string": {"query": question, "default_field": "*"}},
                },
            }
        else:
            arguments = _tool_arguments(name, question)

        result = await client.call_tool(name, arguments)
        text = _format_tool_result(result)
        if getattr(result, "is_error", False):
            raise RuntimeError(text or f"MCP tool {name} failed")
        return text


def call_mcp(question: str, tool_name: str = "SearchIndexTool") -> str:
    """Call the upstream OpenSearch MCP server and return tool output text."""
    return asyncio.run(_call_mcp_async(question, tool_name))
