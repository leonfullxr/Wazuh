"""Public entry point of the Wazuh MCP server package: the FastAPI app."""

from .app import app

__all__ = ["app"]
