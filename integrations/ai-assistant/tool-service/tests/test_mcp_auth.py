"""MCP streamable HTTP auth gate (V3.3)."""
from starlette.testclient import TestClient

from app.mcp_surface import MCP_APP


def test_mcp_requires_credentials():
    client = TestClient(MCP_APP)
    r = client.get("/")
    assert r.status_code == 401
