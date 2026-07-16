# MCP adapter (P1.8)

Stdio MCP server over the existing HTTP surfaces. Same identity chain, same
veracity pipeline — MCP is just another door (D21).

## Setup

```bash
pip install -r mcp/requirements.txt
python3 mcp/server.py
```

By default the server mints turn JWTs on demand (indexer Basic auth via the
auth-shim, V3.6) and refreshes before the 10-minute TTL. Override with a
static token for one-shot use:

```bash
export WAI_MCP_JWT=$(curl -s -u analyst1:analyst1 -X POST \
  http://localhost:8081/v1/token/exchange \
  -H 'X-Env-Id: lab' | jq -r .access_token)
```

Optional env vars: `WAI_MCP_SHIM_URL`, `WAI_MCP_USER`, `WAI_MCP_PASSWORD`,
`WAI_MCP_ENV_ID`, `WAI_MCP_BASE_URL`.

## Claude Desktop config snippet

```json
{
  "mcpServers": {
    "wazuh-ai": {
      "command": "python3",
      "args": ["/path/to/integrations/ai-assistant/mcp/server.py"],
      "env": {
        "WAI_MCP_BASE_URL": "http://localhost:8080"
      }
    }
  }
}
```

Tools exposed: `wazuh_chat`, `wazuh_call_tool`, `wazuh_list_tools`.

## Streamable HTTP (V3.3)

The gateway also serves MCP at **`http://localhost:8080/mcp`** (streamable HTTP).
Use a turn JWT or env key on every request — same credentials as the other
surfaces:

```bash
# Per-user (Cursor / Claude Desktop remote MCP)
export WAI_MCP_JWT=$(curl -s -u analyst1:analyst1 -X POST \
  http://localhost:8081/v1/token/exchange \
  -H 'X-Env-Id: lab' | jq -r .access_token)
```

Cursor / Claude Desktop remote MCP config:

```json
{
  "mcpServers": {
    "wazuh-ai": {
      "url": "http://localhost:8080/mcp",
      "headers": {
        "Authorization": "Bearer ${WAI_MCP_JWT}"
      }
    }
  }
}
```

Env-scoped (connector-style): send `X-Env-Key` instead of `Authorization`.

The stdio adapter (`mcp/server.py`) remains for offline/dev hosts that cannot
reach the gateway URL directly.
