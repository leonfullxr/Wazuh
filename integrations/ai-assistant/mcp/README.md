# MCP adapter (P1.8)

Stdio MCP server over the existing HTTP surfaces. Same identity chain, same
veracity pipeline — MCP is just another door (D21).

## Setup

```bash
pip install -r mcp/requirements.txt
python3 mcp/server.py
```

By default the server mints turn JWTs on demand (Keycloak password grant +
shim exchange) and refreshes before the 10-minute TTL (R2.7). Override with
a static token for one-shot use:

```bash
export WAI_MCP_JWT=$(curl -s -X POST http://localhost:8081/v1/token/exchange \
  -H "Authorization: Bearer $OIDC" | jq -r .access_token)
```

Optional env vars: `WAI_MCP_KC_URL`, `WAI_MCP_SHIM_URL`, `WAI_MCP_KC_USER`,
`WAI_MCP_KC_PASSWORD`, `WAI_MCP_BASE_URL`.

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
