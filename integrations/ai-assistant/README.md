# Wazuh Dashboard AI assistant (proof of concept)

Experimental OpenSearch Dashboard assistant for a single-host Wazuh deployment. This folder is our own code — not a copy of the official Wazuh integrations installer.

You can review the gateway, tests, and scripts without a live Wazuh stack. Run the installer only on a real single-host Wazuh node when you are ready to deploy.

For the later SOC service (playbooks, vector search, and related features), see [integrations/ai-soc](../ai-soc/).

## What it does

1. **Dashboard assistant** — installs `assistantDashboards` and `mlCommonsDashboards`, then registers an ML Commons HTTP connector that calls our gateway.
2. **MCP-LLM gateway** — FastAPI service on port 9912. `POST /analyze` receives the ML Commons request, routes intent, and returns `{"output":{"message":"..."}}`.
3. **OpenSearch MCP server** — upstream `opensearch-mcp-server-py` on port 9900 (SSE). The gateway is the MCP client. Indexer access uses basic auth from environment variables.

**Analysis questions** (alerts, DQL, vulnerabilities, SCA, IT hygiene) go through MCP tools against the indexer.

**Actions** (restart agent, create dashboard, email PDF report) stay in the gateway. They do not run until the user sends the exact token `CONFIRM`. A pending action returns a Pending Action block. `NO` cancels. A new unrelated question does not execute a stale pending action.

Supported LLM providers (`LLM_PROVIDER`): `openai`, `gemini`, `claude_bedrock`, `openai_compatible`. If the provider key is missing, `/analyze` still returns a clear error for LLM enhancement; routing and the confirm gate work without a live LLM.

## Prerequisites

- Single-host Wazuh 4.x with indexer, manager, and dashboard on one machine (documented path).
- Python 3.10+ and systemd for the installer.
- Outbound access to your LLM provider (optional for analysis-only routing tests).
- A non-placeholder `GATEWAY_API_KEY`.

Thin note: `install_ai_assistant.sh` also accepts `DEPLOYMENT_TYPE=indexer` (MCP + gateway only) or `DEPLOYMENT_TYPE=dashboard` (plugins + connector only) when components run on separate hosts.

## Architecture

```text
Analyst (Dashboard Assistant UI)
        |
        v
Wazuh Indexer (ML Commons connector)
        |  POST /analyze + API key
        v
MCP-LLM gateway :9912
   |                    \
   | analysis            \ actions (CONFIRM gate)
   v                      v
OpenSearch MCP :9900    Manager / Dashboard / SMTP
   |
   v
Wazuh Indexer (basic auth)
```

## Installation

```bash
cd integrations/ai-assistant
cp ai-assistant.env.example ai-assistant.env
# Edit ai-assistant.env — set indexer creds, GATEWAY_API_KEY, LLM keys.

sudo bash install_ai_assistant.sh ./ai-assistant.env
```

Preview the plan without installing:

```bash
DRY_RUN=1 bash install_ai_assistant.sh ./ai-assistant.env
```

## Verification

```bash
# Gateway health
curl -s http://127.0.0.1:9912/health

# Gateway analyze (replace key)
curl -s -X POST http://127.0.0.1:9912/analyze \
  -H "X-Api-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"parameters":{"question":"How many alerts fired today?"}}'

# Unit tests (no network)
pytest mcp-llm-gateway/tests -q
```

Open the Wazuh dashboard, click the assistant icon, and ask a question.

## Sample questions

| Question | Path |
|---|---|
| How many critical alerts in the last 24 hours? | MCP → indexer |
| Show SCA failures on agent web-01 | MCP → indexer |
| List open vulnerabilities for agent db-02 | MCP → indexer |
| Restart agent web-01 | Pending action → reply `CONFIRM` |
| Create dashboard "SOC overview" | Pending action → reply `CONFIRM` |
| Email PDF report to analyst@example.com | Pending action → reply `CONFIRM` |

## Notes

- Indexer auth is basic username/password. No extra indexer roles or custom auth domains in this PoC.
- The MCP server package is installed from PyPI; we do not vendor its source. See [mcp-server/README.md](mcp-server/README.md).
- Gateway code lives in [mcp-llm-gateway/](mcp-llm-gateway/). LLM and MCP calls are behind functions you can stub in tests.
- This PoC does not include playbooks, RAG, or in-cluster model hosting. Those belong in [integrations/ai-soc](../ai-soc/).
