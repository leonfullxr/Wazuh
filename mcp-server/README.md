# wazuh-mcp

Part of the [Wazuh knowledge base](../README.md) repository.

Getting the code:

```bash
git clone https://github.com/leonfullxr/Wazuh.git && cd Wazuh/mcp-server
```

wazuh-mcp is a Model Context Protocol (MCP) server that exposes the Wazuh Manager API and the Wazuh Indexer to AI clients over Streamable HTTP. An MCP client can query alerts, agents, vulnerabilities and compliance data, and dispatch active responses, with scope-based access control and audit logging.

---

## Overview

- **Tools:** 55 tools in 8 toolsets: alerts, agents, vulnerabilities, threat analysis, compliance (PCI-DSS, HIPAA, SOX, GDPR, NIST, ISO 27001:2022), web search, manager/cluster health, and active response with verification and rollback. Also 5 guided prompts, 6 resources and 3 resource templates. In multi-cluster mode a 56th tool, `list_wazuh_clusters`, is added.
- **Read-only by default:** the 14 state-changing tools require the `wazuh:write` scope, which is never granted implicitly.
- **MCP transport:** Streamable HTTP at `/mcp`. Serves protocol revision 2026-07-28 (stateless requests) and the `initialize` handshake for 2025-11-25, 2025-06-18, 2025-03-26 and 2024-11-05. The legacy HTTP+SSE endpoint `/sse` returns `410 Gone`.
- **Authentication:** bearer tokens minted from an API key; OAuth 2.0 (authorization code + PKCE) with sign-in by API key or at an OpenID Connect provider (Entra ID, Google Workspace, Okta, Keycloak); or no auth for local development.
- **Deployment:** Docker Compose (built locally) or from source; optional Redis for multi-instance sessions; optional multi-cluster routing.
- **Local models:** a vLLM + Open WebUI stack (`compose.local-llm.yml`) and toolset filtering for small models. The only tool that calls a service outside your Wazuh deployment is the optional `search_external_context` (You.com), which can be disabled on its own.

Supported Wazuh versions: 4.8.0 through 4.14.7. Alert, vulnerability and alert-backed compliance tools need the Wazuh Indexer. See [WAZUH_COMPATIBILITY.md](WAZUH_COMPATIBILITY.md).

---

## Quick Start

Requires Docker with Compose v2 and a Wazuh Manager API user.

```bash
cp .env.example .env
```

Set the Wazuh connection in `.env`:

```env
WAZUH_HOST=your-wazuh-manager
WAZUH_USER=your-api-user
WAZUH_PASS=your-api-password

# Needed for alert, vulnerability and alert-backed compliance tools
WAZUH_INDEXER_HOST=your-wazuh-indexer
WAZUH_INDEXER_USER=your-indexer-user
WAZUH_INDEXER_PASS=your-indexer-password
```

The Manager's TLS certificate is verified. A stock Wazuh install uses a self-signed API certificate that cannot pass verification, so either reissue it for your host and set `WAZUH_CA_BUNDLE`, or, for a first test, add `WAZUH_ALLOW_SELF_SIGNED=true` (connects without verification; logged at startup). Details: [Manager TLS](docs/configuration.md#manager-tls).

Generate the token signing key and an API key. `compose.yml` runs the server with `ENVIRONMENT=production`, which refuses to start without `AUTH_SECRET_KEY`. Production does not print a generated `MCP_API_KEY`, so set it explicitly. The API key must start with `wazuh_` followed by 43 characters:

```bash
echo "AUTH_SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')" >> .env
echo "MCP_API_KEY=$(python3 -c 'import secrets; print("wazuh_" + secrets.token_urlsafe(32))')" >> .env
```

Build and start the server, then check it:

```bash
docker compose up -d --build
curl http://localhost:3000/health     # liveness
curl http://localhost:3000/ready      # checks Manager/Indexer reachability
```

Exchange the API key for a bearer token (valid for `TOKEN_LIFETIME_HOURS`, default 24):

```bash
curl -s -X POST http://localhost:3000/auth/token -H 'Content-Type: application/json' \
  -d "{\"api_key\": \"$(grep ^MCP_API_KEY= .env | cut -d= -f2)\"}"
```

The key is read-only. To allow active-response tools, add `MCP_API_KEY_SCOPES="wazuh:read wazuh:write"` to `.env`, recreate the container with `docker compose up -d` (`restart` keeps the old environment), and mint a new token.

Compose publishes the port on `127.0.0.1` only. The server speaks plain HTTP; put a TLS-terminating reverse proxy in front before exposing it (set `MCP_BIND` to change the host bind address).

### Running from source

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
set -a; . ./.env; set +a              # the server reads the environment, not .env
.venv/bin/wazuh-mcp                   # or: .venv/bin/python -m wazuh_mcp
```

Requires Python 3.11 or later. Optional extras: `redis` (Redis session store) and `gcf` (`RESPONSE_FORMAT=gcf`).

### Tests

```bash
.venv/bin/python -m pytest -q
```

---

## Connecting Clients

All clients use the Streamable HTTP endpoint `https://<your-host>/mcp`.

| Client | Auth mode | How it authenticates |
|--------|-----------|----------------------|
| Claude custom connectors (claude.ai, Claude Desktop) | `oauth` | OAuth authorization code with PKCE. The server pre-registers a public client, `claude-desktop`, for Claude's callback URLs. Users sign in on the server's `/oauth/authorize` page with a `wazuh_` API key (the grant is capped at that key's scopes), or at your OpenID Connect provider when `OAUTH_IDP_ISSUER` is set. |
| Open WebUI, LibreChat, scripts and other MCP clients | `bearer` (default) | `Authorization: Bearer <token>` using a token from `POST /auth/token`. |

In OAuth mode, set `OAUTH_ISSUER_URL` to the server's public HTTPS URL (otherwise it is derived from each request, which behind a proxy may not be the public URL). Dynamic Client Registration (`/oauth/register`) is off unless `OAUTH_ENABLE_DCR=true`, and cannot be combined with `OAUTH_IDP_ISSUER`.

Guides: [Claude Integration](docs/CLAUDE_INTEGRATION.md) and [Local LLMs](docs/LOCAL_LLM.md).

---

## Local LLMs

The server does not call a model; it only executes tools. To keep SIEM data on-premises, pair it with a local model:

```bash
cat >> .env <<ENVEND
VLLM_API_KEY=$(openssl rand -hex 32)
WEBUI_SECRET_KEY=$(openssl rand -hex 32)
ENVEND
docker compose -f compose.yml -f compose.local-llm.yml up -d
```

This adds vLLM (default model Qwen3.6-35B-A3B FP8, about 42 GB of VRAM on one NVIDIA GPU; not published on a host port) and Open WebUI on `127.0.0.1:8080`. In Open WebUI's admin settings, add an MCP (Streamable HTTP) tool server at `http://wazuh-mcp:3000/mcp` with a bearer token.

For smaller models, expose fewer tools with `WAZUH_TOOLSETS` / `WAZUH_DISABLED_TOOLS`, and check tool selection before rollout with `evals/tool_selection.py` (25 SOC scenarios, including two prompt-injection cases, against any OpenAI-compatible endpoint; no tools are executed). Model sizing, Ollama and LiteLLM are covered in the [Local LLM Guide](docs/LOCAL_LLM.md).

---

## Tools

55 tools, grouped into toolsets that can be enabled with `WAZUH_TOOLSETS` (comma-separated; default all). R = `wazuh:read`, W = `wazuh:write`.

| Toolset | Count | Tools |
|---------|-------|-------|
| `alerts` | 5 R | `get_wazuh_alerts`, `get_wazuh_alert_summary`, `get_alerts_aggregated`, `analyze_alert_patterns`, `search_security_events` |
| `agents` | 6 R | `get_wazuh_agents`, `get_wazuh_running_agents`, `check_agent_health`, `get_agent_processes`, `get_agent_ports`, `get_agent_configuration` |
| `vulnerabilities` | 3 R | `get_wazuh_vulnerabilities`, `get_wazuh_critical_vulnerabilities`, `get_wazuh_vulnerability_summary` |
| `analysis` | 5 R | `analyze_security_threat`, `check_ioc_reputation`, `perform_risk_assessment`, `get_top_security_threats`, `generate_security_report` |
| `web_search` | 1 R | `search_external_context`: You.com web search; returns a "not enabled" result unless `YDC_API_KEY` is set |
| `compliance` | 6 R | `run_compliance_check` (PCI-DSS, HIPAA, SOX, GDPR, NIST, ISO27001), `get_iso27001_dashboard`, `get_iso27001_control_detail`, `get_iso27001_gap_analysis`, `get_iso27001_alerts`, `get_sca_policy_checks` |
| `system` | 10 R | `get_wazuh_statistics`, `get_wazuh_weekly_stats`, `get_wazuh_cluster_health`, `get_wazuh_cluster_nodes`, `get_wazuh_rules_summary`, `get_wazuh_remoted_stats`, `get_wazuh_log_collector_stats`, `search_wazuh_manager_logs`, `get_wazuh_manager_error_logs`, `validate_wazuh_connection` |
| `response` (containment) | 9 W | `wazuh_block_ip`, `wazuh_isolate_host`, `wazuh_kill_process`, `wazuh_disable_user`, `wazuh_quarantine_file`, `wazuh_firewall_drop`, `wazuh_host_deny`, `wazuh_active_response`, `wazuh_restart` |
| `response` (rollback) | 5 W | `wazuh_unisolate_host`, `wazuh_enable_user`, `wazuh_restore_file`, `wazuh_firewall_allow`, `wazuh_host_allow` |
| `response` (verification) | 5 R | `wazuh_check_blocked_ip`, `wazuh_check_agent_isolation`, `wazuh_check_process`, `wazuh_check_user_status`, `wazuh_check_file_quarantine` |

- Totals: 41 read tools and 14 write tools in the default catalog. Tokens without `wazuh:write` do not see the write tools in `tools/list`.
- In multi-cluster mode a 56th tool, `list_wazuh_clusters` (`system`, read), is added and every tool accepts an optional `cluster_id`.
- `WAZUH_DISABLED_TOOLS` hides individual tools. Hidden tools are removed from `tools/list` and refused by `tools/call`; unknown toolset or tool names stop the server at startup.
- Every tool carries MCP annotations derived from its scope: read tools are `readOnlyHint: true`; containment tools are `destructiveHint: true`; rollback tools are `destructiveHint: false`; only `search_external_context` is `openWorldHint: true`.
- Input schemas are closed (`additionalProperties: false`); undeclared arguments are refused.
- Timestamp filters accept ISO 8601 or OpenSearch date math (`now-24h`).
- Prompts: `security_investigation`, `threat_hunt`, `compliance_audit`, `vulnerability_assessment`, `iso27001_assessment`.

Per-tool parameters: [API documentation](docs/api/).

### Active response behaviour

- Results report `execution_status: "dispatched"`: Wazuh confirms the command was delivered to the agent, not that it ran. Confirm the effect with the matching `wazuh_check_*` tool.
- Blocks are permanent until removed. Wazuh ignores the timeout for API-triggered commands, so a positive `duration` is refused.
- `wazuh_firewall_allow` and `wazuh_host_allow` require an operator-deployed undo command (`WAZUH_AR_FIREWALL_UNDO_COMMAND`, `WAZUH_AR_HOSTDENY_UNDO_COMMAND`); without one they refuse.

---

## Security Model

| Control | Behaviour |
|---------|-----------|
| Scopes (RBAC) | Each tool requires `wazuh:read` or `wazuh:write`. A token without a scope claim is read-only. `MCP_API_KEY` is read-only unless `MCP_API_KEY_SCOPES` includes `wazuh:write`. With `AUTH_MODE=none`, write tools are disabled unless `AUTHLESS_ALLOW_WRITE=true`. |
| Bearer tokens | JWTs signed with `AUTH_SECRET_KEY`, must carry `exp`, and are bound to the API key they were minted from: revoking or rotating the key invalidates its tokens. Refresh tokens are not accepted as access tokens. |
| OAuth | Authorization code flow with mandatory S256 PKCE, single-use codes, refresh-token rotation with replay detection, and revocation. Users sign in with a `wazuh_` API key (the grant is capped at that key's scopes, and its tokens end when the key is revoked) or at an OpenID Connect provider (ID token signature, issuer, audience, expiry and nonce verified; tenant, domain and user allow-lists; group-to-scope mapping), so scopes, rate limits and audit entries are per user. |
| Action guardrails | IP-blocking tools refuse loopback, the Manager's address (when `WAZUH_HOST` is an IP) and anything in `WAZUH_PROTECTED_IPS`; the generic active-response tool does not dispatch IP blocks, quarantine, process kills or account disables. Actions and restarts aimed at agent `000` (the Manager) need `WAZUH_ALLOW_MANAGER_AR=true`; fleet-wide blocks need `WAZUH_ALLOW_FLEET_AR=true`; quarantine refuses system and agent directories. In production, write tools require `confirm=true` (`WAZUH_REQUIRE_ACTION_CONFIRMATION`). |
| Wazuh TLS | The Manager and Indexer certificates are verified by default, against the system store or `WAZUH_CA_BUNDLE`. Disabling Manager verification (`WAZUH_ALLOW_SELF_SIGNED=true`) is logged at startup, as an error in production. |
| Audit log | Every write-tool call that passes the scope and confirmation checks is logged before and after execution (logger `wazuh_mcp.audit`) with the principal, session, arguments and outcome. |
| Redaction | Credentials and tokens are redacted from tool output in every response format, and from server logs. |
| Input validation | Typed validation of agent IDs, IPs, paths and command names; Indexer queries are built as Query DSL, not by string interpolation. |
| Rate limiting | Sliding window, default 100 requests per 60 s (`RATE_LIMIT_REQUESTS`, `RATE_LIMIT_WINDOW`): per principal and client IP on `/mcp` and `/`, per client IP on other endpoints except the probe endpoints (`/health`, `/ready`, `/metrics` and their `/healthz`, `/readyz`, `/live`, `/livez` aliases). Failed authentication is rate limited by client IP. Set `TRUSTED_PROXIES` when running behind a proxy. |
| Resource bounds | Circuit breaker on Wazuh calls: opens after 5 consecutive failures, retries after 60 s. Oversized tool results are truncated with a note (`MAX_TOOL_RESPONSE_CHARS`). `limit` on `get_wazuh_alerts` and `search_security_events` is capped at `MAX_ALERTS_PER_QUERY` (default 1000). The in-memory session store is capped at `MAX_SESSIONS` (1000) and `MAX_SESSIONS_PER_PRINCIPAL` (100), and stored client metadata is truncated. |
| Container | Runs as UID 1000; `compose.yml` sets a read-only root filesystem, `cap_drop: ALL` and `no-new-privileges`. The runtime image does not include pip. |

There is no built-in TLS listener; terminate TLS at a reverse proxy or load balancer. For security issues, contact the maintainer privately rather than opening a public issue.

---

## Configuration

All settings are environment variables (usually via `.env`). The ones most deployments touch:

| Variable | Default | Purpose |
|----------|---------|---------|
| `WAZUH_HOST`, `WAZUH_USER`, `WAZUH_PASS` | (none) | Manager API connection (required) |
| `WAZUH_PORT` | `55000` | Manager API port |
| `WAZUH_CA_BUNDLE` | (none) | CA PEM used instead of the system store to verify the Manager and Indexer; see [Manager TLS](docs/configuration.md#manager-tls) |
| `WAZUH_ALLOW_SELF_SIGNED` | `false` | `true` connects to the Manager without certificate verification (logged at startup) |
| `WAZUH_INDEXER_HOST`, `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASS` | (none) | Indexer connection; an `http://` host prefix selects plain HTTP |
| `WAZUH_INDEXER_PORT` | `9200` | Indexer port |
| `ENVIRONMENT` | `development` | `production` requires a strong `AUTH_SECRET_KEY` (unless `AUTH_MODE=none`) |
| `AUTH_MODE` | `bearer` | `bearer`, `oauth` or `none` |
| `AUTH_SECRET_KEY` | generated per process outside production | Token signing key; use the same value on every instance |
| `MCP_API_KEY` / `API_KEYS` | generated per process if unset (printed only in development) | A single `wazuh_` key, or a JSON list of hashed keys with per-key scopes |
| `MCP_API_KEY_SCOPES` | `wazuh:read` | Space-separated scopes for `MCP_API_KEY` |
| `OAUTH_ISSUER_URL` | derived from the request | Public HTTPS URL of the server, for `AUTH_MODE=oauth` |
| `OAUTH_IDP_ISSUER` | (none) | OpenID Connect provider for OAuth sign-in (with `OAUTH_IDP_CLIENT_ID`); API-key sign-in when unset |
| `WAZUH_REQUIRE_ACTION_CONFIRMATION` | `true` in production, else `false` | Write tools require `confirm=true` |
| `MCP_HOST`, `MCP_PORT` | `127.0.0.1` (`0.0.0.0` in the Docker image), `3000` | Bind address and port |
| `ALLOWED_ORIGINS` | `https://claude.ai,http://localhost:3000` | CORS allow-list (exact match) |
| `WAZUH_TOOLSETS`, `WAZUH_DISABLED_TOOLS` | all enabled | Limit the exposed tools |
| `REDIS_URL` | (none) | Shared session store for multi-instance deployments |
| `WAZUH_CLUSTERS_FILE` | `./config/clusters.json` | Multi-cluster topology; single-cluster mode when absent |
| `RESPONSE_FORMAT` | `json` | `gcf` encodes alert, event and vulnerability collections in the compact GCF format (lossless; falls back to JSON if the encoder is unavailable) |
| `YDC_API_KEY` | (none) | Enables `search_external_context` |

Complete reference, including OAuth TTLs, rate limits, sessions and active-response settings: [Configuration Guide](docs/configuration.md). Multi-cluster setup: [Multi-Cluster Guide](docs/MULTI_CLUSTER.md) and [`config/clusters.json.example`](config/clusters.json.example).

---

## HTTP Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/mcp` | POST, GET, DELETE | MCP Streamable HTTP |
| `/` | POST, GET | Same handler as `/mcp` |
| `/sse` | GET, POST | Returns `410 Gone`; use `/mcp` |
| `/health` | GET | Liveness; no dependency checks |
| `/ready` | GET | Readiness; 503 when the Manager, Indexer or memory headroom check fails |
| `/metrics` | GET | Prometheus metrics |
| `/auth/token` | POST | Exchange an API key for a bearer JWT |
| `/.well-known/oauth-authorization-server` | GET | OAuth metadata (RFC 8414), `AUTH_MODE=oauth` only |
| `/.well-known/oauth-protected-resource` | GET | Protected-resource metadata (RFC 9728), `AUTH_MODE=oauth` only |
| `/oauth/authorize`, `/oauth/token`, `/oauth/revoke`, `/oauth/register`, `/oauth/callback` | GET/POST | OAuth endpoints, `AUTH_MODE=oauth` only (`/oauth/register` requires `OAUTH_ENABLE_DCR=true` and no `OAUTH_IDP_ISSUER`; `/oauth/callback` is the OpenID Connect redirect URI and needs `OAUTH_IDP_ISSUER`) |
| `/docs`, `/redoc`, `/openapi.json` | GET | OpenAPI documentation |

---

## Project Layout

- `Dockerfile`: multi-stage image build (Alpine, non-root UID 1000)
- `compose.yml`: production compose file; service `wazuh-mcp`, read-only root filesystem
- `compose.dev.yml`: development compose file; mounts `src/` into the container
- `compose.local-llm.yml`: optional vLLM and Open WebUI stack, added with `-f`
- `.env.example`: configuration template (copy to `.env`)
- `.dockerignore`, `.gitignore`: build context and git exclusions
- `pyproject.toml`: package metadata (`wazuh-mcp` 0.1.0), dependencies and extras
- `requirements.txt`: dependency list installed by the Docker builder stage
- `WAZUH_COMPATIBILITY.md`: supported Wazuh versions and API notes
- `LICENSE`: MIT license
- `config/clusters.json.example`: multi-cluster topology example
- `docs/`: operator guides and the per-tool API reference
- `evals/`: tool-selection evaluation harness (`tool_selection.py`) and 25 SOC scenarios (`scenarios.json`)
- `tests/integration/`: pytest suite, one file per area (auth, OAuth, MCP protocol, scope enforcement, active response, and so on)
- `src/wazuh_mcp/`: the server package
  - `__init__.py`: package metadata
  - `__main__.py`: CLI entry point (`wazuh-mcp`, `python -m wazuh_mcp`)
  - `config.py`: environment configuration and startup validation
  - `auth.py`: API keys and bearer JWTs
  - `oauth.py`: OAuth 2.0 authorization server (PKCE, API-key sign-in)
  - `oidc.py`: OpenID Connect sign-in at an external identity provider
  - `security.py`: rate limiting, input validation, log redaction
  - `toolsets.py`: toolset membership, `WAZUH_TOOLSETS` resolution, tool annotations
  - `clusters.py`: multi-cluster registry and routing
  - `session_store.py`: in-memory and Redis session storage
  - `resilience.py`: circuit breakers, retries, timeouts
  - `monitoring.py`: Prometheus metrics and structured logging
  - `gcf_format.py`: optional GCF response encoding
  - `server/`: FastAPI application and MCP protocol handling
    - `__init__.py`: package entry point (the FastAPI app)
    - `app.py`: lifespan, middleware stack and router registration
    - `transport.py`: HTTP routes `/mcp`, `/` and `/sse` (410 Gone)
    - `http_security.py`: authentication, rate limiting, CORS and Origin checks
    - `ops.py`: health, readiness, metrics, OAuth metadata and the token endpoint
    - `jsonrpc.py`: JSON-RPC 2.0 models and envelope helpers
    - `dispatch.py`: routes JSON-RPC methods to their handlers
    - `handlers.py`: initialize, ping, logging, prompts, resources and completion
    - `tool_catalog.py`: `tools/list` handler and tool argument-name lookup
    - `tool_calls.py`: `tools/call` handler (validation, dispatch, response shaping)
    - `tool_policy.py`: scope classification (`READ_SCOPE_TOOLS`, `WRITE_SCOPE_TOOLS`) and action guardrails
    - `output.py`: redaction and compaction of tool output
    - `sessions.py`: MCP session model and bounded session creation
    - `state.py`: runtime singletons read at call time
    - `constants.py`: protocol versions, method tables, limits and error codes
  - `api/`: Wazuh backend clients
    - `wazuh_client.py`: Wazuh Manager REST API client
    - `wazuh_indexer.py`: Wazuh Indexer (OpenSearch) client

---

## Documentation

| Document | Contents |
|----------|----------|
| [Configuration Guide](docs/configuration.md) | Every environment variable, auth modes, RBAC |
| [Claude Integration](docs/CLAUDE_INTEGRATION.md) | Connecting Claude custom connectors |
| [Local LLM Guide](docs/LOCAL_LLM.md) | vLLM, Open WebUI, Ollama, LiteLLM, tool-selection eval |
| [Multi-Cluster](docs/MULTI_CLUSTER.md) | Named clusters and Cross-Cluster Search |
| [Operations](docs/OPERATIONS.md) | Deployment, monitoring, maintenance |
| [Advanced Features](docs/ADVANCED_FEATURES.md) | Multi-instance deployment, compact output |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common problems and fixes |
| [API Reference](docs/api/) | Per-tool parameters |
| [Security Hardening](docs/security/) | Hardening guidance |
| [Wazuh Compatibility](WAZUH_COMPATIBILITY.md) | Supported Wazuh versions |

Bugs and feature requests: [GitHub issues](https://github.com/leonfullxr/Wazuh/issues). For security issues, contact the maintainer privately rather than opening a public issue.

---

## License

MIT. See [LICENSE](LICENSE).
