# Local stand-in

Run `wazuh-mcp` without a Wazuh cluster and without Docker. `dev/standin.py` is a stdlib HTTPS Manager API (port 55000) and an HTTP Indexer (port 9200), seeded with agents, alerts, vulnerabilities, SCA policies, and manager logs. It needs `openssl` on `PATH` to mint a one-day certificate. The Manager client always uses HTTPS, so start the MCP server with `WAZUH_ALLOW_SELF_SIGNED=true`.

## 1. Start the stand-in

From `mcp-server/`:

```bash
python3 dev/standin.py
```

Leave it running. It listens on `127.0.0.1` only.

| Service | URL | Credentials |
|---------|-----|-------------|
| Manager API | `https://127.0.0.1:55000` | `wazuh` / `wazuh` |
| Indexer | `http://127.0.0.1:9200` | `admin` / `admin` |

The alert tie-breaker field for `wazuh-mcp-preflight` is `event.id`.

## 2. Install and start the MCP server

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

Shared connection settings:

```bash
export WAZUH_HOST=127.0.0.1 WAZUH_PORT=55000 WAZUH_USER=wazuh WAZUH_PASS=wazuh
export WAZUH_ALLOW_SELF_SIGNED=true
export WAZUH_INDEXER_HOST=http://127.0.0.1 WAZUH_INDEXER_PORT=9200
export WAZUH_INDEXER_USER=admin WAZUH_INDEXER_PASS=admin WAZUH_INDEXER_VERIFY_SSL=false
export ENVIRONMENT=development MCP_HOST=127.0.0.1 LOG_LEVEL=INFO
```

Authless, including write tools (port 3000):

```bash
export AUTH_MODE=none AUTHLESS_ALLOW_WRITE=true MCP_PORT=3000
.venv/bin/wazuh-mcp
```

API key. The key must be `wazuh_` plus 43 characters:

```bash
export AUTH_MODE=bearer MCP_PORT=3001
export AUTH_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
export MCP_API_KEY="$(python3 -c 'import secrets; print("wazuh_"+secrets.token_urlsafe(32))')"
export MCP_API_KEY_SCOPES="wazuh:read wazuh:write"
.venv/bin/wazuh-mcp
# exchange the key:
curl -sS -X POST http://127.0.0.1:3001/auth/token -H 'Content-Type: application/json' \
  -d "{\"api_key\":\"$MCP_API_KEY\"}"
```

OAuth sign-in page (port 3002). Open the authorize URL in a browser; the pre-registered client is `claude-desktop`:

```bash
export AUTH_MODE=oauth MCP_PORT=3002 OAUTH_ISSUER_URL=http://127.0.0.1:3002
export AUTH_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
export MCP_API_KEY="$(python3 -c 'import secrets; print("wazuh_"+secrets.token_urlsafe(32))')"
export MCP_API_KEY_SCOPES="wazuh:read wazuh:write"
.venv/bin/wazuh-mcp
```

```text
http://127.0.0.1:3002/oauth/authorize?response_type=code&client_id=claude-desktop&redirect_uri=https%3A%2F%2Fclaude.ai%2Fapi%2Fmcp%2Fauth_callback&scope=wazuh%3Aread%20wazuh%3Awrite&state=demo&code_challenge=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&code_challenge_method=S256
```

Checks that do not need a browser:

```bash
curl -sS http://127.0.0.1:3000/health
curl -sS http://127.0.0.1:3000/ready
WAZUH_INDEXER_HOST=http://127.0.0.1 WAZUH_INDEXER_PORT=9200 \
  WAZUH_INDEXER_USER=admin WAZUH_INDEXER_PASS=admin WAZUH_INDEXER_VERIFY_SSL=false \
  .venv/bin/wazuh-mcp-preflight --cluster default --tie-breaker event.id
```

## 3. Call it with the official MCP SDK

`mcp` is the client, not a server dependency:

```bash
.venv/bin/pip install 'mcp>=1.8'
.venv/bin/python dev/exercise.py --url http://127.0.0.1:3000/mcp
# bearer:
.venv/bin/python dev/exercise.py --url http://127.0.0.1:3001/mcp --token "$ACCESS_TOKEN"
```

The script initializes, lists tools, prompts, and resources, then calls one tool from each toolset, including active response. It writes the full text to `/tmp/wazuh-mcp-transcript.json`.
