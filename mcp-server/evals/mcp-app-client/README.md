# Optional MCP Apps client verification

This offline-data pilot exercises the server using the official TypeScript MCP client and Apps `AppBridge` in a sandboxed Chrome iframe. It checks initialization, tool and resource discovery, the timeline viewer, matching structured and JSON text results, and evidence lookup. The fixture is adapted from `tests/integration/test_investigation_http_workflow.py`; it injects synthetic authentication, a mock manager and indexer, and skips the server lifespan. It does not test production credentials, startup, deployment, or an existing MCP host application.

Requirements: Node.js 20+, npm registry access, a Python environment with the server dependencies (default `mcp-server/.venv/bin/python`), and a local Chrome executable. The runner installs exactly pinned npm dependencies in a temporary directory and removes it afterward. It starts two loopback-only servers and stops them when finished.

From `mcp-server`:

```sh
CHROME_PATH=/usr/bin/google-chrome ./evals/mcp-app-client/run.sh
```

Set `MCP_PYTHON` to another Python executable if needed. If `CHROME_PATH` is omitted, Playwright uses its installed Chromium. Browser binaries are not downloaded by this runner. Loopback connections must be permitted by the execution environment.
