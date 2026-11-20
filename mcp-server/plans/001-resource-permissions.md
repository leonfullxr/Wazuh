# Enforce read permissions on MCP resources

P1 · Small · Low change risk · Independent. Planned at `cccb1e8` on 2026-11-20. Status: implemented. See the [combined verification record](../../docs/delivery_report.md).

## Current behavior and evidence

A resource exposes the same SIEM data as a read tool. The bearer or OAuth principal reaching the handler can have an empty or write-only effective scope. At handlers.py:434, `handle_resources_read` selects a backend using the URI without consulting the session token. At tool_calls.py:119, read tools call `auth_token.has_scope(required_scope)`. Both transports supply the request token.

## Ownership and setup

Run commands from `mcp-server/` in a dedicated worktree using GPT-6.1 Terra at high effort. The coordinator maintains the index. Write scope is limited to the following paths.

- `src/wazuh_mcp/server/handlers.py`
- `tests/integration/test_scope_enforcement.py`

Compare the current checkout with the baseline using `git diff cccb1e8..HEAD -- src/wazuh_mcp/server/handlers.py tests/integration/test_scope_enforcement.py`. Reconcile expected predecessors against the behavior above. Use a worktree-local Python 3.11+ environment installed with `python3 -m venv .venv && .venv/bin/python -m pip install -e '.[dev]'`. Confirm `.venv/bin/python -c 'import wazuh_mcp; print(wazuh_mcp.__file__)'` points into this worktree.

## Implementation contract

Use the current request’s effective `wazuh:read` scope for list, templates/list and read. Return empty lists when read is unavailable. Raise the existing `ResourceNotFound` with a constant public message for denied reads, before parsing the target or looking up a backend. `dispatch.py:100` already maps this to -32002. Preserve normal authless read access via the synthetic token. Scope this change to read permissions; operator toolset filters govern tools today.

Both supported transports are HTTP. Modern dispatch attaches `session._auth_token` to an ephemeral session. Legacy dispatch attaches it after loading the stored record. Dispatch passes that session to all three resource handlers. Use the attached token’s `has_scope("wazuh:read")` on each call. A missing token denies access. In transport tests initialize a separate session per principal, then reduce scopes on the same owner to prove the next request uses the new grant. Cover synthetic authless tokens on both paths.

Denied discovery returns exactly `{"resources":[]}` and `{"resourceTemplates":[]}`. A valid, unknown or malformed URI from a denied caller must produce the same code (-32002) and message (`Resource not found`) with zero registry or backend calls. Include an authorized read through dispatch. Static prompts and completion suggestions do not retrieve backend evidence.

## Acceptance tests

Use the `AuthToken` / stub pattern in test_scope_enforcement.py. Cover read-only, read+write, write-only, empty effective scopes and missing token. Assert zero backend calls and empty discovery on denial. Cover both a named resource and an agent template, a legacy request and a stateless request with its required metadata. Assert an authorized unknown URI still returns -32002.

1. Run `.venv/bin/python -m pytest -q tests/integration/test_scope_enforcement.py tests/integration/test_mcp_protocol.py tests/integration/test_input_validation.py` against the current checkout. Add the targeted expectations above and confirm the regression test distinguishes the current and required behavior.
2. Implement the contract, then rerun the focused command. All specified behaviors must pass.
3. Run `.venv/bin/ruff check --no-cache .`, `.venv/bin/python -m pytest -q` and `git diff --check`. Require zero exit status and inspect `git status --short` for scope. Report commands, counts, skips, and the diff to the coordinator for integrated verification.

## Maintenance and scope decisions

Keep authorization ahead of backend selection as resources are added. Escalate a proposed change to the public error code or to toolset membership as a separate design decision.
