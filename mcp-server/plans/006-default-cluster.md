# Resolve resource reads through the configured default cluster

P2 · Small · Medium change risk · After 001. Planned at `cccb1e8` on 2026-11-20. Status: implemented. See the [combined verification record](../../docs/delivery_report.md).

## Current behavior and evidence

In multi-cluster mode `cluster_registry.get(None)` returns the configured default. Tools use this lookup at tool_calls.py:91. All nine resource variants at handlers.py:457–473 directly call `state.wazuh_client`, the environment-configured Manager/Indexer. Two ways of asking for the same data can silently select different clusters.

## Ownership and setup

Run commands from `mcp-server/` in a dedicated worktree using GPT-6.1 Terra at high effort. The coordinator maintains the index. Write scope is limited to the following paths.

- `src/wazuh_mcp/server/handlers.py`
- `tests/integration/test_scope_enforcement.py`
- `tests/integration/test_clusters.py`
- `tests/integration/test_input_validation.py`
- `docs/MULTI_CLUSTER.md`

Compare the current checkout with the baseline using `git diff cccb1e8..HEAD -- src/wazuh_mcp/server/handlers.py tests/integration/test_scope_enforcement.py tests/integration/test_clusters.py tests/integration/test_input_validation.py docs/MULTI_CLUSTER.md`. Reconcile expected predecessors against the behavior above. Use a worktree-local Python 3.11+ environment installed with `python3 -m venv .venv && .venv/bin/python -m pip install -e '.[dev]'`. Confirm `.venv/bin/python -c 'import wazuh_mcp; print(wazuh_mcp.__file__)'` points into this worktree.

## Implementation contract

Resolve the registry default once per authorized valid resource read. Preserve every existing URI and envelope and the permission check landed by 001. The separate, documented /ready behavior probes the environment cluster. Document the resource default, an example where it differs and the operator migration effect.

Use the registry contract that already serves tools. In single-cluster mode `get(None)` resolves the environment client. In multi-cluster mode it resolves the named default. Validate a permitted URI before registry lookup. Verify zero registry calls for an unknown or malformed URI. The shared scope tests may update their client stub after 001. Assert the existing generic -32603 backend error code at dispatch and leave public error sanitization to 004. Document that an environment-only green readiness probe does not establish reachability of a different named default.

## Acceptance tests

Use distinct spy clients in test_clusters.py for environment and named default. For all six concrete resources and three templates, assert only the resolved client is called, once with normalized arguments. Verify single-cluster behavior, authorization denial before lookup, and correct backend-error translation. Update the `TestResources._read` stub at test_input_validation.py:527 to stub the registry at the same boundary.

1. Run `.venv/bin/python -m pytest -q tests/integration/test_clusters.py tests/integration/test_input_validation.py tests/integration/test_scope_enforcement.py` against the current checkout. Add the targeted expectations above and confirm the regression test distinguishes the current and required behavior.
2. Implement the contract, then rerun the focused command. All specified behaviors must pass.
3. Run `.venv/bin/ruff check --no-cache .`, `.venv/bin/python -m pytest -q` and `git diff --check`. Require zero exit status and inspect `git status --short` for scope. Report commands, counts, skips, and the diff to the coordinator for integrated verification.

## Maintenance and scope decisions

Operators who relied on resource URIs always using the environment cluster will see the configured default after rollout. Explicit cluster URIs are a later product decision.
