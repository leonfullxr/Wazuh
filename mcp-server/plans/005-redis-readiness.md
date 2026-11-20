# Make Redis session-store failures visible to readiness

P1 · Small · Low change risk · Independent. Planned at `cccb1e8` on 2026-11-20. Status: implemented. See the [combined verification record](../../docs/delivery_report.md).

## Current behavior and evidence

At session_store.py:311 initialization happens before the try block, but line 316 returns `0` on a later SCAN failure. At ops.py:125 readiness accepts the count as valid. A mock initialized Redis store with a failing scan returned HTTP 200. The operations guide at docs/OPERATIONS.md:52 promises 503 when a configured session store fails.

## Ownership and setup

Run commands from `mcp-server/` in a dedicated worktree using GPT-6.1 Terra at high effort. The coordinator maintains the index. Write scope is limited to the following paths.

- `src/wazuh_mcp/session_store.py`
- `tests/integration/test_health.py`

Compare the current checkout with the baseline using `git diff cccb1e8..HEAD -- src/wazuh_mcp/session_store.py tests/integration/test_health.py`. Reconcile expected predecessors against the behavior above. Use a worktree-local Python 3.11+ environment installed with `python3 -m venv .venv && .venv/bin/python -m pip install -e '.[dev]'`. Confirm `.venv/bin/python -c 'import wazuh_mcp; print(wazuh_mcp.__file__)'` points into this worktree.

## Implementation contract

Follow RedisSessionStore.get error translation at session_store.py:214. Preserve valid counts including zero, propagate a `SessionStoreUnavailable` when count cannot complete, and use the existing outer readiness failure response in ops.py:204. Readiness results are cached five seconds; reset or advance that cache in tests.

The production Redis count path is the readiness call in ops.py. SessionManager.count delegates to its store, but the session cap returns before count for a Redis store. Liveness and Prometheus collection do not call it. The outer probe exception handler already returns 503 with `status: unhealthy` and a timestamp. Keep the session-prefix SCAN. Bound the complete scan across all pages to the readiness probe budget (use a five-second maximum if no shorter configured budget exists). Normalize initialization, timeout and later-page errors without converting caller cancellation. Test failure before the first scan, a cancelled count, a stalled page and cache expiry followed by recovery. Inspect the HTTP body for absence of backend diagnostics.

## Acceptance tests

Through the ASGI probe in test_health.py, use a real RedisSessionStore instance with the Redis transport stubbed. Test empty healthy storage, failure after initialization, a failure on a later SCAN page, a fresh successful evaluation after the failure cache expires, and independent liveness. Expect 503 without backend diagnostics for failure and 200 for an empty healthy store. Keep Redis tests deterministic and offline.

1. Run `.venv/bin/python -m pytest -q tests/integration/test_health.py tests/integration/test_runtime_edge_cases.py` against the current checkout. Add the targeted expectations above and confirm the regression test distinguishes the current and required behavior.
2. Implement the contract, then rerun the focused command. All specified behaviors must pass.
3. Run `.venv/bin/ruff check --no-cache .`, `.venv/bin/python -m pytest -q` and `git diff --check`. Require zero exit status and inspect `git status --short` for scope. Report commands, counts, skips, and the diff to the coordinator for integrated verification.

## Maintenance and scope decisions

Retain the existing probe cache and public response shape. Keep the Redis count on the SCAN path so readiness avoids fetching every session payload.
