# Check the owner before using a legacy session

P1 · Medium · Medium change risk · Independent. Planned at `cccb1e8` on 2026-11-20. Status: implemented. See the [combined verification record](../../docs/delivery_report.md).

## Current behavior and evidence

Session creation at sessions.py:294 stores `session.principal = principal`. Transport lookup at transport.py:406 touches the returned session, and deletion at line 616 removes it, without comparing its owner. Tools still receive the current request token. The regression concerns session integrity and attribution.

## Ownership and setup

Run commands from `mcp-server/` in a dedicated worktree using GPT-6.1 Terra at high effort. The coordinator maintains the index. Write scope is limited to the following paths.

- `src/wazuh_mcp/server/transport.py`
- `src/wazuh_mcp/auth.py`
- `src/wazuh_mcp/server/http_security.py`
- `tests/integration/test_business_logic.py`
- `src/wazuh_mcp/server/sessions.py`
- `tests/integration/test_session_memory_bound.py`
- `tests/integration/test_mcp_protocol.py`

Compare the current checkout with the baseline using `git diff cccb1e8..HEAD -- src/wazuh_mcp/server/transport.py src/wazuh_mcp/auth.py src/wazuh_mcp/server/http_security.py tests/integration/test_business_logic.py src/wazuh_mcp/server/sessions.py tests/integration/test_session_memory_bound.py tests/integration/test_mcp_protocol.py`. Reconcile expected predecessors against the behavior above. Use a worktree-local Python 3.11+ environment installed with `python3 -m venv .venv && .venv/bin/python -m pip install -e '.[dev]'`. Confirm `.venv/bin/python -c 'import wazuh_mcp; print(wazuh_mcp.__file__)'` points into this worktree.

## Implementation contract

Persist a versioned owner identity derived at authentication. Retain the existing principal used for capacity limits. Centralize owned lookup for legacy GET, POST and DELETE and the existing-ID path of `get_or_create_session`. Check ownership before timestamp update, expiry removal or deletion. Unknown and foreign IDs receive the same 404 on public routes. Ownerless persisted records require a fresh initialize. Authless records with the explicit shared authless principal remain usable in authless mode. For the helper, never turn a supplied unknown/foreign ID into a new persisted session. Keep stateless requests independent of the store.

**Owner identity.** The current principal is lossy. Authless uses the literal `authless`, API-key IDs are operator-configurable strings, JWTs use `jwt:<sub>` or a token digest, and OAuth flattens client and subject into a colon-separated string. Use a typed owner with separate fields for credential family, security domain/issuer where applicable, client and subject (including OAuth subject kind). Construct it from verified credentials and server configuration. Keep delimiters in individual fields. A subjectless OAuth client represents that client only. Reject an ambiguous or absent identity. A subjectless bearer whose only identity is its token digest may reuse a session with that credential for its lifetime. Refresh with the same stable identity retains ownership. Test overlapping IDs across families and credential refresh. Authless records require an authless server. A missing, empty, whitespace-only or pre-upgrade owner requires reinitialization.

`MCPSession.to_dict` and `_session_from_dict` already persist the legacy principal. Extend both for the typed owner. In-memory get and Redis GET are read-only. Prove survival across serialization with both real store classes, a stub Redis client and a freshly constructed SessionManager over the same data. Foreign GET, POST and DELETE must leave payload, expiry, activity, initialized-session cache and Redis writes unchanged, including a foreign expired record. Reject GET before producing an SSE stream. Centralize the verified owner lookup and deletion in sessions.py. Use an internal session-not-found exception for an invalid supplied ID and map it to the same public 404. Only the owner may trigger expiry cleanup in this lookup. Update the existing business-logic fixation test for supplied unknown IDs and retain its UUID assertion for a fresh handshake. Check a denied request racing an allowed one leaves the owner unchanged.

## Acceptance tests

Use synthetic principals and the in-memory and Redis adapter fixtures. Cover own, foreign, expired, ownerless and unknown sessions and a refreshed token representing the same principal. Verify denied lookups leave the record and its activity timestamp untouched. Exercise root aliases, /mcp, DELETE and authorized streaming via the existing generator test pattern without waiting for a live stream. Check modern requests with a session header still follow stateless handling.

1. Run `.venv/bin/python -m pytest -q tests/integration/test_session_memory_bound.py tests/integration/test_mcp_protocol.py tests/integration/test_runtime_edge_cases.py` against the current checkout. Add the targeted expectations above and confirm the regression test distinguishes the current and required behavior.
2. Implement the contract, then rerun the focused command. All specified behaviors must pass.
3. Run `.venv/bin/ruff check --no-cache .`, `.venv/bin/python -m pytest -q` and `git diff --check`. Require zero exit status and inspect `git status --short` for scope. Report commands, counts, skips, and the diff to the coordinator for integrated verification.

## Maintenance and scope decisions

Every legacy session created before the typed-owner deployment requires one new handshake. Drain old replicas before opening the shared session namespace to upgraded replicas. Modern stateless clients can continue normally.
