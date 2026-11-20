# Preserve registered OAuth callback queries

P2 · Small · Low change risk · Independent. Planned at `cccb1e8` on 2026-11-20. Status: implemented. See the [combined verification record](../../docs/delivery_report.md).

## Current behavior and evidence

Redirect registration at oauth.py:246 accepts HTTPS URLs with query strings. Success and error paths append a fresh `?`, for example `RedirectResponse(f"{redirect_uri}?{urlencode(params)}", status_code=303)` at line 1071. This can turn a returned authorization code into part of the existing query value.

## Ownership and setup

Run commands from `mcp-server/` in a dedicated worktree using GPT-6.1 Terra at high effort. The coordinator maintains the index. Write scope is limited to the following paths.

- `src/wazuh_mcp/oauth.py`
- `tests/integration/test_oauth.py`
- `tests/integration/test_oauth_login.py`
- `tests/integration/test_oidc_identity_provider.py`

Compare the current checkout with the baseline using `git diff cccb1e8..HEAD -- src/wazuh_mcp/oauth.py tests/integration/test_oauth.py tests/integration/test_oauth_login.py tests/integration/test_oidc_identity_provider.py`. Reconcile expected predecessors against the behavior above. Use a worktree-local Python 3.11+ environment installed with `python3 -m venv .venv && .venv/bin/python -m pip install -e '.[dev]'`. Confirm `.venv/bin/python -c 'import wazuh_mcp; print(wazuh_mcp.__file__)'` points into this worktree.

## Implementation contract

Use one helper for registered client redirects, including API-key and IdP success/error paths at lines 858, 868, 928, 976, 1063 and 1071. Append encoded response parameters to the existing raw query and preserve path, percent encoding, duplicate unrelated parameters, redirect status and cache headers. Keep exact registered-URI comparison and fragment rejection. Define reserved callback names (`code`, `state`, `iss`, `error`, `error_description`, `error_uri`) as invalid in a registered callback query. Reject them at both registration and authorization before redirect. Do not rewrite the IdP authorization endpoint.

Treat reserved response parameter names case-insensitively as an explicit local registration policy. Decode query keys once for inspection, including bare keys and encoded names. Preserve unrelated raw query bytes and ordering. Append after an existing trailing `?` or `&` directly, otherwise choose `?` for no query and `&` for an existing query. Dynamic registration returns HTTP 400 with OAuth error `invalid_redirect_uri`. If a preconfigured or pending callback violates the same policy, fail directly with HTTP 400 and no Location header. Audit every client-facing RedirectResponse/Location in _check_request, callback and authorize_submit. The IdP authorization redirect has a separate destination contract. Retain exact redirect URI matching for registration lookup and code exchange.

Test encoded and mixed-case reserved keys, a bare key, a duplicate, trailing delimiters, static clients in both login modes, successful exchange with the original exact URI and rejection with an altered query. Use distinct fresh codes for exchange cases.

## Acceptance tests

Extend the existing route tests using ASGITransport. Parse `Location` and assert original parameters and one copy of each response parameter, on success and on a client-facing error, with and without a preexisting query. Include unrelated repeated parameters, an encoded value, absent state, reserved-key rejection, and an unregistered URI. Preserve current HTTP status and cache headers.

1. Run `.venv/bin/python -m pytest -q tests/integration/test_oauth.py tests/integration/test_oauth_login.py tests/integration/test_oidc_identity_provider.py` against the current checkout. Add the targeted expectations above and confirm the regression test distinguishes the current and required behavior.
2. Implement the contract, then rerun the focused command. All specified behaviors must pass.
3. Run `.venv/bin/ruff check --no-cache .`, `.venv/bin/python -m pytest -q` and `git diff --check`. Require zero exit status and inspect `git status --short` for scope. Report commands, counts, skips, and the diff to the coordinator for integrated verification.

## Maintenance and scope decisions

Retain exact-string redirect comparison during code exchange. Document rejection if a deployment offers configurable pre-registered callbacks containing reserved names.
