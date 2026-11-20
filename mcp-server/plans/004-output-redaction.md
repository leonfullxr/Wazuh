# Redact tool and resource data before serialization

P1 · Medium · Medium change risk · After 002 and 006 for shared file ownership. Planned at `cccb1e8` on 2026-11-20. Status: implemented. See the [combined verification record](../../docs/delivery_report.md).

## Current behavior and evidence

Tool success applies `_sanitize_output_text(text)` at tool_calls.py:170 after encoding. output.py:10 handles textual labels, while quoted JSON object keys carry structured secrets. `_tool_error` at tool_calls.py:178 returns its text directly. Resource reads also serialize before cleaning at handlers.py:484. GCF uses `encode_generic(result)` at gcf_format.py:49.

## Ownership and setup

Run commands from `mcp-server/` in a dedicated worktree using GPT-6.1 Terra at high effort. The coordinator maintains the index. Write scope is limited to the following paths.

- `src/wazuh_mcp/server/output.py`
- `src/wazuh_mcp/server/dispatch.py`
- `src/wazuh_mcp/server/tool_policy.py`
- `src/wazuh_mcp/api/wazuh_client.py`
- `src/wazuh_mcp/security.py`
- `src/wazuh_mcp/server/tool_calls.py`
- `src/wazuh_mcp/server/handlers.py`
- `src/wazuh_mcp/gcf_format.py`
- `tests/integration/test_gcf_format.py`
- `tests/integration/test_output_redaction.py` (new)

Compare the current checkout with the baseline using `git diff cccb1e8..HEAD -- src/wazuh_mcp/server/output.py src/wazuh_mcp/server/dispatch.py src/wazuh_mcp/server/tool_policy.py src/wazuh_mcp/api/wazuh_client.py src/wazuh_mcp/security.py src/wazuh_mcp/server/tool_calls.py src/wazuh_mcp/server/handlers.py src/wazuh_mcp/gcf_format.py tests/integration/test_gcf_format.py tests/integration/test_output_redaction.py`. Reconcile expected predecessors against the behavior above. Use a worktree-local Python 3.11+ environment installed with `python3 -m venv .venv && .venv/bin/python -m pip install -e '.[dev]'`. Confirm `.venv/bin/python -c 'import wazuh_mcp; print(wazuh_mcp.__file__)'` points into this worktree.

## Implementation contract

Add one shared recursive transformation over JSON objects, lists and strings. Normalize ASCII field names by lowercasing and removing hyphens and underscores. The closed sensitive set is `password, passwd, apikey, xapikey, apisecret, clientsecret, privatekey, authorization, proxyauthorization, accesstoken, refreshtoken, idtoken, sessiontoken, token, secret, cookie, setcookie`. Leave working-directory field PWD intact. Replace the whole value of each matching key with `[REDACTED]`, including empty, null and container values. Sanitize log-like free text separately. Preserve ordinary keys, scalar types, nulls, labels and ordering. Apply to backend objects before JSON or GCF encoding and to successful embedded error fields. Preserve the existing size policy and MCP response envelopes. Avoid mutating cached input or running regex replacements on the final GCF wire.

Sanitize credential-bearing substrings in keys and free text, including Bearer/Basic headers, URL userinfo and quoted or escaped JSON in full_log. Apply the same policy to scalar conversions before encoding. Preserve distinct safe keys on collision using deterministic disambiguation. For opaque or over-depth data that cannot be sanitized within the output budget, return a truncation marker inside a valid response. Do not emit an uninspected tail. In `gcf_format.render_result`, pass the same already-clean, JSON-compatible object to GCF and fallback JSON. Use decoder assertions for supported GCF shapes and force the fallback once.

Retain existing `isError` and JSON-RPC envelopes. Public validation and protected-target errors use reviewed templates at the producer (`ToolValidationError` or an explicit safe subclass) with sanitized parameter labels. Map `IndexerNotConfiguredError` and connection failures to constant configuration/retry guidance. For any unclassified backend exception return only `Tool execution failed.` for tool calls, or the existing generic -32603 internal error for resources. An ordinary ValueError conveys no assurance its text is safe. Remove raw exception messages from embedded report errors and from client-visible diagnostics. Log the tool, error class and available correlation ID without raw backend text or a traceback containing the message. Exercise the changed paths through dispatch and verify existing operational guidance.

## Acceptance tests

Route error, refusal and success text through safe boundaries. Unexpected failures expose the specified public message. Diagnostics belong in server logs. Preserve actionable validation, confirmation and guardrail instructions via reviewed safe messages rather than raw backend exception text. Exercise nested records, alternate key casing, harmless near-match keys, quoted/escaped free text, safe guidance, and exception output. Use invented sentinel values. Decode JSON/GCF for exact equality to the sanitized object, including the existing fallback. Check authorized MCP resource text is valid JSON after redaction.

1. Run `.venv/bin/python -m pytest -q tests/integration/test_business_logic.py tests/integration/test_gcf_format.py tests/integration/test_destructive_guardrails.py tests/integration/test_input_validation.py` against the current checkout. Add the targeted expectations above and confirm the regression test distinguishes the current and required behavior.
2. Create tests/integration/test_output_redaction.py with the new cases, confirm the relevant failure against baseline, then implement the contract. Rerun the focused command together with the new file. All specified behaviors must pass.
3. Run `.venv/bin/ruff check --no-cache .`, `.venv/bin/python -m pytest -q` and `git diff --check`. Require zero exit status and inspect `git status --short` for scope. Report commands, counts, skips, and the diff to the coordinator for integrated verification.

## Maintenance and scope decisions

Keep redaction near common output boundaries. Preserve existing safe operational messages asserted by business-logic and protected-target tests. Start from the integrated 002 and 006 revisions. Check protected-target and business-logic tests against the existing safe guidance.
