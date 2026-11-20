# Require complete evidence for an ISO vulnerability score

P1 · Medium · Medium change risk · Independent. Planned at `cccb1e8` on 2026-11-20. Status: implemented. See the [combined verification record](../../docs/delivery_report.md).

## Current behavior and evidence

The dashboard at wazuh_client.py:1745 requests up to 500 findings per target. After any successful query it sets `vuln_query_ok = True`. A later failure exits the loop with that flag set. Line 1839 calculates A.8.8 from the partial counts. In a two-agent fixture, one empty response followed by an outage produced score 100, pass, high confidence. The tests around test_active_response.py:193 cover one-agent success and failure.

## Ownership and setup

Run commands from `mcp-server/` in a dedicated worktree using GPT-6.1 Terra at high effort. The coordinator maintains the index. Write scope is limited to the following paths.

- `src/wazuh_mcp/api/wazuh_client.py`
- `src/wazuh_mcp/api/wazuh_indexer.py`
- `tests/integration/test_active_response.py`
- `docs/api/compliance-reporting.md`

Compare the current checkout with the baseline using `git diff cccb1e8..HEAD -- src/wazuh_mcp/api/wazuh_client.py src/wazuh_mcp/api/wazuh_indexer.py tests/integration/test_active_response.py docs/api/compliance-reporting.md`. Reconcile expected predecessors against the behavior above. Use a worktree-local Python 3.11+ environment installed with `python3 -m venv .venv && .venv/bin/python -m pip install -e '.[dev]'`. Confirm `.venv/bin/python -c 'import wazuh_mcp; print(wazuh_mcp.__file__)'` points into this worktree.

## Implementation contract

Keep this repair bounded to dashboard evidence. Track complete, partial or unavailable coverage independently of observed severity counts. Compare Manager fleet matches and each Indexer total with rows returned. Distinguish an explicit agent from the fleet. An unknown or incomplete count must not establish completeness. If no targets were assessed, suppress the score. Preserve complete-zero score 100, including the explicit single-agent case when supported by evidence. Keep existing caps and severity weights.

**Completeness at the adapter boundary.** The normalized Indexer response currently drops shard and timeout information and substitutes the page length for an unknown total (wazuh_indexer.py:543). Carry an additive completeness indicator from the vulnerability search response before this information is lost. Require a successful search, no timeout or failed shards, an exact total (integer or object with `relation=eq`), and a page covering that total. Treat a reported partial cross-cluster search or an unrecognized severity that affects the calculation as incomplete. Validate Manager `total_failed_items` and the reported target count. Preserve the public Indexer count format. Add the dashboard coverage field and document the nullable dashboard summary. A complete, authorized zero-hit query for a known explicit target is valid. An unconfirmed target is unavailable.

**Response contract.** Under `data.vulnerability_coverage` return `status` (complete, partial, unavailable), `expected_agents` (exact integer or null), `completed_agents` (integer with complete findings), `observed_counts` (nonnegative severity counters using the existing summary keys), and `reasons` (a deduplicated list drawn from `unknown_total`, `target_list_incomplete`, `no_targets`, `source_unavailable`, `search_incomplete`, `page_truncated`, `unknown_severity`). Continue with remaining identified targets after a failure. With some usable evidence but incomplete coverage, report partial. With no usable assessment, including a fleet with zero targets, report unavailable. For an explicitly requested agent require an authorized confirmed target and scope completeness to that agent. Keep the successful-query counter separate from completed agents.

For partial or unavailable coverage set `data.vulnerability_summary`, A.8.8 score, `domain_summary["A.8"].weighted_score` and `overall_weighted_score` to null. Use A.8.8 status `no_data`, confidence `none` and overall posture `insufficient_data`. Keep measured controls and other domain scores available. Document the nullable summary as an intentional response change. Preserve observed severity counts in coverage, in the board text as lower bounds and in the A.8.8 gap. For incomplete assessments add a gap of type `incomplete_evidence` carrying coverage status, observed counts and `score_upper_bound` (null without observations, otherwise apply the existing penalty formula to observed counts). When the bound is below 75 label it as a known failure in the board and gap. Use critical gap severity when the bound is below 40. A truncated page containing hundreds of critical findings must still surface that exposure prominently.

Test unknown, missing, noninteger and lower-bound totals at both adapters, zero-agent fleet, both agent success/failure orders, nonzero lower bounds, and explicit agent complete-zero, truncated and failed queries. For 600 critical matches with a 500-row page assert null aggregate, zero score upper bound and a critical gap. Confirm the input-validation fixture only checks agent filtering and the regression fixture checks alert coverage independently of A.8.8. Retain those assertions. The separate ISO evidence endpoint has its own collection loop and is outside the scoring change.

## Acceptance tests

Add a test for a failure after first success, a truncated agent list, a truncated finding page, timed out or partially failed searches returning HTTP 200, lower-bound and missing totals, complete empty findings, and unavailable data. Use backend-shaped totals in positive fixtures. For incomplete evidence expect A.8.8 `no_data`, null score, confidence `none`, an additive coverage status and observed counts labeled as partial. Check the board sentence, aggregate and gap view agree. Preserve existing `scoring.vuln_agents_aggregated` semantics as agents actually queried successfully. Keep unrelated controls and their weights stable.

1. Run `.venv/bin/python -m pytest -q tests/integration/test_active_response.py tests/integration/test_input_validation.py tests/integration/test_regressions.py` against the current checkout. Add the targeted expectations above and confirm the regression test distinguishes the current and required behavior.
2. Implement the contract, then rerun the focused command. All specified behaviors must pass.
3. Run `.venv/bin/ruff check --no-cache .`, `.venv/bin/python -m pytest -q` and `git diff --check`. Require zero exit status and inspect `git status --short` for scope. Report commands, counts, skips, and the diff to the coordinator for integrated verification.

## Maintenance and scope decisions

The reported score can decrease or disappear after this change. Document partial/unavailable response examples. Treat exact aggregation and a larger fleet scan as a separate performance decision.
