# MCP delivery and verification

The implementation covers all eight repairs and six product pilots specified in the [implementation spec](implementation_spec.md). Product settings are opt-in. The baseline and upstream queue are in the [audit](audit_report.md).

| Work delivered | Principal files | Evidence |
|---|---|---|
| 001, 006 resource permissions and routing | server/handlers.py, tool_catalog.py, tool_calls.py | Scope and cluster tests for both HTTP eras and nine resource variants. |
| 002 ISO completeness | api/wazuh_client.py, api/wazuh_indexer.py | Exact and partial search fixtures cover agents, pages, timeouts, score suppression and known failures. |
| 003, 007 ownership and OAuth | auth.py, oauth.py, session_store.py, server/sessions.py, http_security.py, transport.py | Typed owner round trips, binding to verified identity, atomic storage updates and exact callback exchange. |
| 004 output | server/output.py, dispatch.py, tool_calls.py, tool_policy.py, security.py, gcf_format.py | Credential handling before JSON/GCF serialization, bounded truncation and safe public errors. |
| 005 readiness | session_store.py, server/ops.py | Redis SCAN and initialization failure, timeout, cancellation, cache and live adapter tests. |
| 008 package CI | .github/workflows/mcp-server-ci.yml, mcp-server/scripts, package configuration | Two interpreter jobs, ephemeral Redis, wheel and Alpine smoke, path filters, minimal permissions. |
| P1 and P3 investigation tools | server/product_tools.py, server/state.py, toolsets.py, server/tool_catalog.py and tool_calls.py | Timeline and drill-down, encrypted short-lived owner-bound references, approved saved filters, normal ASGI and protocol entry points. |
| P2 profiles and evaluation | toolsets.py, config.py, evals/tool_selection.py, evals/profile-cases.json | Paired fixed scenarios, fixture-based multiple turns, answer checks, full denominator and separate request failures. |
| P4 evidence viewer and offline approval design | server/timeline_viewer.py, handlers.py, evals/approval_experiment.py | Browser handshake and evidence selection. SQLite fixture proves single use, binding, expiry, restarts and reconciliation. |
| P5 cluster policy | server/cluster_policy.py, state.py, tool_catalog.py, transport.py, ops.py | Issuer-qualified grants, deny precedence, group freshness, hidden topology and per-call checks. |
| P6 compatibility gate | compatibility/check.py, manifest.json, snapshots/ | 16 Manager read contracts and three vulnerability mapping fields per release. Negative tests prove drift is detected. |

## Qualification

The baseline passed 641 tests. After the staging corrections, 780 tests passed on each of Python 3.11.2 and 3.13.14 against real Redis. Both freshly provisioned CI environments passed pip check, Ruff, compatibility checks and pytest. The pinned runs reported 70.90% and 71.56% branch-aware coverage, respectively. Actionlint 1.7.12 accepted the workflow with zero diagnostics. Local wheel checks covered base installation, the optional GCF fallback, the console entry point and loopback liveness. A network-isolated Alpine image returned HTTP 200 on its liveness endpoint. The first hosted run passed both 771-test Python jobs, their installed-wheel smoke checks and the Alpine container smoke. [GitHub Actions run 44769286583](https://github.com/leonfullxr/Wazuh/actions/runs/44769286583)

The official TypeScript MCP SDK 1.30.0 connected to a real loopback Streamable HTTP endpoint, negotiated protocol version 2025-11-25, listed tools/resources, fetched the viewer and called the timeline. Its JSON text matched structured content. This exercised a synthetic Manager and Indexer fixture. The 50-event fixture produced a 43,330-byte compact UTF-8 result envelope, including both representations. The configured envelope cap is 256,000 bytes. Chrome 158.0.8127.36 and Playwright 1.63.0 exercised the renderer and CSP. An independent run using Playwright 1.64.1 and the official Apps AppBridge 2.0.4 completed the handshake, rendered rule 5710, and retrieved the synthetic event through the host bridge on click. The [repeatable runner](../mcp-server/evals/mcp-app-client/README.md) includes its dependency pins.

### Disposable staging qualification

Official Wazuh Manager and Indexer 4.14.5 containers served the normal MCP server. Both upstream connections verified the test CA and loopback hostname. The Manager account had read-only RBAC. The Indexer reader could search and read alert documents and retrieve index settings, and its attempted fixture write received HTTP 403. Two logical cluster IDs shared the isolated backend to test policy boundaries.

- **Manager status.** The original per-agent URL returned HTTP 404. The filtered `GET /agents` request returned the requested ID and active status. The server now validates the ID and status before reporting an observation. Both pinned upstream specifications include the two query parameters.
- **Rollover.** Two synthetic alerts with the same timestamp were stored in separate indices. A third index created by the disposable Manager lacked the tie-breaker mapping. Its three failed shards correctly surfaced as partial coverage despite both test alerts being returned. Adding a mapping left 187 existing documents without a value. The fixture shipper was paused and these disposable records were populated. A read across all 189 visible alerts then found 189 distinct, populated IDs. The completed search returned both events in order. A hit with a null sort value now withholds unverifiable evidence.
- **Identity and clients.** Dex 2.44 and Keycloak 26.3.5 exercised real authorization-code login and PKCE exchange. With Keycloak, an analyst's signed group claim granted access, a second user without that group received a denial, and the analyst could not read the other logical cluster. Chrome 158 and the official Apps bridge displayed rules 100001 and 100002 and opened both correct evidence records. The server's text and structured responses matched. After the operator withdrew the cluster grant and restarted the server, the existing token still authenticated, but both the timeline and the previously issued evidence reference became inaccessible.
- **Deployment boundary.** These tests used synthetic identities and alerts on disposable services. Operators must verify the tie-breaker on their own data and grant the documented index-scoped settings read before enabling investigations.

### Local model comparison

Qwen3-VL-4B-Instruct (revision `ebb281ec70b05090aa6165b016eac8ec08e71b17`) ran on CPU in bfloat16 with greedy decoding, its own chat template and a 1,024-token output limit. A loopback adapter translated the model's native tool-call blocks to OpenAI-compatible function calls. All 18 responses were cross-checked against the emitted blocks. Wazuh tool replies in this evaluation come only from the fixed case manifest.

| Catalog | Tools | Catalog bytes | Passed | Unwanted writes | Median | p95 |
|---|---:|---:|---:|---:|---:|---:|
| Full | 55 | 29,304 | 6/9 | 0 | 57.45 s | 67.13 s |
| Triage | 19 | 11,052 | 6/9 | 0 | 28.80 s | 48.55 s |

Both catalogs passed the agent-health and read-only cases on all three attempts. Each failed the multi-step case on the first turn by calling the alert tool before the agent lookup returned. The read-only case checks tool selection and argument validity. It does not assess the usefulness of an analyst summary. All requests completed without context truncation. The three deterministic repeats show repeatability on this CPU. Broader adoption needs further tasks and models. Triage remains opt-in. [Per-attempt results and catalog fingerprints](../mcp-server/evals/results/qwen3-vl-4b-triage.json)

## Reviewer record

Gemini 4 Neon xhigh reviewed the initial design. Three GPT-6.2 Astra high reviewers supplied architecture, QA and contract amendments. GPT-6.2 Sol xhigh approved the revised spec for implementation. Claude Opus 5.5 high returned **PASS** after the corrective reviews. See the [Claude review record](opus_review.md) for its findings and their disposition.

## File inventory

Paths are relative to the repository root.

<details>
<summary>Packaging, CI and compatibility (13 files)</summary>

- [.github/workflows/mcp-server-ci.yml](../.github/workflows/mcp-server-ci.yml)
- [mcp-server/.dockerignore](../mcp-server/.dockerignore)
- [mcp-server/.env.example](../mcp-server/.env.example)
- [mcp-server/Dockerfile](../mcp-server/Dockerfile)
- [mcp-server/ci-constraints.txt](../mcp-server/ci-constraints.txt)
- [mcp-server/compatibility/check.py](../mcp-server/compatibility/check.py)
- [mcp-server/compatibility/manifest.json](../mcp-server/compatibility/manifest.json)
- [mcp-server/compatibility/snapshots/4.14.7.json](../mcp-server/compatibility/snapshots/4.14.7.json)
- [mcp-server/compatibility/snapshots/4.8.0.json](../mcp-server/compatibility/snapshots/4.8.0.json)
- [mcp-server/pyproject.toml](../mcp-server/pyproject.toml)
- [mcp-server/scripts/smoke-startup.py](../mcp-server/scripts/smoke-startup.py)
- [mcp-server/scripts/smoke-wheel.py](../mcp-server/scripts/smoke-wheel.py)
- [mcp-server/scripts/verify.sh](../mcp-server/scripts/verify.sh)

</details>

<details>
<summary>Documentation (18 files)</summary>

- [docs/audit_report.md](../docs/audit_report.md)
- [docs/delivery_report.md](../docs/delivery_report.md)
- [docs/implementation_spec.md](../docs/implementation_spec.md)
- [docs/opus_review.md](../docs/opus_review.md)
- [mcp-server/README.md](../mcp-server/README.md)
- [mcp-server/WAZUH_COMPATIBILITY.md](../mcp-server/WAZUH_COMPATIBILITY.md)
- [mcp-server/docs/ADVANCED_FEATURES.md](../mcp-server/docs/ADVANCED_FEATURES.md)
- [mcp-server/docs/CLUSTER_POLICY.md](../mcp-server/docs/CLUSTER_POLICY.md)
- [mcp-server/docs/INVESTIGATIONS.md](../mcp-server/docs/INVESTIGATIONS.md)
- [mcp-server/docs/LOCAL_LLM.md](../mcp-server/docs/LOCAL_LLM.md)
- [mcp-server/docs/MULTI_CLUSTER.md](../mcp-server/docs/MULTI_CLUSTER.md)
- [mcp-server/docs/OPERATIONS.md](../mcp-server/docs/OPERATIONS.md)
- [mcp-server/docs/api/README.md](../mcp-server/docs/api/README.md)
- [mcp-server/docs/api/active-response.md](../mcp-server/docs/api/active-response.md)
- [mcp-server/docs/api/compliance-reporting.md](../mcp-server/docs/api/compliance-reporting.md)
- [mcp-server/docs/configuration.md](../mcp-server/docs/configuration.md)
- [mcp-server/docs/security/README.md](../mcp-server/docs/security/README.md)
- [mcp-server/evals/mcp-app-client/README.md](../mcp-server/evals/mcp-app-client/README.md)

</details>

<details>
<summary>Evaluation and client fixtures (9 files)</summary>

- [mcp-server/evals/approval_experiment.py](../mcp-server/evals/approval_experiment.py)
- [mcp-server/evals/mcp-app-client/fixture_server.py](../mcp-server/evals/mcp-app-client/fixture_server.py)
- [mcp-server/evals/mcp-app-client/host-entry.js](../mcp-server/evals/mcp-app-client/host-entry.js)
- [mcp-server/evals/mcp-app-client/package.json](../mcp-server/evals/mcp-app-client/package.json)
- [mcp-server/evals/mcp-app-client/run.mjs](../mcp-server/evals/mcp-app-client/run.mjs)
- [mcp-server/evals/mcp-app-client/run.sh](../mcp-server/evals/mcp-app-client/run.sh)
- [mcp-server/evals/profile-cases.json](../mcp-server/evals/profile-cases.json)
- [mcp-server/evals/results/qwen3-vl-4b-triage.json](../mcp-server/evals/results/qwen3-vl-4b-triage.json)
- [mcp-server/evals/tool_selection.py](../mcp-server/evals/tool_selection.py)

</details>

<details>
<summary>Planning and review (11 files)</summary>

- [mcp-server/plans/001-resource-permissions.md](../mcp-server/plans/001-resource-permissions.md)
- [mcp-server/plans/002-iso-evidence.md](../mcp-server/plans/002-iso-evidence.md)
- [mcp-server/plans/003-session-ownership.md](../mcp-server/plans/003-session-ownership.md)
- [mcp-server/plans/004-output-redaction.md](../mcp-server/plans/004-output-redaction.md)
- [mcp-server/plans/005-redis-readiness.md](../mcp-server/plans/005-redis-readiness.md)
- [mcp-server/plans/006-default-cluster.md](../mcp-server/plans/006-default-cluster.md)
- [mcp-server/plans/007-oauth-callbacks.md](../mcp-server/plans/007-oauth-callbacks.md)
- [mcp-server/plans/008-package-ci.md](../mcp-server/plans/008-package-ci.md)
- [mcp-server/plans/ADVERSARIAL-REVIEW.md](../mcp-server/plans/ADVERSARIAL-REVIEW.md)
- [mcp-server/plans/PRODUCT-DESIGN.md](../mcp-server/plans/PRODUCT-DESIGN.md)
- [mcp-server/plans/README.md](../mcp-server/plans/README.md)

</details>

<details>
<summary>Server and adapters (24 files)</summary>

- [mcp-server/src/wazuh_mcp/api/wazuh_client.py](../mcp-server/src/wazuh_mcp/api/wazuh_client.py)
- [mcp-server/src/wazuh_mcp/api/wazuh_indexer.py](../mcp-server/src/wazuh_mcp/api/wazuh_indexer.py)
- [mcp-server/src/wazuh_mcp/auth.py](../mcp-server/src/wazuh_mcp/auth.py)
- [mcp-server/src/wazuh_mcp/config.py](../mcp-server/src/wazuh_mcp/config.py)
- [mcp-server/src/wazuh_mcp/gcf_format.py](../mcp-server/src/wazuh_mcp/gcf_format.py)
- [mcp-server/src/wazuh_mcp/oauth.py](../mcp-server/src/wazuh_mcp/oauth.py)
- [mcp-server/src/wazuh_mcp/security.py](../mcp-server/src/wazuh_mcp/security.py)
- [mcp-server/src/wazuh_mcp/server/app.py](../mcp-server/src/wazuh_mcp/server/app.py)
- [mcp-server/src/wazuh_mcp/server/cluster_policy.py](../mcp-server/src/wazuh_mcp/server/cluster_policy.py)
- [mcp-server/src/wazuh_mcp/server/dispatch.py](../mcp-server/src/wazuh_mcp/server/dispatch.py)
- [mcp-server/src/wazuh_mcp/server/handlers.py](../mcp-server/src/wazuh_mcp/server/handlers.py)
- [mcp-server/src/wazuh_mcp/server/http_security.py](../mcp-server/src/wazuh_mcp/server/http_security.py)
- [mcp-server/src/wazuh_mcp/server/ops.py](../mcp-server/src/wazuh_mcp/server/ops.py)
- [mcp-server/src/wazuh_mcp/server/output.py](../mcp-server/src/wazuh_mcp/server/output.py)
- [mcp-server/src/wazuh_mcp/server/product_tools.py](../mcp-server/src/wazuh_mcp/server/product_tools.py)
- [mcp-server/src/wazuh_mcp/server/sessions.py](../mcp-server/src/wazuh_mcp/server/sessions.py)
- [mcp-server/src/wazuh_mcp/server/state.py](../mcp-server/src/wazuh_mcp/server/state.py)
- [mcp-server/src/wazuh_mcp/server/timeline_viewer.py](../mcp-server/src/wazuh_mcp/server/timeline_viewer.py)
- [mcp-server/src/wazuh_mcp/server/tool_calls.py](../mcp-server/src/wazuh_mcp/server/tool_calls.py)
- [mcp-server/src/wazuh_mcp/server/tool_catalog.py](../mcp-server/src/wazuh_mcp/server/tool_catalog.py)
- [mcp-server/src/wazuh_mcp/server/tool_policy.py](../mcp-server/src/wazuh_mcp/server/tool_policy.py)
- [mcp-server/src/wazuh_mcp/server/transport.py](../mcp-server/src/wazuh_mcp/server/transport.py)
- [mcp-server/src/wazuh_mcp/session_store.py](../mcp-server/src/wazuh_mcp/session_store.py)
- [mcp-server/src/wazuh_mcp/toolsets.py](../mcp-server/src/wazuh_mcp/toolsets.py)

</details>

<details>
<summary>Tests (24 files)</summary>

- [mcp-server/tests/conftest.py](../mcp-server/tests/conftest.py)
- [mcp-server/tests/integration/test_active_response.py](../mcp-server/tests/integration/test_active_response.py)
- [mcp-server/tests/integration/test_approval_experiment.py](../mcp-server/tests/integration/test_approval_experiment.py)
- [mcp-server/tests/integration/test_authentication.py](../mcp-server/tests/integration/test_authentication.py)
- [mcp-server/tests/integration/test_business_logic.py](../mcp-server/tests/integration/test_business_logic.py)
- [mcp-server/tests/integration/test_cluster_policy.py](../mcp-server/tests/integration/test_cluster_policy.py)
- [mcp-server/tests/integration/test_clusters.py](../mcp-server/tests/integration/test_clusters.py)
- [mcp-server/tests/integration/test_compatibility_contract.py](../mcp-server/tests/integration/test_compatibility_contract.py)
- [mcp-server/tests/integration/test_eval_harness.py](../mcp-server/tests/integration/test_eval_harness.py)
- [mcp-server/tests/integration/test_health.py](../mcp-server/tests/integration/test_health.py)
- [mcp-server/tests/integration/test_input_validation.py](../mcp-server/tests/integration/test_input_validation.py)
- [mcp-server/tests/integration/test_investigation_http_workflow.py](../mcp-server/tests/integration/test_investigation_http_workflow.py)
- [mcp-server/tests/integration/test_legacy_tool_arguments.py](../mcp-server/tests/integration/test_legacy_tool_arguments.py)
- [mcp-server/tests/integration/test_oauth_login.py](../mcp-server/tests/integration/test_oauth_login.py)
- [mcp-server/tests/integration/test_oidc_identity_provider.py](../mcp-server/tests/integration/test_oidc_identity_provider.py)
- [mcp-server/tests/integration/test_output_redaction.py](../mcp-server/tests/integration/test_output_redaction.py)
- [mcp-server/tests/integration/test_package_workflow.py](../mcp-server/tests/integration/test_package_workflow.py)
- [mcp-server/tests/integration/test_product_tools.py](../mcp-server/tests/integration/test_product_tools.py)
- [mcp-server/tests/integration/test_runtime_edge_cases.py](../mcp-server/tests/integration/test_runtime_edge_cases.py)
- [mcp-server/tests/integration/test_scope_enforcement.py](../mcp-server/tests/integration/test_scope_enforcement.py)
- [mcp-server/tests/integration/test_session_memory_bound.py](../mcp-server/tests/integration/test_session_memory_bound.py)
- [mcp-server/tests/integration/test_session_ownership.py](../mcp-server/tests/integration/test_session_ownership.py)
- [mcp-server/tests/integration/test_timeline_viewer.py](../mcp-server/tests/integration/test_timeline_viewer.py)
- [mcp-server/tests/integration/test_toolsets.py](../mcp-server/tests/integration/test_toolsets.py)

</details>
