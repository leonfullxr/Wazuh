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

The baseline passed 641 tests. The revised candidate passed 771 tests on each of Python 3.11.2 and 3.13.14 against real Redis. Both freshly provisioned CI environments passed pip check, Ruff, compatibility checks and pytest. The pinned runs reported 70.84% and 71.51% branch-aware coverage, respectively. Actionlint 1.7.12 accepted the workflow with zero diagnostics. Local wheel checks covered base installation, the optional GCF fallback, the console entry point and loopback liveness. A network-isolated Alpine image returned HTTP 200 on its liveness endpoint. The first hosted run passed both 771-test Python jobs, their installed-wheel smoke checks and the Alpine container smoke. [GitHub Actions run 44769286583](https://github.com/leonfullxr/Wazuh/actions/runs/44769286583)

The official TypeScript MCP SDK 1.30.0 connected to a real loopback Streamable HTTP endpoint, negotiated protocol version 2025-11-25, listed tools/resources, fetched the viewer and called the timeline. Its JSON text matched structured content. This exercised a synthetic Manager and Indexer fixture. The 50-event fixture produced a 43,330-byte compact UTF-8 result envelope, including both representations. The configured envelope cap is 256,000 bytes. Chrome 158.0.8127.36 and Playwright 1.63.0 exercised the renderer and CSP. An independent run using Playwright 1.64.1 and the official Apps AppBridge 2.0.4 completed the handshake, rendered rule 5710, and retrieved the synthetic event through the host bridge on click. The [repeatable runner](../mcp-server/evals/mcp-app-client/README.md) includes its dependency pins. A paired real-model timing result remains unmeasured because the local inference service was unavailable.

The OpenSearch sortable field must be verified unique across the actual deployment's rollover indices before enabling investigations. Version endpoints were checked against official pinned Wazuh specifications. Live Wazuh and IdP qualification is pending an identified staging deployment and intended client. The paired profile evaluation needs a reachable local tool-calling model service.

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
<summary>Evaluation and client fixtures (8 files)</summary>

- [mcp-server/evals/approval_experiment.py](../mcp-server/evals/approval_experiment.py)
- [mcp-server/evals/mcp-app-client/fixture_server.py](../mcp-server/evals/mcp-app-client/fixture_server.py)
- [mcp-server/evals/mcp-app-client/host-entry.js](../mcp-server/evals/mcp-app-client/host-entry.js)
- [mcp-server/evals/mcp-app-client/package.json](../mcp-server/evals/mcp-app-client/package.json)
- [mcp-server/evals/mcp-app-client/run.mjs](../mcp-server/evals/mcp-app-client/run.mjs)
- [mcp-server/evals/mcp-app-client/run.sh](../mcp-server/evals/mcp-app-client/run.sh)
- [mcp-server/evals/profile-cases.json](../mcp-server/evals/profile-cases.json)
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
