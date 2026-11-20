# Wazuh MCP implementation plan

The first release closes eight verified gaps in the Python MCP server. The product proposal starts with a read-only agent timeline that cites its evidence and tells the analyst which data was unavailable. The eight fixes and six product proposals have separate acceptance criteria. See the [implemented specification](../../docs/implementation_spec.md) and the [validation and delivery record](../../docs/delivery_report.md).

Baseline `cccb1e8` on 2026-11-20. In the package environment, 641 pytest tests passed with normal socket access. The proposed coverage command reported 65.77% against the configured 37% floor. Ruff passed, and pip reported consistent dependencies. No live Manager, Indexer, Redis, IdP or container was used. A local dependency audit found advisory matches in four development-environment packages; image reachability and severity were not established. Production impact requires a separate image assessment.

## Work packages

| Audit ID | Executor handoff | Dependency | Status |
|---|---|---|---|
| 1 | [Enforce read permissions on MCP resources](001-resource-permissions.md) | Independent | Implemented |
| 2 | [Require complete evidence for an ISO vulnerability score](002-iso-evidence.md) | Independent | Implemented |
| 3 | [Check the owner before using a legacy session](003-session-ownership.md) | Independent | Implemented |
| 4 | [Redact tool and resource data before serialization](004-output-redaction.md) | 002 and 006 | Implemented |
| 5 | [Make Redis session-store failures visible to readiness](005-redis-readiness.md) | Independent | Implemented |
| 6 | [Resolve resource reads through the configured default cluster](006-default-cluster.md) | 001 | Implemented |
| 7 | [Preserve registered OAuth callback queries](007-oauth-callbacks.md) | Independent | Implemented |
| 8 | [Run the MCP package checks on pull requests](008-package-ci.md) | Independent | Implemented |

## Parallel execution

The implementation used GPT-6.1 Terra high workers and coordinator-owned verification and integration. The table below records the original work allocation. The consolidated specification supersedes the initial sequence. Give each worker the full handoff file from this directory and its own git worktree and virtual environment. The plan files may be uncommitted in the coordinator checkout; pass the selected plan text or copy it into the worker’s task context. Do not rely on it appearing in a fresh worktree. Reserve the coordinator for review and integration. Three worker lanes fit the four-slot session.

| Lane | First assignment | Subsequent assignments |
|---|---|---|
| A · resource access and output | 001 resource scope | 006 default cluster → 004 output redaction once 002 lands |
| B · evidence and probes | 002 ISO evidence | 005 Redis readiness |
| C · identity and delivery | 003 session owner | 007 OAuth callbacks → 008 package CI |

Plans 001 and 006 share the resource handler and scope tests. Plan 004 needs both 006 (resource handler) and 002 (backend error producers). All other fix packages can move to the next available Terra worker. The coordinator reviews and integrates each diff before dispatching its dependants. Maintain independent worktrees and preserve unrelated changes. [Gemini review and dispositions](ADVERSARIAL-REVIEW.md)

## Integration and rollout

Install with `python -m pip install -e '.[dev]'` in the combined checkout’s own environment under `mcp-server/`. Verify the imported source path. Run `.venv/bin/python -m pip check`, `.venv/bin/ruff check --no-cache .`, `.venv/bin/python -m pytest -q --cov` and `git diff --check`. Record test totals, coverage, interpreter and hosted status.

| Combined check | What must hold |
|---|---|
| 001 + 003 | An owned legacy session respects current scope after refresh or downgrade. A foreign ID is refused before dispatch. Stateless requests use their own authenticated token. |
| 001 + 006 + 004 | Only an authorized resource reaches the named default. Its serialized data matches the sanitized tool data. An unknown resource or denied caller triggers no backend lookup. |
| 002 + 004 | A partial ISO assessment retains observed counts and gap severity while suppressing an aggregate score. A failed subquery never exposes raw backend exception text. |
| 005, 007, 008 | Verify Redis readiness failure and recovery, query-bearing OAuth callback and token exchange, workflow events, pinned actions, install and each enabled Python job. Keep local and hosted results separate. |

Before rollout, identify resource consumers needing read scope, confirm Redis supports prefix SCAN within the probe budget, inventory registered callback queries for reserved names, and identify deployments whose resource default differs from the environment cluster. Drain old replicas before the typed-owner cutover and expect existing legacy clients to initialize again. Explain the now-null ISO summary and weighted scores to dashboard consumers. The implementation gate ends with an integrated candidate. Deployment remains a separate decision.

## Product decisions

[Product design and acceptance criteria](PRODUCT-DESIGN.md) describes six proposals. Start P2’s evaluation and P6’s inventory while fixes run. Build P1 after the resource scope, routing, redaction and evidence-completeness contracts land. The P1 pilot also consumes the typed owner from 003. P3 and the P4 viewer reuse the P1 result format. The P4 response spike requires a trusted approval surface and a durable shared store before live implementation. Prioritize P5 before onboarding multiple organizations to a shared server.

## Considered and deferred

The documented environment-only readiness check in multi-cluster mode is intentional. The Redis session caps and process-local OAuth state are documented operational tradeoffs. A wholesale rewrite of the tool registry would put policy and dispatch in the same migration as behavioral fixes; defer it until contract tests cover the new workflows. Keep generic code execution outside the initial product roadmap; named filters, reviewed investigations and the existing policy-enforced tools cover the first use cases.
