# Adversarial review of the Wazuh MCP plan

Gemini 4 Neon (XHigh), model ID `gemini-4-neon-xhigh`, reviewed the original eight handoffs, the execution index and the product design in an isolated directory. It received the plans only. The code checks and revisions below were performed by the coordinator against baseline `cccb1e8`. The reviewer’s verdict on the original draft was **changes requested**. This record describes the revisions following that verdict. The subsequent three Astra reviews and Sol xhigh gate apply to the consolidated [implementation specification](../../docs/implementation_spec.md).

## Implementation findings

| Gemini ID | Disposition and execution consequence |
|---|---|
| B1 · Session persistence and mutation | Verified the in-memory and Redis GET paths, the existing principal serialization and the independent touch on transport lookup. [003](003-session-ownership.md) now requires real adapter round trips, a fresh manager, and assertions on denied reads, writes, deletes, activity and expiry. |
| B2 · Worker interference | [001](001-resource-permissions.md) tests current scopes on an owned session. [006](006-default-cluster.md) owns the registry fixture migration. Backend error producers put [004](004-output-redaction.md) behind both 002 and 006. Existing direct helper tests in test_business_logic.py belong to 003 for the fixation change. |
| B3 · Resource permission boundary | Verified dispatch supplies a session carrying the current request token in both HTTP eras. 001 now specifies exact denied envelopes and a constant error for valid, unknown and malformed resource reads. Test zero backend work on denial. |
| B4 · Favorable ISO aggregates from missing data | [002](002-iso-evidence.md) specifies the public coverage fields, nullable affected aggregate scores, board text and gap severity. A page of critical findings still yields a visible known failure even if the total assessment is incomplete. |
| B5 · Incomplete and zero evidence | The Indexer adapter loses exact-total and partial-search metadata. It now belongs to 002. The tests distinguish an assessed agent with zero findings from a fleet with no assessed agents and cover both failure orders, partial HTTP successes and explicit target scope. |
| B6 · Ambiguous owners and legacy lookups | Existing principal strings flatten credential information. 003 now introduces a typed persisted owner, defines behavior across refresh and auth-mode changes, centralizes denial and requires pre-upgrade sessions to initialize again. |
| B7 · Redaction and exception provenance | 004 specifies credential aliases, a fixed sentinel, working-directory preservation, text handling, format fallbacks, typed public errors and narrowly scoped server logs. It calls for equality of decoded redacted data and exercises the final protocol response. |
| B8 · Redis count callers | Verified readiness calls Redis count, the Redis session cap returns before the count, and liveness and metrics do not depend on it. [005](005-redis-readiness.md) now exercises initialization, later-page failure, bounded timeout, cancellation and recovery. |
| B9 · OAuth query ambiguity | [007](007-oauth-callbacks.md) now covers registration and authorization, preconfigured clients, raw unrelated query bytes and exact token exchange. It declares a conservative case-insensitive policy for reserved names. |
| B10 · CI reproducibility | [008](008-package-ci.md) pins both actions from the sibling workflow, uses an editable install and specifies event validation. Python 3.13 enters the matrix after a clean qualification run. Hosted checks remain pending until implementation. |
| B11 · Combined tests and rollout | The [integration gate](README.md#integration-and-rollout) now covers cross-package behavior and the operational changes to permissions, Redis readiness, callback registration, ISO scores and session cutover. |

## Product findings

| Gemini ID | Decision incorporated into the product design |
|---|---|
| PD1 · Timeline retrieval | Reject an oversized window, select a deterministic page at the Indexer, and ship an authorized evidence lookup alongside the timeline. Define replica-compatible references, scope checks and a plain JSON fallback. [P1](PRODUCT-DESIGN.md#p1-give-the-analyst-an-evidence-backed-alert-timeline) |
| PD2 · Viewer and approvals | Render untrusted alert text literally in an isolated viewer. The response prototype uses a stub. Any live design needs authenticated human approval and durable single-use and reconciliation records. [P4](PRODUCT-DESIGN.md#p4-show-evidence-and-reviewable-actions-inside-compatible-mcp-clients) |
| PD3 · Multi-cluster policy | Define namespaced subjects, group unions, deny precedence, strict startup, hidden denied destinations and a concrete first-release cross-cluster restriction. [P5](PRODUCT-DESIGN.md#p5-add-access-policies-for-individual-clusters) |
| PD4 · Operational contracts | Pin profile selection to startup configuration, constrain saved-query fields and parameters, and compare supported releases against offline Manager specs and Indexer fixtures. [P2–P6](PRODUCT-DESIGN.md) |

The optional review items on symbol references, invalid-resource lookups, readiness visibility, bounded SCAN, CI concurrency and discovery envelopes are reflected in the handoffs. Dependency pinning for Ruff remains a package-wide dependency decision. The ISO evidence collector has a separate vulnerability query outside the dashboard scoring change. Regression, integration and rollout checks described here are acceptance criteria for the implementation workers. The measured planning baseline is recorded in the [index](README.md).
