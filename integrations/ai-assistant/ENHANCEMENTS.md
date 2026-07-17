# Enhancements - forward backlog (for Cursor)

Current design: [`ARCHITECTURE.md`](ARCHITECTURE.md). What has already shipped
and why - the E1-E15 arc and the eight review rounds - lives in
[`DESIGN-JOURNAL.md`](DESIGN-JOURNAL.md); this file holds only work **not yet
built**. When a new round starts, add it here as a spec (files + change +
acceptance + a golden case), then fold it into the journal once shipped and
reviewed.

Status: **E1-E15 shipped, reviewed, and live-validated; the golden set is
green.** The PoC is feature-complete. Everything below is deferred-with-intent -
none of it blocks the self-hosted PoC.

## Guardrails (constrain any new item)

- **Query, don't embed (D4/D5).** Tenant telemetry is never vectorized; a vector
  store is permitted only over curated *public reference content* (D57).
- **The model never writes a query / computes a number (D4).** New capability is
  typed tools/IR, veracity-checked server-side.
- **Writes are propose→confirm (D20)** with a tiered executor credential the
  model never holds.
- **Cache-stability:** per-turn context rides as transient messages, never the
  static prelude.
- **Recognitions route deterministically** (lane 0 / playbooks / reference
  router), not via model tool-selection.
- Rejected: semantic answer cache, LLM-judge in the live path, lane 3, ML
  Commons as orchestrator.

## Backlog

| Item | Notes |
|---|---|
| Streamable-HTTP `/mcp` surface | The stdio MCP adapter ships today; a streamable-HTTP endpoint with per-user/env-key auth is the multi-env-friendly form. |
| Amazon Bedrock fidelity leg | The one untested inference posture; needs AWS credentials. Prove the golden set + prompt-cache token accounting on Bedrock. |
| Shim audit-on-rejection | Emit structured audit events on auth-shim rejection paths (bad creds, missing role, unknown env); add a per-IP/user exchange throttle. |
| v3 diagram PNG re-export | `.drawio` sources are current; regenerate `diagrams/png/` from the GUI (no headless exporter on the build host). |
| Multi-environment isolation suite (V3.2) | Set aside by choice for the self-hosted focus. A `kind/` two-tenant harness exists; the live cross-tenant isolation assertions are the remaining work if multi-tenancy becomes the showcase. |

When picking one up, write its spec in place here (as prior rounds did), keep
the D-tag/golden-case conventions, and hand back for review.
