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

## E16 - self-hosted deployment automation (active spec)

**Why:** onboarding a real self-hosted Wazuh today is the eight manual steps in
`README.md` §"Apply it to your own self-hosted Wazuh" plus several `make`
targets aimed at the docker harness. Operators want **two scripts**: one that
installs the *dashboard components* (Assistant plugins + ML Commons connector),
one that stands up the *gateway + local LLM + supporting components* - each
idempotent, env-driven, and safe to run against an existing deployment. This is
orchestration of pieces that already exist (`dashboard_assistant_setup.sh`,
`mlcommons_embed_setup.sh`, `manager_executor_setup.sh`, `securityconfig/apply.sh`,
the compose services) into two operator entry points; do **not** duplicate their
logic - call them.

Scope note: the harness `make` targets assume the bundled docker Wazuh. These
scripts target a **pre-existing** self-hosted Wazuh (the operator already has
indexer/manager/dashboard), so they must read connection + credentials from a
config file / env and never `make wazuh`.

### Script 1 - `scripts/install_dashboard_assistant.sh` (dashboard node)

Automates the Dashboards-side install so the chat appears in the operator's
Wazuh dashboard, wired to the gateway.

| Step | Detail |
|---|---|
| Detect OSD version | Parse `/usr/share/wazuh-dashboard/package.json` (as upstream `install_ai_assistant.sh`); never hardcode. |
| Install plugins | Download the matching OpenSearch Dashboards bundle, extract `assistantDashboards` + `mlCommonsDashboards` into the dashboard plugins dir, fix ownership/permissions, set `assistant.chat.enabled: true`, restart the dashboard. (Container deployments: point at the `dashboard-assistant/Dockerfile` image path instead.) |
| ML Commons wiring | Call `scripts/dashboard_assistant_setup.sh` (cluster settings + trusted connector endpoint = the gateway URL, remote model + HTTP connector with `X-Env-Key`, conversational agent, `os_chat` root agent). |
| Embeddings | Call `scripts/mlcommons_embed_setup.sh` (register the in-cluster embedding model) unless the operator points `WAI_EMBED_*` elsewhere. |
| Idempotent + preflight | Re-runnable; preflight-checks indexer/gateway reachability and required creds; prints what it changed. |

**Acceptance:** on a stock self-hosted Wazuh, one run makes the Assistant icon
appear and answer "Hi" through the gateway; re-running is a no-op; missing
prerequisites fail with a clear message, not a stack trace.

### Script 2 - `scripts/install_gateway.sh` (gateway + LLM node)

Stands up everything the gateway needs, pointed at the operator's Wazuh.

| Step | Detail |
|---|---|
| Security objects | Apply `securityconfig/` to the operator's indexer (JWT auth domain trusting `keys/jwt-public.pem`, the read-only + writer + operator/responder roles). |
| Local LLM + embeddings | Start Ollama (or accept a Bedrock/OpenAI-compatible endpoint via env), pull the model; ensure the embeddings model. |
| Env registry | Generate/validate `environments.yaml` from a template + the operator's answers (indexer URL, CA, `gateway_key`, reader/executor creds, action tiers). |
| Executor RBAC | Call `scripts/manager_executor_setup.sh` if any write tiers are enabled. |
| Gateway + shim | Start `tool-service` + `auth-shim` (compose, or emit systemd units for a non-docker host) reachable from the indexer (connector callback) and able to reach the indexer + manager. |
| Keys | `make keys` (or reuse existing) for the shim keypair. |

**Acceptance:** after Script 1 + Script 2, `make evals-connector` (or the
equivalent live check) is green against the operator's environment; the gateway
health endpoint is up; a chat turn in the dashboard returns a verifiable answer.

### README section + docs

- Add `README.md` §"Automated self-hosted deployment": prerequisites, the
  two-script flow (which runs where), a one-paragraph "what each does", and
  verification. Keep the existing manual eight-step section as the "what the
  scripts do under the hood / advanced" reference beneath it.
- Reference `diagrams/png/wazuh-ai-selfhosted--self-hosted-poc-icons.png` for the
  target shape.
- A config template (`deploy.env.example`) holding the operator inputs both
  scripts read.

**Guardrails for this item:** the scripts never invent credentials or weaken
TLS (pin the env CA), never run `make wazuh`, are idempotent, and print a
preflight summary before mutating anything. No secrets committed - the config
template holds placeholders only.

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
