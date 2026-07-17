# wazuh-ai - architecture (current, consolidated)

This is the single authoritative description of the system as built. For *how*
it got here - the phase-by-phase journey, the decisions and their rationale,
and the review findings that caught real bugs - see
[`DESIGN-JOURNAL.md`](DESIGN-JOURNAL.md). Diagrams:
[`diagrams/wazuh-ai-v3-gateway.drawio`](diagrams/wazuh-ai-v3-gateway.drawio)
(topology) and
[`diagrams/wazuh-ai-v3-workflow.drawio`](diagrams/wazuh-ai-v3-workflow.drawio)
(one turn end to end).

## 1. Thesis

An AI security assistant for Wazuh where **veracity is a property of the
architecture, not a prompt**. The model never writes a datastore query and
never computes a number (D4). It selects typed tools or emits a typed query
plan; the gateway compiles, validates, executes as the asking identity, and
verifies every citation and number against what was actually retrieved. Write
operations are proposed by the model and executed only after a human confirms,
under a credential the model never holds.

## 2. Topology - two edges, one gateway, N environments

```
Dashboard Assistant (in Wazuh Dashboard) ─ ML Commons connector ─┐
n8n · direct API · MCP · confirm UI ─ auth-shim (turn JWT) ───────┤
                                                                  ▼
                        wazuh-ai GATEWAY (the tool-service)
        env registry · admission · lanes · IR · compiler · 4 checks
        · citations · grounded numbers · actions · audit · per-env state
                    │ queries as the principal        │ inference port
                    ▼                                  ▼
        Environment's Wazuh Indexer +          Ollama · Bedrock ·
        Manager API (per environment)          OpenAI-compatible
```

- **The chat lives inside the Wazuh Dashboard.** The Dashboards Assistant
  plugin → OpenSearch ML Commons → an HTTP connector → our
  `/v1/connector/analyze`. We adopt this edge from the official
  [wazuh/integrations AI_assistant](https://github.com/wazuh/integrations/tree/main/integrations/AI_assistant)
  but replace its query-writing gateway with this veracity core (D44: the
  gateway and MCP surface are one deployable over one tool registry).
- **One gateway serves many environments (D43).** A per-environment credential
  - never the request payload (D6) - resolves through the environment registry
  to that environment's indexer, CA, reader principal, action tiers, and
  budgets. Admission (D14), evidence cache, lane-0 vectors, audit, and the kill
  switch are all per-environment. The PoC runs one environment (`lab`); every
  interface is the multi-environment shape.
- **Inference is a port (D37/D39/D46):** local Ollama (`gpt-oss:20b`, the
  16 GB-budget default, validated 9/9), Amazon Bedrock, or any
  OpenAI-compatible endpoint; each of the two model tiers can bind its own
  provider. The model never sees a credential.

## 3. Identity per edge

| Edge | Runs as | Verified by |
|---|---|---|
| Dashboard Assistant (connector) | `wazuh_ai_env_reader` - per-env, read-only (D42) | per-env `X-Env-Key` in the ML Commons connector → env registry |
| n8n · direct API · MCP · confirm UI | the analyst, per-user (D11) | indexer Basic creds → auth-shim `authinfo` verify → turn JWT ≤10 min (D52) |

- The **auth-shim** is the only holder of the mint key; the core verifies with
  the public key and never mints (D30). Identity is verified against each
  **environment's own indexer** (`_plugins/_security/authinfo`) - there is no
  external IdP (D52; Keycloak was the earlier stand-in, removed in V3.6).
- The `tenant` claim is proven by *which* environment's authinfo accepted the
  credentials, never asserted by the payload (D6).
- Telemetry executes **as the principal** through the indexer JWT auth domain
  (D11), so the assistant can never surface more than that identity may read.
  The dashboard edge's read-only downgrade is disclosed in every answer's
  label (`· environment-scoped identity`) and in audit (`claimed_user=null`).

## 4. A read turn - the lane cascade

Order is by verifiability; each rung escalates only if the cheaper one cannot
answer. Language of the answer follows `detect(question)` (V3.8a), and an
embedding scope classifier refuses off-topic/injection questions before any
model runs (fails open).

1. **Lane 0 (D40):** one embedding matches the question to a curated bilingual
   template → typed IR → executed with no model in the loop; a near-miss just
   under threshold becomes a few-shot hint instead of being discarded.
2. **Playbooks (D55):** on a lane-0 miss, an embedding may match a curated
   investigation playbook (ordered typed tool steps). Every step runs the
   normal veracity path; the model only synthesizes from collected evidence.
3. **Lane 1:** the model picks **typed tools** with schema-validated params -
   never free-form queries (D4). Catalog: alerts (`count_alerts`,
   `auth_failures`, `brute_force_summary`, `top_rules`, `search_alerts`,
   `alert_histogram`, `alert_timeline`, `related_alerts`, `compare_windows`,
   `mitre_coverage`, `agent_posture`), knowledge (`mitre_lookup` exact ATT&CK
   id; `knowledge_search` over curated public docs only - D57/D60;
   `rule_reference` / `field_dictionary` exact catalogs - D61;
   `describe_capabilities` from the live registry), environment
   (`list_agents`, `index_health`, `list_dashboards`), states
   (`count_vulnerabilities` over `wazuh-states-vulnerabilities-*`, its own
   allowlist).
4. **Lane 2:** the model emits a typed **Query IR**, allowlist-checked and
   compiled to OpenSearch DSL server-side - no scripts, regexp, or wildcards
   (D22/D29). Lane 3 (free generation) stays off (D32).

**Per-turn context** (transient, never in the cached prelude, so prompt-cache
prefixes stay stable): the per-environment context card (agents, OS mix, geo
field presence, existing dashboards; 15-min TTL), the domain/reporting/dashboard
prompt modules, optional answer-shape instructions (D56), and the language line.

**Every read funnels through the veracity pipeline (D24):** (1) mapping
validation, (2) dry-run, (3) execute as the principal, (4) zero-hit
differential diagnosis. Counts come from the datastore, never from the model
counting a list. The IR-keyed evidence cache is always disclosed
(`served_from_cache`, D41). "Query, don't embed": tenant telemetry is never
vectorized (D4/D5) - the only embeddings are over questions and curated
exemplars.

Before synthesis, an **evidence-side injection guard (D59)** scans the
retrieved (attacker-controlled) evidence for prompt-injection shapes and
neutralizes them by delimiting rather than dropping - deterministic, no model.

**Answer assembly:** citation verification (`[alert]`/`[agg]`/`[kb]` must have
been retrieved this turn) plus the grounded-number check (a number beside a
citation must equal an evidence value); mismatches surface as `corrections`,
never silently. Every answer carries a verifiability label derived from its
lane and checks (D23).

## 5. Write actions (propose → confirm)

The assistant is write-capable by design, but the model never calls a write API
directly.

- **Two phases (D20):** the model calls a `propose_*` tool (typed schema +
  preview) → a proposal card, nothing executed. A human confirms; only then
  does a **per-tier executor credential - never the model (D35)** - run it.
  Executors: dashboard (saved-objects via the Dashboards API), manager
  (`agent:restart`), active-response (`active-response:command`), each a
  least-privilege Wazuh user, mutually exclusive.
- **Confirmation** is either `POST /v1/actions/{id}/confirm` (operator JWT) or
  a conversational **"yes"/"no"** - a deterministic bilingual intent match
  *outside* the model (D54). On direct edges the JWT's tier role
  (`wazuh_ai_operator` / `wazuh_ai_responder`) authorizes; on the dashboard
  edge a "yes" executes under the environment principal (**D53**, Leon's
  explicit trust decision: dashboard access is the authority - a documented
  lowering of D42/D48).
- **Guardrails that always hold:** per-environment tier opt-in (deny by
  default - an env that hasn't enabled a tier can't even propose it),
  high-risk actions require echoing the target, idempotency (D49, replays and
  cross-proposal key reuse handled), per-tier rate caps, and full audit. Risk
  tiers gate UX (D51). The action catalog is code, not prompt (D50).

## 6. Observability, admission, resilience

Structured JSON audit per token rejection, tool call, turn, proposal, and
confirm (D8); Prometheus counters/histograms by lane, tool, outcome, tokens,
latency. Admission is one stream per user, a per-tenant semaphore, and honest
429s - no silent downgrades (D14). Honest failure modes: 503 when the
inference backend is unreachable, 401 when the indexer rejects a turn
credential, per-tenant kill switch.

Multi-turn context (D7/D58) is a documented seam: in-memory by default, or
persisted to the environment's own indexer, with a rolling summary that keeps
replayed context within a token budget. Only text the analyst already saw is
stored - never raw telemetry.

## 7. Consolidated decision log

Status: **active** unless noted. Superseded decisions are kept for lineage.

| Tag | Decision | Status |
|---|---|---|
| D3 / D38 | Bedrock Guardrails attach per invocation, per-deployment profiles | active (bedrock) |
| D4 / D5 | Model never writes queries; tenant telemetry never embedded ("query, don't embed") | active |
| D6 | Tenant/environment id from deployment/credential, never from input | active |
| D7 | Conversation and audit state belong in the deployment's own indexer | seam (in-memory in PoC) |
| D8 | Application-level audit events | active |
| D11 | Telemetry queries execute as the logged-in analyst via the indexer JWT auth domain | active (direct edges) |
| D12 | Bilingual (EN/ES) by construction | active |
| D14 | Admission control with honest rejection; no silent downgrade | active |
| D18 | Access gated by an opt-in analyst role | active |
| D20 | Two-phase actions: propose (model) → confirm (human + executor) | active |
| D21 | Headless core, multiple surfaces (SSE chat, sync JSON, per-tool HTTP, MCP, connector) | active |
| D22 / D29 | Typed Query IR, per-datastore compilers, OpenSearch DSL first | active |
| D23 | Every answer carries a verifiability label | active |
| D24 | The four veracity checks | active |
| D26 | Local-render and cloud-synthesis modes | active |
| D28 | n8n (and every edge) is edge-only; the gateway owns the loop | active |
| D30 | Minting lives in the auth-shim sidecar; the core verifies, never mints | active |
| D32 | Lanes 1-2 ship with all checks; lane 3 (free generation) stays off | active |
| D33 | The bilingual golden set is a CI gate | active |
| D34 | Explain-this-alert via a deep link (`alert_id`) | active |
| D35 | Per-action-tier executor principals, least privilege (manager: upload_file + analysisd_reload for suppress; dedicated `monitor_executor_basic` for Alerting) | active |
| D37 / D39 | Two model tiers; each tier binds its own provider/endpoint | active |
| D40 | Lane 0: embedding-matched curated templates, no model | active |
| D41 | Evidence cache keyed on the canonical IR, always disclosed | active |
| D42 | Dashboard connector edge is environment-scoped (read-only per-env principal) | active |
| D43 | One gateway, many environments; env id from the credential | active |
| D44 | Gateway and MCP surface are one deployable over one registry | active |
| D45 | Connector-edge conversation memory belongs to ML Commons | active |
| D46 | Local-first inference under a 16 GB budget; in-cluster embeddings | active |
| D47 | ~~Write operations deferred, not in v3~~ | **superseded** - actions shipped (D20) |
| D48 | ~~Propose on every edge; confirm on direct edges only~~ | **superseded by D53** |
| D49 | Idempotency on every confirm | active |
| D50 | Action catalog is code, not prompt | active |
| D51 | Risk tiers gate confirmation UX | active |
| D52 | Identity via the environment's own indexer authinfo; no external IdP (Keycloak removed) | active |
| D53 | Dashboard-edge conversational "yes" executes under the env principal (dashboard access = authority) | active (bounded by §5 guardrails) |
| D54 | Confirmation is a deterministic intent match outside the model; high-risk needs target echo | active |
| D55 | Investigation playbooks: curated ordered typed tool sequences; model only synthesizes | active |
| D56 | Per-intent answer shapes (triage card / incident / exec) as transient context | active |
| D57 | Vector store only over curated public reference content (`knowledge_search`) | active |
| D58 | Conversation store backends: memory (default) or indexer; rolling summary budget | active |
| D59 | Evidence-side injection scan before synthesis (deterministic neutralize) | active |
| D60 | Wazuh docs KB: version-pinned corpus from `llms.txt` at build time (`make docs-kb`) | active |
| D61 | Exact-match reference lookups (`rule_reference`, `field_dictionary`) cited as `[kb:]` | active |
| D62 | Per-intent tool subsetting: routing optimization only; fail open; lane 2 stays available | active |

## 8. Surfaces and configuration

Surfaces: `POST /v1/chat` (SSE), `POST /v1/chat/sync`, `POST /v1/tools/{name}`,
`POST /v1/connector/analyze` (ML Commons), `POST /v1/actions/{id}/confirm|reject`,
and the stdio MCP adapter (`mcp/`). Full configuration knob reference is
documented inline in [`.env.example`](.env.example); the environment registry
shape is [`environments.yaml.example`](environments.yaml.example).

## 9. Document and diagram map

| For | Read |
|---|---|
| Current design (this) | `ARCHITECTURE.md` |
| The journey: phases, decisions + rationale, review findings, results (incl. the enhancement arc E1-E8 and Round 7) | `DESIGN-JOURNAL.md` |
| Forward enhancements not yet built (Cursor-ready tiers) | `ENHANCEMENTS.md` |
| Topology diagram (labelled) | `diagrams/wazuh-ai-v3-gateway.drawio` |
| Turn-workflow diagram (labelled) | `diagrams/wazuh-ai-v3-workflow.drawio` |
| Icon-forward topology + turn flow | `diagrams/wazuh-ai-v3-icons.drawio` |
| Self-hosted PoC deployment (this box) + posture comparison | `diagrams/wazuh-ai-selfhosted.drawio` |
| Original self-hosted PoC decks (historical) | `diagrams/wazuh-ai-poc-architecture.drawio`, `wazuh-ai-enhancements.drawio` |

## 10. Deferred / roadmap

Second-environment isolation suite (V3.2, partial), streamable-HTTP `/mcp`
(V3.3), per-user identity propagation through the connector edge if OpenSearch
gains it (revisits D53, OQ-V3-4), the Bedrock fidelity leg (needs AWS creds),
shim audit-on-rejection, and PNG re-export of the v3 draw.io sources (no
headless exporter on the build host).
