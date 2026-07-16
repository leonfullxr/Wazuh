# wazuh-ai v3 — the multi-environment MCP-LLM Gateway behind the Dashboard Assistant

> **Current design lives in [`ARCHITECTURE.md`](ARCHITECTURE.md)** (consolidated,
> as-built). This file is the V3.1–V3.7 implementation record: phase
> instructions, payloads, and rationale. Follow-ups:
> [`ARCHITECTURE-V3.5-ACTIONS.md`](ARCHITECTURE-V3.5-ACTIONS.md) (actions),
> [`ARCHITECTURE-V3.8-UX.md`](ARCHITECTURE-V3.8-UX.md) (language, Keycloak
> removal, conversational confirm).

Date: 2026-07-15 · Author: Claude (reviewer) · Implementer: Cursor
Decision (Leon): the chat moves INTO the Wazuh dashboard via the OpenSearch
Dashboards Assistant + ML Commons HTTP connector, following the shape of the
official reference at
[wazuh/integrations → AI_assistant](https://github.com/wazuh/integrations/tree/main/integrations/AI_assistant),
with OUR gateway replacing its gateway — redesigned to serve **many
environments from one deployment**. PoC: one environment on the existing
docker harness, local LLM, 16 GB inference budget — but every interface is
the multi-environment shape.

**How to use this file (Cursor):** implement phase V3.1 fully before touching
V3.2+. Mirror the upstream installer's ML Commons object shapes exactly where
this doc says "as upstream" — the working reference is
`install_ai_assistant.sh` in the wazuh/integrations repo (concrete payloads
quoted below so you don't need to re-derive them). Keep D-tag comments; new
decisions are D42–D47.

---

## 1. What we adopt from upstream, and what we replace

The reference integration proves the edge works on exactly our version line
(Wazuh 4.14.x / OpenSearch 2.19.4): `assistantDashboards` +
`mlCommonsDashboards` plugins on the Wazuh dashboard, an ML Commons remote
model whose HTTP connector points at a gateway, a conversational agent with
`max_iteration: 1` wired as the `os_chat` root agent. We adopt that edge
verbatim.

What we replace — the gap table (this is why our gateway exists):

| Dimension | Upstream reference | wazuh-ai v3 |
|---|---|---|
| Query generation | LangChain agent free-forms queries (incl. DQL) | Model never writes a query: lanes, typed tools, IR, allowlist (D4) — unchanged |
| Veracity | None: no checks, no citations, no eval gate | Four checks, citation + grounded-number verification, verifiability label, golden set (D23/D24/D33) |
| Data-plane identity | Indexer **admin** credentials in the MCP server | Per-environment read-only principal; per-user turn JWT preserved on direct surfaces (D11, D42) |
| Gateway auth | One static API key for everything | Per-environment credential → environment resolution; env identity never from payload (D6/D43) |
| Environments | One installation per environment, on the Wazuh nodes | One central gateway, N environments (D43); PoC runs one |
| LLM | OpenAI / Gemini / Bedrock only | The existing provider port: local Ollama first, Bedrock unchanged |
| Actions | Agent restart/remove, dashboards, PDF email with text `CONFIRM` | **V3.5** Actions v1.5: propose → confirm (D20/D35) — see ARCHITECTURE-V3.5-ACTIONS.md |
| Topology | Gateway + separate MCP server (2 services) | One service: the tool-service IS the gateway; the MCP surface is a projection of the same registry (D44) |

## 2. New design decisions

| Tag | Decision |
|---|---|
| D42 | The dashboard-assistant edge is **environment-scoped, not user-scoped**. The 2.19 connector cannot propagate the dashboard user's identity verifiably, so turns entering through it execute as that environment's dedicated read-only principal. Per-user D11 identity remains on every direct surface (n8n, API, MCP-with-JWT). The downgrade is explicit in the answer label and in audit. |
| D43 | One gateway, many environments. An environment registry maps credential → environment → {indexer endpoint, CA, reader principal, budgets, locale}. The environment id NEVER comes from the request payload — only from the verified credential (D6 extended). Admission (D14), evidence cache, lane-0 vectors, audit and kill switch are all per-environment. |
| D44 | The gateway and the MCP server are one deployable. The typed tool registry is the single catalog; the MCP surface and the connector surface are projections of it. Splitting into two services later is a deployment choice, not a rewrite — the registry is the seam. |
| D45 | Conversation memory on the connector edge belongs to ML Commons (`conversation_index`, `message_history_limit: 10` — as upstream). The gateway treats each `/analyze` call as self-contained; its own conversation store keeps serving the direct surfaces. One memory owner per edge, never two. |
| D46 | Local-first inference for the PoC under a 16 GB budget: `gpt-oss:20b` (≈13 GB, validated 9/9 with lane 0), embeddings in-cluster via ML Commons (C3 — per environment, which is exactly the right scaling shape), Bedrock path unchanged for production. |
| D47 | Upstream's naive `CONFIRM` string-match is rejected. Write operations ship via Actions v3.5 (D20/D35), not v3 read-only. |

## 3. Target topology (many environments) and PoC realization

```
ENVIRONMENT 1..N (customer Wazuh, 4.8–4.16.x / OpenSearch 2.19.x)
┌────────────────────────────────────────────────────────┐
│ Wazuh Dashboard + assistantDashboards/mlCommonsDashboards
│   └─ ML Commons (indexer): remote model + conversational agent
│        └─ HTTP connector ──── env credential ────┐
│ Wazuh Indexer: alerts, states indices,           │
│   ML Commons embeddings model (C3),              │
│   wazuh_ai_env_reader principal (read-only)      │
└──────────────────────────────────────────────────┼─────┘
                                                   ▼
CENTRAL (one deployment for all environments)
┌────────────────────────────────────────────────────────┐
│ wazuh-ai GATEWAY (the tool-service, evolved)           │
│  surfaces: /v1/connector/analyze (NEW, ML Commons)     │
│            /v1/chat, /v1/chat/sync, /v1/tools (as-is)  │
│            /mcp (streamable HTTP, V3.3)                │
│  env registry: credential → env → indexer/CA/reader    │
│  per-env: admission · evidence cache · lane-0 vectors  │
│           · audit stream · kill switch                 │
│  the SAME core: lanes · IR · compiler · 4 checks ·     │
│  citations · grounded numbers · knowledge/env tools    │
│  provider port: Ollama (local) · Bedrock · OpenAI-compat│
└────────────────────────────────────────────────────────┘
```

PoC realization on the existing harness: the docker Wazuh single-node is
environment `lab`; the gateway is the existing tool-service container with the
new surface; Ollama serves `gpt-oss:20b`; the registry holds one entry. The
connectivity assumption (gateway can reach each environment's indexer) matches
the Wazuh Cloud topology this mirrors; on-prem environments would need an
outbound-only pattern — recorded as open question OQ-V3-1, out of PoC scope.

## 4. Identity model per edge (read this before writing any code)

| Edge | Who the query runs as | How the caller is verified |
|---|---|---|
| Dashboard assistant (connector) | `wazuh_ai_env_reader` — per-env, read-only, indexer-local | Per-env gateway credential in the connector (`X-Env-Key`), stored encrypted by ML Commons |
| n8n / direct API / eval runner | The analyst (turn JWT, D11) — unchanged | Indexer Basic creds → shim authinfo verify → turn JWT (V3.6; no IdP stand-in) |
| MCP adapter | The analyst (turn JWT it mints/refreshes) — unchanged | Same chain |

Rules that make the downgrade honest:
- The env reader principal is created in each environment's securityconfig:
  role `wazuh_ai_env_reader_role` = read-only on `wazuh-alerts-*` + the C1
  grants (`indices:monitor/*` scoped, saved-objects read, ml predict for C3).
  It can never write, never read other indices — prove it with the same
  curl-pair negative tests as D11.
- Answers on this edge carry the label suffix `· environment-scoped identity`
  so an analyst (and a screenshotting auditor) can see which trust level
  produced the answer.
- Audit `turn_complete` on this edge records `env`, `edge: "connector"`, and
  `user: null` (do NOT log an unverifiable username as if it were verified;
  if ML Commons ever passes one, record it under `claimed_user`).

## 5. Phase V3.1 — the connector edge, single environment (the PoC)

### V3.1a Environment registry (the multi-env seam)

| File | Change |
|---|---|
| `tool-service/app/environments.py` | `EnvConfig` dataclass: `env_id, indexer_url, indexer_ca_path, reader_bearer (or reader_basic), embed_ml_model_id, locale, admission overrides`. Loader: `WAI_ENVS_FILE` (YAML, one doc per env) with a single-env fallback built from today's `WAI_*` vars so the existing harness config keeps working unchanged. `resolve_by_key(key) -> EnvConfig` via constant-time compare of per-env `gateway_key`. |
| `tool-service/app/indexer.py` | `Indexer` becomes per-env: registry dict `env_id -> Indexer` built from EnvConfig (today's singleton = the `lab` entry). `execute_ir` and friends take the env's client. |
| `tool-service/app/admission.py`, `veracity.py` (evidence cache), `lane0.py`/`embeddings.py` (vector + turn caches), `audit.py` (add `env` field) | Key all per-env state by `env_id`. Mechanical; the PoC exercises one env but the keying is the deliverable. |

`environments.yaml` (PoC content, committed as `.example`):

```yaml
- env_id: lab
  gateway_key: ${WAI_ENV_LAB_KEY}        # strong random; the connector credential
  indexer_url: https://wazuh.indexer:9200
  indexer_ca_path: ""                    # lab; prod pins per-env CA
  reader_basic: ${WAI_ENV_LAB_READER}    # "user:pass" of wazuh_ai_env_reader
  embed_ml_model_id: ${WAI_EMBED_ML_MODEL_ID}
  locale: bilingual
```

### V3.1b The connector surface

| File | Change |
|---|---|
| `tool-service/app/main.py` | `POST /v1/connector/analyze`. Auth: `X-Env-Key` header → `environments.resolve_by_key` (401 on miss, audit `env_key_rejected`). Body: `{"parameters": {"prompt": "..."}}` — as upstream. Runs `run_turn` with an env-scoped principal (V3.1c) and returns **`{"output": {"message": "<answer>\n\n_<label> · environment-scoped identity_"}}`** — the shape the upstream agent's `response_filter: $.output.message` expects. Non-streaming (the connector is one-shot; `request_timeout 120s` upstream — honor `WAI_CONNECTOR_TIMEOUT_S`, default 110, and return the budget-note answer if the loop overruns, never a 504). |
| `tool-service/app/loop.py` | `run_turn` gains a `principal` argument: either the existing `User` (turn JWT) or a new `EnvPrincipal(env_id)`; the veracity executor picks the indexer client + credential from it. Lane 0, scope, knowledge, env tools all work identically — they are principal-agnostic by construction. |
| `tool-service/app/auth.py` | `EnvPrincipal` dataclass; no minting, no JWT — the reader credential lives in EnvConfig and is attached at the indexer client, never handed to the model or the caller. |

### V3.1c The environment reader principal

| File | Change |
|---|---|
| `securityconfig/` | New internal user `wazuh_ai_env_reader` + role `wazuh_ai_env_reader_role`: read-only `wazuh-alerts-*`, the C1 monitor/saved-objects grants, the C3 ml-predict grant. Applied by the same `apply.sh` flow. |
| `README.md` §4 | The negative proof extends: env reader can `_count`, cannot DELETE, cannot read non-granted indices — same curl pair, third principal. |

### V3.1d Dashboard assistant installation (our harness)

The wazuh-docker dashboard container loses hand-installed plugins on
recreate, so bake them:

| File | Change |
|---|---|
| `dashboard-assistant/Dockerfile` | `FROM wazuh/wazuh-dashboard:${WAZUH_VERSION}`; read the OSD version from `/usr/share/wazuh-dashboard/package.json` at build time; download `https://artifacts.opensearch.org/releases/bundle/opensearch-dashboards/<ver>/opensearch-dashboards-<ver>-linux-x64.tar.gz`; copy `plugins/assistantDashboards` and `plugins/mlCommonsDashboards` into the wazuh-dashboard plugins dir with `wazuh-dashboard:wazuh-dashboard` ownership, mode 750 — exactly the upstream installer's steps, containerized. |
| wazuh-docker overlay | Point the single-node compose at the derived image (document the one-line image override rather than patching the cloned repo; `make dashboard-assistant` builds and swaps it). Add `assistant.chat.enabled: true` to the mounted `opensearch_dashboards.yml`. |

### V3.1e ML Commons wiring (setup script, as upstream with our endpoint/auth)

| File | Change |
|---|---|
| `scripts/dashboard_assistant_setup.sh` + `make assistant-setup` | Idempotent (delete-and-recreate by name). Steps, with upstream's exact payload shapes: |

1. Cluster settings (PUT `_cluster/settings`, persistent):
   `plugins.ml_commons.agent_framework_enabled: true`,
   `only_run_on_ml_node: false`, `connector.private_ip_enabled: true`,
   `trusted_connector_endpoints_regex` += `^http://tool-service:8080/.*$`
   (the in-network gateway URL — NOT localhost; the connector fires from the
   indexer node).
2. Register + deploy the remote model with inline connector — as upstream,
   with: `endpoint = http://tool-service:8080/v1/connector/analyze`, header
   `X-Env-Key: ${credential.api_key}`, credential = the env's `gateway_key`,
   `request_body: {"parameters": {"prompt": "${parameters.prompt}"}}`,
   `request_timeout: 120s`.
3. Register the conversational agent — as upstream verbatim: type
   `conversational`, `app_type: os_chat`, llm parameters
   `prompt: ${parameters.question}`, `response_filter: $.output.message`,
   `max_iteration: 1`, `stop_when_no_tool_found: true`,
   `message_history_limit: 10`, memory `conversation_index`, one placeholder
   `SearchIndexTool` (the framework requires a tool; the gateway does the work).
4. Root agent: PUT `.plugins-ml-config/_doc/os_chat` with
   `{"type": "os_chat_root_agent", "configuration": {"agent_id": ...}}`
   using the admin cert pair — as upstream.
5. Print the verification steps: dashboard → Assistant icon → "Hi".

Note on the inbound prompt: with `max_iteration: 1` the agent composes
question + recent history into `${parameters.prompt}`. The gateway treats the
whole string as the turn text (D45). Do not try to parse history out of it.

### V3.1f Eval leg through the dashboard path

| File | Change |
|---|---|
| `golden/run_evals.py` | `WAI_EVAL_EDGE=connector` mode: instead of the JWT chain + `/v1/chat/sync`, execute each case via the agent: `POST /_plugins/_ml/agents/<agent_id>/_execute` with `{"parameters": {"question": ...}}` (admin basic auth, reading agent_id from the setup script's output file). Assertions unchanged except: `verifiability` is extracted from the returned message text (the label line), and identity-dependent asserts are skipped with an explicit `SKIPPED (env-scoped edge)` print, never silently. |
| `Makefile` | `make evals-connector`. |

**Phase V3.1 acceptance:**
1. `make dashboard-assistant assistant-setup` on the running harness → the
   Assistant icon appears in the Wazuh dashboard and answers "Hi".
2. Asking the six demo-storyline questions in the dashboard produces the same
   answers as n8n, each labeled with `· environment-scoped identity`.
3. `make evals-connector` passes the same golden cases (11 minus the
   explicitly-skipped identity negatives) through the dashboard path.
4. The env reader negative proof: reader can read alerts, cannot DELETE,
   cannot read an ungranted index.
5. A wrong `X-Env-Key` → 401 + `env_key_rejected` audit; the key never
   appears in any log.
6. Everything existing stays green: `make test`, `make evals` (direct edge,
   per-user identity intact).

## 6. Phase V3.2 — second environment (proving D43)

Stand up environment 2 as the kind tenant-b namespace from Track B (or a
second wazuh-docker on another port — pick whichever is cheaper after Track B
lands). Registry gains a second entry with its own `gateway_key`, reader
principal and indexer endpoint. The isolation suite extends: env-1's key
against env-2's data is impossible by construction (the key resolves to
env-1's indexer client — there is no request field to say otherwise), and the
per-env kill switch (`enabled: false` in the registry entry) 503s one
environment while the other keeps answering.

## 7. Phase V3.3 — the MCP surface, multi-environment

`mcp/server.py` (stdio, host-local) evolves into a streamable-HTTP MCP
endpoint on the gateway (`/mcp`), auth accepting either a turn JWT (per-user,
D11) or an env key (env-scoped, D42) — the same principal resolution as every
other surface. The tool list is the same registry. Claude Desktop/Cursor
config moves from spawning a local process to a URL + credential. The stdio
adapter stays for offline/dev use.

## 8. Deferred with intent

- **States indices** (`wazuh-states-vulnerabilities`, `wazuh-states-inventory-*`
  — upstream's SCA/vuln/hygiene questions): legitimate and valuable, but each
  index family needs its own allowlist + tools + golden cases. Spec as V3.4
  after the connector edge is green; do not widen `ALLOWED_FIELDS` casually.
- **Per-user identity through the connector**: revisit if/when the assistant
  plugin or ML Commons grows verifiable user propagation (OpenSearch 3.x
  line); the gateway's principal abstraction (V3.1b) is the ready seam.

**Actions (write operations)** moved to **ARCHITECTURE-V3.5-ACTIONS.md** (D20/D35).
V3.5a scaffolds propose/confirm; V3.5b wires executors; V3.5c adds dashboard
confirm UI.

## 9. PoC resource budget (16 GB inference)

`gpt-oss:20b` ≈ 13 GB + 16k KV ≈ 1 GB fits; embeddings are in-cluster (C3),
so Ollama holds exactly one model. `qwen3:30b-a3b-instruct-2507` remains the
validated quality alternative where >20 GB is available. RAG posture is
unchanged and already built: lane 0 + scope + few-shot (question embeddings),
knowledge + environment tools (curated/exact retrieval), evidence cache,
prompt/KV caching. No vector store over telemetry — D4/D5 survive v3 intact.

## 10. Diagrams

`diagrams/wazuh-ai-v3-gateway.drawio`: page 1 = target multi-environment
topology (this file §3), page 2 = PoC realization on the harness with the
exact container/port/credential wiring.

`diagrams/wazuh-ai-v3-workflow.drawio`: one turn end to end as built through
V3.8 — both edges, admission, conversational/API confirm, language+scope, the
read lane cascade (lanes 0/1/2, knowledge/env/states tools), the write-actions
lane, the veracity pipeline, and answer assembly. This is the current
turn-workflow reference; the historical decks (`wazuh-ai-poc-architecture`,
`wazuh-ai-enhancements`) cover the pre-v3 layers.

PNG exports are pending a manual draw.io export (no headless exporter on the
build host); the `.drawio` sources are the source of truth.

## Open questions

- **OQ-V3-1**: on-prem environments where the gateway cannot reach the
  indexer inbound — candidate: per-env outbound agent/tunnel. Out of scope.
- **OQ-V3-2**: connector `request_timeout` ceiling vs slow local models —
  110 s gateway budget forces lane-0/cache coverage for the dashboard's
  common questions; measure hit rates per env and tune the corpus.
- **OQ-V3-3**: does `mlCommonsDashboards` require any indexer-side settings
  beyond §V3.1e on the Wazuh fork — verify during V3.1d bring-up.

---

## Phase V3.6 — identity without Keycloak (decision: Leon, 2026-07-16)

**D52.** Keycloak is removed. It was the lab stand-in for a customer-SSO
world that v3 no longer describes: environments are Wazuh deployments that
already own a user store — the OpenSearch security plugin (internal users,
LDAP, or SSO the env admin configured there). The shim's verify-only posture
(D30) is unchanged; only its **verification source** changes: from Keycloak
JWKS to the environment's own indexer via
`POST /_plugins/_security/authinfo`. Everything downstream is byte-identical
(turn JWT mint + TTL + dual audience, indexer JWT auth domain, D11
queries-as-user). Environments with SSO inherit it through the security
plugin — we support SSO without owning an IdP. If a future product needs an
IdP decoupled from Wazuh accounts, the shim's verify-X-mint-Y seam takes an
OIDC verifier back as a contained change.

Tenant-claim subtlety (D6 preserved): the login request names its
environment as a *hint*; the shim verifies the credentials against **that
environment's indexer** — the `tenant` claim is proven by authinfo
succeeding on that env, never asserted by the payload.

| File | Change |
|---|---|
| `auth-shim/app/main.py` | Rewrite exchange: `POST /v1/token/exchange` with Basic auth (+ `X-Env-Id` hint, default sole env) → `authinfo` against that env's indexer (CA from registry) → require `wazuh_ai_analyst` in `backend_roles` → mint the same turn JWT (`sub` = user_name, `backend_roles` verbatim from authinfo, `tenant` = verified env). Drop all `SHIM_KC_*`; add `SHIM_ENVS_FILE` (same `environments.yaml`). |
| `securityconfig/` | Grant the shim an authinfo-capable path: authinfo authenticates the USER's own creds, so no shim principal is needed at all — the shim holds only the mint key. Add `wazuh_ai_analyst`/`wazuh_ai_operator`/`wazuh_ai_responder` as backend_roles on the lab users (create `analyst1`, `operator1` as internal users; delete the Keycloak realm coupling). |
| `docker-compose.poc.yml` | Delete the `keycloak` service; shim mounts `environments.yaml` read-only. |
| `keycloak/` | Delete directory (realm export becomes git history). |
| n8n workflow, `mcp/server.py`, `golden/run_evals.py`, actions confirm UI (`ui_static.py`) | One-call login: Basic creds → shim → turn JWT. Drop the OIDC leg everywhere. |
| Track B kind manifests | Per-tenant realm replaced by per-env internal users; the cross-tenant token assertion is unchanged (still distinct mint keys + tenant claims). |
| `README.md` §4, diagrams | Identity chain: analyst creds → shim verifies via env indexer authinfo → turn JWT ≤10 min → core + indexer verify. Keycloak boxes removed from the v3 deck (older decks are historical). |

**Acceptance:** all existing identity negatives pass with the new chain
(wrong password → 401 at authinfo; user without the analyst backend_role →
403 at the shim; cross-env credentials → 401, audited); `make evals` and the
actions confirm flow green with zero Keycloak references left in compose,
Makefile, or docs; RAM footprint drops by the Keycloak container.

---

## Phase V3.7 — environment & domain context: closing the answer-quality gap

Reference studied: the upstream gateway ships a ~10 KB domain prompt plus
per-intent prompt files (`dashboard-builder.prompt`, `dql-builder.prompt`,
`report-generator.prompt`). Its dashboards are better than ours for two
reasons: richer **construction code** behind a strict spec, and a prompt that
teaches **domain recipes** (multi-signal brute-force, severity bands, geo
fields). Our ruling for adopting this: **teach code first, prompt second** —
every upstream prompt-policy that can become a typed tool or template becomes
one (that is our structural advantage); only composition semantics the model
genuinely needs go into prompt modules. Everything below is eval-gated (D33).

### V3.7a Tool/template upgrades (code, the biggest wins)

| Item | Change |
|---|---|
| `auth_failures` tool | **Bug found via upstream:** filter `rule.groups` on ANY of `authentication_failed`, `authentication_failures`, `win_authentication_failed` (today only the first — Windows auth failures are invisible). `op: in` on the existing IR. Golden case with a seeded Windows auth-fail alert. |
| New lane-1 tool `brute_force_summary` | The upstream 3-signal recipe as a typed tool: MITRE (`rule.mitre.id` = T1110) OR auth-fail groups, aggregated by `data.srcip` and `data.dstuser`, with timeline. One tool call instead of hoping the model composes it. |
| `dashboard_templates.py` | Match upstream's output quality per template: metric header row, timeline histogram, top-N tables (srcip, dstuser), geo **region map** built from the fields that actually exist in the live mapping (`GeoLocation.*` on stock Wazuh; the field_resolver already validates against the mapping — extend its alias table with upstream's alias rules). Panel sizing via the existing layout engine. |
| New knowledge tool `dashboard_design_guide` | Already referenced by the schema's error text — make it real: returns available templates, panel types, field aliases, sizing rules. The model consults it before proposing `template=custom`. |

### V3.7b Prompt modules (bounded, versioned, cache-stable)

`tool-service/app/prompts/*.md`, loaded at startup, byte-stable per build:

| Module | Content | When appended |
|---|---|---|
| `domain.md` (~600 tokens) | Severity bands (rule.level 0–6/7–11/12–14/15+), the auth-failure group triad, geo enrichment field names, "totals from total_matching" reinforcement | Always (part of the static prelude — extends the prompt-cache prefix, never varies per turn) |
| `reporting.md` (~400 tokens) | Upstream's answer shape adapted: Summary with exact total · Key findings with citations · Impact · Recommendation · Triage (Benign/Suspicious/Malicious + confidence). | Analysis-tier turns only |
| `dashboards.md` (~400 tokens) | Template catalog one-liners, custom-panel schema, field alias hints | Only when action tools are offered |

### V3.7c Environment context card (dynamic, per-env, cached)

A compact per-env block (≤800 tokens) injected as a **transient message**
(after the static prefix — same cache rule as the near-miss hint): Wazuh
version, agent count + OS mix, top rule groups (7d), whether geo/vuln fields
exist in the mapping, existing dashboard titles (dedupe hint for
`propose_create_dashboard`). Built from the env tools we already have,
cached per env with a 15-minute TTL (`WAI_ENV_CARD_TTL`), disclosed in audit
(`env_card_age_s`). This is what "understands the environment" means without
embedding telemetry.

### V3.7d Eval additions

Golden: Windows auth-fail case; brute-force summary case asserting the
3-signal recipe ran (tool selection); dashboard-quality case asserting the
proposed brute-force bundle contains ≥4 panels including a geo map and a
timeline (assert on the proposal preview, no confirm needed). Actions eval
gains a `custom` template case exercising `dashboard_design_guide`.

**Acceptance:** `make evals` green including new cases; a "create a brute
force dashboard" proposal preview lists metric+timeline+top-N+geo panels
comparable to the upstream reference; prompt-cache prefix stability
verified unchanged (static modules extend the prelude; the env card rides as
a message).

---

## Phase V3.4 — states indices (vulnerabilities first)

Deferred from §8 until the connector edge and V3.7 domain context were green.
Upstream answers SCA/vuln/hygiene questions against `wazuh-states-vulnerabilities-*`
and `wazuh-states-inventory-*`. Our ruling: **never widen the alerts
`ALLOWED_FIELDS` table** — each index family gets its own IR, compiler, and
veracity path (same D4/D24 guarantees, separate seam).

### V3.4a Vulnerability states (first family)

| Item | Change |
|---|---|
| `index_families.py` | `IndexFamily` enum, per-family index patterns, allowlists, time fields, `_source` projections |
| `states_models.py` | `StatesQueryIR` + validators against `VULN_ALLOWED_FIELDS` only |
| `states_compiler.py` | IR → OpenSearch DSL for `wazuh-states-vulnerabilities-*` (`vulnerability.detected_at` window) |
| `states_veracity.py` | Same four checks as alerts, keyed on the vuln index mapping |
| `indexer.py` | `search_index(pattern, …)` + `get_mapping(pattern, …)` — alerts path unchanged |
| Lane-1 tools | `count_vulnerabilities`, `vulnerabilities_by_severity` (terms on `vulnerability.severity`) |
| `config.py` / env registry | `vulnerabilities_index` default `wazuh-states-vulnerabilities-*` |
| `seed/seed_vulnerabilities.py` | Idempotent sample CVE rows for golden cases (marker `wazuh-ai-seed-vuln`) |
| `prompts/domain.md` | One paragraph: states indices are snapshot inventory, not alert streams |

### V3.4b Inventory states (second family, after vuln evals green)

`wazuh-states-inventory-*` (packages, ports, processes, hotfixes) — same
pattern: own allowlist, own tools (`inventory_packages`, …), own golden cases.
Do not start until V3.4a evals pass.

### V3.4c Eval additions

Golden: total vulnerability count; top severity breakdown; agent-scoped vuln
count. Connector-edge cases skip user-scoped negatives; env reader must have
read on the states index pattern in securityconfig.

**Acceptance:** `make evals` green on vuln cases; alerts evals unchanged;
`ALLOWED_FIELDS` in `models.py` still alerts-only; states queries rejected if
they reference alert fields and vice versa.
