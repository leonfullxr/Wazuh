<!-- HISTORICAL / IMPLEMENTATION RECORD. Current design: ARCHITECTURE.md.
     This doc keeps the actions design rationale, the phase instructions, and
     the Round-6 review findings. -->

# wazuh-ai v3.5 - Actions (write operations by design)

Date: 2026-07-15 · Implements D20/D35 · Supersedes ARCHITECTURE-V3.md §8 (actions deferred)

**Decision (Leon):** the assistant is not read-only long term. It must be able
to restart agents, create dashboards/visualizations, run active response, and
other Wazuh operations - but **never** by letting the model call a write API
directly. Writes follow the same veracity discipline as reads: typed params,
allowlists, audit, and an explicit human confirmation step.

---

## 1. What changes from v3

| v3 (read-only) | v3.5 (Actions) |
|---|---|
| Model calls read tools → immediate execution | Model calls **`propose_*`** tools → **proposal card** |
| `list_dashboards` (titles only) | `propose_create_dashboard` → confirm → saved object write |
| Manager API untouched | `propose_restart_agent`, `propose_active_response` → confirm → manager API |
| Env reader = read only | Env reader may **propose**; only **verified user** may **confirm** |
| Upstream `CONFIRM` string match | Typed confirmation via `POST /v1/actions/{id}/confirm` + idempotency key |

Query lanes (0/1/2), IR, four veracity checks, and citation rules for **read**
turns are unchanged. Actions are a **parallel lane A** (Actions v1.5).

---

## 2. Design decisions

| Tag | Decision |
|---|---|
| D20 | **Two-phase actions:** propose (model + typed schema + preview) → confirm (human + operator role + executor principal). The model never holds write credentials. |
| D35 | **Per-action-tier executor principals:** dashboard writes use an indexer saved-objects writer; manager mutations use a Wazuh API operator; active response uses a **narrower** AR executor with command allowlist. One compromised tier does not grant the others. |
| D48 | **Propose on every edge; confirm on direct edges only.** The dashboard connector (`EnvPrincipal`, D42) may create proposals so the UI can show a card, but `POST /v1/actions/{id}/confirm` requires a turn JWT with `wazuh_ai_operator`. When OpenSearch propagates verifiable user identity through the connector (OQ-V3-4), confirm may move to the dashboard without relaxing D20. |
| D49 | **Idempotency:** every confirm carries `Idempotency-Key` (or body field). Replays return the original result; no double restart / double AR. |
| D50 | **Action catalog is code, not prompt:** each action is a pydantic schema + preview function + executor. New actions = new golden cases, not new system-prompt paragraphs. |
| D51 | **Risk tiers gate UX:** `low` (dashboard create), `medium` (agent restart), `high` (active response). High-risk proposals include mandatory `reason` (min length) and surface target agent/command in the preview. |

---

## 3. Turn shape with actions enabled

```
User: "Create a brute-force GeoIP dashboard"
        │
        ▼
Lane 0 / scope (unchanged) ──miss──► model loop
        │
        ▼
Model calls read tools (auth_failures, search_alerts) - gather evidence
        │
        ▼
Model calls propose_create_dashboard(title, template=brute_force_geoip, ...)
        │
        ▼
Gateway validates schema → builds preview → stores ActionProposal (TTL 15m)
        │
        ▼
Answer includes proposal card:
  - proposal_id, preview markdown, risk tier
  - confirm URL (direct API or future dashboard widget)
  - label: "action proposed · not executed"
        │
        ▼ (analyst with wazuh_ai_operator role)
POST /v1/actions/{proposal_id}/confirm  +  Idempotency-Key
        │
        ▼
Executor for tier `dashboard` → indexer saved-objects API (operator creds)
        │
        ▼
Audit action_confirmed · answer / redirect to new dashboard
```

The model **must not** claim the dashboard exists until confirm succeeds.

---

## 4. Action catalog (v3.5a scaffold → v3.5b wire-up)

| Action | Tool name | Tier | Risk | Executor backend | Phase |
|---|---|---|---|---|---|
| Create dashboard | `propose_create_dashboard` | `dashboard` | low | OpenSearch saved objects (`.kibana`) | 3.5a schema + preview; 3.5b write |
| Create visualization | `propose_create_visualization` | `dashboard` | low | saved objects + index pattern ref | 3.5b |
| Restart agent | `propose_restart_agent` | `manager` | medium | `PUT /agents/{id}/restart` | 3.5a schema; 3.5b API |
| Run active response | `propose_active_response` | `active_response` | high | `PUT /active-response` (command allowlist) | 3.5a schema; 3.5b API |
| Remove agent | `propose_remove_agent` | `manager` | high | manager API | deferred |
| Email report | `propose_email_report` | `reports` | medium | indexer/reporting | deferred |

**Templates** (dashboard tier): curated panel bundles validated offline -
`brute_force_geoip`, `auth_failures_top_users`, etc. The model picks a template
or `custom` with an explicit panel list (bounded schema).

**Active-response allowlist** (initial): `restart-ossec`, `firewall-drop`,
`disable-account` - extend only with golden cases per command.

---

## 5. Identity and securityconfig

### Read path (unchanged)

- `wazuh_ai_analyst` → turn JWT → `wazuh_ai_analyst_role` (alerts read, C1, C3)
- `wazuh_ai_env_reader` → connector → read-only (D42)

### Write path (new)

| Principal | User | Role | Grants |
|---|---|---|---|
| Dashboard executor | `wazuh_ai_dashboard_writer` | `wazuh_ai_dashboard_writer_role` | `create`, `write`, `delete` on `.kibana*` saved objects only |
| Manager executor | `wazuh_ai_manager_operator` | `wazuh_ai_manager_operator_role` | Wazuh indexer security role mapping to manager API RBAC (restart, status) - **no** active-response |
| AR executor | `wazuh_ai_ar_executor` | `wazuh_ai_ar_executor_role` | Active-response API only, scoped commands |

Confirm endpoint verifies:

1. Turn JWT valid (D11)
2. `wazuh_ai_operator` ∈ `backend_roles` (umbrella - maps to executor creds server-side)
3. Proposal not expired, status `pending`, env matches token tenant
4. Idempotency key not already consumed

Executor credentials live in **environment registry** (D43), never in the model
context:

```yaml
- env_id: lab
  # ... existing reader ...
  dashboard_executor_basic: ${WAI_ENV_LAB_DASHBOARD_EXECUTOR}
  manager_api_url: https://wazuh.manager:55000
  manager_executor_basic: ${WAI_ENV_LAB_MANAGER_EXECUTOR}
  ar_executor_basic: ${WAI_ENV_LAB_AR_EXECUTOR}
```

---

## 6. API surface

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/v1/actions/{proposal_id}` | analyst JWT | Fetch proposal preview (for UI card) |
| `POST` | `/v1/actions/{proposal_id}/confirm` | operator JWT + idempotency | Execute proposal |
| `POST` | `/v1/actions/{proposal_id}/reject` | analyst JWT | Cancel pending proposal |

Chat SSE may emit `event: action_proposed` with `{proposal_id, preview, confirm_path}` for n8n/dashboard widgets (v3.5c).

Config: `WAI_ACTIONS_ENABLED=true` adds `propose_*` tools to the model catalog.

---

## 7. Implementation phases

| Phase | Deliverable | Acceptance |
|---|---|---|
| **V3.5a** (this PR) | `app/actions/*`, propose tools, confirm API, securityconfig scaffold, tests | Proposal + confirm flow works; executor returns `not_configured` without creds; env principal cannot confirm |
| **V3.5b** | Wire dashboard executor (saved objects), manager restart, AR allowlist | Golden case: create brute-force dashboard; restart agent in lab; AR dry-run |
| **V3.5c** | Dashboard UI confirm card; operator role on lab users | Click confirm in Wazuh dashboard without curl |
| **V3.5d** | `make evals-actions` | Bilingual action golden set |

---

## 8. What we explicitly do not do

- **No** `CONFIRM` in chat text as authorization (upstream anti-pattern).
- **No** write grants on `wazuh_ai_env_reader` or analyst read role.
- **No** free-form dashboard JSON from the model - templates + bounded `custom`.
- **No** active-response commands outside the allowlist.
- **No** executing proposals from the connector edge until D48 is revisited with verifiable user propagation.

---

## 9. Open questions

- **OQ-V3-4:** OpenSearch 3.x / assistant plugin user propagation for in-dashboard confirm without a side-channel JWT.
- **OQ-V3-5:** GeoIP field names vary by Wazuh version - dashboard templates versioned per `WAZUH_VERSION`.
- **OQ-V3-6:** Whether operator role should be per-action (`wazuh_ai_ar_operator` vs `wazuh_ai_operator` umbrella).

---

## 10. Diagram delta

Update `diagrams/wazuh-ai-v3-gateway.drawio` box "Deferred by design (D47)" →
**Actions v3.5 (D20/D35):** propose in loop · confirm via `/v1/actions` ·
tiered executors.

---

## Round 6 - review findings on the V3.x + actions implementation (2026-07-16)

Verdict: the propose→confirm machinery, tiered executors, idempotency store
and audit events are the right skeleton, and 64/64 unit tests pass. But the
implementation ships with its safety inverted by default, and the
active-response executor has a targeting bug that could fire fleet-wide.
Decision context (Leon): the assistant is write-capable **long term, by
design** - these findings ARE the long-term design; fix them, don't patch
around them. Blockers R6.1-R6.5 land before any live actions test.

### R6.1 Active-response targeting - CRITICAL BLOCKER

Verified against the live Wazuh 4.14 API spec: `agents_list` is a **query
parameter** whose documented default is **"all agents selected by default if
not specified"**. `execute_active_response_action` sends `"agents"` in the
**body** - a field `ActiveResponseBody` does not define. Depending on API
strictness that is either a guaranteed 400 or a **fleet-wide command
execution**. Neither is acceptable.

| File | Change |
|---|---|
| `tool-service/app/actions/executors.py` | `params={"agents_list": p.agent_id}` on the PUT; remove `agents` from the body. The request MUST be refused client-side if `agent_id` is empty - never emit an AR call without an explicit `agents_list`. Same pattern check on `restart_agent` (path-param form is fine as implemented). |
| tests | A unit test asserting the built request has `agents_list` set and that an empty agent id raises - this class of bug must be structurally unrepresentable. |

### R6.2 Direct mode defaults + fabricated operator - BLOCKER

`actions_direct` defaults to **True** (execute on model tool call, no
confirm), and `operator_for_writes` **synthesizes** a `User` carrying
`wazuh_ai_operator` for the env-scoped connector principal. Together the
unverified dashboard edge executes writes with an invented operator - the
upstream anti-pattern this document exists to reject, reintroduced as the
default. Long-term rulings:

- `actions_direct` **defaults to False**. Propose→confirm is the product.
- Direct mode, when explicitly enabled, requires a **verified User** with the
  operator role AND applies to the **dashboard tier only**. Manager and
  active-response tiers execute exclusively through `/v1/actions/{id}/confirm`
  - no configuration combination may bypass that.
- `operator_for_writes` never fabricates identity: an `EnvPrincipal` gets
  `ActionPermissionError`, full stop. The connector edge proposes; it never
  executes (D48 as written).

### R6.3 Active-response `arguments` - BLOCKER

`ActiveResponseParams.arguments` is a free-form `dict` (and the executor
sends `p.arguments or []` - a type it can never be). The highest-risk action
must not carry an unbounded injection surface: make it `list[str]`,
`max_length=5`, each item `max_length=100`, pattern-restricted to
`[A-Za-z0-9._:/-]` - or drop it entirely for the three allowlisted commands
(none require custom arguments). Prefer dropping it.

### R6.4 Dashboard field auto-fix is discarded - BLOCKER

`_prepare_dashboard_objects` computes `resolved = validate_and_resolve_bundle_fields(...)`
and throws it away (lint flags it); the ORIGINAL objects are written. The
".keyword-suffix auto-fix" the resolver exists for never applies - dashboards
get created with broken field references whenever resolution changed
anything. Write the resolved bundle.

### R6.5 The actions eval artifact contradicts itself - BLOCKER

`golden/last_run_actions.json` reports `passed: 4 / total: 4` in the header
while every case record carries `passed: false` with empty failures. The
runner's record bookkeeping is broken, which means the actions gate currently
asserts nothing. Fix `run_evals_actions.py` record handling (mirror the main
runner's), then re-run - do not trust any prior green from this artifact.

### R6.6 Per-environment, per-tier action enablement (long-term)

A customer environment must **opt in per tier**. Registry entries gain
`actions: [dashboard]` (deny-by-default; `manager` and `active_response`
listed explicitly per env). The proposal step already knows the env - refuse
at propose time with an honest "actions of this tier are not enabled for
this environment". `WAI_ACTIONS_ENABLED` stays as the global master switch,
and the per-env kill switch covers actions too.

### R6.7 Re-type friction for high-risk confirms (Actions v1.5, D-notes)

For `risk == high` the confirm body must echo the target:
`{"confirm_target": {"agent_id": ..., "command": ...}}`, compared against the
proposal server-side; mismatch → 409 with the diff. A mis-click can restart
an agent; it must not be able to fire `disable-account` on the wrong target.

### R6.8 Blast-radius caps (D14 extended to writes)

Per-env, per-tier execution rate caps in the registry (defaults:
`manager: 10/h`, `active_response: 5/h`, dashboard uncapped). Cap hit →
honest 429 on confirm, audited `action_rate_limited`. Ten bad confirms should
not be able to become a hundred.

### R6.9 Saved objects via the Dashboard API, not raw index writes

`_write_saved_objects` PUTs documents into a hardcoded `.kibana_1` - silently
wrong after any OSD migration (alias moves to `.kibana_2`, dashboards vanish
into an orphan index) and it bypasses reference integrity. Long-term: the
dashboard executor talks to the **Dashboards saved-objects HTTP API**
(`POST <dashboard_url>/api/saved_objects/_bulk_create`, `osd-xsrf: true`,
executor basic auth). Registry gains `dashboard_api_url`. The stray
`osd-xsrf` header on indexer requests shows this was the original intent.

### R6.10 Executor TLS + manager RBAC (hygiene, same pass)

- All executor HTTP clients honor the env CA (`indexer_ca_path` /
  a new `manager_ca_path`) instead of `verify=False`.
- Setup docs/scripts create **least-privilege Wazuh API users** per tier via
  Wazuh RBAC policies: manager executor = `agent:restart` only; AR executor =
  `active-response:command` only. Never `wazuh-wui`/admin as an executor.
- Idempotency key reuse across *different* proposals → 409 (today the second
  proposal silently returns the first's result and stays pending).
- Proposal store gets the standard cheap bound (evict expired beyond 512).

### R6.11 Operator roles per exposure (ruling on OQ-V3-6)

Two roles, not one umbrella: `wazuh_ai_operator` confirms dashboard-tier;
`wazuh_ai_responder` additionally required for manager + active-response
tiers. Lab users (`operator1`, etc.) carry both roles. Cheap
now, painful to retrofit after customers exist.

### R6.12 Status corrections to this document

- V3.3 (streamable-HTTP `/mcp` with env-key auth) is **not implemented** -
  the stdio adapter is unchanged. Keep it on the roadmap; do not mark done.
- V3.2 is partial: the registry and constant-time key resolution are real;
  the second-environment isolation extension has no suite yet.
- COMMIT the working tree before applying Round 6 - the entire V3.x + actions
  implementation is currently uncommitted, and uncommitted work has been
  clobbered twice in this project's history.
