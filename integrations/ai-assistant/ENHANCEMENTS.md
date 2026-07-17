# Enhancements - implementation spec (for Cursor)

Forward-looking work. Current design is in [`ARCHITECTURE.md`](ARCHITECTURE.md);
the journey and rationale in [`DESIGN-JOURNAL.md`](DESIGN-JOURNAL.md). Apply
items in tier order (E1 first). New decisions are **D55-D59**; keep the D-tag
comment convention. Every item that changes an answer or an action path gets a
golden case (D33) - it is not done until the eval covers it.

## Guardrails (constrain every item below)

These are the project's design laws; an enhancement that breaks one is wrong,
not clever.

- **Query, don't embed (D4/D5).** Tenant telemetry is never vectorized. The
  only sanctioned vector store is over *public reference content* (E6).
- **The model never writes a query and never computes a number (D4).** New
  capabilities are typed tools/IR, compiled and veracity-checked server-side.
- **Writes are propose→confirm (D20).** No new capability executes a mutation
  without the confirm step and a tiered executor credential the model never
  holds.
- **No semantic answer cache, no LLM-judge in the live path, no free-generation
  lane (lane 3 stays off, D32).** These are explicitly rejected; do not add
  them even if an item seems to invite it.
- **Cache-stability:** anything per-question/per-turn rides as transient
  context, never the static prompt prelude (keeps the prompt-cache prefix
  byte-stable).

---

## Tier 1 - the highest-value additions

### E1. Investigation playbooks (D55)

**Why:** the biggest capability jump and the sharpest showcase of the veracity
thesis - a whole guided investigation where the model still cannot fabricate a
query or a number. "Recognition before reasoning" extended from single queries
(lane 0) to multi-step investigations.

**D55:** a playbook is a *curated, ordered sequence of typed tool calls* run as
code. The sequence (which tools, in what order, how each step's output seeds
the next) is deterministic; only the final synthesis is generated. Every step
passes the normal veracity pipeline. A playbook can never issue a step outside
the typed catalog.

| File | Change |
|---|---|
| `tool-service/app/playbooks.py` (new) | `Playbook` dataclass: id, trigger exemplars (bilingual, like lane 0), ordered steps. A step names a registry tool + how to derive its params from the question and prior step evidence (e.g. `related_alerts` seeded with the srcip from `get_alert`). A runner executes steps through `execute_ir`/the tool path, collects evidence, and hands the compacted set to synthesis. |
| `tool-service/app/loop.py` | Route to a playbook the same way lane 0 is matched (embedding match on the playbook trigger corpus, above threshold). On match, run the playbook; the model only writes the final summary from the collected evidence. Below threshold, normal loop. |
| seed playbooks | Ship 2-3: **explain-alert** (`get_alert` → `related_alerts` by srcip/dstuser → `auth_failures` for the user → `mitre_lookup` on the rule technique), **brute-force triage** (`brute_force_summary` → `alert_timeline` for the top srcip → related successful logins), **agent triage** (`agent_posture` → recent high-sev alerts → open vulns). These depend on E4 tools. |
| `golden/golden.yaml` | A playbook case: assert the expected tools ran in order, the answer cites real evidence, and no unverified citations/numbers. |

**Acceptance:** "investigate alert `<id>`" runs the explain-alert playbook end
to end; the verifiability label shows the veracity checks ran on every step;
an invented citation still surfaces as a correction.

### E2. Expand the lane-0 template corpus (extends D40)

**Why:** nearly free, and every added pair is another zero-token, no-model,
fully-verifiable answer. Pure "more context via templates" on the input side.

| File | Change |
|---|---|
| `tool-service/app/lane0.py` | Add curated bilingual exemplar→template pairs for common SOC questions the corpus lacks: agents that stopped reporting, new agents this week, top source IPs, high-severity by agent, most frequent MITRE technique, alerts for a given rule id, SCA/vuln quick counts. Reuse existing tools; only add `run_query_ir` templates where a specific tool does not exist. |
| `golden/golden.yaml` | One case per new template family, asserting the lane-0 label ("no model involved") and the datastore count. |

**Acceptance:** the new questions answer via lane 0 (zero model tokens) with
correct counts; existing cases stay green.

### E3. Structured output templates (D56)

**Why:** "more context via templates" on the *output* side. A fixed answer
schema makes triage answers sharper and makes citation/grounded-number
verification easier because the fields land in known positions.

**D56:** per-intent answer schemas the model fills, rendered to a consistent
shape. The schema is prompt-guided (a template module), not a hard parser, and
the existing verifiers still run on the rendered text.

| File | Change |
|---|---|
| `tool-service/app/prompts/reporting.md` | Extend with named answer shapes: **triage card** (Summary · Evidence · Impact · Recommendation · Triage verdict + confidence), **incident summary**, **exec rollup**. Bilingual. |
| `tool-service/app/loop.py` | Select the shape by intent (playbook result → triage card; a "summarize/report" ask → the relevant shape); inject the chosen shape as transient context, never the static prelude. |
| `golden/golden.yaml` | Assert a triage answer contains the expected sections and still passes citation + grounded-number checks. |

**Acceptance:** a triage question returns the card shape with verified
citations; cache-prefix stability is unchanged (shape rides as transient).

---

## Tier 2 - broaden the typed catalog

### E4. New read tools (extends the lane-1 catalog, D4)

**Why:** the current catalog can count and list but not correlate or trend;
these are the gaps investigations need, all compiling to IR and passing the
four checks. E1's playbooks depend on several of them.

| Tool | Shape |
|---|---|
| `alert_timeline` | ordered events for an agent / srcip / dstuser over a window (uses the existing date_histogram / sorted search) |
| `related_alerts` | pivot from one alert on shared `data.srcip` / `data.dstuser` / `rule.id` |
| `compare_windows` | datastore-computed deltas between two windows (this week vs last) - two aggregations, differenced server-side, never by the model |
| `mitre_coverage` | terms aggregation over `rule.mitre.id` - which techniques are firing |
| `agent_posture` | one agent: recent alerts + last-seen + open vuln count (joins alerts and the states path) |

| File | Change |
|---|---|
| `tool-service/app/tools.py` | Register each as a typed tool with a pydantic schema and an IR builder. `compare_windows` needs the loop/veracity to run two IRs and difference the totals server-side (extend the tool result, not the model). |
| `tool-service/app/models.py` / `compiler.py` | Only if a new aggregation shape is required; prefer expressing these with existing IR primitives. |
| `golden/golden.yaml` | One case per tool asserting tool selection and datastore-computed values. |

**Acceptance:** each tool answers through `/v1/chat/sync` and `/v1/tools/*`
with verified numbers; the allowlist is unchanged (no new raw fields exposed
without a deliberate addition).

### E5. New write actions (extends D20/D35)

**Why:** the propose→confirm framework and tiers exist; adding actions is now
cheap and on-thesis. `create_indexer_monitor` matches the upstream integration's
"alert on failed logins" demo.

| Action | Tier | Notes |
|---|---|---|
| `add_agent_to_group` | manager | typed `{agent_id, group}`, target echo on confirm |
| `create_indexer_monitor` | dashboard/indexer | a curated monitor template (query + schedule + destination), like the dashboard templates - not free-form |
| `suppress_noisy_rule` | manager | high-risk: reason required, target echo |

| File | Change |
|---|---|
| `tool-service/app/actions/schemas.py`, `registry.py`, `executors.py` | Add each as a `propose_*` tool + preview + tiered executor, mirroring the existing dashboard/manager/AR pattern. Monitors write via the indexer monitor API with the dashboard-tier (or a new monitor tier) executor credential. |
| `environments.yaml.example` | Document any new executor credential / tier. |
| `golden/actions.yaml` | Propose→confirm case per action, including the high-risk target-echo path for `suppress_noisy_rule`. |

**Acceptance:** each action proposes a card, executes only after confirm under
its tiered credential, is refused when its tier is not enabled for the env, and
is audited.

---

## Tier 3 - depth and safety

### E6. Public-content knowledge base (D57) - the one sanctioned vector store

**Why:** note 02 §10 carves out the only exception to query-don't-embed:
*public reference content* (MITRE technique detail, rule/decoder docs,
remediation runbooks) may be embedded because it is not tenant telemetry.
`mitre_lookup` is the exact-match seed; this adds semantic retrieval over a
curated public corpus so "how do I remediate this?" pulls grounded guidance.

**D57:** a vector store is permitted **only** over curated public content
shipped/controlled with the deployment, never over tenant data. Answers from it
cite a `[kb:...]` source and are verified like any citation.

| File | Change |
|---|---|
| `tool-service/app/knowledge.py` + a curated corpus dir | A `knowledge_search` lane-1 tool over an embedded public corpus (runbooks, remediation notes). Embeddings via the same ML Commons / Ollama endpoint already used; the corpus is versioned in-repo or a controlled index, not tenant indices. |
| `tool-service/app/loop.py` | `[kb:...]` citation verification already exists; extend it to the retrieved doc ids. |
| `golden/golden.yaml` | A remediation question returns a grounded `[kb:...]`-cited answer; an off-corpus question does not fabricate one. |

**Acceptance:** remediation/how-to questions cite real corpus docs; no tenant
index is ever embedded; the retrieval is disclosed in the label.

### E7. Persistent conversation + rolling summary (D58, implements the D7 seam)

**Why:** `state.py` is the documented D7 seam; multi-turn currently dies with
the process. Persist to the tenant's own indexer and keep a rolling summary so
long / cross-session conversations degrade gracefully - still no semantic
memory over telemetry.

| File | Change |
|---|---|
| `tool-service/app/state.py` | Back the store with a per-tenant indexer index (`wazuh_ai_state` principal, D7) behind the existing interface; keep in-memory as the default/fallback. Add a rolling ≤2k-token summary trim so replayed context stays bounded. |
| `config.py` | A knob to select the backend (memory vs indexer) and the summary budget. |

**Acceptance:** a conversation survives a tool-service restart when the indexer
backend is on; replayed context stays within the summary budget; telemetry is
never summarized into the store beyond what the analyst already saw.

### E8. Evidence-side injection scan (extends the injection-defense thesis)

**Why:** the scope classifier guards the *input*; alert evidence is
attacker-controlled and can carry injection aimed at the synthesis step ("the
logs attack back"). A scan on *retrieved evidence* closes that gap.

| File | Change |
|---|---|
| `tool-service/app/loop.py` (or a small `evidence_guard.py`) | Before synthesis, scan compacted evidence for injection-shaped content (imperative overrides, prompt-leak attempts); flag as an audit event and neutralize (delimit / mark untrusted) rather than drop. Deterministic patterns first; no model in the guard. |
| `golden/golden.yaml` | An alert whose `full_log` contains an injection attempt is answered safely and the attempt is audited. |

**Acceptance:** a poisoned-evidence case produces a safe answer + an audit
event; legitimate evidence is untouched.

---

## Suggested order

E1 + E2 + E3 first (they answer "skills" and "templates" together and showcase
the thesis), then E4 (which E1's richer playbooks want), then E5, then E6-E8 as
depth. Each tier is independently shippable and eval-gated.

---

## Round 7 - review findings (2026-07-17)

Reviewed E1-E8 as implemented (Tier 1/2/3 + E5 write actions). Unit gates green
(123 tool-service + 4 auth-shim). Tier 3 is clean and on-thesis - knowledge
search is corpus-only, persistent conversation stores only what the analyst
already saw, the evidence guard is deterministic. E5 executor *structure* is
correct (curated templates, numeric guards, high-risk target echo). But a live
`make evals-actions` run came back **10/15 (was 11/12)**: a real regression in
dashboard creation, plus latent permission gaps the eval does not exercise. Fix
F1 first (it broke a working flagship feature), then F2-F4.

### F1. `create_dashboard` region-map hard-fails the whole write - BLOCKER (live-confirmed)

`make evals-actions` shows `brute-force-geoip-dashboard-{en,es}` failing with
audit `status: index_pattern_unavailable`. The GeoIP scripted-field work
(commit 5a99b60) made the region-map panel *require* registering
`GeoLocation.country_iso2` on the `wazuh-alerts-*` index pattern, and
`_prepare_dashboard_objects` (`tool-service/app/actions/executors.py:61-98`)
**aborts the entire dashboard** when that registration fails or the field is not
aggregatable. Dashboard create worked at the V3.5 live sign-off; this regressed
it.

**Fix - graceful degradation, not hard failure.** An optional enrichment panel
must never block the whole dashboard:

- In `_prepare_dashboard_objects`, when `ensure_country_iso2_scripted_field`
  fails OR `FIELD_COUNTRY_ISO2` is not aggregatable after registration, **drop
  or substitute** the region-map panel (e.g. replace it with a top-countries
  table on an existing field, or omit it and re-flow the layout) and **continue**
  the write. Return `ok=True` with a `details.degraded` note naming what was
  dropped and why - never `index_pattern_unavailable` as a terminal status for
  an optional panel.
- Verify the `wazuh-alerts-*` index-pattern saved object exists and the
  dashboard executor can write scripted fields; if the index pattern itself is
  missing, that is a separate setup note (document it), still degrade rather
  than fail.

**Acceptance:** `brute-force-geoip-dashboard-{en,es}` return `ok=True`; with the
geo field present the dashboard has the region map, without it the dashboard is
still created and `details.degraded` says the geo panel was substituted; audit
never shows `index_pattern_unavailable` as a terminal failure.

### F2. Confirm failure path emits a misleading check - GATE

`conv-yes-dashboard-en` and `conv-connector-yes-en` fail asserting check
`action_confirmed`, but the result carried only `['action_executed']`. Root
cause is two-fold: (a) they hit F1 (the dashboard write failed), and (b) the
conversational executor-error path
(`tool-service/app/loop.py:436`) labels a *failed* execution with
`checks=["action_executed"]` - which is both untrue (nothing executed) and
missing the `action_confirmed` the success path emits (`loop.py:447`).

**Fix:** the failure path should emit an honest check such as
`action_confirm_failed` (not `action_executed`), and the eval case should assert
that a *successful* conv confirm carries `action_confirmed`. Once F1 is fixed
these cases execute successfully and should pass; keep the honest failure label
so a future executor failure is never mislabeled as executed.

**Acceptance:** a successful conv confirm carries `action_confirmed`; a failed
one carries `action_confirm_failed` and never `action_executed`; both eval
cases pass.

### F3. New write actions will 403 on execution - the eval does not catch it

The actions eval only *proposes* the three new actions (or does bare-yes
reprompt); it never confirm-executes them, so their credential gaps are latent:

- `add_agent_to_group` and `suppress_noisy_rule` run as `manager_executor_basic`,
  but `scripts/manager_executor_setup.sh` grants that user only `agent:restart`.
  Group-add needs `agent:modify_group`; suppress writes `PUT /manager/files`
  needing `manager:upload_file`. Both will 403.
- `create_indexer_monitor` (tier dashboard) uses `dashboard_executor_basic`
  (backend role `kibanauser` = saved-objects on `.kibana*`), but POSTs to
  `/_plugins/_alerting/monitors`, which needs Alerting-plugin write. It will
  403; the `reader_basic` fallback is read-only.

**Fix:**
- Extend `manager_executor_setup.sh` to grant `agent:modify_group` and
  `manager:upload_file` to the manager executor (or split a dedicated
  higher-privilege tier - state the least-privilege trade-off either way, D35).
- Give `create_indexer_monitor` an alerting-capable credential (a new
  `monitor_executor_basic` on the env with an alerting-write role, e.g.
  `alerting_full_access`), rather than the saved-objects writer.
- **Add confirm-execute eval cases** (behind a flag / against the lab agent) for
  all three new actions so this whole class of gap cannot hide again - the value
  of this finding is that unit + propose-only evals missed it; only a live
  confirm-execute surfaces it.

**Acceptance:** each new write action confirm-executes successfully against the
lab stack with its scoped executor; removing the grant makes it fail closed
with an honest error; the new execute eval cases are green.

### F4. `suppress_noisy_rule` is inert until reload, and grants broad write

Writing `etc/rules/local_rules_wazuh_ai_<id>.xml` via `PUT /manager/files` does
not reload analysisd, so the suppression does not take effect until a manager
restart/reload; and `manager:upload_file` lets that executor write *any* manager
file - a real blast radius.

**Fix:** after writing the rule file, trigger a ruleset reload (the manager
restart/reload API) so the suppression takes effect, and note the added
permission; scope the executor grant as narrowly as the API allows and document
the trade-off. If a safe narrow grant is not available, keep `suppress_noisy_rule`
behind an explicit per-env opt-in and say so in the preview.

**Acceptance:** after confirm, the suppressed rule stops firing (verified by a
follow-up count) without a manual restart; the executor grant and its blast
radius are documented.

### F5 (minor, carried). Composite-tool dispatch is triplicated

The `if tool.composite: ... elif name == ...` chain is duplicated in `loop.py`
(free loop), `playbooks.invoke_tool`, and `main.py` (`/v1/tools`). Behavior is
correct; fold into one `dispatch_composite(name, params, principal)` helper so a
new composite is added in one place. Do when next touching that code.

### Not re-touch

Tier 3 (E6/E7/E8), the E5 executor structure, and the read-side Tier 1/2 tools
are correct - findings above are permission wiring and one regression, not the
core logic.

### Round 7 implementation status (Cursor)

- **F1** — graceful region-map degradation in `_prepare_dashboard_objects` (never
  terminal `index_pattern_unavailable` for optional geo enrichment).
- **F2** — conversational executor-error path emits `action_confirm_failed`.
- **F3** — manager_executor_setup grants agent:modify_group +
  group:modify_assignments, rules:update/delete, manager:read+restart;
  `monitor_executor_basic` + securityconfig monitor writer; confirm-execute
  golden cases behind `WAI_EVAL_ACTIONS_EXECUTE=1`.
- **F4** — suppress uses `PUT /rules/files/{filename}` then
  `PUT /manager/analysisd/reload`; preview documents manager:restart blast radius.
- **F5** — `composite_dispatch.dispatch_composite` shared by loop / playbooks / HTTP.
