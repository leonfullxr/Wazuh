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
