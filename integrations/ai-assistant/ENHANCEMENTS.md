# Enhancements - implementation spec (for Cursor)

Forward-looking work. Current design: [`ARCHITECTURE.md`](ARCHITECTURE.md);
the journey (incl. the earlier E1-E8 arc): [`DESIGN-JOURNAL.md`](DESIGN-JOURNAL.md).
This round is **E9-E15**, new decisions **D60-D62**. Continue the E-numbering and
D-tag conventions. Every item that changes an answer, a tool, or a routing
decision gets a golden case (D33) - not done until the eval covers it.

Theme: **more context on the environment, and how to navigate it** - plus the
routing/cost optimizations that context makes possible. All of it is
context/knowledge/routing; none of it touches the veracity guarantees.

## Guardrails (unchanged - constrain every item)

- **Query, don't embed (D4/D5).** Tenant telemetry is never vectorized. A vector
  store is permitted **only** over curated *public reference content* (D57) -
  E9's docs corpus is exactly that.
- **The model never writes a query / computes a number (D4).** New context is
  knowledge tools and prompt context, not new query power.
- **Knowledge corpora are curated, version-pinned, and controlled** - built from
  a known source at deploy/build time, never live-scraped per turn, never mixed
  with telemetry.
- **Cache-stability:** per-turn/per-question context rides as transient messages,
  never the static prelude.
- Rejected as before: semantic answer cache, LLM-judge in the live path,
  lane 3, ML Commons as orchestrator (it is the connector edge + embeddings
  only).

---

## Tier A - the headline: navigate the environment

### E9. Wazuh documentation knowledge base via `llms.txt` (D60, extends D57)

**Why:** the biggest capability gap is that the assistant can *count and list*
but not *explain or guide*. Wazuh publishes a curated AI index at
`https://documentation.wazuh.com/llms.txt` (llmstxt.org format, ~80+ public doc
pages: install, ruleset/decoders, FIM, vuln detection, SCA, active response,
API, compliance mappings). Ingesting it into the existing `knowledge_search`
corpus lets the assistant answer "how do I configure X", "what does this alert
mean", "how do I remediate this CVE", "which control maps to this" with
grounded, `[kb:]`-cited answers linking the real doc - turning it from
"reports what's there" into "explains it and guides you."

**D60:** the Wazuh docs KB is a curated, version-pinned corpus built from
`llms.txt` at build/deploy time (honoring its ingestion instructions: markdown
path transforms, version handling). It is public reference content only (D57),
never live-fetched per query, never telemetry. Answers cite `[kb:<doc-id>]` with
the source URL and are verified like any citation.

| File | Change |
|---|---|
| `scripts/wazuh_docs_ingest.py` (new) + Makefile `docs-kb` | Fetch `llms.txt`, follow its listed markdown pages for the pinned `WAZUH_VERSION`, chunk (heading-aware, bounded size), and write a `knowledge/wazuh_docs.json` corpus of `{id, title, url, section, text}`. Idempotent; re-runnable per version. Respect the file's "Instructions for AI Agents" (path/version rules). Keep total size bounded (curate sections, not the whole site). |
| `tool-service/app/knowledge.py` | Load the docs corpus alongside `corpus.json`; extend `knowledge_search` to search both (or add a `doc_search`/source filter). Each hit returns title + url + snippet; the `[kb:]` id resolves to a doc. Embeddings via the existing endpoint; cache corpus vectors like the current corpus. |
| `tool-service/app/loop.py` | `[kb:]` citation verification already exists - ensure returned doc ids are in the citable set. |
| `tool-service/app/config.py` | `WAI_DOCS_KB_ENABLED` (default true when the corpus file is present), corpus path, top-k. |
| `golden/golden.yaml` | A "how do I / what does X mean / how to remediate" case returns a `[kb:]`-cited answer from the docs corpus; an off-corpus question does not fabricate a citation. |

**Acceptance:** `make docs-kb` builds `wazuh_docs.json` from `llms.txt` for the
pinned version; a how-to question returns a grounded, `[kb:]`-cited doc answer;
no tenant index is embedded; the citation verifier still catches an invented
`[kb:]`.

---

## Tier B - navigation aids

### E10. Reference lookups: rule/decoder + field dictionary (D61)

**Why:** the most common navigation question about an alert is "what does this
mean." Give exact, cited reference answers instead of the model guessing.

**D61:** curated reference lookups are exact-match knowledge tools (no
embeddings needed), sourced from the ruleset docs / a shipped field map, cited
`[kb:]`.

| File | Change |
|---|---|
| `tool-service/app/knowledge.py` + `knowledge/rule_reference.json`, `knowledge/field_dictionary.json` | `rule_reference(rule_id | rule_group | decoder_name)` -> purpose/description from a curated map (seed the common seeded/SOC rules + groups); `list_alert_fields`/`field_dictionary` -> the alert schema vocabulary (`rule.level` severity bands, `rule.groups` values, `data.*` meanings). Both are lane-1 knowledge tools, cited. |
| `tool-service/app/tools.py` | Register both as `knowledge=True` tools. |
| `golden/golden.yaml` | "what does rule 5710 / the authentication_failed group mean" returns the cited reference; a field-meaning question returns the dictionary entry. |

**Acceptance:** rule/group/decoder and field questions answer from the curated
reference with a `[kb:]` cite; unknown ids fail closed honestly (no fabrication).

### E11. Self-describe / capabilities tool

**Why:** discoverability - "what can you do / what can I ask?" Helps analysts
navigate and nudges the model toward the right tool.

| File | Change |
|---|---|
| `tool-service/app/tools.py` (+ a small `capabilities` helper) | A `describe_capabilities` tool returning the available lanes, tool catalog (names + one-line descriptions), action tiers enabled for this env, and data families (alerts, vuln states, dashboards, docs KB). Built from the live registry + env config - never hardcoded. No datastore access. |
| `golden/golden.yaml` | "what can you do / que puedes hacer" lists real tools/actions for the env. |

**Acceptance:** the tool reflects the actual registry and the env's enabled
action tiers; disabling a tier removes it from the output.

### E12. Enrich the per-environment context card (extends the env card)

**Why:** more "what's in this environment" context, which also steers tool
selection. Cheap - the env tools already exist.

| File | Change |
|---|---|
| `tool-service/app/environment_card.py` | Add (best-effort, all read-only, cached with the existing TTL): Wazuh version, enabled modules/integrations if discoverable, alert index list + rough retention window, cluster health, and top rule groups (7d). Keep the card within its size cap; degrade fields that error rather than failing the card. |
| `golden/golden.yaml` | (optional) assert the card injects the new fields when available; no telemetry beyond aggregate context. |

**Acceptance:** the card carries the new fields when reachable, stays within the
size cap, rides as transient context (cache-prefix stable), and never blocks a
turn if a field errors.

---

## Tier C - optimizations

### E13. Per-intent tool subsetting (D62)

**Why:** all ~16 tools are offered on every model turn - token cost and
selection noise. The lane-0/scope embedding is already computed per turn; use it
to offer only the relevant tool subset.

**D62:** the model is offered an intent-scoped subset of the typed catalog per
turn (e.g. vulnerability intent -> vuln + states tools; investigation ->
correlation tools; always include a small always-on core). The subset is a
routing optimization only - it never changes what a tool does or the veracity
path, and lane 2 (`run_query_ir`) stays available so nothing becomes
unanswerable. Fail open to the full catalog when intent is unclear or embeddings
are unavailable.

| File | Change |
|---|---|
| `tool-service/app/loop.py` + a small `tool_router` | Map intent (from the shared embedding / lane-0 near-miss signal) to a tool subset; pass only that subset to `converse_tool_specs()` for the model turn. Always include a core set; fail open to all tools on low confidence. |
| `tool-service/app/config.py` | `WAI_TOOL_SUBSET_ENABLED` (default on when embeddings available). |
| `golden/golden.yaml` | Existing cases stay green (proves nothing became unanswerable); add an audit/metric of offered-tool-count so the reduction is measurable. |

**Acceptance:** offered-tool count drops on clearly-scoped questions; the full
golden set stays green (nothing lost); low-confidence turns still see the full
catalog.

### E14. Per-tool field projection

**Why:** shrink evidence payloads (eases the 16k local context and reduces
compaction dropping hits) by returning only the fields relevant to the tool.

| File | Change |
|---|---|
| `tool-service/app/compiler.py` / `veracity.py` (evidence shaping) or per-tool `to_ir` | Let a tool declare the source fields its answer needs; project the datastore `_source`/evidence to those. Counts/aggregations unaffected (already datastore-computed). |
| `golden/golden.yaml` | Existing count/citation cases stay green with smaller payloads. |

**Acceptance:** evidence payloads shrink for narrow tools; no case regresses;
citations still resolve.

### E15. Citation-token prompt hardening

**Why:** de-flake the two stochastic golden cases where gpt-oss cites evidence
*metadata* keys (`zero_hit_diagnosis`, `veracity_checks_passed`) as if they were
data refs - the verifier catches them (a `number`/citation correction), but it
makes those cases flaky.

| File | Change |
|---|---|
| `tool-service/app/loop.py` (system prompt / prompt module) | Enumerate the citable tokens (alert ids, agg keys, `total_matching`, `[kb:]` ids) and explicitly forbid citing metadata field names. |
| `golden/golden.yaml` | The zero-hit and brute-force-summary cases pass consistently (no spurious corrections). |

**Acceptance:** the previously-stochastic cases pass reliably; the verifier is
unchanged (still catches a real invented citation).

---

## Suggested order

E9 first (the headline - it is the "navigate the environment" capability and
reuses the D57 machinery), then E10-E11 (navigation aids on the same corpus
pattern), then E13 (the optimization that pays off in cost and accuracy), then
E12/E14/E15 as polish. Each item is independently shippable and eval-gated.
