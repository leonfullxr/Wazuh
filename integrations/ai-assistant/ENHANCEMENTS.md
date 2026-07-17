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

### E10. Reference lookups: rule/decoder + field dictionary (D61) — **shipped**

See D61 in [`ARCHITECTURE.md`](ARCHITECTURE.md). Tools: `rule_reference`,
`field_dictionary`; corpora in `knowledge/rule_reference.json` and
`knowledge/field_dictionary.json`.

### E11. Self-describe / capabilities tool — **shipped**

`describe_capabilities` builds the card from the live `REGISTRY` + env action
tiers (`capabilities.py`).

### E12. Enrich the per-environment context card (extends the env card) — **shipped**

Best-effort fields: indexer/Wazuh versions, cluster health, alert index list +
retention window, signal-family hints from 7d groups; each field degrades
independently (`environment_card.py`).

---

## Tier C - optimizations

### E13. Per-intent tool subsetting (D62) — **shipped**

`tool_router.py` + `converse_tool_specs(subset)` / `tool_specs_for_turn`;
`WAI_TOOL_SUBSET_ENABLED` (default on). Fail open; core always includes
`run_query_ir` and knowledge tools.

### E14. Per-tool field projection — **shipped**

`QueryIR.source_fields` + compiler defaults aligned with `_flatten_hit`;
`get_alert` uses detail (incl. `full_log`); list/timeline tools use a narrower
projection.

### E15. Citation-token prompt hardening — **shipped**

System prompt enumerates citable tokens and forbids metadata field citations
(`zero_hit_diagnosis`, `veracity_*`, etc.).

---

## Suggested order

E9–E15 shipped. Further work goes in a new ENHANCEMENTS round when needed.
