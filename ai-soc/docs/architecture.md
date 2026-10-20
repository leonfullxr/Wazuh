# Architecture

AI SOC answers an analyst's question about a Wazuh deployment. It never changes Wazuh: it does not modify Wazuh configuration or run active response. Its only writes go to its own state, audit and feedback stores. Terms used here are defined in [CONTEXT.md](../CONTEXT.md).

## Request flow

```
question -> deterministic planner -> topic plans
         -> per topic: bounded reads as the analyst -> evidence pack
         -> per topic: deterministic checks -> optional tool-free judgment
         -> finding validation -> durable audit -> answer
```

1. Planning is deterministic. The planner maps the question to reviewed topics, a time window and approved fetches. No model creates a plan; an optional embedding fallback can only suggest a topic in a clarification. An ambiguous or incomplete question gets a clarification, not a guess.
2. Each fetch uses one of six service-owned query templates with an allowlisted set of fields ([specification](specification.md)). Callers cannot supply index names or query DSL. Every read runs with the analyst's own site authority, and indexer rows are not cached across requests or principals.
3. A topic's fetch results, check results and evidence items form its evidence pack. The pack is hashed and bound to the topic, so one topic cannot cite another topic's evidence.
4. Judgment is optional and per topic. The model receives the pack, the topic's approved finding templates and fixed rules. It has no tools and cannot read raw logs. It can only propose structured findings.
5. The validator renders a finding only if it uses an approved template, cites evidence from the same pack, binds the required fields to values that the evidence actually contains, and meets the template's check prerequisites. Everything else is removed and the reason is recorded.
6. The answer is published only after its audit record is durably acknowledged. If a stage cannot complete, the answer marks it as left out with a reason. It never fills the gap with a guessed result.

## How false positives are reduced

- The model cannot invent a finding type. Findings come only from reviewed templates, and the wording is rendered by the service, not the model.
- A finding must cite evidence. A citation that is unknown, from another topic, bound to a missing or unsupported value, or whose template prerequisites failed is removed (`unknown_evidence`, `cross_topic`, `bad_binding`, `unsupported_value`, `failed_prerequisite`).
- Counts come from exact backend aggregates with their own evidence, not from counting the rows on screen. An approximate count is labeled approximate.
- Threshold and absence statements need exact counts or a demonstrably complete cohort. A first page of results is never treated as the whole population.

## How missed threats and false all-clears are avoided

- Missing, filtered, denied, unsupported or unavailable telemetry is reported as that state. It is never turned into "nothing found".
- A zero result counts as empty only when the index is confirmed, visibility is full, the window has a positive exact count and the matching filter is identified. Even then, it only means that no records matched that scope and window. It does not mean the system is healthy.
- Unknown visibility or ingestion produces fixed wording and no all-clear.
- An empty finding list is not proof of safety: the model can still omit an attack. Deterministic checks and the analyst stay in the loop.

## Confidence and grounding

Every answer carries build provenance: the service commit, image digest, content commit and pack digest. Each rendered statement traces to evidence IDs from one topic's pack, and the reason for each removed finding is recorded. Confidence comes from these bindings and from the stated scope, visibility and exactness of each read. It does not come from the model's own assessment.

Passing tests show that these rules hold. They do not measure detection quality. Measuring that needs labeled outcomes and a replay baseline with reported denominators.

## Components

| Package | Responsibility |
|---|---|
| `ai_soc.planning` | Deterministic question parsing and topic plans |
| `ai_soc.query` | Template compiler, indexer client, paging cursors |
| `ai_soc.content` | Signed content packs: topics, playbooks, templates, documents |
| `ai_soc.judgment` | Eligibility, prompt assembly and the tool-free model provider |
| `ai_soc.validation` | Finding validation and safe bilingual rendering |
| `ai_soc.application` | Request orchestration, budgets, leases and composition |
| `ai_soc.api`, `ai_soc.mcp` | REST and MCP interfaces over the same application |
| `ai_soc.identity` | ALB browser assertions, MCP bearer tokens and indexer tokens |
| `ai_soc.state`, `ai_soc.feedback`, `ai_soc.telemetry` | Durable state, feedback delivery, audit, traces and metrics |
| `ai_soc.live`, `ai_soc.devserver` | Sealed live boot and the loopback-only synthetic dev server |

Wire and port contracts are defined in [contracts.md](contracts.md) and the schemas under `contracts/v1/`.

The alert and vulnerability sources, their field paths, timestamp meanings and read outcomes are described in [source-capabilities.md](source-capabilities.md).
