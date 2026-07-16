# Design journal

The story of how this assistant was built - the decisions and *why*, the bugs
review caught before they shipped, and the results measured on real hardware.
It is deliberately a narrative, not a spec: the current design lives in
[`ARCHITECTURE.md`](ARCHITECTURE.md) (with the D-tag decision log), and the
mechanics live in the code. This file is the knowledge behind those.

Working model throughout: Claude reviewed and specified, Cursor implemented,
and each pass was validated on a local Wazuh stack before the next. The
recurring, hard-won process lessons are collected at the end.

---

## 1. The starting problem, and the RAG ruling

The assistant existed but its eval harness had never passed on the test box.
The review found three compounding causes, none of them the model:

1. **No GPU acceleration.** The compose GPU stanza was NVIDIA-only; the test
   machine has an AMD RX 7600 XT (ROCm), so the model ran on CPU - minutes per
   step, timeouts, flaky tool calls.
2. **Silent context overflow.** Ollama defaults to a 4096-token context; the
   loop sends ~2k tokens of system+schemas plus up to a full evidence budget
   per tool result. The runtime truncated silently, so the model *lost* the
   evidence it was meant to cite, then miscounted.
3. **Ground-truth drift.** Seed data aged out of rolling windows between
   seeding and evaluation; frozen expected counts drifted within minutes.

The foundational architectural decision predates all of this and survived
every later phase: **"query, don't embed" (D4/D5).** Tenant telemetry is never
vectorized - the indexer *is* the retrieval layer, driven through typed tools.
A vector store over alerts would be a second copy of tenant data to isolate,
retain, and erase, stale within minutes, and less verifiable than a
datastore-computed count. The only embeddings in the system are over
*questions* and *curated exemplars*, never data.

## 2. Enablement and the veracity enhancements (P0/P1)

P0 made the harness runnable (ROCm image + device passthrough, a 16k context
window, an 8k local evidence budget, idempotent re-seeding, live ground-truth
references taken through the same tool surface the model uses). P1 added the
recognition-before-reasoning features: lane-0 near-miss few-shot hints, the
embedding scope classifier, the `mitre_lookup` knowledge tool (exact ATT&CK
lookup - the sanctioned place for embeddings-adjacent knowledge, still no
telemetry vectorized), prompt/KV caching, and an MCP surface.

**Round 2 review** caught several issues before they compounded, the sharpest
being process, not code: an earlier round's endorsed hardening had been left
in a `git stash` and the new pass was built without it - it had to be
recovered and merged. Code blockers included a missing import that would crash
any `mitre_lookup` turn, a bake-off target that never actually switched the
model (so all three "results" graded the same model), and a scope classifier
that **failed closed** - refusing ambiguous input and running even when no
embeddings endpoint existed. The fix set the enduring rule: the scope
classifier fails *open*, greetings bypass it, and it only exists when lane 0
does.

## 3. Local validation and the model bake-off

With the harness fixed, the results came in on the AMD box (lane 0 on = the
demo posture; lane 0 off = grading the model itself):

| Model | Golden set | Note |
|---|---|---|
| `gpt-oss:20b` + lane 0 | 9/9 | demo default; 7/9 cases answered with zero model tokens |
| `qwen3:30b-a3b-instruct-2507` (model-only) | 9/9 | best model-only accuracy, ~17 s/turn |
| `gpt-oss:20b` (model-only) | 7-8/9 | fits the 16 GB GPU fully |
| `qwen3:30b-a3b` thinking tag | 3/9 | burns the output cap on reasoning tokens - use the instruct build |
| `qwen2.5:14b` | 2/9 | dense-14b tool-calling weakness, as predicted |

The most valuable moment was unscripted: the **grounded-number check** flagged
a model that claimed 2,023 alerts while its own tool had returned 0 - surfaced
as a correction in the response, not a confident lie. The veracity machinery
earning its keep on an input nobody wrote a test for.

## 4. The v3 pivot: the chat moves into the Wazuh Dashboard

The thin n8n chat edge lacked environment context, so the product decision was
to embed the chat in the Wazuh Dashboard using the OpenSearch **Dashboards
Assistant** and ML Commons' HTTP connector - following the official
[wazuh/integrations AI_assistant](https://github.com/wazuh/integrations/tree/main/integrations/AI_assistant)
edge, but replacing its query-writing LangChain gateway with this veracity
core. That reference proves the edge on exactly the Wazuh 4.14 / OpenSearch
2.19 line the deployments use.

Two rulings shaped v3:

- **ML Commons never orchestrates the loop.** It is approved as the *connector
  edge* and (later) for *in-cluster embeddings*, but never as the agent
  orchestrator: that would put a standing credential inside the cluster
  (breaking queries-as-the-analyst) and re-couple orchestration to OpenSearch
  against the datastore-portability goal. The gateway stays the brain (D44).
- **One gateway, many environments (D42/D43).** A per-environment credential -
  never the request payload - resolves to that environment's indexer, reader
  principal, action tiers, and budgets. The dashboard edge cannot propagate a
  verified user, so it runs as a read-only per-environment principal, disclosed
  in every answer's label. The PoC runs one environment; every interface is the
  multi-environment shape.

## 5. Identity without an external IdP (V3.6)

Keycloak had been the SSO stand-in and, by measure, the single largest source
of bugs (issuer-mismatch failures that silently broke every host-driven auth).
It was removed. Identity is now verified against each environment's **own
indexer** via `_plugins/_security/authinfo`, and the tenant claim is *proven*
by which environment accepted the credentials, never asserted (D52/D6). The
shim keeps its mint-key isolation (D30); environments inherit whatever their
security plugin already trusts - internal users, LDAP, or SSO - so the product
supports SSO without owning an IdP.

## 6. Coverage and domain context (V3.4 / V3.7)

Vulnerability **states** (`wazuh-states-vulnerabilities-*`) got their own typed
path with a separate allowlist - never widening the alerts allowlist casually.
Environment tools (`list_agents`, `index_health`, `list_dashboards`) and
in-cluster ML Commons embeddings landed, plus a per-environment **context
card** (agents, OS mix, geo-field presence, existing dashboards) injected as
transient per-turn context so the prompt-cache prefix stays byte-stable.

Studying the upstream prompt library surfaced a real bug in our own tool: our
`auth_failures` filtered only `authentication_failed`, so **Windows auth
failures were invisible** (`win_authentication_failed` missing). That became a
fix plus a `brute_force_summary` composite tool encoding the multi-signal
recipe. The ruling: **teach code first, prompt second** - anything expressible
as a typed tool becomes one; only composition semantics go into prompt modules.

## 7. Write actions by design (V3.5), and the review that mattered

The assistant became write-capable - restart agents, create dashboards, run
active response - but the model never calls a write API. Two-phase: the model
`propose_*`s a typed action with a preview; a human confirms; a per-tier
executor credential the model never holds runs it (D20/D35).

**Round 6 review caught a genuinely dangerous bug.** Verified against the live
Wazuh API spec, the active-response executor put the agent list in the request
*body*, while the API's `agents_list` is a *query parameter that defaults to
ALL AGENTS when absent* - so the call would either 400 or fire a command
fleet-wide. It also shipped with propose-confirm **off by default** and a
*fabricated* operator identity for the unverified edge - the exact anti-pattern
the design existed to reject. Both were fixed structurally, and the pass added
the enduring guardrails: per-environment tier opt-in (deny by default),
re-type-the-target friction on high-risk confirms, per-tier rate caps,
idempotency, and two operator roles (`wazuh_ai_operator` for dashboards,
`wazuh_ai_responder` for manager/AR).

## 8. Live actions sign-off

The first real writes against the live stack, all end to end: a brute-force
dashboard proposed in chat → confirmed → the saved object verified present;
agent 001 restarted (the daemon actually restarted, confirmed in its logs) via
a least-privilege operator; active-response `restart-ossec` with the high-risk
`confirm_target` gate proven (missing target → 409, wrong target → 409, correct
→ executed). Two bugs only a live run could surface were fixed: the Wazuh API's
`?raw=true` token endpoint returns bare text (not JSON, which had 500'd every
manager/AR confirm), and the dashboard executor needs the `kibanauser` backend
role (no underscore) or saved-object writes 403.

## 9. UX polish (V3.8)

Three requested changes. **Language fidelity:** an English question sometimes
answered in Spanish because lane 0 rendered in the *matched exemplar's*
language - and the embedding model is cross-lingual, so English questions
matched Spanish exemplars. Fixed by detecting the *question's* language at
every render site. **Keycloak fully removed**, including a confirm-UI login
that still did an OIDC grant against the now-deleted service. **Conversational
confirm:** "yes"/"confirm" executes a pending action, "no" cancels - a
deterministic bilingual intent match *outside* the model (D54). The security
call (D53): on the dashboard edge a "yes" executes under the environment
principal - dashboard access accepted as the authority, a documented,
deliberate lowering of the per-user bar, bounded by the tier opt-in, target
echo, rate caps, and audit that always hold.

## 10. Deferred, with intent

The multi-environment cross-tenant isolation suite (a `kind/` two-tenant
harness exists; the full suite is partial), a streamable-HTTP `/mcp` surface
(the stdio adapter ships today), the Amazon Bedrock fidelity leg (needs AWS
credentials), and re-exporting the v3 diagram PNGs when the draw.io GUI is
available. None block the self-hosted PoC.

## 11. Cross-cutting lessons

- **Commit after every accepted pass.** Uncommitted work was clobbered twice;
  a stash rescue and several "the tree was uncommitted at review" notes trace
  back to this. It is the most repeated lesson in the project.
- **Verify live, not just in units.** The fleet-wide AR bug, the `raw=true`
  token parsing, the `kibanauser` role, and the language leak all passed unit
  tests and failed (or would have failed) only against the real stack.
- **The veracity machinery pays for itself on unscripted input.** The
  grounded-number and citation checks caught real model errors that no
  assertion was looking for.
- **Review before merge caught a command that could have hit every agent.**
  The single strongest argument for the propose→review→confirm discipline the
  product is built on.
