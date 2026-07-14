# wazuh-ai enhancements — implementation spec

Review output for the local AMD test harness. **Cursor applies P0 + P1** (decision
1). MCP is item **P1.8**. Model bake-off covers **all three models** (decision 3).

RAG posture (decision 2): **query, don't embed** for tenant telemetry. The typed-tool
pipeline against the indexer is the retrieval layer. No vector store over alerts.
Embeddings are used for lane-0 recognition, scope classification, and near-miss
few-shot hints — not for alert retrieval.

Diagrams: `diagrams/wazuh-ai-enhancements.drawio` (three pages — turn workflow,
cache/knowledge placement, AMD test harness). Orange = new/changed.

---

## P0 — eval harness blockers (apply in order)

### P0.1 ROCm GPU for Ollama

**Problem:** Compose GPU stanza was NVIDIA-only; AMD RX 7600 XT ran `gpt-oss:20b` on CPU
(minutes per step, timeouts, flaky tool calls).

| File | Change |
|---|---|
| `docker-compose.poc.yml` | `image: ollama/ollama:rocm`, `/dev/kfd` + `/dev/dri`, `group_add: [video, render]` |
| `docker-compose.poc.yml` | `OLLAMA_IMAGE` override for CPU/NVIDIA hosts |
| `Makefile` | `make ollama-gpu-verify` — `ollama ps` + optional `rocm-smi` |
| `.env.example` | Document ROCm defaults |

**Acceptance:** `make ollama-gpu-verify` shows GPU/ROCm in `ollama ps`, not 100% CPU.

### P0.2 Context overflow

**Problem:** Ollama defaults to 4096-token context; loop sends ~2k system+schemas plus
up to evidence budget per tool result → silent truncation.

| File | Change |
|---|---|
| `docker-compose.poc.yml` | `OLLAMA_CONTEXT_LENGTH=16384` |
| `tool-service/app/config.py` | `evidence_budget_chars` default **8000** |
| `docker-compose.poc.yml`, `.env.example` | Match 8k default |

**Acceptance:** Tool results compact to ≤8k chars; Ollama starts with 16k context.

### P0.3 Idempotent re-seed

**Problem:** Seeding 4 days ago left stale windows; re-seeding duplicated documents.

| File | Change |
|---|---|
| `seed/seed_alerts.py` | `SEED_MARKER = wazuh-ai-seed` on `manager.name` |
| `seed/seed_alerts.py` | `_delete_by_query` on marker before bulk index |

**Acceptance:** `make seed` twice → same doc count, fresh timestamps, no duplicates.

### P0.4 Live ground truth + eval artifacts

**Problem:** Static `ground_truth.json` drifts (windows age out, organic alerts change top rule).

| File | Change |
|---|---|
| `golden/live_gt.py` | Re-query indexer for time-windowed counts + live top rule |
| `golden/run_evals.py` | Call `load_and_refresh` before cases; write `last_run.json` |
| `Makefile` | `make evals-fresh` (seed + evals), `make bakeoff` (three models) |
| `.gitignore` | `golden/last_run.json` |

**Acceptance:** Evals pass after 4+ days without manual GT edits; `last_run.json` has per-case results.

---

## P1 — quality and surfaces

### P1.1 Lane-0 near-miss few-shot

| File | Change |
|---|---|
| `tool-service/app/lane0.py` | `near_miss()` when score ∈ [floor, threshold) |
| `tool-service/app/loop.py` | Append hint to system prompt on near-miss |
| `tool-service/app/config.py` | `lane0_near_miss_floor` (default 0.65) |

**Acceptance:** Near-miss questions get exemplar hint in audit; tool selection improves on golden set.

### P1.2 Embedding scope classifier

| File | Change |
|---|---|
| `tool-service/app/scope.py` | In/out-of-scope embedding classifier |
| `tool-service/app/loop.py` | Refuse out-of-scope before model loop |
| `tool-service/app/metrics.py` | `wazuh_ai_scope_total` counter |

**Acceptance:** `out-of-scope-es` and `injection-resist-en` golden cases pass without tool calls.

### P1.3 `mitre_lookup` knowledge tool

| File | Change |
|---|---|
| `tool-service/app/knowledge.py` | Exact MITRE id lookup |
| `tool-service/app/knowledge/mitre_techniques.json` | Local catalog |
| `tool-service/app/tools.py` | Register as `knowledge=True` tool |
| `tool-service/app/loop.py`, `main.py` | Knowledge tool execution path |

**Acceptance:** `mitre_lookup(T1110)` returns name/tactic/description; no indexer query.

### P1.4–P1.6 Prompt caching

| File | Change |
|---|---|
| `tool-service/app/llm.py` | Second Bedrock `cachePoint` before latest message (history cache) |
| `tool-service/app/llm.py` | Document Ollama KV-prefix-reuse invariant |

**Acceptance:** With `WAI_PROMPT_CACHE=true`, multi-step turns show cache hits on Bedrock (verify billing).

### P1.8 MCP adapter

| File | Change |
|---|---|
| `mcp/server.py` | Stdio MCP over HTTP surfaces |
| `mcp/README.md` | Setup + Claude Desktop config |

**Acceptance:** MCP host can call `wazuh_chat` and `wazuh_call_tool` with turn JWT.

---

## P2 — deferred

- Persistent conversation store (indexer-backed, D7)
- Cross-tenant isolation suite in kind
- Full MITRE ATT&CK catalog sync
- Remote streamable-HTTP MCP (vs stdio)

---

## Section 7 — test phase (after P0+P1 land)

Run in order:

```bash
make seed                    # idempotent fresh synthetic data
make ollama                  # ROCm image + model pull
make ollama-gpu-verify       # confirm GPU, not CPU
make poc                     # recreate tool-service with new env
make test                    # 26-case unit suite
make evals-fresh             # seed + live GT + golden set
make bakeoff                 # qwen2.5:14b, gpt-oss:20b, qwen3:30b-a3b
```

Identity negatives: cross-tenant token, viewer role, wrong signing key (README s5).

Artifacts: `golden/last_run.json`, `golden/last_run.<model>.json` per bake-off model.

---

## Round 2 — review findings on the P0+P1 implementation (2026-07-14)

Verdict: structure is right and the 26-case unit suite passes, but there are
four blockers (R2.0–R2.3) that must land before the test phase. Fix in order.

### R2.0 Restore the stashed round-1 hardening — BLOCKER

`git stash list` shows `stash@{0}` (WIP on b87bb5e). It holds **endorsed**
changes this pass was unknowingly built without. Recover with a 3-way apply
and hand-merge the conflicts:

```bash
git stash show -p 'stash@{0}' > /tmp/round1.patch
git apply --3way /tmp/round1.patch   # veracity.py + containerization/* apply clean
```

Merge rules per conflicted file (keep BOTH sides):

| File | Keep from stash | Keep from this pass |
|---|---|---|
| `golden/run_evals.py` | per-case fresh JWT (10-min TTL vs slow local runs) · `REF_TOOLS` live count bracketing via `/v1/tools/*` (same code path as the assistant, pre/post-turn re-read) · 429 wait-out loop · `WAI_EVAL_TIMEOUT_S`/`WAI_EVAL_RETRIES` · typography folding · count assertions require `datastore_computed_counts` in checks | `run_suite` record collection · `write_last_run` artifact |
| `tool-service/app/loop.py` | system-prompt `executed_window` rule · `agg_names |= {aggs, "total_matching", tool name, "zero_hit_diagnosis"}` | scope gate · near-miss hint · knowledge branch |
| `tool-service/app/llm.py` | `stream_options: {include_usage: true}` | history `cachePoint` |
| `tool-service/app/main.py` | `_indexer_http_error` 401/403→401, else 502 (both surfaces) | knowledge branch in `call_tool` |
| `tool-service/app/tools.py` | sharpened `count_alerts` + `auth_failures` descriptions | `mitre_lookup` ToolDef |
| `tool-service/app/veracity.py` | `executed_window` on Evidence (applies clean) | — |

`live_gt.py` then shrinks to what `REF_TOOLS` cannot do: live `top_rule_id`
and `sample_alert_id` re-resolution. Its admin-credential count refresh is
superseded (one-shot pre-suite counts reintroduce mid-run drift on slow local
models; drop those fields from `refresh()`). Drop the stash only after
`git diff` review, then **commit everything** — uncommitted work got clobbered
once already.

### R2.1 `loop.py` missing import — BLOCKER

Lint: `loop.py:224 undefined name 'mitre_lookup'` (the import sits unused in
`tools.py`). Any model call to the *advertised* `mitre_lookup` tool crashes
the turn with a NameError → 500/SSE error, not a tool-error the model can
recover from.

| File | Change |
|---|---|
| `tool-service/app/loop.py` | `from .knowledge import mitre_lookup` |
| `tool-service/app/tools.py` | drop the unused `mitre_lookup` import |

**Acceptance:** ruff/pyflakes F-rules clean on `tool-service/app/`; a chat turn
asking "what is technique T1110?" returns the catalog entry.

### R2.2 `make bakeoff` never switches models — BLOCKER

`WAI_MODEL_*` env vars only reach `run_evals.py` (artifact labels); the
tool-service **container** keeps the model it was started with — all three
artifacts currently grade the same model under different names.

| File | Change |
|---|---|
| `Makefile` | per model: `ollama pull $$m` → recreate tool-service with the model env (`WAI_MODEL_ROUTER/ANALYSIS=$$m docker compose -f docker-compose.poc.yml up -d --force-recreate tool-service`) → poll `/healthz` → run evals → copy artifact |

**Acceptance:** `turn_complete` audit events show a different `model` per
bake-off leg; `last_run.<model>.json` headers match the model that answered.

### R2.3 Scope classifier fails closed and runs everywhere — BLOCKER

Three problems: (a) tie→refuse: `in_scope = in-out ≥ margin` refuses anything
ambiguous — "hola"/"thanks" now get a hard refusal instead of the friendly
router reply (regression); (b) enabled by default even with no embeddings
endpoint — the docstring and `.env.example` claim it inherits `lane0_enabled`
but the code doesn't, so Bedrock-only deployments eat a failing (up to 30 s)
embed call on every turn; (c) it also fires on greetings.

| File | Change |
|---|---|
| `tool-service/app/scope.py` | refuse only when clearly out: `in_scope = (out_score - in_score) < CFG.scope_margin` |
| `tool-service/app/scope.py` | `enabled()` = `scope_classifier_enabled and lane0_enabled` (match the docs) |
| `tool-service/app/loop.py` | skip `scope.classify` when `_SIMPLE_RE` matches (greetings → router tier as before) |

**Acceptance:** "hola" gets a greeting, not a refusal; `out-of-scope-es` and
`injection-resist-en` still refuse with zero tool calls; a Bedrock-only config
(lane 0 off) makes zero embed calls.

### R2.4 Embed once per turn

`lane0.match`, `scope.classify` and `lane0.near_miss` each embed the same
question — three HTTP round trips. Share one memoized embed helper (small
`embeddings.py` with an LRU text→vector used by both modules), and derive the
near-miss from `match()`'s already-computed scores instead of re-embedding.

**Acceptance:** one `/embeddings` POST per question per turn (ollama logs).

### R2.5 Near-miss hint placement

The hint is appended to the **system prompt**, so system varies per question —
that breaks the cross-turn KV/prompt-cache prefix invariant documented in
`llm.py` (P1.6). Inject it as a transient user message before the question
(never saved to `state`), keeping system byte-stable.

### R2.6 GPU group GIDs

`group_add: [video, render]` resolves names against the *container* image,
where GIDs can differ from the host (host: `render=105`, `video=44`). Use
numeric with env overrides: `group_add: ["${RENDER_GID:-105}", "${VIDEO_GID:-44}"]`
and document `getent group render video` in `.env.example`.

**Acceptance:** `make ollama-gpu-verify` shows the model on GPU, not CPU.

### R2.7 MCP token lifecycle

`WAI_MCP_JWT` is pre-minted and dies ≤10 min into a session. Have `server.py`
mint on demand: Keycloak password grant + shim exchange (env
`WAI_MCP_KC_USER`/`WAI_MCP_KC_PASSWORD`, urls), cache until `exp - 30 s`,
re-mint transparently. Keep `WAI_MCP_JWT` as an override for one-shot use.

**Acceptance:** an MCP session keeps working past the 10-minute mark.

### R2.8 Silently dropped spec items — dispositions

| Item | Decision |
|---|---|
| Grounded-number check (round-1 P1.5) | **Implement now** — it is the veracity thesis. Numbers in a sentence citing `[agg:<name>]` must equal a value reachable under that agg (total, bucket count, zero-hit probe). Mismatch → existing `correction` event with `kind="number"`. While there: add the `kb` citation kind — `CITATION_RE` gains `kb`, valid iff that technique id was returned by `mitre_lookup` this turn; knowledge branch adds its tool name to `agg_names`. |
| Parallel tool calls + zero-hit probes (round-1 P1.7) | Defer to P2 — latency-only, fine. |
| Surface `cacheReadInputTokens`/`cacheWriteInputTokens` into `usage` (P1.1 acceptance) | Implement now — without it the Bedrock cache is unverifiable (ledger Q4). |

### R2.9 Seed delete robustness (minor)

`_delete_by_query` without `conflicts=proceed` 409s the whole seed if organic
indexing races the delete: `params={"refresh": "true", "conflicts": "proceed"}`.

### Section 7 amendment

The scope classifier and near-miss hints require embeddings: add `make embed`
and `WAI_LANE0_ENABLED=true` to the test sequence before `make poc`, or both
features silently no-op (and with R2.3 fixed, that no-op is at least safe).

---

## Round 3 — Track B: kind cluster and the cross-tenant isolation suite

Status of rounds 1–2: shipped and validated (golden 9/9 lane-0-on; bake-off
matrix in `golden/last_run.*.json`; results note
`Notes/Obsidian/Wazuh/wazuh-ai/15-local-validation-results.md`). Track B is
the notes' declared next stage (13 §7): move the SAME container images into a
kind cluster with two tenant namespaces and prove the isolation story that
Compose cannot express. Cursor implements; scope below is deliberately
minimal — this demonstrates isolation primitives, not production packaging.

### B1. Cluster and layout

| File | Change |
|---|---|
| `kind/cluster.yaml` | Single-node kind cluster; `extraPortMappings` for the two tool-service NodePorts |
| `kind/README.md` | Bring-up walkthrough + what each assertion proves |
| `Makefile` | `kind-up`, `kind-tenants`, `kind-isolation`, `kind-down` targets |

Keep the Wazuh stack and Ollama on the host (docker), reachable from kind via
the host gateway — running Wazuh inside kind proves nothing new and costs
10 GB. The cluster runs only what multi-tenancy changes: per-tenant auth-shim
and tool-service.

### B2. Two tenants, same images

| File | Change |
|---|---|
| `kind/tenants/tenant-a/` and `tenant-b/` | Namespace, Deployments (auth-shim + tool-service), Services, Secrets |
| `keys/gen-keys.sh` | Accept an output-dir argument so each tenant gets its OWN mint keypair |
| `keycloak/realm-export.json` | Second realm (or a second client + role pair) so each tenant has its own IdP audience |

Per tenant: own RSA keypair (the mint key is the tenant boundary, D30), own
`WAI_TENANT` value, own `SHIM_KC_ISSUER`. The container images are the ones
`docker compose build` produces — load them with `kind load docker-image`;
zero image changes allowed (that is the point of D36's "same containers").

Indexer note: the lab indexer's JWT auth domain trusts one public key. Give
tenant-b's tool-service a syntactically valid but indexer-untrusted keypair
and the isolation suite gains a free extra assertion: tenant-b can pass
service-level auth yet still cannot read telemetry the indexer does not trust
its key for. Document this asymmetry in `kind/README.md` — per-tenant
indexers are an AWS-stage concern, deliberately out of scope.

### B3. NetworkPolicy walls

| File | Change |
|---|---|
| `kind/tenants/<t>/netpol.yaml` | Default-deny ingress+egress; allow DNS; allow same-namespace; allow egress to host indexer/Keycloak/Ollama CIDR; allow ingress from the NodePort |

kind's default CNI (kindnetd) does not enforce NetworkPolicy — install a CNI
that does (Calico is the boring choice) in `kind-up`, or the walls are
decorative.

### B4. The isolation suite (the deliverable)

| File | Change |
|---|---|
| `kind/isolation_suite.sh` | Asserts, exit nonzero on any failure |

Assertions, each observable and audited:

1. **Happy path per tenant**: tenant-a analyst mints via tenant-a shim, asks
   tenant-a tool-service, gets an answer (lane 0 acceptable).
2. **Cross-tenant token**: tenant-a turn JWT presented to tenant-b
   tool-service → 401/403 at signature or tenant-claim check, and the
   `cross_tenant_token_rejected` audit event is emitted (assert on pod logs).
3. **Cross-namespace network**: a curl pod in tenant-a cannot reach
   `tool-service.tenant-b.svc` (connection timeout, not 403 — the wall, not
   the guard).
4. **Golden set still green**: `run_evals.py` pointed at tenant-a's NodePort
   passes, proving the k8s move changed no behavior (parameterize the
   runner's base urls via env: `WAI_EVAL_SVC_URL`, `WAI_EVAL_KC_URL`,
   `WAI_EVAL_SHIM_URL`, defaults unchanged).

**Acceptance:** `make kind-up kind-tenants kind-isolation` exits 0 on this
machine with the docker Wazuh stack running; each of the four assertions
prints what it proved; `make kind-down` leaves the docker stack untouched.

### B0. Honest 503 when the inference backend is unreachable (small, do first)

Observed live: with the ollama container stopped, every chat turn surfaces
`httpx.ConnectError` as a raw 500. The design's posture is honest rejection (D14): catch `httpx.ConnectError`/`ConnectTimeout`
from the provider in both chat surfaces (`main.py`, same pattern as
`_indexer_http_error`) and return
`503 "inference backend unreachable"` + an `llm_unreachable` audit event.

**Acceptance:** stop the ollama container, ask a question → clean 503 with
that message; audit event emitted; eval runner reports it as a transport
failure naming the backend. **Done** (July 2026): verified with ollama
stopped manually; audit emits `llm_unreachable`.

### B5. Demo refresh (docs, no code)

`n8n/README.md` gains a "what the answer shows" section (labels for lane 0 /
scope classifier / cache disclosure, corrections rendering) and a scripted
demo storyline for re-recording `demo/demo.gif` — see the file; execution is
a human-with-a-screen-recorder task.
