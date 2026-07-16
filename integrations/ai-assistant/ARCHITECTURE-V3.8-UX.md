# wazuh-ai v3.8 — language fidelity, Keycloak removal, conversational confirm

Date: 2026-07-16 · Author: Claude (reviewer) · Implementer: Cursor
Three targeted changes requested by Leon. New decisions D53–D54.

**How to use this file (Cursor):** V3.8a and V3.8b are self-contained; do them
first. V3.8c changes the actions trust model with an explicit, documented
security trade-off — read §3.0 before writing code. Keep D-tag comments. Every
change that touches an answer or an action path gets a golden case (D33).

---

## 1. V3.8a — Language fidelity (bug fix)

**Symptom:** an English question sometimes gets a Spanish answer.

**Root cause (confirmed in code):** `lane0.render_local` chooses the answer
language from `match_.exemplar.lang` — the language of the *matched exemplar*,
not the user's question. The embedding model (bge-m3 / MiniLM) is cross-lingual,
so an English question routinely matches the Spanish half of an exemplar pair
above the 0.80 threshold, and lane 0 then renders Spanish. The model loop has a
weaker version of the same issue: the only language instruction is the static
"Answer in the user's language", with no per-turn signal, so Spanish
conversation history or a Spanish near-miss hint can pull it over.

**Fix — one shared detector, three call sites:**

| File | Change |
|---|---|
| `tool-service/app/language.py` (new) | `detect(text) -> "es" | "en"`: deterministic, no model. Spanish if the text has Spanish-only diacritics (`ñ`, `¿`, `¡`), or ≥2 Spanish stopword/question-word hits (`qué, cuánto/a/s, cuál, cómo, cuándo, dónde, alertas, agentes, fallos, reglas, muéstrame, últim*`) outstripping English hits; else English. Bounded word lists, unit-tested with the golden questions. |
| `tool-service/app/lane0.py` | `render_local` takes the **question** (or a resolved `lang`) and renders from `detect(question)`, never `exemplar.lang`. Thread the original `text` from `run_turn` into the render call (the `Lane0Analysis`/`Lane0Match` already flows there — add `question` to it or pass `text` alongside). Keep the `_STR["en"|"es"]` tables. |
| `tool-service/app/loop.py` | Scope-refusal language: replace the `re.search(r"\b(que|cuant|cual|como)\b", …)` heuristic with `language.detect(text)`. |
| `tool-service/app/loop.py` | Model loop: inject a per-turn line **into the transient context block** (where the env card / near-miss hint already ride — NOT the static prelude, so the prompt-cache prefix stays byte-stable): `"Reply entirely in {en=English|es=Spanish}. The user's message is in that language."` Placed after the static prefix as a system/user transient message. |

**Guard for both edges:** the connector edge composes history into
`${parameters.prompt}`; `detect()` runs on the full inbound text, which is fine
— the latest user line dominates the word counts in practice, and the explicit
instruction resolves ties.

**Golden (D33):** add a case where an English question is a known cross-lingual
match to a Spanish exemplar (e.g. "how many alerts in the last 24 hours") and
assert the answer contains English marker words and none of the Spanish
template strings (`alertas coincidentes`, `entre … y …`); mirror one ES→EN.
These fail today and pass after the fix.

---

## 2. V3.8b — Fully remove Keycloak

The compose service and `keycloak/` realm export are already gone (V3.6). What
remains is dead config, backward-compat fallbacks, one **functionally broken**
UI path, and stale doc/diagram references. Remove all of it — no OIDC fallback
kept (D52 is final: identity is the environment's own indexer via authinfo).

### 2a. Functional (do first — the confirm UI is currently broken)

`tool-service/app/actions/ui_static.py` still performs an OIDC **password grant
against Keycloak** (`${kcUrl}/realms/${kcRealm}/protocol/openid-connect/token`)
then exchanges — against a Keycloak that no longer exists, so operator sign-in
in the confirm card is dead. Rewrite `login()` to the V3.6 chain:

```js
// Basic creds -> shim /v1/token/exchange (X-Env-Id) -> turn JWT
const basic = btoa(`${user}:${pass}`);
const exchanged = await fetch(`${CFG.shimUrl}/v1/token/exchange`, {
  method: "POST",
  headers: { Authorization: `Basic ${basic}`, "X-Env-Id": CFG.envId },
});
if (!exchanged.ok) throw new Error(`sign-in failed (${exchanged.status})`);
setJwt((await exchanged.json()).access_token);
```

- Label "Operator sign-in (Keycloak)" → "Operator sign-in".
- `main.py` `_actions_ui_config()`: drop `kcUrl`, `kcRealm`, `kcClient`; add
  `envId` (from `WAI_ACTIONS_ENV_ID`) and keep `shimUrl`.
- Corresponding `WAI_ACTIONS_KC_*` settings in `config.py` → delete.

### 2b. Dead config and fallbacks

| File | Remove |
|---|---|
| `.env`, `.env.example` | the whole `KC_ADMIN / KC_ADMIN_PASSWORD / KC_REALM / KC_CLIENT_ID / KC_URL` block and its "Keycloak (the customer IdP stand-in)" heading |
| `mcp/server.py` | `WAI_MCP_KC_USER` / `WAI_MCP_KC_PASSWORD` fallbacks — keep only `WAI_MCP_USER` / `WAI_MCP_PASSWORD` |
| `golden/run_evals.py`, `golden/run_evals_actions.py` | `WAI_EVAL_KC_USER` / `WAI_EVAL_KC_PASSWORD` fallbacks — keep `WAI_EVAL_USER` / `WAI_EVAL_PASSWORD` |
| `golden/actions.yaml` | the `confirm_user … Keycloak` comment wording |
| `kind/host-gateway.sh` | "Keycloak" in the comment (the service is gone from kind too) |

### 2c. Docs and diagrams

| File | Change |
|---|---|
| `README.md` §4 | Identity chain narrative: analyst Basic creds → shim verifies via the environment's indexer `authinfo` → turn JWT ≤10 min → core + indexer verify. Remove the Keycloak password-grant curl; replace with the Basic→shim call. Remove Keycloak from the §1 component table and the "what runs where" mermaid. |
| `ENHANCEMENTS.md`, `ARCHITECTURE-V3.md`, `ARCHITECTURE-V3.5-ACTIONS.md` | Purge remaining Keycloak mentions or mark them explicitly historical ("v1/v2 used Keycloak; removed in V3.6"). Do not rewrite settled history — annotate. |
| `diagrams/wazuh-ai-v3-gateway.drawio` | Already Keycloak-free (V3.6); verify no stray "Keycloak" label remains except an optional "(replaces the former Keycloak stand-in)" note. |
| `diagrams/wazuh-ai-poc-architecture.drawio`, `diagrams/wazuh-ai-enhancements.drawio` | These are **historical snapshot decks** (v1 PoC, round-1 enhancements). Add a title-line note "HISTORICAL — identity now via indexer authinfo (V3.6), no Keycloak" rather than rescreenshotting the whole deck. The current-truth diagram is `wazuh-ai-v3-gateway.drawio`. If PNG exports are regenerated, do the identity diagram (`2-turn-data-flow`) too. |

**Acceptance:** `grep -rIi keycloak integrations/ai-assistant --exclude-dir=.wazuh-docker`
returns only explicit "historical / removed in V3.6" annotations; the confirm
UI operator sign-in works end-to-end (Basic → shim → JWT → confirm); `make
test`, `make evals`, `make evals-actions`, `make evals-connector` all green.

---

## 3. V3.8c — Conversational confirm ("yes" / "confirm")

Requested UX: when the assistant proposes a write/delete/PUT/POST action and
the user replies "confirm" or "yes", the assistant proceeds; "no" cancels.

### 3.0 Trust model — read before coding

The current design (D20/D48) executes actions only through
`POST /v1/actions/{id}/confirm` carrying an operator/responder **JWT** — chat
text is a trigger, never authorization. Conversational confirm keeps that on the
direct edges. On the **dashboard connector edge** there is no verified per-user
identity (D42: turns run as the env reader), so a chat "yes" cannot be tied to a
person.

**Leon's decision (2026-07-16): on the connector edge, execute on "yes",
trusting dashboard access as the authority.** This is recorded as **D53** and is
a deliberate, accepted lowering of D42/D48 — NOT an oversight. The security bar
on that edge becomes: *anyone who can open the dashboard Assistant chat can
trigger the action tiers that environment has opted into.* That is acceptable
because Wazuh dashboard access is already gated to trusted operators, and it is
bounded by the mitigations in §3.3 which stay MANDATORY.

### 3.1 Affirmation / negation detection (D54)

`tool-service/app/actions/confirm_intent.py` (new), deterministic bilingual:

- Affirm: `yes, y, confirm, confirmed, proceed, go ahead, do it, ok, okay,`
  `sí, si, confirmar, confirmo, adelante, procede, hazlo, dale`
- Negate: `no, cancel, stop, abort, nope, cancela, cancelar, detente, para`
- Match only when the message is *essentially just* the affirmation/negation
  (short, or affirmation + the action's target tokens) — a substantive new
  question must never be swallowed. Anything else → normal turn (proposal stays
  pending until its TTL).

### 3.2 Turn routing

In `run_turn`, before the model loop, when actions are enabled:

1. Look up **pending proposals** for this turn's scope (see §3.4).
2. If the message is a negation and ≥1 pending → reject the most-recent (or the
   named one); answer "cancelled", audit `action_rejected`.
3. If the message is an affirmation and exactly one pending proposal is in scope
   → run the confirm path deterministically (below); the model does not run.
4. If an affirmation but **multiple** pending → do NOT auto-confirm; the
   assistant lists them (`proposal_id` + one-line preview) and asks which. Never
   guess on ambiguity.
5. Otherwise → normal turn.

Confirm path = the same `confirm_proposal(...)` the API uses (idempotency key
auto-generated as `conv:{conversation_id}:{proposal_id}` so a repeated "yes"
is a safe replay, D49). The assistant's reply reports the executor result
verbatim (created / restarted / executed, or the honest error) and MUST NOT
claim success the executor did not return.

### 3.3 Authorization by edge — mandatory guardrails

| Edge | "yes" authorizes because | Guardrails that STAY |
|---|---|---|
| Direct (User JWT) | the JWT carries the tier's role (`wazuh_ai_operator` for dashboard, `wazuh_ai_responder` for manager/AR). `can_confirm_tier` is checked exactly as the API does. Word = trigger, JWT+role = authorization. | all of the below |
| Connector (EnvPrincipal) | **D53:** dashboard access is the authority; no per-user check. | **per-env tier opt-in** (deny-by-default: an env not listing `manager`/`active_response` can't even propose them, so "yes" has nothing to execute); **high-risk target echo** (§3.5); **per-tier rate caps** (R6.8); **full audit** `edge=connector, claimed_user=null`; **idempotency**; **kill switch**. |

### 3.4 Pending-proposal lookup

Proposals already carry `env_id` and `proposer_sub`. Add conversation scoping:

- Store/index pending proposals by `(env_id, conversation_id)`. Direct edges
  pass `conversation_id`; the connector edge composes history but the gateway
  treats `/analyze` as self-contained (D45), so pass the connector's memory id
  through as `conversation_id` when present, else fall back to
  `(env_id, connector-default)` with a **short window** (`WAI_CONFIRM_WINDOW_S`,
  default 300 s). If more than one is pending in that fallback scope → the
  ambiguity path (§3.2.4), never auto-confirm.
- Direct-edge confirm additionally requires `proposer_sub == user.sub` OR the
  confirmer holding the tier role (an operator may confirm another analyst's
  proposal; that is intended and audited).

### 3.5 High-risk stays gated even conversationally

For `risk == high` (active response, agent remove), a bare "yes" is
**insufficient**. The proposal answer instructs: *"Reply `yes restart-ossec on
001` to confirm."* The confirm-intent parser extracts `{command, agent_id}` from
the affirmation and feeds the existing `confirm_target` check (R6.7); mismatch
or a bare "yes" → the assistant re-prompts with the exact phrase, does not
execute. Low/medium accept a bare "yes".

### 3.6 Prompts

- `prompts/actions_propose.md` (or the existing propose prompt): the assistant,
  after proposing, states the confirm instruction in the user's language
  (§V3.8a): low/medium → "Reply **yes** to confirm or **no** to cancel";
  high → the target-echo phrase.
- The assistant never executes in its own narration; execution is the
  deterministic confirm path.

### 3.7 Config

| Knob | Default | Meaning |
|---|---|---|
| `WAI_ACTIONS_CONVERSATIONAL` | `true` | Enable "yes"/"confirm" routing (the requested UX) |
| `WAI_CONFIRM_WINDOW_S` | `300` | Fallback pending-proposal window when no conversation id (connector edge) |

The `/v1/actions/{id}/confirm` API and the UI card remain as the
higher-assurance path and for programmatic use — conversational confirm is
additive, not a replacement.

### 3.8 Golden (D33) — `golden/actions.yaml`

- direct: propose dashboard → "yes" → executed; propose → "no" → rejected.
- connector edge: propose (env with `dashboard` tier) → "yes" → executed under
  env principal, audit shows `edge=connector`.
- high-risk: propose AR → bare "yes" → re-prompt (not executed); "yes
  restart-ossec on 001" → executed.
- ambiguity: two pending → "yes" → assistant asks which, nothing executed.
- tier denial: env without `manager` tier → "restart agent 001" → refused at
  propose time; a later "yes" has nothing to run.
- language: the propose/confirm prompts answer in the user's language (V3.8a).

---

## 4. New design decisions

| Tag | Decision |
|---|---|
| D53 | On the dashboard connector edge, a conversational "yes"/"confirm" executes the pending action under the environment principal — dashboard access is accepted as the authority (Leon, 2026-07-16). A deliberate, documented lowering of D42/D48, bounded by per-env tier opt-in, high-risk target echo, rate caps, idempotency, and full audit (`claimed_user=null`). Revisit if verifiable per-user identity reaches the connector edge (OQ-V3-4). |
| D54 | Confirmation is a deterministic, bilingual intent match outside the model; the model proposes and instructs, it never self-authorizes execution. High-risk requires echoing the target, never a bare affirmation. |

## 5. Diagram delta

`diagrams/wazuh-ai-v3-gateway.drawio`: on the turn-flow, add the branch
"pending proposal + affirmation → deterministic confirm (bypasses the model)"
and annotate the connector edge box with "D53: chat 'yes' executes under env
principal — dashboard access = authority; high-risk still target-echoed." Mark
the Keycloak removal per §2c.

## 6. Open questions

- **OQ-V3-7:** the connector edge has no stable conversation id guaranteed
  across turns; the `(env, connector-default)` + 300 s fallback plus the
  ambiguity guard is the safe interim. If ML Commons memory exposes a
  conversation id to the connector payload, thread it through and drop the
  fallback. Verify during V3.8c bring-up.
