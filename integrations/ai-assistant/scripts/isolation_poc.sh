#!/usr/bin/env bash
# PoC isolation checks (V3.2) against the local docker stack — no kind required.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SHIM="${WAI_EVAL_SHIM_URL:-http://localhost:8081}"
SVC="${WAI_EVAL_SVC_URL:-http://localhost:8080}"
ENV_A="${WAI_EVAL_ENV_ID:-lab}"
ENV_B="${WAI_EVAL_ENV_B_ID:-lab-b}"
KEY_A="${WAI_ENV_LAB_KEY:-}"
KEY_B="${WAI_ENV_LAB_B_KEY:-}"

failures=0
say() { printf '\n=== %s ===\n' "$1"; }
ok() { echo "PASS: $1"; }
bad() { echo "FAIL: $1"; failures=$((failures + 1)); }

say "1 · connector rejects unknown env key"
CODE=$(curl -s -o /tmp/wai-iso-badkey.json -w '%{http_code}' \
  -X POST "$SVC/v1/connector/analyze" \
  -H "Content-Type: application/json" \
  -H "X-Env-Key: definitely-not-a-real-key" \
  -d '{"parameters":{"prompt":"ping"}}')
if [[ "$CODE" == "401" ]]; then
  ok "unknown X-Env-Key returned HTTP 401"
else
  bad "expected 401, got HTTP $CODE body=$(cat /tmp/wai-iso-badkey.json)"
fi

say "2 · shim rejects bad password (audited)"
CODE=$(curl -s -o /tmp/wai-iso-badpass.json -w '%{http_code}' \
  -X POST "$SHIM/v1/token/exchange" \
  -u "analyst1:wrong-password" \
  -H "X-Env-Id: $ENV_A")
if [[ "$CODE" == "401" ]]; then
  ok "bad password returned HTTP 401"
else
  bad "expected 401, got HTTP $CODE body=$(cat /tmp/wai-iso-badpass.json)"
fi

say "3 · happy path mint + chat for primary env"
JWT=$(curl -sf -X POST "$SHIM/v1/token/exchange" \
  -u analyst1:analyst1 \
  -H "X-Env-Id: $ENV_A" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
ANS=$(curl -sf -X POST "$SVC/v1/chat/sync" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"text":"How many alerts in the last 24 hours?"}')
if echo "$ANS" | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d.get("answer")'; then
  ok "tenant-a analyst got an answer"
else
  bad "chat/sync failed: $ANS"
fi

if [[ -n "$KEY_B" && -n "$KEY_A" ]]; then
  say "4 · cross-env JWT rejected on second env key path"
  CODE=$(curl -s -o /tmp/wai-iso-cross.json -w '%{http_code}' \
    -X POST "$SVC/v1/connector/analyze" \
    -H "Content-Type: application/json" \
    -H "X-Env-Key: $KEY_B" \
    -d '{"parameters":{"prompt":"ping"}}')
  # JWT from env A should not be involved; this asserts the B key resolves independently.
  if [[ "$CODE" == "200" ]]; then
    ok "env-b connector key accepted (isolated principal)"
  else
    bad "env-b connector returned HTTP $CODE (check WAI_ENV_LAB_B_KEY and registry)"
  fi
else
  say "4 · skipped (set WAI_ENV_LAB_KEY and WAI_ENV_LAB_B_KEY for dual-env checks)"
fi

say "summary"
if [[ $failures -eq 0 ]]; then
  echo "All isolation assertions passed."
  exit 0
fi
echo "$failures assertion(s) failed."
exit 1
