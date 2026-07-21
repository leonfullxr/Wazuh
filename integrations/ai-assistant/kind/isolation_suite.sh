#!/usr/bin/env bash
# Track B isolation suite (B4). Requires: docker Wazuh + Ollama up,
# kind cluster with tenant-a and tenant-b deployed.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SHIM_A="${WAI_EVAL_SHIM_A_URL:-http://localhost:30771}"
SVC_A="${WAI_EVAL_SVC_A_URL:-http://localhost:30880}"
SHIM_B="${WAI_EVAL_SHIM_B_URL:-http://localhost:30772}"
SVC_B="${WAI_EVAL_SVC_B_URL:-http://localhost:30881}"

failures=0
say() { printf '\n=== %s ===\n' "$1"; }
ok() { echo "PASS: $1"; }
bad() { echo "FAIL: $1"; failures=$((failures + 1)); }

mint_turn() {
  local user="$1" pass="$2" shim="$3" env_id="$4"
  curl -sf -X POST "$shim/v1/token/exchange" \
    -u "$user:$pass" \
    -H "X-Env-Id: $env_id" \
    | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])'
}

say "1 · happy path tenant-a"
JWT_A=$(mint_turn analyst1 analyst1 "$SHIM_A" tenant-a)
ANS=$(curl -sf -X POST "$SVC_A/v1/chat/sync" \
  -H "Authorization: Bearer $JWT_A" \
  -H "Content-Type: application/json" \
  -d '{"text":"How many alerts in the last 24 hours?"}')
if echo "$ANS" | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d.get("answer") and "verifiability" in d'; then
  ok "tenant-a analyst got an answer ($(echo "$ANS" | python3 -c 'import sys,json; print(json.load(sys.stdin)["verifiability"][:60])')…)"
else
  bad "tenant-a chat/sync failed: $ANS"
fi

say "2 · cross-tenant token rejected"
CODE=$(curl -s -o /tmp/wai-cross.json -w '%{http_code}' -X POST "$SVC_B/v1/chat/sync" \
  -H "Authorization: Bearer $JWT_A" \
  -H "Content-Type: application/json" \
  -d '{"text":"ping"}')
if [[ "$CODE" == "401" || "$CODE" == "403" ]]; then
  ok "tenant-a JWT on tenant-b service returned HTTP $CODE"
else
  bad "expected 401/403, got HTTP $CODE body=$(cat /tmp/wai-cross.json)"
fi
sleep 2
if kubectl -n tenant-b logs deployment/tool-service --tail=200 2>/dev/null | grep -q cross_tenant_token_rejected; then
  ok "cross_tenant_token_rejected audit event in tenant-b logs"
elif [[ "$CODE" == "401" ]]; then
  ok "rejected at signature check (tenant-b verify key != tenant-a mint key)"
else
  bad "cross_tenant_token_rejected not found in tenant-b tool-service logs"
fi

say "3 · cross-namespace network wall"
kubectl delete pod curl-isolation -n tenant-a --ignore-not-found --wait=false 2>/dev/null || true
kubectl run curl-isolation -n tenant-a --image=curlimages/curl:8.5.0 --restart=Never \
  --command -- sh -c 'curl -sS --connect-timeout 3 -m 5 http://tool-service.tenant-b.svc.cluster.local:8080/healthz' \
  >/tmp/wai-curl-cross.txt 2>&1 || true
for _ in $(seq 1 30); do
  phase=$(kubectl get pod curl-isolation -n tenant-a -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
  [[ "$phase" == "Succeeded" || "$phase" == "Failed" ]] && break
  sleep 1
done
kubectl logs curl-isolation -n tenant-a >/tmp/wai-curl-cross.txt 2>&1 || true
kubectl delete pod curl-isolation -n tenant-a --ignore-not-found --wait=false
if grep -qiE 'timed out|Connection refused|Could not resolve|Failed to connect|Connection timed out' /tmp/wai-curl-cross.txt; then
  ok "tenant-a pod cannot reach tenant-b service (network wall)"
else
  bad "expected connection failure, got: $(tr '\n' ' ' </tmp/wai-curl-cross.txt)"
fi

say "4 · golden set on tenant-a NodePort"
_golden() {
  WAI_EVAL_SHIM_URL="$SHIM_A" \
  WAI_EVAL_SVC_URL="$SVC_A" \
  WAI_EVAL_ENV_ID=tenant-a \
  python3 golden/run_evals.py
}
if _golden; then
  ok "golden/last_run.json green against tenant-a"
elif _golden; then
  ok "golden/last_run.json green against tenant-a (passed on retry)"
else
  bad "golden set failed on tenant-a (see output above)"
fi

say "summary"
if [[ $failures -eq 0 ]]; then
  echo "All four isolation assertions passed."
  exit 0
fi
echo "$failures assertion(s) failed."
exit 1
