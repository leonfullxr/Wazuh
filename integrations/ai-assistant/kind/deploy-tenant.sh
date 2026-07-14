#!/usr/bin/env bash
# Render and apply one tenant namespace (auth-shim + tool-service + NetworkPolicy).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
[[ -f .env ]] && set -a && source .env && set +a

TENANT="${1:?usage: deploy-tenant.sh <tenant-a|tenant-b>}"
HOST_GW="${HOST_GW:-$(./kind/host-gateway.sh)}"

case "$TENANT" in
  tenant-a)
    KEYS_DIR="$ROOT/keys"
    KC_REALM="wazuh-poc"
    JWT_ISSUER="wazuh-ai-shim.lab"
    SHIM_NODEPORT=30771
    SVC_NODEPORT=30880
  ;;
  tenant-b)
    KEYS_DIR="$ROOT/keys/tenant-b"
    KC_REALM="wazuh-poc-b"
    JWT_ISSUER="wazuh-ai-shim.tenant-b"
    SHIM_NODEPORT=30772
    SVC_NODEPORT=30881
  ;;
  *)
    echo "unknown tenant: $TENANT" >&2
    exit 1
  ;;
esac

if [[ ! -f "$KEYS_DIR/jwt-private.pem" ]]; then
  echo "missing keys in $KEYS_DIR — run make kind-keys first" >&2
  exit 1
fi

export TENANT HOST_GW KEYS_DIR KC_REALM JWT_ISSUER SHIM_NODEPORT SVC_NODEPORT
export WAI_LLM_PROVIDER="${WAI_LLM_PROVIDER:-openai}"
export WAI_MODEL_ROUTER="${WAI_MODEL_ROUTER:-gpt-oss:20b}"
export WAI_MODEL_ANALYSIS="${WAI_MODEL_ANALYSIS:-gpt-oss:20b}"
export WAI_LANE0_ENABLED="${WAI_LANE0_ENABLED:-true}"
export WAI_EMBED_MODEL="${WAI_EMBED_MODEL:-bge-m3}"
export WAI_EVIDENCE_CACHE_TTL="${WAI_EVIDENCE_CACHE_TTL:-60}"

kubectl create namespace "$TENANT" --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace "$TENANT" wazuh-ai/tenant="$TENANT" --overwrite
kubectl -n "$TENANT" create secret generic jwt-keys \
  --from-file=jwt-private.pem="$KEYS_DIR/jwt-private.pem" \
  --from-file=jwt-public.pem="$KEYS_DIR/jwt-public.pem" \
  --dry-run=client -o yaml | kubectl apply -f -

envsubst < kind/tenants/tenant.yaml.tpl | kubectl apply -f -
kubectl -n "$TENANT" rollout status deployment/auth-shim --timeout=120s
kubectl -n "$TENANT" rollout status deployment/tool-service --timeout=180s
echo "tenant $TENANT ready (shim :$SHIM_NODEPORT tool-service :$SVC_NODEPORT host_gw=$HOST_GW)"
