#!/usr/bin/env bash
# One-time ML Commons embedding model setup for Track C3.
#
# Registers and deploys the bilingual MiniLM sentence-transformer into the
# Wazuh indexer the PoC already runs. Writes the deployed model id to
# .mlcommons-embed-model-id for WAI_EMBED_ML_MODEL_ID.
#
# Prerequisites: `make wazuh` stack up; admin certs in the indexer container.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CONTAINER="${CONTAINER:-single-node-wazuh.indexer-1}"
CERTS="${CERTS:-/usr/share/wazuh-indexer/config/certs}"
INDEXER_URL="${INDEXER_URL:-https://localhost:9200}"
MODEL_NAME="huggingface/sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
MODEL_VERSION="${ML_MODEL_VERSION:-1.0.2}"
MODEL_FORMAT="${ML_MODEL_FORMAT:-ONNX}"

admin_curl() {
  docker exec "$CONTAINER" curl -sk \
    --cert "$CERTS/admin.pem" \
    --key "$CERTS/admin-key.pem" \
    "$@"
}

echo "==> enabling ML Commons on data nodes (single-node lab)"
admin_curl -X PUT "$INDEXER_URL/_cluster/settings" \
  -H 'Content-Type: application/json' \
  -d '{"persistent":{"plugins.ml_commons.only_run_on_ml_node":false}}' \
  | python3 -m json.tool | head -20

echo "==> registering pretrained embedding model ($MODEL_NAME $MODEL_VERSION $MODEL_FORMAT)"
REGISTER=$(admin_curl -X POST "$INDEXER_URL/_plugins/_ml/models/_register?deploy=true" \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"$MODEL_NAME\",\"version\":\"$MODEL_VERSION\",\"model_format\":\"$MODEL_FORMAT\"}")
echo "$REGISTER" | python3 -m json.tool

MODEL_ID=$(echo "$REGISTER" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("model_id") or d.get("task_id",""))')
if [[ -z "$MODEL_ID" ]]; then
  echo "registration did not return model_id — check task status manually" >&2
  exit 1
fi

# deploy=true may return task_id first; poll until model_id is known.
if [[ "$MODEL_ID" != *[!0-9a-zA-Z_-]* ]] && [[ ${#MODEL_ID} -lt 10 ]]; then
  TASK_ID="$MODEL_ID"
  echo "==> waiting for register task $TASK_ID"
  for _ in $(seq 1 60); do
  STATUS=$(admin_curl "$INDEXER_URL/_plugins/_ml/tasks/$TASK_ID" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("state",""))' || true)
    echo "  task state: $STATUS"
    [[ "$STATUS" == "COMPLETED" ]] && break
    [[ "$STATUS" == "FAILED" ]] && { admin_curl "$INDEXER_URL/_plugins/_ml/tasks/$TASK_ID"; exit 1; }
    sleep 5
  done
  MODEL_ID=$(admin_curl "$INDEXER_URL/_plugins/_ml/tasks/$TASK_ID" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("model_id",""))')
fi

if [[ -z "$MODEL_ID" ]]; then
  echo "could not resolve model_id after registration" >&2
  exit 1
fi

echo "==> waiting for model $MODEL_ID to deploy"
for _ in $(seq 1 60); do
  STATE=$(admin_curl "$INDEXER_URL/_plugins/_ml/models/$MODEL_ID" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("model_state",""))' || true)
  echo "  model_state: $STATE"
  [[ "$STATE" == "DEPLOYED" ]] && break
  sleep 5
done

echo "$MODEL_ID" > .mlcommons-embed-model-id
echo "wrote $ROOT/.mlcommons-embed-model-id"
echo
echo "Next:"
echo "  1. make securityconfig   # grants ml predict to wazuh_ai_analyst_role"
echo "  2. Set in .env:"
echo "       WAI_EMBED_PROVIDER=mlcommons"
echo "       WAI_EMBED_ML_MODEL_ID=$MODEL_ID"
echo "  3. make poc              # recreate tool-service"
echo "  4. Re-verify lane-0 thresholds against golden set (MiniLM cosine scale differs from bge-m3)"
