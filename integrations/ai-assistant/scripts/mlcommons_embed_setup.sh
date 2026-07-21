#!/usr/bin/env bash
# One-time ML Commons embedding model setup for Track C3.
#
# Registers and deploys the bilingual MiniLM sentence-transformer into the
# Wazuh indexer the PoC already runs. Writes the deployed model id to
# .mlcommons-embed-model-id for WAI_EMBED_ML_MODEL_ID.
#
# Prerequisites: `make wazuh` stack up; indexer reachable on localhost:9200.
#
# Uses host-side admin basic auth (same as seed/seed_alerts.py). Client-cert
# curl from inside the indexer container breaks after cert regeneration.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Load lab defaults from .env when present.
if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

INDEXER_URL="${INDEXER_URL:-https://localhost:9200}"
INDEXER_ADMIN_USER="${INDEXER_ADMIN_USER:-admin}"
INDEXER_ADMIN_PASSWORD="${INDEXER_ADMIN_PASSWORD:-SecretPassword}"
MODEL_NAME="huggingface/sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
MODEL_VERSION="${ML_MODEL_VERSION:-1.0.2}"
MODEL_FORMAT="${ML_MODEL_FORMAT:-ONNX}"

admin_curl() {
  local out http
  out=$(mktemp)
  http=$(curl -sk -u "${INDEXER_ADMIN_USER}:${INDEXER_ADMIN_PASSWORD}" \
    -w '%{http_code}' -o "$out" "$@") || {
    echo "curl failed: $*" >&2
    rm -f "$out"
    return 1
  }
  if [[ "$http" -lt 200 || "$http" -ge 300 ]]; then
    echo "indexer HTTP $http for: $*" >&2
    cat "$out" >&2
    rm -f "$out"
    return 1
  fi
  cat "$out"
  rm -f "$out"
}

json_field() {
  python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get(sys.argv[1],""))' "$1"
}

echo "==> enabling ML Commons on data nodes (single-node lab)"
admin_curl -X PUT "${INDEXER_URL}/_cluster/settings" \
  -H 'Content-Type: application/json' \
  -d '{"persistent":{"plugins.ml_commons.only_run_on_ml_node":false}}' \
  | python3 -m json.tool | head -20

echo "==> registering pretrained embedding model ($MODEL_NAME $MODEL_VERSION $MODEL_FORMAT)"
REGISTER=$(admin_curl -X POST "${INDEXER_URL}/_plugins/_ml/models/_register?deploy=true" \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"$MODEL_NAME\",\"version\":\"$MODEL_VERSION\",\"model_format\":\"$MODEL_FORMAT\"}")
echo "$REGISTER" | python3 -m json.tool

MODEL_ID=$(echo "$REGISTER" | json_field model_id)
if [[ -z "$MODEL_ID" ]]; then
  MODEL_ID=$(echo "$REGISTER" | json_field task_id)
fi
if [[ -z "$MODEL_ID" ]]; then
  echo "registration did not return model_id or task_id" >&2
  exit 1
fi

# deploy=true may return task_id first; poll until model_id is known.
if ! admin_curl "${INDEXER_URL}/_plugins/_ml/models/${MODEL_ID}" >/dev/null 2>&1; then
  TASK_ID="$MODEL_ID"
  echo "==> waiting for register task $TASK_ID"
  for _ in $(seq 1 60); do
    TASK_JSON=$(admin_curl "${INDEXER_URL}/_plugins/_ml/tasks/$TASK_ID")
    STATUS=$(echo "$TASK_JSON" | json_field state)
    echo "  task state: $STATUS"
    [[ "$STATUS" == "COMPLETED" ]] && break
    if [[ "$STATUS" == "FAILED" ]]; then
      echo "$TASK_JSON" | python3 -m json.tool >&2
      exit 1
    fi
    sleep 5
  done
  MODEL_ID=$(echo "$TASK_JSON" | json_field model_id)
fi

if [[ -z "$MODEL_ID" ]]; then
  echo "could not resolve model_id after registration" >&2
  exit 1
fi

echo "==> waiting for model $MODEL_ID to deploy"
for _ in $(seq 1 60); do
  MODEL_JSON=$(admin_curl "${INDEXER_URL}/_plugins/_ml/models/$MODEL_ID")
  STATE=$(echo "$MODEL_JSON" | json_field model_state)
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
echo "  3. docker compose -f docker-compose.poc.yml up -d --build tool-service"
echo "  4. Re-verify lane-0 thresholds against golden set (MiniLM cosine scale differs from bge-m3)"
