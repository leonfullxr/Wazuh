#!/usr/bin/env bash
# Register ML Commons connector, model, agent, and os_chat root mapping.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${AI_ASSISTANT_ENV:-$ROOT/ai-assistant.env}"
DRY_RUN="${DRY_RUN:-0}"

log() { printf '[ai-assistant] %s\n' "$*"; }
skip() { log "skipped, not on an indexer host: $*"; exit 0; }
fail() { log "ERROR: $*"; exit 1; }

if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

INDEXER_URL="${INDEXER_URL:-https://${WAZUH_INDEXER_IP:-127.0.0.1}:9200}"
INDEXER_USER="${WAZUH_INDEXER_USER:-admin}"
INDEXER_PASS="${WAZUH_INDEXER_PASS:-}"
GATEWAY_HOST="${GATEWAY_PUBLIC_HOST:-127.0.0.1}"
GATEWAY_PORT="${GATEWAY_PORT:-9912}"
GATEWAY_KEY="${GATEWAY_API_KEY:-}"
VERIFY_TLS="${WAZUH_INDEXER_VERIFY_TLS:-true}"
MODEL_NAME="wazuh-ai-assistant-model"
CONNECTOR_NAME="wazuh-ai-assistant-connector"
AGENT_NAME="wazuh-ai-assistant-agent"

if [[ -z "$INDEXER_PASS" || "$INDEXER_PASS" == "CHANGE_ME" ]]; then
  if [[ "$DRY_RUN" == "1" ]]; then
    skip "indexer credentials not configured"
  fi
  fail "set WAZUH_INDEXER_PASS in $ENV_FILE"
fi

if [[ -z "$GATEWAY_KEY" || "$GATEWAY_KEY" == "CHANGE_ME" ]]; then
  if [[ "$DRY_RUN" == "1" ]]; then
    skip "gateway API key not configured"
  fi
  fail "set GATEWAY_API_KEY in $ENV_FILE"
fi

CURL_TLS=(-k)
if [[ "$VERIFY_TLS" == "true" ]]; then
  CURL_TLS=()
fi

if [[ "$DRY_RUN" == "1" ]]; then
  log "DRY_RUN: would register connector at http://${GATEWAY_HOST}:${GATEWAY_PORT}/analyze"
  log "DRY_RUN: indexer $INDEXER_URL"
  exit 0
fi

admin_curl() {
  curl "${CURL_TLS[@]}" -sS -u "${INDEXER_USER}:${INDEXER_PASS}" "$@"
}

json_field() {
  python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get(sys.argv[1],""))' "$1"
}

GATEWAY_ENDPOINT="http://${GATEWAY_HOST}:${GATEWAY_PORT}/analyze"
GATEWAY_REGEX="^http://${GATEWAY_HOST}:${GATEWAY_PORT}/.*$"

log "enabling ML Commons agent framework"
admin_curl -X PUT "${INDEXER_URL}/_cluster/settings" \
  -H 'Content-Type: application/json' \
  -d "$(python3 - "$GATEWAY_REGEX" <<'PY'
import json, sys
regex = sys.argv[1]
print(json.dumps({
  "persistent": {
    "plugins.ml_commons.agent_framework_enabled": True,
    "plugins.ml_commons.only_run_on_ml_node": False,
    "plugins.ml_commons.connector.private_ip_enabled": True,
    "plugins.ml_commons.trusted_connector_endpoints_regex": [regex],
  },
}))
PY
)" >/dev/null

MODEL_PAYLOAD=$(python3 - "$GATEWAY_ENDPOINT" "$GATEWAY_KEY" "$MODEL_NAME" "$CONNECTOR_NAME" <<'PY'
import json, sys
endpoint, key, model_name, connector_name = sys.argv[1:5]
print(json.dumps({
  "name": model_name,
  "function_name": "remote",
  "description": "Wazuh AI assistant gateway connector",
  "connector": {
    "name": connector_name,
    "version": 1,
    "protocol": "http",
    "parameters": {"endpoint": endpoint},
    "credential": {"api_key": key},
    "actions": [{
      "action_type": "predict",
      "method": "POST",
      "url": "${parameters.endpoint}",
      "headers": {
        "Content-Type": "application/json",
        "X-Api-Key": "${credential.api_key}",
      },
      "request_body": '{ "parameters": { "question": "${parameters.prompt}" } }',
      "request_timeout": "120s",
    }],
  },
}))
PY
)

log "registering remote model"
REGISTER=$(admin_curl -X POST "${INDEXER_URL}/_plugins/_ml/models/_register" \
  -H 'Content-Type: application/json' -d "$MODEL_PAYLOAD")
MODEL_ID=$(echo "$REGISTER" | json_field model_id)
TASK_ID=$(echo "$REGISTER" | json_field task_id)

if [[ -z "$MODEL_ID" && -n "$TASK_ID" ]]; then
  log "waiting for async registration task $TASK_ID"
  for _ in $(seq 1 60); do
    TASK_RESP=$(admin_curl "${INDEXER_URL}/_plugins/_ml/tasks/${TASK_ID}")
    MODEL_ID=$(echo "$TASK_RESP" | json_field model_id)
    [[ -n "$MODEL_ID" ]] && break
    sleep 5
  done
fi

[[ -n "$MODEL_ID" ]] || fail "model registration did not return model_id"

log "deploying model $MODEL_ID"
admin_curl -X POST "${INDEXER_URL}/_plugins/_ml/models/${MODEL_ID}/_deploy" \
  -H 'Content-Type: application/json' -d '{}' >/dev/null

AGENT_PAYLOAD=$(python3 - "$MODEL_ID" "$AGENT_NAME" <<'PY'
import json, sys
model_id, agent_name = sys.argv[1], sys.argv[2]
print(json.dumps({
  "name": agent_name,
  "type": "conversational",
  "app_type": "os_chat",
  "description": "Wazuh dashboard assistant agent",
  "llm": {
    "model_id": model_id,
    "parameters": {
      "prompt": "${parameters.question}",
      "response_filter": "$.output.message",
      "max_iteration": 1,
      "stop_when_no_tool_found": True,
      "message_history_limit": 10,
    },
  },
  "memory": {"type": "conversation_index"},
  "tools": [{"type": "SearchIndexTool", "name": "placeholder_noop"}],
}))
PY
)

log "registering conversational agent"
AGENT_RESP=$(admin_curl -X POST "${INDEXER_URL}/_plugins/_ml/agents/_register" \
  -H 'Content-Type: application/json' -d "$AGENT_PAYLOAD")
AGENT_ID=$(echo "$AGENT_RESP" | json_field agent_id)
[[ -n "$AGENT_ID" ]] || fail "agent registration did not return agent_id"

log "setting os_chat root agent"
admin_curl -X PUT "${INDEXER_URL}/.plugins-ml-config/_doc/os_chat" \
  -H 'Content-Type: application/json' \
  -d "$(python3 -c "import json,sys; print(json.dumps({'type':'os_chat_root_agent','configuration':{'agent_id':sys.argv[1]}}))" "$AGENT_ID")" \
  >/dev/null

log "connector registered (model=$MODEL_ID agent=$AGENT_ID)"
