#!/usr/bin/env bash
# V3.1e — ML Commons wiring for the Dashboard Assistant connector edge.
#
# Idempotent: deletes and recreates the named model/agent on each run.
# Writes .dashboard-assistant-model-id and .dashboard-assistant-agent-id.
#
# Prerequisites:
#   make wazuh && make securityconfig && make poc
#   WAI_ENV_LAB_KEY set (connector credential)
#   tool-service reachable from wazuh.indexer as http://tool-service:8080
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

INDEXER_URL="${INDEXER_URL:-https://localhost:9200}"
INDEXER_ADMIN_USER="${INDEXER_ADMIN_USER:-admin}"
INDEXER_ADMIN_PASSWORD="${INDEXER_ADMIN_PASSWORD:-SecretPassword}"
GATEWAY_HOST="${WAI_CONNECTOR_HOST:-tool-service}"
GATEWAY_PORT="${WAI_CONNECTOR_PORT:-8080}"
GATEWAY_KEY="${WAI_ENV_LAB_KEY:-}"
MODEL_NAME="wazuh-ai-gateway-model"
CONNECTOR_NAME="wazuh-ai-gateway-connector"
AGENT_NAME="wazuh-ai-os-chat-agent"
CONTAINER="${CONTAINER:-single-node-wazuh.indexer-1}"
CERTS="${CERTS:-/usr/share/wazuh-indexer/config/certs}"

if [[ -z "$GATEWAY_KEY" ]]; then
  GATEWAY_KEY="$(openssl rand -hex 32)"
  echo "generated WAI_ENV_LAB_KEY=$GATEWAY_KEY"
  echo "Add that line to .env before the next tool-service recreate."
fi

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

delete_by_name() {
  local kind="$1" name="$2"
  local hits
  hits=$(admin_curl "${INDEXER_URL}/_plugins/_ml/${kind}/_search" \
    -H 'Content-Type: application/json' \
    -d "{\"query\":{\"match\":{\"name\":\"${name}\"}},\"size\":20}" 2>/dev/null || echo '{}')
  python3 - "$kind" "$name" "$hits" <<'PY'
import json, sys, subprocess, os
kind, name, raw = sys.argv[1], sys.argv[2], sys.argv[3]
data = json.loads(raw or "{}")
ids = [h.get("_id") for h in data.get("hits", {}).get("hits", []) if h.get("_id")]
url = os.environ.get("INDEXER_URL", "https://localhost:9200")
user = os.environ.get("INDEXER_ADMIN_USER", "admin")
passwd = os.environ.get("INDEXER_ADMIN_PASSWORD", "SecretPassword")
for mid in ids:
    subprocess.run(
        ["curl", "-sk", "-u", f"{user}:{passwd}", "-X", "DELETE", f"{url}/_plugins/_ml/{kind}/{mid}"],
        check=False,
    )
PY
}

echo "==> ML Commons cluster settings (agent framework + trusted connector regex)"
GATEWAY_REGEX="^http://${GATEWAY_HOST}:${GATEWAY_PORT}/.*$"
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
    "plugins.ml_commons.trusted_connector_endpoints_regex": [
      "^https://runtime\\.sagemaker\\..*[a-z0-9-]\\.amazonaws\\.com/.*$",
      "^https://api\\.openai\\.com/.*$",
      "^https://api\\.cohere\\.ai/.*$",
      "^https://bedrock-runtime\\..*[a-z0-9-]\\.amazonaws\\.com/.*$",
      regex,
    ],
  },
}))
PY
)" | python3 -m json.tool | head -30

echo "==> removing prior model/agent (idempotent)"
delete_by_name models "$MODEL_NAME"
delete_by_name agents "$AGENT_NAME"

echo "==> registering remote model + inline connector"
MODEL_PAYLOAD=$(python3 - "$GATEWAY_HOST" "$GATEWAY_PORT" "$GATEWAY_KEY" "$MODEL_NAME" "$CONNECTOR_NAME" <<'PY'
import json, sys
host, port, key, model_name, connector_name = sys.argv[1:6]
endpoint = f"http://{host}:{port}/v1/connector/analyze"
print(json.dumps({
  "name": model_name,
  "function_name": "remote",
  "description": "Remote model: wazuh-ai gateway connector",
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
        "X-Env-Key": "${credential.api_key}",
      },
      "request_body": '{ "parameters": { "prompt": "${parameters.prompt}" } }',
      "request_timeout": "120s",
    }],
  },
}))
PY
)
REGISTER=$(admin_curl -X POST "${INDEXER_URL}/_plugins/_ml/models/_register" \
  -H 'Content-Type: application/json' -d "$MODEL_PAYLOAD")
echo "$REGISTER" | python3 -m json.tool

MODEL_ID=$(echo "$REGISTER" | json_field model_id)
if [[ -z "$MODEL_ID" ]]; then
  MODEL_ID=$(echo "$REGISTER" | json_field task_id)
fi
if [[ -z "$MODEL_ID" ]]; then
  echo "model registration did not return model_id" >&2
  exit 1
fi

echo "==> deploying model $MODEL_ID"
admin_curl -X POST "${INDEXER_URL}/_plugins/_ml/models/${MODEL_ID}/_deploy" \
  -H 'Content-Type: application/json' -d '{}' | python3 -m json.tool

for _ in $(seq 1 60); do
  STATE=$(admin_curl "${INDEXER_URL}/_plugins/_ml/models/${MODEL_ID}" | json_field model_state)
  echo "  model_state: $STATE"
  [[ "$STATE" == "DEPLOYED" ]] && break
  sleep 5
done

AGENT_PAYLOAD=$(python3 - "$MODEL_ID" "$AGENT_NAME" <<'PY'
import json, sys
model_id, agent_name = sys.argv[1], sys.argv[2]
print(json.dumps({
  "name": agent_name,
  "type": "conversational",
  "app_type": "os_chat",
  "description": "Conversational agent delegating to wazuh-ai gateway",
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

echo "==> registering conversational agent"
AGENT_RESP=$(admin_curl -X POST "${INDEXER_URL}/_plugins/_ml/agents/_register" \
  -H 'Content-Type: application/json' -d "$AGENT_PAYLOAD")
echo "$AGENT_RESP" | python3 -m json.tool
AGENT_ID=$(echo "$AGENT_RESP" | json_field agent_id)
if [[ -z "$AGENT_ID" ]]; then
  echo "agent registration did not return agent_id" >&2
  exit 1
fi

echo "==> setting os_chat root agent (admin cert)"
ROOT_PAYLOAD=$(python3 -c "import json,sys; print(json.dumps({'type':'os_chat_root_agent','configuration':{'agent_id':sys.argv[1]}}))" "$AGENT_ID")
docker exec "$CONTAINER" curl -sk \
  --cacert "$CERTS/root-ca.pem" \
  --cert "$CERTS/admin.pem" \
  --key "$CERTS/admin-key.pem" \
  -X PUT "https://wazuh.indexer:9200/.plugins-ml-config/_doc/os_chat" \
  -H 'Content-Type: application/json' \
  -d "$ROOT_PAYLOAD" | python3 -m json.tool

echo "$MODEL_ID" > .dashboard-assistant-model-id
echo "$AGENT_ID" > .dashboard-assistant-agent-id
echo "wrote .dashboard-assistant-model-id and .dashboard-assistant-agent-id"

cat <<EOF

Next:
  1. Ensure .env has: WAI_ENV_LAB_KEY=$GATEWAY_KEY
     WAI_ENV_LAB_READER=wazuh_ai_env_reader:EnvReaderLab1!
  2. make poc   # recreate tool-service with env key
  3. Open https://localhost (admin / SecretPassword) → Assistant icon → "Hi"
  4. make evals-connector

EOF
