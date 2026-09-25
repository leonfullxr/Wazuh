#!/usr/bin/env bash
# Install Wazuh Dashboard AI assistant PoC (MCP server + gateway + dashboard wiring).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="${1:-$ROOT/ai-assistant.env}"
DRY_RUN="${DRY_RUN:-0}"
INSTALL_ROOT="${INSTALL_ROOT:-/opt/wazuh-ai-assistant}"

log() { printf '[ai-assistant] %s\n' "$*"; }
fail() { log "ERROR: $*"; exit 1; }

[[ -f "$ENV_FILE" ]] || fail "env file not found: $ENV_FILE"

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

DEPLOYMENT_TYPE="${DEPLOYMENT_TYPE:-all-in-one}"
LLM_PROVIDER="${LLM_PROVIDER:-openai}"
MCP_PORT="${MCP_SERVER_PORT:-9900}"
GW_PORT="${GATEWAY_PORT:-9912}"

if [[ -z "${GATEWAY_API_KEY:-}" || "${GATEWAY_API_KEY}" == "CHANGE_ME" ]]; then
  [[ "$DRY_RUN" == "1" ]] || fail "set GATEWAY_API_KEY in $ENV_FILE (not empty or CHANGE_ME)"
fi

log "deployment type: $DEPLOYMENT_TYPE"
log "llm provider: $LLM_PROVIDER"

case "$DEPLOYMENT_TYPE" in
  all-in-one)
    log "plan: MCP server port $MCP_PORT, gateway port $GW_PORT, dashboard plugins + connector"
    ;;
  indexer)
    log "plan: MCP server port $MCP_PORT, gateway port $GW_PORT"
    ;;
  dashboard)
    log "plan: dashboard plugins + connector registration"
    ;;
  *)
    fail "unknown DEPLOYMENT_TYPE: $DEPLOYMENT_TYPE"
    ;;
esac

export AI_ASSISTANT_ENV="$ENV_FILE"

if [[ "$DRY_RUN" == "1" ]]; then
  log "DRY_RUN=1 — no packages installed, no services started"
  case "$DEPLOYMENT_TYPE" in
    all-in-one|dashboard)
      bash "$ROOT/dashboard/install_dashboard_plugins.sh"
      bash "$ROOT/dashboard/register_connector.sh"
      ;;
  esac
  exit 0
fi

command -v python3 >/dev/null || fail "python3 required"
command -v systemctl >/dev/null || fail "systemctl required (single-host install)"

mkdir -p "$INSTALL_ROOT" /etc/wazuh-ai-assistant
cp "$ENV_FILE" /etc/wazuh-ai-assistant/ai-assistant.env

write_mcp_env() {
  cat >/etc/wazuh-ai-assistant/mcp-server.env <<EOF
OPENSEARCH_URL=https://${WAZUH_INDEXER_IP:-127.0.0.1}:9200
OPENSEARCH_USERNAME=${WAZUH_INDEXER_USER:-admin}
OPENSEARCH_PASSWORD=${WAZUH_INDEXER_PASS:-}
OPENSEARCH_SSL_VERIFY=${WAZUH_INDEXER_VERIFY_TLS:-false}
EOF
}

install_services() {
  python3 -m venv "$INSTALL_ROOT/venv"
  # shellcheck disable=SC1091
  source "$INSTALL_ROOT/venv/bin/activate"
  pip install -q --upgrade pip
  pip install -q opensearch-mcp-server-py
  pip install -q -r "$ROOT/mcp-llm-gateway/requirements.txt"

  rm -rf "$INSTALL_ROOT/mcp-llm-gateway"
  cp -a "$ROOT/mcp-llm-gateway" "$INSTALL_ROOT/mcp-llm-gateway"

  cat >/etc/systemd/system/wazuh-ai-mcp-server.service <<EOF
[Unit]
Description=Wazuh AI Assistant MCP server
After=network.target

[Service]
Type=simple
EnvironmentFile=/etc/wazuh-ai-assistant/mcp-server.env
ExecStart=$INSTALL_ROOT/venv/bin/opensearch-mcp-server-py --transport stream --host ${MCP_SERVER_HOST:-0.0.0.0} --port ${MCP_PORT}
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

  cat >/etc/systemd/system/wazuh-ai-gateway.service <<EOF
[Unit]
Description=Wazuh AI Assistant MCP-LLM gateway
After=network.target wazuh-ai-mcp-server.service

[Service]
Type=simple
EnvironmentFile=/etc/wazuh-ai-assistant/ai-assistant.env
WorkingDirectory=$INSTALL_ROOT/mcp-llm-gateway
ExecStart=$INSTALL_ROOT/venv/bin/uvicorn gateway.main:app --host ${GATEWAY_HOST:-0.0.0.0} --port ${GW_PORT}
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable wazuh-ai-mcp-server.service wazuh-ai-gateway.service
  systemctl restart wazuh-ai-mcp-server.service wazuh-ai-gateway.service
}

case "$DEPLOYMENT_TYPE" in
  all-in-one|indexer)
    write_mcp_env
    install_services
    ;;
esac

case "$DEPLOYMENT_TYPE" in
  all-in-one|dashboard)
    bash "$ROOT/dashboard/install_dashboard_plugins.sh"
    bash "$ROOT/dashboard/register_connector.sh"
    ;;
esac

log "installation complete"
