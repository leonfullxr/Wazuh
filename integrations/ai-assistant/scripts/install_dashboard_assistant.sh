#!/usr/bin/env bash
# E16 — Install Dashboards Assistant plugins + wire ML Commons to the gateway.
#
# Targets a PRE-EXISTING self-hosted Wazuh dashboard / indexer.
# Orchestrates existing scripts; does not duplicate their logic.
# Never runs `make wazuh`.
#
# Usage:
#   cp deploy.env.example deploy.env   # fill endpoints + creds
#   sudo bash scripts/install_dashboard_assistant.sh
#   # or: DEPLOY_ENV=/path/to/deploy.env bash scripts/install_dashboard_assistant.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib/deploy_common.sh"

deploy_load_env "$ROOT"
cd "$ROOT"

DASHBOARD_MODE="${DASHBOARD_MODE:-package}"
WAZUH_DASHBOARD_HOME="${WAZUH_DASHBOARD_HOME:-/usr/share/wazuh-dashboard}"
WAZUH_DASHBOARD_PLUGINS_DIR="${WAZUH_DASHBOARD_PLUGINS_DIR:-$WAZUH_DASHBOARD_HOME/plugins}"
WAZUH_DASHBOARD_CONFIG="${WAZUH_DASHBOARD_CONFIG:-/etc/wazuh-dashboard/opensearch_dashboards.yml}"
WAZUH_DASHBOARD_SERVICE="${WAZUH_DASHBOARD_SERVICE:-wazuh-dashboard}"
SKIP_DASHBOARD_RESTART="${SKIP_DASHBOARD_RESTART:-false}"
SKIP_EMBEDDINGS="${SKIP_EMBEDDINGS:-false}"
WAI_CONNECTOR_HOST="${WAI_CONNECTOR_HOST:-tool-service}"
WAI_CONNECTOR_PORT="${WAI_CONNECTOR_PORT:-8080}"

install_plugins_package() {
  local pkg_json="$WAZUH_DASHBOARD_HOME/package.json"
  local osd_ver work
  [[ -f "$pkg_json" ]] || deploy_fail "Dashboard package.json not found at $pkg_json (set WAZUH_DASHBOARD_HOME or DASHBOARD_MODE=container)"
  osd_ver="$(grep '"version":' "$pkg_json" | head -n 1 | cut -d'"' -f4)"
  [[ -n "$osd_ver" ]] || deploy_fail "Could not parse OpenSearch Dashboards version from $pkg_json"
  deploy_log "Detected OpenSearch Dashboards version: $osd_ver"

  if [[ -d "$WAZUH_DASHBOARD_PLUGINS_DIR/assistantDashboards" \
     && -d "$WAZUH_DASHBOARD_PLUGINS_DIR/mlCommonsDashboards" ]]; then
    deploy_log "Plugins already present under $WAZUH_DASHBOARD_PLUGINS_DIR (idempotent skip of download)"
  else
    deploy_command_exists curl || deploy_fail "curl required"
    deploy_command_exists tar || deploy_fail "tar required"
    work="$(mktemp -d)"
    trap 'rm -rf "$work"' RETURN
    deploy_log "Downloading OpenSearch Dashboards $osd_ver bundle (plugin source)"
    curl -fsSL \
      "https://artifacts.opensearch.org/releases/bundle/opensearch-dashboards/${osd_ver}/opensearch-dashboards-${osd_ver}-linux-x64.tar.gz" \
      -o "$work/osd.tgz"
    tar -xzf "$work/osd.tgz" -C "$work"
    [[ -d "$work/opensearch-dashboards-${osd_ver}/plugins/assistantDashboards" ]] \
      || deploy_fail "assistantDashboards missing from OSD $osd_ver bundle"
    [[ -d "$work/opensearch-dashboards-${osd_ver}/plugins/mlCommonsDashboards" ]] \
      || deploy_fail "mlCommonsDashboards missing from OSD $osd_ver bundle"
    mkdir -p "$WAZUH_DASHBOARD_PLUGINS_DIR"
    rm -rf "$WAZUH_DASHBOARD_PLUGINS_DIR/assistantDashboards" \
           "$WAZUH_DASHBOARD_PLUGINS_DIR/mlCommonsDashboards"
    cp -a "$work/opensearch-dashboards-${osd_ver}/plugins/assistantDashboards" \
      "$WAZUH_DASHBOARD_PLUGINS_DIR/"
    cp -a "$work/opensearch-dashboards-${osd_ver}/plugins/mlCommonsDashboards" \
      "$WAZUH_DASHBOARD_PLUGINS_DIR/"
    chown -R wazuh-dashboard:wazuh-dashboard \
      "$WAZUH_DASHBOARD_PLUGINS_DIR/assistantDashboards" \
      "$WAZUH_DASHBOARD_PLUGINS_DIR/mlCommonsDashboards" 2>/dev/null || true
    chmod -R 750 \
      "$WAZUH_DASHBOARD_PLUGINS_DIR/assistantDashboards" \
      "$WAZUH_DASHBOARD_PLUGINS_DIR/mlCommonsDashboards"
    deploy_log "Installed assistantDashboards + mlCommonsDashboards"
  fi

  if [[ -f "$WAZUH_DASHBOARD_CONFIG" ]]; then
    if ! grep -q '^assistant.chat.enabled:' "$WAZUH_DASHBOARD_CONFIG"; then
      echo "assistant.chat.enabled: true" >> "$WAZUH_DASHBOARD_CONFIG"
      deploy_log "Set assistant.chat.enabled: true in $WAZUH_DASHBOARD_CONFIG"
    else
      sed -i 's/^assistant.chat.enabled:.*/assistant.chat.enabled: true/' \
        "$WAZUH_DASHBOARD_CONFIG"
      deploy_log "Ensured assistant.chat.enabled: true"
    fi
  else
    deploy_warn "Dashboard config not found: $WAZUH_DASHBOARD_CONFIG — set assistant.chat.enabled: true manually"
  fi

  if [[ "$SKIP_DASHBOARD_RESTART" != "true" ]]; then
    if deploy_command_exists systemctl; then
      systemctl restart "$WAZUH_DASHBOARD_SERVICE" \
        || deploy_warn "Could not restart $WAZUH_DASHBOARD_SERVICE — restart it manually"
    else
      deploy_warn "systemctl not available — restart the dashboard service manually"
    fi
  fi
}

print_container_path() {
  deploy_log "DASHBOARD_MODE=container — bake plugins with the repo Dockerfile, then point your stack at the image:"
  echo "  docker build -t wazuh-ai-dashboard:<your-wazuh-version> \\"
  echo "    --build-arg WAZUH_VERSION=<your-wazuh-version> \\"
  echo "    -f $ROOT/dashboard-assistant/Dockerfile $ROOT"
  echo "  # Ensure assistant.chat.enabled: true in the dashboard opensearch_dashboards.yml"
  echo "  # Then recreate the dashboard container with WAZUH_DASHBOARD_IMAGE=wazuh-ai-dashboard:..."
}

ensure_gateway_key() {
  if [[ -z "${WAI_ENV_LAB_KEY:-}" ]]; then
    WAI_ENV_LAB_KEY="$(openssl rand -hex 32)"
    export WAI_ENV_LAB_KEY
    deploy_warn "Generated WAI_ENV_LAB_KEY=$WAI_ENV_LAB_KEY"
    deploy_warn "Add that value to deploy.env (and environments.yaml) before recreate of tool-service."
  fi
  export WAI_ENV_LAB_KEY
  export INDEXER_URL INDEXER_ADMIN_USER INDEXER_ADMIN_PASSWORD
  export WAI_CONNECTOR_HOST WAI_CONNECTOR_PORT
}

wire_ml_commons() {
  ensure_gateway_key
  deploy_log "Wiring ML Commons connector/model/agent via scripts/dashboard_assistant_setup.sh"
  chmod +x "$ROOT/scripts/dashboard_assistant_setup.sh"
  # Existing script reads INDEXER_* and WAI_CONNECTOR_* / WAI_ENV_LAB_KEY from env.
  "$ROOT/scripts/dashboard_assistant_setup.sh"
}

wire_embeddings() {
  if [[ "$SKIP_EMBEDDINGS" == "true" ]]; then
    deploy_log "SKIP_EMBEDDINGS=true — not registering in-cluster embedding model"
    return 0
  fi
  if [[ -n "${WAI_EMBED_BASE_URL:-}" && "${WAI_EMBED_PROVIDER:-}" == "openai" ]]; then
    deploy_log "External embeddings configured (WAI_EMBED_BASE_URL=$WAI_EMBED_BASE_URL) — skipping mlcommons_embed_setup.sh"
    return 0
  fi
  deploy_log "Registering ML Commons embedding model via scripts/mlcommons_embed_setup.sh"
  chmod +x "$ROOT/scripts/mlcommons_embed_setup.sh"
  "$ROOT/scripts/mlcommons_embed_setup.sh" || deploy_warn "Embeddings setup failed — set WAI_EMBED_* manually if needed"
}

# ---- main -------------------------------------------------------------------
deploy_preflight_banner "install_dashboard_assistant.sh (E16)"
echo " mode:       $DASHBOARD_MODE"
echo " plugins:    $WAZUH_DASHBOARD_PLUGINS_DIR"
echo " embeddings: skip=$SKIP_EMBEDDINGS"
echo

deploy_check_indexer
deploy_check_gateway || true

case "$DASHBOARD_MODE" in
  package)
    [[ "$(id -u)" -eq 0 ]] || deploy_fail "DASHBOARD_MODE=package requires root (plugin install + service restart)"
    install_plugins_package
    ;;
  container)
    print_container_path
    ;;
  skip)
    deploy_log "DASHBOARD_MODE=skip — assuming plugins + assistant.chat.enabled already present"
    ;;
  *)
    deploy_fail "Unknown DASHBOARD_MODE=$DASHBOARD_MODE (use package|container|skip)"
    ;;
esac

wire_ml_commons
wire_embeddings

deploy_log "Done. Verification:"
echo "  1. Open the Wazuh dashboard and confirm the Assistant icon appears."
echo "  2. Ask \"Hi\" — the reply should come through the gateway (verifiability label)."
echo "  3. Re-run this script anytime; plugin download is skipped when already installed."
echo "  4. Ensure install_gateway.sh has placed tool-service where the indexer can reach"
echo "     http://${WAI_CONNECTOR_HOST}:${WAI_CONNECTOR_PORT}/v1/connector/analyze"
