#!/usr/bin/env bash
# Install assistantDashboards and mlCommonsDashboards for Wazuh Dashboard.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${AI_ASSISTANT_ENV:-$ROOT/ai-assistant.env}"
DRY_RUN="${DRY_RUN:-0}"

WAZUH_DASHBOARD_HOME="${WAZUH_DASHBOARD_HOME:-/usr/share/wazuh-dashboard}"
WAZUH_DASHBOARD_PLUGINS_DIR="${WAZUH_DASHBOARD_PLUGINS_DIR:-$WAZUH_DASHBOARD_HOME/plugins}"
WAZUH_DASHBOARD_CONFIG="${WAZUH_DASHBOARD_CONFIG:-/etc/wazuh-dashboard/opensearch_dashboards.yml}"
WAZUH_DASHBOARD_SERVICE="${WAZUH_DASHBOARD_SERVICE:-wazuh-dashboard}"

log() { printf '[ai-assistant] %s\n' "$*"; }
skip() { log "skipped, not on a dashboard host: $*"; exit 0; }
fail() { log "ERROR: $*"; exit 1; }

if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

PKG_JSON="$WAZUH_DASHBOARD_HOME/package.json"
if [[ ! -f "$PKG_JSON" ]]; then
  if [[ "$DRY_RUN" == "1" ]]; then
    skip "package.json not found at $PKG_JSON"
  fi
  fail "package.json not found at $PKG_JSON"
fi

OSD_VER="$(grep '"version":' "$PKG_JSON" | head -n 1 | cut -d'"' -f4)"
[[ -n "$OSD_VER" ]] || fail "could not parse OpenSearch Dashboards version"

if [[ "$DRY_RUN" == "1" ]]; then
  log "DRY_RUN: would install assistantDashboards + mlCommonsDashboards for OSD $OSD_VER"
  log "DRY_RUN: plugins dir $WAZUH_DASHBOARD_PLUGINS_DIR"
  exit 0
fi

if [[ -d "$WAZUH_DASHBOARD_PLUGINS_DIR/assistantDashboards" \
   && -d "$WAZUH_DASHBOARD_PLUGINS_DIR/mlCommonsDashboards" ]]; then
  log "plugins already present (idempotent skip)"
else
  command -v curl >/dev/null || fail "curl required"
  command -v tar >/dev/null || fail "tar required"
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' RETURN
  log "downloading OpenSearch Dashboards $OSD_VER bundle"
  curl -fsSL \
    "https://artifacts.opensearch.org/releases/bundle/opensearch-dashboards/${OSD_VER}/opensearch-dashboards-${OSD_VER}-linux-x64.tar.gz" \
    -o "$work/osd.tgz"
  tar -xzf "$work/osd.tgz" -C "$work"
  src="$work/opensearch-dashboards-${OSD_VER}/plugins"
  [[ -d "$src/assistantDashboards" ]] || fail "assistantDashboards missing from bundle"
  [[ -d "$src/mlCommonsDashboards" ]] || fail "mlCommonsDashboards missing from bundle"
  mkdir -p "$WAZUH_DASHBOARD_PLUGINS_DIR"
  rm -rf \
    "$WAZUH_DASHBOARD_PLUGINS_DIR/assistantDashboards" \
    "$WAZUH_DASHBOARD_PLUGINS_DIR/mlCommonsDashboards"
  cp -a "$src/assistantDashboards" "$WAZUH_DASHBOARD_PLUGINS_DIR/"
  cp -a "$src/mlCommonsDashboards" "$WAZUH_DASHBOARD_PLUGINS_DIR/"
  chown -R wazuh-dashboard:wazuh-dashboard \
    "$WAZUH_DASHBOARD_PLUGINS_DIR/assistantDashboards" \
    "$WAZUH_DASHBOARD_PLUGINS_DIR/mlCommonsDashboards" 2>/dev/null || true
  chmod -R 750 \
    "$WAZUH_DASHBOARD_PLUGINS_DIR/assistantDashboards" \
    "$WAZUH_DASHBOARD_PLUGINS_DIR/mlCommonsDashboards"
  log "installed assistantDashboards + mlCommonsDashboards"
fi

if [[ -f "$WAZUH_DASHBOARD_CONFIG" ]]; then
  if ! grep -q '^assistant.chat.enabled:' "$WAZUH_DASHBOARD_CONFIG"; then
    echo "assistant.chat.enabled: true" >> "$WAZUH_DASHBOARD_CONFIG"
  else
    sed -i 's/^assistant\.chat\.enabled:.*/assistant.chat.enabled: true/' \
      "$WAZUH_DASHBOARD_CONFIG"
  fi
  log "enabled assistant.chat.enabled in $WAZUH_DASHBOARD_CONFIG"
fi

if command -v systemctl >/dev/null; then
  systemctl restart "$WAZUH_DASHBOARD_SERVICE" \
    || log "could not restart $WAZUH_DASHBOARD_SERVICE — restart manually"
fi
