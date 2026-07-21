#!/usr/bin/env bash
# Shared helpers for E16 installers. Sourced by install_*.sh — not run directly.
# shellcheck disable=SC2034

: "${_DEPLOY_COMMON_LOADED:=}"
[[ -n "$_DEPLOY_COMMON_LOADED" ]] && return 0
_DEPLOY_COMMON_LOADED=1

deploy_log()  { echo -e "\n[INFO] $*"; }
deploy_warn() { echo -e "\n[WARN] $*" >&2; }
deploy_fail() { echo -e "\n[ERROR] $*" >&2; exit 1; }

deploy_require() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    deploy_fail "Missing required variable: $name (set it in deploy.env)"
  fi
}

deploy_command_exists() { command -v "$1" >/dev/null 2>&1; }

# Resolve repo root from a script under scripts/ or scripts/lib/.
deploy_root_from() {
  local here
  here="$(cd "$(dirname "$1")" && pwd)"
  if [[ "$(basename "$here")" == "lib" ]]; then
    cd "$here/../.." && pwd
  else
    cd "$here/.." && pwd
  fi
}

# Load deploy.env then optional .env (deploy.env wins for overlapping keys).
deploy_load_env() {
  local root="$1"
  local file="${DEPLOY_ENV:-$root/deploy.env}"
  if [[ ! -f "$file" ]]; then
    deploy_fail "Config not found: $file
Copy deploy.env.example → deploy.env and fill your Wazuh endpoints/credentials.
Never run make wazuh — these installers target a pre-existing deployment."
  fi
  set -a
  # shellcheck disable=SC1090
  source "$file"
  set +a
  if [[ -f "$root/.env" ]]; then
    # Fill gaps only; do not override deploy.env.
    set -a
    # shellcheck disable=SC1091
    source "$root/.env"
    set +a
    set -a
    # shellcheck disable=SC1090
    source "$file"
    set +a
  fi
  DEPLOY_ENV_FILE="$file"
}

deploy_curl_tls() {
  # Prefer pinning the env CA; fall back to -k only when explicitly allowed.
  if [[ -n "${INDEXER_CA_PATH:-}" && -f "${INDEXER_CA_PATH}" ]]; then
    echo "--cacert ${INDEXER_CA_PATH}"
  elif [[ "${INDEXER_VERIFY_TLS:-true}" == "true" ]]; then
    deploy_fail "INDEXER_VERIFY_TLS=true but INDEXER_CA_PATH is missing or unreadable"
  else
    deploy_warn "TLS verification disabled (INDEXER_VERIFY_TLS=false) — lab only"
    echo "-k"
  fi
}

deploy_preflight_banner() {
  local title="$1"
  echo "============================================================"
  echo " $title"
  echo "============================================================"
  echo " config:     ${DEPLOY_ENV_FILE:-?}"
  echo " indexer:    ${INDEXER_URL:-?}"
  echo " gateway:    ${WAI_CONNECTOR_HOST:-?}:${WAI_CONNECTOR_PORT:-8080}"
  echo " env_id:     ${WAI_ENV_ID:-lab}"
  echo " TLS CA:     ${INDEXER_CA_PATH:-'(none — verify_tls=${INDEXER_VERIFY_TLS:-false})'}"
  echo "============================================================"
}

deploy_check_indexer() {
  local tls
  # shellcheck disable=SC2046
  tls=$(deploy_curl_tls)
  deploy_require INDEXER_URL
  deploy_require INDEXER_ADMIN_USER
  deploy_require INDEXER_ADMIN_PASSWORD
  # word-split intentional for curl flags
  # shellcheck disable=SC2086
  if ! curl -sf $tls -u "${INDEXER_ADMIN_USER}:${INDEXER_ADMIN_PASSWORD}" \
    "${INDEXER_URL}/_cluster/health?timeout=5s" >/dev/null; then
    deploy_fail "Indexer not reachable at ${INDEXER_URL} (check URL, CA, admin creds)"
  fi
  deploy_log "Indexer reachable"
}

deploy_check_gateway() {
  local url="http://${WAI_CONNECTOR_HOST:-127.0.0.1}:${WAI_CONNECTOR_PORT:-8080}/healthz"
  if curl -sf --connect-timeout 3 "$url" >/dev/null 2>&1 \
    || curl -sf --connect-timeout 3 "http://127.0.0.1:${WAI_CONNECTOR_PORT:-8080}/healthz" >/dev/null 2>&1; then
    deploy_log "Gateway health endpoint reachable"
    return 0
  fi
  deploy_warn "Gateway not reachable yet at $url (expected before install_gateway / after start)"
  return 1
}
