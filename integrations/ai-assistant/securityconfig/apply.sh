#!/usr/bin/env bash
# Adds the wazuh-ai JWT auth domain, the analyst role and its mapping to the
# LIVE indexer securityconfig of the wazuh-docker single-node stack.
#
# Flow: docker cp the three live files out -> merge our fragments in with
# merge_securityconfig.py -> docker cp back to /tmp -> run securityadmin.sh
# per file. In the fleet this is a template change in the config pipeline
# instead; this script is the lab-manual equivalent.
#
# Host requirement: python3 + pyyaml (pip install -r ../requirements-host.txt)
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$(cd .. && pwd)"
if [[ -f "$ROOT/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT/.env"
  set +a
fi
INDEXER_URL="${INDEXER_URL:-https://localhost:9200}"
INDEXER_ADMIN_USER="${INDEXER_ADMIN_USER:-admin}"
INDEXER_ADMIN_PASSWORD="${INDEXER_ADMIN_PASSWORD:-SecretPassword}"

CONTAINER="${CONTAINER:-single-node-wazuh.indexer-1}"   # verify: docker ps
SC_DIR="${SC_DIR:-/usr/share/wazuh-indexer/config/opensearch-security}"
CERTS="${CERTS:-/usr/share/wazuh-indexer/config/certs}"   # Wazuh 4.14+ layout
WAZUH_DIR="${WAZUH_DIR:-$ROOT/.wazuh-docker/single-node}"
[[ "$WAZUH_DIR" != /* ]] && WAZUH_DIR="$ROOT/$WAZUH_DIR"
HOST_INTERNAL_USERS="${HOST_INTERNAL_USERS:-$WAZUH_DIR/config/wazuh_indexer/internal_users.yml}"
TOOLS=/usr/share/wazuh-indexer/plugins/opensearch-security/tools

wait_for_indexer() {
  local tries="${INDEXER_WAIT_TRIES:-60}"
  local delay="${INDEXER_WAIT_DELAY_S:-5}"
  echo "waiting for indexer to accept connections (up to $((tries * delay))s)..."
  for ((i = 1; i <= tries; i++)); do
    if curl -sk -u "${INDEXER_ADMIN_USER}:${INDEXER_ADMIN_PASSWORD}" \
      "${INDEXER_URL}/_cluster/health?wait_for_status=yellow&timeout=5s" \
      2>/dev/null | grep -qE '"status":"(yellow|green)"'; then
      echo "indexer ready (attempt $i/$tries)"
      return 0
    fi
    sleep "$delay"
  done
  echo "indexer not ready at $INDEXER_URL — check: docker logs $CONTAINER" >&2
  return 1
}

# After `docker compose run generator` the PEM files on disk update, but a
# running indexer keeps serving the previous TLS cert until restart. securityadmin
# then fails PKIX even though admin.pem verifies against root-ca.pem on disk.
ensure_indexer_tls_synced() {
  local tmp served ondisk
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  docker cp "$CONTAINER:$CERTS/wazuh.indexer.pem" "$tmp/wazuh.indexer.pem" >/dev/null 2>&1 || return 0
  served=$(echo | openssl s_client -connect localhost:9200 -servername wazuh.indexer 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256 2>/dev/null || true)
  ondisk=$(openssl x509 -in "$tmp/wazuh.indexer.pem" -noout -fingerprint -sha256 2>/dev/null || true)
  if [[ -z "$served" || -z "$ondisk" || "$served" == "$ondisk" ]]; then
    return 0
  fi
  echo "indexer TLS cert on disk does not match what :9200 is serving (stale in-memory cert)."
  echo "restarting $CONTAINER so securityadmin can connect..."
  docker restart "$CONTAINER" >/dev/null
  wait_for_indexer
}

wait_for_indexer
ensure_indexer_tls_synced

mkdir -p tmp
for f in config.yml roles.yml roles_mapping.yml internal_users.yml; do
  docker cp "$CONTAINER:$SC_DIR/$f" "tmp/$f"
done

python3 merge_securityconfig.py tmp ../keys/jwt-public.pem

docker exec "$CONTAINER" mkdir -p /tmp/wazuh-ai
for f in config.yml roles.yml roles_mapping.yml internal_users.yml; do
  docker cp "tmp/$f" "$CONTAINER:/tmp/wazuh-ai/$f"
done

run_admin() {
  docker exec -e JAVA_HOME=/usr/share/wazuh-indexer/jdk "$CONTAINER" \
    bash "$TOOLS/securityadmin.sh" \
    -f "/tmp/wazuh-ai/$1" -t "$2" -icl -nhnv \
    -cacert "$CERTS/root-ca.pem" \
    -cert "$CERTS/admin.pem" \
    -key "$CERTS/admin-key.pem" \
    -h wazuh.indexer
}

run_admin config.yml config
run_admin roles.yml roles
run_admin roles_mapping.yml rolesmapping
run_admin internal_users.yml internalusers

# Persist role files on disk; config.yml stays dynamic-only (securityadmin) so
# signing_key is not rewritten into a broken multiline PEM on restart.
for f in roles.yml roles_mapping.yml; do
  docker cp "tmp/$f" "$CONTAINER:$SC_DIR/$f"
done
# internal_users.yml is bind-mounted from the host in wazuh-docker — docker cp
# into the container path fails with "device or resource busy".
cp "tmp/internal_users.yml" "$HOST_INTERNAL_USERS"

echo "securityconfig applied: JWT auth domain + analyst + env reader principals are live"
