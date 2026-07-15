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

CONTAINER="${CONTAINER:-single-node-wazuh.indexer-1}"   # verify: docker ps
SC_DIR="${SC_DIR:-/usr/share/wazuh-indexer/config/opensearch-security}"
CERTS="${CERTS:-/usr/share/wazuh-indexer/config/certs}"   # Wazuh 4.14+ layout
TOOLS=/usr/share/wazuh-indexer/plugins/opensearch-security/tools

wait_for_indexer() {
  local tries="${INDEXER_WAIT_TRIES:-60}"
  local delay="${INDEXER_WAIT_DELAY_S:-5}"
  echo "waiting for indexer to accept connections (up to $((tries * delay))s)..."
  for ((i = 1; i <= tries; i++)); do
    if docker exec "$CONTAINER" curl -sk \
      --cert "$CERTS/admin.pem" \
      --key "$CERTS/admin-key.pem" \
      "https://localhost:9200/_cluster/health?wait_for_status=yellow&timeout=5s" \
      2>/dev/null | grep -qE '"status":"(yellow|green)"'; then
      echo "indexer ready (attempt $i/$tries)"
      return 0
    fi
    sleep "$delay"
  done
  echo "indexer not ready on $CONTAINER — check: docker logs $CONTAINER" >&2
  return 1
}

wait_for_indexer

mkdir -p tmp
for f in config.yml roles.yml roles_mapping.yml; do
  docker cp "$CONTAINER:$SC_DIR/$f" "tmp/$f"
done

python3 merge_securityconfig.py tmp ../keys/jwt-public.pem

docker exec "$CONTAINER" mkdir -p /tmp/wazuh-ai
for f in config.yml roles.yml roles_mapping.yml; do
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

# Persist role files on disk; config.yml stays dynamic-only (securityadmin) so
# signing_key is not rewritten into a broken multiline PEM on restart.
for f in roles.yml roles_mapping.yml; do
  docker cp "tmp/$f" "$CONTAINER:$SC_DIR/$f"
done

echo "securityconfig applied: JWT auth domain + wazuh_ai_analyst_role are live"
