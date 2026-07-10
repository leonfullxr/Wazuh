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
# Paths as shipped in wazuh-indexer 4.14 images (override via env if yours differ)
SC_DIR="${SC_DIR:-/usr/share/wazuh-indexer/config/opensearch-security}"
CERTS="${CERTS:-/usr/share/wazuh-indexer/config/certs}"
TOOLS="${TOOLS:-/usr/share/wazuh-indexer/plugins/opensearch-security/tools}"

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

echo "securityconfig applied: JWT auth domain + wazuh_ai_analyst_role are live"
