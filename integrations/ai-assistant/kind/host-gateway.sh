#!/usr/bin/env bash
# IP pods use to reach host-published docker services (Keycloak, Ollama, indexer).
set -euo pipefail
KIND_CLUSTER="${KIND_CLUSTER:-wazuh-ai}"
NODE="${KIND_CLUSTER}-control-plane"
if docker inspect "$NODE" >/dev/null 2>&1; then
  docker exec "$NODE" ip route show default | awk '{print $3; exit}'
else
  echo "172.17.0.1"
fi
