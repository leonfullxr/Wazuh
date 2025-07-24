#!/bin/bash
set -euo pipefail

#
# update_maxmind.sh
#  Automates GeoLite2-Country, GeoLite2-City, and GeoLite2-ASN updates for Wazuh.
#  Downloads each tarball, extracts the .mmdb, compares byte-by-byte to avoid unnecessary updates.
#

###############
# 1. Configuration
###############
# Set to "true" if running in Docker mode, "false" for systemd mode (non-containerized):
CONTAINER=false

ACCOUNT_ID="..."   # Your MaxMind Account ID
LICENSE_KEY="..."  # Your MaxMind License Key
DB_TYPES=("GeoLite2-Country" "GeoLite2-City" "GeoLite2-ASN")
TEMP_DIR="$(mktemp -d)"
UPDATED_ANY=false

# Container variables
if [[ "$CONTAINER" == true ]]; then
    DEST_DIR=".../multi-node/config/wazuh_indexer/geoip-data" # Your host path
    DEFAULT_IMAGE="wazuh/wazuh-indexer:4.12.0" # Default image to use for bootstrapping <-- Please change to your version
    COMPOSE_FILE=".../multi-node/docker-compose.yml" # Your file path
    
    INDEXERS=$(sudo docker ps --filter "ancestor="${DEFAULT_IMAGE}"" --format "{{.Names}}")
    
    if [[ -z "$INDEXERS" ]]; then
      echo "No running indexer containers for image ${DEFAULT_IMAGE}" >&2
      exit 1
    fi

    echo "Found indexer containers:"
    while read -r c; do
      echo "  • $c"
    done <<<"$INDEXERS"
    
    SERVICES=""
    for c in $INDEXERS; do
      # e.g. multi-node-wazuh1.indexer-1 → wazuh1.indexer
      svc=${c#multi-node-}           # remove project name and hyphen
      svc=${svc%-[0-9]*}            # remove trailing -1, -2, etc.
      SERVICES="$SERVICES $svc"
    done

    echo "Detected services to recreate:$SERVICES"
    
    # --- Bootstrap host dir only if empty ---
    mkdir -p "$DEST_DIR"
    # If it's empty, seed just the three GeoIP DBs from a fresh image
    if [ -z "$(ls -A "$DEST_DIR")" ]; then
      echo "GeoIP dir is empty; bootstrapping default .mmdb files…"
      # 1) Create a stopped container from the default image
      TMP_CID=$(docker create "$DEFAULT_IMAGE")

      # 2) Copy each DB file out into our host folder
      for f in GeoLite2-City.mmdb GeoLite2-Country.mmdb GeoLite2-ASN.mmdb; do
        echo "  • Copying $f"
        docker cp "${TMP_CID}":/usr/share/wazuh-indexer/modules/ingest-geoip/"$f" "$DEST_DIR"
      done

      # 3) Clean up the temp container
      docker rm "$TMP_CID" >/dev/null
      echo "Bootstrapped GeoIP DBs into $DEST_DIR"
    else
      echo "GeoIP dir already populated; skipping bootstrap."
    fi
else
    DEST_DIR="/usr/share/wazuh-indexer/modules/ingest-geoip"
fi
#############################
# 2. Ensure Wazuh Indexer is running (called on exit)
#############################
stop_indexer() {
  if [[ "$CONTAINER" == true ]]; then
      echo "Stopping all indexer containers…"
      for c in $INDEXERS; do
        echo "  • $c"
        sudo docker stop "$c" || echo "  Could not stop $c"
      done
  else
    echo "Stopping systemd service wazuh-indexer..."
    sudo systemctl stop wazuh-indexer || true
  fi
}

start_indexer() {
  if [[ "$CONTAINER" == true ]]; then
    echo "Starting all indexer containers…"
    for c in $INDEXERS; do
      echo "  • $c"
      sudo docker start "$c" || echo "  Could not start $c"
    done
  else
    echo "Starting systemd service wazuh-indexer..."
    sudo systemctl start wazuh-indexer
  fi
}
ensure_indexer_running() {
  echo "Ensuring indexer is running..."
  if [[ "$CONTAINER" == true ]]; then
    echo "Ensuring all indexers are running…"
    for c in $INDEXERS; do
      if ! sudo docker ps --filter "name=$c" --filter "status=running" \
           | grep -qw "$c"; then
        sudo docker start "$c" && echo "  • Started $c" || echo "  Failed $c"
      else
        echo "  • $c is already running."
      fi
    done
  else
    if ! systemctl is-active --quiet wazuh-indexer; then
      start_indexer
    else
      echo "  Systemd service is already active."
    fi
  fi
}
trap ensure_indexer_running EXIT

#############################
# 3. Download, extract, compare, and update one database
#############################
update_db() {
    local db="$1"
    local suffix="tar.gz"
    local download_url="https://download.maxmind.com/app/geoip_download?edition_id=${db}&license_key=${LICENSE_KEY}&suffix=${suffix}"
    local dest_file="${DEST_DIR}/${db}.mmdb"
    local tmp_mmdb="${TEMP_DIR}/${db}.mmdb"

    echo "Checking ${db}..."

    # 3.a Download & extract .mmdb into a temp file in one step
    if ! curl -sSL --fail -u "${ACCOUNT_ID}:${LICENSE_KEY}" "${download_url}" \
         | tar -xOzf - --wildcards "*/${db}.mmdb" --strip-components=1 > "${tmp_mmdb}"; then
        echo "  ERROR: Failed to download or extract ${db}.mmdb" >&2
        [[ -f "${tmp_mmdb}" ]] && rm -f "${tmp_mmdb}"
        return 1
    fi
    echo "  Extracted ${db}.mmdb to temporary file."

    # 3.b If existing .mmdb is present, compare against the new one using cmp
    if [[ -f "${dest_file}" ]]; then
        if cmp --silent -- "${tmp_mmdb}" "${dest_file}"; then
            echo "  ${db} is up to date (contents identical)."
            rm -f "${tmp_mmdb}"
            return 0
        fi
    fi

    # 3.c If we reach here, the new .mmdb differs or the old one did not exist
    echo "  New or changed ${db} detected; installing updated .mmdb..."

    # 3.d Move new .mmdb into place atomically
    mv "${tmp_mmdb}" "${dest_file}"
    echo "  Moved ${db}.mmdb to ${dest_file}"

    # 3.e Set correct ownership
    if [[ "$CONTAINER" == true ]]; then
      sudo chown -R 1000:1000 "${dest_file}"
    else
      chown wazuh-indexer:wazuh-indexer "${dest_file}"
    fi
    
    UPDATED_ANY=true
    return 0
}

# Rollback function: restores original GeoLite2 DBs from the image
rollback_geoip() {
  echo "⏪ Rolling back GeoIP DBs to default image versions…"

  # 1) Spin up a stopped container from the default image
  local tmp_cid
  tmp_cid=$(sudo docker create "wazuh/wazuh-indexer:4.12.0")  # create returns the new container ID

  # 2) Copy each of the three DB files back into DEST_DIR
  for f in GeoLite2-City.mmdb GeoLite2-Country.mmdb GeoLite2-ASN.mmdb; do
    echo "   • Restoring $f"
    sudo docker cp "${tmp_cid}":/usr/share/wazuh-indexer/modules/ingest-geoip/"$f" \
      "${DEST_DIR}/${f}"                               # cp works on stopped containers
    sudo chown 1000:1000 "${DEST_DIR}/${f}"                  # ensure correct ownership
  done

  # 3) Clean up the temporary container
  sudo docker rm "${tmp_cid}" >/dev/null

  # 4) Recreate the indexer so it picks up the rolled-back files
  echo "🔄 Restarting indexer container…"
  sudo docker-compose -f "${COMPOSE_FILE}" up -d --force-recreate "${CONTAINER_NAME}"
  echo "✅ Rollback complete."
}


#############################
# 4. Stop Wazuh Indexer before updates (optional but recommended)
#############################
echo "Stopping indexer..."
if [[ "$CONTAINER" == true ]]; then
    #if sudo docker ps --filter "name=${CONTAINER_NAME}" --filter "status=running" | grep -q "${CONTAINER_NAME}"; then
    stop_indexer
    echo "  Wazuh Indexer stopped."
    #else
     #   echo "  Wazuh Indexer is not running; skipping stop."
    #fi
else
    if systemctl is-active --quiet wazuh-indexer; then
        stop_indexer
        echo "  Wazuh Indexer stopped."
    else
        echo "  Wazuh Indexer is not running; skipping stop."
    fi
fi

#############################
# 5. Iterate over each DB type
#############################
for db_type in "${DB_TYPES[@]}"; do
    if ! update_db "${db_type}"; then
        echo "  WARNING: update_db failed for ${db_type}"
    fi
done

#############################
# 6. Cleanup temporary directory
#############################
rm -rf "${TEMP_DIR}"

#############################
# 7. Restart Wazuh Indexer if any DB was updated
#############################
if [[ "${UPDATED_ANY}" == true ]]; then
    echo "Updates applied; restarting indexer..."
    if [[ "$CONTAINER" == true ]]; then
      echo "Updates applied; recreating indexer containers to pick up new mounts…"
      for svc in $SERVICES; do
        echo "  • Removing old container for service '$svc'…"
        docker-compose -f "$COMPOSE_FILE" rm -sf "$svc" \
          && docker-compose -f "$COMPOSE_FILE" up -d --force-recreate "$svc" \
          && echo "     Recreated $svc" || echo "    Failed to recreate $svc"
      done
      echo "All indexer containers have been recreated with updated mounts."
    else
        sudo systemctl restart wazuh-indexer
    fi
    echo "MaxMind GeoLite2 databases have been updated successfully."
else
    echo "No updates needed; indexer will be ensured up by trap."
fi

exit 0