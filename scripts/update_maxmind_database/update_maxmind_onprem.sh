#!/bin/bash
set -euo pipefail

#
# update_maxmind.sh --> For non-containerized Wazuh installations
#  Automates GeoLite2-Country, GeoLite2-City, and GeoLite2-ASN updates for Wazuh.
#  Downloads each tarball, extracts the .mmdb, compares byte-by-byte to avoid unnecessary updates.
#

###############
# 1. Configuration
###############
ACCOUNT_ID="..."   # Your MaxMind Account ID
LICENSE_KEY="..."  # Your MaxMind License Key
DB_TYPES=("GeoLite2-Country" "GeoLite2-City" "GeoLite2-ASN")
DEST_DIR="/usr/share/wazuh-indexer/modules/ingest-geoip"
TEMP_DIR="$(mktemp -d)"
UPDATED_ANY=false

#############################
# 2. Ensure Wazuh Indexer is running (called on exit)
#############################
ensure_indexer_running() {
    echo "Ensuring Wazuh Indexer service is running..."
    if ! systemctl is-active --quiet wazuh-indexer; then
        if systemctl start wazuh-indexer; then
            echo "  Wazuh Indexer started."
        else
            echo "  ERROR: Failed to start Wazuh Indexer." >&2
        fi
    else
        echo "  Wazuh Indexer is already running."
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

    # 3.a Download & extract .mmdb into a temp file in one step :contentReference[oaicite:2]{index=2}
    if ! curl -sSL --fail -u "${ACCOUNT_ID}:${LICENSE_KEY}" "${download_url}" \
         | tar -xOzf - --wildcards "*/${db}.mmdb" --strip-components=1 > "${tmp_mmdb}"; then
        echo "  ERROR: Failed to download or extract ${db}.mmdb" >&2
        [[ -f "${tmp_mmdb}" ]] && rm -f "${tmp_mmdb}"
        return 1
    fi
    echo "  Extracted ${db}.mmdb to temporary file."

    # 3.b If existing .mmdb is present, compare against the new one using cmp :contentReference[oaicite:3]{index=3}
    if [[ -f "${dest_file}" ]]; then
        if cmp --silent -- "${tmp_mmdb}" "${dest_file}"; then
            echo "  ${db} is up to date (contents identical)."
            rm -f "${tmp_mmdb}"
            return 0
        fi
    fi

    # 3.c If we reach here, the new .mmdb differs or the old one did not exist
    echo "  New or changed ${db} detected; installing updated .mmdb..."

    # 3.d Move new .mmdb into place atomically :contentReference[oaicite:4]{index=4}
    mv "${tmp_mmdb}" "${dest_file}"
    echo "  Moved ${db}.mmdb to ${dest_file}"

    # 3.e Set correct ownership
    chown wazuh-indexer:wazuh-indexer "${dest_file}"

    UPDATED_ANY=true
    return 0
}

#############################
# 4. Stop Wazuh Indexer before updates (optional but recommended)
#############################
echo "Stopping Wazuh Indexer service..."
if systemctl is-active --quiet wazuh-indexer; then
    systemctl stop wazuh-indexer
    echo "  Wazuh Indexer stopped."
else
    echo "  Wazuh Indexer is not running; skipping stop."
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
    echo "Restarting Wazuh Indexer service..."
    if systemctl restart wazuh-indexer; then
        echo "  Wazuh Indexer restarted."
        echo "MaxMind GeoLite2 databases have been updated successfully."
    else
        echo "  ERROR: Failed to restart Wazuh Indexer." >&2
    fi
else
    echo "No updates were necessary; Wazuh Indexer will be ensured running by EXIT trap."
fi

exit 0