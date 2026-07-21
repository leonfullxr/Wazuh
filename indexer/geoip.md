# GeoIP Enrichment

The default Wazuh installation ships an
[ingest pipeline](https://github.com/wazuh/wazuh/blob/master/extensions/filebeat/7.x/wazuh-module/alerts/ingest/pipeline.json)
that runs the GeoIP processor at **index time**, enriching alerts with a
`GeoLocation` object (country, city, coordinates) derived from the source IP.

The key architectural consequence: enrichment happens **after** the manager
has already decoded the event and evaluated the ruleset. Therefore:

- You **cannot** write Wazuh rules that match on `GeoLocation.*` fields, and
  you cannot lower/raise an alert level with a custom rule based on country.
- You **can** act on GeoLocation at the indexer layer: OpenSearch Alerting
  monitors on `GeoLocation.country_name`, or pipeline processors that rewrite
  the alert (see [below](#filtering-alerts-by-country)).

## Table of Contents

- [Updating the GeoLite2 databases](#updating-the-geolite2-databases)
- [Automated update script](#automated-update-script)
- [Filtering alerts by country](#filtering-alerts-by-country)
- [References](#references)

## Updating the GeoLite2 databases

The indexer bundles MaxMind GeoLite2 databases under
`/usr/share/wazuh-indexer/modules/ingest-geoip/`. They go stale; to refresh
them, download current editions from MaxMind (free GeoLite2 account required)
and swap the `.mmdb` files:

```bash
# 1. Download GeoLite2-City, GeoLite2-Country and GeoLite2-ASN tarballs
#    from MaxMind, then extract them
tar -xvzf GeoLite2-City_<date>.tar.gz
tar -xvzf GeoLite2-Country_<date>.tar.gz
tar -xvzf GeoLite2-ASN_<date>.tar.gz

# 2. Move the bundled databases aside
mv /usr/share/wazuh-indexer/modules/ingest-geoip/GeoLite2-* /tmp/

# 3. Install the fresh .mmdb files
cp GeoLite2-City_<date>/GeoLite2-City.mmdb       /usr/share/wazuh-indexer/modules/ingest-geoip/
cp GeoLite2-Country_<date>/GeoLite2-Country.mmdb /usr/share/wazuh-indexer/modules/ingest-geoip/
cp GeoLite2-ASN_<date>/GeoLite2-ASN.mmdb         /usr/share/wazuh-indexer/modules/ingest-geoip/

# 4. Fix ownership and restart
chown wazuh-indexer:wazuh-indexer /usr/share/wazuh-indexer/modules/ingest-geoip/GeoLite2-*
systemctl restart wazuh-indexer
```

Repeat on every indexer node. In a cluster, restart one node at a time.

## Automated update script

The script below downloads each edition through the MaxMind API, compares it
byte-for-byte against the installed database, installs only real updates, and
restarts the indexer only if something changed. An EXIT trap guarantees the
indexer is left running even if the script fails midway.

<details>
<summary>Click to expand update_maxmind.sh</summary>

```bash
#!/usr/bin/env bash
set -euo pipefail

#
# update_maxmind.sh
#  Automates GeoLite2-Country, GeoLite2-City, and GeoLite2-ASN updates for Wazuh.
#  Downloads each tarball, extracts the .mmdb, compares byte-by-byte to avoid
#  unnecessary updates.
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

    # 3.a Download & extract .mmdb into a temp file in one step
    if ! curl -sSL --fail -u "${ACCOUNT_ID}:${LICENSE_KEY}" "${download_url}" \
         | tar -xOzf - --wildcards "*/${db}.mmdb" --strip-components=1 > "${tmp_mmdb}"; then
        echo "  ERROR: Failed to download or extract ${db}.mmdb" >&2
        [[ -f "${tmp_mmdb}" ]] && rm -f "${tmp_mmdb}"
        return 1
    fi
    echo "  Extracted ${db}.mmdb to temporary file."

    # 3.b If an existing .mmdb is present, compare against the new one
    if [[ -f "${dest_file}" ]]; then
        if cmp --silent -- "${tmp_mmdb}" "${dest_file}"; then
            echo "  ${db} is up to date (contents identical)."
            rm -f "${tmp_mmdb}"
            return 0
        fi
    fi

    # 3.c New or changed database: install it
    echo "  New or changed ${db} detected; installing updated .mmdb..."
    mv "${tmp_mmdb}" "${dest_file}"
    echo "  Moved ${db}.mmdb to ${dest_file}"
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
```

</details>

Schedule it daily (MaxMind updates GeoLite2 twice a week):

```bash
sudo install -m 755 update_maxmind.sh /usr/local/bin/update_maxmind.sh
sudo crontab -e
# Add:
0 2 * * * /usr/local/bin/update_maxmind.sh >> /var/log/update_maxmind.log 2>&1
```

## Filtering alerts by country

Since rules cannot see `GeoLocation`, escalate geographically suspicious
alerts by adding `set` processors to the same Filebeat ingest pipeline that
does the enrichment. Example: raise any alert originating outside Germany to
level 12 with a dedicated rule ID.

1. Back up and edit
   `/usr/share/filebeat/module/wazuh/alerts/ingest/pipeline.json` on the
   manager, adding these processors **after** the GeoIP processors:

   ```json
   {
     "set": {
       "if": "ctx.GeoLocation?.country_name != 'Germany'",
       "field": "rule.id",
       "value": "104456",
       "override": true,
       "ignore_failure": true
     }
   },
   {
     "set": {
       "if": "ctx.GeoLocation?.country_name != 'Germany'",
       "field": "rule.level",
       "value": "12",
       "override": true,
       "ignore_failure": true
     }
   },
   {
     "set": {
       "if": "ctx.GeoLocation?.country_name != 'Germany'",
       "field": "rule.description",
       "value": "Operation detected from a country other than Germany ({{GeoLocation.country_name}}).",
       "override": true,
       "ignore_failure": true
     }
   },
   ```

2. Upload and restart:

   ```bash
   filebeat setup --pipelines
   systemctl restart filebeat
   ```

3. Apply the same change on **all** manager nodes.

Notes:

- This rewrites the indexed document only - manager-side outputs (email,
  integrations, active response) still see the original level.
- For notification-only use cases, an OpenSearch **Alerting monitor** on
  `GeoLocation.country_name` is simpler and requires no pipeline surgery.
- `pipeline.json` is shared with the
  [index separation](index-separation.md#coordinating-pipelinejson-changes)
  and [timestamp formatting](ingest-pipeline-customization.md)
  customizations - keep them coordinated and re-apply after upgrades.

## References

- [Wazuh - GeoIP enrichment discussion](https://github.com/wazuh/wazuh/issues/4053)
- [MaxMind - Updating GeoIP databases](https://dev.maxmind.com/geoip/updating-databases/)
- [Elastic - Enrich events with GeoIP information (Filebeat)](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-geoip)
