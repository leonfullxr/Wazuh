#!/bin/bash
# wazuh-services-monitoring.sh - Simple watchdog for Wazuh services on an
# all-in-one node. Sends an email if any service is not running.
#
# Usage: run hourly from cron:
#   0 * * * * /path/to/wazuh-services-monitoring.sh
#
# Requires a working mail transport agent (e.g. Postfix) and mailutils.

EMAIL_FROM="sender@example.com"
EMAIL_TO="recipient@example.com"

SERVICES=("wazuh-manager" "wazuh-indexer" "wazuh-dashboard" "filebeat")

for SERVICE_NAME in "${SERVICES[@]}"; do
    if [[ "$(systemctl is-active $SERVICE_NAME)" != "active" ]]; then
        echo "Service $SERVICE_NAME is not running" | mail -s "Wazuh service down" -r "$EMAIL_FROM" "$EMAIL_TO"
    fi
done
