#!/bin/bash
# wazuh-services-monitoring-multinode.sh - Multi-node Wazuh services watchdog.
# Runs centrally and checks specified services on multiple remote nodes via
# SSH. If a service is found inactive, an email notification is sent.
#
# Prerequisites: passwordless SSH from the monitoring server to each node,
# and a working mail transport agent (e.g. Postfix).
#
# Usage: run hourly from cron:
#   0 * * * * /path/to/wazuh-services-monitoring-multinode.sh

# Define the list of nodes and their respective services.
# Modify these arrays to match your environment.
declare -A NODES_SERVICES
# Format: NODES_SERVICES[node_hostname]="service1 service2 ..."
NODES_SERVICES["wazuh-master"]="wazuh-manager filebeat"
NODES_SERVICES["wazuh-worker"]="wazuh-manager filebeat"
NODES_SERVICES["wazuh-indexer"]="wazuh-indexer"
NODES_SERVICES["wazuh-dashboard"]="wazuh-dashboard"

# Email settings
EMAIL_FROM="sender@example.com"
EMAIL_TO="recipient@example.com"
EMAIL_SUBJECT="Wazuh Service Down Alert on Multi-Node Environment"

# Loop through each node and check its services
for NODE in "${!NODES_SERVICES[@]}"; do
    SERVICES=${NODES_SERVICES[$NODE]}
    for SERVICE in $SERVICES; do
        # Execute the systemctl command via SSH on the remote node
        STATUS=$(ssh -o ConnectTimeout=10 "$NODE" "systemctl is-active $SERVICE" 2>/dev/null)

        if [[ "$STATUS" != "active" ]]; then
            MESSAGE="Service $SERVICE is not running on $NODE (status: $STATUS)"
            echo "$MESSAGE" | mail -s "$EMAIL_SUBJECT" -r "$EMAIL_FROM" "$EMAIL_TO"
        fi
    done
done
