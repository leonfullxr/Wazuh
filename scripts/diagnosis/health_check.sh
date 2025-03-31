#!/bin/bash
# Wazuh Comprehensive Healthcheck Script with Logging

# Prompt for Wazuh API credentials and connection details.
read -p "Enter Wazuh API User (default: wazuh): " WAZUH_API_USER
read -s -p "Enter Wazuh API Password (default: wazuh): " WAZUH_API_PASSWORD
echo ""
read -p "Enter Wazuh Host (default: localhost): " input_host
WAZUH_HOST=${input_host:-localhost}
read -p "Enter Wazuh Port (default: 55000): " input_port
WAZUH_PORT=${input_port:-55000}

# Create healthcheck directory and initialize the commands log file.
mkdir -p healthcheck
OUTPUT_FILE="healthcheck/commands"
echo "Wazuh Healthcheck Log - $(date)" > "$OUTPUT_FILE"
echo "------------------------------------------------------" >> "$OUTPUT_FILE"

# Redirect all further output to both the terminal and the log file.
exec > >(tee -a "$OUTPUT_FILE") 2>&1

echo "=== Authenticating to Wazuh API ==="
TOKEN=$(curl -s -u "$WAZUH_API_USER:$WAZUH_API_PASSWORD" -k -X POST "https://$WAZUH_HOST:$WAZUH_PORT/security/user/authenticate?raw=true")
if [ -z "$TOKEN" ]; then
  echo "Error: Unable to obtain API token. Please check your credentials."
  exit 1
fi
echo "API token obtained: $TOKEN"

echo -e "\n=== Wazuh Version Check via API ==="
curl -s -k -X GET "https://$WAZUH_HOST:$WAZUH_PORT/manager/version/check?pretty=true" -H "Authorization: Bearer $TOKEN"
echo ""

echo -e "\n=== Wazuh Agent Status Check via API ==="
curl -s -k -X GET "https://$WAZUH_HOST:$WAZUH_PORT/agents/summary/status?pretty=true" -H "Authorization: Bearer $TOKEN"
echo ""

echo -e "\n=== Hardware Information ==="
echo "CPU Information:"
lscpu

echo -e "\nRAM Information:"
free -h

echo -e "\nDisk Usage:"
df -h

echo -e "\nOS Release Info:"
cat /etc/*release*

echo -e "\n=== Wazuh Manager Status and Version ==="
echo "Wazuh Manager Service Status:"
systemctl status wazuh-manager -l

echo -e "\nWazuh Version Information:"
# For Wazuh < 4.2 use /etc/ossec-init.conf; for Wazuh >= 4.2 use /var/ossec/bin/wazuh-control info.
if [ -f /etc/ossec-init.conf ]; then
  echo "Detected Wazuh version < 4.2:"
  cat /etc/ossec-init.conf
else
  echo "Detected Wazuh version >= 4.2:"
  /var/ossec/bin/wazuh-control info
fi

echo -e "\n=== Wazuh Alerts and Cold Storage Retention Policy ==="
echo "Empty alert files (if any):"
find /var/ossec/logs/alerts/ -type f -empty

echo -e "\nSize of alerts folder:"
du -h /var/ossec/logs/alerts/

echo -e "\nSize of archives folder:"
du -h /var/ossec/logs/archives/

echo -e "\nCurrent crontab entries:"
crontab -l

echo -e "\nExample cronjob entries for deleting files older than 365 days:"
echo "0 0 * * * find /var/ossec/logs/alerts/ -type f -mtime +365 -exec rm -f {} ;"
echo "0 0 * * * find /var/ossec/logs/archives/ -type f -mtime +365 -exec rm -f {} ;"

echo -e "\n=== Filebeat Status ==="
echo "Testing Filebeat output:"
filebeat test output

echo -e "\nFilebeat service status:"
systemctl status filebeat

echo -e "\nFilebeat configuration:"
cat /etc/filebeat/filebeat.yml

echo -e "\n=== Agents Status ==="
echo "General Agent Count:"
echo "Cluster:"
/var/ossec/bin/cluster_control -a | wc -l
echo "Single Node:"
/var/ossec/bin/agent_control -ls | wc -l

echo -e "\nActive Agents Count:"
echo "Cluster:"
/var/ossec/bin/cluster_control -a | grep -i active | wc -l
echo "Single Node:"
/var/ossec/bin/agent_control -ls | grep -i active | wc -l

echo -e "\nDisconnected Agents Count:"
echo "Cluster:"
/var/ossec/bin/cluster_control -a | grep -i disconnected | wc -l
echo "Single Node:"
/var/ossec/bin/agent_control -ls | grep -i disconnected | wc -l

echo -e "\nNever Connected Agents Count:"
echo "Cluster:"
/var/ossec/bin/cluster_control -a | grep -i never_connected | wc -l
echo "Single Node:"
/var/ossec/bin/agent_control -ls | grep -i never_connected | wc -l

echo -e "\nPending Agents Count:"
echo "Cluster:"
/var/ossec/bin/cluster_control -a | grep -i pending | wc -l
echo "Single Node:"
/var/ossec/bin/agent_control -ls | grep -i pending | wc -l

echo -e "\n=== Check Complete ==="
