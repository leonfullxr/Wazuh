#!/bin/bash
set -e

print_help() {
  cat <<EOF
Wazuh Diagnosis Script

This script collects diagnostic information from a Wazuh environment, including:
  - Manager API details (version, configuration, health, logs, etc.)
  - Indexer API details (cluster health, indices, settings, etc.)
  - Cluster node information via cluster_control
  - Agent status and system hardware information

Usage:
  bash diagnosis.sh [--healthcheck] [--help]

Options:
  --healthcheck    Run a limited upgrade readiness check. This mode verifies:
                     * Wazuh version (must be >= 4.5.0)
                     * Disk usage on / (must be below 85%)
                     * Indexer cluster health (must be green)
                     * That both Manager and Indexer APIs return HTTP 200.
                   If any of these checks fail, the environment is deemed not ready for upgrade.

  --help           Display this help message.

If no option is provided, the script runs the full diagnosis and outputs detailed results.
EOF
}

if [ "$1" = "--help" ]; then
  print_help
  exit 0
fi

# === Global Variables ===
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
OUTPUT_PATH="/tmp/wazuh_diagnostic_reports"
MANAGER_OUTPUT="${OUTPUT_PATH}/manager"
INDEXER_OUTPUT="${OUTPUT_PATH}/indexer"
CLUSTER_OUTPUT="${OUTPUT_PATH}/cluster"
AGENTS_OUTPUT="${OUTPUT_PATH}/agents"

WAZUH_PATH="/var/ossec"
LOGS_PATH="${WAZUH_PATH}/logs"
STATE_FILES_PATH="${WAZUH_PATH}/var/run"
SHARED_PATH="${WAZUH_PATH}/etc/shared"
MULTIGROUPS_PATH="${WAZUH_PATH}/var/multigroups"

CLUSTER_ENABLED=false

# https://gist.github.com/JBlond/2fea43a3049b38287e5e9cefc87b2124
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'  # No Color

# Manager API defaults
WAZUH_API_USER=wazuh
WAZUH_API_PASSWORD=wazuh
WAZUH_HOST=localhost
WAZUH_PORT=55000

# Indexer API defaults
INDEXER_API_USER=admin
INDEXER_API_PASSWORD=admin
INDEXER_HOST=localhost
INDEXER_PORT=9200

# === Check Functions ===
# --- Check Root User ---
if [ "$(id -u)" -ne 0 ]; then
  echo "Please run this script as root"
  exit 1
fi

# --- Check Cluster Enabled ---
check_cluster_enabled() {
  local cluster_disabled

  cluster_disabled=$(sed -n '/<cluster>/,/<\/cluster>/p' /var/ossec/etc/ossec.conf | sed -n 's/.*<disabled>\(.*\)<\/disabled>.*/\1/p' | head -n 1)
  if [ "$cluster_disabled" = "no" ]; then
    CLUSTER_ENABLED=true
  else
    CLUSTER_ENABLED=false
  fi
  echo "Cluster active: $CLUSTER_ENABLED"
}
check_cluster_enabled

# --- Check Server IP Address (for Manager) ---
check_server_ip_addr() {
  # Try to capture a static (forever) IP from all non-loopback interfaces
  local ip_list selected_ip
  ip_list=$(ip -o addr show scope global | awk '/inet / {print $4, $NF}' | grep 'forever' | awk '{print $1}' | cut -d/ -f1)

  if [ -n "$ip_list" ]; then
    # If more than one static IP is found, select the first one
    selected_ip=$(echo "$ip_list" | head -n1)
  else
    # Fallback: use the default outbound IP (this might be dynamic)
    selected_ip=$(ip route get 8.8.8.8 | awk -F"src " 'NR==1{split($2,a," "); print a[1]}')
  fi
  WAZUH_HOST=$selected_ip
  echo "Wazuh Manager IP: $WAZUH_HOST"
}
check_server_ip_addr

# Create output directories
mkdir -p "$MANAGER_OUTPUT" "$INDEXER_OUTPUT" "$CLUSTER_OUTPUT" "$AGENTS_OUTPUT" "$OUTPUT_PATH"

# Log file
LOG_FILE="${OUTPUT_PATH}/report.log"

# Global flag for stopping background tasks
STOP_FLAG=0

# Global API Tokens (to be set after authentication)
TOKEN=""
INDEXER_TOKEN=""

# === Prompt for API Credentials ===
# Manager API Credentials
read -p "Enter Wazuh API User (default: $WAZUH_API_USER): " input_user
WAZUH_API_USER=${input_user:-$WAZUH_API_USER}
read -p "Enter Wazuh API Password (default: $WAZUH_API_PASSWORD): " input_password
WAZUH_API_PASSWORD=${input_password:-$WAZUH_API_PASSWORD}
read -p "Enter Wazuh Host (default: $WAZUH_HOST): " input_host
WAZUH_HOST=${input_host:-$WAZUH_HOST}
read -p "Enter Wazuh Port (default: $WAZUH_PORT): " input_port
WAZUH_PORT=${input_port:-$WAZUH_PORT}

# Indexer API Credentials
read -p "Enter Indexer API User (default: $INDEXER_API_USER): " input_indexer_user
INDEXER_API_USER=${input_indexer_user:-$INDEXER_API_USER}
read -s -p "Enter Indexer API Password (default: $INDEXER_API_PASSWORD): " input_indexer_password
echo ""
INDEXER_API_PASSWORD=${input_indexer_password:-$INDEXER_API_PASSWORD}
read -p "Enter Indexer Host (default: $WAZUH_HOST): " input_indexer_host
INDEXER_HOST=${input_indexer_host:-$WAZUH_HOST}
read -p "Enter Indexer Port (default: $INDEXER_PORT): " input_indexer_port
INDEXER_PORT=${input_indexer_port:-$INDEXER_PORT}

# === Logging Functions ===
log_info() {
  echo "$(date '+%Y/%m/%d %H:%M:%S') INFO: $1" | tee -a "$LOG_FILE"
}

log_warning() {
  echo "$(date '+%Y/%m/%d %H:%M:%S') WARNING: $1" | tee -a "$LOG_FILE"
}

log_error() {
  echo "$(date '+%Y/%m/%d %H:%M:%S') ERROR: $1" | tee -a "$LOG_FILE" >&2
}

# === Utility Functions ===
current_timestamp() {
  date "+%Y-%m-%d %H:%M:%S"
}

compare_versions() {
  # Returns 0 if $1 < $2, 1 otherwise.
  if [ "$(printf '%s\n' "$1" "$2" | sort -V | head -n1)" = "$1" ] && [ "$1" != "$2" ]; then
    return 0
  else
    return 1
  fi
}

# === Write Output Functions for Each Directory ===
write_output_manager() {
  local filename="$1"
  local content="$2"
  printf "%s" "$content" > "${MANAGER_OUTPUT}/${filename}"
  log_info "Wrote manager output: ${filename}"
}

write_output_indexer() {
  local filename="$1"
  local content="$2"
  echo -e "$content" > "${INDEXER_OUTPUT}/${filename}"
  log_info "Wrote indexer output: ${filename}"
}

write_output_cluster() {
  local filename="$1"
  local content="$2"
  echo -e "$content" > "${CLUSTER_OUTPUT}/${filename}"
  log_info "Wrote cluster output: ${filename}"
}

write_output_agents() {
  local filename="$1"
  local content="$2"
  echo -e "$content" > "${AGENTS_OUTPUT}/${filename}"
  log_info "Wrote agents output: ${filename}"
}

write_output() {
  local filename="$1"
  local content="$2"
  if printf "%s" "$content" > "${OUTPUT_PATH}/${filename}"; then
    log_info "Successfully wrote content to ${filename}"
  else
    log_error "Error writing content to ${filename}"
  fi
}

# === API Authentication Function ===
authenticate_api() {
  log_info "=== Authenticating to Wazuh API ==="
  TOKEN=$(curl -s -u "$WAZUH_API_USER:$WAZUH_API_PASSWORD" -k -X POST "https://${WAZUH_HOST}:${WAZUH_PORT}/security/user/authenticate?raw=true")
  if [ -z "$TOKEN" ]; then
    echo "Error: Unable to obtain API token. Please check your credentials."
    exit 1
  fi
  echo "API token obtained: $TOKEN"
}

# === API Check Functions ===
wazuh_version_check() {
  log_info "Performing Wazuh Version Check via API"
  local version_output
  version_output=$(curl -k -X GET "https://${WAZUH_HOST}:${WAZUH_PORT}/manager/version/check?pretty=true" -H "Authorization: Bearer $TOKEN")
  write_output_manager "wazuh_version_check.json" "$version_output"
}

# Modified wazuh_agent_status_check function:
wazuh_agent_status_check() {
  log_info "Performing Wazuh Agent Status Check via API"
  local agent_status_output
  agent_status_output=$(curl -s -k -X GET "https://${WAZUH_HOST}:${WAZUH_PORT}/agents/summary/status?pretty=true" -H "Authorization: Bearer $TOKEN")
  write_output_manager "wazuh_agent_status_check.json" "$agent_status_output"
}

# === Cluster Function ===
# TODO: check API calls to every node in the cluster
get_cluster_healthcheck() {
  log_info "Obtaining cluster healthcheck via API"
  
  local api_config
  local healthcheck
  local local_config
  local status
  local nodes
  
  api_config=$(curl -s -k -X GET "https://${WAZUH_HOST}:${WAZUH_PORT}/cluster/api/config?pretty=true" -H "Authorization: Bearer $TOKEN")
  healthcheck=$(curl -s -k -X GET "https://${WAZUH_HOST}:${WAZUH_PORT}/cluster/healthcheck?pretty=true" -H "Authorization: Bearer $TOKEN")
  local_config=$(curl -s -k -X GET "https://${WAZUH_HOST}:${WAZUH_PORT}/cluster/local/config?pretty=true" -H "Authorization: Bearer $TOKEN")
  status=$(curl -s -k -X GET "https://${WAZUH_HOST}:${WAZUH_PORT}/cluster/status?pretty=true" -H "Authorization: Bearer $TOKEN")
  nodes=$(curl -s -k -X GET "https://${WAZUH_HOST}:${WAZUH_PORT}/cluster/nodes" -H "Authorization: Bearer $TOKEN")
  
  local combined_json="{"
  combined_json+="\"cluster_api_config\": $api_config, "
  combined_json+="\"cluster_healthcheck\": $healthcheck, "
  combined_json+="\"cluster_local_config\": $local_config, "
  combined_json+="\"cluster_status\": $status, "
  combined_json+="\"cluster_nodes\": $nodes"

  # --- Get per-node information (skip the master node) ---
  local node_checks="{"
  local first_node=1
  # Skip header line and loop through each node line from cluster_control -l
  while read -r node type version address; do
    if [ "$type" != "master" ]; then
      if [ $first_node -eq 0 ]; then
        node_checks+=", "
      fi
      first_node=0
      # For each node, perform API calls using the node name as the identifier:
      local node_status node_config node_logs node_daemons
      node_status=$(curl -s -k -X GET "https://${WAZUH_HOST}:${WAZUH_PORT}/cluster/${node}/status?pretty=true" -H "Authorization: Bearer $TOKEN")
      node_config=$(curl -s -k -X GET "https://${WAZUH_HOST}:${WAZUH_PORT}/cluster/${node}/configuration?pretty=true" -H "Authorization: Bearer $TOKEN")
      node_logs=$(curl -s -k -X GET "https://${WAZUH_HOST}:${WAZUH_PORT}/cluster/${node}/logs/summary?pretty=true" -H "Authorization: Bearer $TOKEN")
      node_daemons=$(curl -s -k -X GET "https://${WAZUH_HOST}:${WAZUH_PORT}/cluster/${node}/daemons/stats?daemons_list=wazuh-analysisd,wazuh-remoted&pretty=true" -H "Authorization: Bearer $TOKEN")
      
      node_checks+="\"$node\": {"
      node_checks+="\"status\": $node_status, "
      node_checks+="\"configuration\": $node_config, "
      node_checks+="\"logs_summary\": $node_logs, "
      node_checks+="\"daemons_stats\": $node_daemons"
      node_checks+="}"
    fi
  done < <(/var/ossec/bin/cluster_control -l | tail -n +2)
  node_checks+="}"

  combined_json+=", \"node_checks\": $node_checks"
  combined_json+="}"
  
  write_output_cluster "get_cluster_healthcheck.json" "$combined_json"
}

# === Indexer Function ===
get_indexer_healthcheck() {
  log_info "Obtaining Indexer healthcheck via API"
  local indices
  local cluster_health
  local allocation_explain
  local cluster_settings
  local nodes_stats
  local nodes_info
  local nodes_allocation
  local health_status

  indices=$(curl -s -k -u $INDEXER_API_USER:$INDEXER_API_PASSWORD "https://${INDEXER_HOST}:${INDEXER_PORT}/_cat/indices?format=json")
  cluster_health=$(curl -s -k -u $INDEXER_API_USER:$INDEXER_API_PASSWORD "https://${INDEXER_HOST}:${INDEXER_PORT}/_cluster/health?pretty=true")
  
  # Extract the "status" value from the cluster health JSON
  health_status=$(echo "$cluster_health" | grep -o '"status" *: *"[^"]*"' | sed 's/.*: *"//; s/"//')
  if [ "$health_status" = "yellow" ] || [ "$health_status" = "red" ]; then
    allocation_explain=$(curl -s -k -u $INDEXER_API_USER:$INDEXER_API_PASSWORD "https://${INDEXER_HOST}:${INDEXER_PORT}/_cluster/allocation/explain?pretty=true")
  else
    allocation_explain="{}"
  fi

  cluster_settings=$(curl -s -k -u $INDEXER_API_USER:$INDEXER_API_PASSWORD "https://${INDEXER_HOST}:${INDEXER_PORT}/_cluster/settings?pretty=true")
  nodes_stats=$(curl -s -k -u $INDEXER_API_USER:$INDEXER_API_PASSWORD "https://${INDEXER_HOST}:${INDEXER_PORT}/_cluster/stats?pretty=true")
  nodes_allocation=$(curl -s -k -u $INDEXER_API_USER:$INDEXER_API_PASSWORD "https://${INDEXER_HOST}:${INDEXER_PORT}/_cat/allocation/?format=json&v")
  nodes_info=$(curl -s -k -u $INDEXER_API_USER:$INDEXER_API_PASSWORD "https://${INDEXER_HOST}:${INDEXER_PORT}/_cat/nodes?format=json&v")


  local combined_json="{"
  combined_json+="\"indices\": $indices, "
  combined_json+="\"cluster_health\": $cluster_health, "
  combined_json+="\"allocation_explain\": $allocation_explain, "
  combined_json+="\"cluster_settings\": $cluster_settings, "
  combined_json+="\"nodes_stats\": $nodes_stats, "
  combined_json+="\"nodes_allocation\": $nodes_allocation, "
  combined_json+="\"nodes_info\": $nodes_info"
  combined_json+="}"
  
  write_output_indexer "get_indexer_healthcheck.json" "$combined_json"
}

# === get_manager_configuration Function ===
get_manager_configuration() {
  local manager_configuration
  manager_configuration=$(curl -s -k -X GET "https://${WAZUH_HOST}:${WAZUH_PORT}/manager/configuration?pretty=true" -H "Authorization: Bearer $TOKEN")
  write_output_manager "get_manager_configuration.json" "$manager_configuration"
}

# === get_manager_healthcheck Function ===
get_manager_healthcheck() {
  log_info "Obtaining manager healthcheck via API"
  local manager_info
  local manager_status
  local manager_api_config
  local manager_version_check

  manager_info=$(curl -s -k -X GET "https://${WAZUH_HOST}:${WAZUH_PORT}/manager/info?pretty=true" -H "Authorization: Bearer $TOKEN")
  manager_status=$(curl -s -k -X GET "https://${WAZUH_HOST}:${WAZUH_PORT}/manager/status?pretty=true" -H "Authorization: Bearer $TOKEN")
  manager_api_config=$(curl -s -k -X GET "https://${WAZUH_HOST}:${WAZUH_PORT}/manager/api/config?pretty=true" -H "Authorization: Bearer $TOKEN")
  manager_version_check=$(curl -s -k -X GET "https://${WAZUH_HOST}:${WAZUH_PORT}/manager/version/check?pretty=true" -H "Authorization: Bearer $TOKEN")

  local combined_json="{"
  combined_json+="\"manager_info\": $manager_info, "
  combined_json+="\"manager_status\": $manager_status, "
  combined_json+="\"manager_api_config\": $manager_api_config, "
  combined_json+="\"manager_version_check\": $manager_version_check"
  combined_json+="}"

  write_output_manager "get_manager_healthcheck.json" "$combined_json"
}

get_agent_info() {
  log_info "Obtaining agent information via API"

  local agents_summary

  agents_summary=$(curl -s -k -X GET "https://${WAZUH_HOST}:${WAZUH_PORT}/agents/summary/status?pretty=true" -H "Authorization: Bearer $TOKEN")

  local combined_json="{"
  combined_json+="\"agents_summary\": $agents_summary"
  combined_json+="}"

  write_output_agents "get_agent_info.json" "$combined_json"
}

# === File Writing Functions ===
# === Hardware & Manager Status Functions (Stored in Manager Output) ===
get_hardware_info() {
  log_info "Retrieving hardware information..."
  {
    echo -e "\n=== Hardware Information ==="
    echo "CPU Information:"; lscpu
    echo -e "\nRAM Information:"; free -h
    echo -e "\nDisk Usage:"; df -h
    echo -e "\nOS Release Info:"; cat /etc/*release*
  } > "${MANAGER_OUTPUT}/hardware_info.txt"
  log_info "Parsed hardware information to manager/hardware_info.txt"
}

wazuh_manager_status_info() {
  log_info "Retrieving Wazuh Manager status and version information..."
  {
    echo -e "\n=== Wazuh Manager Status and Version ==="
    echo "Wazuh Manager Service Status:"; systemctl status wazuh-manager -l
    echo -e "\n=== Wazuh Alerts File Lsof ==="
    echo "Alerts file lsof:"; lsof /var/ossec/logs/alerts/alerts.json
    echo -e "\n=== Wazuh Alerts and Cold Storage Retention Policy ==="
    echo "Empty alert files (if any):"; find /var/ossec/logs/alerts/ -type f -empty
    echo -e "\nSize of alerts folder:"; du -h /var/ossec/logs/alerts/
    echo -e "\nSize of archives folder:"; du -h /var/ossec/logs/archives/
    echo -e "\nCurrent crontab entries:"; crontab -l 2>/dev/null || echo "No crontab for root"
    echo -e "\n=== Filebeat Status ==="
    echo "Testing Filebeat output:"; filebeat test output
    echo -e "\nFilebeat service status:"; systemctl status filebeat
    echo -e "\nFilebeat configuration:"; cat /etc/filebeat/filebeat.yml
    echo -e "\n=== Agents Status ==="
    echo "General Agent Count:"
    if [ "$CLUSTER_ENABLED" = true ]; then
      echo "Cluster:"; /var/ossec/bin/cluster_control -a | wc -l
    else
      echo "Single Node:"; /var/ossec/bin/agent_control -ls | wc -l
    fi
    echo -e "\nActive Agents Count:"
    if [ "$CLUSTER_ENABLED" = true ]; then
      echo "Cluster:"; /var/ossec/bin/cluster_control -a | grep -i active | wc -l
    else
      echo "Single Node:"; /var/ossec/bin/agent_control -ls | grep -i active | wc -l
    fi
    echo -e "\nDisconnected Agents Count:"
    if [ "$CLUSTER_ENABLED" = true ]; then
      echo "Cluster:"; /var/ossec/bin/cluster_control -a | grep -i disconnected | wc -l
    else
      echo "Single Node:"; /var/ossec/bin/agent_control -ls | grep -i disconnected | wc -l
    fi
    echo -e "\nNever Connected Agents Count:"
    if [ "$CLUSTER_ENABLED" = true ]; then
      echo "Cluster:"; /var/ossec/bin/cluster_control -a | grep -i never_connected | wc -l
    else
      echo "Single Node:"; /var/ossec/bin/agent_control -ls | grep -i never_connected | wc -l
    fi
    echo -e "\nPending Agents Count:"
    if [ "$CLUSTER_ENABLED" = true ]; then
      echo "Cluster:"; /var/ossec/bin/cluster_control -a | grep -i pending | wc -l
    else
      echo "Single Node:"; /var/ossec/bin/agent_control -ls | grep -i pending | wc -l
    fi
    echo -e "\n=== Check Complete ==="
  } > "${MANAGER_OUTPUT}/wazuh_manager_status.txt"
  log_info "Parsed Wazuh Manager status to manager/wazuh_manager_status.txt"
}

# === File Retrieval Functions (remain in base OUTPUT_PATH) ===
# TODO: ask if needed, or add more files
get_wazuh_logs() {
  log_info "Retrieving Wazuh logs..."
  for log_file in ossec.log api.log cluster.log; do
    if [ -f "${LOGS_PATH}/${log_file}" ]; then
      cp "${LOGS_PATH}/${log_file}" "$OUTPUT_PATH" && log_info "Successfully copied ${log_file}" || log_error "Error copying ${log_file}"
    else
      log_error "Log file ${log_file} not found in ${LOGS_PATH}"
    fi
  done
}

get_wazuh_state_files() {
  log_info "Retrieving Wazuh state files..."
  for state_file in wazuh-analysisd.state wazuh-remoted.state; do
    if [ -f "${STATE_FILES_PATH}/${state_file}" ]; then
      cp "${STATE_FILES_PATH}/${state_file}" "$OUTPUT_PATH" && log_info "Successfully copied ${state_file}" || log_error "Error copying ${state_file}"
    else
      log_error "State file ${state_file} not found in ${STATE_FILES_PATH}"
    fi
  done
}

get_wazuh_groups_info() {
  log_info "Retrieving Wazuh groups information..."
  local json_output="{\"shared\": {"
  local first=1
  while IFS= read -r -d '' file; do
    rel_path="${file#$SHARED_PATH/}"
    size=$(stat -c%s "$file" 2>/dev/null)
    if [ $first -eq 1 ]; then first=0; else json_output+=", "; fi
    json_output+="\"${rel_path}\": ${size}"
  done < <(find "$SHARED_PATH" -type f -print0)
  json_output+="}, \"multigroups\": {"
  first=1
  while IFS= read -r -d '' file; do
    rel_path="${file#$MULTIGROUPS_PATH/}"
    size=$(stat -c%s "$file" 2>/dev/null)
    if [ $first -eq 1 ]; then first=0; else json_output+=", "; fi
    json_output+="\"${rel_path}\": ${size}"
  done < <(find "$MULTIGROUPS_PATH" -type f -print0)
  json_output+="}}"
  write_output "groups_info.json" "$json_output"
  log_info "Parsed groups information to JSON file"
}

# --- Healthcheck Mode ---
healthcheck_mode() {
  local fail=0
  local messages=""

  # Authenticate Manager and Indexer APIs
  authenticate_api

  # 1. Check version: if version is prior to 4.5.0 -> fail
  local version_output current_version
  version_output=$(curl -s -k -X GET "https://${WAZUH_HOST}:${WAZUH_PORT}/?pretty=true" -H "Authorization: Bearer $TOKEN")
  current_version=$(echo "$version_output" | grep -o '"api_version" *: *"[^"]*"' | sed 's/.*: *"//; s/"//')
  current_version=${current_version#v}  # Remove leading "v"
  if compare_versions "$current_version" "4.5.0"; then
    messages+="${RED}Wazuh version ($current_version) is too old. Upgrade requires at least version 4.5.0.${NC}\n"
    fail=1
  fi

  # 2. Check disk space: if / is >85% used -> fail
  # Manager disk usage
  local disk_usage
  disk_usage=$(df / | tail -n1 | awk '{print $5}' | tr -d '%')
  if [ "$disk_usage" -gt 85 ]; then
    messages+="${RED}Disk usage on / is ${disk_usage}%, which exceeds the 85% threshold.${NC}\n"
    fail=1
  fi
  # Check Indexer disk usage: iterate over all nodes from the allocation API
  local allocation_output over_threshold
  allocation_output=$(curl -s -k -u $INDEXER_API_USER:$INDEXER_API_PASSWORD "https://${INDEXER_HOST}:${INDEXER_PORT}/_cat/allocation/?format=json&v")
  # Use jq to build an array of disk.percent (converting to number), then count any value >=85
  over_threshold=$(echo "$allocation_output" | jq '[.[] | select(.["disk.percent"] != null) | (.["disk.percent"] | tonumber)] | map(select(. >= 85)) | length')
  if [ "$over_threshold" -gt 0 ]; then
    messages+="${RED}One or more Indexer nodes have disk usage >= 85% (via allocation API).${NC}\n"
    fail=1
  fi

  # 3. Check Indexer health: if _cluster/health status is yellow or red -> fail
  local indexer_health idx_status
  indexer_health=$(curl -s -k -u $INDEXER_API_USER:$INDEXER_API_PASSWORD "https://${INDEXER_HOST}:${INDEXER_PORT}/_cluster/health?pretty=true")
  idx_status=$(echo "$indexer_health" | grep -o '"status" *: *"[^"]*"' | sed 's/.*: *"//; s/"//')
  if [ "$idx_status" = "yellow" ] || [ "$idx_status" = "red" ]; then
    messages+="${RED}Indexer cluster health is $idx_status.${NC}\n"
    fail=1
  fi

  # 4. Check services: verify that the Manager and Indexer APIs respond with 200 OK.
  local mgr_http_code idx_http_code
  mgr_http_code=$(curl -s -o /dev/null -w "%{http_code}" -k -X GET "https://${WAZUH_HOST}:${WAZUH_PORT}/?pretty=true" -H "Authorization: Bearer $TOKEN")
  if [ "$mgr_http_code" -ne 200 ]; then
    messages+="${RED}Wazuh Manager API did not return 200 OK (got $mgr_http_code).${NC}\n"
    fail=1
  fi

  idx_http_code=$(curl -s -o /dev/null -w "%{http_code}" -k -u $INDEXER_API_USER:$INDEXER_API_PASSWORD "https://${INDEXER_HOST}:${INDEXER_PORT}/_cluster/health?pretty=true")
  if [ "$idx_http_code" -ne 200 ]; then
    messages+="${RED}Indexer API did not return 200 OK (got $idx_http_code).${NC}\n"
    fail=1
  fi

  if [ "$fail" -eq 1 ]; then
    echo -e "${RED}Environment is not ready for upgrade:${NC}"
    echo -e "$messages"
  else
    echo -e "${GREEN}Environment ready for upgrade${NC}"
  fi
}

# === Signal Handling ===
force_thread_stop() {
  log_warning "Interrupt received. Exiting gracefully..."
  exit 0
}
trap force_thread_stop SIGINT

# === Compress Report Function ===
compress_report() {
  log_info "Compressing the report..."
  if command -v zip >/dev/null 2>&1; then
    local zip_file="/tmp/wazuh_diagnostic_report.zip"
    (cd "$OUTPUT_PATH" && zip -r "$zip_file" .) && log_info "Generated ZIP report in ${zip_file}" || log_error "Error generating ZIP report"
  else
    local tar_file="/tmp/wazuh_diagnostic_report.tar.gz"
    (cd "$OUTPUT_PATH" && tar -czf "$tar_file" .) && log_info "Generated TAR.GZ report in ${tar_file}" || log_error "Error generating TAR.GZ report"
  fi
  rm -rf "$OUTPUT_PATH"
}

# === Main Function ===
main() {
  if [ "$1" = "--healthcheck" ]; then
    echo -e "${YELLOW}Running healthcheck mode...${NC}"
    healthcheck_mode
    exit 0
  fi

  echo -e "${YELLOW}========================================${NC}"
  echo -e "${GREEN}Starting full diagnosis mode...${NC}"
  echo -e "${YELLOW}========================================${NC}"

  echo -e "${GREEN}-- Authenticating to Wazuh API --${NC}"
  authenticate_api

  echo -e "${GREEN}-- Running Manager API Checks --${NC}"
  echo -e "${YELLOW}   Performing Wazuh Version Check...${NC}"
  wazuh_version_check
  echo -e "${YELLOW}   Performing Wazuh Agent Status Check...${NC}"
  wazuh_agent_status_check
  echo -e "${YELLOW}   Retrieving Manager Configuration...${NC}"
  get_manager_configuration
  echo -e "${YELLOW}   Retrieving Manager Healthcheck...${NC}"
  get_manager_healthcheck

  echo -e "${GREEN}-- Retrieving Hardware Information and Manager Status --${NC}"
  get_hardware_info
  wazuh_manager_status_info

  echo -e "${GREEN}-- Running Cluster API Checks --${NC}"
  get_cluster_healthcheck

  echo -e "${GREEN}-- Running Indexer API Checks --${NC}"
  get_indexer_healthcheck

  echo -e "${GREEN}-- Retrieving Agent Information --${NC}"
  get_agent_info

  echo -e "${GREEN}-- Retrieving Additional Files (Logs, State Files, Groups) --${NC}"
  get_wazuh_logs
  get_wazuh_state_files
  get_wazuh_groups_info

  echo -e "${GREEN}-- Compressing the report into a ZIP file --${NC}"
  compress_report

  echo -e "${GREEN}Full diagnosis completed.${NC}"
}

# === Script Execution ===
main "$@"