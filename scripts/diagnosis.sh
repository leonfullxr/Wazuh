#!/bin/bash
set -e

# === Global Variables ===
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
OUTPUT_PATH="${SCRIPT_DIR}/wazuh_diagnostic_reports"
WAZUH_PATH="/var/ossec"
LOGS_PATH="${WAZUH_PATH}/logs"
STATE_FILES_PATH="${WAZUH_PATH}/var/run"
SHARED_PATH="${WAZUH_PATH}/etc/shared"
MULTIGROUPS_PATH="${WAZUH_PATH}/var/multigroups"
CLUSTER_ENABLED=false
WAZUH_API_USER=wazuh
WAZUH_API_PASSWORD=wazuh
WAZUH_HOST=localhost
WAZUH_PORT=55000

# TODO:
# Generar zip en /tpm
# Pedir credentiales para Indexer API, IP address, y puerto
# Sacar info de todos los nodos Wazuh server, configuracion y logs
# Sacar solamente summary de los agentes
# lsof /var/ossec/logs/alerts/alerts.json

# === Check Functions ===
# === Check Root User ===
if [ "$(id -u)" -ne 0 ]; then
  echo "Please run this script as root"
  exit 1
fi

# === Check Cluster Enabled ===
check_cluster_enabled() {
  local cluster_disabled

  cluster_disabled=$(sed -n '/<cluster>/,/<\/cluster>/p' /var/ossec/etc/ossec.conf | sed -n 's/.*<disabled>\(.*\)<\/disabled>.*/\1/p' | head -n 1)
  if [ "$cluster_disabled" = "no" ]; then
    CLUSTER_ENABLED=true
  else
    CLUSTER_ENABLED=false
  fi
}
check_cluster_enabled

# === Check Server IP Address ===
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
}
check_server_ip_addr

# Create output directory
mkdir -p "$OUTPUT_PATH"

# Log file
LOG_FILE="${OUTPUT_PATH}/report.log"

# Global flag for stopping background tasks
STOP_FLAG=0

# Global API Token (to be set after authentication)
TOKEN=""

# === Prompt for Wazuh API Credentials and Connection Details ===
read -p "Enter Wazuh API User (default: $WAZUH_API_USER): " input_user
WAZUH_API_USER=${input_user:-$WAZUH_API_USER}
read -p "Enter Wazuh API Password (default: $WAZUH_API_PASSWORD): " input_password
WAZUH_API_PASSWORD=${input_password:-$WAZUH_API_PASSWORD}
read -p "Enter Wazuh Host (default: $WAZUH_HOST): " input_host
WAZUH_HOST=${input_host:-$WAZUH_HOST}
read -p "Enter Wazuh Port (default: $WAZUH_PORT): " input_port
WAZUH_PORT=${input_port:-$WAZUH_PORT}

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
  version_output=$(curl -s -k -X GET "https://${WAZUH_HOST}:${WAZUH_PORT}/manager/version/check?pretty=true" -H "Authorization: Bearer $TOKEN")
  write_json_output "wazuh_version_check.json" "$version_output"
}

# Modified wazuh_agent_status_check function:
wazuh_agent_status_check() {
  log_info "Performing Wazuh Agent Status Check via API"
  local agent_status_output
  agent_status_output=$(curl -s -k -X GET "https://${WAZUH_HOST}:${WAZUH_PORT}/agents/summary/status?pretty=true" -H "Authorization: Bearer $TOKEN")
  write_json_output "wazuh_agent_status_check.json" "$agent_status_output"
}


# === Dummy Implementations of Wazuh Functions ===
# === get_cluster_healthcheck Function ===
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
  combined_json+="}"
  
  write_json_output "get_cluster_healthcheck.json" "$combined_json"
}

# === get_manager_configuration Function ===
get_manager_configuration() {
  local manager_configuration
  manager_configuration=$(curl -s -k -X GET "https://${WAZUH_HOST}:${WAZUH_PORT}/manager/configuration?pretty=true" -H "Authorization: Bearer $TOKEN")
  # TODO: Fix invalid escape sequences: double any backslash not followed by a valid JSON escape character
  local fixed_configuration
  fixed_configuration=$(echo "$manager_configuration" | sed -E 's/\\([^"\\/bfnrtu])/\\\\\1/g')
  write_json_output "get_manager_configuration.json" "$fixed_configuration"
}

# === get_manager_healthcheck Function ===
get_manager_healthcheck() {
  log_info "Obtaining manager healthcheck via API"

  local manager_info
  local manager_status
  local manager_api_config
  local manager_version_check

  # TODO: check for cluster healthcheck instead of the manager one
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

  write_json_output "get_manager_healthcheck.json" "$combined_json"
}

# TODO: ask for what API calls are needed
get_agent_info() {
  log_info "Obtaining agent information via API"

  local agents_active
  local agents_pending
  local agents_never_connected
  local agents_disconnected
  local agents_summary

  agents_active=$(curl -s -k -X GET "https://${WAZUH_HOST}:${WAZUH_PORT}/agents?status=active" -H "Authorization: Bearer $TOKEN")
  agents_pending=$(curl -s -k -X GET "https://${WAZUH_HOST}:${WAZUH_PORT}/agents?status=pending" -H "Authorization: Bearer $TOKEN")
  agents_never_connected=$(curl -s -k -X GET "https://${WAZUH_HOST}:${WAZUH_PORT}/agents?status=never_connected" -H "Authorization: Bearer $TOKEN")
  agents_disconnected=$(curl -s -k -X GET "https://${WAZUH_HOST}:${WAZUH_PORT}/agents?status=disconnected" -H "Authorization: Bearer $TOKEN")
  agents_summary=$(curl -s -k -X GET "https://${WAZUH_HOST}:${WAZUH_PORT}/agents/summary/status?pretty=true" -H "Authorization: Bearer $TOKEN")

  local combined_json="{"
  combined_json+="\"agents_active\": $agents_active, "
  combined_json+="\"agents_pending\": $agents_pending, "
  combined_json+="\"agents_never_connected\": $agents_never_connected, "
  combined_json+="\"agents_disconnected\": $agents_disconnected, "
  combined_json+="\"agents_summary\": $agents_summary"
  combined_json+="}"

  echo "get_agent_info.json" "$combined_json"
}

# === File Writing Functions ===
get_hardware_info() {
  log_info "Retrieving hardware information..."
  {
    echo -e "\n=== Hardware Information ==="
    echo "CPU Information:"
    lscpu

    echo -e "\nRAM Information:"
    free -h

    echo -e "\nDisk Usage:"
    df -h

    echo -e "\nOS Release Info:"
    cat /etc/*release*
  } > "${OUTPUT_PATH}/hardware_info.txt"
  log_info "Parsed hardware information to text file"
}

wazuh_manager_status_info() {
  log_info "Retrieving Wazuh Manager status and version information..."
  {
    echo -e "\n=== Wazuh Manager Status and Version ==="
    echo "Wazuh Manager Service Status:"
    systemctl status wazuh-manager -l

    echo -e "\n=== Wazuh Alerts and Cold Storage Retention Policy ==="
    echo "Empty alert files (if any):"
    find /var/ossec/logs/alerts/ -type f -empty

    echo -e "\nSize of alerts folder:"
    du -h /var/ossec/logs/alerts/

    echo -e "\nSize of archives folder:"
    du -h /var/ossec/logs/archives/

    echo -e "\n=== Filebeat Status ==="
    echo "Testing Filebeat output:"
    filebeat test output

    echo -e "\nFilebeat service status:"
    systemctl status filebeat

    echo -e "\nFilebeat configuration:"
    cat /etc/filebeat/filebeat.yml

    echo -e "\n=== Agents Status ==="
    echo "General Agent Count:"
    # Check if the cluster is enabled
    if [ "$CLUSTER_ENABLED" = true ]; then
      echo "Cluster:"
      /var/ossec/bin/cluster_control -a | wc -l
    else
      echo "Single Node:"
      /var/ossec/bin/agent_control -ls | wc -l
    fi

    echo -e "\nActive Agents Count:"
    if [ "$CLUSTER_ENABLED" = true ]; then
      echo "Cluster:"
      /var/ossec/bin/cluster_control -a | grep -i active | wc -l
    else
      echo "Single Node:"
      /var/ossec/bin/agent_control -ls | grep -i active | wc -l
    fi

    echo -e "\nDisconnected Agents Count:"
    if [ "$CLUSTER_ENABLED" = true ]; then
      echo "Cluster:"
      /var/ossec/bin/cluster_control -a | grep -i disconnected | wc -l
    else
      echo "Single Node:"
      /var/ossec/bin/agent_control -ls | grep -i disconnected | wc -l
    fi

    echo -e "\nNever Connected Agents Count:"
    if [ "$CLUSTER_ENABLED" = true ]; then
      echo "Cluster:"
      /var/ossec/bin/cluster_control -a | grep -i never_connected | wc -l
    else
      echo "Single Node:"
      /var/ossec/bin/agent_control -ls | grep -i never_connected | wc -l
    fi

    echo -e "\nPending Agents Count:"
    if [ "$CLUSTER_ENABLED" = true ]; then
      echo "Cluster:"
      /var/ossec/bin/cluster_control -a | grep -i pending | wc -l
    else
      echo "Single Node:"
      /var/ossec/bin/agent_control -ls | grep -i pending | wc -l
    fi

    echo -e "\n=== Check Complete ==="
  } > "${OUTPUT_PATH}/wazuh_manager_status.txt"
  log_info "Parsed Wazuh Manager status and version information to text file"
}

write_output() {
  local filename="$1"
  local content="$2"
  if echo -e "$content" > "${OUTPUT_PATH}/${filename}"; then
    log_info "Successfully wrote content to ${filename}"
  else
    log_error "Error writing content to ${filename}"
  fi
}

write_json_output() {
  local filename="$1"
  local content="$2"
  write_output "$filename" "$content"
}

# === Data Retrieval Functions ===
get_wazuh_logs() {
  log_info "Retrieving Wazuh logs..."
  for log_file in ossec.log api.log cluster.log; do
    if [ -f "${LOGS_PATH}/${log_file}" ]; then
      cp "${LOGS_PATH}/${log_file}" "$OUTPUT_PATH" && log_info "Successfully copied ${log_file}" \
        || log_error "Error copying ${log_file}"
    else
      log_error "Log file ${log_file} not found in ${LOGS_PATH}"
    fi
  done
}

get_wazuh_state_files() {
  log_info "Retrieving Wazuh state files..."
  for state_file in wazuh-analysisd.state wazuh-remoted.state; do
    if [ -f "${STATE_FILES_PATH}/${state_file}" ]; then
      cp "${STATE_FILES_PATH}/${state_file}" "$OUTPUT_PATH" && log_info "Successfully copied ${state_file}" \
        || log_error "Error copying ${state_file}"
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
    if [ $first -eq 1 ]; then
      first=0
    else
      json_output+=","
    fi
    json_output+="\"${rel_path}\": ${size}"
  done < <(find "$SHARED_PATH" -type f -print0)
  json_output+="},"
  json_output+="\"multigroups\": {"
  first=1
  while IFS= read -r -d '' file; do
    rel_path="${file#$MULTIGROUPS_PATH/}"
    size=$(stat -c%s "$file" 2>/dev/null)
    if [ $first -eq 1 ]; then
      first=0
    else
      json_output+=","
    fi
    json_output+="\"${rel_path}\": ${size}"
  done < <(find "$MULTIGROUPS_PATH" -type f -print0)
  json_output+="}}"
  write_json_output "groups_info.json" "$json_output"
  log_info "Parsed groups information to JSON file"
}

# === Signal Handling ===
force_thread_stop() {
  log_warning "Interrupt received. Exiting gracefully..."
  exit 0
}
trap force_thread_stop SIGINT

# === Compress Report Function ===
compress_report() {
  log_info "Generating ZIP file with the report..."
  local zip_file="${SCRIPT_DIR}/wazuh_diagnostic_report.zip"
  (cd "$OUTPUT_PATH" && zip -r "$zip_file" .) \
    && log_info "Generated ZIP report in ${zip_file}" \
    || log_error "Error generating ZIP report"
  rm -rf "$OUTPUT_PATH"
}

# === Main Function ===
main() {
  # Authenticate and get API token
  authenticate_api

  # API Checks
  wazuh_version_check
  wazuh_agent_status_check
  get_manager_configuration

  # Healthcheck Functions
  get_cluster_healthcheck
  get_manager_healthcheck

  # Agent Information
  get_agent_info

  # File Retrieval
  get_wazuh_logs
  get_wazuh_state_files
  wazuh_manager_status_info
  get_hardware_info
  get_wazuh_groups_info

  # Compress the report
  compress_report
}

# === Script Execution ===
main