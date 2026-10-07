#!/bin/bash
# wazuh_config_backup.sh - Point-in-time tar backup of central component configuration.
# Distilled from a production support engagement. See README.md for design notes
# and deliberate simplifications.
#
# Usage:
#   REMOTE_HOST=192.0.2.10 REMOTE_USER=backup REMOTE_PASS='secret' ./wazuh_config_backup.sh
#   ./wazuh_config_backup.sh --remote-host 192.0.2.10 --remote-user backup --selftest
#
# Cron example (daily 01:00):
#   0 1 * * * /opt/wazuh-backup/wazuh_config_backup.sh >/dev/null 2>&1

set -u

REMOTE_USER="${REMOTE_USER:-}"
REMOTE_HOST="${REMOTE_HOST:-}"
REMOTE_PASS="${REMOTE_PASS:-}"
REMOTE_BACKUP_PATH="${REMOTE_BACKUP_PATH:-/backup/wazuh-backup}"
LOCAL_BACKUP_PATH="${LOCAL_BACKUP_PATH:-/tmp/backups}"
RETENTION_COUNT="${RETENTION_COUNT:-3}"
EMAIL_TO="${EMAIL_TO:-backup@example.com}"
EMAIL_FROM="${EMAIL_FROM:-wazuh@example.com}"
AUTO_RESTORE="${AUTO_RESTORE:-no}"

HTML_REPORT="/tmp/wazuh_backup_report.html"
LOG_FILE="/tmp/wazuh_config_backup.log"
LOCK_FILE="/tmp/wazuh_backup.lock"

SENDMAIL_BIN="/sbin/sendmail"
SSHPASS_BIN="/usr/bin/sshpass"
TAR_BIN="/bin/tar"
DU_BIN="/usr/bin/du"
DF_BIN="/usr/bin/df"
AWK_BIN="/usr/bin/awk"
TEE_BIN="/usr/bin/tee"

FINAL_STATUS="SUCCESS"
FAILURE_CAUSE="None"
REMOTE_SEND_STATUS="NOT RUN"
RESTORE_STATUS="NOT RUN"
MANAGER_DOWNTIME="0"
MISSING_FILES=""
RETENTION_DELETED="No files were deleted due to retention policy."

usage() {
    grep "^#" "$0" | sed 's/^# //;s/^#//'
    exit 0
}

# Minimal item lists. Extend with site-specific custom paths.
# Full per-component reference lives in ../../upgrading/pre-upgrade-checklist.md
MANAGER_ITEMS=(
"/etc/filebeat/"
"/etc/postfix/"
"/var/ossec/api/configuration/"
"/var/ossec/etc/client.keys"
"/var/ossec/etc/ossec.conf"
"/var/ossec/etc/internal_options.conf"
"/var/ossec/etc/local_internal_options.conf"
"/var/ossec/etc/rules/local_rules.xml"
"/var/ossec/etc/decoders/local_decoder.xml"
"/var/ossec/etc/shared/"
"/var/ossec/queue/agents-timestamp"
"/var/ossec/queue/rids/"
"/var/ossec/queue/fts/"
"/var/ossec/stats/"
"/var/ossec/var/multigroups/"
"/var/ossec/etc/lists/"
"/var/ossec/integrations/"
"/var/ossec/wodles/"
"/var/ossec/active-response/bin/"
)
INDEXER_ITEMS=(
"/etc/wazuh-indexer/certs/"
"/etc/wazuh-indexer/opensearch.yml"
"/etc/wazuh-indexer/jvm.options"
"/etc/wazuh-indexer/opensearch.keystore"
"/etc/wazuh-indexer/opensearch-security/"
)
DASHBOARD_ITEMS=(
"/etc/wazuh-dashboard/certs/"
"/etc/wazuh-dashboard/opensearch_dashboards.yml"
"/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml"
)

if [ -f /proc/sys/crypto/fips_enabled ] && [ "$(cat /proc/sys/crypto/fips_enabled)" = "1" ]; then
    SSH_OPTS="-o KexAlgorithms=ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521"
else
    SSH_OPTS=""
fi

while [ "$#" -gt 0 ]; do
    case "$1" in
        --remote-user) REMOTE_USER="$2"; shift 2 ;;
        --remote-host) REMOTE_HOST="$2"; shift 2 ;;
        --remote-pass) REMOTE_PASS="$2"; shift 2 ;;
        --remote-path) REMOTE_BACKUP_PATH="$2"; shift 2 ;;
        --retention) RETENTION_COUNT="$2"; shift 2 ;;
        --auto-restore) AUTO_RESTORE="$2"; shift 2 ;;
        --selftest) SELFTEST="yes"; shift ;;
        -h|--help) usage ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
done

run_selftest() {
    local fail=0
    echo "[selftest] checking script structure"
    bash -n "$0" || { echo "[selftest] FAIL: syntax error"; return 1; }
    # Verify critical ordering: manager must restart before scp.
    # Extract line numbers and compare numerically.
    local start_line scp_line
    start_line=$(grep -n "systemctl start wazuh-manager" "$0" | head -1 | cut -d: -f1)
    scp_line=$(grep -n "scp -o StrictHostKeyChecking" "$0" | head -1 | cut -d: -f1)
    if [ "$start_line" -ge "$scp_line" ]; then
        echo "[selftest] FAIL: manager restart must precede scp transfer"
        fail=1
    else
        echo "[selftest] OK: restart (line $start_line) precedes scp (line $scp_line)"
    fi
    # Verify no integrity check sits between stop and start.
    local stop_line
    stop_line=$(grep -n "systemctl stop wazuh-manager" "$0" | head -1 | cut -d: -f1)
    if sed -n "${stop_line},${start_line}p" "$0" | grep -q "tar -tzf"; then
        echo "[selftest] FAIL: integrity check between stop and start holds downtime open"
        fail=1
    else
        echo "[selftest] OK: no integrity check inside the stopped window"
    fi
    # Verify lock, full binary paths, and MIME header are present.
    grep -q "LOCK_FILE" "$0" && echo "[selftest] OK: lock file present" || { echo "[selftest] FAIL: no lock"; fail=1; }
    grep -q "Content-Type: text/html" "$0" && echo "[selftest] OK: HTML MIME header present" || { echo "[selftest] FAIL: no MIME header"; fail=1; }
    [ "$fail" -eq 0 ] && echo "[selftest] PASS" || echo "[selftest] FAIL"
    return "$fail"
}

send_report() {
    [ -x "$SENDMAIL_BIN" ] || { echo "[WARNING] sendmail missing, skipping email"; return 0; }
    {
        echo "To: $EMAIL_TO"
        echo "From: $EMAIL_FROM"
        echo "Subject: Wazuh Backup Report - $FINAL_STATUS"
        echo "MIME-Version: 1.0"
        echo "Content-Type: text/html; charset=UTF-8"
        echo ""
        cat "$HTML_REPORT"
    } | "$SENDMAIL_BIN" -t || echo "[ERROR] Failed to send email"
}

write_report() {
    cat <<EOF > "$HTML_REPORT"
<html><head><style>
body { font-family: Arial; font-size: 13px; }
h1 { background:#003366; color:white; padding:10px; }
h2 { color:#003366; border-bottom:2px solid #ccc; }
table { border-collapse: collapse; width: 100%; }
th, td { border:1px solid #ccc; padding:6px; text-align:left; }
</style></head><body>
<h1>Wazuh Backup Report</h1>
<table>
<tr><th>Parameter</th><th>Value</th></tr>
<tr><td>Status</td><td>$FINAL_STATUS</td></tr>
<tr><td>Generated on</td><td>$(date)</td></tr>
<tr><td>Host</td><td>$(hostname -f) ($(hostname -I | awk '{print $1}'))</td></tr>
<tr><td>Remote path</td><td>$REMOTE_USER@$REMOTE_HOST:$REMOTE_BACKUP_PATH</td></tr>
<tr><td>Backup size</td><td>${BACKUP_SIZE_HR:-N/A}</td></tr>
<tr><td>Failure cause</td><td>$FAILURE_CAUSE</td></tr>
<tr><td>Remote send</td><td>$REMOTE_SEND_STATUS</td></tr>
<tr><td>Restore</td><td>$RESTORE_STATUS</td></tr>
<tr><td>Manager downtime</td><td>${MANAGER_DOWNTIME}s</td></tr>
</table>
<h2>Missing files (skipped, not fatal unless all missing)</h2><pre>${MISSING_FILES:-None}</pre>
<h2>Retention deletions</h2><pre>$RETENTION_DELETED</pre>
</body></html>
EOF
}

if [ "${SELFTEST:-no}" = "yes" ]; then
    run_selftest
    exit $?
fi

if [ -f "$LOCK_FILE" ]; then
    echo "[INFO] Previous backup still running. Exiting."
    exit 0
fi
touch "$LOCK_FILE"
trap 'rm -f "$LOCK_FILE"' EXIT

exec > >("$TEE_BIN" -a "$LOG_FILE") 2>&1

[ -x "$SSHPASS_BIN" ] || { FINAL_STATUS="FAILED"; FAILURE_CAUSE="sshpass missing at $SSHPASS_BIN"; write_report; send_report; exit 1; }
[ -x "$TAR_BIN" ] || { FINAL_STATUS="FAILED"; FAILURE_CAUSE="tar missing at $TAR_BIN"; write_report; send_report; exit 1; }
if [ -z "$REMOTE_USER" ] || [ -z "$REMOTE_HOST" ] || [ -z "$REMOTE_PASS" ]; then
    FINAL_STATUS="FAILED"; FAILURE_CAUSE="Remote user, host, or password is missing"
    write_report; send_report; exit 1
fi
mkdir -p "$LOCAL_BACKUP_PATH"

if ! "$SSHPASS_BIN" -p "$REMOTE_PASS" ssh -o StrictHostKeyChecking=no $SSH_OPTS \
    "$REMOTE_USER@$REMOTE_HOST" "mkdir -p $REMOTE_BACKUP_PATH && test -w $REMOTE_BACKUP_PATH"; then
    FINAL_STATUS="FAILED"; FAILURE_CAUSE="Remote directory creation or write check failed"
    write_report; send_report; exit 1
fi

echo "[INFO] Stopping wazuh-manager for a consistent queue DB copy..."
START_TIME=$(date +%s.%N)
systemctl stop wazuh-manager

BACKUP_TAR="$LOCAL_BACKUP_PATH/backup_$(date +'%Y-%m-%d_%H-%M-%S').tar.gz"
EXISTING_FILES=()
ALL_ITEMS=("${MANAGER_ITEMS[@]}" "${INDEXER_ITEMS[@]}" "${DASHBOARD_ITEMS[@]}")
for item in "${ALL_ITEMS[@]}"; do
    if [ -e "$item" ]; then
        EXISTING_FILES+=("$item")
    else
        echo "[WARNING] $item does not exist, skipping..."
        MISSING_FILES+="$item missing"$'\n'
    fi
done

if [ "${#EXISTING_FILES[@]}" -eq 0 ]; then
    FINAL_STATUS="FAILED"; FAILURE_CAUSE="No valid files found for backup"
    systemctl start wazuh-manager
    write_report; send_report; exit 1
fi

if ! "$TAR_BIN" -czpf "$BACKUP_TAR" "${EXISTING_FILES[@]}"; then
    FINAL_STATUS="FAILED"; FAILURE_CAUSE="Tar creation failed"
    systemctl start wazuh-manager
    write_report; send_report; exit 1
fi

# Restart first, before any slow follow-up work. Do not run tar -tzf
# verification here; it holds the manager stopped on large archives.
echo "[INFO] Starting wazuh-manager..."
systemctl start wazuh-manager
END_TIME=$(date +%s.%N)
MANAGER_DOWNTIME=$(echo "$START_TIME $END_TIME" | "$AWK_BIN" '{printf "%.2f", $2-$1}')

BACKUP_SIZE_HR=$("$DU_BIN" -h "$BACKUP_TAR" | "$AWK_BIN" '{print $1}')

if "$SSHPASS_BIN" -p "$REMOTE_PASS" scp -o StrictHostKeyChecking=no $SSH_OPTS \
    "$BACKUP_TAR" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_BACKUP_PATH/"; then
    REMOTE_SEND_STATUS="SUCCESS"
else
    FINAL_STATUS="FAILED"; FAILURE_CAUSE="SCP transfer failed"
    write_report; send_report; exit 1
fi

if [ "$AUTO_RESTORE" = "yes" ]; then
    if "$SSHPASS_BIN" -p "$REMOTE_PASS" ssh $SSH_OPTS "$REMOTE_USER@$REMOTE_HOST" \
        "tar -xzpf $REMOTE_BACKUP_PATH/$(basename "$BACKUP_TAR") -C /"; then
        RESTORE_STATUS="SUCCESS"
    else
        RESTORE_STATUS="FAILED"; FINAL_STATUS="FAILED"; FAILURE_CAUSE="Auto-restore failed"
    fi
fi

REMOTE_BACKUPS=$("$SSHPASS_BIN" -p "$REMOTE_PASS" ssh $SSH_OPTS \
    "$REMOTE_USER@$REMOTE_HOST" "ls -1t $REMOTE_BACKUP_PATH/backup_*.tar.gz 2>/dev/null")
BACKUP_COUNT=$(echo "$REMOTE_BACKUPS" | sed '/^$/d' | wc -l)
if [ "$BACKUP_COUNT" -gt "$RETENTION_COUNT" ]; then
    OLD_BACKUPS=$(echo "$REMOTE_BACKUPS" | tail -n +$((RETENTION_COUNT + 1)))
    RETENTION_DELETED=""
    for b in $OLD_BACKUPS; do
        "$SSHPASS_BIN" -p "$REMOTE_PASS" ssh $SSH_OPTS "$REMOTE_USER@$REMOTE_HOST" "rm -f $b"
        RETENTION_DELETED+="$b"$'\n'
    done
fi

[ -n "$MISSING_FILES" ] && FINAL_STATUS="FAILED"
write_report
send_report
rm -f "$HTML_REPORT" "$BACKUP_TAR"
echo "[INFO] Done with status: $FINAL_STATUS (manager downtime ${MANAGER_DOWNTIME}s)"
