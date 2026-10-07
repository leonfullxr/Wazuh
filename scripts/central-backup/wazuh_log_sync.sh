#!/bin/bash
# wazuh_log_sync.sh - Incremental sync of compressed manager logs to cold storage.
# Distilled from a production support engagement. See README.md for design notes
# and deliberate simplifications.
#
# Copies only finalized compressed files (*.json.gz, *.log.gz) from
# /var/ossec/logs/alerts and /var/ossec/logs/archives. Tracks what was already
# sent in SENT_LOG using a path:mtime fingerprint so reruns send only new files.
#
# Usage:
#   REMOTE_HOST=192.0.2.10 REMOTE_USER=backup REMOTE_PASS='secret' ./wazuh_log_sync.sh
#   ./wazuh_log_sync.sh --remote-host 192.0.2.10 --restore no --remove no --selftest
#
# Cron example (daily 01:30):
#   30 1 * * * /opt/wazuh-backup/wazuh_log_sync.sh >/dev/null 2>&1

set -u

REMOTE_USER="${REMOTE_USER:-}"
REMOTE_HOST="${REMOTE_HOST:-}"
REMOTE_PASS="${REMOTE_PASS:-}"
RESTORE="${RESTORE:-no}"
REMOVE="${REMOVE:-no}"
STAGING_DIR="${STAGING_DIR:-/backup/wazuh-logs}"

ALERT_DIR="/var/ossec/logs/alerts"
ARCHIVE_DIR="/var/ossec/logs/archives"
SENT_LOG="/var/ossec/logs/ossec_sent_files.log"
TMP_FILE_ALERTS="/tmp/ossec_rsync_alerts.txt"
TMP_FILE_ARCHIVES="/tmp/ossec_rsync_archives.txt"
TMP_SIZE_ALERTS="/tmp/ossec_rsync_alerts_sizes.txt"
TMP_SIZE_ARCHIVES="/tmp/ossec_rsync_archives_sizes.txt"
HTML_REPORT="/tmp/wazuh_rsync_report.html"
LOG_FILE="/tmp/wazuh_rsync_script.log"
SENDMAIL_BIN="/sbin/sendmail"
EMAIL_TO="${EMAIL_TO:-backup@example.com}"
EMAIL_FROM="${EMAIL_FROM:-wazuh@example.com}"

FINAL_STATUS="SUCCESS"
FAILURE_CAUSE="None"
ALERTS_RSYNC_STATUS="NOT RUN"
ARCHIVES_RSYNC_STATUS="NOT RUN"
ALERTS_FILE_COUNT=0
ARCHIVES_FILE_COUNT=0
ALERTS_SENT_COUNT=0
ARCHIVES_SENT_COUNT=0
SCRIPT_START_TIME=$(date +%s)

while [ "$#" -gt 0 ]; do
    case "$1" in
        --remote-user) REMOTE_USER="$2"; shift 2 ;;
        --remote-host) REMOTE_HOST="$2"; shift 2 ;;
        --remote-pass) REMOTE_PASS="$2"; shift 2 ;;
        --restore) RESTORE="$2"; shift 2 ;;
        --remove) REMOVE="$2"; shift 2 ;;
        --staging-dir) STAGING_DIR="$2"; shift 2 ;;
        --selftest) SELFTEST="yes"; shift ;;
        -h|--help) grep "^#" "$0" | sed 's/^# //;s/^#//'; exit 0 ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
done

run_selftest() {
    local fail=0
    echo "[selftest] checking script structure"
    bash -n "$0" || { echo "[selftest] FAIL: syntax error"; return 1; }
    grep -q 'json.gz.*log.gz\|EXTENSIONS' "$0" \
        && echo "[selftest] OK: compressed-only filter present" \
        || { echo "[selftest] FAIL: no compressed-only filter"; fail=1; }
    grep -q 'SENT_LOG' "$0" \
        && echo "[selftest] OK: sent-log dedup present" \
        || { echo "[selftest] FAIL: no sent-log"; fail=1; }
    grep -q 'NO FILES FOUND' "$0" \
        && echo "[selftest] OK: empty-run status present" \
        || { echo "[selftest] FAIL: no empty-run status"; fail=1; }
    grep -q 'stat -c %Y' "$0" \
        && echo "[selftest] OK: mtime fingerprint present" \
        || { echo "[selftest] FAIL: no mtime fingerprint"; fail=1; }
    grep -q 'Content-Type: text/html' "$0" \
        && echo "[selftest] OK: HTML MIME header present" \
        || { echo "[selftest] FAIL: no MIME header"; fail=1; }
    [ "$fail" -eq 0 ] && echo "[selftest] PASS" || echo "[selftest] FAIL"
    return "$fail"
}

generate_html_report() {
    local alert_rows="<tr><td colspan=\"2\">No alert files transferred</td></tr>"
    local archive_rows="<tr><td colspan=\"2\">No archive files transferred</td></tr>"
    local end_time duration
    end_time=$(date +%s)
    duration=$((end_time - SCRIPT_START_TIME))
    [ -s "$TMP_SIZE_ALERTS" ] && {
        alert_rows=""
        while IFS='|' read -r rel_path size; do
            alert_rows+="<tr><td>$rel_path</td><td>${size:-N/A}</td></tr>"
        done < "$TMP_SIZE_ALERTS"
    }
    [ -s "$TMP_SIZE_ARCHIVES" ] && {
        archive_rows=""
        while IFS='|' read -r rel_path size; do
            archive_rows+="<tr><td>$rel_path</td><td>${size:-N/A}</td></tr>"
        done < "$TMP_SIZE_ARCHIVES"
    }
    cat <<EOF > "$HTML_REPORT"
<html><head><style>
body { font-family: Arial; font-size: 13px; }
h1 { background:#003366; color:white; padding:10px; }
h2 { color:#003366; border-bottom:2px solid #ccc; }
table { border-collapse: collapse; width: 100%; text-align:left; }
th, td { border:1px solid #ccc; padding:6px; text-align:left; }
</style></head><body>
<h1>Wazuh Log Sync Report</h1>
<table>
<tr><th>Parameter</th><th>Value</th></tr>
<tr><td>Status</td><td>$FINAL_STATUS</td></tr>
<tr><td>Generated on</td><td>$(date)</td></tr>
<tr><td>Host</td><td>$(hostname -f) ($(hostname -I | awk '{print $1}'))</td></tr>
<tr><td>Remote</td><td>$REMOTE_USER@$REMOTE_HOST</td></tr>
<tr><td>Restore mode</td><td>$RESTORE</td></tr>
<tr><td>Remove source</td><td>$REMOVE</td></tr>
<tr><td>Duration</td><td>${duration}s</td></tr>
<tr><td>Failure cause</td><td>$FAILURE_CAUSE</td></tr>
</table>
<h2>Transfer Summary</h2>
<table>
<tr><th>Category</th><th>Files Found</th><th>Files Sent</th><th>Rsync Status</th></tr>
<tr><td>Alerts</td><td>$ALERTS_FILE_COUNT</td><td>$ALERTS_SENT_COUNT</td><td>$ALERTS_RSYNC_STATUS</td></tr>
<tr><td>Archives</td><td>$ARCHIVES_FILE_COUNT</td><td>$ARCHIVES_SENT_COUNT</td><td>$ARCHIVES_RSYNC_STATUS</td></tr>
</table>
<h2>Alert Files Transferred</h2>
<table><tr><th>File</th><th>Size</th></tr>$alert_rows</table>
<h2>Archive Files Transferred</h2>
<table><tr><th>File</th><th>Size</th></tr>$archive_rows</table>
</body></html>
EOF
}

send_email_report() {
    [ -x "$SENDMAIL_BIN" ] || { echo "[WARNING] sendmail missing, skipping email"; return 0; }
    {
        echo "To: $EMAIL_TO"
        echo "From: $EMAIL_FROM"
        echo "Subject: Wazuh Log Sync Report - $FINAL_STATUS"
        echo "MIME-Version: 1.0"
        echo "Content-Type: text/html; charset=UTF-8"
        echo ""
        cat "$HTML_REPORT"
    } | "$SENDMAIL_BIN" -t || echo "[ERROR] Failed to send email"
}

if [ "${SELFTEST:-no}" = "yes" ]; then
    run_selftest
    exit $?
fi

exec > >(tee -a "$LOG_FILE") 2>&1

if [ -z "$REMOTE_USER" ] || [ -z "$REMOTE_HOST" ] || [ -z "$REMOTE_PASS" ]; then
    FINAL_STATUS="FAILED"; FAILURE_CAUSE="Remote user, host, or password is missing"
    generate_html_report; send_email_report; exit 1
fi
if ! command -v sshpass >/dev/null 2>&1; then
    FINAL_STATUS="FAILED"; FAILURE_CAUSE="sshpass binary not found"
    generate_html_report; send_email_report; exit 1
fi

echo "[INFO] Checking SSH connectivity to $REMOTE_USER@$REMOTE_HOST..."
if ! sshpass -p "$REMOTE_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
    "$REMOTE_USER@$REMOTE_HOST" "echo OK" 2>&1 | grep -q "OK"; then
    FINAL_STATUS="FAILED"; FAILURE_CAUSE="SSH connection to $REMOTE_USER@$REMOTE_HOST failed"
    generate_html_report; send_email_report; exit 1
fi
echo "[INFO] SSH connectivity OK."

touch "$SENT_LOG"
: > "$TMP_FILE_ALERTS"; : > "$TMP_FILE_ARCHIVES"
: > "$TMP_SIZE_ALERTS"; : > "$TMP_SIZE_ARCHIVES"

scan_dir() {
    local dir="$1" root="$2" tmp="$3" sizes="$4"
    [ -d "$dir" ] || return 0
    find "$dir" -type f \( -name "*.json.gz" -o -name "*.log.gz" \) | while IFS= read -r file; do
        [ -e "$file" ] || continue
        local mtime fingerprint rel size
        mtime=$(stat -c %Y "$file")
        fingerprint="${file}:${mtime}"
        grep -qxF "$fingerprint" "$SENT_LOG" && continue
        rel="${file#$root/}"
        echo "$rel" >> "$tmp"
        size=$(du -sh "$file" 2>/dev/null | awk '{print $1}')
        echo "${rel}|${size}" >> "$sizes"
    done
}

echo "[INFO] Scanning for compressed logs (.json.gz, .log.gz)..."
scan_dir "$ALERT_DIR" "$ALERT_DIR" "$TMP_FILE_ALERTS" "$TMP_SIZE_ALERTS"
scan_dir "$ARCHIVE_DIR" "$ARCHIVE_DIR" "$TMP_FILE_ARCHIVES" "$TMP_SIZE_ARCHIVES"

[ -s "$TMP_FILE_ALERTS" ] && ALERTS_FILE_COUNT=$(wc -l < "$TMP_FILE_ALERTS")
[ -s "$TMP_FILE_ARCHIVES" ] && ARCHIVES_FILE_COUNT=$(wc -l < "$TMP_FILE_ARCHIVES")

if [ ! -s "$TMP_FILE_ALERTS" ] && [ ! -s "$TMP_FILE_ARCHIVES" ]; then
    echo "[INFO] No new compressed logs to send."
    FINAL_STATUS="NO FILES FOUND"
    FAILURE_CAUSE="None, no new compressed files pending transfer"
    generate_html_report; send_email_report
    rm -f "$TMP_FILE_ALERTS" "$TMP_FILE_ARCHIVES" "$TMP_SIZE_ALERTS" "$TMP_SIZE_ARCHIVES" "$HTML_REPORT"
    exit 0
fi

RSYNC_OPTS="-avz"
[ "$REMOVE" = "yes" ] && RSYNC_OPTS="$RSYNC_OPTS --remove-source-files"

run_rsync() {
    local tmp="$1" src_root="$2" remote_dest="$3" status_var="$4" count_var="$5"
    [ -s "$tmp" ] || return 0
    echo "[INFO] Ensuring remote directory exists: $remote_dest"
    sshpass -p "$REMOTE_PASS" ssh -o StrictHostKeyChecking=no \
        "$REMOTE_USER@$REMOTE_HOST" "mkdir -p $remote_dest"
    echo "[INFO] Sending from $src_root to $REMOTE_USER@$REMOTE_HOST:$remote_dest"
    if sshpass -p "$REMOTE_PASS" rsync $RSYNC_OPTS \
        --files-from="$tmp" \
        -e "ssh -o StrictHostKeyChecking=no" \
        "$src_root/" "$REMOTE_USER@$REMOTE_HOST:$remote_dest"; then
        eval "$status_var=SUCCESS"
        local sent=0
        while IFS= read -r rel_path; do
            local abs_path mtime
            abs_path="$src_root/$rel_path"
            [ -e "$abs_path" ] || continue
            mtime=$(stat -c %Y "$abs_path")
            echo "${abs_path}:${mtime}" >> "$SENT_LOG"
            sent=$((sent + 1))
        done < "$tmp"
        eval "$count_var=$sent"
    else
        eval "$status_var=FAILED"
        FINAL_STATUS="FAILED"
        FAILURE_CAUSE="rsync failed for $src_root"
        echo "[WARNING] rsync failed for $src_root, files not marked as sent."
    fi
}

if [ "$RESTORE" = "yes" ]; then
    run_rsync "$TMP_FILE_ALERTS" "$ALERT_DIR" "$ALERT_DIR/" ALERTS_RSYNC_STATUS ALERTS_SENT_COUNT
    run_rsync "$TMP_FILE_ARCHIVES" "$ARCHIVE_DIR" "$ARCHIVE_DIR/" ARCHIVES_RSYNC_STATUS ARCHIVES_SENT_COUNT
else
    run_rsync "$TMP_FILE_ALERTS" "$ALERT_DIR" "$STAGING_DIR/alerts" ALERTS_RSYNC_STATUS ALERTS_SENT_COUNT
    run_rsync "$TMP_FILE_ARCHIVES" "$ARCHIVE_DIR" "$STAGING_DIR/archives" ARCHIVES_RSYNC_STATUS ARCHIVES_SENT_COUNT
fi

generate_html_report
send_email_report
rm -f "$TMP_FILE_ALERTS" "$TMP_FILE_ARCHIVES" "$TMP_SIZE_ALERTS" "$TMP_SIZE_ARCHIVES" "$HTML_REPORT"
echo "[INFO] Done with status: $FINAL_STATUS"
