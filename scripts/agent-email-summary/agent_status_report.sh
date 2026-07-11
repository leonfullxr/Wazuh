#!/bin/bash
# agent_status_report.sh - Query the Wazuh API for disconnected/pending/
# never-connected agents and send an HTML-formatted email report.
#
# Usage: edit the configuration below (or export the variables), then run
# manually or from cron, e.g. daily at 8 AM:
#   0 8 * * * /path/to/agent_status_report.sh
#
# Requires: curl, jq, and a working sendmail (e.g. via Postfix).

# Wazuh API configuration
WAZUH_BASE_URL="${WAZUH_BASE_URL:-https://<MANAGER_IP>:55000}"
API_USERNAME="${WAZUH_API_USER:-wazuh-wui}"
API_PASSWORD="${WAZUH_API_PASSWORD:-wazuh-wui}"
# Email configuration
FROM_EMAIL="${FROM_EMAIL:-wazuh-reports@example.com}"
TO_EMAIL="${TO_EMAIL:-recipient@example.com}"
SUBJECT="Wazuh Agent Status Report"
# Authenticate and get the token
TOKEN=$(curl -u $API_USERNAME:$API_PASSWORD -k -X POST "$WAZUH_BASE_URL/security/user/authenticate?raw=true")
# Get the disconnected, pending and never connected agents and process them
DISCONNECTED_AGENTS=$(curl -k -X GET "$WAZUH_BASE_URL/agents?status=disconnected,pending,never_connected&pretty=true&select=ip,id,name,dateAdd,lastKeepAlive,status" -H "Authorization: Bearer $TOKEN")
# Begin HTML body
HTML_BODY="<html><head>
  <style>
    body { font-family: Tahoma, sans-serif; background-color: #FFFFFF; color: #333; margin: 0; padding: 0; font-size: 16px; }
    .container { width: 90%; margin: 0 auto; text-align: center; background-color: #FFFFFF; padding: 30px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); }
    /* Header */
    h2, h3 { color: #333; }
    h2 { font-size: 30px; }
    h3 { font-size: 26px; }
    p { font-size: 18px; color: #666; }
    /* Table */
    .table-container { overflow-x: auto; margin-top: 20px; }
    table { width: 100%; border-collapse: collapse; table-layout: fixed; font-size: 16px; color: #000; }
    th, td { padding: 12px; text-align: center; border: 1px solid #ddd; word-wrap: break-word; }
    th { background-color: #2d3e50; color: #fff; font-size: 18px; }
    tr:nth-child(even) { background-color: #b3f4f7; }
    tr:nth-child(odd)  { background-color: #dffcff; }
    /* Status colors */
    .active           { background-color: #90EE90; color: #000; }  /* Light green */
    .disconnected     { background-color: #FFCCCB; color: #000; }  /* Light red   */
    .pending          { background-color: #FFFACD; color: #000; }  /* Light yellow*/
    .never_connected  { background-color: #D3D3D3; color: #000; }  /* Light gray  */
    /* Footer */
    .footer { font-size: 14px; color: #666; text-align: center; margin-top: 40px; }
  </style>
</head><body>"
# Main content container
HTML_BODY+="<div class='container'>"
# Header
HTML_BODY+="<h2>Wazuh Agent Status Report</h2>"
HTML_BODY+="<p><strong>Date:</strong> $(date '+%Y-%m-%d %H:%M:%S')</p>"
# Agent status table
HTML_BODY+="<h3>Agent Status</h3>"
HTML_BODY+="<div class='table-container'>"
HTML_BODY+="<table>"
HTML_BODY+="<tr><th>Agent Name</th><th>Agent IP</th><th>Agent Added Date</th><th>Last Connection Received</th><th>Status</th></tr>"
# Format agents rows
ROWS_HTML=""
for row in $(echo "$DISCONNECTED_AGENTS" | jq -r '.data.affected_items[] | @base64'); do
  _jq() { echo "$row" | base64 --decode | jq -r "$1"; }

  agent_name=$(_jq '.name')
  agent_ip=$(_jq '.ip')
  agent_date_add_utc=$(_jq '.dateAdd')
  last_keep_alive_utc=$(_jq '.lastKeepAlive')
  agent_status=$(_jq '.status')

  agent_date_add_local=$(date -d "$agent_date_add_utc" +"%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "N/A")
  last_keep_alive_local=$(date -d "$last_keep_alive_utc" +"%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "N/A")

  case "$agent_status" in
    disconnected)    row_class="disconnected"    ;;
    pending)         row_class="pending"         ;;
    never_connected) row_class="never_connected" ;;
    active)          row_class="active"          ;;
    *)               row_class=""               ;;
  esac

  ROWS_HTML+="<tr class=\"$row_class\">\
<td>$agent_name</td>\
<td>$agent_ip</td>\
<td>$agent_date_add_local</td>\
<td>$last_keep_alive_local</td>\
<td>$agent_status</td>\
</tr>"
done
# Close HTML & footer
HTML_BODY+="$ROWS_HTML"
HTML_BODY+="</table></div>"
HTML_BODY+="<div class='footer'>This report was generated automatically by the Wazuh System</div>"
HTML_BODY+="</div></body></html>"
# Send the email using sendmail (handled by Postfix)
echo -e "Subject: $SUBJECT\nContent-Type: text/html; charset=UTF-8\nFrom: $FROM_EMAIL\nTo: $TO_EMAIL\n\n$HTML_BODY" | sendmail -t
