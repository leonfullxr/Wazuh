#!/bin/bash
# delete_alerts_by_rule.sh - Delete indexed Wazuh alerts matching a rule ID
# within a date range, using the OpenSearch _delete_by_query API.
#
# Example: purge rule 60106 alerts older than 30 days but newer than 1 year.
#
# Usage:
#   INDEXER_URL=https://<indexer-ip>:9200 INDEXER_USER=admin INDEXER_PASS=secret \
#     ./delete_alerts_by_rule.sh <rule_id>
#
# Can be scheduled via cron for periodic housekeeping.

set -euo pipefail

INDEXER_URL="${INDEXER_URL:-https://127.0.0.1:9200}"
INDEXER_USER="${INDEXER_USER:-admin}"
INDEXER_PASS="${INDEXER_PASS:-admin}"
RULE_ID="${1:?Usage: $0 <rule_id>}"

# Deletion window: alerts between 1 year ago and 30 days ago
dstart=$(date --date="1 year ago" +%Y-%m-%d)
dend=$(date --date="30 days ago" +%Y-%m-%d)

curl -k -u "${INDEXER_USER}:${INDEXER_PASS}" \
  -X POST "${INDEXER_URL}/wazuh-alerts-*/_delete_by_query" \
  -H "Content-Type: application/json" \
  --data "{
  \"query\": {
    \"bool\": {
      \"filter\": [
        { \"match_phrase\": { \"rule.id\": \"${RULE_ID}\" } },
        {
          \"range\": {
            \"timestamp\": {
              \"gte\": \"${dstart}T00:00:00.000Z\",
              \"lte\": \"${dend}T00:00:00.000Z\",
              \"format\": \"strict_date_optional_time\"
            }
          }
        }
      ]
    }
  }
}"
