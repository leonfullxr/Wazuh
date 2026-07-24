# Alert and archive retention (deletion policies)

Wazuh stores alert and archive logs on the manager filesystem under
`/var/ossec/logs/alerts/` and `/var/ossec/logs/archives/`, and indexed alerts in
the Wazuh indexer (`wazuh-alerts-*`). Neither is deleted automatically, so you
need a retention policy for both layers:

1. **Filesystem**: a cron job that removes old log files on the manager.
2. **Indexer**: an Index State Management (ISM) policy, or targeted
   `_delete_by_query` calls for surgical cleanup.

## 1. Filesystem cleanup (30-day example)

`cleanup.sh` deletes alert and archive files older than a configurable number
of days (default 30). It handles all the file extensions Wazuh produces
(`.log`, `.json`, `.sum`, `.log.sum`, `.json.sum`, `.log.gz`, `.json.gz`) and
logs its actions to `/var/log/messages`.

1. Copy `cleanup.sh` to your manager and make it executable:

   ```bash
   chmod +x /path/to/cleanup.sh
   ```

2. Adjust `RETENTION_DAYS` in the script if you want a different window.

3. Create a cron job to run it daily (2 AM in this example):

   ```
   0 2 * * * /path/to/cleanup.sh >/dev/null 2>&1
   ```

### Simpler alternative: find + mtime

If you only need to purge compressed/checksum files by modification time, two
crontab lines do the job without any script:

```
45 0 * * * find /var/ossec/logs/alerts/ -regex ".*\.gz\|.*\.sum" -type f -mtime +30 -exec rm -f {} \;
45 0 * * * find /var/ossec/logs/archives/ -regex ".*\.gz\|.*\.sum" -type f -mtime +30 -exec rm -f {} \;
```

## 2. Targeted deletion of indexed alerts

`delete_alerts_by_rule.sh` deletes indexed alerts that match a specific rule ID
within a date range (by default: older than 30 days but newer than 1 year),
using the OpenSearch `_delete_by_query` API. Useful for purging a noisy rule
without touching the rest of your data.

```bash
INDEXER_URL=https://<indexer-ip>:9200 INDEXER_USER=admin INDEXER_PASS='<password>' \
  ./delete_alerts_by_rule.sh 60106
```

The equivalent query can be run manually from the Dev Tools console:

```
POST wazuh-alerts-*/_delete_by_query
{
  "query": {
    "bool": {
      "filter": [
        { "match_phrase": { "rule.id": "5502" } },
        {
          "range": {
            "timestamp": {
              "gte": "2025-02-24T16:29:31.216Z",
              "lte": "2025-02-25T16:29:31.216Z",
              "format": "strict_date_optional_time"
            }
          }
        }
      ]
    }
  }
}
```

Tip: before deleting, confirm what will match by searching the alerts first
(see [`../alert-search`](../alert-search) for a local `alerts.json` search, or
run the same query with `_search` instead of `_delete_by_query`).

## 3. Indexer Index State Management (ISM) policy

For automatic index lifecycle handling, create an Index Management Policy as
described in the [Wazuh index management blog post](https://wazuh.com/blog/wazuh-index-management/):

- Go to Index Management > Index Policies
- Create the policy below (change ages as needed). It keeps indices hot,
  moves them to a read-only cold state after 30 days, and deletes them after
  a year:

```json
{
    "policy": {
        "description": "Wazuh index state management for Wazuh to move indices into a cold state after 30 days and delete them after a year.",
        "default_state": "hot",
        "states": [
            {
                "name": "hot",
                "actions": [
                    {
                        "replica_count": {
                            "number_of_replicas": 0
                        }
                    }
                ],
                "transitions": [
                    {
                        "state_name": "cold",
                        "conditions": {
                            "min_index_age": "30d"
                        }
                    }
                ]
            },
            {
                "name": "cold",
                "actions": [
                    {
                        "read_only": {}
                    }
                ],
                "transitions": [
                    {
                        "state_name": "delete",
                        "conditions": {
                            "min_index_age": "365d"
                        }
                    }
                ]
            },
            {
                "name": "delete",
                "actions": [
                    {
                        "delete": {}
                    }
                ],
                "transitions": []
            }
        ],
        "ism_template": {
            "index_patterns": ["wazuh-alerts*"],
            "priority": 100
        }
    }
}
```
