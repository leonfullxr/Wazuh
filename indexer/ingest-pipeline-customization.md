# Customizing the Wazuh Ingest Pipeline

The Filebeat Wazuh module installs an ingest pipeline that normalizes alert
timestamps, enriches IP addresses, and selects the destination index. Change
it only when the indexed document must differ from the manager-side alert.
Dashboard timezone display should normally be configured in the dashboard;
rewriting `full_log` is for downstream consumers that require a literal local
timestamp in that field.

Pipeline changes affect only newly indexed documents. They do not change the
alert in `/var/ossec/logs/alerts/alerts.json`, manager-side integrations, or
active responses.

## Prerequisites

- Shell access to every Wazuh manager that runs Filebeat.
- A maintenance window and a representative test event.
- An IANA timezone such as `Europe/Madrid`, not an ambiguous abbreviation.
- A backup or configuration-management copy of the current pipeline.

The examples use:

```text
/usr/share/filebeat/module/wazuh/alerts/ingest/pipeline.json
```

Confirm that path and the existing processor order on the installed Wazuh
release before editing.

## Procedure: add a local timestamp to `full_log`

1. Confirm that the operating-system timezone is correct on the event source.
   If the Wazuh agent uses its chrooted timezone file, synchronize it:

   ```bash
   timedatectl
   sudo systemctl stop wazuh-agent
   sudo cp --preserve=mode,ownership /var/ossec/etc/localtime \
     /var/ossec/etc/localtime.bak
   sudo cp /etc/localtime /var/ossec/etc/localtime
   sudo chown root:wazuh /var/ossec/etc/localtime
   sudo systemctl start wazuh-agent
   ```

2. On each manager, back up the pipeline:

   ```bash
   sudo cp \
     /usr/share/filebeat/module/wazuh/alerts/ingest/pipeline.json \
     /usr/share/filebeat/module/wazuh/alerts/ingest/pipeline.json.bak
   ```

3. After the processor that populates `@timestamp`, add processors equivalent
   to the following. Replace `Europe/Madrid` with the required IANA timezone:

   ```json
   {
     "date": {
       "field": "@timestamp",
       "target_field": "local_timestamp",
       "formats": ["ISO8601"],
       "timezone": "Europe/Madrid",
       "output_format": "yyyy-MM-dd'T'HH:mm:ss.SSSXXX",
       "ignore_failure": true
     }
   },
   {
     "rename": {
       "field": "full_log",
       "target_field": "original_log",
       "ignore_missing": true
     }
   },
   {
     "set": {
       "if": "ctx.local_timestamp != null && ctx.original_log != null",
       "field": "full_log",
       "value": "{{{local_timestamp}}} {{{original_log}}}",
       "ignore_failure": true
     }
   }
   ```

   Keep `@timestamp` unchanged. OpenSearch stores absolute event time in UTC;
   `local_timestamp` is an additional presentation value.

4. Validate the JSON and upload the pipeline:

   ```bash
   python3 -m json.tool \
     /usr/share/filebeat/module/wazuh/alerts/ingest/pipeline.json >/dev/null
   sudo filebeat setup --pipelines
   sudo systemctl restart filebeat
   sudo filebeat test output
   ```

5. Apply the same version-controlled change on every manager node. A mixed
   manager cluster otherwise produces documents with different schemas.

## Verification

Generate a representative event, then inspect a newly indexed document in
**Indexer management > Dev Tools**:

```http
GET wazuh-alerts-*/_search
{
  "size": 1,
  "sort": [
    { "@timestamp": "desc" }
  ],
  "_source": [
    "@timestamp",
    "local_timestamp",
    "full_log",
    "original_log",
    "agent.name"
  ],
  "query": {
    "exists": {
      "field": "local_timestamp"
    }
  }
}
```

Verify that:

- `@timestamp` still represents the correct instant.
- `local_timestamp` has the expected UTC offset, including daylight-saving
  behavior for the selected timezone.
- `full_log` starts with that value and `original_log` preserves the source
  message.
- Filebeat has no pipeline or mapping errors:

  ```bash
  sudo journalctl -u filebeat --since "10 minutes ago" --no-pager
  ```

## Upgrade and rollback

Wazuh upgrades can replace `pipeline.json`. Keep the customization as a
reviewable patch and revalidate it against the new stock pipeline before
reapplying it. Coordinate this change with
[index separation](index-separation.md) and
[GeoIP customization](geoip.md), because all three modify the same processor
list.

To roll back, restore the backup, upload it, and restart Filebeat:

```bash
sudo cp \
  /usr/share/filebeat/module/wazuh/alerts/ingest/pipeline.json.bak \
  /usr/share/filebeat/module/wazuh/alerts/ingest/pipeline.json
sudo filebeat setup --pipelines
sudo systemctl restart filebeat
sudo filebeat test output
```

## See also

- [Index separation](index-separation.md)
- [GeoIP enrichment](geoip.md)
- [OpenSearch date processor](https://docs.opensearch.org/latest/ingest-pipelines/processors/date/)
