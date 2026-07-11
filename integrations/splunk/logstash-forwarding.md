<!-- Support: WS-19244 -->

# Forwarding Wazuh Indexer Alerts to Splunk with Logstash

This guide queries selected Wazuh Indexer indices with the Logstash OpenSearch
input plugin and sends each document to Splunk's HTTP Event Collector (HEC).
It is distinct from the alert-by-alert Splunk SOAR hook documented in this
directory.

Use this pattern when Splunk needs indexed Wazuh alerts and a scheduled pull
is acceptable. For lowest-latency manager alerts, compare the official
Splunk Universal Forwarder path that reads
`/var/ossec/logs/alerts/alerts.json` directly.

## Prerequisites

- A dedicated Logstash host with network access to:
  - Wazuh Indexer HTTPS/9200.
  - Splunk HEC HTTPS/8088.
- A least-privilege Wazuh Indexer user with read access only to the selected
  index patterns.
- A Splunk HEC token restricted to the destination index and sourcetype.
- The Wazuh Indexer root CA and the CA that validates Splunk HEC.
- A decision about duplicate handling and backfill.

The scheduled time-range query is at-least-once: overlapping windows prevent
late-arriving events from being missed, but can resend documents. Design
Splunk-side deduplication or use a checkpoint-capable source if duplicates are
unacceptable.

## Procedure

### 1. Prepare Splunk HEC

Create an HEC input in Splunk, enable TLS, select a destination index, and
record the token. From the Logstash host:

```bash
read -rsp "Splunk HEC token: " SPLUNK_AUTH; echo
curl --fail --silent --show-error \
  --cacert /etc/logstash/certs/splunk-ca.pem \
  -H "Authorization: Splunk ${SPLUNK_AUTH}" \
  "https://splunk.example.com:8088/services/collector/health"
unset SPLUNK_AUTH
```

Do not continue until certificate verification and authentication succeed
without `-k`.

### 2. Install the OpenSearch input

Use the Logstash version supported by the installed Java runtime, then install
the input plugin:

```bash
sudo /usr/share/logstash/bin/logstash-plugin install logstash-input-opensearch
sudo /usr/share/logstash/bin/logstash-plugin list --verbose \
  | grep logstash-input-opensearch
```

Copy the CA files to a root-owned directory:

```bash
sudo install -d -o root -g logstash -m 750 /etc/logstash/certs
sudo install -o root -g logstash -m 640 root-ca.pem \
  /etc/logstash/certs/wazuh-root-ca.pem
sudo install -o root -g logstash -m 640 splunk-ca.pem \
  /etc/logstash/certs/splunk-ca.pem
```

### 3. Store secrets in the Logstash keystore

Create the keystore and add values interactively:

```bash
sudo -E /usr/share/logstash/bin/logstash-keystore \
  --path.settings /etc/logstash create
sudo -E /usr/share/logstash/bin/logstash-keystore \
  --path.settings /etc/logstash add WAZUH_INDEXER_USERNAME
sudo -E /usr/share/logstash/bin/logstash-keystore \
  --path.settings /etc/logstash add WAZUH_INDEXER_PASSWORD
sudo -E /usr/share/logstash/bin/logstash-keystore \
  --path.settings /etc/logstash add SPLUNK_AUTH
```

If the keystore itself uses `LOGSTASH_KEYSTORE_PASS`, provide that variable to
both administrative commands and the systemd service using the operating
system's protected service environment file. Set that file to mode `600`.

### 4. Create the pipeline

Create `/etc/logstash/conf.d/wazuh-splunk.conf`:

```ruby
input {
  opensearch {
    hosts => ["https://<WAZUH_INDEXER_ADDRESS>:9200"]
    user => "${WAZUH_INDEXER_USERNAME}"
    password => "${WAZUH_INDEXER_PASSWORD}"
    index => "wazuh-alerts-4.x-*"
    ssl => true
    ca_file => "/etc/logstash/certs/wazuh-root-ca.pem"
    query => '{
      "query": {
        "range": {
          "@timestamp": {
            "gte": "now-2m",
            "lt": "now"
          }
        }
      },
      "sort": [
        { "@timestamp": "asc" }
      ]
    }'
    schedule => "* * * * *"
  }
}

filter {
  mutate {
    add_field => {
      "[@metadata][splunk_source]" => "wazuh-indexer"
    }
  }
}

output {
  http {
    url => "https://splunk.example.com:8088/services/collector/raw"
    http_method => "post"
    format => "json"
    content_type => "application/json"
    headers => {
      "Authorization" => "Splunk ${SPLUNK_AUTH}"
      "X-Splunk-Request-Channel" => "wazuh-logstash"
    }
    cacert => "/etc/logstash/certs/splunk-ca.pem"
  }
}
```

Change the index pattern to the minimum required set. Do not use an indexer
administrator account. The two-minute query window intentionally overlaps
runs to tolerate indexing delay; account for duplicates in Splunk.

### 5. Validate and start

```bash
sudo -E /usr/share/logstash/bin/logstash \
  --path.settings /etc/logstash \
  --config.test_and_exit \
  -f /etc/logstash/conf.d/wazuh-splunk.conf
```

Run in the foreground during the first test:

```bash
sudo systemctl stop logstash
sudo -E /usr/share/logstash/bin/logstash \
  --path.settings /etc/logstash \
  -f /etc/logstash/conf.d/wazuh-splunk.conf
```

After one successful scheduled cycle, stop the foreground process and enable
the service:

```bash
sudo systemctl enable --now logstash
sudo journalctl -u logstash --since "10 minutes ago" --no-pager
```

## Verification

Generate one identifiable Wazuh alert and verify it at each boundary:

1. It exists in `wazuh-alerts-4.x-*` with the expected `@timestamp`.
2. Logstash reports no OpenSearch TLS/authentication errors.
3. Splunk HEC metrics show accepted events and no invalid-token responses.
4. A Splunk search returns the event:

   ```text
   index=<SPLUNK_INDEX> sourcetype=<HEC_SOURCETYPE>
   | search rule.id="<RULE_ID>" agent.name="<AGENT_NAME>"
   ```

5. Compare Wazuh and Splunk counts over a fixed interval and quantify any
   duplicates introduced by the overlap window.

## Operations and recovery

- Monitor lag between Wazuh `@timestamp` and Splunk `_indextime`.
- A scheduled relative-time query is not a durable checkpoint. If Logstash is
  down longer than the query window, perform an explicit bounded backfill.
- Run backfills in a separate pipeline with fixed `gte`/`lt` timestamps and
  throttle them to protect the Wazuh Indexer.
- Preserve a stable source document identifier in Splunk if the HEC/event
  design supports deduplication.
- Rotate the indexer password and HEC token through the keystore; restart
  Logstash and verify both endpoints afterward.
- Keep CA renewal dates in monitoring. Never replace `cacert` with disabled
  verification.

## See also

- [Splunk integration hub](README.md)
- [Official Wazuh Splunk integration](https://documentation.wazuh.com/current/integrations-guide/splunk/index.html)
- [Wazuh Indexer operations](../../indexer/README.md)
