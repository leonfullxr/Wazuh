# Health Check

## Table of Contents
- [Introduction](#introduction)
- [Manager / Server](#manager--server)
- [Filebeat](#filebeat)
- [Indexer](#indexer)
- [Dashboard](#dashboard)

## Introduction

Per-component health verification commands. Run them before and after an upgrade (see the [Pre-Upgrade Checklist](pre-upgrade-checklist.md)) or whenever something feels off.

The `GET` queries below run from the dashboard under **Indexer management > Dev Tools**, or equivalently with curl:

```bash
curl -k -u <USER>:<PASSWORD> https://<WAZUH_INDEXER_IP>:9200/<QUERY>
```

## Manager / Server

```bash
# Service and daemon status
systemctl status wazuh-manager
/var/ossec/bin/wazuh-control status

# Cluster nodes (multi-node deployments)
/var/ossec/bin/cluster_control -l

# Recent errors/warnings
grep -iE "error|warning|critical" /var/ossec/logs/ossec.log | tail -50
```

Via the Wazuh API (Dev Tools / API console):

```
GET /manager/version/check
```

## Filebeat

```bash
filebeat test output
```

Expected: all checks report `ok` against the indexer on port 9200. A `401` here means the Filebeat keystore credentials are stale — update the keystore with the current indexer username/password.

## Indexer

```
GET _cat/health?v&pretty=true&format=json
GET _cluster/health?pretty
GET _cat/indices/wazuh-alerts-*?v&h=index,pri
GET /wazuh-alerts-*/_stats/store?human=true
GET /wazuh-archives-*/_stats/store?human=true
GET /wazuh-monitoring-*/_stats/store?human=true

GET _cluster/allocation/explain
```

- Cluster status should be `green`. On `yellow`/`red`, `_cluster/allocation/explain` tells you why a shard is not allocated.
- Watch the store sizes against the disk watermarks — once a node crosses the high watermark, the indexer stops allocating shards to it and indexing can grind to a halt.

## Dashboard

```bash
systemctl status wazuh-dashboard
journalctl -u wazuh-dashboard --since "1 hour ago" | tail -30
```

Then verify the web UI loads on port 443 and the agents overview populates.
