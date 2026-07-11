# Separating Alerts into Dedicated Indices

By default every alert lands in the daily `wazuh-alerts-4.x-*` index.
Routing a subset of alerts (e.g. everything from a specific technology or
rule group) into its own index pattern enables per-source
[retention policies](ilm-retention.md), separate access control, and cleaner
dashboards.

The routing happens in the Filebeat ingest pipeline that names the
destination index: `date_index_name` processors are evaluated in order, and
a conditional one placed **before** the default catches matching alerts
first.

## Table of Contents

- [Procedure](#procedure)
- [Alerts with multiple rule groups](#alerts-with-multiple-rule-groups)
- [Make the new pattern usable](#make-the-new-pattern-usable)
- [Coordinating pipeline.json changes](#coordinating-pipelinejson-changes)

## Procedure

On **every Wazuh manager node**:

1. Back up and edit the pipeline:

   ```bash
   cp /usr/share/filebeat/module/wazuh/alerts/ingest/pipeline.json \
      /usr/share/filebeat/module/wazuh/alerts/ingest/pipeline.json.bak
   nano /usr/share/filebeat/module/wazuh/alerts/ingest/pipeline.json
   ```

2. **Before** the existing `date_index_name` processor, insert a conditional
   one. Example routing a rule group into `wazuh-custom-alerts-4.x-*` daily
   indices:

   ```json
   {
     "date_index_name": {
       "field": "timestamp",
       "date_rounding": "d",
       "index_name_prefix": "wazuh-custom-alerts-4.x-",
       "index_name_format": "yyyy.MM.dd",
       "ignore_failure": false,
       "if": "ctx.rule?.groups == '<your_group_name>'"
     }
   },
   ```

   This exact-equality condition only matches alerts whose rule has **that
   single group** — see the next section for the common multi-group case.

3. Upload the pipeline and restart services:

   ```bash
   filebeat setup --pipelines
   systemctl restart filebeat
   systemctl restart wazuh-manager
   ```

## Alerts with multiple rule groups

Most rules belong to several groups, in which case `rule.groups` is a list
and the equality check above never matches. Use a `contains` condition
instead:

```json
{
  "date_index_name": {
    "field": "timestamp",
    "date_rounding": "d",
    "index_name_prefix": "wazuh-custom-alerts-4.x-",
    "index_name_format": "yyyy.MM.dd",
    "ignore_failure": false,
    "if": "ctx.rule?.groups != null && ctx.rule.groups.contains('<your_group_name>')"
  }
},
```

You can key the condition on other fields the same way — for example on an
agent label: `"if": "ctx.agent?.labels?.group == 'db'"`. A processor accepts
only **one** `if`; combine multiple criteria with `&&` / `||` inside it.

## Make the new pattern usable

- **Index template:** the stock template only matches `wazuh-alerts-*` /
  `wazuh-archives-*`. If your prefix does not fall under those patterns
  (e.g. `custom-alerts-...`), new indices will get dynamic mappings and
  default shard settings. Keeping the `wazuh-` prefix scheme as above, or
  cloning `/etc/filebeat/wazuh-template.json` with an adjusted
  `index_patterns`, avoids that.
- **Dashboard index pattern:** create `wazuh-custom-alerts-*` under
  **Dashboard management > Index patterns** so the new indices are
  searchable from the UI.
- **Retention:** add the new pattern to your
  [ISM policy](ilm-retention.md#example-delete-alerts-after-90-days) —
  separated indices are usually separated precisely to give them different
  retention.
- Historical alerts already indexed into `wazuh-alerts-4.x-*` are not moved
  by the pipeline change; [reindex](reindexing.md) them if needed.

## Coordinating pipeline.json changes

`pipeline.json` is a single shared file also modified by the
[GeoIP country filtering](geoip.md#filtering-alerts-by-country) and
[timezone](misc-operations.md#showing-local-time-in-full_log) customizations.
All customizations must coexist in the same file, be re-uploaded together
with `filebeat setup --pipelines`, and be **re-applied after Wazuh upgrades**,
which ship a fresh pipeline. Keep your processors in version control or a
documented diff.
