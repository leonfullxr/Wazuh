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
- [Single cluster with logical separation vs. separate clusters](#single-cluster-with-logical-separation-vs-separate-clusters)
- [Where separation happens: manager vs index level](#where-separation-happens-manager-vs-index-level)

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
   single group** - see the next section for the common multi-group case.

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

You can key the condition on other fields the same way - for example on an
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
  [ISM policy](ilm-retention.md#example-delete-alerts-after-90-days) -
  separated indices are usually separated precisely to give them different
  retention.
- Historical alerts already indexed into `wazuh-alerts-4.x-*` are not moved
  by the pipeline change; [reindex](reindexing.md) them if needed.

## Coordinating pipeline.json changes

`pipeline.json` is a single shared file also modified by the
[GeoIP country filtering](geoip.md#filtering-alerts-by-country) and
[timestamp formatting](ingest-pipeline-customization.md) customizations.
All customizations must coexist in the same file, be re-uploaded together
with `filebeat setup --pipelines`, and be **re-applied after Wazuh upgrades**,
which ship a fresh pipeline. Keep your processors in version control or a
documented diff.

## Single cluster with logical separation vs. separate clusters

Routing multiple environments (sites, tenants) into one indexer cluster and separating them only by index prefix - as the [procedure above](#procedure) does - is perfectly valid for Wazuh; the manager and indexer do not care that several prefixes coexist. Wazuh does not mandate one model over the other; the right choice depends on scale and how you operate the data.

| | One cluster, logical (index-prefix) separation | Separate clusters / environments per site |
|---|---|---|
| Resources & cost | Fewer nodes, less overhead | More nodes and infrastructure |
| Central visibility | Simple - everything in one dashboard | Needs a centralized console / cross-cluster search |
| Data isolation | Weaker - all data shares one cluster | Strong - physical separation |
| Per-source resourcing | Not possible - one shared resource pool | Each environment sized independently |
| Main scaling limit | **Shard growth** (below) caps retention before adding nodes | Each cluster scales on its own |

The decisive constraint for the single-cluster model is **shard accumulation**: every prefix is another daily index, so total shards grow with sources × retention, and each indexer node handles ~1000 shards by default. The more logical environments you fold into one cluster, the sooner you reach that ceiling. Work the numbers for your retention and source count with the [shard-planning example](shard-management.md#worked-example-planning-shard-count-for-retention-and-many-sources) before committing.

Rule of thumb: a single cluster with logical separation is fine for a **small, stable** number of sources; lean toward separate environments with a centralized console when the number of sources is **medium-to-large or growing**, or when you need per-source resourcing or hard data isolation.

## Where separation happens: manager vs index level

A related design choice is how agents reach the manager cluster, because it decides whether events are even separable at the manager level:

- **Load balancer → any worker** (agents connect to one LB address on 1514/1515, distributed across workers). What most multi-node deployments use: any worker can replace another, giving the best availability and resource use. The trade-off is that **events from all sites are mixed** across workers, so separation can then happen only at the index level (the pipeline routing above).
- **Dedicated worker per agent group** (agents statically assigned to a specific worker per site). Keeps each site's events **separated from ingestion** at the manager level - convenient when you must hand a client only their own logs, or recover one site's data in isolation. The trade-off is weaker resilience: no automatic failover to another worker.

The LB choice does not fully lock you in: even with mixed logs you can still separate at the index level **provided agents carry a group label or have identifiable names** to key the pipeline condition on (`ctx.agent?.labels?.group`, agent-name patterns). But separating cleanly from the start - by dedicated worker, or by a planned label scheme - is far less work than untangling mixed data later.

See [AWS load balancer](../troubleshooting/agents/aws-load-balancer.md) and [Kubernetes load balancing & ingress](../containerization/kubernetes/load-balancing-and-ingress.md) for the load-balancer implementation and its pitfalls.
