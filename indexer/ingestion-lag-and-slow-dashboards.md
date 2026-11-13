# Ingestion lag and slow dashboards on a high-volume indexer

Dashboards are slow and events reach the indexer late, while the deployment has few users and a high archive volume. This guide shows how to find the saturated layer first, and then whether the Filebeat connection method (Kubernetes Service or an explicit host list) is worth changing at all.

**Applies to:** Wazuh 4.x managers shipping with Filebeat to the Wazuh indexer, including Kubernetes StatefulSet deployments with archiving enabled. Distilled from a support case on Wazuh 4.14.x with about 360 million archive events per day, three indexer pods, and Ceph RBD storage.

> OpenShift is not an officially supported platform for Wazuh. The guidance here depends on how Filebeat and the indexer behave, not on the orchestrator. Networking, security context constraints, and Ceph storage on OpenShift need review with your platform team or Red Hat.

## Table of Contents

- [Symptoms](#symptoms)
- [Decide what is saturated first](#decide-what-is-saturated-first)
- [Filebeat to indexer: Service or host list](#filebeat-to-indexer-service-or-host-list)
- [Filebeat load-balancing facts](#filebeat-load-balancing-facts)
- [Dashboard traffic](#dashboard-traffic)
- [Step 1: Confirm the live Filebeat output](#step-1-confirm-the-live-filebeat-output)
- [Step 2: Check the indexer write path](#step-2-check-the-indexer-write-path)
- [Step 3: Check replicas and what is indexed](#step-3-check-replicas-and-what-is-indexed)
- [Step 4: Check CPU requests, limits, and memory](#step-4-check-cpu-requests-limits-and-memory)
- [Step 5: Check storage latency](#step-5-check-storage-latency)
- [Step 6: Check Filebeat and the manager](#step-6-check-filebeat-and-the-manager)
- [Reading the results](#reading-the-results)
- [Testing failover and duplicates](#testing-failover-and-duplicates)
- [Data to collect](#data-to-collect)
- [Reference configuration and sizing](#reference-configuration-and-sizing)
- [Related](#related)

## Symptoms

- Dashboard searches are slow for everyone, even when few people use the dashboards. The load comes from ingestion, not from users.
- Events appear late in the dashboard (ingestion lag). Measure it as the gap between the event time and the time the event becomes searchable.
- `wazuh-archives-*` grows much faster than `wazuh-alerts-*`, and indexing does not keep up with the manager's output at peak.
- Filebeat logs show retries, HTTP `429`, or timeouts on bulk requests, or the periodic metrics show a growing queue.

## Decide what is saturated first

Changing the Filebeat connection method spreads bulk requests across indexer pods. It does not reduce the indexing work each event causes. Find the saturated layer before changing anything in Filebeat.

| Layer | Check | Points to a bottleneck when |
|---|---|---|
| Indexer write path | `write` thread pool `rejected` and `queue` | `rejected` keeps rising during peak ingestion |
| Indexer CPU | `cpu` in `_cat/nodes`, and throttling (step 4) | CPU stays high, or the indexer pods are throttled |
| Indexer heap | `heap.percent` and GC behavior | Sustained high values or long GC pauses |
| Storage | Write latency on the indexer volumes at peak (step 5) | Latency above the targets in the [storage latency guide](../troubleshooting/server/wazuh-db-storage-latency.md#storage-requirements) |
| Filebeat | Output counters and queue fill (step 6) | The queue stays full while the indexer keeps accepting requests |
| Network | Retransmits between managers and indexers | Packet loss or retransmits during peaks |

If the indexer rejects bulk writes or the storage latency is high, changing the Filebeat connection method will not fix the lag. Fix the saturated layer first.

## Filebeat to indexer: Service or host list

Filebeat can send to one Kubernetes Service URL, or to each indexer pod listed under `hosts`. Both are supported by Filebeat. Wazuh support reports that the wazuh-kubernetes v4.14.7 reference manifests point Filebeat at a single Service URL; confirm that in the tag you deploy. A host list is not documented as a Wazuh recommendation, but it is a reasonable option at high volume when the indexer has spare capacity.

| Concern | Kubernetes Service | Host list with `loadbalance: true` |
|---|---|---|
| What gets balanced | TCP connections. kube-proxy picks a pod when a connection opens | Bulk requests, across the configured hosts |
| Clients per Filebeat | One per worker, because the Service is one host entry | One per host per worker (total = hosts x worker) |
| Balance with few managers | Can be uneven. Each manager's connection stays with one indexer pod | Each manager reaches every indexer pod |
| Indexer pod down | kube-proxy stops routing to it. A connection on that pod breaks and reconnects to a live pod | Filebeat sends to the remaining hosts after the error |
| Ingest pipeline CPU | Concentrated on the pods that receive the connections | Spread across pods, because the node that receives a bulk request runs the pipeline |
| Maintenance | Nothing to change when pods scale | The host list must change when the StatefulSet is scaled |
| TLS | The certificate must match the Service name | With `ssl.verification_mode: 'full'`, each pod name (or a matching wildcard) must be in the certificate SAN |
| Total indexing work | Same | Same |

Neither option reduces total indexing work. The host list spreads pipeline CPU and request coordination more evenly, so it helps most when the pods are unevenly loaded and the indexer has headroom. If the indexer is saturated, the gain is small.

## Filebeat load-balancing facts

These are taken from the Filebeat 7.10 reference, which Wazuh 4.x bundles. Check them against the Filebeat version in your manager image.

- **Enable it explicitly:** the 7.10 load-balancing page documents `loadbalance: true` as the switch. Do not assume it is on by default.
- **Clients:** the total number of load-balancing workers is hosts x `worker`. `worker` defaults to 1 per host.
- **Batch size:** `bulk_max_size` defaults to 50 in 7.10. A sample configuration sets 1024. Larger batches mean fewer requests, but a failed request retries more events at once.
- **Retries:** the 7.10 Elasticsearch output page states that Filebeat ignores `max_retries` and retries indefinitely. A slow or failing indexer therefore shows up as a growing queue and lag, not as dropped events. Watch the queue.
- **Reconnect backoff:** after a network error, a host waits `backoff.init` (1s by default) before reconnecting. The wait grows exponentially up to `backoff.max` (60s by default).
- **Delivery is at least once:** an event that was sent but not acknowledged (timeout, restart, or an indexer pod killed mid-request) is sent again. Duplicates are possible with either connection method. Filebeat only avoids them when each event has a deterministic `_id` (the `document_id` option). Check whether the Wazuh archive pipeline in your version sets one before you count duplicates as a fault.

## Dashboard traffic

Keep the Kubernetes Service for Dashboard-to-indexer requests. Dashboard request volume is low for a small user group, so a host list adds configuration without a clear gain. When dashboards are slow in this situation, the likelier cause is that the indexer nodes are busy with ingestion, because searches and bulk indexing share the same CPU, heap, and disk.

## Step 1: Confirm the live Filebeat output

A support case often shows a host-list configuration while the description says traffic goes through a Service, or the reverse. Confirm what the running manager actually uses before changing anything. Check every manager pod, because each one runs its own Filebeat.

```bash
kubectl -n wazuh exec <MANAGER_POD> -- grep -A6 'output.elasticsearch' /etc/filebeat/filebeat.yml
kubectl -n wazuh exec <MANAGER_POD> -- filebeat test output
```

`filebeat test output` runs a connection and TLS check for each configured host. One line group per host confirms a host list. A single group pointing at the Service name confirms a Service.

## Step 2: Check the indexer write path

Run these in Dev Tools (or with `curl` against the indexer):

```http
GET _cluster/health
GET _cat/nodes?v&h=name,node.role,cpu,load_1m,heap.percent,ram.percent,disk.used_percent
GET _cat/thread_pool/write?v&h=node_name,active,queue,rejected,completed
GET _nodes/hot_threads
```

How to read them:

- `rejected` on the write pool counts bulk requests the indexer refused because its queue was full. Filebeat retries them, so rejections show up as backlog and lag rather than silently missing events. What matters is whether the count keeps rising during the peak.
- High `cpu` with `hot_threads` showing indexing or ingest threads means the nodes need more CPU, less volume, or a cheaper pipeline.
- A yellow or red cluster during ingestion changes the picture. Fix shard state first, using [shard management](shard-management.md#cluster-health-red-and-yellow-states).

For rates, run the `_nodes/stats` calls in [Data to collect](#data-to-collect) twice, about five minutes apart, during the peak.

## Step 3: Check replicas and what is indexed

```http
GET _cat/indices/wazuh-*?v&s=index&h=index,health,pri,rep,docs.count,pri.store.size,store.size
GET _cat/shards/wazuh-archives-*?v&s=index
```

- Each replica adds a second copy to write and store. For those indices, indexing work and disk use roughly double. Read the `rep` column rather than assuming a value.
- Replicas are a durability choice. Dropping them to gain speed means accepting that a lost node takes its copies with it. Make that decision explicitly, not as a performance fix.
- Size disk from retention: daily primary volume x retention days x (1 + replicas), plus headroom for merges and shard relocation. See [replica management](replicas.md) and [disk management](disk-management.md).

Whether archives are indexed is a separate question from whether they are written:

- The manager writes archive files when `logall_json` is enabled in the `<global>` block of `ossec.conf`. The Filebeat `archives` setting only controls whether those files are also indexed.
- Whether archive events must be searchable is a retention and access decision. If the requirement is compliance retention, the archive files on disk, backed up or shipped to cheaper storage, may meet it without indexing every event. Confirm with the owner of that requirement, and keep the files either way.
- If you stop indexing archives, measure the change with the rate method. Ingestion load drops by roughly the archive share of the write rate.

## Step 4: Check CPU requests, limits, and memory

In Kubernetes, the CPU request is what the scheduler reserves for the pod, and it sets the pod's share when the node is busy. The CPU limit is a ceiling. A pod that reaches its limit is throttled even when the node has idle CPU. For write-heavy indexer pods, keep the request close to the limit so the capacity you pay for is actually reserved.

```bash
kubectl -n wazuh get pod <INDEXER_POD> -o jsonpath='{.spec.containers[0].resources}{"\n"}'
kubectl -n wazuh top pods
kubectl -n wazuh exec <INDEXER_POD> -- cat /sys/fs/cgroup/cpu.stat    # cgroup v2; on v1 use /sys/fs/cgroup/cpu/cpu.stat
kubectl -n wazuh describe pod <INDEXER_POD> | grep -A3 -E 'Last State|Restart Count'
```

In `cpu.stat`, compare `nr_throttled` with `nr_periods`. A rising ratio during peaks means the limit is the bottleneck. The `describe` output shows `OOMKilled` and restart counts.

For memory, the JVM heap should be about half the container memory limit, with `-Xms` equal to `-Xmx`. A 16 GiB limit with an 8 GiB heap leaves the rest for the OS page cache, which Lucene depends on.

## Step 5: Check storage latency

Indexing, refreshes, and segment merges issue many small writes. They are sensitive to write latency, so storage is one of the first things to measure. Network block storage such as Ceph RBD adds latency to every write.

Measure write latency and throughput on the indexer volumes at peak, from storage-side metrics if you have them, or from the node hosting each pod. Compare the results with the [storage requirements](../troubleshooting/server/wazuh-db-storage-latency.md#storage-requirements) and read the [Ceph RBD guidance](../troubleshooting/server/wazuh-db-storage-latency.md#ceph-rbd-guidance), which applies to indexer volumes as well. If latency is high, have the storage team fix it before anyone tunes Filebeat.

## Step 6: Check Filebeat and the manager

The sample configuration enables Filebeat metrics logging (`logging.metrics.enabled: true`). The periodic metrics lines report output and pipeline counters. Look for:

- Acknowledged versus failed and dropped events in the output counters.
- Queue fill in the pipeline counters.

A queue that stays full while the indexer keeps acknowledging requests means Filebeat reads faster than it can publish. That points to the indexer or the network, not to the choice between Service and host list.

Filter the logs for the signatures that matter:

```bash
kubectl -n wazuh logs <MANAGER_POD> | grep -iE '429|rejected|Failed to publish|timeout|backoff'
```

Two Filebeat checks are easy to miss:

- **Lag versus rotation:** if the lag grows longer than the time archive files stay on disk before rotation or deletion, Filebeat can lose data. Compare the lag with your rotation settings.
- **Registry across restarts:** Filebeat records how far it has read each file in its registry, under its data path. If that path is not on a volume that survives pod restarts, a restarted manager pod has no record and can send archive events again, which creates duplicates. Find the data path in your manifest and check whether a volume backs it. Verify with the count method in [Testing failover and duplicates](#testing-failover-and-duplicates) after any restart.

Also check the manager's analysis state, because a slow manager makes the indexer look idle:

```bash
kubectl -n wazuh exec <MANAGER_POD> -- cat /var/ossec/var/run/wazuh-analysisd.state
```

Look at queue usage and dropped events, as described in [analysisd](../troubleshooting/server/analysisd.md#measuring-eps).

> **Sample queue sizing:** the sample `queue.mem.events: 16384` has a comment that says "4 x bulk_max_size x workers". With `worker: 1` and three hosts (three clients), that formula gives 12288, not 16384. Treat the queue size as a tunable and check its comment against your host and worker count.

## Reading the results

| Observation | Next step |
|---|---|
| Write-pool rejections climb and indexer CPU is high | Add indexer CPU or nodes, reduce the indexed volume (for example, archives), or review the ingest pipeline cost. More Filebeat parallelism will not help and may increase rejections |
| Storage write latency is high at peak | Fix storage first, then revisit CPU |
| Indexer pods show CPU throttling | Raise the CPU request and limit, or reduce load |
| Indexer healthy, no rejections, Filebeat queue full | Check the network path and the Filebeat output. A host list can help when one Service endpoint is hot |
| Indexer healthy, Filebeat queue empty, but events are late | The delay is before Filebeat: check analysisd and the manager's archive writes |
| Indexer and Filebeat healthy, dashboards still slow | Look at the query side: time ranges, index patterns, and shard counts ([shard management](shard-management.md)). The connection method is not the cause |
| Document counts exceed archive line counts after a restart | Registry persistence and document IDs (step 6 and the section below) |

## Testing failover and duplicates

Use a controlled test to answer the open questions for your own cluster, rather than relying on documentation alone.

1. In a quiet window, record `_cat/thread_pool/write` and the Filebeat output counters on each manager.
2. Restart one indexer pod during moderate load: `kubectl -n wazuh delete pod <INDEXER_POD>`. Watch how quickly the other pods take the load, and whether Filebeat's failed counter rises and then recovers.
3. For duplicates and loss, pick a day whose archive file is complete (not today's file). Count its lines and compare with the document count for that day:

```bash
kubectl -n wazuh exec <MANAGER_POD> -- wc -l /var/ossec/logs/archives/<YYYY>/<Mon>/ossec-archive-<DD>.json
```

```http
GET wazuh-archives-*/_count
{
  "query": { "range": { "<TIME_FIELD>": { "gte": "<DAY_START>", "lt": "<NEXT_DAY_START>" } } }
}
```

Confirm `<TIME_FIELD>` with `GET wazuh-archives-*/_mapping` for your version. Each archive file line is one event. A document count above the line count points to duplicates. Below it points to loss or to events still in flight.

## Data to collect

Collect these during a period of high ingestion so the rates reflect the peak.

- **Indexer:** the Dev Tools requests from step 2, plus:

  ```http
  GET _nodes/stats/indices/indexing,refresh,merge
  GET _nodes/stats/ingest
  GET _nodes/stats/http
  ```

  Run the `_nodes/stats` calls twice, about five minutes apart. The rate per node is (second value minus first value) divided by the elapsed seconds, for example `indices.indexing.index_total`.
- **Filebeat, each manager pod:** about 15 minutes of logs, including the periodic metrics lines and the grep from step 6.
- **Manager:** the analysisd state file from step 6, and `kubectl -n wazuh top pods`.
- **Kubernetes:** the indexer pods' resource requests and limits, restart counts, `OOMKilled` events, and CPU throttling metrics where your monitoring has them. On OpenShift, `oc` takes the same arguments.
- **Storage:** write latency and throughput on the indexer volumes at peak.
- **Network:** retransmits between manager and indexer nodes at peak, if available.

## Reference configuration and sizing

- The supported reference for Kubernetes is the [wazuh-kubernetes repository](https://github.com/wazuh/wazuh-kubernetes) at the tag that matches your Wazuh version. It covers Amazon EKS and local Kubernetes. This repo's [highly available EKS guide](../containerization/kubernetes/eks-ha/) shows a full build.
- No OpenShift reference configuration or OpenShift-specific sizing guidance exists.
- Sizing depends mainly on events per second, retention, replica count, and whether archives are indexed. Start with the [sizing guide](../upgrading/sizing.md).

Worked arithmetic from the case: about 360 million events per day, divided by 86,400 seconds, is about 4,150 events per second on average. Size for the peak rate, not the average, and measure the peak with the two-snapshot method. The sample `bulk_max_size: 1024` and `timeout: 90s` are starting points, not measured optima.

## Related

- [Indexer README](README.md) - the write path and the quick reference
- [Replica management](replicas.md) and [Shard management](shard-management.md)
- [Disk management](disk-management.md) and [Cluster topology](cluster-topology.md)
- [Kubernetes guides](../containerization/kubernetes/README.md) and [Indexer HA on EKS](../containerization/kubernetes/eks-ha/05-indexer-ha.md)
- [Red Hat OpenShift / OKD](../containerization/kubernetes/openshift.md) - support status and SCC notes
- [Archives disabled after pod update](../containerization/kubernetes/archives-disabled-after-update.md) - if archive indexing stopped after an upgrade
- [wazuh-db storage latency](../troubleshooting/server/wazuh-db-storage-latency.md) - storage requirements and Ceph RBD guidance
- [Analysisd, EPS, and dropped events](../troubleshooting/server/analysisd.md) - manager-side queues and EPS measurement
- [IndexerConnector queue growth](../troubleshooting/server/indexer-connector-queue-growth.md) - a different symptom: manager-side queue growth, not indexer write pressure
