# Sizing a Wazuh Deployment

Questionnaire and decision rules for sizing a distributed Wazuh deployment. It covers the inputs an architecture review needs and the node count for each component. It also covers where the data lands, and how to allocate storage that is already bought.

> **Applies to:** Wazuh 4.x distributed deployments on physical servers or VMs.
> The retention model and the node-count rules apply to any platform. The
> storage-layout section assumes local disks.

## Table of Contents

- [The sizing questionnaire](#the-sizing-questionnaire)
- [Two different retentions, both called "cold"](#two-different-retentions-both-called-cold)
- [Node counts per component](#node-counts-per-component)
- [Storage layout](#storage-layout)
- [Settings to get right at install time](#settings-to-get-right-at-install-time)
- [Worked example: 1250 endpoints](#worked-example-1250-endpoints)
- [Related](#related)

## The sizing questionnaire

Answer all of these before anyone provisions hardware. An architecture review cannot start without them:

| Input | Notes |
|---|---|
| Number of servers to monitor | Hosts and VMs running an agent |
| Number of workstations to monitor | Typically the largest count, and the lowest EPS per endpoint |
| Number of network devices | Devices sending syslog, not running an agent |
| Estimated cloud EPS | Events per second pulled from O365, Azure, GCP, AWS, and similar. Enter 0 if no cloud module is enabled |
| Indexer retention, in days | The period the data stays searchable in the dashboard. Covers all ISM phases together |
| Manager retention, in days | The period the compressed JSON files stay on the manager |
| Is HA a requirement | Determines the minimum node count for every component |
| Replica shards | 1 in any HA cluster. Doubles the indexed footprint |

Two of these are regularly misunderstood. "Cloud EPS" means events pulled from cloud service APIs, not the total event rate of the infrastructure. The two retention values describe two different stores, which the next section explains.

## Two different retentions, both called "cold"

This distinction causes more sizing errors than any other, because the word "cold" names two unrelated things.

| | Indexer retention | Manager retention |
|---|---|---|
| Where | Wazuh indexer (OpenSearch) | `/var/ossec/logs/alerts/<year>/<month>` and `/var/ossec/logs/archives/<year>/<month>` |
| Format | Indexed documents | Gzip-compressed JSON, rotated daily |
| Phases | Hot, warm, cold, delete, through ISM | None. One flat period |
| Searchable in the dashboard | Yes | No |
| Deleted automatically | Yes, by the ISM policy | **No.** A cronjob is required |
| Purpose | Day-to-day investigation | Recovery and long-term legal retention |

The "cold" phase of an ISM policy is a state of an index inside the indexer. It has nothing to do with the manager files.

The dashboard never reads the gzip files. The write path runs one way. The manager writes `alerts.json`, and Filebeat reads that live file and ships it to the indexer. The file is compressed and rotated at the end of the day. To search the archived data again you must re-ingest it. See [recovering data from alert backups](https://wazuh.com/blog/recover-your-data-using-wazuh-alerts-backups/).

Three consequences for sizing:

- **The manager files are never deleted for you.** Add a cronjob per path, matched to the agreed manager retention:

  ```bash
  0 0 * * * find /var/ossec/logs/alerts/   -type f -mtime +365 -exec rm -f {} \;
  0 0 * * * find /var/ossec/logs/archives/ -type f -mtime +365 -exec rm -f {} \;
  ```

- **The path is not configurable.** The compressed files are written locally. You cannot point the manager at a NAS. To move them off the node, copy or sync them out on a schedule.
- **Archives are optional and much larger than alerts.** `archives.json` holds every received event, not only the events that matched a rule. Enable it only when raw-event retention is a stated requirement, and size it separately.

## Node counts per component

Redundancy for every component does not mean the same node count for every component.

| Component | Minimum for HA | Rule |
|---|---|---|
| Indexer | 3 | Odd numbers only. See [cluster topology](../indexer/cluster-topology.md) |
| Manager | 2 | One master, one or more workers. Needs a load balancer in front |
| Dashboard | 2 | No clustering. Each one is independent and fully active |
| Load balancer | 2 | Otherwise it becomes the single point of failure for the whole deployment |

Three points that repeatedly surprise people:

- **A 4-node indexer cluster buys nothing over 3.** Both tolerate exactly one node failure. Grow 3, 5, 7. The reason is voting, not storage. See [voting and quorum](../indexer/cluster-topology.md#voting-and-quorum).
- **A manager cluster does not balance agents by itself.** Without a load balancer it runs in failover mode only. Every agent reports to whichever address is first in its own configuration. See [NGINX stream load balancer](../integrations/nginx/README.md).
- **Dashboards are not a cluster.** Deploy several, generate their certificates together from one root CA, and let users switch URL, or put them behind a load balancer. They consume few resources, so they can share a node with an indexer.

## Storage layout

The indexer requires **local disks on each node**. Do not consolidate all the large disks into one chassis and serve the other nodes from it. That reintroduces the single point of failure the cluster exists to remove, and it puts a network hop in the indexer write path.

When the hardware is already bought and cannot change, allocate it by this order of priority:

1. **Spread capacity across nodes before optimizing any single node.** Three nodes with 8 TB each beat one node with 20 TB and two with nothing. The second layout has more raw space and less usable redundancy. A replica cannot be placed on the same node as its primary, so capacity that exists on only one node cannot hold a replica.
2. **Prefer RAID 10 over RAID 6 for the indexer.** RAID 6 gives more usable space from the same disks. Its write penalty works directly against a near-real-time indexing workload. Use RAID 6 only for the manager archive volume, where writes are sequential and reads are rare.
3. **Put the manager database paths on the fastest media available.** `/var/ossec/queue/db` and `/var/ossec/var/db` are latency-sensitive in a way that the rest of the deployment is not. See [wazuh-db storage latency](../troubleshooting/server/wazuh-db-storage-latency.md).
4. **Size for the watermark, not for the disk.** The indexer stops allocating shards to a node before the disk is full. Plan steady-state usage well below the low watermark, and leave room for shard relocation after a node failure. See [disk management](../indexer/disk-management.md).

Calculate the indexer requirement as:

```text
indexed data = daily primary data x retention days x (1 + replicas)
```

Then add headroom for the watermark. A cluster that is exactly full at the delete phase has no room to relocate shards when a node fails.

## Settings to get right at install time

| Setting | Value |
|---|---|
| JVM heap | Half of system RAM, minimum and maximum equal, capped at 32 GB |
| Swap | Disabled |
| Replicas | 1 on any multi-node cluster, 0 on a single node |
| Index codec | Leave at the default. See [index codecs](../indexer/ilm-retention.md#index-codecs-and-compression) |
| Disk watermarks | Understand the defaults before changing them. See [disk management](../indexer/disk-management.md) |

There is no fixed "keep disks below 75 percent" rule. Indexing throttles under high indexing rates, mostly because Filebeat sends small batches of small documents. Disk occupation is governed separately by `cluster.routing.allocation.disk.watermark`, which stops allocation on a node or across the cluster once a threshold is passed.

## Worked example: 1250 endpoints

An estate of 160 servers, 1000 workstations, and 60 network devices, with HA required and 1 replica.

| Decision | Outcome |
|---|---|
| Indexer nodes | 3, not 4. A fourth adds storage but no extra fault tolerance |
| Manager nodes | 2, one master and one worker, behind a load balancer |
| Dashboard nodes | 2, co-located with indexer nodes |
| Load balancers | 2, co-located with the dashboards, on machines separate from the managers |
| Network devices | Syslog to an rsyslog collector that runs an agent, not straight to the manager |

The network-device decision is worth stating explicitly, because it is a resilience gap rather than a capacity one. Syslog senders have no buffering and no failover: if the receiver is unavailable, the events are simply lost. An rsyslog collector that runs an agent adds a disk buffer. The agent also encrypts the traffic. The syslog listener on the manager cannot do either. See [ingesting device syslog](../integrations/syslog/README.md#option-2-rsyslog-collector-plus-agent).

Do not treat the agent's own buffer as a substitute. It absorbs short EPS bursts and network delay only. Events generated while an agent is disconnected from the manager are lost.

## Related

- [Deployment architecture](deployment-architecture.md) - planning questions, reference hardware, and the firewall port matrix
- [Indexer cluster topology](../indexer/cluster-topology.md) - node counts, voting, quorum, replicas, and safe topology changes
- [ISM retention](../indexer/ilm-retention.md) - writing the policy that enforces the indexer retention period
- [Disk management](../indexer/disk-management.md) - watermarks, read-only indices, and recovery
- [Shard management](../indexer/shard-management.md) - shard sizing and the primary-count calculation
- [NGINX stream load balancer](../integrations/nginx/README.md) - balancing agent traffic, and load-balancer HA
- [Ingesting device syslog](../integrations/syslog/README.md) - collector architectures for network devices
- [Disaster recovery](disaster-recovery.md) - active/passive site design and failback
