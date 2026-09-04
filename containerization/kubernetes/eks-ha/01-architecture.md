# 1. Architecture and what HA actually buys you

Read this before you provision. Later pages are procedural; the design choices
and their limits live here.

## Target topology

Two managers, three indexers, one dashboard, spread over three Availability
Zones in one region.

```
  Region
  +---------------------------+  +---------------------------+  +---------------------------+
  |  AZ a                     |  |  AZ b                     |  |  AZ c                     |
  |                           |  |                           |  |                           |
  |  manager master           |  |  manager worker           |  |  dashboard                |
  |    EBS 100 GiB            |  |    EBS 100 GiB            |  |    no volume              |
  |                           |  |                           |  |                           |
  |  indexer-0                |  |  indexer-1                |  |  indexer-2                |
  |    EBS 200 GiB            |  |    EBS 200 GiB            |  |    EBS 200 GiB            |
  |                           |  |                           |  |                           |
  |  node group ng-az-a       |  |  node group ng-az-b       |  |  node group ng-az-c       |
  +---------------------------+  +---------------------------+  +---------------------------+

  NLB (agent events 1514, enrollment 1515)  ->  managers
  ALB (dashboard 443)                       ->  dashboard
```

The EKS control plane is already highly available across three AZs and run by
AWS. This guide does not alter that, and that plane is not where failures show
up for this stack.

## The one thing to be clear about: there is no master failover

Wazuh 4.x allows exactly one master in a manager cluster. `node_type` is static
config. There is no leader election, no automatic worker-to-master promotion,
and no active/passive pair. That matches the
[types of nodes](https://documentation.wazuh.com/current/user-manual/wazuh-server-cluster/types-of-nodes.html)
docs; multi-master support is still an open feature request, not a shipped
feature. Wazuh 5.x leaves this unchanged as well.

So on Kubernetes, "HA for the master" means only this: **the StatefulSet
rebrings the same master, same identity, same volume, onto another node.** That
is failover by reschedule, not by election. You recover after a node failure.
You do not keep service during one, and you do not ride out loss of the
master's whole AZ without operator work.

The `<haproxy_helper>` block under `<cluster>` does not alter this. It spreads
agents across workers when the worker set changes; it does not address master
failure. See
[load balancers](https://documentation.wazuh.com/current/user-manual/wazuh-server-cluster/load-balancers.html).

### What keeps working while the master is down

This is why a single master is tolerable in practice, and it is better than
many expect:

- Agents that are already enrolled keep sending events on 1514 to the worker.
- The worker's `analysisd` keeps evaluating rules locally.
- The worker's own Filebeat keeps shipping alerts to the indexer.

Put differently: **detection and alerting continue**, and indexer data stays
current. See
[how the server cluster works](https://documentation.wazuh.com/current/user-manual/wazuh-server-cluster/how-server-cluster-works.html).

### What stops while the master is down

- **New agent enrollment.** `authd` runs on the master only; workers forward
  enrollment to it. Existing agents are unaffected, new ones cannot register.
- **The Wazuh API on 55000, and therefore most of the dashboard's agent
  management views.** Alert browsing still works, because that reads the indexer
  directly, not the API.
- **Agent group and `agent.conf` distribution.** Agents keep running their
  cached configuration; changes do not propagate.
- **`client.keys` as an authoritative record.** Workers hold read-only copies.
- **Rule, decoder and CDB list distribution**, since the master is where they
  are edited and synced from.
- **Cluster synchronisation.** `wazuh-clusterd` on the workers retries
  indefinitely; there is no documented timeout and no degradation beyond the
  above.

There is no hard deadline. Workers stay in this degraded-but-functional mode
for as long as needed.

## Failure matrix

What each failure actually does, assuming the layout above.

| Failure | Indexer | Managers | Dashboard | Automatic? |
|---------|---------|----------|-----------|-----------|
| One pod crashes | Restarted in place, same volume | Restarted in place, same volume | Restarted | Yes, seconds |
| One node drained (node group upgrade) | Pod moves to another node in the same AZ | Same | Moves anywhere | Yes, if spare capacity exists in that AZ |
| One node terminated | Same, once the Node object is removed | Same | Same | Yes, minutes. See timing below |
| One node hung but Node object still present | Pod stuck `Terminating` | Pod stuck `Terminating` | Recovers after 300s | **No, needs an operator** |
| One AZ lost | 2 of 3 nodes, quorum holds, cluster yellow, still writable | Whichever manager was there cannot reschedule | Moves to another AZ | Partly. See below |
| Two AZs lost | Quorum lost, no writes | Both likely down | Moves | No |

### Why a terminated node recovers but a hung node does not

This is the main operational fact in the design, and it is a Kubernetes
property, not a Wazuh one.

A StatefulSet guarantees at-most-one pod per ordinal. When a node stops
reporting, the pod is marked for deletion but **the replacement is not created
until the old pod object is actually gone**, because creating it earlier could
mean two pods with the same identity writing the same volume. Kubernetes
documents this in
[force deleting StatefulSet pods](https://kubernetes.io/docs/tasks/run-application/force-delete-stateful-set-pod/).

The paths diverge as follows:

- **Instance terminated.** The AWS cloud controller sees the EC2 instance is
  gone and deletes the Node object. Pod garbage collection then drops the pod,
  the volume detaches, and the StatefulSet creates the replacement. This is
  automatic. Budget several minutes end to end: roughly 40 seconds for the node
  to be marked NotReady, 300 seconds of default taint toleration, then volume
  detach and reattach.
- **Instance alive but wedged**, or a network partition. The Node object stays.
  The pod sits in `Terminating` forever. Nothing recovers until someone deletes
  the pod with `--force` or deletes the Node object.

For a Deployment such as the dashboard, none of this applies; a replacement pod
is created after the 300 second toleration regardless.

EBS helps here: a gp3 volume in `ReadWriteOnce` attaches to only one instance at
a time, so the storage layer blocks two masters writing the same data. A force
delete cannot cause split-brain writes in this setup; it can only leave a
replacement pod in `ContainerCreating` until the old attachment times out and
releases. That makes the force delete in
[7. Failure drills](07-failure-drills.md) safe to run, but confirm the node is
genuinely gone first.

### Why an AZ loss is different for the manager than for the indexer

EBS volumes are zonal. A PersistentVolume backed by EBS carries node affinity
for the AZ it was created in, so a pod using it can only ever be scheduled in
that AZ. That is fine for a node failure, because there are other nodes in the
same AZ. It is not fine for an AZ failure, because there are none.

- **Indexer** survives it by design. Three nodes means two remain, which is a
  quorum of three, so the cluster stays writable. With one replica shard and
  zone awareness there is a copy of every shard outside the failed AZ, so no
  data is lost. The cluster reports yellow because the replicas that lived in
  the dead AZ are unassigned, and yellow is the correct and expected state here.
- **Managers** do not. Whichever manager was in the failed AZ stays `Pending`
  until the AZ returns, because its volume cannot follow it. If that was the
  master, you are in the degraded mode described above until either the AZ
  recovers or you restore its volume from a snapshot into a surviving AZ.

That is why [8. Operations](08-operations.md) treats snapshotting the master's
volume as a hard requirement, not optional hygiene. Snapshots are what turn an
AZ loss from "wait it out" into "restore in another AZ".

### The EFS question

Putting the manager on EFS looks attractive because EFS is regional, so a pod
could land in any AZ. Do not put `/var/ossec/queue/db` there.

That path is SQLite databases with many small synchronous writes and file
locking. EFS is NFS: single-digit millisecond latency per operation versus
roughly half a millisecond for gp3, plus another millisecond or two when
crossing an AZ. `wazuh-db` latency is already the documented reason agents show
as disconnected on the master under load; see
[agent-info-sync-failures.md](../agent-info-sync-failures.md). Moving that
workload onto NFS makes the failure mode you are trying to avoid more likely,
in exchange for faster recovery from a rarer failure.

For cross-AZ manager recovery, snapshot and restore is the safer trade.

## Design decisions this leads to

Each of these is implemented somewhere later in the guide.

1. **One managed node group per AZ, each a single-AZ Auto Scaling group.** A
   multi-AZ ASG can replace a lost node in the wrong AZ, where the volume cannot
   follow. Covered in [2. Provision EKS](02-provision-eks.md).
2. **Spare capacity in every AZ**, so a rescheduled pod has somewhere to land in
   its own zone. Node group minimum size of two, not one.
3. **`WaitForFirstConsumer` on the StorageClass**, so a volume is created in the
   AZ where the pod was actually scheduled rather than an arbitrary one.
4. **`topologySpreadConstraints` over `topology.kubernetes.io/zone` for the
   indexer**, so the three nodes land in three AZs rather than two.
5. **Shard allocation awareness by zone on the indexer**, so a shard and its
   replica are never both in the same AZ. Covered in
   [5. Indexer HA](05-indexer-ha.md).
6. **Master and worker in different AZs**, so one AZ cannot take both.
7. **An NLB, not an ALB, for 1514 and 1515.** They are raw TCP; an L7 proxy
   parses the agent stream as HTTP and resets it. Covered in
   [6. Expose agents](06-expose-agents.md).
8. **Agents configured with more than one `<server>` entry**, so they fail over
   between managers themselves rather than depending on the load balancer alone.
9. **Snapshots of both the indexer indices and the manager volume**, because
   neither replication nor rescheduling is a backup.

## Capacity

Sizing here targets a few hundred agents. Scale from
[upgrading/sizing.md](../../../upgrading/sizing.md) for your own event rate,
and treat these as the starting point the rest of the guide assumes.

| Component | Count | Requests | Limits | Volume |
|-----------|-------|----------|--------|--------|
| Manager master | 1 | 1 vCPU, 2 GiB | 2 vCPU, 4 GiB | 100 GiB gp3 |
| Manager worker | 1 | 1 vCPU, 2 GiB | 2 vCPU, 4 GiB | 100 GiB gp3 |
| Indexer | 3 | 2 vCPU, 8 GiB | 4 vCPU, 8 GiB | 200 GiB gp3 |
| Dashboard | 1 | 200m, 512 MiB | 1 vCPU, 2 GiB | none |

Indexer heap is half the memory limit, so 4 GiB, set through
`OPENSEARCH_JAVA_OPTS`. Both `-Xms` and `-Xmx` get that value; a heap allowed to
grow just means the JVM is killed later rather than sooner.

One dashboard replica is intentional, not an oversight. It is stateless, it
reschedules anywhere, and it is outside the alert ingestion path, so a couple of
minutes of downtime costs a browser refresh. Use two replicas if you want
zero-downtime dashboard upgrades.

Next: [2. Provision the EKS cluster](02-provision-eks.md).
