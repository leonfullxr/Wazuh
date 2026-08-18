# Indexer Cluster Topology: Nodes, Voting, and Replicas

How many indexer nodes a cluster needs, how the cluster elects a cluster manager, and how replica shards relate to that election. These are three separate decisions. Teams often merge them into one and size the cluster wrong.

> **Applies to:** Wazuh indexer 4.x, which is based on OpenSearch 2.x. The voting
> model comes from OpenSearch. The index defaults and template paths are
> specific to Wazuh.

## Table of Contents

- [Three separate questions](#three-separate-questions)
- [Node roles](#node-roles)
- [Voting and quorum](#voting-and-quorum)
  - [The quorum formula](#the-quorum-formula)
  - [Fault tolerance by node count](#fault-tolerance-by-node-count)
  - [Why an even node count adds nothing](#why-an-even-node-count-adds-nothing)
  - [Split brain](#split-brain)
- [Replicas are copies, not votes](#replicas-are-copies-not-votes)
  - [Cluster health and node loss](#cluster-health-and-node-loss)
  - [The permanent yellow rule](#the-permanent-yellow-rule)
- [Combining the two limits](#combining-the-two-limits)
- [Bootstrapping a new cluster](#bootstrapping-a-new-cluster)
- [Inspect the live topology](#inspect-the-live-topology)
- [Change the topology safely](#change-the-topology-safely)
- [When to specialize node roles](#when-to-specialize-node-roles)
- [Related](#related)

## Three separate questions

Answer these one at a time. Each has a different constraint:

| Question | Decided by | Guide |
|---|---|---|
| How many nodes? | Quorum, then storage | [Voting and quorum](#voting-and-quorum) |
| How many copies of each shard? | Data redundancy | [Replicas are copies, not votes](#replicas-are-copies-not-votes) |
| Which roles does each node hold? | Cluster size | [Node roles](#node-roles) |

The common mistake is to treat replicas as the redundancy setting and node count as a storage decision. Node count decides whether the cluster stays available at all. Replicas decide whether the data survives. A cluster can hold every copy of its data and still refuse to serve it.

## Node roles

Every Wazuh indexer node carries four roles by default:

| Role | Function |
|---|---|
| `cluster_manager` | The node can be elected cluster manager. The cluster manager creates and deletes indices, tracks the other nodes, and decides shard placement |
| `data` | The node stores shards. It serves indexing, search, and aggregation |
| `ingest` | The node runs ingest pipelines before it indexes a document |
| `remote_cluster_client` | The node can connect to a remote cluster, for [cross-cluster search](cross-cluster-search.md) |

Because the default set includes `cluster_manager`, the node count and the voting count are normally the same number. This guide assumes the defaults. If you split the roles, read every rule below as a rule about **cluster-manager-eligible** nodes, not about all nodes.

OpenSearch renamed the `master` role to `cluster_manager`. Older settings and API paths that use `master` still work, and the documentation marks them as deprecated. Prefer the current names in new configuration.

## Voting and quorum

The cluster-manager-eligible nodes elect one active cluster manager. They also agree on every change to the cluster state, such as a new index or a moved shard. Both actions need a majority vote.

The nodes that vote are the **voting configuration**. The cluster maintains this set itself:

- A node joins the voting configuration when it joins the cluster.
- A node leaves the voting configuration when it shuts down cleanly.
- The setting `cluster.auto_shrink_voting_configuration` controls what happens after an unclean departure. The default value is `true`. The cluster then removes a departed node from the voting configuration, but only while the set keeps at least three nodes.

The voting configuration is therefore usually equal to the set of cluster-manager-eligible nodes. It can differ during a failure, so [inspect it directly](#inspect-the-live-topology) rather than assume.

### The quorum formula

For a voting configuration of `N` nodes:

```text
quorum   = floor(N / 2) + 1
failures = N - quorum
```

The cluster stays available while the number of reachable voting nodes is greater than or equal to the quorum. Below the quorum, the cluster has no elected cluster manager. It rejects writes and cluster-state changes even when every shard is present on disk.

### Fault tolerance by node count

| Cluster-manager-eligible nodes | Quorum | Node failures tolerated |
|---|---|---|
| 1 | 1 | 0 (single point of failure) |
| 2 | 2 | 0 (both nodes must stay available) |
| 3 | 2 | 1 |
| 4 | 3 | 1 |
| 5 | 3 | 2 |
| 6 | 4 | 2 |
| 7 | 4 | 3 |

> **A two-node cluster tolerates zero failures.** It is not a smaller form of
> high availability. It has twice the hardware of a single node, twice the
> failure surface, and the same tolerance of zero. Either accept one node, or
> deploy three.

### Why an even node count adds nothing

The tolerated failures follow `ceil(N / 2) - 1`. That value increases only when `N` moves from even to odd. Every even step adds one node to the cluster and one node to the quorum. The difference between them does not change.

A 4-node cluster tolerates exactly what a 3-node cluster tolerates. The fourth node adds storage, indexing throughput, and search capacity. It adds no resilience.

**Grow a cluster in odd numbers: 3, 5, 7.** Add an even-numbered node only when you need its capacity and you accept that it does not improve availability.

### Split brain

Two partitions of the same cluster can never both hold a majority. This is the property that makes the majority rule worth its cost. When a network splits a 5-node cluster into groups of 3 and 2, the group of 3 elects a cluster manager and continues. The group of 2 has no quorum and stops accepting writes. The two halves cannot diverge.

An even split of a 4-node cluster gives 2 and 2. Neither side reaches the quorum of 3, so the whole cluster stops. This is correct behavior and it is another reason to prefer odd counts.

## Replicas are copies, not votes

The `number_of_replicas` setting controls how many extra copies of each shard the cluster keeps:

```text
copies per shard = number_of_replicas + 1
```

A replica shard can never live on the same node as its primary. The cluster therefore needs at least `number_of_replicas + 1` **data** nodes to place every copy.

For Wazuh indices, set this in the index template at `/etc/filebeat/wazuh-template.json` before the next daily index is created. To change existing indices, or to fix the `.opendistro-*` system indices, see [replica management](replicas.md).

### Cluster health and node loss

Cluster health describes shard placement only. It says nothing about the quorum:

| State | Meaning |
|---|---|
| Green | Every primary and every replica is assigned |
| Yellow | Every primary is assigned. At least one replica is not |
| Red | At least one primary is not assigned. That data is unavailable |

A yellow cluster serves every search and accepts every write. It has lost redundancy, not data. A red cluster has lost access to part of the data.

### The permanent yellow rule

After the loss of `F` nodes, the cluster can return to green only while:

```text
number_of_replicas <= data_nodes - F - 1
```

Two consequences:

- **1 replica on 3 nodes.** Losing one node leaves two, and two copies still fit on two nodes. The cluster goes yellow, reallocates, and returns to green.
- **2 replicas on 3 nodes.** Three copies do not fit on two nodes. The cluster stays yellow until the node returns. No amount of waiting fixes it.

Setting more replicas than the cluster can place is a common cause of a cluster that never reaches green. Check the node count before you raise the replica count.

## Combining the two limits

The cluster survives the smaller of the two limits. Compute both, then take the lower number:

| Nodes | Replicas | Data survives | Quorum survives | Effective tolerance | Verdict |
|---|---|---|---|---|---|
| 1 | 0 | 0 | 0 | 0 | All-in-one. No HA |
| 2 | 1 | 1 | 0 | **0** | Wasteful. The quorum limit cancels the replica |
| 3 | 1 | 1 | 1 | **1** | Balanced. The normal Wazuh HA cluster |
| 3 | 2 | 2 | 1 | **1** | Permanent yellow after one loss. Do not use |
| 4 | 1 | 1 | 1 | **1** | The fourth node adds capacity only |
| 4 | 2 | 2 | 1 | **1** | The quorum limit wastes the second replica |
| 5 | 2 | 2 | 2 | **2** | Balanced. The next real step up from 3 |
| 5 | 1 | 1 | 2 | **1** | The replica limit wastes two nodes of resilience |

The balanced pairings are **3 nodes with 1 replica** and **5 nodes with 2 replicas**. Every other row spends hardware on a limit that something else already caps.

This answers the question that starts most of these discussions. "Can I run 2 replicas on a 4-node cluster?" Yes. The cluster places the data correctly. It still fails after two node losses, because two survivors cannot form a quorum of 3. Pair 2 replicas with 5 nodes.

> Replicas cost disk on every node and add to the cluster-wide shard count.
> Include them in [shard planning](shard-management.md#sizing-guidelines) and in
> [disk capacity](disk-management.md).

## Bootstrapping a new cluster

A new cluster needs to elect its first cluster manager before a voting configuration exists. Two settings in `/etc/wazuh-indexer/opensearch.yml` control that:

```yaml
discovery.seed_hosts:
  - <INDEXER_1_IP>
  - <INDEXER_2_IP>
  - <INDEXER_3_IP>
cluster.initial_cluster_manager_nodes:
  - <INDEXER_1_NAME>
  - <INDEXER_2_NAME>
  - <INDEXER_3_NAME>
```

Three rules apply to `cluster.initial_cluster_manager_nodes`:

1. List the **node names**, not the IP addresses. The names must match `node.name` on each node exactly.
2. List the same set on every node. A different set per node can bootstrap two separate clusters.
3. The setting applies **only to the very first start**. The cluster ignores it afterward. Leave it in place or remove it, but never edit it to bootstrap an existing cluster.

Never add a node to an existing cluster by listing it in `cluster.initial_cluster_manager_nodes`. Set `discovery.seed_hosts` and let the node join.

> The legacy setting `discovery.zen.minimum_master_nodes` no longer exists.
> OpenSearch computes the quorum from the voting configuration. Advice that
> tells you to set it by hand predates OpenSearch and Elasticsearch 7, and it
> does not apply to the Wazuh indexer.

## Inspect the live topology

Run these from **Indexer management > Dev Tools**, or with `curl` against `https://<INDEXER_IP>:9200`.

List the nodes and their roles. The `cluster_manager` column marks the elected node with `*`:

```http
GET _cat/nodes?v&h=name,node.role,cluster_manager,heap.percent,disk.used_percent
```

Show the current voting configuration. Use this to confirm which nodes actually vote:

```http
GET _cluster/state?filter_path=metadata.cluster_coordination.last_committed_config
```

Show the elected cluster manager:

```http
GET _cat/cluster_manager?v
```

Show health, plus the count of unassigned shards:

```http
GET _cluster/health
```

If shards do not assign, ask the cluster why:

```http
GET _cluster/allocation/explain
```

## Change the topology safely

### Add a node

1. Install the same indexer version as the running cluster.
2. Set `cluster.name` and `discovery.seed_hosts` to match the cluster. Do **not** set `cluster.initial_cluster_manager_nodes`.
3. Deploy certificates from the same root CA.
4. Start the node and confirm that it joins with `GET _cat/nodes?v`.
5. Wait for the cluster to return to green before you add the next node.

The voting configuration grows automatically. Remember that the tolerance improves only when the total reaches the next odd number.

### Remove a node

Removing a cluster-manager-eligible node changes the quorum. Exclude it from the voting configuration first, so the cluster shrinks the voting set in a controlled way:

```http
POST _cluster/voting_config_exclusions?node_names=<NODE_NAME>
```

Then stop the node, and clear the exclusion list afterward:

```http
DELETE _cluster/voting_config_exclusions
```

Clear the list. An exclusion that stays in place restricts future elections.

### Rolling restart

Stop one node at a time. Never stop enough nodes to lose the quorum. On a 3-node cluster that means exactly one node.

1. Stop shard reallocation, so the cluster does not copy shards during a short restart:

   ```http
   PUT _cluster/settings
   { "persistent": { "cluster.routing.allocation.enable": "primaries" } }
   ```

2. Restart one node. Wait until it rejoins.
3. Re-enable allocation and wait for green:

   ```http
   PUT _cluster/settings
   { "persistent": { "cluster.routing.allocation.enable": null } }
   ```

4. Repeat for the next node.

## When to specialize node roles

Two specializations are supported. Neither is worth its cost on a small cluster.

**Dedicated cluster-manager nodes.** Give three small nodes the `cluster_manager` role only, and remove that role from the data nodes. This isolates elections from heavy indexing load, so a saturated data node cannot destabilize the cluster. It also fixes the voting count at 3 while the data tier scales freely. Consider it above roughly ten data nodes.

**Hot and warm data tiers.** Tag nodes with an attribute, then use an ISM allocation action to move older indices onto nodes with slower disks. This puts cold data on cheap storage while hot data stays on fast storage.

Below roughly ten nodes, keep the default roles on every node. Role specialization makes maintenance and troubleshooting materially harder, and a small cluster rarely recovers that cost. Move data between phases with [ISM](ilm-retention.md) instead, and let the cluster place shards itself.

## Related

- [Replica management](replicas.md) - setting the replica count on existing and future indices, and the yellow single-node cluster
- [Shard management](shard-management.md) - shard sizing, primary counts, and cluster health states
- [Disk management](disk-management.md) - watermarks, read-only indices, and capacity planning
- [ISM retention](ilm-retention.md) - moving data between phases and deleting it on schedule
- [Sizing a Wazuh deployment](../upgrading/sizing.md) - node counts for every component, not only the indexer
- [Cross-cluster search](cross-cluster-search.md) - querying a remote indexer cluster
- [OpenSearch - cluster formation and voting](https://docs.opensearch.org/docs/latest/tuning-your-cluster/)
