# 5. Indexer high availability

Among the components in this stack, only the indexer is built for true HA:
three nodes, quorum voting, and every shard duplicated into a second
Availability Zone. Below is what to configure and the reasons behind each
choice.

Run commands from inside a pod, or prefix with
`kubectl -n wazuh exec wazuh-indexer-0 --`. Replace the admin password as
needed.

## 5.1 Quorum

A set of three master-eligible nodes survives the loss of one. Majority of
that set is required for cluster formation and for writes, which means 2 of 3.

When one node fails, the other two still hold a majority. If the failed node
was cluster manager, a new one is elected and writes continue. Health turns
yellow because replicas that lived on the lost node become unassigned.

When two fail, the remaining node cannot reach majority. There is no cluster
manager, writes stop, and the API surfaces master-not-discovered errors. No
knob changes this; that is how quorum works.

Four nodes do not improve on three. A majority of four is three, so you still
tolerate only one failure while paying for a fourth node. Scale three to five
instead of stopping at four.

```bash
curl -sk -u admin:PASS https://localhost:9200/_cluster/health?pretty
curl -sk -u admin:PASS https://localhost:9200/_cat/nodes?v
```

In the overlay, `discovery.seed_hosts` names all three pod DNS entries, unlike
the upstream base which seeds only node 0. A single seed means that if that
pod is missing during bootstrap, the cluster never forms.

## 5.2 Why zone awareness is not configured, and when you will need it

OpenSearch refuses to co-locate a primary and its replica on one node. With
exactly three indexer nodes, one in each of three AZs, "another node" already
means "another AZ". Shard and replica land in separate zones with no awareness
settings.

That only holds while you keep one node per zone. Scale to six nodes across
three AZs and each zone has two nodes; OpenSearch may then place a shard and
its replica on those two, putting both copies in one failure domain. Configure
allocation awareness then:

```yaml
# opensearch.yml on every node
node.attr.zone: ${NODE_ZONE}
cluster.routing.allocation.awareness.attributes: zone
cluster.routing.allocation.awareness.force.zone.values: eu-west-1a,eu-west-1b,eu-west-1c
```

Getting `NODE_ZONE` populated is the hard part. The Downward API exposes pod
fields only, so a pod cannot read its node's labels. Practical options:

- An init container whose ServiceAccount can `get nodes`, reading
  `topology.kubernetes.io/zone` from its own node and writing it into a shared
  `emptyDir` that the main container sources.
- One StatefulSet per AZ, with the zone value hardcoded. Crude, but no RBAC
  and no runtime plumbing.

Leave this unset until you need it. On three nodes with forced awareness across
three zones, losing a zone leaves replicas permanently unassigned instead of
relocating them. That behaviour is correct, yet yellow becomes the steady state
for the outage rather than a short-lived condition.

## 5.3 Replica count on the Wazuh indices

With `index.number_of_replicas: 1` you get one replica per primary: two copies
of the data. That is what lets an AZ fail without losing data.

Filebeat on the manager applies the Wazuh index templates from
`wazuh-template.json`. Nothing inside the indexer does that. Filebeat reapplies
the template on start, so a direct edit of that template can be wiped by a
manager restart or image upgrade.

Prefer a separate template at higher priority. Filebeat's template stays as-is;
yours wins:

```bash
curl -sk -u admin:PASS -X PUT \
  'https://localhost:9200/_index_template/wazuh-ha-replicas' \
  -H 'Content-Type: application/json' -d '{
    "index_patterns": ["wazuh-alerts-*", "wazuh-archives-*",
                       "wazuh-states-vulnerabilities-*", "wazuh-monitoring-*",
                       "wazuh-statistics-*"],
    "priority": 500,
    "template": {
      "settings": {
        "index.number_of_shards": 3,
        "index.number_of_replicas": 1,
        "index.refresh_interval": "5s"
      }
    }
  }'
```

Three primaries distribute a day's index across three nodes. One replica each
yields six shards per daily index, two per node.

Templates only affect indices created after they exist. Patch the ones you
already have once:

```bash
curl -sk -u admin:PASS -X PUT 'https://localhost:9200/wazuh-alerts-*/_settings' \
  -H 'Content-Type: application/json' -d '{"index":{"number_of_replicas":1}}'
```

Verify the live settings. The useful columns are `pri` and `rep`:

```bash
curl -sk -u admin:PASS 'https://localhost:9200/_cat/indices/wazuh-*?v&h=index,health,pri,rep,docs.count,store.size'
```

An index with `rep 0` has a single copy; if that node's disk dies, the data is
gone.

## 5.4 Delayed allocation

The overlay raises `index.unassigned.node_left.delayed_timeout` to `10m` from
the one-minute default.

One minute is shorter than a typical pod reschedule plus EBS detach and
reattach. During a normal rolling restart, OpenSearch decides the node is gone
for good and starts rebuilding every shard it held onto the other two nodes.
The original node then returns and the rebuild has to be reversed. On a cluster
with real data that is tens of minutes of wasted network and disk work, and it
repeats on every restart.

Ten minutes covers a reschedule without delaying rebuilds too long when a node
is truly dead.

## 5.5 Disk watermarks

Upstream sets `cluster.routing.allocation.disk.threshold_enabled: false`, which
disables the protection. The overlay turns it back on.

With watermarks off, nothing prevents a node from filling its disk. A full data
volume on an indexer is worse than read-only shards: recovery means growing the
volume or deleting indices on a node that may not even start cleanly. Overlay
thresholds are 80, 85 and 90 percent for low, high and flood stage, tighter than
OpenSearch defaults of 85, 90 and 95, to leave a SIEM more room for an ingestion
spike. That tightening is a local judgement call, not an upstream
recommendation.

Behaviour at each stage: at **low** the node gets no new shard allocations; at
**high** OpenSearch begins relocating shards off it; at **flood stage** every
index with a shard on that node is marked read-only and ingestion stops. Clearing
disk space does not lift the flood-stage block by itself:

```bash
curl -sk -u admin:PASS -X PUT 'https://localhost:9200/_all/_settings' \
  -H 'Content-Type: application/json' \
  -d '{"index.blocks.read_only_allow_delete": null}'
```

Size storage from retention. Rough formula: daily primary volume times retention
days times one plus the replica count (one replica doubles capacity). Leave
extra headroom for segment merges, shard relocation, translogs, and the
watermark you do not want to hit.

## 5.6 Probes

Readiness is TCP on 9200; liveness is TCP on 9300. That is what the overlay
uses.

An HTTP probe on 9200 would need credentials: the REST port requires auth and
returns 401 to anonymous callers. More critically, **never gate readiness on
cluster health being green**. Rolling restarts leave the cluster yellow for the
whole window, so a green-only readiness check means the first restarted pod
never becomes Ready, the rollout hangs, and liveness eventually kills the pod.

## 5.7 Rolling restarts

Safe sequence for config changes or upgrades:

```bash
# 1. Stop OpenSearch relocating shards while nodes come and go
curl -sk -u admin:PASS -X PUT 'https://localhost:9200/_cluster/settings' \
  -H 'Content-Type: application/json' \
  -d '{"persistent":{"cluster.routing.allocation.enable":"primaries"}}'

# 2. Flush, so recovery has less translog to replay
curl -sk -u admin:PASS -X POST 'https://localhost:9200/_flush'

# 3. Restart. A StatefulSet RollingUpdate replaces pods one at a time in
#    reverse ordinal order, waiting for each to be Ready.
kubectl -n wazuh rollout restart statefulset/wazuh-indexer
kubectl -n wazuh rollout status statefulset/wazuh-indexer --timeout=20m

# 4. Re-enable allocation
curl -sk -u admin:PASS -X PUT 'https://localhost:9200/_cluster/settings' \
  -H 'Content-Type: application/json' \
  -d '{"persistent":{"cluster.routing.allocation.enable":null}}'

# 5. Wait for green
curl -sk -u admin:PASS 'https://localhost:9200/_cluster/health?wait_for_status=green&timeout=10m&pretty'
```

Do not skip step 4. Leaving allocation restricted keeps the cluster yellow with
no end date. That is a frequent reason clusters "never recover" after
maintenance.

About `podManagementPolicy: Parallel`, which the overlay inherits from
upstream: some sources say this is unsafe for an indexer and should be
`OrderedReady`. That is wrong. `podManagementPolicy` only controls initial
create and scale; `RollingUpdate` still replaces one pod at a time. Switching
to `OrderedReady` breaks a fresh install, because bootstrap needs a quorum of
`cluster.initial_master_nodes` and pod 0 alone cannot form a cluster, so pod 1
is never created if pod 0's readiness is required first.

Next: [6. Expose agents and the dashboard](06-expose-agents.md).
