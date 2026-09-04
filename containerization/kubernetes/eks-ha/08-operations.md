# 8. Operations

Backups, upgrades, and the few tasks whose procedure is easy to get wrong.

## 8.1 Snapshot the manager volumes

Required, not optional hygiene. Without it, an AZ loss is "wait for AWS"; with
it, you can restore into another zone per the runbook in
[7. Failure drills](07-failure-drills.md). Replication does not help: there is
one master and its state sits on one zonal volume.

Target the volume tags the EBS CSI driver applies, via AWS Backup or a Data
Lifecycle Manager policy.

```bash
# Find the volumes
kubectl -n wazuh get pv -o custom-columns=\
'PV:.metadata.name,CLAIM:.spec.claimRef.name,VOLUME:.spec.csi.volumeHandle'

# One-off snapshot
aws ec2 create-snapshot --volume-id vol-xxxx \
  --description "wazuh manager master $(date -Is)" \
  --tag-specifications 'ResourceType=snapshot,Tags=[{Key=app,Value=wazuh},{Key=component,Value=manager-master}]'
```

A DLM policy on `tag:kubernetes.io/created-for/pvc/name` with a daily schedule
and a fortnight of retention is sufficient. Snapshot the worker as well; it is
cheap and avoids a re-sync later.

Alternatively use the CSI snapshotter and keep snapshots as Kubernetes objects
if you already run the external-snapshotter and a `VolumeSnapshotClass`. Either
approach works. Skipping both does not.

**Test a restore.** An untested snapshot is a belief, not a backup. The restore
path requires an exact PVC name; hit that requirement in staging before you
need it.

## 8.2 Snapshot the indexer to S3

Separate from volume snapshots, and the right tool for index data because
restore is per index.

The `repository-s3` plugin is **not bundled** in `wazuh/wazuh-indexer:4.14.7`.
Verified against the image:

```bash
docker run --rm --entrypoint ls wazuh/wazuh-indexer:4.14.7 \
  /usr/share/wazuh-indexer/plugins/
```

`repository-s3` is absent from that list, and plugins cannot be installed into a
running node, so S3 snapshots need a custom image.

```dockerfile
FROM wazuh/wazuh-indexer:4.14.7
USER 0
# The image ships no /etc/sysconfig/wazuh-indexer, which opensearch-env sources
# when OPENSEARCH_PATH_CONF is unset, so the plugin tool fails with a confusing
# "No such file or directory" unless this is set explicitly.
ENV OPENSEARCH_PATH_CONF=/usr/share/wazuh-indexer/config
RUN /usr/share/wazuh-indexer/bin/opensearch-plugin install --batch repository-s3 \
 && chown -R 1000:1000 /usr/share/wazuh-indexer/plugins
USER 1000
```

Build, push to ECR, and point the indexer StatefulSet at that image. Plugin
version follows the bundled OpenSearch version (2.19.5 for Wazuh 4.14.7); no
manual pin is required.

Register the repository next. On credentials: `repository-s3` uses the
standard AWS credential chain, so IRSA should work, but open OpenSearch issues
describe web identity tokens that are not refreshed - snapshots succeed for
about an hour then fail. Keys in the keystore are the reliable option. If you
use IRSA, alert on snapshot failure instead of assuming it keeps working.

```bash
# Keystore credentials, on every node, then reload
kubectl -n wazuh exec wazuh-indexer-0 -- bash -c \
 'echo "$AWS_KEY" | /usr/share/wazuh-indexer/bin/opensearch-keystore add --stdin --force s3.client.default.access_key'
kubectl -n wazuh exec wazuh-indexer-0 -- bash -c \
 'echo "$AWS_SECRET" | /usr/share/wazuh-indexer/bin/opensearch-keystore add --stdin --force s3.client.default.secret_key'

curl -sk -u admin:PASS -X POST 'https://localhost:9200/_nodes/reload_secure_settings'

curl -sk -u admin:PASS -X PUT 'https://localhost:9200/_snapshot/s3_backup' \
  -H 'Content-Type: application/json' -d '{
    "type": "s3",
    "settings": { "bucket": "my-wazuh-snapshots", "region": "eu-west-1",
                  "base_path": "wazuh-ha", "server_side_encryption": true }
  }'
```

Automate with a snapshot management policy rather than a CronJob:

```bash
curl -sk -u admin:PASS -X POST 'https://localhost:9200/_plugins/_sm/policies/wazuh-daily' \
  -H 'Content-Type: application/json' -d '{
    "description": "Daily Wazuh snapshot",
    "creation":  { "schedule": { "cron": { "expression": "0 2 * * *", "timezone": "UTC" } } },
    "deletion":  { "condition": { "max_age": "30d", "max_count": 30 } },
    "snapshot_config": { "repository": "s3_backup", "indices": "wazuh-*" }
  }'
```

The `opensearch-index-management` plugin that provides this is already in the
image.

## 8.3 Retention

Two separate problems.

**Indexer indices.** Use ISM. Without a policy, indices accumulate until a
watermark stops ingestion.

```bash
curl -sk -u admin:PASS -X PUT 'https://localhost:9200/_plugins/_ism/policies/wazuh-retention' \
  -H 'Content-Type: application/json' -d '{
    "policy": {
      "description": "Wazuh alert retention",
      "default_state": "hot",
      "states": [
        { "name": "hot",
          "actions": [],
          "transitions": [ { "state_name": "delete", "conditions": { "min_index_age": "90d" } } ] },
        { "name": "delete", "actions": [ { "delete": {} } ], "transitions": [] }
      ],
      "ism_template": [ { "index_patterns": ["wazuh-alerts-*"], "priority": 100 } ]
    }
  }'
```

Archives grow much faster than alerts and usually need shorter retention. See
[indexer/](../../../indexer/) for rollover and ISM decisions in more depth.

**Manager logs.** The manager never prunes `/var/ossec/logs/alerts` or
`/var/ossec/logs/archives`, and the path is not configurable, so the volume
fills eventually. A CronJob against the master's PVC is the usual answer:

```bash
find /var/ossec/logs/alerts/   -type f -mtime +90 -delete
find /var/ossec/logs/archives/ -type f -mtime +30 -delete
```

## 8.4 Upgrading Wazuh

Order: indexer, then managers, then dashboard. Take snapshots first.

```bash
# 1. Indexer, using the rolling restart procedure in 05-indexer-ha.md
kubectl -n wazuh set image statefulset/wazuh-indexer wazuh-indexer=wazuh/wazuh-indexer:4.14.8
kubectl -n wazuh rollout status statefulset/wazuh-indexer --timeout=30m

# 2. Master, then worker
kubectl -n wazuh set image statefulset/wazuh-manager-master wazuh-manager=wazuh/wazuh-manager:4.14.8
kubectl -n wazuh rollout status statefulset/wazuh-manager-master --timeout=15m
kubectl -n wazuh set image statefulset/wazuh-manager-worker wazuh-manager=wazuh/wazuh-manager:4.14.8
kubectl -n wazuh rollout status statefulset/wazuh-manager-worker --timeout=15m

# 3. Dashboard
kubectl -n wazuh set image deployment/wazuh-dashboard wazuh-dashboard=wazuh/wazuh-dashboard:4.14.8
```

Prefer bumping the tag in the overlay and re-applying so cluster state matches
git. Use `set image` when you need the change immediately.

After any manager image change, check two things:

**Archives.** If you use the archives module, confirm it is still enabled. The
manager entrypoint regenerates `/etc/filebeat/filebeat.yml` at every start from
a template inside the image, after volumes are mounted, and that template ships
archives disabled. A ConfigMap mounted at the destination path is silently
overwritten. Mount over the source template at
`/var/ossec/data_tmp/exclusion/etc/filebeat/filebeat.yml` instead. Full
write-up in [archives-disabled-after-update.md](../archives-disabled-after-update.md).

```bash
kubectl -n wazuh exec wazuh-manager-master-0 -- grep -A3 archives /etc/filebeat/filebeat.yml
```

**`ossec.conf` drift.** Upstream `master.conf` and `worker.conf` change between
releases. Diff the new files against yours before assuming your copies are still
current.

## 8.5 Upgrading the cluster

Control plane first, then node groups, then addons.

```bash
eksctl upgrade cluster --name wazuh-ha --version 1.36 --approve

# One node group at a time. The indexer PDB paces evictions.
for ng in ng-indexer-1a ng-indexer-1b ng-indexer-1c \
          ng-manager-1a ng-manager-1b ng-manager-1c; do
  eksctl upgrade nodegroup --cluster wazuh-ha --name "$ng" --kubernetes-version 1.36
done

eksctl utils update-addon --cluster wazuh-ha --name vpc-cni --version latest
eksctl utils update-addon --cluster wazuh-ha --name aws-ebs-csi-driver --version latest
```

Upgrade manager node groups in a maintenance window. Draining the master's node
restarts the master, which costs enrollment and the API for a few minutes, and
no PDB can prevent that for a single-pod workload.

Keep the Cluster Autoscaler's minor version aligned with the cluster's.

## 8.6 Scaling

**Indexer**, three to five. Never four; a majority of four is three, so it
tolerates the same single failure as three.

```bash
kubectl -n wazuh scale statefulset wazuh-indexer --replicas=5
```

Add matching node groups first. Once you have more nodes than AZs, read
[5.2](05-indexer-ha.md) on allocation awareness: "different node" no longer
implies "different AZ".

**Manager workers**, freely. This is how you add manager capacity.

```bash
kubectl -n wazuh scale statefulset wazuh-manager-worker --replicas=3
```

Past three you must relax worker anti-affinity from
`requiredDuringScheduling` to `preferredDuringScheduling`, or extra pods stay
`Pending` for want of a fourth AZ.

**Manager master**, never. There is exactly one. Scaling the StatefulSet above
one creates a second pod that will not act as a second master.

**Storage.** `allowVolumeExpansion: true` allows online growth, but
`volumeClaimTemplates` are immutable, so the template and live PVCs must change
separately:

```bash
kubectl -n wazuh patch pvc wazuh-indexer-wazuh-indexer-0 \
  -p '{"spec":{"resources":{"requests":{"storage":"400Gi"}}}}'
```

Update the overlay to match, then recreate the StatefulSet with
`--cascade=orphan` so the change sticks without deleting the pods:

```bash
kubectl -n wazuh delete statefulset wazuh-indexer --cascade=orphan
kubectl apply -k envs/eks-ha/
```

Shrinking is not possible. Volumes can also only be expanded once every six
hours.

## 8.7 Cost

Rough monthly figures for this guide's topology in `eu-west-1`, on-demand.
Regions and instance choices move these a lot; price your own with the
[AWS Pricing Calculator](https://calculator.aws/) rather than trusting a table
in a document.

| Item | Quantity | Approximate monthly |
|------|----------|--------------------|
| EKS control plane | 1 | $73 |
| m6i.xlarge nodes | 6 | $840 |
| gp3 storage | 700 GiB | $60 |
| NAT gateways | 3 | $100 plus data processing |
| Network Load Balancers | 2 | $35 plus LCU |
| Application Load Balancer | 1 | $20 plus LCU |
| Cross-AZ transfer | varies | $0.01/GB each direction |
| **Total** | | **roughly $1,100 to $1,300** |

Where spend concentrates, and what you can change:

- **Nodes dominate.** Six on-demand nodes at `minSize: 1` per group is the
  floor for this topology. Compute Savings Plans or Reserved Instances cut this
  substantially for a workload that runs permanently, which a SIEM does. Do not
  use Spot for the indexer or the managers.
- **Three NAT gateways** cost roughly $70/month more than one. That is the price
  of not making every AZ depend on a single zone's gateway. VPC endpoints for
  S3 and ECR reduce the data-processing component.
- **Cross-AZ transfer** is charged in both directions, so indexer replication
  between zones is billed twice. Zone spreading is the point of the design, so
  treat this as the cost of availability rather than something to optimise
  away. Keeping the indexer service as `ClusterIP` rather than the upstream
  base's LoadBalancer already avoids a large slice of pointless cross-AZ and
  load balancer traffic.
- **Storage** scales with retention and replicas. One replica doubles it. ISM
  retention is the lever.

A useful sanity check: the stack costs less than one serious incident that went
undetected.

## 8.8 What to watch

Beyond the alerts in [7. Failure drills](07-failure-drills.md):

```bash
# Cluster health and shard state
curl -sk -u admin:PASS 'https://localhost:9200/_cluster/health?pretty'
curl -sk -u admin:PASS 'https://localhost:9200/_cat/shards/wazuh-*?v&h=index,shard,prirep,state,node'

# Disk headroom per node
curl -sk -u admin:PASS 'https://localhost:9200/_cat/allocation?v'

# Manager cluster and agent counts
kubectl -n wazuh exec wazuh-manager-master-0 -- /var/ossec/bin/cluster_control -l
kubectl -n wazuh exec wazuh-manager-master-0 -- /var/ossec/bin/agent_control -l | tail -5

# analysisd thread count. Thousands means the thread pinning is not in effect
kubectl -n wazuh exec wazuh-manager-worker-0 -- \
  sh -c 'ls /proc/$(pgrep -f wazuh-analysisd)/task | wc -l'

# Events dropped
kubectl -n wazuh exec wazuh-manager-worker-0 -- \
  grep -c 'Events dropped' /var/ossec/logs/ossec.log
```

The Wazuh dashboard covers agent health well. It will not tell you an indexer
node is down or a volume is nearly full; put those in whatever watches your
infrastructure.
