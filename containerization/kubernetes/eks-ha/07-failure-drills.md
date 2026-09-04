# 7. Failure drills and runbooks

Run these on staging before production depends on them. The goal is not to
prove resilience in the abstract; it is to see which failures self-heal, which
need a person, and how long each takes on your cluster rather than on paper.

Write down the timings you observe. Figures below follow from the defaults;
they are not measurements from your environment.

## Timing you inherit from Kubernetes

Three defaults set the lower bound on node-failure recovery:

| Setting | Default | Effect |
|---------|---------|--------|
| `--node-monitor-grace-period` | 40s | How long before an unresponsive node is marked `NotReady` |
| `tolerationSeconds` for `node.kubernetes.io/unreachable` and `not-ready` | 300s | How long a pod tolerates that taint before eviction |
| EBS detach and reattach | 1 to 6 min | Volume released from the old node and attached to the new one |

A node failure therefore costs about six minutes before a replacement pod even
starts, plus volume attach and app startup. That is the platform mechanism, not
a misconfiguration. You can shorten toleration per pod, but do it on purpose: a
short toleration turns a brief network blip into a full reschedule and EBS
reattach, which is usually worse than waiting.

## Drill 1: kill a pod

Cheapest drill. It should be uneventful.

```bash
kubectl -n wazuh delete pod wazuh-indexer-1
kubectl -n wazuh get pods -w
```

**Expect:** the StatefulSet recreates the pod on the same node with the same
volume; Ready within a minute or two. Cluster health goes yellow while the pod
is gone and returns to green soon after. With `delayed_timeout` at 10 minutes,
no shard rebuild begins.

```bash
kubectl -n wazuh exec wazuh-indexer-0 -- \
  curl -sk -u admin:PASS 'https://localhost:9200/_cluster/health?pretty'
```

Repeat on `wazuh-manager-master-0`. Same recovery pattern, plus a short API
outage while it restarts. Confirm the manager cluster reforms:

```bash
kubectl -n wazuh exec wazuh-manager-master-0 -- /var/ossec/bin/cluster_control -l
```

## Drill 2: terminate a node

This path recovers without intervention; knowing why matters for the next
drill.

```bash
NODE=$(kubectl -n wazuh get pod wazuh-indexer-1 -o jsonpath='{.spec.nodeName}')
INSTANCE=$(kubectl get node "$NODE" -o jsonpath='{.spec.providerID}' | awk -F/ '{print $NF}')
echo "terminating $INSTANCE ($NODE)"
aws ec2 terminate-instances --instance-ids "$INSTANCE"

# Watch, and time it
time kubectl -n wazuh wait --for=condition=Ready pod/wazuh-indexer-1 --timeout=20m
```

**Expect:** automatic recovery. Sequence: the AWS cloud controller sees the
instance gone and deletes the Node object; pod garbage collection removes the
pod; the volume detaches; Cluster Autoscaler starts a replacement node **in the
same AZ** (node group is single-AZ); the StatefulSet schedules the pod there.

Deleting the Node object is what makes recovery automatic. That is the
difference between this drill and the next.

**Watch for:** a replacement node in another AZ. That means the node group
spans more than one AZ; the pod stays `Pending` forever because its volume
cannot follow. Fix the node group layout in
[2. Provision EKS](02-provision-eks.md).

```bash
kubectl get nodes -L topology.kubernetes.io/zone
kubectl -n wazuh describe pod wazuh-indexer-1 | tail -20
```

A `volume node affinity conflict` event is this exact failure mode.

## Drill 3: make a node unreachable without terminating it

This case does **not** self-heal. It is why this page exists.

Simulate by blocking the kubelet while leaving the instance running, so the
Node object remains. Via SSM on the node:

```bash
sudo iptables -I INPUT -p tcp --dport 10250 -j DROP
sudo systemctl stop kubelet
```

**Expect:** node becomes `NotReady` after about 40 seconds. After the 300
second toleration, the dashboard pod (Deployment) is rescheduled and recovers.
Manager and indexer pods enter `Terminating` **and stay there indefinitely**.

```bash
kubectl -n wazuh get pods -o wide
# wazuh-manager-master-0   1/1   Terminating   ...
```

A StatefulSet allows at most one pod per ordinal, so the replacement is not
created until the old pod object is gone. Kubernetes cannot tell whether an
unreachable node is dead or partitioned, and will not decide for you. See
[force deleting StatefulSet pods](https://kubernetes.io/docs/tasks/run-application/force-delete-stateful-set-pod/).

### Runbook: stuck StatefulSet pod

**Confirm the node is genuinely gone before doing anything.** You are about to
override a guarantee that exists to stop two pods sharing one identity.

```bash
kubectl get node "$NODE" -o wide
aws ec2 describe-instance-status --instance-ids "$INSTANCE" \
  --include-all-instances --query 'InstanceStatuses[].InstanceState.Name'
```

Prefer deleting the Node object so normal garbage collection runs:

```bash
kubectl delete node "$NODE"
```

or force-delete the pod:

```bash
kubectl -n wazuh delete pod wazuh-manager-master-0 --grace-period=0 --force
```

**Expect afterwards:** the replacement is created, then sits in
`ContainerCreating` for up to six minutes while EBS is released from the old
attachment. That wait is normal, not a second failure.

For EBS the split-brain risk is bounded by the storage layer: a gp3 volume in
`ReadWriteOnce` attaches to only one instance at a time, so two masters cannot
write the same data. Premature force delete at worst leaves a pod waiting on a
volume; it does not corrupt data. That is an EBS property, not a Kubernetes
one, and it would not hold for a `ReadWriteMany` filesystem.

If you want automation instead, honest options are a controller such as
[medik8s/node-healthcheck-operator](https://github.com/medik8s/node-healthcheck-operator)
that fences and remediates unhealthy nodes, or accept the manual step and alert
on it. Do not CronJob force-deletes of `Terminating` pods on a timer; that will
eventually fire during a network partition where the original pod is still
alive.

## Drill 4: lose the master

People ask about this one. Measure what actually breaks.

```bash
kubectl -n wazuh scale statefulset wazuh-manager-master --replicas=0
```

Check each capability in turn.

**Still working:**

```bash
# Events still arriving from agents to the worker
kubectl -n wazuh logs wazuh-manager-worker-0 -c wazuh-manager --tail=20

# Alerts still reaching the indexer, count should keep climbing
for i in 1 2 3; do
  kubectl -n wazuh exec wazuh-indexer-0 -- curl -sk -u admin:PASS \
    'https://localhost:9200/wazuh-alerts-*/_count' ; sleep 60
done

# Dashboard still renders alerts, because that reads the indexer, not the API
```

**Broken:**

```bash
# API gone
curl -sk -o /dev/null -w '%{http_code}\n' https://wazuh.internal.example.com:55000/

# New enrollment fails: authd runs only on the master
/var/ossec/bin/agent-auth -m wazuh.internal.example.com   # on a test host
```

Also broken, though slower to notice: agent group and `agent.conf`
distribution, rule and decoder sync to workers, and `client.keys` as the
authoritative record. Agents keep running their cached configuration.

Workers log the lost master and retry with no timeout. Beyond the gaps above
there is no further degradation, so the state is survivable for as long as you
need to repair it.

Recover:

```bash
kubectl -n wazuh scale statefulset wazuh-manager-master --replicas=1
kubectl -n wazuh wait --for=condition=Ready pod/wazuh-manager-master-0 --timeout=10m
kubectl -n wazuh exec wazuh-manager-master-0 -- /var/ossec/bin/cluster_control -l
```

The master comes back as the same master: identity and `client.keys` returned
with the volume. No re-enrollment is required.

## Drill 5: lose an Availability Zone

Highest-value drill; the one that surfaces real gaps. Simulate by draining and
cordoning both nodes in one AZ.

```bash
AZ=eu-west-1a
NODES=$(kubectl get nodes -l topology.kubernetes.io/zone=$AZ -o name)
for n in $NODES; do kubectl cordon "${n#node/}"; done
for n in $NODES; do kubectl drain "${n#node/}" --ignore-daemonsets --delete-emptydir-data --timeout=10m; done
```

**Expect, if the master's volume was in that AZ:**

- Indexer: two nodes remain, quorum holds, cluster yellow, still accepting
  writes. Correct and expected.
- The manager whose volume lived in that AZ: `Pending`, with a
  `volume node affinity conflict` event. It cannot move; its EBS volume cannot
  leave the zone.
- Dashboard: reschedules into a surviving AZ and recovers.

```bash
kubectl -n wazuh get pods -o wide
kubectl -n wazuh describe pod wazuh-manager-master-0 | grep -A5 Events
```

If the stranded pod is the master, you are in the Drill 4 degraded state until
the AZ returns. Detection and alerting continue; enrollment and the API do not.

### Runbook: restore a manager into a different AZ

Only if the AZ will not return soon. This is a rebuild, not a failover, and it
needs a recent snapshot - which is why
[8. Operations](08-operations.md) treats snapshotting the master's volume as a
requirement.

```bash
# 1. Find the most recent snapshot of the master's volume
aws ec2 describe-snapshots --owner-ids self \
  --filters "Name=tag:kubernetes.io/created-for/pvc/name,Values=wazuh-manager-master-wazuh-manager-master-0" \
  --query 'sort_by(Snapshots,&StartTime)[-1].[SnapshotId,StartTime]' --output text

# 2. Create a volume from it in a SURVIVING AZ
aws ec2 create-volume --snapshot-id snap-xxxx --availability-zone eu-west-1b \
  --volume-type gp3 --encrypted \
  --tag-specifications 'ResourceType=volume,Tags=[{Key=Name,Value=wazuh-master-restored}]'

# 3. Scale the master down and remove the stranded PVC and PV
kubectl -n wazuh scale statefulset wazuh-manager-master --replicas=0
kubectl -n wazuh delete pvc wazuh-manager-master-wazuh-manager-master-0
# reclaimPolicy is Retain, so the old PV survives; release it
kubectl delete pv <old-pv-name>

# 4. Create a PV bound to the restored volume, with node affinity for the new
#    AZ, and a PVC with the exact name the StatefulSet expects, then scale up.
kubectl -n wazuh scale statefulset wazuh-manager-master --replicas=1
```

The PVC name a StatefulSet expects is
`<volumeClaimTemplate-name>-<statefulset-name>-<ordinal>`, here
`wazuh-manager-master-wazuh-manager-master-0`. Get the name wrong and the
StatefulSet provisions a fresh empty volume; the master returns with no
`client.keys` and every agent needs re-enrollment.

Practise this drill. It has the most steps and the most to lose if it goes
wrong.

Recover the drill:

```bash
for n in $NODES; do kubectl uncordon "${n#node/}"; done
```

## Drill 6: node group upgrade

Routine work that often causes an unplanned outage.

```bash
eksctl upgrade nodegroup --cluster wazuh-ha --name ng-indexer-1a --kubernetes-version 1.36
```

**Expect:** nodes roll one at a time. The indexer PDB (`minAvailable: 2`)
blocks a second eviction until the first indexer is Ready again, so the cluster
never drops below quorum.

**Watch for:** drain blocked forever on the master. There is no PDB for it: a
single-pod budget either blocks every drain or does nothing. The drain will
evict the master and it will restart. That is a short enrollment and API
outage, and the correct trade. Schedule it; do not discover it live.

```bash
# Before a planned drain of the master's node, know what you are accepting
kubectl -n wazuh get pod wazuh-manager-master-0 -o wide
```

## What to alert on

From the drills above, not from a generic catalogue.

| Condition | Why |
|-----------|-----|
| Any pod in `Terminating` for more than 10 minutes | Drill 3, needs a human |
| Any pod `Pending` for more than 10 minutes | Stranded volume, Drill 5 |
| `wazuh-manager-master` unavailable for more than 5 minutes | Enrollment and API down |
| Indexer cluster status red, or nodes fewer than 3 | Quorum at risk |
| Indexer yellow for more than 30 minutes | Allocation stuck, or allocation still disabled after maintenance |
| Disk usage above the low watermark | Ingestion stops at flood stage |
| Agent count dropping | Events not arriving, independent of pod health |
| No documents added to `wazuh-alerts-*` in 15 minutes | The pipeline is broken somewhere probes cannot see |

That last alert is the most valuable and the least obvious. Every pod can be
`Ready` while alerts stop arriving, because readiness only proves a port is
open.

Next: [8. Operations](08-operations.md).
