# Highly available Wazuh on Amazon EKS

Build Wazuh on EKS in stages: **2 managers, 3 indexers, 1 dashboard**, placed
across three Availability Zones, with one replica shard on the indexer.

Start with [1. Architecture](01-architecture.md). That page states which
failures recover alone, which need an operator, and the reasons. Short form:
the indexer is truly highly available; the manager master is not. Wazuh allows
only one master and has no automatic promotion. That limit comes from the
product, not from this layout, and the guide designs around it instead of
hiding it.

## Steps

| | Page | What it covers |
|--|------|----------------|
| 1 | [Architecture](01-architecture.md) | Topology, failure matrix, what breaks when the master is down, why EBS being zonal drives the whole node layout |
| 2 | [Provision EKS](02-provision-eks.md) | The cluster, with eksctl or Terraform |
| 3 | [Cluster prerequisites](03-cluster-prerequisites.md) | EBS CSI driver, StorageClass, load balancer controller, autoscaler |
| 4 | [Deploy Wazuh](04-deploy-wazuh.md) | Upstream Kustomize plus the overlay in `manifests/overlay/` |
| 5 | [Indexer HA](05-indexer-ha.md) | Quorum, replicas, allocation, watermarks, rolling restarts |
| 6 | [Expose agents](06-expose-agents.md) | NLBs for 1514 and 1515, ALB for the dashboard, agent-side failover |
| 7 | [Failure drills](07-failure-drills.md) | Six drills with expected behaviour, and the runbooks for the two that need intervention |
| 8 | [Operations](08-operations.md) | Snapshots, retention, upgrades, scaling, cost |

## Artifacts

Files under [`manifests/`](manifests/) are complete working copies, not
snippets.

```
manifests/
  eksctl/cluster.yaml        3 AZs, 6 single-AZ managed node groups, 4 addons
  terraform/main.tf          the same cluster in Terraform
  overlay/                   Kustomize overlay for wazuh-kubernetes v4.14.7
```

Drop the overlay into a clone of
[wazuh/wazuh-kubernetes](https://github.com/wazuh/wazuh-kubernetes) at
`envs/eks-ha/`. Each file in the overlay documents the change and the reason.

## The summary, if you read nothing else

**What survives an AZ loss with no intervention:** indexer quorum (2 of 3) plus
a shard copy outside the failed zone; the dashboard, which is stateless.

**What survives a node loss with no intervention:** the full stack, once the
instance is terminated and its Node object is gone. Plan on about six minutes:
40 second node grace, 300 second pod toleration, then EBS reattach.

**What needs a human:** an unreachable node that was never terminated leaves
StatefulSet pods in `Terminating` forever, because a StatefulSet will not spawn
a replacement while the old pod object remains. An AZ outage that traps a
manager is the other case: its zonal EBS volume cannot move to another zone.

**What no amount of Kubernetes fixes:** with the master down you lose new agent
enrollment, the Wazuh API (and most dashboard agent management), and agent group
and rule distribution. Enrolled agents still ship events to the worker; the
worker still evaluates rules; alerts still land in the indexer. **Detection
continues.** State that trade clearly with whoever signs off on the deployment.

## Cost

In `eu-west-1` on-demand, expect about $1,100 to $1,300 a month, mostly six
`m6i.xlarge` nodes. [8. Operations](08-operations.md) itemizes spend and what
is worth trimming; usually that is not the capacity that buys availability.
Price your region yourself; do not rely on the table alone.

## Deploying with Helm instead

The [Helm chart in this repository](../helm/wazuh/) targets the same topology
and bakes most overlay choices into defaults, including single-node and
zero-worker layouts. This guide stays on Kustomize because that matches Wazuh's
own docs, which helps if you raise a support case. Steps 1, 2, 3, 6, 7 and 8
are the same either path; only step 4 changes.

## Related reading in this repository

- [eks.md](../eks.md) is the EKS topic reference (storage classes, ECR, SSO,
  secrets, custom CAs). This folder is the end-to-end HA build.
- [agent-info-sync-failures.md](../agent-info-sync-failures.md) covers the
  analysisd thread pool issue the overlay pins, and why manager probes are TCP
  instead of exec.
- [load-balancing-and-ingress.md](../load-balancing-and-ingress.md) backs step
  6.
- [persistent-storage.md](../persistent-storage.md) lists what survives a pod
  restart versus what the image regenerates.
- [upgrading/sizing.md](../../../upgrading/sizing.md) for capacity past the few
  hundred agents this guide assumes.

## Caveats

Pinned versions go stale. This guide locks Kubernetes 1.35, Wazuh 4.14.7 and
the AWS Load Balancer Controller chart 3.5.0; each section shows how to look up
the current value instead of trusting the printed one. Two version numbers from
the research behind this guide were already outdated when written, so treat the
lookup as part of the procedure.

Manifests here were built and validated. The custom indexer image in
[8.2](08-operations.md) was built and confirmed to include the plugin. Nothing
has been exercised on a live EKS cluster, so timings in
[7. Failure drills](07-failure-drills.md) follow documented defaults, not
measured runs. Run the drills in staging and record what you observe.
