# Wazuh on Amazon EKS

**Applies to:** Wazuh 4.x · Amazon EKS · [wazuh-kubernetes](https://github.com/wazuh/wazuh-kubernetes) deployment

[Back to Kubernetes README](./README.md)

## Table of Contents

- [Overview](#overview)
- [Storage configuration](#storage-configuration)
- [Pod affinity and Availability Zones](#pod-affinity-and-availability-zones)
- [Configuration management and customization](#configuration-management-and-customization)
- [Ingress and TLS](#ingress-and-tls)
- [Authentication and secrets](#authentication-and-secrets)
- [Rules management and auditability](#rules-management-and-auditability)
- [Agent enrollment and custom CAs](#agent-enrollment-and-custom-cas)
- [Useful commands](#useful-commands)

## Overview

Practical answers to the questions that keep showing up when you put Wazuh on
Amazon EKS with the official Kustomize-based
[wazuh-kubernetes](https://github.com/wazuh/wazuh-kubernetes) repo: storage
class choice, Availability Zone pinning, private registries (ECR), switching
from a LoadBalancer to an Ingress, SSO, and agent enrollment.

General Kubernetes requirements live in the
[official Wazuh Kubernetes documentation](https://documentation.wazuh.com/current/deployment-options/deploying-with-kubernetes/index.html).

## Storage configuration

**Can gp3 replace the default gp2?**

Yes. On current EKS clusters gp3 usually beats gp2 on price/performance and is
the recommended type. In your environment overlay, edit `storage-class.yaml`
and set the type to `gp3`.

**Does Wazuh need a particular storage class?**

No. The cluster default works if it supports dynamic provisioning and meets
the
[resource requirements](https://documentation.wazuh.com/current/deployment-options/deploying-with-kubernetes/kubernetes-conf.html#resource-requirement)
for your layout (the indexer is the most I/O-sensitive piece).

**Is `volumeBindingMode: WaitForFirstConsumer` compatible?**

Yes, and you should use it. Provisioning waits until a pod that uses the
PersistentVolumeClaim is scheduled, so the EBS volume lands in the same
Availability Zone as the pod.

**`reclaimPolicy: Delete` vs `Retain`?**

The Wazuh manifests default to `Retain`, which leaves the volume around for
manual cleanup when its claim goes away — safer against accidental data loss.
`Delete` removes the volume automatically. Pick based on your retention
policy; see the Kubernetes
[persistent volumes documentation](https://kubernetes.io/docs/concepts/storage/persistent-volumes/).

Example storage class for EKS:

```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: wazuh-storage
provisioner: ebs.csi.aws.com
parameters:
  type: gp3
volumeBindingMode: WaitForFirstConsumer
reclaimPolicy: Retain
```

## Pod affinity and Availability Zones

EBS volumes are zonal. Schedule a pod in a different AZ from its volume and
attachment fails; the pod stays `Pending`. To keep pods and volumes together:

1. Set `volumeBindingMode: WaitForFirstConsumer` on the storage class (above)
   so the volume is created where the pod lands.
2. Add `nodeAffinity` with a `topologyKey` on the AZ node label
   (`topology.kubernetes.io/zone`) to pin Wazuh pods to a chosen zone:

```yaml
affinity:
  nodeAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      nodeSelectorTerms:
        - matchExpressions:
            - key: topology.kubernetes.io/zone
              operator: In
              values:
                - us-east-1a
```

The stock Kustomize layout ships no affinity rules — add them as patches under
your environment overlay (`envs/`).

Pinning every indexer into one Availability Zone fixes attachment locality but
creates a single zone failure domain. For HA, combine `WaitForFirstConsumer`,
topology spread/anti-affinity, and one StatefulSet replica plus its EBS volume
per selected zone. Confirm OpenSearch primary and replica shards are spread
across those zones too.

## Configuration management and customization

**Where do changes go in the wazuh-kubernetes repository?**

Put every environment-specific edit under `envs/` (Kustomize overlays). Leave
the base manifests in the `wazuh/` subfolders alone — a clean base turns
upgrades to newer Wazuh versions into a rebase instead of a merge-conflict
chase.

**Pulling images from a private ECR**

Point the image references in your Kustomize overlay at your ECR repository
(`<ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/wazuh/wazuh-manager:<VERSION>`).
Give the node IAM role `AmazonEC2ContainerRegistryReadOnly` (or equivalent
pull permissions) so nodes can fetch the images.

**Adjusting pod sizing**

Set resource requests/limits in the Kustomize overlays, then watch real usage
(`kubectl top pods -n wazuh`) and adjust. Size the indexer JVM heap to about
50% of the container memory limit, with a 32 GB cap.

## Ingress and TLS

**Moving from a LoadBalancer to an Ingress**

1. Install an Ingress controller (for example AWS Load Balancer Controller or
   ingress-nginx).
2. Create Ingress resources whose routing rules target the Wazuh dashboard
   service — confirm the service name and port match the deployment.
3. Point DNS at the Ingress controller's external address.
4. Put TLS settings on the Ingress resource for secure external access.

**Can an AWS NLB terminate TLS to simplify certificate management?**

An NLB can terminate TLS for *external* access (the dashboard, for example),
but it cannot stand in for the certificates used **between the central
components** (indexer, manager, dashboard). Inter-component TLS still follows
the
[certificate setup](https://documentation.wazuh.com/current/deployment-options/deploying-with-kubernetes/kubernetes-deployment.html#setup-ssl-certificates)
in the official documentation.

## Authentication and secrets

**SSO**

Wazuh supports SAML-based Single Sign-On with providers such as Okta,
Microsoft Entra ID, PingOne, Google, JumpCloud, OneLogin, and Keycloak. See
[Single sign-on - Wazuh documentation](https://documentation.wazuh.com/current/user-manual/user-administration/single-sign-on/index.html).
On Kubernetes, apply the SAML configuration files and restart the affected
workloads:

```bash
kubectl apply -f wazuh-indexer-saml-config.yaml
kubectl rollout restart statefulset wazuh-indexer -n wazuh

kubectl apply -f wazuh-dashboard-saml-config.yaml
kubectl rollout restart deployment wazuh-dashboard -n wazuh
```

**Avoiding plaintext passwords in Kustomize with AWS Secrets Manager**

- Keep sensitive values (indexer passwords, API credentials) in AWS Secrets
  Manager.
- Sync them into Kubernetes Secrets (for example with the Secrets Store CSI
  driver and its AWS provider, or External Secrets Operator).
- Have the pods reference those Kubernetes Secrets instead of hard-coding
  values in the overlays.

## Rules management and auditability

**Tracking `local_rules.xml` changes**

Keep custom rules in Git: a dedicated repository or branch, pull-request
workflow, review before merge, and CI/CD deploy onto the manager pods. That
gives a clear audit trail of who changed which rule and when.

**Letting external contributors add rules safely**

- Role-based access control on the Git repository and a branching strategy
  that requires PRs.
- Automated syntax/security checks in CI (for example `wazuh-logtest` runs)
  before merge.
- Peer review by the security team, plus a staging environment to validate
  rules before production.

**Alerting when a rule file is modified or disabled**

- Turn on Wazuh **FIM (syscheck)** for the custom rules directory so any edit
  raises an alert.
- Optionally add **auditd** on the manager host/pod for who-did-what detail.
- Build alert rules/notifications for unexpected changes.

## Agent enrollment and custom CAs

**Custom root CA for agent communication**

- Drop the CA certificate at `/var/ossec/etc/rootCA.pem` on the manager and
  the agents.
- Reference it from the agent `ossec.conf` (`<server_ca_path>` under the
  enrollment block).
- Restart the agent and the manager pods to apply.

**Private vs public CA**

Either works. A public CA (Let's Encrypt, DigiCert, ...) or an internal CA is
fine as long as the certificate is properly signed and trusted by the agents —
distribute the CA cert to every managed system.

**Recommended enrollment method**

Use the
[agent-auth tool](https://documentation.wazuh.com/current/user-manual/reference/tools/agent-auth.html)
with password authentication. Mount the enrollment password from a Kubernetes
Secret as `/var/ossec/etc/authd.pass`, readable only by the agent process, and
call `agent-auth` without putting the password on the command line:

```bash
/var/ossec/bin/agent-auth -m <WAZUH_MANAGER_IP> -A <AGENT_NAME>
```

Passing `-P <ENROLLMENT_PASSWORD>` leaves the secret in shell history and the
process list. Remove the mounted enrollment secret after registration unless
the pod must re-enroll on its own.

**Are pre-shared keys supported?**

The enrollment password in `/var/ossec/etc/authd.pass` on the manager acts as
a pre-shared key **for enrollment only**. Ongoing traffic does not use it —
after enrollment, agents talk to the manager over TLS on port 1514 with their
individual agent keys.

## Useful commands

```bash
# Cluster and node inspection
kubectl cluster-info
kubectl get nodes --show-labels
eksctl get clusters
aws eks update-kubeconfig --region <REGION> --name <CLUSTER_NAME>

# Wazuh services (external IPs / load balancers)
kubectl get services -o wide -n wazuh
```

## Related

- [AWS credentials as Secrets/ConfigMaps](./aws-credentials.md) - keeping AWS module credentials across pod restarts
- [Cluster debugging](./cluster-debugging.md) - kubectl/minikube diagnostic commands
- [Agent DaemonSet (custom image)](./agent-daemonset.md) - includes EKS Fargate logging via CloudWatch
