# Wazuh on Amazon EKS

**Applies to:** Wazuh 4.x, Amazon EKS, [wazuh-kubernetes](https://github.com/wazuh/wazuh-kubernetes) deployment

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

This guide collects answers to the questions that come up most often when deploying Wazuh on Amazon EKS with the official Kustomize-based [wazuh-kubernetes](https://github.com/wazuh/wazuh-kubernetes) repository: storage class selection, Availability Zone pinning, private registries (ECR), moving from a LoadBalancer to an Ingress, SSO, and agent enrollment.

For general Kubernetes requirements, see the [official Wazuh Kubernetes documentation](https://documentation.wazuh.com/current/deployment-options/deploying-with-kubernetes/index.html).

## Storage configuration

**Can gp3 be used instead of the default gp2?**

Yes. gp3 offers better price/performance than gp2 and is the recommended choice on current EKS clusters. Modify `storage-class.yaml` in your environment overlay to set the type to `gp3`.

**Does Wazuh require a specific storage class?**

No. Wazuh can use the default storage class of the cluster, as long as it supports dynamic provisioning and meets the [resource requirements](https://documentation.wazuh.com/current/deployment-options/deploying-with-kubernetes/kubernetes-conf.html#resource-requirement) of your deployment (the indexer is the most I/O-sensitive component).

**Is `volumeBindingMode: WaitForFirstConsumer` compatible?**

Yes, and it is actively recommended. It delays volume provisioning until a pod using the PersistentVolumeClaim is scheduled, which guarantees the EBS volume is created in the same Availability Zone as the pod.

**`reclaimPolicy: Delete` vs `Retain`?**

The Wazuh manifests default to `Retain`, which keeps the volume for manual reclamation when its claim is deleted: safer against accidental data loss. `Delete` cleans up automatically. Choose based on your data retention policy; see the Kubernetes [persistent volumes documentation](https://kubernetes.io/docs/concepts/storage/persistent-volumes/).

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

EBS volumes are zonal: a pod scheduled in a different AZ from its EBS volume cannot attach it, and the pod stays `Pending`. To keep pods and their volumes co-located:

1. Use `volumeBindingMode: WaitForFirstConsumer` on the storage class (see above), so the volume is provisioned wherever the pod lands.
2. Add `nodeAffinity` rules with a `topologyKey` based on the AZ node label (`topology.kubernetes.io/zone`) to pin the Wazuh pods to a specific zone:

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

The default Kustomize setup does not ship affinity rules - add them as patches in your environment overlay (`envs/`).

Pinning every indexer to one Availability Zone solves attachment locality but
creates a zone-level failure domain. For HA, use `WaitForFirstConsumer`,
topology spread/anti-affinity, and one StatefulSet replica plus its EBS volume
per selected zone. Verify OpenSearch primary and replica shards are also
distributed across those zones.

## Configuration management and customization

**Where should changes be made in the wazuh-kubernetes repository?**

All environment-specific changes belong in the `envs/` directory (Kustomize overlays). Do not modify the base manifests under the `wazuh/` subfolders: keeping the base pristine makes upgrades to newer Wazuh versions a clean rebase instead of a merge conflict hunt.

**Pulling images from a private ECR**

Update the image references in your Kustomize overlay to point at your ECR repository (`<ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/wazuh/wazuh-manager:<VERSION>`), and make sure the node IAM role includes the `AmazonEC2ContainerRegistryReadOnly` policy (or equivalent pull permissions) so nodes can fetch the images.

**Adjusting pod sizing**

Set resource requests/limits in the Kustomize overlays, then monitor actual usage (`kubectl top pods -n wazuh`) and iterate. The indexer JVM heap should be sized to roughly 50% of the container memory limit, capped at 32 GB.

## Ingress and TLS

**Moving from a LoadBalancer to an Ingress**

1. Deploy an Ingress controller in the cluster (e.g. AWS Load Balancer Controller or ingress-nginx).
2. Create Ingress resources with routing rules pointing at the Wazuh dashboard service. Verify the service name and port match the deployment.
3. Update DNS records to point to the Ingress controller's external address.
4. Include TLS settings in the Ingress resource for secure external access.

**Can an AWS NLB terminate TLS to simplify certificate management?**

An NLB can terminate TLS for *external* access (e.g. the dashboard), but it cannot replace the certificates used for communication between the central components (indexer, manager, dashboard). Inter-component TLS must follow the [certificate setup](https://documentation.wazuh.com/current/deployment-options/deploying-with-kubernetes/kubernetes-deployment.html#setup-ssl-certificates) described in the official documentation.

## Authentication and secrets

**SSO**

Wazuh supports SAML-based Single Sign-On with providers such as Okta, Microsoft Entra ID, PingOne, Google, JumpCloud, OneLogin, and Keycloak. See [Single sign-on - Wazuh documentation](https://documentation.wazuh.com/current/user-manual/user-administration/single-sign-on/index.html). On Kubernetes, apply the SAML configuration files and restart the affected workloads:

```bash
kubectl apply -f wazuh-indexer-saml-config.yaml
kubectl rollout restart statefulset wazuh-indexer -n wazuh

kubectl apply -f wazuh-dashboard-saml-config.yaml
kubectl rollout restart deployment wazuh-dashboard -n wazuh
```

**Avoiding plaintext passwords in Kustomize with AWS Secrets Manager**

- Store the sensitive values (indexer passwords, API credentials) in AWS Secrets Manager.
- Sync them into Kubernetes Secrets (e.g. with the Secrets Store CSI driver and its AWS provider, or External Secrets Operator).
- Reference the Kubernetes Secrets from the pods instead of hard-coding values in the overlays.

## Rules management and auditability

**Tracking `local_rules.xml` changes**

Manage custom rules in Git: a dedicated repository (or branch) with a pull-request workflow, review before merge, and CI/CD deployment to the manager pods. This gives full audit traceability of who changed which rule and when.

**Letting external contributors add rules safely**

- Role-based access control on the Git repository and a branching strategy that requires PRs.
- Automated syntax/security validation in CI (e.g. `wazuh-logtest` runs) before merge.
- Peer review by the security team, and a staging environment to validate rules before production.

**Alerting when a rule file is modified or disabled**

- Enable Wazuh FIM (syscheck) on the custom rules directory so any modification generates an alert.
- Optionally add auditd monitoring on the manager host/pod for who-did-what detail.
- Build alert rules/notifications for unexpected changes.

## Agent enrollment and custom CAs

**Custom root CA for agent communication**

- Place the CA certificate at `/var/ossec/etc/rootCA.pem` on both the manager and the agents.
- Reference it from the agent `ossec.conf` (`<server_ca_path>` under the enrollment block).
- Restart the agent and the manager pods to apply.

**Private vs public CA**

Both work. You can use a public CA (Let's Encrypt, DigiCert, ...) or an internal CA: the certificate just needs to be properly signed and trusted by the agents, so distribute the CA cert to all managed systems.

**Recommended enrollment method**

Use the [agent-auth tool](https://documentation.wazuh.com/current/user-manual/reference/tools/agent-auth.html)
with password authentication. Mount the enrollment password from a Kubernetes
Secret as `/var/ossec/etc/authd.pass`, readable only by the agent process, and
invoke `agent-auth` without putting the password in the command line:

```bash
/var/ossec/bin/agent-auth -m <WAZUH_MANAGER_IP> -A <AGENT_NAME>
```

Passing `-P <ENROLLMENT_PASSWORD>` exposes the secret in shell history and the
process list. Remove the mounted enrollment secret after registration if the
pod does not need to re-enroll automatically.

**Are pre-shared keys supported?**

The enrollment password stored in `/var/ossec/etc/authd.pass` on the manager acts as a pre-shared key for enrollment only. It is not used for ongoing communication: after enrollment, agents talk to the manager over TLS on port 1514 using their individual agent keys.

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

- [AWS credentials as Secrets/ConfigMaps](./aws-credentials.md) - persisting AWS module credentials across pod restarts
- [Cluster debugging](./cluster-debugging.md) - kubectl/minikube diagnostic commands
- [Agent DaemonSet (custom image)](./agent-daemonset.md) - includes EKS Fargate logging via CloudWatch
