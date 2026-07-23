# Debugging a Wazuh Kubernetes deployment

**Applies to:** Wazuh 4.x on Kubernetes, kubectl, minikube (local labs)

[Back to Kubernetes README](./README.md)

A field-tested command reference for diagnosing Wazuh clusters deployed with the official [wazuh-kubernetes](https://github.com/wazuh/wazuh-kubernetes) manifests.

## Table of Contents

- [Local lab with minikube](#local-lab-with-minikube)
- [General pod diagnostics](#general-pod-diagnostics)
- [Master pod OOMKilled and cluster restart loops](#master-pod-oomkilled-and-cluster-restart-loops)
- [DNS resolution problems (minikube)](#dns-resolution-problems-minikube)
- [Changing the namespace breaks cluster DNS](#changing-the-namespace-breaks-cluster-dns)
- [Working with the indexer pods](#working-with-the-indexer-pods)
- [Dashboard diagnostics](#dashboard-diagnostics)
- [EKS context commands](#eks-context-commands)

## Local lab with minikube

Spin up a local cluster and deploy the local environment overlay:

```bash
minikube start --cpus=4 --memory=8192
kubectl config use-context minikube

# Check available storage classes and point envs/local-env/storage-class.yaml
# at the minikube provisioner
kubectl get sc

kubectl apply -k envs/local-env/

kubectl get namespaces | grep wazuh
kubectl get pods -n wazuh

# Access the dashboard locally
kubectl -n wazuh port-forward service/dashboard 8443:443
```

## General pod diagnostics

```bash
kubectl get pods -n wazuh
kubectl get pods -n wazuh -o wide          # includes pod IP and node
kubectl describe pod <POD_NAME> -n wazuh   # events: scheduling, image pulls, mounts
```

`kubectl describe` is the first stop for pods stuck in `Pending` (storage/affinity issues), `ImagePullBackOff` (registry/DNS issues), or `CrashLoopBackOff` (check the events, then the logs).

## Master pod OOMKilled and cluster restart loops

A cluster that "crashes every 2-5 minutes" (the master restarts, workers then restart, cluster comms drop and re-form on a loop) is very often the master being OOMKilled, not a Wazuh bug. Confirm it:

```bash
kubectl get pods -n <namespace> -o wide                    # RESTARTS climbing on the master
kubectl describe pod wazuh-manager-master-0 -n <namespace> | grep -A3 "Last State"
# Last State: Terminated   Reason: OOMKilled
```

The stock manifests ship deliberately small limits (the master defaults to roughly `400m` CPU / `512Mi` RAM). That is below what a manager with enrolled agents needs, so it is killed the moment memory spikes, taking cluster communication down with it. Raise the requests/limits in your overlay and redeploy.

The documented "minimum requirements" are for the whole cluster with no agents; they are not per-pod values. As a starting point per component (mirrors the non-container [sizing guide](https://documentation.wazuh.com/current/quickstart.html#requirements)):

| Component | ~50 agents | ~100 agents |
|---|---|---|
| Manager master | 1 vCPU, 2 GiB | 2 vCPU, 4 GiB |
| Manager worker | 1 vCPU, 2 GiB | 2 vCPU, 4 GiB |
| Indexer | 2 vCPU, 4 GiB | 4 vCPU, 8-16 GiB |
| Dashboard | 1 vCPU, 1 GiB | 1 vCPU, 2 GiB |

Set the indexer JVM heap to ~50% of its memory limit (cap 32 GB), then watch real usage with `kubectl top pods -n <namespace>` and iterate.

## DNS resolution problems (minikube)

A common failure mode in local labs is image pulls failing because the minikube VM cannot resolve the registry:

```bash
minikube ssh
nslookup registry-1.docker.io
dig registry-1.docker.io
exit

# If resolution fails, restart minikube using the host's resolver
minikube stop
minikube start --extra-config=kubelet.resolvConf=/etc/resolv.conf
```

## Changing the namespace breaks cluster DNS

The `wazuh-kubernetes` manifests rely on Kubernetes DNS service discovery, and several config values embed the namespace. Deploy into any namespace other than the default `wazuh` without updating those references and the cluster silently fails to form. A common signature is the agent successfully getting a key from the master but then failing to send logs: the master cannot hand the agent off to a worker because cluster communication is broken.

Short service names (`wazuh-indexer`, `wazuh`) resolve fine as long as every component is in the same namespace: Kubernetes expands `wazuh-indexer` to `wazuh-indexer.<namespace>.svc.cluster.local`. The breakage comes from fully-qualified names that hard-code the namespace, most importantly the master node entry in the cluster config (`master.conf` / `worker.conf`), which uses the headless-service form `<pod>.<service>.<namespace>`:

```xml
<nodes>
  <node>wazuh-manager-master-0.wazuh-cluster.<namespace></node>
</nodes>
```

When you change the namespace, update it there (and audit the overlay for any other FQDN that includes the old namespace). The cluster key and node name (`to_be_replaced_by_*` placeholders) are substituted automatically at deploy time: do not hand-edit those. Verify the cluster formed from Server management to Cluster, or:

```bash
kubectl exec -n <namespace> wazuh-manager-master-0 -- /var/ossec/bin/cluster_control -l
```

Setting the namespace once via the Kustomize overlay (`kustomization.yml`) is the intended workflow, but the FQDN above still has to match the namespace you choose: that one is not rewritten for you.

## Working with the indexer pods

```bash
# Shell into an indexer pod
kubectl exec -it wazuh-indexer-0 -n wazuh -- bash

# List the containers in a pod (needed for -c on multi-container pods)
kubectl get pod wazuh-indexer-0 -n wazuh -o jsonpath='{.spec.containers[*].name}'

# Copy a config file out of the pod...
kubectl cp wazuh/wazuh-indexer-0:/path/in/container/config.yml ./config.yml
# ...or with a specific container
kubectl cp -n wazuh -c <CONTAINER_NAME> wazuh-indexer-0:/path/to/config.yml ./config.yml
# Alternative when kubectl cp fails (no tar in image)
kubectl exec -n wazuh wazuh-indexer-0 -- cat /path/in/container/config.yml > ./config.yml

# Push an edited file back into the pod
cat ./config.yml | kubectl exec -i -n wazuh wazuh-indexer-0 -- sh -c 'cat > /path/in/container/config.yml'

# Apply security config changes (e.g. SAML) and restart the statefulset
kubectl apply -f wazuh-indexer-saml-config.yaml
kubectl rollout restart statefulset wazuh-indexer -n wazuh

# Crashing pod? Get the logs of the PREVIOUS container instance
kubectl logs wazuh-indexer-0 -n wazuh --previous

# Minimal images have no shell tooling - attach an ephemeral debug container
kubectl debug -it wazuh-indexer-0 -n wazuh --image=busybox --target=wazuh-indexer -- /bin/sh
```

When running `securityadmin.sh` inside the indexer, locate the security `config.yml` first:

```bash
find / -type f -name config.yml 2>/dev/null
```

## Dashboard diagnostics

```bash
# External IP of the dashboard service
kubectl get services -o wide -n wazuh

# Apply SAML/dashboard config changes and restart
kubectl apply -f wazuh-dashboard-saml-config.yaml
kubectl rollout restart deployment wazuh-dashboard -n wazuh

# Follow the dashboard log
kubectl logs -n wazuh <DASHBOARD_POD_NAME> -f
```

## EKS context commands

```bash
kubectl cluster-info
kubectl get nodes --show-labels
eksctl get clusters
aws eks update-kubeconfig --region <REGION> --name <CLUSTER_NAME>
cat ~/.kube/config
```

## Related

- [Wazuh on Amazon EKS](./eks.md) - storage classes, affinity, ingress, SSO
- [Wazuh on GKE](./gke.md) - [Wazuh on AKS](./aks.md)
- [Docker network and proxy debugging](../docker/network-proxy-debugging.md) - the container-level equivalent
