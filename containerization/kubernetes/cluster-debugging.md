# Debugging a Wazuh Kubernetes deployment

**Applies to:** Wazuh 4.x on Kubernetes · kubectl · minikube (local labs)

[Back to Kubernetes README](./README.md)

A field-tested command reference for diagnosing Wazuh clusters deployed with the official [wazuh-kubernetes](https://github.com/wazuh/wazuh-kubernetes) manifests.

## Table of Contents

- [Local lab with minikube](#local-lab-with-minikube)
- [General pod diagnostics](#general-pod-diagnostics)
- [DNS resolution problems (minikube)](#dns-resolution-problems-minikube)
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

- [Wazuh on Amazon EKS](./eks.md) — storage classes, affinity, ingress, SSO
- [Wazuh on GKE](./gke.md) · [Wazuh on AKS](./aks.md)
- [Docker network and proxy debugging](../docker/network-proxy-debugging.md) — the container-level equivalent
