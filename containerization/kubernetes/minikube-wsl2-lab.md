# Wazuh on Minikube in WSL2 with a Windows Agent (Lab)

A single-machine lab: Wazuh from the official `wazuh-kubernetes` manifests on
Minikube (Docker driver) inside WSL2 Ubuntu, with the dashboard reachable from
the Windows browser and the Windows host itself enrolled as an agent. The
parts that usually go wrong are service exposure (`minikube tunnel`) and the
agent port settings.

> Applies to Wazuh 4.14.x (`wazuh-kubernetes` tags `v4.14.1` and `v4.14.5`
> checked), Minikube with the Docker driver, WSL2 Ubuntu 24.04 on Windows.
> Lab only: default credentials and self-signed certificates.

## Table of Contents

- [Requirements](#requirements)
- [Install the tools](#install-the-tools)
- [Deploy Wazuh](#deploy-wazuh)
- [Expose the services with minikube tunnel](#expose-the-services-with-minikube-tunnel)
- [Enroll the Windows host as an agent](#enroll-the-windows-host-as-an-agent)
- [Troubleshooting](#troubleshooting)
- [Cleanup](#cleanup)
- [Related](#related)

## Requirements

- Windows with WSL2 (`wsl --install -d Ubuntu` from an elevated PowerShell).
- 4 CPUs, 8 GB RAM, and 30 GB of disk for the Minikube node.
- Outbound internet for the images.

## Install the tools

Inside WSL Ubuntu:

```bash
sudo apt update && sudo apt install -y docker.io curl git ca-certificates
sudo usermod -aG docker $USER && newgrp docker

curl -LO "https://dl.k8s.io/release/$(curl -Ls https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -m 0755 kubectl /usr/local/bin/kubectl

curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube

minikube start --driver=docker --cpus=4 --memory=8g --disk-size=30g
kubectl get nodes
```

[K9s](https://k9scli.io/) is a useful optional terminal UI (`k9s -n wazuh`).

## Deploy Wazuh

```bash
git clone --depth 1 -b v<WAZUH_VERSION> https://github.com/wazuh/wazuh-kubernetes.git
cd wazuh-kubernetes

# local-env patches the StorageClass to microk8s; Minikube uses its own provisioner
sed -i 's|microk8s.io/hostpath|k8s.io/minikube-hostpath|' envs/local-env/storage-class.yaml

bash wazuh/certs/indexer_cluster/generate_certs.sh
bash wazuh/certs/dashboard_http/generate_certs.sh

kubectl apply -k envs/local-env
kubectl -n wazuh get pods -w      # wait for every pod 1/1 Running
```

The `sed` is the only StorageClass change needed. Copying the built-in
`standard` class under the name `wazuh-storage` as well is redundant, since
the kustomize patch already creates `wazuh-storage` with the same provisioner.

## Expose the services with minikube tunnel

The `dashboard`, `wazuh` (master: 1515 enrollment, 55000 API), and
`wazuh-workers` (1514 events) Services are all `type: LoadBalancer`. On
Minikube they stay `<pending>` until a tunnel runs. In a second WSL terminal,
left open:

```bash
minikube tunnel      # asks for your sudo password to bind 443 and other low ports
```

```bash
kubectl -n wazuh get svc     # EXTERNAL-IP should now be 127.0.0.1
```

WSL2 forwards `localhost` to Windows, so the Windows browser reaches the
dashboard at `https://127.0.0.1`. Log in as `admin` with the password from
`wazuh/secrets/indexer-cred-secret.yaml` (repo default `SecretPassword`).

## Enroll the Windows host as an agent

From PowerShell on the same Windows host:

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-<WAZUH_VERSION>-1.msi -OutFile "$env:TEMP\wazuh-agent.msi"
msiexec.exe /i "$env:TEMP\wazuh-agent.msi" /q WAZUH_MANAGER="127.0.0.1" WAZUH_REGISTRATION_PASSWORD="<AUTHD_PASSWORD>" WAZUH_AGENT_NAME="win-lab" WAZUH_AGENT_GROUP="default"
NET START WazuhSvc
```

`<AUTHD_PASSWORD>` is in `wazuh/secrets/wazuh-authd-pass-secret.yaml` (repo
default `password`).

> Leave `WAZUH_MANAGER_PORT` unset. It sets the event port (default 1514), not
> the enrollment port. Setting it to 1515 makes the agent enroll correctly and
> then send its events to the enrollment service, so it never shows as active.
> Enrollment always uses 1515 (`WAZUH_REGISTRATION_PORT`).

Enrollment goes to the master Service and events to the workers Service. Both
work with one `WAZUH_MANAGER` address here only because the tunnel publishes
every LoadBalancer on `127.0.0.1`.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Services `EXTERNAL-IP <pending>`, dashboard unreachable | No `minikube tunnel` running, or its sudo prompt was not answered | Run the tunnel in its own terminal and enter the password |
| Dashboard shows the API offline on first login | Manager API came up before the dashboard checked it | `kubectl -n wazuh exec wazuh-manager-master-0 -- /var/ossec/bin/wazuh-control restart`, then refresh |
| Agent enrolled but never active | `WAZUH_MANAGER_PORT=1515`, or the tunnel stopped | Reinstall without `WAZUH_MANAGER_PORT`; keep the tunnel open |
| Manager pod `Permission denied` under `/var/ossec` on its volume | Volume ownership does not match the `wazuh` user | Check the UID with `kubectl -n wazuh exec wazuh-manager-master-0 -- id wazuh` and set `spec.template.spec.securityContext.fsGroup` to it in both manager StatefulSets (the repo ships `101`) |
| PVCs `Pending` | StorageClass still points at `microk8s.io/hostpath` | Apply the `sed` above and re-apply the overlay |

More kubectl diagnostics: [Cluster debugging](cluster-debugging.md).

## Cleanup

```bash
minikube delete --all
docker system prune -a --volumes   # removes ALL unused Docker images and volumes in this WSL distro
```

To remove the whole distro: `wsl --unregister Ubuntu` (PowerShell).

## Related

- [Wazuh on k3s with Rancher management](k3s-rancher-lab.md) - two-VM Vagrant lab
- [Cluster debugging](cluster-debugging.md) - minikube DNS, OOMKilled loops, indexer and dashboard checks
- [Load balancing, ingress & proxies](load-balancing-and-ingress.md)
- [Wazuh deployment on Kubernetes](https://documentation.wazuh.com/current/deployment-options/deploying-with-kubernetes/index.html)
