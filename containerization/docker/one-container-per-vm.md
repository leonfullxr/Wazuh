# One Container per VM across Hosts

**Applies to:** Wazuh 4.x central components in Docker, one container per VM on separate hosts

[Back to Docker README](./README.md)

## Overview

The official `wazuh-docker` multi-node stack is a single-host Docker Compose
reference: its containers communicate over a shared Compose bridge network.
Spreading one container per VM across separate hosts works, but it is not an
officially validated topology, so expect extra troubleshooting surface. If a
VM runs nothing but its Wazuh node, prefer a native install and skip the
container layer entirely.

## Networking: bridge with published ports

Use `bridge` with explicit port publishing, not `host` networking. Host mode
only avoids NAT overhead on a single Docker host; across VMs it buys nothing
and drops port and network isolation. Publish the ports each role needs and
bind them to the VM's real interface:

```bash
docker run -d --name wazuh-indexer-1 \
  -p 9200:9200 -p 9300:9300 \
  wazuh/wazuh-indexer:4.x.y
```

Restrict the VM firewall so 9200/9300 accept only the peer indexer IPs, not
`0.0.0.0`. If the deployment later moves to Swarm, prefer an overlay network
over manual per-host port mappings (see [Swarm](./swarm.md)).

## Volumes: data and certificates outside the container

Mount two categories outside the container writable layer so a `docker rm`
or recreation never touches them:

- **Data:** a bind mount or named volume for the indexer data path. Losing
  it on a node loses that node's shard data.
- **Certificates:** a bind mount from a host path holding the node cert and
  key plus the shared root and admin certs. Generate once per the
  [cross-cluster search procedure](../../indexer/cross-cluster-search.md)
  (or the single-cluster equivalent), place the files on each VM before
  first start, and restart only the affected container on rotation.

Also bind-mount indexer logs and `opensearch.yml` when config changes must
survive recreation without rebuilding the image.

## Kernel setting stays on the host

Containers share the host kernel, so set the indexer prerequisite there:

```bash
sysctl -w vm.max_map_count=262144
```

Persist it in `/etc/sysctl.conf` or a `sysctl.d` drop-in on every indexer
VM. There is no per-container namespace for this setting.

## Load balancer and certificates are unchanged

- **Dashboards** stay stateless behind the load balancer. Health checks and
  LB configuration match a native install; keep the published port stable
  across recreation (no random host ports) and let the health-check
  interval tolerate container restart time.
- **Certificates and onboarding** follow the standard procedure; only the
  destination changes from a system path to the bind-mounted host path.
  Keep the root CA stable and onboard incrementally per the
  [MSSP design notes](../../indexer/cross-cluster-search.md#mssp-design-topology-sizing-and-segmentation).
