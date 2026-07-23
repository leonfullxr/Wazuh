# Docker network and proxy debugging

**Applies to:** Wazuh Docker deployments (single/multi-node), proxy-authenticated environments

[Back to Docker README](./README.md)

## Overview

Command reference for diagnosing connectivity problems in containerized Wazuh deployments: containers that cannot reach each other, and outbound traffic that must traverse an HTTP proxy (a common requirement in corporate networks, e.g. when the dashboard or integrations need to reach identity providers such as Microsoft Entra ID).

## Inspecting container networking

```bash
# IP address of a container (e.g. an indexer node in the multi-node compose stack)
sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' multi-node-wazuh1.indexer-1

# Interfaces from inside the container's network namespace,
# without needing ip/ifconfig installed in the image
docker run --rm --network container:multi-node-wazuh1.indexer-1 busybox ip addr

# Or directly, if the image ships iproute2
docker exec -it multi-node-wazuh1.indexer-1 ip a
```

## Testing service-to-service reachability

```bash
# Resolve and reach another service by its compose service name
curl -v http://wazuh1.indexer
```

Name resolution failures here usually mean the containers are not on the same Docker network: check the `networks:` sections of the compose file.

## Testing proxy connectivity

```bash
# Verify the proxy forwards traffic (172.17.0.1 = docker0 gateway, i.e. proxy on the host)
curl -v -x http://172.17.0.1:3128 http://ifconfig.me

# Confirm on the proxy side that the request went through (Squid example)
docker logs squid-proxy | grep "ifconfig.me"

# Test outbound connectivity from inside a specific container
docker exec -it <CONTAINER_NAME> curl -v http://ifconfig.me

# Check which proxy variables the container actually sees
docker exec -it <CONTAINER_NAME> env | grep -i proxy
```

Common failure modes:

- **Proxy variables set on the host but not in the container.** `http_proxy`/`https_proxy`/`no_proxy` must be passed via `environment:` in the compose file (or `-e` flags); containers do not inherit the host shell environment.
- **`no_proxy` missing internal names.** Inter-container traffic (indexer, manager, dashboard hostnames) must be excluded from the proxy, otherwise TLS connections between Wazuh components are sent to the proxy and fail.
- **Proxy reachable from the host but not from containers.** Use the `docker0` gateway address (typically `172.17.0.1`) or the host's LAN IP rather than `localhost`, which resolves to the container itself.

## Related

- [Wazuh agent DaemonSet (custom image)](../kubernetes/agent-daemonset.md) - containerized agents where these issues typically surface
- [Kubernetes cluster debugging](../kubernetes/cluster-debugging.md)
