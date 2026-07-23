# Wazuh on Docker Swarm and Portainer

**Applies to:** Wazuh 4.x, Docker Swarm / Portainer stacks, [wazuh-docker](https://github.com/wazuh/wazuh-docker) images

[Back to Docker README](./README.md)

## Overview

Wazuh does not ship official Docker Swarm or Portainer deployment files: the official `wazuh-docker` repository targets plain Docker Compose. The compose files can nevertheless be adapted to run as Swarm stacks (including Portainer-managed ones), and this guide collects the adaptations and failure modes seen in real deployments: certificate generation, service naming, shared (NFS) volume storage, port remapping for multiple stacks on one host, and agent enrollment against non-default ports.

## Certificate generation: why Portainer alone is not enough

The official deployment is a two-step process: a throwaway `generator` service creates the TLS certificates, then the actual stack mounts them:

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.x.y
cd wazuh-docker/single-node/
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
```

Portainer stacks only accept a single compose file per stack, so the generator cannot run as part of the stack. Merging the two files (`docker compose -f generate-indexer-certs.yml -f docker-compose.yml config > merged.yml`) does not work either: the Wazuh services declare file bind mounts of certificates that do not exist yet, so container creation fails with:

```text
error mounting ".../config/wazuh_indexer_ssl_certs/admin-key.pem" ...
Are you trying to mount a directory onto a file (or vice-versa)?
```

Docker creates a *directory* at the missing host path, and the mount of a directory onto a file inside the container is rejected. The same happens with Portainer's "upload compose file" and "git repository" stack options: the certificates are simply not there.

**Working approach:** SSH into the Swarm/Portainer host, clone the repository, run the certificate generator once from the CLI, and only then deploy the stack (from the CLI or by pointing Portainer at the on-disk compose file). After that, the running stack is fully manageable from the Portainer UI.

## Service names: no underscores, ever

Swarm prefixes service container hostnames with the stack name using an underscore (e.g. `mystack_wazuh1-indexer`). This breaks the indexer cluster in a non-obvious way: underscores are not valid in hostnames used for TLS certificates and OpenSearch cluster discovery. The symptom is a cluster that never forms, with errors such as:

```text
BindTransportException[Failed to resolve host [wazuh1.indexer]]; nested: UnknownHostException
BindTransportException[Failed to bind to <ip>:[9300-9400]]; nested: BindException[Cannot assign requested address]
```

and TLS handshake rejections between nodes, because the node name, DNS name, and certificate CN/SAN no longer agree.

Mitigations, all of which must be applied consistently:

- Set explicit `hostname:` values on every service using hyphens only (e.g. `wazuh-cluster-b-wazuh1-indexer` instead of `wazuh-cluster-b_wazuh1-indexer`).
- Use the same hyphenated names in every `opensearch.yml` (`node.name`, `discovery.seed_hosts`, `cluster.initial_master_nodes`, `plugins.security.nodes_dn`).
- Regenerate the node certificates so the CN/SANs match those exact hostnames. When a service is reachable under more than one name (compose alias plus stack-prefixed name), include both as `subjectAltName` entries:

```ini
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
req_extensions     = req_ext

[ dn ]
CN = wazuh-indexer

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = wazuh-indexer
DNS.2 = <stack-prefixed-or-external-name>
```

If the infrastructure may change, issue certificates against FQDNs rather than IPs.

## Volumes on shared storage (NFS)

For Swarm high availability the data volumes usually live on shared storage (NFS) rather than named local volumes. Two gotchas:

- **Ownership/permissions are lost on the NFS share.** Volume directories that worked with local root-owned storage will fail once moved: the indexer in particular refuses to start (misleading Java errors) when it cannot write its data path. Fix the permissions on the share so the container users (non-root UIDs such as 1000/994) can read and write their volume directories.
- **Plan the location up front.** Cloning the repo and letting volumes default under a small root filesystem fills the disk quickly; place configs and volume bind paths on the large shared mount (e.g. `/share/wazuh/<stack>/volumes`) from the start.

Note that the indexer data path on NFS works, but network storage adds latency to an I/O-sensitive component: prefer local or guaranteed-IOPS storage for production indexers.

## Multiple stacks on one host: port remapping and agent enrollment

Running two Wazuh stacks (e.g. a single-node and a multi-node cluster) on the same Swarm host requires remapping the published ports of at least one stack:

| Purpose | Container port | Stack 1 (default) | Stack 2 (remapped example) |
|---|---|---|---|
| Agent communication | 1514 | 1514 | 1524 |
| Agent enrollment | 1515 | 1515 | 1525 |
| Wazuh API | 55000 | 55000 | 55010 |
| Indexer HTTP | 9200 | 9200 | 9210 |
| Indexer transport | 9300 | 9300 | 9310 |

The classic failure mode: agents deployed against the remapped stack with only `WAZUH_MANAGER_PORT` set enroll against the default 1515 (which belongs to the other stack) and then show up there as `never_connected`, while logging:

```text
wazuh-agentd: ERROR: (1208): Unable to connect to enrollment service at '[<ip>]:1515'
```

Always set both ports in the deployment variables when the registration port is remapped:

```powershell
msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER='<manager-fqdn>' `
  WAZUH_MANAGER_PORT='1524' WAZUH_REGISTRATION_PORT='1525' WAZUH_AGENT_NAME='<name>'
```

or enroll manually with the custom port:

```bash
/var/ossec/bin/agent-auth -m <manager-fqdn> -p 1525
```

Agents mis-enrolled in the wrong cluster must be deleted there (API or `manage_agents`) before re-enrolling, or they re-register automatically to the wrong place again.

## Fronting the stack with an NGINX stream proxy

To centralize TLS exposure (and load-balance agents across manager nodes), remove the port mappings from the Wazuh services and publish everything through an `nginx` service using the `stream` module as a TCP/TLS passthrough:

```nginx
stream {
    upstream wazuhmanager        { server wazuh.manager:55000; }
    upstream wazuhdashboard      { server wazuh.dashboard:5601; }
    upstream wazuhindexer-http   { server wazuh.indexer:9200; }
    upstream wazuhindexer-transport { server wazuh.indexer:9300; }
    upstream agents {
        hash $remote_addr consistent;    # keep each agent pinned to one manager
        server wazuh.master:1514;
        server wazuh.worker:1514;
    }

    server { listen 55000; proxy_pass wazuhmanager; }
    server { listen 443;   proxy_pass wazuhdashboard; }
    server { listen 9200;  proxy_pass wazuhindexer-http; }
    server { listen 9300;  proxy_pass wazuhindexer-transport; }
    server { listen 1514;  proxy_pass agents; }
}
```

Ports to open between components: 443 (dashboard UI), 9200 (indexer HTTP), 9300 (indexer transport, required for Cross-Cluster Search from an external console), 55000 (API), 1514/1515 (agents).

## Connecting a stack to an external Cross-Cluster Search console

When a central (VM-based) indexer/dashboard pulls data from Docker-based clusters via Cross-Cluster Search, the containerized indexer must publish a transport address the external console can resolve. In the indexer configuration (`opensearch.yml` inside the container):

```yaml
transport.port: 9300
transport.publish_port: 9300
transport.bind_host: 0.0.0.0
transport.publish_host: <externally-resolvable-fqdn>
```

Without `transport.publish_host`, the remote console receives the container's overlay-network IP during the transport handshake and fails with:

```text
handshake failed for [connectToRemoteMasterNode[<overlay-ip>:9300]]
```

## Scaling: adding an indexer node to a containerized cluster

To add an indexer (for example an extra hot node) to a running Docker-based cluster without an outage:

1. **Add a new service block** to the compose/stack file, cloned from an existing indexer service: unique `hostname`, its own data volume, and mounts for its own certificate/key plus its own `opensearch.yml`.
2. **Generate certificates for the new node** signed by the *existing* root CA (regenerating everything also works but forces restarts everywhere).
3. **Write the new node's `opensearch.yml`** with the full node list, and any role attributes it needs, e.g. for a hot node:

   ```yaml
   node.attr.temp: hot
   node.roles: [ data, ingest ]
   ```

4. **Update every existing indexer's `opensearch.yml`**: this is the step that is easy to miss:
   - add the new node to `discovery.seed_hosts` and `cluster.initial_master_nodes`
   - add the new node's certificate DN to `plugins.security.nodes_dn`
   - bump `node.max_local_storage_nodes` if you use it
5. **Re-run `docker compose up -d`** (or update the stack). Compose only recreates the changed/new services; the cluster absorbs the new node and rebalances shards.

Verify with:

```bash
curl -k -u admin:<password> 'https://<indexer>:9200/_cat/nodes?v'
curl -k -u admin:<password> 'https://<indexer>:9200/_cluster/health?pretty'
```

## Related

- [Backup and migration of Wazuh Docker installations](./backup-and-migration.md)
- [Network & proxy debugging](./network-proxy-debugging.md)
- [Single-node deployment](./single-node/)
- [Managing multiple Wazuh clusters with Cross-Cluster Search (Wazuh blog)](https://wazuh.com/blog/managing-multiple-wazuh-clusters-with-cross-cluster-search/)
