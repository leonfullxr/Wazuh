# Single-Node Docker Deployment and Traefik Overlay

This directory is a reference overlay for a single Wazuh manager, indexer, and
dashboard. A single-node stack is appropriate for a lab, evaluation, or a
small environment that accepts one-host failure risk. It is not highly
available.

The Compose file under `traefik/` is not a complete standalone distribution:
it expects the `config/` tree from the official `wazuh-docker` single-node
deployment at the same Wazuh version. Start from the official repository,
copy or apply the relevant changes as an overlay, and review the diff during
every upgrade.

## Prerequisites

- Docker Engine and the Compose plugin.
- A checked-out official `wazuh-docker` release matching every image tag.
- Sufficient memory, disk, `vm.max_map_count`, and file-descriptor limits.
- DNS and a trusted certificate for public dashboard access.
- An external Traefik `frontend` network if using the labels in the example.

Do not commit a populated `.env`. Use unique passwords and store production
secrets in a protected deployment secret mechanism.

## Deployment workflow

1. Select one Wazuh version and use it consistently:

   ```bash
   git clone --depth 1 --branch v<WAZUH_VERSION> \
     https://github.com/wazuh/wazuh-docker.git
   cd wazuh-docker/single-node
   ```

2. Copy the environment template to a local ignored file and set unique
   values for:

   ```text
   INDEXER_USERNAME
   INDEXER_PASSWORD
   DASHBOARD_USERNAME
   DASHBOARD_PASSWORD
   API_USERNAME
   API_PASSWORD
   ```

3. Generate the central-component certificates using the official release's
   generator and verify that the expected files exist under
   `config/wazuh_indexer_ssl_certs/`.

4. Apply the service, volume, and Traefik-label changes from
   [`traefik/docker-compose.yml`](traefik/docker-compose.yml) to the official
   Compose file. Do not copy a stale image tag into a newer configuration
   tree.

5. Validate before starting:

   ```bash
   docker compose config --quiet
   sysctl vm.max_map_count
   docker compose pull
   ```

6. Start and wait for health:

   ```bash
   docker compose up -d
   docker compose ps
   docker compose logs --since=10m wazuh.indexer
   docker compose logs --since=10m wazuh.manager
   docker compose logs --since=10m wazuh.dashboard
   ```

## Traefik exposure

The example assumes Traefik already owns an external Docker network named
`frontend`. Attach only the dashboard service to that network and route a
real FQDN such as `wazuh.example.com` to dashboard port `5601`.

Production safeguards:

- Remove the dashboard host-port mapping when Traefik is the only ingress
  path.
- Do not publish indexer port 9200 or manager API port 55000 to the Internet.
- Restrict agent enrollment 1515 and syslog 514 at the host firewall.
- Use a DNS challenge or another controlled certificate resolver; never put a
  provider token directly in Compose labels.
- Set the Traefik backend scheme to `https` and define how Traefik validates
  the dashboard certificate. Do not disable verification globally.
- Add security headers and an upstream access policy appropriate to the SOC.

Example labels after replacing the hostname and certificate resolver:

```yaml
labels:
  - traefik.enable=true
  - traefik.http.routers.wazuh.rule=Host(`wazuh.example.com`)
  - traefik.http.routers.wazuh.entrypoints=websecure
  - traefik.http.routers.wazuh.tls=true
  - traefik.http.routers.wazuh.tls.certresolver=<CERT_RESOLVER>
  - traefik.http.services.wazuh.loadbalancer.server.port=5601
  - traefik.http.services.wazuh.loadbalancer.server.scheme=https
networks:
  - frontend
```

## Verification

```bash
curl --fail --show-error \
  --cacert <PUBLIC_OR_PRIVATE_CA_FILE> \
  https://wazuh.example.com/app/login
docker compose exec wazuh.manager filebeat test output
docker compose exec wazuh.indexer \
  curl --fail --silent --cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
  -u "<INDEXER_USERNAME>:<INDEXER_PASSWORD>" \
  https://localhost:9200/_cluster/health
```

Verify persistent volumes exist and test a controlled restart:

```bash
docker compose down
docker volume ls | grep wazuh
docker compose up -d
```

The dashboard, agents, and indexed data must return without regenerating
credentials or losing configuration.

## See also

- [Official Wazuh Docker deployment](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html)
- [Docker backup and migration](../backup-and-migration.md)
- [Docker network and proxy debugging](../network-proxy-debugging.md)
- [Certificate hub](../../../certificates/README.md)
