# Backup, restore, and migration of Wazuh Docker installations

**Applies to:** Wazuh 4.x, Docker Compose deployments (single-node and multi-node)

[Back to Docker README](./README.md)

## Overview

Wazuh data in a Docker deployment lives in named Docker volumes (indexer data, manager `etc`/`queue`/`logs`, dashboard config, etc.), plus the `docker-compose.yml` and `config/` directory (including certificates) on the host. To move an installation to new machines (or to take a recoverable backup), copy the volumes and the config, not the underlying disk.

Physically moving the data disk to a new host can work, but only if the directory structure, permissions, Docker volume names, and certificates are all identical. It is fragile and not recommended for production. The reliable procedure is a volume-level backup and restore.

## 1. Back up the cluster

Stop the containers first so the data is quiesced:

```bash
cd /path/to/wazuh-docker/<single-node|multi-node>
docker compose down
```

List the Wazuh volumes:

```bash
docker volume ls | grep wazuh
```

Back each volume up into a tarball. This runs a throwaway `alpine` container that mounts the volume and tars its contents:

```bash
mkdir -p /backup/wazuh
for vol in $(docker volume ls -q | grep wazuh); do
  docker run --rm -v ${vol}:/data -v /backup/wazuh:/backup alpine \
    tar czf /backup/${vol}.tar.gz -C /data .
done
```

`tar: socket ignored` warnings for files under `queue/`, `sockets/`, `router/`, `alerts/` are expected and harmless: those are UNIX sockets, not data.

For large production volumes the plain command shows no progress. Add tar checkpoints:

```bash
tar czf /backup/${vol}.tar.gz -C /data . \
  --checkpoint=.1000 --checkpoint-action=echo="Processed %u files"
```

or use a progress bar with `pv`:

```bash
for vol in $(docker volume ls -q | grep wazuh); do
  docker run --rm -v ${vol}:/data -v /backup/wazuh:/backup alpine sh -c \
    "apk add --no-cache pv >/dev/null && \
     tar cf - -C /data . | pv -pterab -s \$(du -sb /data | awk '{print \$1}') | \
     gzip > /backup/${vol}.tar.gz"
done
```

Finally, back up the configuration and certificates:

```bash
cp -a docker-compose.yml config/ /backup/wazuh/
```

In older image versions the certificates may live outside `config/`, so back those up too.

## 2. Restore on the new host

Recreate the empty volumes by deploying the same Wazuh version once, then stopping it. This guarantees the volume names match exactly what the restore loop expects:

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v<same-version>
cd wazuh-docker/<single-node|multi-node>
docker compose create   # creates named volumes without starting services
docker compose down
docker volume ls | grep wazuh   # verify the volumes exist
```

Restore each tarball into its matching volume:

```bash
for file in /backup/wazuh/*.tar.gz; do
  vol=$(basename "$file" .tar.gz)
  echo "Restoring volume: $vol"
  docker run --rm -v ${vol}:/data -v /backup/wazuh:/backup alpine \
    sh -c "cd /data && tar xzf /backup/${vol}.tar.gz"
done
```

Restore the config and compose file, then start the cluster:

```bash
cp -a /backup/wazuh/config ./config
cp -a /backup/wazuh/docker-compose.yml ./
docker compose up -d
docker compose ps
```

## Consistency requirements

The restore only works cleanly when the target matches the source:

- **Same Wazuh version.** Clone the same `-b vX.Y.Z` tag. If you also intend to upgrade, restore first on the matching version, verify, then follow the [upgrade procedure](https://documentation.wazuh.com/current/deployment-options/docker/upgrading-wazuh-docker.html) separately.
- **Same volume names.** These are derived from the compose project (directory) name, so keep the deployment in a directory with the same name, or recreate the volumes with `docker compose create` as above.
- **Certificates and hostnames.** If the new host has a different IP or hostname, update the certificates and every reference to it (`opensearch.yml`, `wazuh_manager.conf`, reverse-proxy config, compose environment variables).

## Verification

```bash
docker compose ps                              # all services Up
docker logs <container> --tail 50              # no startup errors
curl -k -u admin:<password> \
  'https://<indexer-host>:9200/_cluster/health?pretty'   # status green, expected node count
```

Confirm on the dashboard that historical alerts are present and that agents reconnect.

## Related

- [Wazuh on Docker Swarm and Portainer](./swarm.md)
- [Archives disabled after container update](./archives-disabled-after-update.md)
- [Upgrading Wazuh on Docker](https://documentation.wazuh.com/current/deployment-options/docker/upgrading-wazuh-docker.html)
