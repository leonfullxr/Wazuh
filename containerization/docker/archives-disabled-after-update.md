# Archives disabled after container update

**Applies to:** Wazuh 4.x - Docker Compose multi-node clusters (Manager + Worker + Indexers)

[Back to Docker README](./README.md)

## Problem

After updating the Wazuh Manager image or recreating the containers, `wazuh-archives-*` indices stop receiving documents in OpenSearch. The Wazuh Dashboard shows no data in the Archives view despite logs being written to disk at `/var/ossec/logs/archives/archives.json`. No data is lost - the issue is with ingestion, not storage.

A bind mount of a custom `filebeat.yml` (with `archives: enabled: true`) to `/etc/filebeat/filebeat.yml` has no lasting effect - the setting reverts to `false` on every container startup.

## Root cause

The container entrypoint regenerates `/etc/filebeat/filebeat.yml` at every startup by copying a bundled default template from inside the image:

```text
Source template (inside image):
  /var/ossec/data_tmp/exclusion/etc/filebeat/filebeat.yml

Written to at startup:
  /etc/filebeat/filebeat.yml   <- this is what a standard bind mount targets
```

The write happens after the bind mount is applied, so the mount is silently overwritten. The default template ships with `archives: enabled: false`.

Tracked upstream at [wazuh-docker #2240](https://github.com/wazuh/wazuh-docker/issues/2240).

## Solution A Mount over the source template

Mount your custom `filebeat.yml` directly over the template the entrypoint reads, rather than the destination it writes to.

**1. Extract the full default template for your version**

Always start from the full default rather than writing a minimal file from scratch - replacing the entire file with only the archives section will drop required output and pipeline settings.

```bash
docker run --rm --entrypoint cat wazuh/wazuh-manager:<version> \
  /var/ossec/data_tmp/exclusion/etc/filebeat/filebeat.yml
```

Save the output to `./config/wazuh_cluster/filebeat.yml` and set `archives: enabled: true`:

```yaml
filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true
    archives:
      enabled: true    # <- change this from false to true
```

**2. Update `docker-compose.yml` for both Manager and Worker**

```yaml
services:
  wazuh.master:
    image: wazuh/wazuh-manager:4.14.4
    volumes:
      - ./config/wazuh_cluster/filebeat.yml:/var/ossec/data_tmp/exclusion/etc/filebeat/filebeat.yml:ro
      # ... your other existing mounts

  wazuh.worker:
    image: wazuh/wazuh-manager:4.14.4
    volumes:
      - ./config/wazuh_cluster/filebeat.yml:/var/ossec/data_tmp/exclusion/etc/filebeat/filebeat.yml:ro
      # ... your other existing mounts
```

The `:ro` flag prevents any process inside the container from modifying your source file. When the entrypoint copies the template, it reads your mounted version, so the final `/etc/filebeat/filebeat.yml` will have archives enabled.

**3. Restart the cluster**

```bash
docker compose down
docker compose up -d
```

## Solution B - Custom Docker image (CI/CD / immutable image approach)

For pipelines that favour immutable images over runtime bind mounts:

```dockerfile
FROM wazuh/wazuh-manager:4.14.4

COPY filebeat.yml /var/ossec/data_tmp/exclusion/etc/filebeat/filebeat.yml
```

No runtime mounts are needed. The configuration is baked into the image and survives `docker pull` and registry-based rollouts.

## Upgrade procedure

When moving to a new Wazuh version, the internal template may have changed. Before bringing the cluster up on the new image:

```bash
# Extract the new version's default template
docker run --rm --entrypoint cat wazuh/wazuh-manager:<new-version> \
  /var/ossec/data_tmp/exclusion/etc/filebeat/filebeat.yml > /tmp/filebeat-new.yml

# Diff against your pinned version
diff ./config/wazuh_cluster/filebeat.yml /tmp/filebeat-new.yml
```

Merge any new fields into your pinned file, update the image tag in `docker-compose.yml`, then bring the cluster up.

## Verification

```bash
# 1. Confirm the configuration is active inside the container
docker exec -it <wazuh-manager-container> \
  cat /etc/filebeat/filebeat.yml | grep -A3 archives

# Expected output:
#     archives:
#       enabled: true

# 2. Test Filebeat connectivity to the indexer
docker exec -it <wazuh-manager-container> filebeat test output

# 3. Check for archive indices in OpenSearch
curl -sk -u admin:<password> \
  "https://<indexer-host>:9200/_cat/indices/wazuh-archives-*?v&h=index,health,docs.count"

# 4. If the index is absent, inspect Filebeat logs
docker exec -it <wazuh-manager-container> tail -f /var/log/filebeat/filebeat
```

## Related

- [Kubernetes variant of this issue](../kubernetes/archives-disabled-after-update.md)
- [wazuh-docker #2240](https://github.com/wazuh/wazuh-docker/issues/2240)
- [Wazuh archives documentation](https://documentation.wazuh.com/current/user-manual/manager/wazuh-archives.html)
