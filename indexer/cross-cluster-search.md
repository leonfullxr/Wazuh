# Cross-Cluster Search (CCS)

<!-- Support: WS-31921, WS-35178, WS-32949, WS-27627, WS-33856 -->

Cross-cluster search lets a central ("main") Wazuh Indexer cluster query the
indices of one or more remote Wazuh environments: typical for multi-site or
multi-tenant setups where each site keeps its own full Wazuh stack but a
central SOC needs a single pane of glass.

Requirements that trip most deployments:

- **All nodes across all environments must trust a common root CA.** In
  practice this means regenerating certificates for every node from one CA.
- The main cluster reaches the remote indexers on the transport port
  (9300), not 9200.
- Remote indexers must list the main cluster's node certificates in
  `plugins.security.nodes_dn`.

## Table of Contents

- [1. Regenerate certificates from a shared CA](#1-regenerate-certificates-from-a-shared-ca)
- [2. Configure the remote indexers](#2-configure-the-remote-indexers)
- [3. Register the remote cluster](#3-register-the-remote-cluster)
- [4. Connect the dashboard to the remote managers](#4-connect-the-dashboard-to-the-remote-managers)
- [5. Create the remote index pattern](#5-create-the-remote-index-pattern)
- [6. LDAP authorization across CCS environments](#6-ldap-authorization-across-ccs-environments)
- [Adding a cluster later](#adding-a-cluster-later)

## 1. Regenerate certificates from a shared CA

1. Back up the existing certificates on every node of every environment:

   ```bash
   # on the managers
   mv /etc/filebeat/certs/ /etc/filebeat/certs.old/
   # on the indexers
   mv /etc/wazuh-indexer/certs/ /etc/wazuh-indexer/certs.old/
   # on the dashboard
   mv /etc/wazuh-dashboard/certs/ /etc/wazuh-dashboard/certs.old/
   ```

2. Download the certificate tool and config (match your Wazuh version):

   ```bash
   curl -sO https://packages.wazuh.com/4.12/wazuh-certs-tool.sh
   curl -sO https://packages.wazuh.com/4.12/config.yml
   ```

3. Edit `config.yml` and declare every node of every environment (main
   and remote indexers, all managers, the dashboard):

   ```yaml
   nodes:
     indexer:
       - name: main_node-1
         ip: "<MAIN_INDEXER-1_IP>"
       - name: main_node-2
         ip: "<MAIN_INDEXER-2_IP>"
       - name: remote_node-1
         ip: "<REMOTE_INDEXER-1_IP>"
     server:
       - name: main_wazuh-1
         ip: "<MAIN_MANAGER-1_IP>"
         node_type: master
       - name: main_wazuh-2
         ip: "<MAIN_MANAGER-2_IP>"
         node_type: worker
       - name: remote_wazuh-1
         ip: "<REMOTE_MANAGER-1_IP>"
         node_type: worker
     dashboard:
       - name: dashboard
         ip: "<DASHBOARD_IP>"
   ```

4. Generate and pack the certificates:

   ```bash
   ./wazuh-certs-tool.sh -A
   tar -cvf ./wazuh-certificates.tar -C ./wazuh-certificates/ .
   rm -rf ./wazuh-certificates
   ```

5. Copy `wazuh-certificates.tar` to every node and deploy:

   <details>
   <summary>Click to expand per-node deployment commands</summary>

   ```bash
   # Indexer nodes
   NODE_NAME=<INDEXER_NODE_NAME>
   mkdir /etc/wazuh-indexer/certs
   tar -xf ./wazuh-certificates.tar -C /etc/wazuh-indexer/certs/ \
     ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./admin.pem ./admin-key.pem ./root-ca.pem
   mv -n /etc/wazuh-indexer/certs/$NODE_NAME.pem /etc/wazuh-indexer/certs/indexer.pem
   mv -n /etc/wazuh-indexer/certs/$NODE_NAME-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
   chmod 500 /etc/wazuh-indexer/certs
   chmod 400 /etc/wazuh-indexer/certs/*
   chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs

   # Manager nodes (Filebeat)
   NODE_NAME=<SERVER_NODE_NAME>
   mkdir /etc/filebeat/certs
   tar -xf ./wazuh-certificates.tar -C /etc/filebeat/certs/ \
     ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./root-ca.pem
   mv -n /etc/filebeat/certs/$NODE_NAME.pem /etc/filebeat/certs/filebeat.pem
   mv -n /etc/filebeat/certs/$NODE_NAME-key.pem /etc/filebeat/certs/filebeat-key.pem
   chmod 500 /etc/filebeat/certs
   chmod 400 /etc/filebeat/certs/*
   chown -R root:root /etc/filebeat/certs

   # Dashboard node
   NODE_NAME=<DASHBOARD_NODE_NAME>
   mkdir /etc/wazuh-dashboard/certs
   tar -xf ./wazuh-certificates.tar -C /etc/wazuh-dashboard/certs/ \
     ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./root-ca.pem
   mv -n /etc/wazuh-dashboard/certs/$NODE_NAME.pem /etc/wazuh-dashboard/certs/dashboard.pem
   mv -n /etc/wazuh-dashboard/certs/$NODE_NAME-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem
   chmod 500 /etc/wazuh-dashboard/certs
   chmod 400 /etc/wazuh-dashboard/certs/*
   chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs
   ```

   </details>

## 2. Configure the remote indexers

In `/etc/wazuh-indexer/opensearch.yml` on each remote indexer, set the node
name and whitelist the main cluster's certificate DNs under
`plugins.security.nodes_dn` (DN values must match what the cert tool
generated):

```yaml
node.name: remote_node-1
cluster.initial_master_nodes:
  - remote_node-1
plugins.security.nodes_dn:
  - CN=remote_node-1,OU=Docu,O=Wazuh,L=California,C=US
  - CN=main_node-1,OU=Docu,O=Wazuh,L=California,C=US
```

Restart everything in all environments and verify Filebeat:

```bash
systemctl restart wazuh-indexer
systemctl restart wazuh-dashboard
systemctl restart filebeat
filebeat test output
```

## 3. Register the remote cluster

On the main cluster, declare the remote seed nodes (transport port 9300):

```http
PUT _cluster/settings
{
  "persistent": {
    "cluster": {
      "remote": {
        "remote_cluster": {
          "seeds": [
            "<REMOTE_INDEXER-1_IP>:9300",
            "<REMOTE_INDEXER-2_IP>:9300",
            "<REMOTE_INDEXER-3_IP>:9300"
          ]
        }
      }
    }
  }
}
```

Test: remote indices are addressed as `<cluster-alias>:<index-pattern>`:

```http
GET remote_cluster:wazuh-alerts-*/_search
```

## 4. Connect the dashboard to the remote managers

So the Wazuh app can also manage the remote environments' agents, add their
manager APIs to `/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml`:

```yaml
hosts:
  - default:
      url: https://<MAIN_MANAGER_MASTER_IP>
      port: 55000
      username: wazuh-wui
      password: <WUI_PASSWORD>
      run_as: false
  - remote-1:
      url: https://<REMOTE_MANAGER-1_IP>
      port: 55000
      username: wazuh-wui
      password: <WUI_PASSWORD>
      run_as: false
```

## 5. Create the remote index pattern

The dashboard needs an index pattern named after the remote alias. Clone the
existing `wazuh-alerts-*` pattern rather than building one by hand:

```bash
# Download the current wazuh-alerts index pattern
curl -sS -k -u <USERNAME>:<PASSWORD> \
  -XGET "https://<DASHBOARD_IP>/api/saved_objects/index-pattern/wazuh-alerts-*?pretty" \
  -o wazuh-alerts-pattern.json

# Strip the instance-specific fields
jq 'del(.references, .id, .type, .version, .updated_at, .migrationVersion, .namespaces)' \
  wazuh-alerts-pattern.json > entries-removed.json

# Rename it to target the remote cluster
jq '.attributes.title = "remote_cluster:wazuh-alerts-*"' entries-removed.json > new-pattern.json

# Load it
curl -sS -k -u <USERNAME>:<PASSWORD> \
  -XPOST "https://<DASHBOARD_IP>/api/saved_objects/index-pattern/remote_cluster:wazuh-alerts-*" \
  -H 'Content-Type: application/json' -H 'kbn-xsrf: true' \
  -d @new-pattern.json
```

Restart the services once more, then select the
`remote_cluster:wazuh-alerts-*` pattern in the dashboard to browse remote
alerts.

## 6. LDAP authorization across CCS environments

CCS introduces two separate authorization planes:

1. The central indexer cluster authorizes searches against local and
   remote index patterns through OpenSearch Security roles.
2. Each tenant Wazuh manager API authorizes agent and configuration
   operations through Wazuh server RBAC.

Configure LDAP authentication and authorization on the central indexer using
the [LDAP and Active Directory guide](../troubleshooting/ldap-ad.md). Back up
`/etc/wazuh-indexer/opensearch-security/` before changing it and keep the
LDAP CA on every central indexer node.

Map directory groups to indexer roles in
`/etc/wazuh-indexer/opensearch-security/roles_mapping.yml`. Built-in roles are
a safe baseline:

```yaml
all_access:
  reserved: false
  hidden: false
  backend_roles:
    - "admin"
    - "wazuh-ccs-admins"

readall:
  reserved: true
  hidden: false
  backend_roles:
    - "readall"
    - "wazuh-ccs-readonly"
```

Push `config.yml` and `roles_mapping.yml` separately; loading one does not
apply the other:

```bash
export JAVA_HOME=/usr/share/wazuh-indexer/jdk/
SECURITY_ADMIN=/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh

sudo bash "$SECURITY_ADMIN" \
  -f /etc/wazuh-indexer/opensearch-security/config.yml \
  -icl \
  -key /etc/wazuh-indexer/certs/admin-key.pem \
  -cert /etc/wazuh-indexer/certs/admin.pem \
  -cacert /etc/wazuh-indexer/certs/root-ca.pem \
  -h 127.0.0.1 -nhnv

sudo bash "$SECURITY_ADMIN" \
  -f /etc/wazuh-indexer/opensearch-security/roles_mapping.yml \
  -icl \
  -key /etc/wazuh-indexer/certs/admin-key.pem \
  -cert /etc/wazuh-indexer/certs/admin.pem \
  -cacert /etc/wazuh-indexer/certs/root-ca.pem \
  -h 127.0.0.1 -nhnv
```

On the central dashboard, set `run_as: true` for each manager API entry only
after the corresponding Wazuh server role mappings are ready. In Server
management > Security > Roles mapping on every tenant manager:

- Map the LDAP administrator backend role to the Wazuh `administrator` role.
- Map the LDAP read-only backend role to the Wazuh `readonly` role.

The indexer and manager role names are separate namespaces. A successful
remote-index search does not grant agent-management permissions, and a Wazuh
server role does not grant access to remote OpenSearch indices.

Verify with one administrator and one read-only account:

```http
GET _plugins/_security/authinfo
GET remote_cluster:wazuh-alerts-*/_search?size=1
```

Confirm the read-only account can search the intended remote alias but cannot
write indices or modify agents. When using custom indexer roles instead of
`readall`, explicitly include the remote alias/index patterns and test them on
the bundled OpenSearch version; do not assume a local index permission
automatically covers `<cluster-alias>:<index-pattern>`.

## Adding a cluster later

To onboard a new tenant/environment without regenerating everything, sign the
new nodes' certificates with the same root CA:

```bash
openssl genrsa -out filebeat-remote2-key.pem 2048
openssl req -new -key filebeat-remote2-key.pem -out filebeat-remote2.csr \
  -subj "/CN=filebeat-remote2/O=Wazuh/OU=Wazuh/C=US"
openssl x509 -req -in filebeat-remote2.csr \
  -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial \
  -out filebeat-remote2.pem -days 3650 -sha256 \
  -extfile <(printf "subjectAltName=DNS:filebeat-remote2,IP:<REMOTE_MANAGER_IP>")
```

Then repeat steps 2-5 for the new environment only. After onboarding, review
[replica settings](replicas.md) on the remote indices and confirm
[cluster health](shard-management.md#cluster-health-red-and-yellow-states)
on both sides. For a complete multi-SAN or corporate-CA workflow, use the
[component certificate guide](../certificates/component-certificates.md).
