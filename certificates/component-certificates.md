# Wazuh Component Certificates

How to generate, deploy, regenerate and replace the TLS certificates used by the Wazuh indexer, server (Filebeat), and dashboard — including custom CSRs for corporate CAs and the special cases of cross-cluster search and WPK agent upgrades.

## Table of Contents

- [Certificate layout recap](#certificate-layout-recap)
- [Generating certificates with wazuh-certs-tool](#generating-certificates-with-wazuh-certs-tool)
- [Deploying certificates on each component](#deploying-certificates-on-each-component)
- [Regenerating certificates across environments (cross-cluster search)](#regenerating-certificates-across-environments-cross-cluster-search)
- [Using a corporate or commercial CA (custom CSR)](#using-a-corporate-or-commercial-ca-custom-csr)
- [Extracting certificates from a PKCS#12 (.pfx) bundle](#extracting-certificates-from-a-pkcs12-pfx-bundle)
- [Signing additional certificates with an existing root CA](#signing-additional-certificates-with-an-existing-root-ca)
- [WPK upgrade CA on agents](#wpk-upgrade-ca-on-agents)
- [Verification](#verification)

## Certificate layout recap

All components trust a single `root-ca.pem`. Each node has its own certificate/key pair, renamed to a fixed filename during deployment:

| Component | Directory | Files |
|---|---|---|
| Indexer | `/etc/wazuh-indexer/certs/` | `indexer.pem`, `indexer-key.pem`, `admin.pem`, `admin-key.pem`, `root-ca.pem` |
| Server (Filebeat) | `/etc/filebeat/certs/` | `filebeat.pem`, `filebeat-key.pem`, `root-ca.pem` |
| Dashboard | `/etc/wazuh-dashboard/certs/` | `dashboard.pem`, `dashboard-key.pem`, `root-ca.pem` |

The indexer references its files in `/etc/wazuh-indexer/opensearch.yml`:

```yaml
plugins.security.ssl.transport.pemcert_filepath: certs/indexer.pem
plugins.security.ssl.transport.pemkey_filepath: certs/indexer-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: certs/root-ca.pem
```

Make sure these paths point at the files you think they do.

## Generating certificates with wazuh-certs-tool

1. Download the certificate tool and its configuration template (replace `4.x` with your version branch):

    ```bash
    curl -sO https://packages.wazuh.com/4.x/wazuh-certs-tool.sh
    curl -sO https://packages.wazuh.com/4.x/config.yml
    ```

2. Edit `config.yml` and declare every node in the deployment with its name and IP. Add as many node entries as needed:

    ```yaml
    nodes:
      # Wazuh indexer nodes
      indexer:
        - name: node-1
          ip: "<INDEXER_NODE_IP>"
        - name: node-2
          ip: "<INDEXER_NODE_IP>"

      # Wazuh server nodes
      # If there is more than one server node, each must have a node_type
      server:
        - name: wazuh-1
          ip: "<WAZUH_MANAGER_IP>"
          node_type: master
        - name: wazuh-2
          ip: "<WAZUH_MANAGER_IP>"
          node_type: worker

      # Wazuh dashboard nodes
      dashboard:
        - name: dashboard
          ip: "<DASHBOARD_NODE_IP>"
    ```

3. Run the tool and package the output:

    ```bash
    bash ./wazuh-certs-tool.sh -A
    tar -cvf ./wazuh-certificates.tar -C ./wazuh-certificates/ .
    rm -rf ./wazuh-certificates
    ```

4. Copy `wazuh-certificates.tar` to every node.

> **Tip:** before replacing certificates on a live cluster, back up the current ones:
>
> ```bash
> # on managers:
> mv /etc/filebeat/certs/ /etc/filebeat/certs.old/
> # on indexers:
> mv /etc/wazuh-indexer/certs/ /etc/wazuh-indexer/certs.old/
> # on the dashboard:
> mv /etc/wazuh-dashboard/certs/ /etc/wazuh-dashboard/certs.old/
> ```

## Deploying certificates on each component

With `wazuh-certificates.tar` in the working directory of each node:

**Indexer nodes**

```bash
NODE_NAME=<INDEXER_NODE_NAME>
mkdir /etc/wazuh-indexer/certs
tar -xf ./wazuh-certificates.tar -C /etc/wazuh-indexer/certs/ \
  ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./admin.pem ./admin-key.pem ./root-ca.pem
mv -n /etc/wazuh-indexer/certs/$NODE_NAME.pem /etc/wazuh-indexer/certs/indexer.pem
mv -n /etc/wazuh-indexer/certs/$NODE_NAME-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
chmod 500 /etc/wazuh-indexer/certs
chmod 400 /etc/wazuh-indexer/certs/*
chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs
```

**Server (manager) nodes**

```bash
NODE_NAME=<SERVER_NODE_NAME>
mkdir /etc/filebeat/certs
tar -xf ./wazuh-certificates.tar -C /etc/filebeat/certs/ \
  ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./root-ca.pem
mv -n /etc/filebeat/certs/$NODE_NAME.pem /etc/filebeat/certs/filebeat.pem
mv -n /etc/filebeat/certs/$NODE_NAME-key.pem /etc/filebeat/certs/filebeat-key.pem
chmod 500 /etc/filebeat/certs
chmod 400 /etc/filebeat/certs/*
chown -R root:root /etc/filebeat/certs
```

**Dashboard node**

```bash
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

Restart the services and verify:

```bash
systemctl restart wazuh-indexer
systemctl restart wazuh-dashboard
systemctl restart filebeat
filebeat test output
```

## Regenerating certificates across environments (cross-cluster search)

Cross-cluster search (CCS) between a main and one or more remote indexer clusters requires **all nodes in all environments to share the same root CA**. The practical approach is to list every node from every environment in a single `config.yml`, generate one certificate bundle, and deploy it everywhere (steps above).

Two extra CCS-specific steps:

1. On the remote indexers, allow the main cluster's node certificates by DN in `/etc/wazuh-indexer/opensearch.yml`:

    ```yaml
    node.name: remote_node-1
    cluster.initial_master_nodes:
      - remote_node-1
    plugins.security.nodes_dn:
      - CN=remote_node-1,OU=Docu,O=Wazuh,L=California,C=US
      - CN=main_node-1,OU=Docu,O=Wazuh,L=California,C=US
    ```

2. Register the remote cluster seeds on the main cluster and test:

    ```
    PUT _cluster/settings
    {
      "persistent": {
        "cluster": {
          "remote": {
            "remote_cluster": {
              "seeds": [
                "<REMOTE_INDEXER_IP>:9300"
              ]
            }
          }
        }
      }
    }

    GET remote_cluster:wazuh-alerts-*/_search
    ```

To add a new environment later without regenerating everything, sign the new node's certificate with the **existing** CCS root CA key — see [Signing additional certificates](#signing-additional-certificates-with-an-existing-root-ca).

## Using a corporate or commercial CA (custom CSR)

When the certificate must be issued by your organization's PKI or a commercial CA (DigiCert, GlobalSign, Sectigo, ...), generate the key and CSR yourself and hand the CSR to the CA.

1. Create a private key and convert it to PKCS#8 (the format the Wazuh components expect):

    ```bash
    openssl genrsa -out wazuh-server-key-temp.pem 2048
    openssl pkcs8 -inform PEM -outform PEM -in wazuh-server-key-temp.pem \
      -topk8 -nocrypt -v1 PBE-SHA1-3DES -out wazuh-server-key.pem
    ```

2. Create an OpenSSL config with your hostnames/IPs in the **`alt_names`** section (the SAN must contain every name or IP clients will use):

    ```bash
    cat <<EOL > openssl.cnf
    [ req ]
    default_bits       = 2048
    distinguished_name = req_distinguished_name
    req_extensions     = v3_req
    prompt             = no

    [ req_distinguished_name ]
    C  = US
    L  = California
    O  = Example
    OU = Security
    CN = wazuh-server

    [ v3_req ]
    subjectAltName = @alt_names

    [ alt_names ]
    DNS.1 = wazuh.example.com
    IP.1  = 10.0.0.10   # replace with your server IP
    EOL
    ```

3. Generate the CSR:

    ```bash
    openssl req -new -key wazuh-server-key.pem -out wazuh-server.csr -config openssl.cnf
    ```

4. Submit `wazuh-server.csr` to the CA (portal upload or internal PKI workflow), complete domain validation, and download the issued certificate **plus any intermediate CA bundle**.

5. Install the certificate and key on the component (for example the dashboard) and reference the **full chain**, otherwise clients cannot build a path to a trusted root:

    ```yaml
    server.ssl.enabled: true
    server.ssl.key: "/etc/wazuh-dashboard/certs/wazuh-server-key.pem"
    server.ssl.certificate: "/etc/wazuh-dashboard/certs/wazuh-server.pem"
    ```

> For public FQDNs you can also use **Let's Encrypt** (free, automated, 90-day validity) instead of a paid CA — see [https-for-private-ip.md](https-for-private-ip.md#public-fqdns-lets-encrypt-and-commercial-cas) for the certbot workflow.

## Extracting certificates from a PKCS#12 (.pfx) bundle

Corporate CAs often deliver a single `.pfx`/`.p12` file. Split it into the PEM files Wazuh needs:

```bash
# Private key (unencrypted PEM)
openssl pkcs12 -in bundle.pfx -nocerts -nodes -out server.key

# Server (leaf) certificate
openssl pkcs12 -in bundle.pfx -clcerts -nokeys -out server.crt

# CA chain (intermediates + root)
openssl pkcs12 -in bundle.pfx -nokeys -cacerts -out chain.crt

# Inspect the extracted chain
openssl crl2pkcs7 -nocrl -certfile chain.crt | openssl pkcs7 -print_certs -noout
```

## Signing additional certificates with an existing root CA

To issue a certificate for a new node (for example a new Filebeat/manager in a CCS environment) using the root CA generated earlier:

```bash
openssl genrsa -out filebeat-new-key.pem 2048
openssl req -new -key filebeat-new-key.pem -out filebeat-new.csr \
  -subj "/CN=filebeat-new/O=Example/OU=Security/C=US"
openssl x509 -req -in filebeat-new.csr \
  -CA root-ca.pem -CAkey root-ca.key -CAcreateserial \
  -out filebeat-new.pem -days 365 -sha256 \
  -extfile <(printf "subjectAltName=IP:<NODE_IP>")
```

The `-extfile` line is important: without a SAN, hostname verification will fail even though the certificate is otherwise valid.

## WPK upgrade CA on agents

Remote agent upgrades (WPK packages) are signed, and each agent verifies the signature against a CA store (`<ca_store>` in `ossec.conf`). When Wazuh rotates the WPK root CA, agents with the old CA will refuse to upgrade until the new CA is installed.

Download the current `wpk_root.pem` from the [official Wazuh repository](https://github.com/wazuh/wazuh/blob/master/etc/wpk_root.pem) and install it on each agent:

**Linux**

```bash
curl -o /var/ossec/etc/wpk_root_new.pem https://raw.githubusercontent.com/wazuh/wazuh/master/etc/wpk_root.pem
chown root:wazuh /var/ossec/etc/wpk_root_new.pem
```

Add a second `<ca_store>` entry so both the old and the new CA are accepted:

```xml
<ossec_config>
  <active-response>
    <disabled>no</disabled>
    <ca_store>etc/wpk_root.pem</ca_store>
    <ca_store>etc/wpk_root_new.pem</ca_store>
    <ca_verification>yes</ca_verification>
  </active-response>
</ossec_config>
```

Restart the agent (`systemctl restart wazuh-agent` on Linux, `net stop Wazuh && net start Wazuh` on Windows). On Windows the CA store lives in `C:\Program Files (x86)\ossec-agent\`; on macOS in `/Library/Ossec/etc/`.

Notes:

- This cannot be done centrally from the dashboard — distribute the CA file with your configuration management tooling.
- Once the new CA is in place, upgrade agents remotely as described in the [agent upgrade guide](https://documentation.wazuh.com/current/upgrade-guide/wazuh-agent/index.html), e.g.:

    ```bash
    /var/ossec/bin/agent_upgrade -v v4.7.4 -a <AGENT_ID>
    ```

- `Send lock restart error` / `Send open file error` during an upgrade mean the manager did not get an acknowledgment for its upgrade commands — usually network congestion or packet loss, not a certificate problem. Confirm stable agent-manager connectivity and retry one agent at a time.
- As a last-resort test (not for production), CA verification can be disabled on the agent:

    ```xml
    <agent-upgrade>
      <ca_verification>
        <enabled>no</enabled>
      </ca_verification>
    </agent-upgrade>
    ```

## Verification

After any certificate change:

```bash
# Dates, subject, issuer and SANs
openssl x509 -in /etc/wazuh-indexer/certs/indexer.pem -noout -subject -issuer -dates

# Key matches certificate (hashes must be identical)
openssl x509 -noout -modulus -in /etc/wazuh-indexer/certs/indexer.pem | openssl md5
openssl rsa  -noout -modulus -in /etc/wazuh-indexer/certs/indexer-key.pem | openssl md5

# Live handshake against the deployed CA
openssl s_client -connect <INDEXER_IP>:9200 -CAfile /etc/wazuh-indexer/certs/root-ca.pem

# Filebeat -> indexer
filebeat test output
```

If anything fails, follow the full diagnostic flow in [troubleshooting.md](troubleshooting.md).
