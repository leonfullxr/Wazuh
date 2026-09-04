# Signing Wazuh certificates with an Enterprise CA

How to obtain Wazuh certificates from your organization's own certification authority (CA): create the private keys and certificate signing requests (CSRs) yourself, let the Enterprise CA sign them, then deploy the results on the indexer and the dashboard. The guide also covers format conversion, dashboard certificate troubleshooting, using an existing CA with `wazuh-certs-tool.sh` directly, and moving components to new IP addresses.

> Applies to self-hosted Wazuh 4.x on Linux (indexer, manager, dashboard). The same workflow works with a commercial CA such as DigiCert and with an internal Microsoft AD CS installation.

## Table of Contents

- [How the request workflow fits Wazuh](#how-the-request-workflow-fits-wazuh)
- [Create the admin certificate request](#create-the-admin-certificate-request)
- [Create the node certificate requests](#create-the-node-certificate-requests)
- [Sign the requests with your Enterprise CA](#sign-the-requests-with-your-enterprise-ca)
- [Deploy the certificates on the indexer](#deploy-the-certificates-on-the-indexer)
- [Configure the dashboard with a CA-signed certificate](#configure-the-dashboard-with-a-ca-signed-certificate)
- [Convert issued files to PEM format](#convert-issued-files-to-pem-format)
- [Troubleshoot the dashboard after a certificate change](#troubleshoot-the-dashboard-after-a-certificate-change)
- [Replace only the dashboard certificate](#replace-only-the-dashboard-certificate)
- [Use an existing CA with wazuh-certs-tool.sh](#use-an-existing-ca-with-wazuh-certs-toolsh)
- [Change the IP address of Wazuh components](#change-the-ip-address-of-wazuh-components)
- [Verification](#verification)
- [Related](#related)

## How the request workflow fits Wazuh

Every certificate request follows the same three steps:

1. Create a private key.
2. Create a CSR signed with that key.
3. Send the CSR to the CA and receive the signed certificate back.

You then install the certificate, the key, and the CA public certificate (`root-ca.pem`) on the Wazuh nodes. Two Wazuh specifics matter before you start:

- The **admin pair** is a client certificate pair used by `securityadmin.sh` and `wazuh-passwords-tool.sh`. The indexer needs it even though nothing listens on it.
- Each **node certificate** must carry the node address in the Subject Alternative Name (SAN). Clients verify the SAN, not the CN. See [multi-SAN certificates](component-certificates.md#nodes-reachable-on-multiple-addresses-multi-san-certificates) for nodes reachable under several names.

If you already own a CA certificate and key, you can skip the manual CSR work and sign all node certificates with `wazuh-certs-tool.sh`. See [Use an existing CA with wazuh-certs-tool.sh](#use-an-existing-ca-with-wazuh-certs-toolsh).

## Create the admin certificate request

Record the file names and the subject (`-subj`) values. You need both again when you fill in the indexer configuration, because the subject must match the `plugins.security.authcz.admin_dn` entry.

1. Create a temporary private key:

    ```bash
    openssl genrsa -out admin-key-temp.pem 2048
    ```

2. Convert the key to unencrypted PKCS#8. This is the format the indexer expects:

    ```bash
    openssl pkcs8 -inform PEM -outform PEM -in admin-key-temp.pem \
      -topk8 -nocrypt -v1 PBE-SHA1-3DES -out admin-key.pem
    ```

3. Create the CSR:

    ```bash
    openssl req -new -key admin-key.pem \
      -subj "/C=US/ST=California/O=YourOrganization/OU=IT/CN=admin" \
      -out admin.csr
    ```

Keep `admin-key.pem` on the node. Send `admin.csr` to the CA for signing.

## Create the node certificate requests

The process is the same as for the admin pair. Create one key pair for each indexer node.

1. Set the node name and create the keys:

    ```bash
    NODE_NAME=<INDEXER_NODE_NAME>

    openssl genrsa -out $NODE_NAME-key-temp.pem 2048
    openssl pkcs8 -inform PEM -outform PEM -in $NODE_NAME-key-temp.pem \
      -topk8 -nocrypt -v1 PBE-SHA1-3DES -out $NODE_NAME-key.pem
    ```

2. Create the CSR with the node IP in the SAN:

    ```bash
    openssl req -new -key $NODE_NAME-key.pem \
      -subj "/C=US/ST=California/O=YourOrganization/OU=IT/CN=$NODE_NAME" \
      -addext "subjectAltName = DNS:$NODE_NAME.example.com,IP:192.0.2.10" \
      -out $NODE_NAME.csr
    ```

   Replace `192.0.2.10` with the node IP. List every address or name a client will dial. If you omit `-addext`, add the SAN later through an extension file, or the certificate will pass validation but fail hostname verification.

The dashboard and Filebeat pairs use the same commands. Include a SAN there too whenever a client verifies the host name or IP against the certificate.

## Sign the requests with your Enterprise CA

Submit the CSRs to your CA. Most CAs expose this as a portal upload or an internal PKI workflow.

**Microsoft AD CS**

Request a certificate from a template that allows client and server authentication. Confirm these settings before issuance:

- Certificate type: standard X.509
- Hash algorithm: SHA-256

**Sign directly with OpenSSL**

If your team owns the root CA key, sign each request yourself:

```bash
openssl x509 -req -in $NODE_NAME.csr \
  -CA root-ca.pem -CAkey root-ca.key -CAcreateserial \
  -sha256 -out $NODE_NAME.pem -days 3650
```

This signs with SHA-256 and a ten year validity. Adjust `-days` to match your security policy.

## Deploy the certificates on the indexer

Copy onto each indexer node the signed node certificate, its key, the admin pair, and `root-ca.pem` into `/etc/wazuh-indexer/certs/`, keeping the file names referenced by `/etc/wazuh-indexer/opensearch.yml` (the default layout is described in [certificate layout recap](component-certificates.md#certificate-layout-recap)):

```bash
chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs
chmod 500 /etc/wazuh-indexer/certs
chmod 400 /etc/wazuh-indexer/certs/*
systemctl restart wazuh-indexer
```

Always deploy `root-ca.pem` alongside the new certificate. The indexer uses it to validate client certificates such as the admin and Filebeat pairs.

On legacy installations from the Open Distro era (Wazuh 3.x and early 4.x on Elasticsearch), remove any leftover demo certificates so they cannot be picked up by mistake:

```bash
rm -f /etc/elasticsearch/esnode-key.pem /etc/elasticsearch/esnode.pem \
  /etc/elasticsearch/kirk-key.pem /etc/elasticsearch/kirk.pem \
  /etc/elasticsearch/root-ca.pem
```

Current deployments keep their certificates under `/etc/wazuh-indexer/certs/` only, so this step does not apply to them.

> Do not re-run the security initialization (`securityadmin.sh`) as part of a certificate replacement. Run it only when you changed security plugin configuration itself (roles, role mappings, internal users). Re-running it otherwise can overwrite tuned settings.

## Configure the dashboard with a CA-signed certificate

The dashboard keeps its own certificate pair and is configured separately from the indexer. This procedure fits closed networks where automated issuance such as Let's Encrypt is unavailable. By default the dashboard serves the self-signed pair created at deployment time.

1. Copy the certificate and private key to `/etc/wazuh-dashboard/certs/`.

2. Point `/etc/wazuh-dashboard/opensearch_dashboards.yml` at them:

    ```yaml
    server.ssl.key: "/etc/wazuh-dashboard/certs/<PRIVATE_KEY_FILE>.pem"
    server.ssl.certificate: "/etc/wazuh-dashboard/certs/<CERTIFICATE_FILE>.pem"
    ```

   The file names do not need to match the defaults. Only the references must be correct.

3. Set ownership and permissions:

    ```bash
    chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/
    chmod -R 500 /etc/wazuh-dashboard/certs/
    chmod 440 /etc/wazuh-dashboard/certs/<PRIVATE_KEY_FILE>.pem \
      /etc/wazuh-dashboard/certs/<CERTIFICATE_FILE>.pem
    ```

4. Restart the service:

    ```bash
    systemctl restart wazuh-dashboard
    ```

5. Clear the browser cache and cookies for the dashboard URL, then reload and confirm the browser shows the new certificate.

> **Important:** replace only `server.ssl.key` and `server.ssl.certificate`. Never overwrite `root-ca.pem` in that directory with the new certificate or CA file. In one support case the dashboard failed to start because the original `root-ca.pem` had been overwritten with the new web certificate. Restoring the original file resolved it. The dashboard uses `root-ca.pem` to verify the indexer certificate, so the web certificate must never replace it.

## Convert issued files to PEM format

The dashboard needs the certificate and the private key in PEM format. Convert other containers first:

```bash
# .crt/.key pair to PEM
openssl x509 -in certificate.crt -out certificate.pem -outform PEM
openssl rsa -in certificate.key -out certificate-key.pem -outform PEM
```

For a PKCS#12/PFX bundle, see [extracting certificates from a PKCS#12 bundle](component-certificates.md#extracting-certificates-from-a-pkcs12-pfx-bundle). After extraction, check the chain file order: the leaf certificate must come first, followed by intermediate CA certificates. Leave the original Wazuh `root-ca.pem` untouched.

## Troubleshoot the dashboard after a certificate change

If the dashboard becomes unreachable or shows no clear error after you replaced its certificate, work through these checks in order. Back up the previous certificate and key before you start, so recovery stays fast.

1. **Key file completeness.** Open the key file and confirm it contains a full private key block (`BEGIN PRIVATE KEY` / `END PRIVATE KEY`, or the RSA variant). A truncated or public-only block prevents the UI from loading.

2. **Signed certificate, not a request or DER file.** The file must parse as an X.509 certificate:

    ```bash
    openssl x509 -in <CERTIFICATE_FILE>.pem -text -noout
    ```

3. **Valid RSA key.** Parse errors mean the key needs conversion first:

    ```bash
    openssl rsa -check -noout -in <PRIVATE_KEY_FILE>.pem
    # if this fails:
    openssl rsa -in <PRIVATE_KEY_FILE>.key -text > <PRIVATE_KEY_FILE>-converted.pem
    ```

4. **Certificate and key belong together.** Both modulus hashes must match:

    ```bash
    openssl rsa -modulus -noout -in <PRIVATE_KEY_FILE>.pem | openssl md5
    openssl x509 -modulus -noout -in <CERTIFICATE_FILE>.pem | openssl md5
    ```

5. **Issuer is the expected CA.** Compare the issuer of the new certificate with the original Wazuh-generated one kept as backup:

    ```bash
    openssl x509 -in /etc/wazuh-dashboard/certs/<CERTIFICATE_FILE>.pem -issuer -noout
    openssl x509 -in /etc/wazuh-dashboard/certs/backup/wazuh-dashboard.pem -issuer -noout
    ```

6. **Service logs.** Look for SSL errors after the restart:

    ```bash
    journalctl -u wazuh-dashboard | grep -iE "error|warn"
    ```

If the cause stays unclear, restore the backed-up certificate and key under their original names in `/etc/wazuh-dashboard/certs/` and restart `wazuh-dashboard`. This is faster and safer than reverting the whole node to a snapshot. For deeper validation recipes (key/cert hash comparison, chain verification, malformed PEM symptoms), see [validating a server cert, key, and chain](troubleshooting.md#validating-a-server-cert-key-and-chain).

## Replace only the dashboard certificate

Mixing issuers across components is supported. You can replace the dashboard certificate with an internally issued one while the indexer, Filebeat, and inter-node traffic keep the Wazuh-generated self-signed certificates.

In this scenario, a dashboard error of `[ConnectionError]: unable to verify the first certificate` usually points at the dashboard's own pair or its permissions, not at the other components. Re-check the items above: matching modulus (step 4), correct ownership and permissions, and an untouched `root-ca.pem`.

## Use an existing CA with wazuh-certs-tool.sh

When you already own a CA certificate and key (from your internal PKI or a commercial CA), `wazuh-certs-tool.sh` can sign the indexer, server, and dashboard node certificates with them instead of creating a new self-signed root:

```bash
bash ./wazuh-certs-tool.sh -A /path/to/root-ca.pem /path/to/root-ca.key
```

Constraints to know before running it:

- The script, `config.yml`, and the CA files must sit in the same working directory when you run the command.
- `config.yml` must list every node of every type (indexer, server, dashboard). See the example in [generating certificates with wazuh-certs-tool](component-certificates.md#generating-certificates-with-wazuh-certs-tool).
- Supply the CA key as its own file. The tool does not extract a key embedded in a combined PEM.
- `-wi` generates indexer certificates only and skips the dashboard. To cover all node types defined in `config.yml` in one run, use `-A`.
- The output certificates are trusted wherever your CA is already trusted, for example system-wide through your internal PKI.

Then deploy the generated bundle to each component exactly as for self-signed certificates: extract the per-node pair and the CA file into each certs directory, set ownership and permissions, update the configuration, restart. The per-component commands are in [deploying certificates on each component](component-certificates.md#deploying-certificates-on-each-component).

## Change the IP address of Wazuh components

Changing a node IP affects every configuration file that names the node, plus the certificates if their SAN embeds the old IP. Where possible, point inter-component communication at a DNS name instead of an IP so future changes stay limited to DNS.

### Configuration files to update

| Component | File | Settings to update |
|---|---|---|
| Wazuh indexer | `/etc/wazuh-indexer/opensearch.yml` | `network.host`, `discovery.seed_hosts`, `cluster.initial_master_nodes` |
| Wazuh manager | `/var/ossec/etc/ossec.conf` | `<indexer>` connection host and cluster `<node>` addresses when clustered |
| Filebeat (on the manager) | `/etc/filebeat/filebeat.yml` | `output.hosts` pointing at the indexer |
| Wazuh dashboard | `/etc/wazuh-dashboard/opensearch_dashboards.yml` | `opensearch.hosts`, plus `server.host` when pinned to an IP |
| Dashboard API config | `/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml` | Manager API URL when the manager IP changed |
| Agents | `/var/ossec/etc/ossec.conf` (each agent) | `<server><address>` manager IP. Agents stop reporting until updated |

### Regenerate certificates with the new IPs

Certificates carrying the old IP in their SAN stop validating after the change and must be regenerated:

1. Update `config.yml` with the new node IPs.
2. Regenerate the bundle with `bash ./wazuh-certs-tool.sh -A`, or with your Enterprise CA through the methods above.
3. Distribute `wazuh-certificates.tar` to each node and deploy per component ([indexer](component-certificates.md#deploying-certificates-on-each-component), Filebeat, dashboard).

### Recommended sequence

Follow this order to avoid downtime and indexing errors during the move:

1. Generate the new certificates for the new IPs while all services still run on the old IPs.
2. Update `network.host`, `discovery.seed_hosts`, and `cluster.initial_master_nodes` in each indexer `opensearch.yml`. Do not restart yet.
3. Update the indexer addresses in the Filebeat and dashboard configuration files.
4. Stop Filebeat on the managers to halt indexing before the indexer restarts:

    ```bash
    systemctl stop filebeat
    ```

5. Stop the indexer, keep the current certificates as a backup, and deploy the new ones:

    ```bash
    systemctl stop wazuh-indexer
    mkdir /etc/wazuh-indexer/certs/backup
    mv /etc/wazuh-indexer/certs/*.pem /etc/wazuh-indexer/certs/backup/
    ```

   Copy the new certificate files in with matching names, ownership, and permissions, then start the indexer again.
6. Repeat the backup-then-deploy step for the Filebeat and dashboard certificate directories.
7. Stop the manager and change the node IP addresses.
8. Once the new IPs are active, start the services in this order: manager, indexer, Filebeat, dashboard.

### Checks after the change

- Query cluster health from the new indexer address.
- Confirm the dashboard reaches the indexer and the manager API without connection errors.
- Confirm agents reconnect to the new manager IP.
- Review `/var/ossec/logs/ossec.log` on the manager and the indexer logs for connection errors.

### Common errors

- **Dashboard shows `ECONNREFUSED` after an IP change.** The indexer usually did not start after the certificate or IP update. Check the indexer service status and its logs before debugging the dashboard.
- **Indexer refuses to start after certificate redeployment.** Check ownership and permissions of everything under `/etc/wazuh-indexer/certs/`, including backup subfolders. Leftover or wrongly-permitted files in that directory have prevented startup. Moving the stale backup content out resolved this in one support case.

## Verification

After any certificate change on the dashboard:

```bash
# The served certificate matches what you deployed
echo | openssl s_client -connect wazuh.example.com:443 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates

# Key and certificate still match
openssl x509 -noout -modulus -in /etc/wazuh-dashboard/certs/<CERTIFICATE_FILE>.pem | openssl md5
openssl rsa  -noout -modulus -in /etc/wazuh-dashboard/certs/<PRIVATE_KEY_FILE>.pem | openssl md5
```

For the full diagnostic flow across components, see [TLS diagnostic flow](troubleshooting.md#step-by-step-diagnostic-flow).

## Related

- [Component certificates](component-certificates.md) - generating and deploying the central certificate bundle, multi-SAN certificates, and PKCS#12 extraction
- [TLS diagnostic flow](troubleshooting.md#step-by-step-diagnostic-flow) - structured diagnosis of `bad_certificate` and handshake failures
- [HTTPS for a private IP](https-for-private-ip.md) - Let's Encrypt and NGINX alternatives for public FQDNs
