# Certificates, TLS and SSO for Wazuh

Guides for managing TLS certificates across the Wazuh stack, serving the dashboard over HTTPS (including on private IPs), and configuring SAML single sign-on.

## Table of Contents

- [Which certificates does each component use?](#which-certificates-does-each-component-use)
- [Guides in this section](#guides-in-this-section)
- [Quick verification commands](#quick-verification-commands)
- [Related sections](#related-sections)

## Which certificates does each component use?

A default Wazuh deployment (created with `wazuh-certs-tool.sh`) uses one internal root CA and a set of node certificates signed by it:

| Component | Certificate files | Location | Purpose |
|---|---|---|---|
| Wazuh indexer | `indexer.pem`, `indexer-key.pem`, `root-ca.pem` | `/etc/wazuh-indexer/certs/` | TLS on the transport layer (9300) and HTTP REST API (9200) |
| Admin (security ops) | `admin.pem`, `admin-key.pem` | `/etc/wazuh-indexer/certs/` | Client certificate required by `securityadmin.sh` and `wazuh-passwords-tool.sh` |
| Wazuh server (Filebeat) | `filebeat.pem`, `filebeat-key.pem`, `root-ca.pem` | `/etc/filebeat/certs/` | Filebeat shipping alerts to the indexer over TLS |
| Wazuh dashboard | `dashboard.pem`, `dashboard-key.pem`, `root-ca.pem` | `/etc/wazuh-dashboard/certs/` | HTTPS for the web UI (443) and verifying the indexer's certificate |
| Wazuh agent (enrollment) | manager-side cert on port 1515 | managed by the manager | TLS-protected agent enrollment |
| Wazuh agent (WPK upgrades) | `wpk_root.pem` (CA store) | `/var/ossec/etc/` (Linux) | Verifying the signature of remote agent upgrade packages |

Key facts to keep in mind:

- Every node certificate must be signed by the **same root CA** (`root-ca.pem`) that the other components trust. A cert signed by a different CA is the most common cause of `bad_certificate` handshake failures.
- Certificates must contain the node's hostname or IP in the **Subject Alternative Name (SAN)** — the CN alone is not enough for modern clients.
- The **admin certificate** is a client certificate, not a server certificate. Keep it: without it you cannot run `securityadmin.sh` to load security configuration changes (users, roles, SAML config).
- SAML SSO does not add TLS certificates to Wazuh itself, but relies on the IdP's **signing certificate** (exchanged through SAML metadata files) and on the dashboard being served over HTTPS.

## Guides in this section

| Guide | What it covers |
|---|---|
| [component-certificates.md](component-certificates.md) | Generating and deploying certificates with `wazuh-certs-tool.sh`, regenerating/replacing certificates (including across cross-cluster search environments), custom CSRs for corporate CAs, extracting certs from PKCS#12/PFX bundles, and renewing the WPK upgrade CA on agents |
| [https-for-private-ip.md](https-for-private-ip.md) | Serving the Wazuh dashboard (and a self-hosted OpenSearch maps server) over HTTPS on a private IP with self-signed IP-SAN certificates and NGINX, plus Let's Encrypt / commercial CA options for public FQDNs |
| [sso-saml.md](sso-saml.md) | SAML single sign-on for the Wazuh dashboard with Keycloak (or any SAML 2.0 IdP): indexer security config, `securityadmin.sh`, role mapping, dashboard settings, and SP-initiated login URLs |
| [troubleshooting.md](troubleshooting.md) | Diagnosing TLS failures: `bad_certificate` errors, expired or inverted validity windows, key/cert mismatches, CA mismatches, hostname/SAN issues, `openssl s_client` recipes, and agent TLS checks on port 1515 |

## Quick verification commands

```bash
# Inspect a certificate: subject, issuer, validity window, SANs
openssl x509 -in /etc/wazuh-indexer/certs/indexer.pem -noout -subject -issuer -dates -text | grep -A1 "Subject Alternative Name"

# Test the indexer's TLS endpoint against the deployed CA
openssl s_client -connect <INDEXER_IP>:9200 -CAfile /etc/wazuh-indexer/certs/root-ca.pem

# Verify Filebeat can reach the indexer over TLS
filebeat test output

# Check a remote HTTPS endpoint and dump its chain
openssl s_client -connect wazuh.example.com:443 -showcerts
```

See [troubleshooting.md](troubleshooting.md) for the full diagnostic flow.

## Related sections

- [LDAP integration](../integrations/LDAP/README.md) — LDAP/Active Directory authentication, including verifying the AD server's LDAPS certificate
- [Official documentation: Wazuh certificates deployment](https://documentation.wazuh.com/current/deployment-options/deploying-with-wazuh-installation-assistant/deploying-step-by-step.html)
- [Official documentation: Configuring third-party certificates with NGINX](https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/configuring-third-party-certs/ssl-nginx.html)
