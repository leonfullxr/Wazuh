# SAML Single Sign-On for the Wazuh Dashboard

Configuring SAML 2.0 SSO for the Wazuh dashboard with **Keycloak** as the identity provider. The Wazuh-side steps are identical for any SAML 2.0 IdP (JumpCloud, Okta, Azure AD/Entra ID, ...) — only the metadata and role attribute names change. The second half covers the SP-initiated login flow and the classic "404 on the ACS endpoint" mistake.

Official reference: [Single sign-on - Wazuh documentation](https://documentation.wazuh.com/current/user-manual/user-administration/single-sign-on/index.html)

## Table of Contents

- [How SAML fits into the Wazuh stack](#how-saml-fits-into-the-wazuh-stack)
- [Prerequisites and gotchas](#prerequisites-and-gotchas)
- [Wazuh indexer configuration](#wazuh-indexer-configuration)
- [Role mapping](#role-mapping)
- [Wazuh dashboard configuration](#wazuh-dashboard-configuration)
- [SP-initiated login and the ACS 404](#sp-initiated-login-and-the-acs-404)
- [Verification and troubleshooting](#verification-and-troubleshooting)

## How SAML fits into the Wazuh stack

SAML authentication is handled by the **OpenSearch security plugin on the Wazuh indexer**, not by the dashboard itself. The dashboard only needs to be told to use SAML (`opensearch_security.auth.type: "saml"`) and to allowlist the SAML endpoints. The key configuration parameters are:

- `idp.metadata_url` / `idp.metadata_file` — the IdP's SAML metadata (XML), by URL or as a local file. Use one or the other.
- `idp.entity_id` — the IdP's unique entity ID.
- `sp.entity_id` — the entity ID you assign to Wazuh as the Service Provider.
- `kibana_url` — the URL users use to reach the Wazuh dashboard.
- `roles_key` — the SAML assertion attribute that carries the user's roles/groups.
- `exchange_key` — a key used to sign the exchanged assertions; must be **at least 32 characters**.

## Prerequisites and gotchas

- An account with administrator privileges on the Wazuh dashboard.
- The IdP application (realm/client in Keycloak) already configured, with a group or role to map to Wazuh.
- OpenSearch and the SAML assertion are **case-sensitive** — role/group values must match exactly on the IdP and in the Wazuh indexer configuration.
- Each IdP group can only be used as **one** `backend_role`. If you need both admin and read-only access, create a separate IdP group per role. This guide sets up an **administrator** user; for read-only see the [read-only SSO guide](https://documentation.wazuh.com/current/user-manual/user-administration/single-sign-on/read-only/index.html).
- Clear browser cache and cookies before testing.
- `securityadmin.sh` must run as root and needs the **admin certificate/key pair** (see [component-certificates.md](component-certificates.md)).
- Back up `/etc/wazuh-indexer/opensearch-security/` before editing.

## Wazuh indexer configuration

Full walkthrough (including the Keycloak side): [Keycloak - single sign-on with administrator role](https://documentation.wazuh.com/current/user-manual/user-administration/single-sign-on/administrator/keycloak.html).

1. Place the metadata files exchanged with the IdP in the security config directory and fix ownership:

    ```bash
    chown wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/opensearch-security/idp.metadata.xml
    chown wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/opensearch-security/sp.metadata.xml
    ```

2. Edit `/etc/wazuh-indexer/opensearch-security/config.yml`. In `basic_internal_auth_domain`, set `order: 0` and `challenge: false`; then add a `saml_auth_domain` under `authc`:

    ```yaml
    authc:
      basic_internal_auth_domain:
        description: "Authenticate via HTTP Basic against internal users database"
        http_enabled: true
        transport_enabled: true
        order: 0
        http_authenticator:
          type: "basic"
          challenge: false
        authentication_backend:
          type: "intern"
      saml_auth_domain:
        http_enabled: true
        transport_enabled: false
        order: 1
        http_authenticator:
          type: saml
          challenge: true
          config:
            idp:
              metadata_file: '/etc/wazuh-indexer/opensearch-security/idp.metadata.xml'
              entity_id: 'https://idp.example.com/realms/Wazuh'
            sp:
              entity_id: wazuh-saml
              metadata_file: /etc/wazuh-indexer/opensearch-security/sp.metadata.xml
            kibana_url: https://wazuh.example.com
            roles_key: Roles
            exchange_key: '<RANDOM_STRING_OF_AT_LEAST_32_CHARACTERS>'
        authentication_backend:
          type: noop
    ```

    Adjust `idp.metadata_file`, `idp.entity_id`, `sp.entity_id`, `sp.metadata_file`, `kibana_url`, `roles_key` and `exchange_key` to your environment.

3. Load the change with `securityadmin.sh`:

    ```bash
    export JAVA_HOME=/usr/share/wazuh-indexer/jdk/ && \
    bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
      -f /etc/wazuh-indexer/opensearch-security/config.yml \
      -icl \
      -key /etc/wazuh-indexer/certs/admin-key.pem \
      -cert /etc/wazuh-indexer/certs/admin.pem \
      -cacert /etc/wazuh-indexer/certs/root-ca.pem \
      -h 127.0.0.1 -nhnv
    ```

    `-h` is the indexer node's address — replace `127.0.0.1` if running remotely.

    <details>
    <summary>Expected output</summary>

    ```
    Security Admin v7
    Will connect to 127.0.0.1:9200 ... done
    Connected as "CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US"
    OpenSearch Version: 2.10.0
    Contacting opensearch cluster 'opensearch' and wait for YELLOW clusterstate ...
    Clustername: wazuh-cluster
    Clusterstate: GREEN
    Number of nodes: 1
    Number of data nodes: 1
    .opendistro_security index already exists, so we do not need to create one.
    Populate config from /etc/wazuh-indexer/opensearch-security
    Will update '/config' with /etc/wazuh-indexer/opensearch-security/config.yml
    SUCC: Configuration for 'config' created or updated
    Done with success
    ```

    </details>

## Role mapping

1. Edit `/etc/wazuh-indexer/opensearch-security/roles_mapping.yml` and map the IdP role (here the Keycloak realm role `admin`) to the indexer role `all_access`:

    ```yaml
    all_access:
      reserved: false
      hidden: false
      backend_roles:
        - "admin"
    ```

2. Load it the same way:

    ```bash
    export JAVA_HOME=/usr/share/wazuh-indexer/jdk/ && \
    bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
      -f /etc/wazuh-indexer/opensearch-security/roles_mapping.yml \
      -icl \
      -key /etc/wazuh-indexer/certs/admin-key.pem \
      -cert /etc/wazuh-indexer/certs/admin.pem \
      -cacert /etc/wazuh-indexer/certs/root-ca.pem \
      -h 127.0.0.1 -nhnv
    ```

## Wazuh dashboard configuration

1. Check `run_as` in `/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml`:

    ```yaml
    hosts:
      - default:
          url: https://127.0.0.1
          port: 55000
          username: wazuh-wui
          password: "<wazuh-wui-password>"
          run_as: false
    ```

    If `run_as: false`, continue. If `run_as: true`, additionally create a role mapping in the UI: **Server management > Security > Roles mapping > Create Role mapping**, with Roles = `administrator`, User field = `backend_roles`, Search operation = `FIND`, Value = your IdP role (e.g. `admin`).

2. Add to `/etc/wazuh-dashboard/opensearch_dashboards.yml`:

    ```yaml
    opensearch_security.auth.type: "saml"
    server.xsrf.allowlist: ["/_opendistro/_security/saml/acs", "/_opendistro/_security/saml/logout", "/_opendistro/_security/saml/acs/idpinitiated"]
    opensearch_security.session.keepalive: false
    ```

3. Restart and test:

    ```bash
    systemctl restart wazuh-dashboard
    ```

    Browse to the dashboard URL and log in with an IdP account.

## SP-initiated login and the ACS 404

A frequent mistake when wiring the IdP's "Login URL" (or bookmarking SSO) is to point users at the **Assertion Consumer Service (ACS)** endpoint. That fails:

- `GET /_plugins/_security/saml/acs` returns **404** — the ACS endpoint only handles **HTTP POST** (it receives the SAML response from the IdP); there is no GET handler.

For one-click SP-initiated SSO, use a **login initiation URL** instead:

```text
# Dashboards 2.x internal login endpoint (recommended; works regardless of base path)
https://wazuh.example.com/auth/saml/login?redirectHash=false&nextUrl=/

# Or simply the dashboard base path
https://wazuh.example.com/
```

Put one of these in the IdP application's Login URL field. What happens on a GET to `/auth/saml/login`:

1. The security plugin generates a SAML AuthnRequest and 302-redirects the browser to the IdP's SSO URL, carrying the `RelayState`.
2. The user authenticates at the IdP.
3. The IdP POSTs the SAMLResponse to the ACS endpoint (`/_plugins/_security/saml/acs`).
4. The plugin validates the signature, maps assertion attributes to backend roles, sets the session cookie, and redirects to `nextUrl`.

Parameter meaning:

- `redirectHash=false` — do not try to preserve the URL fragment (`#...`) across the IdP redirect.
- `nextUrl=/` — where to land after successful login.

IdP-initiated login (starting from the IdP's app portal) instead POSTs directly to `/_plugins/_security/saml/acs/idpinitiated` — which is why that path is in the `server.xsrf.allowlist` above.

## Verification and troubleshooting

1. Clear browser cache/cookies and open a private window.
2. Browse to the SP-initiated URL; you should be redirected to the IdP, authenticate, and land in the dashboard with no extra clicks.
3. If login fails silently, enable SAML debug logging in `opensearch_dashboards.yml` (`loggers` for the security SAML component) and watch the AuthnRequest/Response lifecycle.
4. If the user logs in but has no permissions, re-check `roles_key`, the exact (case-sensitive) role value in the assertion, and the `roles_mapping.yml` backend role.
5. Remember that any change to `config.yml` or `roles_mapping.yml` only takes effect after re-running `securityadmin.sh`.

For TLS-level failures (the dashboard or IdP endpoint not trusted, certificate errors during metadata download), see [troubleshooting.md](troubleshooting.md).
