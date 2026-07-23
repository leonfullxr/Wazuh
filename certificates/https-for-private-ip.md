# HTTPS for the Wazuh Dashboard on a Private IP

How to serve the Wazuh dashboard (and optionally a self-hosted OpenSearch maps server) over HTTPS when the deployment is only reachable on a private IP address (where Let's Encrypt and public CAs cannot help), using a self-signed IP-SAN certificate and NGINX.

## Table of Contents

- [Background](#background)
- [Option A: same-origin setup (dashboard and maps under one HTTPS origin)](#option-a-same-origin-setup-dashboard-and-maps-under-one-https-origin)
- [Option B: separate ports (dashboard on 443, maps on 8443)](#option-b-separate-ports-dashboard-on-443-maps-on-8443)
- [Creating an IP-SAN certificate](#creating-an-ip-san-certificate)
- [Public FQDNs: Let's Encrypt and commercial CAs](#public-fqdns-lets-encrypt-and-commercial-cas)
- [Disabling HTTPS on the dashboard (lab only)](#disabling-https-on-the-dashboard-lab-only)
- [Verification](#verification)

## Background

- Public CAs (including Let's Encrypt) do not issue certificates for private RFC1918 addresses such as `192.168.x.x` or `10.x.x.x`. Let's Encrypt began issuing certificates for *public* IP addresses in mid-2025, but those are short-lived and still unusable for private ranges. For private networks, use a self-signed certificate or a private CA, or register an internal DNS name and issue a certificate for the FQDN instead.
- Browsers only trust an IP certificate if the IP appears in the certificate's Subject Alternative Name (SAN); the CN alone is not enough.
- If the dashboard is HTTPS but loads resources (e.g. map tiles) over plain HTTP, browsers block them as mixed content, so everything must be served over HTTPS.
- To get a padlock with no warnings, sign the server certificate with a private root CA and import that root CA into the client trust stores.

Throughout this guide, replace `<WAZUH_DASHBOARD_IP>` with your dashboard's private IP (e.g. `192.168.1.100`).

## Option A: same-origin setup (dashboard and maps under one HTTPS origin)

The cleanest layout: NGINX terminates TLS on 443 and serves both the dashboard (`/`) and the maps server (`/maps/`) from the same origin, so the browser never loads `http://` content. The dashboard listens internally on an arbitrary port (6000 here) and the maps server on loopback `127.0.0.1:18080`.

1. Deploy the local maps server. `HOST_URL` must be the external HTTPS URL so the generated manifest and tile links are HTTPS:

    ```bash
    docker rm -f opensearch-maps || true
    docker run -d --name opensearch-maps \
      -v tiles-data:/usr/src/app/public/tiles/data/ \
      -e HOST_URL='https://<WAZUH_DASHBOARD_IP>/maps' \
      -p 127.0.0.1:18080:8080 \
      opensearchproject/opensearch-maps-server:1.0.0 run
    ```

2. Install NGINX (see the [official NGINX reverse-proxy guide](https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/configuring-third-party-certs/ssl-nginx.html#setting-up-nginx-as-reverse-proxy)):

    ```bash
    apt-get update && apt-get install nginx
    systemctl start nginx
    ```

3. Move the dashboard off port 443 in `/etc/wazuh-dashboard/opensearch_dashboards.yml`:

    ```yaml
    server.host: 0.0.0.0
    server.port: 6000
    opensearch.hosts: https://<WAZUH_INDEXER_IP>:9200
    opensearch.ssl.verificationMode: certificate
    opensearch.requestHeadersAllowlist: ["securitytenant","Authorization"]
    opensearch_security.multitenancy.enabled: false
    opensearch_security.readonly_mode.roles: ["kibana_read_only"]
    # You can keep TLS here or simplify and terminate TLS only at NGINX.
    server.ssl.enabled: true
    server.ssl.key: "/etc/wazuh-dashboard/certs/dashboard-key.pem"
    server.ssl.certificate: "/etc/wazuh-dashboard/certs/dashboard.pem"
    opensearch.ssl.certificateAuthorities: ["/etc/wazuh-dashboard/certs/root-ca.pem"]
    uiSettings.overrides.defaultRoute: /app/wz-home
    # Point the dashboard at the same-origin maps manifest:
    map.opensearchManifestServiceUrl: "https://<WAZUH_DASHBOARD_IP>/maps/manifest.json"
    ```

4. Create `/etc/nginx/conf.d/wazuh.conf`:

    ```bash
    unlink /etc/nginx/sites-enabled/default
    ```

    ```nginx
    # Dashboard HTTPS on :443
    server {
      listen 443 ssl http2;
      server_name <WAZUH_DASHBOARD_IP>;
      ssl_certificate     /etc/wazuh-dashboard/certs/dashboard.pem;
      ssl_certificate_key /etc/wazuh-dashboard/certs/dashboard-key.pem;

      # Dashboard
      location / {
        proxy_pass http://<WAZUH_DASHBOARD_IP>:6000/;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        # WebSocket upgrade (required by Dashboards)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
      }

      # Maps server, same origin under /maps/
      location /maps/ {
        proxy_pass http://127.0.0.1:18080/;   # note trailing slash: /maps/ -> /
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_redirect off;
      }
    }
    ```

    > Note: every directive must end with a semicolon: a missing `;` produces `nginx: [emerg] unexpected "}"` on `nginx -t`.

5. Restart everything:

    ```bash
    systemctl restart wazuh-dashboard
    nginx -t && systemctl reload nginx
    ```

6. Check that manifest, tiles and login all answer 200 over HTTPS:

    ```bash
    curl -Ik https://<WAZUH_DASHBOARD_IP>/maps/manifest.json
    curl -Ik https://<WAZUH_DASHBOARD_IP>/maps/tiles/data/0/0/0.png
    curl -Ik https://<WAZUH_DASHBOARD_IP>/app/login
    ```

<details>
<summary>Example verification output</summary>

```text
$ curl -Ik https://192.168.1.100/maps/manifest.json
HTTP/2 200
server: nginx/1.18.0 (Ubuntu)
content-type: application/json; charset=utf-8
content-length: 303
x-powered-by: Express
access-control-allow-origin: *

$ curl -Ik https://192.168.1.100/maps/tiles/data/0/0/0.png
HTTP/2 200
server: nginx/1.18.0 (Ubuntu)
content-type: image/png
content-length: 6918
access-control-allow-origin: *

$ curl -Ik https://192.168.1.100/app/login
HTTP/2 200
server: nginx/1.18.0 (Ubuntu)
content-type: text/html; charset=utf-8
content-security-policy: script-src 'unsafe-eval' 'self'; worker-src blob: 'self'; style-src 'unsafe-inline' 'self'
x-frame-options: sameorigin
```

</details>

## Option B: separate ports (dashboard on 443, maps on 8443)

If you prefer not to touch the dashboard port, keep the dashboard behind NGINX on 443 and expose the maps server on a second HTTPS port (8443) with the same IP-SAN certificate. This avoids subpath rewrites entirely.

1. Start the maps server with `HOST_URL` pointing at the 8443 endpoint:

    ```bash
    docker run -d --name opensearch-maps \
      -v tiles-data:/usr/src/app/public/tiles/data/ \
      -e HOST_URL='https://<WAZUH_DASHBOARD_IP>:8443' \
      -p 8080:8080 \
      opensearchproject/opensearch-maps-server:1.0.0 run
    ```

2. Add a second NGINX server block:

    ```nginx
    server {
        listen 8443 ssl http2;
        server_name <WAZUH_DASHBOARD_IP>;

        ssl_certificate     /etc/nginx/certs/ip.crt;
        ssl_certificate_key /etc/nginx/certs/ip.key;

        # Optional CORS if needed by Dashboards
        add_header Access-Control-Allow-Origin "*" always;

        location / {
            proxy_pass http://127.0.0.1:8080;
            proxy_set_header Host $host;
        }
    }
    ```

3. Point the dashboard at the manifest in `/etc/wazuh-dashboard/opensearch_dashboards.yml` and restart:

    ```yaml
    map.opensearchManifestServiceUrl: "https://<WAZUH_DASHBOARD_IP>:8443/manifest.json"
    ```

## Creating an IP-SAN certificate

Used by either option when you don't want to reuse the dashboard's own certificate. Create `/etc/nginx/openssl-ip.cnf`:

```ini
[ req ]
default_bits       = 2048
prompt             = no
encrypt_key        = no
default_md         = sha256
distinguished_name = dn
x509_extensions    = v3_req

[ dn ]
CN = <WAZUH_DASHBOARD_IP>

[ v3_req ]
subjectAltName   = @alt_names
keyUsage         = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[ alt_names ]
IP.1 = <WAZUH_DASHBOARD_IP>
```

Generate a self-signed certificate (valid ~825 days), or sign the CSR with your internal CA instead:

```bash
sudo mkdir -p /etc/nginx/certs
sudo openssl genrsa -out /etc/nginx/certs/ip.key 2048
sudo openssl req -new -key /etc/nginx/certs/ip.key \
  -out /etc/nginx/certs/ip.csr -config /etc/nginx/openssl-ip.cnf
sudo openssl x509 -req -in /etc/nginx/certs/ip.csr \
  -signkey /etc/nginx/certs/ip.key -out /etc/nginx/certs/ip.crt \
  -days 825 -extensions v3_req -extfile /etc/nginx/openssl-ip.cnf
```

> To avoid browser warnings, sign with a private root CA and import that CA into the client trust stores.

## Public FQDNs: Let's Encrypt and commercial CAs

If the dashboard is reachable on a public domain name, use a real CA instead of a self-signed certificate.

**Let's Encrypt (free, automated, 90-day validity):**

```bash
sudo apt-get install certbot

# Standalone (certbot spins up a temporary web server on :80)
sudo certbot certonly --standalone -d wazuh.example.com \
  --email admin@example.com --agree-tos

# Or, if NGINX is already serving the site:
sudo certbot --nginx -d wazuh.example.com

# Test automatic renewal
sudo certbot renew --dry-run
```

Certbot writes `privkey.pem` and `fullchain.pem` under `/etc/letsencrypt/live/wazuh.example.com/`; point `ssl_certificate`/`ssl_certificate_key` (or the dashboard's `server.ssl.*` settings) at them. Wildcard certificates (`*.example.com`) require the DNS-01 challenge; in Kubernetes, cert-manager automates issuance and renewal.

**Commercial CA:** generate a key and CSR (`openssl genrsa` + `openssl req -new`, CN/SAN matching the FQDN), submit the CSR through the CA portal, then install the issued certificate together with the intermediate chain: see [component-certificates.md](component-certificates.md#using-a-corporate-or-commercial-ca-custom-csr).

## Disabling HTTPS on the dashboard (lab only)

Not recommended for production, but useful in a lab to sidestep mixed-content issues. Back up and edit both `/etc/wazuh-dashboard/opensearch_dashboards.yml` and `/usr/share/wazuh-dashboard/config/opensearch_dashboards.yml` (comment rather than delete, so it's easy to undo):

```yaml
server.port: 80
server.ssl.enabled: false
#server.ssl.key: "/etc/wazuh-dashboard/certs/dashboard-key.pem"
#server.ssl.certificate: "/etc/wazuh-dashboard/certs/dashboard.pem"
opensearch_security.cookie.secure: false
```

Restart and verify the redirect to the login page over plain HTTP:

```bash
systemctl restart wazuh-dashboard
curl -I http://<WAZUH_DASHBOARD_IP>
# HTTP/1.1 302 Found
# location: /app/login?
```

## Verification

```bash
# NGINX config sanity
nginx -t

# TLS handshake and certificate SAN check from a client
echo | openssl s_client -connect <WAZUH_DASHBOARD_IP>:443 2>/dev/null \
  | openssl x509 -noout -subject -dates -ext subjectAltName

# Dashboard reachable over HTTPS
curl -Ik https://<WAZUH_DASHBOARD_IP>/app/login
```

No mixed-content errors should appear in the browser console once every resource (dashboard, manifest, tiles) is HTTPS.

For TCP load balancing of Wazuh agent traffic on ports 1514 and 1515, use the
separate [NGINX stream load-balancer guide](../integrations/nginx/README.md).
