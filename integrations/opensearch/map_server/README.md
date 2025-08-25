# Local maps server HTTPS - [Opensearch](https://docs.opensearch.org/latest/dashboards/visualize/selfhost-maps-server/)

## Introduction

This guide is for enabling HTTPS for the local map server from OpenSearch so that it can be used by the Wazuh dashboard and the browser does not display any mixed content warnings.

There are two methods for achieving this:
1. Enabling HTTPS for the local map server by using a reverse proxy (e.g., NGINX) to handle SSL termination.
2. Disabling HTTPS on the Wazuh dashboard. This is not recommended for production environments.

## Enabling HTTPS for local map server

I have chosen to put the map server **behind the same HTTPS origin** as the `https://<WAZUH_DASHBOARD_IP_OR_FQDN>` serves both Dashboard and the map assets (under `/maps`), so the browser never loads `http://…` content. The dashboard listens internally on `<DASHBOARD_PORT>` (6000 in my case) and the map server on loopback `127.0.0.1:18080` (also arbitrary).

The steps I have followed are the following:

1. Deploy the local map server. In my case, I have used the following commands:
    
    ```bash
    docker rm -f opensearch-maps || true
    docker run -d --name opensearch-maps -v tiles-data:/usr/src/app/public/tiles/data/ -e HOST_URL='https://<WAZUH_DASHBOARD_IP_OR_FQDN>/maps' -p 127.0.0.1:18080:8080 opensearchproject/opensearch-maps-server:1.0.0 run
    ```
    2. Note that you can change the port and/or URL used.
        
2. Install nginx, which will serve as a reverse proxy. I am using a ubuntu server, therefore, I have followed these steps:
    
    1. `apt-get update apt-get install nginx systemctl start nginx systemctl status nginx`
        
    2. However, here is the reference so that you can follow it: [Configuring SSL certificates on the Wazuh dashboard using NGINX](https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/configuring-third-party-certs/ssl-nginx.html#setting-up-nginx-as-reverse-proxy)
        
3. Edit the `/etc/wazuh-dashboard/opensearch_dashboards.yml` file and change the default dashboard port from `443` to another available port number:
    
    ```bash
    # Example from my environment
    server.host: 0.0.0.0
    server.port: <PORT_NUMBER>
    opensearch.hosts: https://<WAZUH_INDEXER_IP_ADDRESS>:9200
    opensearch.ssl.verificationMode: certificate
    #opensearch.username:
    #opensearch.password:
    opensearch.requestHeadersAllowlist: ["securitytenant","Authorization"]
    opensearch_security.multitenancy.enabled: false
    opensearch_security.readonly_mode.roles: ["kibana_read_only"]
    # You can keep TLS here or simplify and terminate TLS only at NGINX.
    # If you keep it:
    server.ssl.enabled: true
    server.ssl.key: "/etc/wazuh-dashboard/certs/dashboard-key.pem"
    server.ssl.certificate: "/etc/wazuh-dashboard/certs/dashboard.pem"
    opensearch.ssl.certificateAuthorities: ["/etc/wazuh-dashboard/certs/root-ca.pem"]
    uiSettings.overrides.defaultRoute: /app/wz-home
    #opensearch_security.cookie.secure: false
    # Point Dashboard to the same-origin maps manifest:
    map.opensearchManifestServiceUrl: "https://<WAZUH_DASHBOARD_IP_ADDRESS>/maps/manifest.json"
    ```

4. Navigate to the `/etc/nginx/conf.d` directory and create a `wazuh.conf` file for the certificate installation:
    
    ```bash
    unlink /etc/nginx/sites-enabled/default
    cd /etc/nginx/conf.d
    touch wazuh.conf
    ```
        
5. Edit `wazuh.conf` and add the following configuration.
    
    ```bash
    # Dashboard HTTPS on :443
    server {
    listen 443 ssl http2;
    server_name <WAZUH_DASHBOARD_IP_ADDRESS>;
    ssl_certificate     /etc/wazuh-dashboard/certs/dashboard.pem;
    ssl_certificate_key /etc/wazuh-dashboard/certs/dashboard-key.pem;

    # Dashboard
    location / {
        proxy_pass http://<WAZUH_DASHBOARD_IP_ADDRESS>:<PORT>/;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /maps/ {
        proxy_pass http://127.0.0.1:18080/;   # replace with your IP:PORT used: /maps/ -> /
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
    }
    ```
    
6. Restart the Wazuh dashboard, the Wazuh server and nginx:
    
    ```bash
    systemctl restart wazuh-dashboard
    systemctl restart wazuh-manager
    nginx -t && systemctl reload nginx
    ```
    
7. Finally, check that everything is working as expected:
    
    ```bash
    curl -Ik https://<WAZUH_DASHBOARD_IP_ADDRESS>/maps/manifest.json
    curl -Ik https://<WAZUH_DASHBOARD_IP_ADDRESS>/maps/tiles/data/0/0/0.png
    curl -Ik https://<WAZUH_DASHBOARD_IP_ADDRESS>/app/login
    ```
        

You should see 200 OK for the manifest/tile over HTTPS.

For a better context, here are the steps I have performed on my local environment:

<details>
<summary> Click here to expand the Performed steps </summary>

```bash
root@wserver-22:/home/vboxuser# docker rm -f opensearch-maps || true
docker run -d --name opensearch-maps \
  -v tiles-data:/usr/src/app/public/tiles/data/ \
  -e HOST_URL='https://192.168.56.250/maps' \
  -p 127.0.0.1:18080:8080 \
  opensearchproject/opensearch-maps-server:1.0.0 run
opensearch-maps
9c1a32c6a560919a6a5bce21f4d55e92de0e7682fbcdcafcde5a64f0aed88501
root@wserver-22:/home/vboxuser# nano /etc/nginx/conf.d/wazuh.conf
root@wserver-22:/home/vboxuser# cat /etc/nginx/conf.d/wazuh.conf
# Dashboard HTTPS on :443
server {
  listen 443 ssl http2;
  server_name 192.168.56.250;
  ssl_certificate     /etc/wazuh-dashboard/certs/dashboard.pem;
  ssl_certificate_key /etc/wazuh-dashboard/certs/dashboard-key.pem;

  # Dashboard
  location / {
    proxy_pass http://192.168.56.250:6000/;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
  }

  location /maps/ {
    proxy_pass http://127.0.0.1:18080/;   # note trailing slash: /maps/ -> /
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_redirect off
  }
}
root@wserver-22:/home/vboxuser# nginx -t && systemctl reload nginx
nginx: [emerg] unexpected "}" in /etc/nginx/conf.d/wazuh.conf:26
nginx: configuration file /etc/nginx/nginx.conf test failed
root@wserver-22:/home/vboxuser# nano /etc/nginx/conf.d/wazuh.conf
root@wserver-22:/home/vboxuser# nginx -t && systemctl reload nginx
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
root@wserver-22:/home/vboxuser# nano /etc/wazuh-dashboard/opensearch_dashboards.yml
root@wserver-22:/home/vboxuser# cat /etc/wazuh-dashboard/opensearch_dashboards.yml
server.host: 0.0.0.0
server.port: 6000
opensearch.hosts: https://192.168.56.250:9200
opensearch.ssl.verificationMode: certificate
#opensearch.username:
#opensearch.password:
opensearch.requestHeadersAllowlist: ["securitytenant","Authorization"]
opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
server.ssl.enabled: true
server.ssl.key: "/etc/wazuh-dashboard/certs/dashboard-key.pem"
server.ssl.certificate: "/etc/wazuh-dashboard/certs/dashboard.pem"
opensearch.ssl.certificateAuthorities: ["/etc/wazuh-dashboard/certs/root-ca.pem"]
uiSettings.overrides.defaultRoute: /app/wz-home
#opensearch_security.cookie.secure: false
map.opensearchManifestServiceUrl: "https://192.168.56.250/maps/manifest.json"
root@wserver-22:/home/vboxuser# nginx -t && systemctl reload nginx
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
root@wserver-22:/home/vboxuser# systemctl restart wazuh-dashboard
```

</details>

<details>
<summary> Click here to expand the Performed checks </summary>

```bash
root@wserver-22:/home/vboxuser# curl -Ik https://192.168.56.250/maps/manifest.json
HTTP/2 200 
server: nginx/1.18.0 (Ubuntu)
date: Wed, 20 Aug 2025 08:59:25 GMT
content-type: application/json; charset=utf-8
content-length: 303
x-powered-by: Express
access-control-allow-origin: *
etag: W/"12f-qOQo+kPzqS3REWedNi9H7bbuXg8"

root@wserver-22:/home/vboxuser# curl -Ik https://192.168.56.250/maps/tiles/data/0/0/0.png
HTTP/2 200 
server: nginx/1.18.0 (Ubuntu)
date: Wed, 20 Aug 2025 08:59:36 GMT
content-type: image/png
content-length: 6918
x-powered-by: Express
access-control-allow-origin: *
accept-ranges: bytes
cache-control: public, max-age=0
last-modified: Thu, 30 Jun 2022 23:46:33 GMT
etag: W/"1b06-181b70257a8"

root@wserver-22:/home/vboxuser# curl -Ik https://192.168.56.250/app/login
HTTP/2 200 
server: nginx/1.18.0 (Ubuntu)
date: Wed, 20 Aug 2025 09:00:55 GMT
content-type: text/html; charset=utf-8
content-length: 113374
set-cookie: security_authentication=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Path=/
set-cookie: security_authentication=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Path=/
content-security-policy: script-src 'unsafe-eval' 'self'; worker-src blob: 'self'; style-src 'unsafe-inline' 'self'
osd-name: wserver-22
x-frame-options: sameorigin
cache-control: private, no-cache, no-store, must-revalidate
vary: accept-encoding
```

</details>

## Disabling HTTPS on the Wazuh Dashboard
If you want to disable https, then you should edit the configuration of the Wazuh dashboard and remove or comment on some settings.

Comment or remove the next settings from the Wazuh dashboard configuration. Edit the file /etc/wazuh-dashboard/opensearch_dashboards.yml and the /usr/share/wazuh-dashboard/config/opensearch_dashboards.yml. I would suggest you comment on these options, prepending a hash (#) before at the beginning of the line of the settings, so you could undo it easily if you would need.

server.ssl.enabled

server.ssl.key

server.ssl.certificate

1. Make a copy of your existing files:
    ```bash
    cp /etc/wazuh-dashboard/opensearch_dashboards.yml /etc/wazuh-dashboard/opensearch_dashboards.yml.bak
    cp /usr/share/wazuh-dashboard/config/opensearch_dashboards.yml /usr/share/wazuh-dashboard/config/opensearch_dashboards.yml.bak
    ```

<details>
<summary>Here is an example of what I have used:</summary>

```bash
root@wserver-22:/home/vboxuser# cat /etc/wazuh-dashboard/opensearch_dashboards.yml
server.host: 0.0.0.0
server.port: 80
opensearch.hosts: https://192.168.56.250:9200
opensearch.ssl.verificationMode: none
#opensearch.username:
#opensearch.password:
opensearch.requestHeadersAllowlist: ["securitytenant","Authorization"]
opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
server.ssl.enabled: false
#server.ssl.key: "/etc/wazuh-dashboard/certs/dashboard-key.pem"
#server.ssl.certificate: "/etc/wazuh-dashboard/certs/dashboard.pem"
#opensearch.ssl.certificateAuthorities: ["/etc/wazuh-dashboard/certs/root-ca.pem"]
uiSettings.overrides.defaultRoute: /app/wz-home
opensearch_security.cookie.secure: false
map.opensearchManifestServiceUrl: "http://192.168.56.250:8080/manifest.json"

root@wserver-22:/home/vboxuser# cat /usr/share/wazuh-dashboard/config/opensearch_dashboards.yml 
server.host: 0.0.0.0
server.port: 80
opensearch.hosts: https://192.168.56.250:9200
opensearch.ssl.verificationMode: none
#opensearch.username:
#opensearch.password:
opensearch.requestHeadersAllowlist: ["securitytenant","Authorization"]
opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
server.ssl.enabled: false
#server.ssl.key: "/etc/wazuh-dashboard/certs/dashboard-key.pem"
#server.ssl.certificate: "/etc/wazuh-dashboard/certs/dashboard.pem"
#opensearch.ssl.certificateAuthorities: ["/etc/wazuh-dashboard/certs/root-ca.pem"]
uiSettings.overrides.defaultRoute: /app/wz-home
opensearch_security.cookie.secure: false
```

</details>

2. Then restart the Wazuh dashboard, depending on your service manager:

    ```bash
    systemctl restart wazuh-dashboard
    ```

3. Verify the server is running on http

    ```bash
    curl -I http://<your_IP>
    ```

    <details>
    <summary> Example</summary>

    ```bash
    # Example
    root@wserver-22:/home/vboxuser# curl -I http://192.168.56.250
    HTTP/1.1 302 Found
    location: /app/login?
    osd-name: wserver-22
    x-frame-options: sameorigin
    cache-control: private, no-cache, no-store, must-revalidate
    set-cookie: security_authentication=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Path=/
    content-length: 0
    Date: Mon, 18 Aug 2025 12:42:41 GMT
    Connection: keep-alive
    Keep-Alive: timeout=120
    ```

    </details>

With this, you should not receive any browser log mixed content errors.