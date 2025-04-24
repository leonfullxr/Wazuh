# SOC Wazuh Lab

A lightweight Security Operations Center lab using Docker, Wazuh, Nginx (reverse-proxy & load-balancer) and two Apache web servers.


## 🚀 Architecture

- **Nginx**: reverse proxy & least-connections load balancing  
- **2× Apache**: backend web servers (you can swap these for DVWA, etc.)  
- **Wazuh Agents**: running inside each container + the host

All containers communicate over a custom Docker bridge network (`webnet`).

## 📂 File summary

File | Purpose
docker-compose.yml | Defines services, volumes, network (webnet).
apache/Dockerfile | Builds Apache containers from httpd:2.4.
apache/html/index.html | Sample home page (swap in DVWA or your app).
nginx/Dockerfile | Builds Nginx from nginx:latest.
nginx/nginx.conf | Reverse-proxy + security headers + load-balancing.
nginx/ssl/nginx-*.{crt,key} | Self-signed cert used by Nginx HTTPS server.

## 🔧 Prerequisites

- Docker & Docker Compose v1.27+  
- OpenSSL (for cert generation)  

## ⚙️ Setup Steps

1.Clone this repo  

```bash
git clone https://github.com/youruser/soc-wazuh-lab.git
cd soc-wazuh-lab
```

2.Create the Docker network

```bash
docker network create webnet
```

3.(Re)generate a self-signed SSL certificate

```bash
mkdir -p nginx/ssl
openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout nginx/ssl/nginx-selfsigned.key \
  -out nginx/ssl/nginx-selfsigned.crt \
  -subj "/C=US/ST=State/L=City/O=Org/OU=Unit/CN=localhost"
```

4.Build & launch

```bash
docker-compose up -d --build
```

Verify the following:

```bash
docker ps shows three containers: apache1, apache2, nginx.
```

* Tail Wazuh logs: ```bash tail -f /var/ossec/logs/ossec.log ```

* Hit http://localhost or https://localhost and watch requests land on both backends.

## 🔗 Links & Further Reading

* Wazuh Docker deployment:
https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html

* Container security in Wazuh:
https://documentation.wazuh.com/current/user-manual/capabilities/container-security/monitoring-docker.html

With this structure in place, you can:

1. Customize the sample index.html or swap in DVWA under apache/html/.

2. Drop your Wazuh Manager into the same network (or run it on the host) and point each agent to it.

3. Extend with container‐security rules via Wazuh’s Docker integration docs linked in the README.

Feel free to tweak, add your own dashboards, or integrate Trivy for image scanning—this repo is your springboard to a full micro‐SOC on Docker!