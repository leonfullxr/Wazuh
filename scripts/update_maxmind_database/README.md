# Maxmind database update script

## Table of Contents
- [Introduction](#introduction)
- [Execution](#execution)
- [Example Usage](#example-usage)
- [Docker Integration](#docker-integration)
  - [Prerequisites](#prerequisites)
  - [Configuration](#configuration)
  - [Installation & Bootstrapping](#installation--bootstrapping)
    - [Example of Placing the Script and Creating the Directories](#example-of-placing-the-script-and-creating-the-directories)
  - [docker-compose.yml Snippet](#docker-composeyml-snippet)
    - [Example docker-compose.yml Snippet](#example-docker-composeyml-snippet)
  - [Running the Update Script](#running-the-update-script)
  - [Example Output](#example-output)
  - [Verifying the Update](#verifying-the-update)
  - [Performing a Test with Updated Database Files](#performing-a-test-with-updated-database-files)

## Introduction
Custom bash script for pulling the latest Maxmind GeoIP database and checking if the current version on the server (Wazuh) has the latest update, if not, replace it and have the indexer use the updated version.

> Note: this is done for an All-in-One environment and docker multi-node deployments, but can be updated for distributed environments with multiple indexers, the script must be located on every indexer node.

There are two versions of the script:

- `update_maxmind.sh`: For both containerized and non-containerized Wazuh installations as it has a more complex logic to handle different environments.
- `update_maxmind_onprem.sh`: For non-containerized Wazuh installations, although this script might be best for users that prefer a more simple script.

This script essentially does the following:

1. Authenticates to MaxMind using your Account ID and License Key.
2. Downloads the latest GeoLite2 Country, City, and ASN databases via curl -sSL.
3. Checks checksums to avoid unnecessary downloads.
4. Extracts and installs the .mmdb files into Wazuh’s ingest-geoip module.
5. Restarts the Wazuh Indexer service to pick up the new databases.

## Execution
You can then create a cron entry for root to execute this script periodically.

```bash
crontab -e
# Add the following line to run the update at 3:00 AM daily
0 3 * * * /usr/local/bin/update_maxmind.sh >> /var/log/update_maxmind.log 2>&1
```

## Example Usage
```bash
[root@wazuh-server maxmind]# bash update_maxmind.sh 
Stopping Wazuh Indexer service...
  Wazuh Indexer stopped.
Checking GeoLite2-Country...
  Extracted GeoLite2-Country.mmdb to temporary file.
  GeoLite2-Country is up to date (contents identical).
Checking GeoLite2-City...
  Extracted GeoLite2-City.mmdb to temporary file.
  GeoLite2-City is up to date (contents identical).
Checking GeoLite2-ASN...
  Extracted GeoLite2-ASN.mmdb to temporary file.
  New or changed GeoLite2-ASN detected; installing updated .mmdb...
  Moved GeoLite2-ASN.mmdb to /usr/share/wazuh-indexer/modules/ingest-geoip/GeoLite2-ASN.mmdb
Restarting Wazuh Indexer service...
  Wazuh Indexer restarted.
MaxMind GeoLite2 databases have been updated successfully.
Ensuring Wazuh Indexer service is running...
  Wazuh Indexer is already running.
[root@wazuh-server maxmind]# ll /usr/share/wazuh-indexer/modules/ingest-geoip/
total 80048
-rw-r-----. 1 wazuh-indexer wazuh-indexer    61503 Mar 26 20:11 geoip2-4.2.0.jar
-rw-r--r--. 1 wazuh-indexer wazuh-indexer 10225027 Jun  6 09:44 GeoLite2-ASN.mmdb
-rw-r--r--. 1 wazuh-indexer wazuh-indexer 60495914 Jun  4 14:06 GeoLite2-City.mmdb
-rw-r--r--. 1 wazuh-indexer wazuh-indexer  9363974 Jun  4 14:06 GeoLite2-Country.mmdb
-rw-r-----. 1 wazuh-indexer wazuh-indexer    27169 Mar 26 20:11 ingest-geoip-2.16.0.jar
-rw-r-----. 1 wazuh-indexer wazuh-indexer    78492 Mar 26 20:11 jackson-annotations-2.17.2.jar
-rw-r-----. 1 wazuh-indexer wazuh-indexer  1649454 Mar 26 20:11 jackson-databind-2.17.2.jar
-rw-r-----. 1 wazuh-indexer wazuh-indexer    38944 Mar 26 20:11 maxmind-db-3.1.0.jar
-rw-r-----. 1 wazuh-indexer wazuh-indexer     1973 Mar 26 20:11 plugin-descriptor.properties
-rw-r-----. 1 wazuh-indexer wazuh-indexer     1764 Mar 26 20:11 plugin-security.policy
[root@wazuh-server maxmind]# bash update_maxmind.sh 
Stopping Wazuh Indexer service...
  Wazuh Indexer stopped.
Checking GeoLite2-Country...
  Extracted GeoLite2-Country.mmdb to temporary file.
  GeoLite2-Country is up to date (contents identical).
Checking GeoLite2-City...
  Extracted GeoLite2-City.mmdb to temporary file.
  GeoLite2-City is up to date (contents identical).
Checking GeoLite2-ASN...
  Extracted GeoLite2-ASN.mmdb to temporary file.
  GeoLite2-ASN is up to date (contents identical).
No updates were necessary; Wazuh Indexer will be ensured running by EXIT trap.
Ensuring Wazuh Indexer service is running...
  Wazuh Indexer started.
```

## Docker Integration

If you are running Wazuh in a Docker container, make sure to adjust the paths and environment variables accordingly.

This document describes how to integrate and test the `update_maxmind.sh` script in a multi-node Docker deployment of Wazuh Indexer. The script automates downloading and binding the latest GeoLite2 databases into each indexer container.

### Prerequisites

* Docker and Docker Compose installed
* A multi-node Wazuh deployment managed via `docker-compose.yml`
* MaxMind **Account ID** and **License Key**

## Configuration

Edit the top of `update_maxmind.sh` to set your own environment variables. Replace the placeholders below (in the script):

```bash
# Path to your project root (where docker-compose.yml lives)
PROJECT_ROOT="/path/to/your/wazuh-docker/multi-node"
CONTAINER=true  # Set to true

# Directory under config/ for GeoIP DBs and scripts
GEOIP_DIR="${PROJECT_ROOT}/config/wazuh_indexer/geoip-data"
SCRIPT_DIR="${PROJECT_ROOT}/config/wazuh_indexer/scripts"

# MaxMind credentials
ACCOUNT_ID="YOUR_MAXMIND_ACCOUNT_ID"
LICENSE_KEY="YOUR_MAXMIND_LICENSE_KEY"

# Wazuh Indexer Docker image (must match your used version)
INDEXER_IMAGE="wazuh/wazuh-indexer:4.12.0"
```

## Installation & Bootstrapping

1. **Bring up your cluster** (if not already running):

   ```bash
   cd "${PROJECT_ROOT}"
   docker-compose up -d
   ```

2. **Prepare the GeoIP folders and scripts**:

   ```bash
   mkdir -p "${GEOIP_DIR}"
   mkdir -p "${SCRIPT_DIR}"
   chmod +x "${SCRIPT_DIR}/update_maxmind.sh"
   ```

<details>
<summary>Example of placing the script and creating the directories</summary>

```bash
> sudo docker-compose up -d

[+] Running 7/7
 ⠿ Container multi-node-wazuh2.indexer-1   Running                                                                                                                                                 0.0s
 ⠿ Container multi-node-wazuh3.indexer-1   Running                                                                                                                                                 0.0s
 ⠿ Container multi-node-wazuh.worker-1     Running                                                                                                                                                 0.0s
 ⠿ Container multi-node-nginx-1            Started                                                                                                                                                 1.1s
 ⠿ Container multi-node-wazuh1.indexer-1   Started                                                                                                                                                 0.3s
 ⠿ Container multi-node-wazuh.master-1     Started                                                                                                                                                 0.3s
 ⠿ Container multi-node-wazuh.dashboard-1  Started                                                                                                                                                 0.2s
 ~/MyVagrant/docker/wazuh-docker/multi-node | #v4.12.0 !1 ?3                                                                                                                                           
> xdg-open  docker-compose.yml 
 ~/MyVagrant/docker/wazuh-docker/multi-node | #v4.12.0 !1 ?3                                                                                                                                           
> ls
config  docker-compose.yml  generate-indexer-certs.yml  Migration-to-Wazuh-4.4.md  README.md  volume-migrator.sh
 ~/MyVagrant/docker/wazuh-docker/multi-node | #v4.12.0 !1 ?3                                                                                                                                           
> mkdir config/wazuh_indexer/geoip-data
 ~/MyVagrant/docker/wazuh-docker/multi-node | #v4.12.0 !1 ?3                                                                                                                                           
> mkdir config/wazuh_indexer/scripts   
 ~/MyVagrant/docker/wazuh-docker/multi-node | #v4.12.0 !1 ?3                                                                                                                                           
> cp ../single-node/config/wazuh_indexer/scripts/update_maxmind.sh config/wazuh_indexer/scripts 
 ~/MyVagrant/docker/wazuh-docker/multi-node | #v4.12.0 !1 ?4                                                                                                                                           
> ll config/wazuh_indexer           
total 24K
drwxr-xr-x 2 leon leon 4.0K Jul 24 09:42 geoip-data
-rw-r--r-- 1 leon leon 1.3K Jul 10 11:53 internal_users.yml
drwxr-xr-x 2 leon leon 4.0K Jul 24 09:42 scripts
-rw-r--r-- 1 leon leon 1.8K Jul 10 11:53 wazuh1.indexer.yml
-rw-r--r-- 1 leon leon 1.8K Jul 10 11:53 wazuh2.indexer.yml
-rw-r--r-- 1 leon leon 1.8K Jul 10 11:53 wazuh3.indexer.yml
```
</details>

## docker-compose.yml Snippet

Ensure each indexer service binds the GeoLite2 files from your host folder:

```yaml
services:
  wazuh1.indexer:
    image: ${INDEXER_IMAGE}
    volumes:
      ...
      - type: bind
        source: ./config/wazuh_indexer/geoip-data/GeoLite2-City.mmdb
        target: /usr/share/wazuh-indexer/modules/ingest-geoip/GeoLite2-City.mmdb
      - type: bind
        source: ./config/wazuh_indexer/geoip-data/GeoLite2-Country.mmdb
        target: /usr/share/wazuh-indexer/modules/ingest-geoip/GeoLite2-Country.mmdb
      - type: bind
        source: ./config/wazuh_indexer/geoip-data/GeoLite2-ASN.mmdb
        target: /usr/share/wazuh-indexer/modules/ingest-geoip/GeoLite2-ASN.mmdb
  wazuh2.indexer:
    # same volumes as above
  wazuh3.indexer:
    # same volumes as above
```

### Example docker-compose.yml Snippet
<details>
<summary>Example docker-compose.yml snippet</summary>

```bash
> cat docker-compose.yml | grep -Ei "Geoip" -A1 -B27

  wazuh1.indexer:
    image: wazuh/wazuh-indexer:4.12.0
    hostname: wazuh1.indexer
    restart: always
    ports:
      - "9200:9200"
    environment:
      - "OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g"
      - "bootstrap.memory_lock=true"
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 65536
        hard: 65536
    volumes:
      - wazuh-indexer-data-1:/var/lib/wazuh-indexer
      - ./config/wazuh_indexer_ssl_certs/root-ca.pem:/usr/share/wazuh-indexer/certs/root-ca.pem
      - ./config/wazuh_indexer_ssl_certs/wazuh1.indexer-key.pem:/usr/share/wazuh-indexer/certs/wazuh1.indexer.key
      - ./config/wazuh_indexer_ssl_certs/wazuh1.indexer.pem:/usr/share/wazuh-indexer/certs/wazuh1.indexer.pem
      - ./config/wazuh_indexer_ssl_certs/admin.pem:/usr/share/wazuh-indexer/certs/admin.pem
      - ./config/wazuh_indexer_ssl_certs/admin-key.pem:/usr/share/wazuh-indexer/certs/admin-key.pem
      - ./config/wazuh_indexer/wazuh1.indexer.yml:/usr/share/wazuh-indexer/opensearch.yml
      - ./config/wazuh_indexer/internal_users.yml:/usr/share/wazuh-indexer/opensearch-security/internal_users.yml
      - type: bind
        source: ./config/wazuh_indexer/geoip-data/GeoLite2-City.mmdb
        target: /usr/share/wazuh-indexer/modules/ingest-geoip/GeoLite2-City.mmdb
      - type: bind
        source: ./config/wazuh_indexer/geoip-data/GeoLite2-Country.mmdb
        target: /usr/share/wazuh-indexer/modules/ingest-geoip/GeoLite2-Country.mmdb
      - type: bind
        source: ./config/wazuh_indexer/geoip-data/GeoLite2-ASN.mmdb
        target: /usr/share/wazuh-indexer/modules/ingest-geoip/GeoLite2-ASN.mmdb

  wazuh2.indexer:
    image: wazuh/wazuh-indexer:4.12.0
    hostname: wazuh2.indexer
    restart: always
    environment:
      - "OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g"
      - "bootstrap.memory_lock=true"
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 65536
        hard: 65536
    volumes:
      - wazuh-indexer-data-2:/var/lib/wazuh-indexer
      - ./config/wazuh_indexer_ssl_certs/root-ca.pem:/usr/share/wazuh-indexer/certs/root-ca.pem
      - ./config/wazuh_indexer_ssl_certs/wazuh2.indexer-key.pem:/usr/share/wazuh-indexer/certs/wazuh2.indexer.key
      - ./config/wazuh_indexer_ssl_certs/wazuh2.indexer.pem:/usr/share/wazuh-indexer/certs/wazuh2.indexer.pem
      - ./config/wazuh_indexer/wazuh2.indexer.yml:/usr/share/wazuh-indexer/opensearch.yml
      - ./config/wazuh_indexer/internal_users.yml:/usr/share/wazuh-indexer/opensearch-security/internal_users.yml
      - type: bind
        source: ./config/wazuh_indexer/geoip-data/GeoLite2-City.mmdb
        target: /usr/share/wazuh-indexer/modules/ingest-geoip/GeoLite2-City.mmdb
      - type: bind
        source: ./config/wazuh_indexer/geoip-data/GeoLite2-Country.mmdb
        target: /usr/share/wazuh-indexer/modules/ingest-geoip/GeoLite2-Country.mmdb
      - type: bind
        source: ./config/wazuh_indexer/geoip-data/GeoLite2-ASN.mmdb
        target: /usr/share/wazuh-indexer/modules/ingest-geoip/GeoLite2-ASN.mmdb

  wazuh3.indexer:
    image: wazuh/wazuh-indexer:4.12.0
    hostname: wazuh3.indexer
    restart: always
    environment:
      - "OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g"
      - "bootstrap.memory_lock=true"
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 65536
        hard: 65536
    volumes:
      - wazuh-indexer-data-3:/var/lib/wazuh-indexer
      - ./config/wazuh_indexer_ssl_certs/root-ca.pem:/usr/share/wazuh-indexer/certs/root-ca.pem
      - ./config/wazuh_indexer_ssl_certs/wazuh3.indexer-key.pem:/usr/share/wazuh-indexer/certs/wazuh3.indexer.key
      - ./config/wazuh_indexer_ssl_certs/wazuh3.indexer.pem:/usr/share/wazuh-indexer/certs/wazuh3.indexer.pem
      - ./config/wazuh_indexer/wazuh3.indexer.yml:/usr/share/wazuh-indexer/opensearch.yml
      - ./config/wazuh_indexer/internal_users.yml:/usr/share/wazuh-indexer/opensearch-security/internal_users.yml
      - type: bind
        source: ./config/wazuh_indexer/geoip-data/GeoLite2-City.mmdb
        target: /usr/share/wazuh-indexer/modules/ingest-geoip/GeoLite2-City.mmdb
      - type: bind
        source: ./config/wazuh_indexer/geoip-data/GeoLite2-Country.mmdb
        target: /usr/share/wazuh-indexer/modules/ingest-geoip/GeoLite2-Country.mmdb
      - type: bind
        source: ./config/wazuh_indexer/geoip-data/GeoLite2-ASN.mmdb
        target: /usr/share/wazuh-indexer/modules/ingest-geoip/GeoLite2-ASN.mmdb
```
</details>

## Running the Update Script

From your project root, execute:

```bash
"${SCRIPT_DIR}/update_maxmind.sh"
```

The script will:

1. Detect all running indexer containers by image
2. Bootstrap default `.mmdb` files into `config/wazuh_indexer/geoip-data/` if empty
3. Stop all indexer containers to update the GeoIP databases
4. Download, compare, and update any changed GeoLite2 databases
5. Recreate each indexer service so Docker re-mounts the updated files
6. Ensure all indexer containers are back up

## Example Output

<details>
<summary>Example output from running the script</summary>

```bash
> ls -la config/wazuh_indexer/geoip-data
total 8
drwxr-xr-x 2 leon leon 4096 Jul 24 09:42 .
drwxr-xr-x 4 leon leon 4096 Jul 24 09:42 ..
 ~/MyVagrant/docker/wazuh-docker/multi-node | #v4.12.0 !2 ?4                                                                                                                                           
> ls -la config/wazuh_indexer/scripts   
total 16
drwxr-xr-x 2 leon leon 4096 Jul 24 09:42 .
drwxr-xr-x 4 leon leon 4096 Jul 24 09:42 ..
-rwxr-xr-x 1 leon leon 7373 Jul 24 09:42 update_maxmind.sh
 ~/MyVagrant/docker/wazuh-docker/multi-node | #v4.12.0 !2 ?4                                                                                                                                           
> sudo docker ps
CONTAINER ID   IMAGE                          COMMAND                  CREATED       STATUS       PORTS                                                                                                                                                       NAMES
0a80f36d5933   nginx:stable                   "/docker-entrypoint.…"   4 hours ago   Up 4 hours   80/tcp, 0.0.0.0:1514->1514/tcp, [::]:1514->1514/tcp                                                                                                         multi-node-nginx-1
12e1eeb4b0f9   wazuh/wazuh-dashboard:4.12.0   "/entrypoint.sh"         4 hours ago   Up 4 hours   443/tcp, 0.0.0.0:443->5601/tcp, [::]:443->5601/tcp                                                                                                          multi-node-wazuh.dashboard-1
a70a1efb2466   wazuh/wazuh-manager:4.12.0     "/init"                  4 hours ago   Up 4 hours   1514/tcp, 0.0.0.0:1515->1515/tcp, [::]:1515->1515/tcp, 0.0.0.0:514->514/udp, [::]:514->514/udp, 1516/tcp, 0.0.0.0:55000->55000/tcp, [::]:55000->55000/tcp   multi-node-wazuh.master-1
6447b133bbd1   wazuh/wazuh-indexer:4.12.0     "/entrypoint.sh open…"   4 hours ago   Up 4 hours   0.0.0.0:9200->9200/tcp, [::]:9200->9200/tcp                                                                                                                 multi-node-wazuh1.indexer-1
f1a27f9deccc   wazuh/wazuh-indexer:4.12.0     "/entrypoint.sh open…"   4 hours ago   Up 4 hours   9200/tcp                                                                                                                                                    multi-node-wazuh2.indexer-1
7dc2fba75c98   wazuh/wazuh-manager:4.12.0     "/init"                  4 hours ago   Up 4 hours   1514-1516/tcp, 514/udp, 55000/tcp                                                                                                                           multi-node-wazuh.worker-1
f136d9308022   wazuh/wazuh-indexer:4.12.0     "/entrypoint.sh open…"   4 hours ago   Up 4 hours   9200/tcp                                                                                                                                                    multi-node-wazuh3.indexer-1
> ./config/wazuh_indexer/scripts/update_maxmind.sh
Found indexer containers:
  • multi-node-wazuh3.indexer-1
  • multi-node-wazuh2.indexer-1
  • multi-node-wazuh1.indexer-1
Detected services to recreate: wazuh3.indexer wazuh2.indexer wazuh1.indexer
GeoIP dir is empty; bootstrapping default .mmdb files…
  • Copying GeoLite2-City.mmdb
Successfully copied 62.9MB to /home/leon/MyVagrant/docker/wazuh-docker/multi-node/config/wazuh_indexer/geoip-data
  • Copying GeoLite2-Country.mmdb
Successfully copied 3.99MB to /home/leon/MyVagrant/docker/wazuh-docker/multi-node/config/wazuh_indexer/geoip-data
  • Copying GeoLite2-ASN.mmdb
Successfully copied 6.61MB to /home/leon/MyVagrant/docker/wazuh-docker/multi-node/config/wazuh_indexer/geoip-data
Bootstrapped GeoIP DBs into /home/leon/MyVagrant/docker/wazuh-docker/multi-node/config/wazuh_indexer/geoip-data
Stopping indexer...
Stopping all indexer containers…
  • multi-node-wazuh3.indexer-1
multi-node-wazuh3.indexer-1
  • multi-node-wazuh2.indexer-1
multi-node-wazuh2.indexer-1
  • multi-node-wazuh1.indexer-1
multi-node-wazuh1.indexer-1
  Wazuh Indexer stopped.
Checking GeoLite2-Country...
  Extracted GeoLite2-Country.mmdb to temporary file.
  New or changed GeoLite2-Country detected; installing updated .mmdb...
  Moved GeoLite2-Country.mmdb to /home/leon/MyVagrant/docker/wazuh-docker/multi-node/config/wazuh_indexer/geoip-data/GeoLite2-Country.mmdb
Checking GeoLite2-City...
  Extracted GeoLite2-City.mmdb to temporary file.
  New or changed GeoLite2-City detected; installing updated .mmdb...
  Moved GeoLite2-City.mmdb to /home/leon/MyVagrant/docker/wazuh-docker/multi-node/config/wazuh_indexer/geoip-data/GeoLite2-City.mmdb
Checking GeoLite2-ASN...
  Extracted GeoLite2-ASN.mmdb to temporary file.
  New or changed GeoLite2-ASN detected; installing updated .mmdb...
  Moved GeoLite2-ASN.mmdb to /home/leon/MyVagrant/docker/wazuh-docker/multi-node/config/wazuh_indexer/geoip-data/GeoLite2-ASN.mmdb
Updates applied; restarting indexer...
Updates applied; recreating indexer containers to pick up new mounts…
  • Removing old container for service 'wazuh3.indexer'…
[+] Running 1/0
 ⠿ Container multi-node-wazuh3.indexer-1  Stopped                                                                                                                                                  0.0s
Going to remove multi-node-wazuh3.indexer-1
[+] Running 1/0
 ⠿ Container multi-node-wazuh3.indexer-1  Removed                                                                                                                                                  0.0s
[+] Running 1/1
 ⠿ Container multi-node-wazuh3.indexer-1  Started                                                                                                                                                  0.2s
     Recreated wazuh3.indexer
  • Removing old container for service 'wazuh2.indexer'…
[+] Running 1/0
 ⠿ Container multi-node-wazuh2.indexer-1  Stopped                                                                                                                                                  0.0s
Going to remove multi-node-wazuh2.indexer-1
[+] Running 1/0
 ⠿ Container multi-node-wazuh2.indexer-1  Removed                                                                                                                                                  0.0s
[+] Running 1/1
 ⠿ Container multi-node-wazuh2.indexer-1  Started                                                                                                                                                  0.2s
     Recreated wazuh2.indexer
  • Removing old container for service 'wazuh1.indexer'…
[+] Running 1/0
 ⠿ Container multi-node-wazuh1.indexer-1  Stopped                                                                                                                                                  0.0s
Going to remove multi-node-wazuh1.indexer-1
[+] Running 1/0
 ⠿ Container multi-node-wazuh1.indexer-1  Removed                                                                                                                                                  0.0s
[+] Running 1/1
 ⠿ Container multi-node-wazuh1.indexer-1  Started                                                                                                                                                  0.3s
     Recreated wazuh1.indexer
All indexer containers have been recreated with updated mounts.
MaxMind GeoLite2 databases have been updated successfully.
Ensuring indexer is running...
Ensuring all indexers are running…
  • multi-node-wazuh3.indexer-1 is already running.
  • multi-node-wazuh2.indexer-1 is already running.
  • multi-node-wazuh1.indexer-1 is already running.
 ~/MyVagrant/docker/wazuh-docker/multi-node | #v4.12.0 !2 ?5                                                                                                                                        5s 
> sudo docker exec multi-node-wazuh2.indexer-1 ls -l /usr/share/wazuh-indexer/modules/ingest-geoip
total 82116
-rw-r--r-- 1 wazuh-indexer wazuh-indexer 10706647 Jul 24 12:04 GeoLite2-ASN.mmdb
-rw-r--r-- 1 wazuh-indexer wazuh-indexer 61731202 Jul 24 12:04 GeoLite2-City.mmdb
-rw-r--r-- 1 wazuh-indexer wazuh-indexer  9752788 Jul 24 12:04 GeoLite2-Country.mmdb
-rw-r----- 1 wazuh-indexer wazuh-indexer    61668 Apr 30 10:54 geoip2-4.2.1.jar
-rw-r----- 1 wazuh-indexer wazuh-indexer    27727 Apr 30 10:54 ingest-geoip-2.19.1.jar
-rw-r----- 1 wazuh-indexer wazuh-indexer    78494 Apr 30 10:54 jackson-annotations-2.18.2.jar
-rw-r----- 1 wazuh-indexer wazuh-indexer  1658755 Apr 30 10:54 jackson-databind-2.18.2.jar
-rw-r----- 1 wazuh-indexer wazuh-indexer    39021 Apr 30 10:54 maxmind-db-3.1.1.jar
-rw-r----- 1 wazuh-indexer wazuh-indexer     1973 Apr 30 10:54 plugin-descriptor.properties
-rw-r----- 1 wazuh-indexer wazuh-indexer     1764 Apr 30 10:54 plugin-security.policy
 ~/MyVagrant/docker/wazuh-docker/multi-node | #v4.12.0 !2 ?5                                                                  
> ls -la config/wazuh_indexer/geoip-data
total 80284
drwxr-xr-x 2 leon leon     4096 Jul 24 14:04 .
drwxr-xr-x 4 leon leon     4096 Jul 24 09:42 ..
-rw-r--r-- 1 leon leon 10706647 Jul 24 14:04 GeoLite2-ASN.mmdb
-rw-r--r-- 1 leon leon 61731202 Jul 24 14:04 GeoLite2-City.mmdb
-rw-r--r-- 1 leon leon  9752788 Jul 24 14:04 GeoLite2-Country.mmdb
```
</details>

### Verifying the Update
<details>
<summary>Verifying the Update</summary>

```bash
> sudo docker exec multi-node-wazuh2.indexer-1 ls -l /usr/share/wazuh-indexer/modules/ingest-geoip
total 82116
-rw-r--r-- 1 wazuh-indexer wazuh-indexer 10706647 Jul 24 12:04 GeoLite2-ASN.mmdb
-rw-r--r-- 1 wazuh-indexer wazuh-indexer 61731202 Jul 24 12:04 GeoLite2-City.mmdb
-rw-r--r-- 1 wazuh-indexer wazuh-indexer  9752788 Jul 24 12:04 GeoLite2-Country.mmdb
-rw-r----- 1 wazuh-indexer wazuh-indexer    61668 Apr 30 10:54 geoip2-4.2.1.jar
-rw-r----- 1 wazuh-indexer wazuh-indexer    27727 Apr 30 10:54 ingest-geoip-2.19.1.jar
-rw-r----- 1 wazuh-indexer wazuh-indexer    78494 Apr 30 10:54 jackson-annotations-2.18.2.jar
-rw-r----- 1 wazuh-indexer wazuh-indexer  1658755 Apr 30 10:54 jackson-databind-2.18.2.jar
-rw-r----- 1 wazuh-indexer wazuh-indexer    39021 Apr 30 10:54 maxmind-db-3.1.1.jar
-rw-r----- 1 wazuh-indexer wazuh-indexer     1973 Apr 30 10:54 plugin-descriptor.properties
-rw-r----- 1 wazuh-indexer wazuh-indexer     1764 Apr 30 10:54 plugin-security.policy
> ls -la config/wazuh_indexer/geoip-data
total 80284
drwxr-xr-x 2 leon leon     4096 Jul 24 14:04 .
drwxr-xr-x 4 leon leon     4096 Jul 24 09:42 ..
-rw-r--r-- 1 leon leon 10706647 Jul 24 14:04 GeoLite2-ASN.mmdb
-rw-r--r-- 1 leon leon 61731202 Jul 24 14:04 GeoLite2-City.mmdb
-rw-r--r-- 1 leon leon  9752788 Jul 24 14:04 GeoLite2-Country.mmdb
```

</details>

You should see the three `.mmdb` files alongside the plugin JARs and properties.

### Performing a test with updated database files
<details>
<summary>Performing a test with updated database files (no need to replace them)</summary>

```bash
> ./config/wazuh_indexer/scripts/update_maxmind.sh
Found indexer containers:
  • multi-node-wazuh1.indexer-1
  • multi-node-wazuh2.indexer-1
  • multi-node-wazuh3.indexer-1
Detected services to recreate: wazuh1.indexer wazuh2.indexer wazuh3.indexer
GeoIP dir already populated; skipping bootstrap.
Stopping indexer...
Stopping all indexer containers…
  • multi-node-wazuh1.indexer-1
multi-node-wazuh1.indexer-1
  • multi-node-wazuh2.indexer-1
multi-node-wazuh2.indexer-1
  • multi-node-wazuh3.indexer-1
multi-node-wazuh3.indexer-1
  Wazuh Indexer stopped.
Checking GeoLite2-Country...
  Extracted GeoLite2-Country.mmdb to temporary file.
  GeoLite2-Country is up to date (contents identical).
Checking GeoLite2-City...
  Extracted GeoLite2-City.mmdb to temporary file.
  GeoLite2-City is up to date (contents identical).
Checking GeoLite2-ASN...
  Extracted GeoLite2-ASN.mmdb to temporary file.
  GeoLite2-ASN is up to date (contents identical).
No updates needed; indexer will be ensured up by trap.
Ensuring indexer is running...
Ensuring all indexers are running…
multi-node-wazuh1.indexer-1
  • Started multi-node-wazuh1.indexer-1
multi-node-wazuh2.indexer-1
  • Started multi-node-wazuh2.indexer-1
multi-node-wazuh3.indexer-1
  • Started multi-node-wazuh3.indexer-1
 ~/MyVagrant/docker/wazuh-docker/multi-node | #v4.12.0 !2 ?5                                                                                                                                       4s 
> 
 ~/MyVagrant/docker/wazuh-docker/multi-node | #v4.12.0 !2 ?5                                                                                                                                       4s 
> ls -la config/wazuh_indexer/geoip-data
total 80284
drwxr-xr-x 2 leon leon     4096 Jul 24 14:04 .
drwxr-xr-x 4 leon leon     4096 Jul 24 09:42 ..
-rw-r--r-- 1 leon leon 10706647 Jul 24 14:04 GeoLite2-ASN.mmdb
-rw-r--r-- 1 leon leon 61731202 Jul 24 14:04 GeoLite2-City.mmdb
-rw-r--r-- 1 leon leon  9752788 Jul 24 14:04 GeoLite2-Country.mmdb
 ~/MyVagrant/docker/wazuh-docker/multi-node | #v4.12.0 !2 ?5                                                                                                                                          
> sudo docker exec multi-node-wazuh2.indexer-1 ls -l /usr/share/wazuh-indexer/modules/ingest-geoip
total 82116
-rw-r--r-- 1 wazuh-indexer wazuh-indexer 10706647 Jul 24 12:04 GeoLite2-ASN.mmdb
-rw-r--r-- 1 wazuh-indexer wazuh-indexer 61731202 Jul 24 12:04 GeoLite2-City.mmdb
-rw-r--r-- 1 wazuh-indexer wazuh-indexer  9752788 Jul 24 12:04 GeoLite2-Country.mmdb
-rw-r----- 1 wazuh-indexer wazuh-indexer    61668 Apr 30 10:54 geoip2-4.2.1.jar
-rw-r----- 1 wazuh-indexer wazuh-indexer    27727 Apr 30 10:54 ingest-geoip-2.19.1.jar
-rw-r----- 1 wazuh-indexer wazuh-indexer    78494 Apr 30 10:54 jackson-annotations-2.18.2.jar
-rw-r----- 1 wazuh-indexer wazuh-indexer  1658755 Apr 30 10:54 jackson-databind-2.18.2.jar
-rw-r----- 1 wazuh-indexer wazuh-indexer    39021 Apr 30 10:54 maxmind-db-3.1.1.jar
-rw-r----- 1 wazuh-indexer wazuh-indexer     1973 Apr 30 10:54 plugin-descriptor.properties
-rw-r----- 1 wazuh-indexer wazuh-indexer     1764 Apr 30 10:54 plugin-security.policy
 ~/MyVagrant/docker/wazuh-docker/multi-node | #v4.12.0 !2 ?5                                                                                                                                          
> sudo docker exec multi-node-wazuh1.indexer-1 ls -l /usr/share/wazuh-indexer/modules/ingest-geoip
total 82116
-rw-r--r-- 1 wazuh-indexer wazuh-indexer 10706647 Jul 24 12:04 GeoLite2-ASN.mmdb
-rw-r--r-- 1 wazuh-indexer wazuh-indexer 61731202 Jul 24 12:04 GeoLite2-City.mmdb
-rw-r--r-- 1 wazuh-indexer wazuh-indexer  9752788 Jul 24 12:04 GeoLite2-Country.mmdb
-rw-r----- 1 wazuh-indexer wazuh-indexer    61668 Apr 30 10:54 geoip2-4.2.1.jar
-rw-r----- 1 wazuh-indexer wazuh-indexer    27727 Apr 30 10:54 ingest-geoip-2.19.1.jar
-rw-r----- 1 wazuh-indexer wazuh-indexer    78494 Apr 30 10:54 jackson-annotations-2.18.2.jar
-rw-r----- 1 wazuh-indexer wazuh-indexer  1658755 Apr 30 10:54 jackson-databind-2.18.2.jar
-rw-r----- 1 wazuh-indexer wazuh-indexer    39021 Apr 30 10:54 maxmind-db-3.1.1.jar
-rw-r----- 1 wazuh-indexer wazuh-indexer     1973 Apr 30 10:54 plugin-descriptor.properties
-rw-r----- 1 wazuh-indexer wazuh-indexer     1764 Apr 30 10:54 plugin-security.policy
 ~/MyVagrant/docker/wazuh-docker/multi-node | #v4.12.0 !2 ?5                                                                                                                                          
> sudo docker exec multi-node-wazuh3.indexer-1 ls -l /usr/share/wazuh-indexer/modules/ingest-geoip
total 82116
-rw-r--r-- 1 wazuh-indexer wazuh-indexer 10706647 Jul 24 12:04 GeoLite2-ASN.mmdb
-rw-r--r-- 1 wazuh-indexer wazuh-indexer 61731202 Jul 24 12:04 GeoLite2-City.mmdb
-rw-r--r-- 1 wazuh-indexer wazuh-indexer  9752788 Jul 24 12:04 GeoLite2-Country.mmdb
-rw-r----- 1 wazuh-indexer wazuh-indexer    61668 Apr 30 10:54 geoip2-4.2.1.jar
-rw-r----- 1 wazuh-indexer wazuh-indexer    27727 Apr 30 10:54 ingest-geoip-2.19.1.jar
-rw-r----- 1 wazuh-indexer wazuh-indexer    78494 Apr 30 10:54 jackson-annotations-2.18.2.jar
-rw-r----- 1 wazuh-indexer wazuh-indexer  1658755 Apr 30 10:54 jackson-databind-2.18.2.jar
-rw-r----- 1 wazuh-indexer wazuh-indexer    39021 Apr 30 10:54 maxmind-db-3.1.1.jar
-rw-r----- 1 wazuh-indexer wazuh-indexer     1973 Apr 30 10:54 plugin-descriptor.properties
-rw-r----- 1 wazuh-indexer wazuh-indexer     1764 Apr 30 10:54 plugin-security.policy
 ~/MyVagrant/docker/wazuh-docker/multi-node | #v4.12.0 !2 ?5                                                                              
```

</details>