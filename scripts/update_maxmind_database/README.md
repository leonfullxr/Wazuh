# Maxmind database update script
Custom bash script for pulling the latest Maxmind GeoIP database and checking if the current version on the server (Wazuh) has the latest update, if not, replace it and have the indexer use the updated version.

Note: this is done for an All-in-One environment, but can be updated for distributed environments with multiple indexers, the script must be located on every indexer node.
## Introduction
It essentially does the following:

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

## Example
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
