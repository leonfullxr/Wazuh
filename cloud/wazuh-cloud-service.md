# Wazuh Cloud Service: Credentials, API Access, and Storage Tiers

## Table of Contents
- [Introduction](#introduction)
- [Credential Types](#credential-types)
- [API Access on Wazuh Cloud](#api-access-on-wazuh-cloud)
  - [Endpoints](#endpoints)
  - [Creating an API User](#creating-an-api-user)
  - [Testing Server API Access](#testing-server-api-access)
  - [Testing Indexer API Access](#testing-indexer-api-access)
- [Storage Tiers: Indexed Data vs Archive Data](#storage-tiers-indexed-data-vs-archive-data)
- [Retrieving Archive (Cold) Data with wcloud-cli](#retrieving-archive-cold-data-with-wcloud-cli)
- [References](#references)

## Introduction

The Wazuh Cloud SaaS offering exposes the same server and indexer APIs as an on-premises deployment, but behind different endpoints and with its own credential model and storage lifecycle. This page collects the customer-side knowledge that most often trips people up: which credentials do what, how to reach the APIs without port 55000/9200, how the hot/cold storage stages work, and how to download archived data with `wcloud-cli`.

Everything here is based on the official [Wazuh Cloud service documentation](https://documentation.wazuh.com/current/cloud-service/index.html).

## Credential Types

Wazuh Cloud uses **separate credential sets per component** -- they are not interchangeable:

1. **Cloud Console credentials** -- the username/password for [the Wazuh Cloud console](https://console.cloud.wazuh.com/). Valid only for the console itself (environment management, API keys, billing).
2. **Wazuh dashboard / manager API credentials** -- the internal users (`wazuh`, `wazuh-wui`, or custom internal users) used to log into the dashboard and to authenticate against the Wazuh server API.
3. **Cloud API keys** -- generated in the console under **API keys**; used by tooling such as `wcloud-cli` (see [below](#retrieving-archive-cold-data-with-wcloud-cli)), not for the server API.

If you lose the `wazuh`/`wazuh-wui` credentials, create a new internal user from **Server management > Security** instead (see [RBAC documentation](https://documentation.wazuh.com/current/user-manual/user-administration/rbac.html)).

## API Access on Wazuh Cloud

### Endpoints

Cloud environments do **not** expose ports 55000 (server API) or 9200 (indexer API). Use path-based endpoints instead, with no port:

| On-premises | Wazuh Cloud |
|---|---|
| `https://<manager>:55000/<endpoint>` | `https://<CLOUD_ID>.cloud.wazuh.com/api/wazuh/<endpoint>` |
| `https://<indexer>:9200/<endpoint>` | `https://<CLOUD_ID>.cloud.wazuh.com/api/elastic/<endpoint>` |

Additionally, the source IP address of your API client must be **whitelisted** for the environment -- request this through Wazuh Cloud support if API calls time out from an otherwise correct setup.

### Creating an API User

1. On the dashboard, go to **Server management > Security > Users** and create an internal user, assigning roles according to your needs.
2. Generate a JWT token (replace credentials and Cloud ID):

   ```bash
   # On-premises
   TOKEN=$(curl -u <USER>:<PASSWORD> -k -X POST "https://<MANAGER_IP>:55000/security/user/authenticate?raw=true")

   # Wazuh Cloud
   TOKEN=$(curl -u <USER>:<PASSWORD> -k -X POST "https://<CLOUD_ID>.cloud.wazuh.com/api/wazuh/security/user/authenticate?raw=true")
   ```

3. Call any endpoint from the [server API reference](https://documentation.wazuh.com/current/user-manual/api/reference.html):

   ```bash
   # List agent groups
   curl -k -X GET "https://<CLOUD_ID>.cloud.wazuh.com/api/wazuh/groups?pretty=true" -H "Authorization: Bearer $TOKEN"

   # List agents
   curl -k -X GET "https://<CLOUD_ID>.cloud.wazuh.com/api/wazuh/agents?pretty=true" -H "Authorization: Bearer $TOKEN"
   ```

When following examples from the [API getting started guide](https://documentation.wazuh.com/current/user-manual/api/getting-started.html), replace every `https://localhost:55000/<ENDPOINT>` with `https://<CLOUD_ID>.cloud.wazuh.com/api/wazuh/<ENDPOINT>`.

### Testing Server API Access

```bash
echo $TOKEN    # should print a JWT; blank or an error means authentication failed

curl -k -X GET "https://<CLOUD_ID>.cloud.wazuh.com/api/wazuh/" -H "Authorization: Bearer $TOKEN"
```

<details>
<summary>Click to expand expected output</summary>

```json
{
  "data": {
    "title": "Wazuh API REST",
    "api_version": "4.7.4",
    "revision": 40717,
    "license_name": "GPL 2.0",
    "license_url": "https://github.com/wazuh/wazuh/blob/master/LICENSE",
    "hostname": "wazuh-master",
    "timestamp": "2024-05-14T21:34:15Z"
  },
  "error": 0
}
```

</details>

If authentication fails, double-check the user credentials, confirm your source IP is whitelisted, and verify network connectivity to the endpoint.

### Testing Indexer API Access

```bash
curl -u <USER>:<PASSWORD> -k -X GET "https://<CLOUD_ID>.cloud.wazuh.com/api/elastic/_cat/indices?s=index"
```

A list of `wazuh-alerts-*` (and possibly `wazuh-archives-*`) indices confirms the indexer path works.

## Storage Tiers: Indexed Data vs Archive Data

Two distinct concepts share the word "archive" -- do not confuse them:

- **`wazuh-archives-*` (index name).** By default Wazuh only indexes alerts of **level 3 or higher** into `wazuh-alerts-*`. Raw events of *all* levels can additionally be stored in `wazuh-archives-*`, but this is disabled by default (`<logall_json>no</logall_json>`) because it significantly increases alert volume and disk usage. See [Wazuh indexer indices](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html) and [Archive data configuration](https://documentation.wazuh.com/current/cloud-service/archive-data/configuration.html).
- **Storage stages** (Wazuh Cloud lifecycle for your indexed data, per [Archive data](https://documentation.wazuh.com/current/cloud-service/archive-data/index.html)):
  - **Indexed data** (formerly *hot storage*) -- recent data, actively readable and writable. Default retention: 3 months.
  - **Archive data** (formerly *cold storage*) -- older data, moved out of the cluster. Indices are frozen/read-only to reduce overhead. Default retention: 1 year.

Example: an index named `wazuh-alerts-4.x-2025.07.30` is queryable and writable for about 3 months (until 2025-10-30), then transitions automatically to cold storage where it remains accessible read-only.

## Retrieving Archive (Cold) Data with wcloud-cli

The [`wcloud-cli` tool](https://documentation.wazuh.com/current/cloud-service/cli/index.html) downloads cold storage data from a Wazuh Cloud environment.

**Prerequisites:** a Linux system (WSL works) with internet access, Python 3.x, and the `boto3` and `requests` packages.

1. **Get a Cloud API key.** In the [Wazuh Cloud console](https://console.cloud.wazuh.com/), open **API keys** in the left menu. Reuse an existing active key or click **Generate API key**, give it a name, and generate it. Copy the key and store it somewhere safe -- it is shown only once.

2. **Install the tool:**

   ```bash
   cd ~
   curl -so ~/wcloud-cli https://packages.wazuh.com/resources/cloud/wcloud-cli && chmod 500 ~/wcloud-cli
   ```

3. **Configure credentials:**

   ```bash
   mkdir ~/.wazuh-cloud && cd ~/.wazuh-cloud && touch credentials
   ```

   Content of `~/.wazuh-cloud/credentials`:

   ```ini
   [default]
   wazuh_cloud_api_key_name = mykey
   wazuh_cloud_api_key_secret = <YOUR_CLOUD_API_KEY>
   ```

   - `wazuh_cloud_api_key_name`: a label of your choosing for the key.
   - `wazuh_cloud_api_key_secret`: the API key from the Cloud console.

4. **Test the credentials:**

   ```bash
   ./wcloud-cli test-credentials --profile default
   ```

   Expected output: `The API key name 'mykey' in the profile 'default' is valid.`

5. **Generate a temporary S3 token** for your environment (replace `<ENVIRONMENT_ID>` with your environment's ID, e.g. a 12-character hex string):

   ```bash
   ./wcloud-cli cold-storage get-aws-s3-token <ENVIRONMENT_ID>
   ```

   The output shows the environment's region, the S3 path, and temporary AWS credentials with their expiry timestamp.

6. **List files** (optional). Dates use `YYYY-MM-DD` format, zero-padded; the minimum range granularity is one day:

   ```bash
   ./wcloud-cli cold-storage list <ENVIRONMENT_ID> --start 2023-12-28 --end 2023-12-29
   ```

7. **Download files:**

   ```bash
   ./wcloud-cli cold-storage download <ENVIRONMENT_ID> /home/<user> --start 2023-12-28 --end 2023-12-29
   ```

   Downloaded alert files follow this naming structure:

   ```text
   /home/<user>/<ENVIRONMENT_ID>/output/alerts/<YEAR>/<MONTH>/<DAY>/<ENVIRONMENT_ID>_output_alerts_<YEAR><MONTH><DAY>T<TIME>_<ID>.json.gz
   ```

8. **Decompress** (in place, no copy is created):

   ```bash
   gzip -d <FILE_NAME>.json.gz
   ```

9. **Narrow to a time-of-day range.** The CLI cannot filter below one day, but the file names embed timestamps, so filter locally, e.g. files from 2023-12-28 during the 12:00 hour:

   ```bash
   ls /home/<user>/<ENVIRONMENT_ID>/output/alerts/2023/12/28/ | grep 2023-12-28T12
   ```

## References

- [Wazuh Cloud service documentation](https://documentation.wazuh.com/current/cloud-service/index.html)
- [wcloud-cli reference](https://documentation.wazuh.com/current/cloud-service/cli/index.html)
- [Archive data - Wazuh Cloud](https://documentation.wazuh.com/current/cloud-service/archive-data/index.html)
- [Wazuh server API reference](https://documentation.wazuh.com/current/user-manual/api/reference.html)
- [Wazuh index management (blog)](https://wazuh.com/blog/wazuh-index-management/)
- [Least-privilege dashboard editing](rbac-dashboards.md) -- restricting what API/dashboard users can do once authenticated
