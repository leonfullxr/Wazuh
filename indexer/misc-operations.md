# Miscellaneous Operations

Smaller indexer-adjacent procedures that do not warrant their own guide.

## Table of Contents

- [Showing local time in full_log](#showing-local-time-in-full_log)
- [Recovering indexer credentials](#recovering-indexer-credentials)

## Showing local time in full_log

Wazuh stores timestamps in UTC and the dashboard converts them for display —
but the raw `full_log` field keeps whatever timestamp the source log carried,
which users often want in local time. The fix is in the Filebeat ingest
pipeline: parse the timestamps with an explicit timezone and prepend the
converted timestamp to `full_log`.

1. Make sure the OS timezone is correct on the agent, and that the agent's
   chrooted copy of the timezone database matches the system's:

   ```bash
   timedatectl set-timezone 'Europe/Madrid'
   hwclock --systohc
   timedatectl    # verify

   systemctl stop wazuh-agent
   mv /var/ossec/etc/localtime /var/ossec/etc/localtime.bak
   cp /etc/localtime /var/ossec/etc/localtime
   chown root:wazuh /var/ossec/etc/localtime
   systemctl start wazuh-agent
   ```

2. On the manager, edit
   `/usr/share/filebeat/module/wazuh/alerts/ingest/pipeline.json` (back it up
   first). Find the existing `date` processor:

   ```json
   {
     "date": {
       "field": "timestamp",
       "target_field": "@timestamp",
       "formats": ["ISO8601"],
       "ignore_failure": false
     }
   },
   ```

   and replace it with a timezone-aware version that also rewrites
   `full_log`:

   ```json
   {
     "date": {
       "field": "timestamp",
       "target_field": "@timestamp",
       "formats": ["ISO8601"],
       "timezone": "Europe/Madrid",
       "ignore_failure": false
     }
   },
   {
     "date": {
       "field": "predecoder.timestamp",
       "target_field": "timestamp",
       "formats": ["ISO8601"],
       "timezone": "Europe/Madrid",
       "ignore_failure": true
     }
   },
   {
     "rename": {
       "field": "full_log",
       "target_field": "original_log"
     }
   },
   {
     "set": {
       "field": "full_log",
       "value": "{{{timestamp}}} {{{original_log}}}"
     }
   },
   ```

   Variant — prepend only the time of day, not the full date, by extracting
   into a `time` field and stripping the date portion:

   ```json
   {
     "set": {
       "field": "time",
       "value": "{{{timestamp}}}",
       "ignore_failure": true,
       "ignore_empty_value": true
     }
   },
   {
     "gsub": {
       "field": "time",
       "pattern": "^\\d{4}-\\d{2}-\\d{2}T",
       "replacement": ""
     }
   },
   ```

3. Upload the pipeline and restart:

   ```bash
   filebeat setup --pipelines
   systemctl restart filebeat
   ```

New alerts will carry the local-time-prefixed `full_log`. Remember this file
is shared with the [index separation](index-separation.md) and
[GeoIP](geoip.md#filtering-alerts-by-country) customizations and is
overwritten on upgrade — see
[coordinating pipeline.json changes](index-separation.md#coordinating-pipelinejson-changes).

References:
[Elastic — date processor](https://www.elastic.co/docs/reference/enrich-processor/date-processor).

## Recovering indexer credentials

When the `admin` password is lost or must be rotated, use the Wazuh passwords
tool with the admin certificate — and remember that **Filebeat and the
dashboard keep their own copies of the credentials**, which must be updated
too or ingestion breaks with authentication errors.

```bash
# 0. Sanity check the current state
filebeat test output

# 1. Back up the security configuration
mkdir /etc/wazuh-indexer/backup
cp /etc/wazuh-indexer/opensearch-security/internal_users.yml /etc/wazuh-indexer/backup/
chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/backup/

# 2. Set the new password using the admin certificate
bash wazuh-passwords-tool.sh -u admin -p '<NEW_PASSWORD>' -v \
  -c /etc/wazuh-indexer/certs/admin.pem \
  -k /etc/wazuh-indexer/certs/admin-key.pem

# 3. Update the Filebeat keystore on every manager node
echo admin | filebeat keystore add username --stdin --force
echo '<NEW_PASSWORD>' | filebeat keystore add password --stdin --force

# 4. Restart and verify
systemctl restart filebeat
filebeat test output
systemctl restart wazuh-manager
```

If Filebeat logs **HTTP 401** errors after a password change, the keystore
still holds the old credentials — repeat step 3 and restart Filebeat.

To verify a password against a bcrypt hash from `internal_users.yml`
(useful when you are not sure which credential a hash corresponds to):

```python
import bcrypt

hashed = b"$2y$12$...hash-from-internal_users.yml..."
password = b"CandidatePassword"

print("matches" if bcrypt.checkpw(password, hashed) else "no match")
```

For the full supported procedure, see
[Wazuh — password management](https://documentation.wazuh.com/current/user-manual/user-administration/password-management.html).
