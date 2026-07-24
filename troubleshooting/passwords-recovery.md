# Password Reset and Recovery

Resetting and recovering passwords across Wazuh components. There are two separate credential stores: do not mix them up:

- **Wazuh API users** (`wazuh`, `wazuh-wui`) - managed by the Wazuh manager's security framework.
- **Indexer internal users** (`admin`, `kibanaserver`, ...) - managed by the OpenSearch security plugin (`internal_users.yml`). Filebeat and the dashboard authenticate against these, so changing them means updating the Filebeat keystore too.

## Table of Contents

- [Reset a Wazuh API user password](#reset-a-wazuh-api-user-password)
- [Reset indexer passwords with wazuh-passwords-tool](#reset-indexer-passwords-with-wazuh-passwords-tool)
- [Verify a password against its bcrypt hash](#verify-a-password-against-its-bcrypt-hash)
- [Restore a previous indexer password from backup](#restore-a-previous-indexer-password-from-backup)
- [Related guides](#related-guides)

## Reset a Wazuh API user password

Access the master node and open the Wazuh Python console:

```bash
/var/ossec/framework/python/bin/python3
```

Import the `update_user` framework function and set the new password (`user_id="1"` is the `wazuh` user):

```python
>>> from wazuh.security import update_user
>>> update_user(user_id="1", password="<NEW_PASSWORD>").render()
```

A successful run returns:

```json
{'data': {'affected_items': [{'id': 1, 'username': 'wazuh', 'allow_run_as': True, 'roles': [1]}],
 'total_affected_items': 1, 'total_failed_items': 0, 'failed_items': []},
 'message': 'User was successfully updated', 'error': 0}
```

> Passwords must meet the API policy: 8-64 characters with upper case, lower case, a digit, and a symbol.

## Reset indexer passwords with wazuh-passwords-tool

Back up the internal users file first, then run the [passwords tool](https://documentation.wazuh.com/current/user-manual/user-administration/password-management.html) and update the Filebeat keystore:

```bash
# Check Filebeat connectivity first (baseline)
filebeat test output

# Back up the current internal users file
mkdir /etc/wazuh-indexer/backup
cp /etc/wazuh-indexer/opensearch-security/internal_users.yml /etc/wazuh-indexer/backup/
chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/backup/

# Run the passwords tool
bash wazuh-passwords-tool.sh -u admin -p '<NEW_PASSWORD>' -v \
  -c /etc/wazuh-indexer/certs/admin.pem \
  -k /etc/wazuh-indexer/certs/admin-key.pem

# Update the Filebeat keystore with the new credentials
echo admin | filebeat keystore add username --stdin --force
echo '<NEW_PASSWORD>' | filebeat keystore add password --stdin --force

systemctl restart filebeat
filebeat test output
systemctl restart wazuh-manager
systemctl restart wazuh-indexer
```

> If `filebeat test output` returns 401 Unauthorized, the keystore credentials do not match the indexer's: re-run the two `filebeat keystore add` commands with the correct password and restart Filebeat.

## Verify a password against its bcrypt hash

Useful for checking which password a hash in `internal_users.yml` corresponds to:

```python
import bcrypt
hashed = b"<HASH_FROM_INTERNAL_USERS_YML>"
password = b"<CANDIDATE_PASSWORD>"
print("matches" if bcrypt.checkpw(password, hashed) else "no match")
```

## Restore a previous indexer password from backup

If the passwords tool has been run (possibly several times) and you need the **original** credentials back, restore the oldest backup of the internal users file with `securityadmin.sh`:

```bash
ls -la /etc/wazuh-indexer/internalusers-backup

export JAVA_HOME=/usr/share/wazuh-indexer/jdk/
/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
  -f /etc/wazuh-indexer/internalusers-backup/<BACKUP_FILE>.yml.bkp \
  -t internalusers \
  -icl \
  -cacert /etc/wazuh-indexer/certs/root-ca.pem \
  -cert /etc/wazuh-indexer/certs/admin.pem \
  -key /etc/wazuh-indexer/certs/admin-key.pem \
  -h <INDEXER_IP> -nhnv

systemctl restart wazuh-indexer
```

Then point the Filebeat keystore back at the restored password and restart the dependent services:

```bash
echo admin | filebeat keystore add username --stdin --force
echo '<RESTORED_PASSWORD>' | filebeat keystore add password --stdin --force

systemctl restart filebeat
systemctl restart wazuh-dashboard
```

## Related guides

- [ldap-ad.md](ldap-ad.md) - external authentication as an alternative to internal users
- The admin certificate/key pair used by `securityadmin.sh` and the passwords tool comes from the deployment certificates - see the certificates section of this knowledge base
