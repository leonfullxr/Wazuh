# NetIQ Identity Manager Decoders

This decoder parses NetIQ Identity Manager audit and request events exported
as CEF syslog. It is intended for identity-governance monitoring where rules
need structured request, actor, target DN, status, privilege, and correlation
fields.

Decoder XML: [`netiq.xml`](netiq.xml). This repository does not ship NetIQ
rules; build rules from the fields verified in your own event samples.

## Overview

The parent recognizes messages containing `IdentityManager`. Child decoders
extract the CEF header and optional extensions including `req_by`,
`req_original`, `target_dn`, `source_dn`, `req_category`, `req_status`,
`correlation_id`, `duser`, `spriv`, `dpriv`, `action`, and `outcome`.

## Prerequisites

- NetIQ Identity Manager exports CEF syslog to a collector monitored by Wazuh.
- The receiving `<localfile>` uses `syslog` format.
- Sanitized samples cover every NetIQ event type that local rules will use.

## Deployment

```bash
sudo install -o wazuh -g wazuh -m 640 netiq.xml \
  /var/ossec/etc/decoders/netiq.xml
sudo /var/ossec/bin/wazuh-analysisd -t
```

Test representative messages with `/var/ossec/bin/wazuh-logtest` before
restarting. A minimal sanitized shape is:

```text
IdentityManager: CEF:0|NetIQ|Identity Manager|4.8.7.0|ROLE_REQUEST|Role request submitted|5|msg=Request Description:Temporary administrator access; Original Requester:analyst@example.com; Request Date:2026-07-10; Target DN: cn=example-user,ou=people,dc=example,dc=com; Request Status: Pending; Correlation ID: 123e4567-e89b-12d3-a456-426614174000 outcome=Success
```

Verify the decoder selected in phase 2 and inspect the extracted values.
NetIQ CEF payloads vary by module and version; update the decoder only from
captured examples, not assumptions about missing fields.

## Verification

```bash
sudo systemctl restart wazuh-manager
sudo journalctl -u wazuh-manager --since "5 minutes ago" --no-pager
```

Send one event through the real syslog path, confirm the fields in
`archives.json` or the dashboard, and then create narrowly scoped rules under
`/var/ossec/etc/rules/`. Deploy the same files to every manager node.

## See also

- [Decoder syntax](../syntax.md)
- [Decoder section deployment workflow](../README.md)
- [LDAP and Active Directory troubleshooting](../../troubleshooting/ldap-ad.md)
