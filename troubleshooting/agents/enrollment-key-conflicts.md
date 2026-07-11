# Enrollment and Key Conflicts

Runbook for `agent key already in use` / duplicate-name warnings during enrollment, and for fleets of roaming devices (laptops, VPN clients) whose IP addresses change constantly.

## Table of Contents

- [Why it happens](#why-it-happens)
- [Prevention](#prevention)
- [Enable force re-enrollment on the manager](#enable-force-re-enrollment-on-the-manager)
- [Roaming devices: laptops and VPN clients](#roaming-devices-laptops-and-vpn-clients)
- [Related guides](#related-guides)

## Why it happens

The manager logs this warning when more than one agent tries to connect using the same agent ID, or when an agent presents a key that no longer matches the one stored on the manager. Typical triggers:

- Two hosts enrolled with the same name (e.g. cloned VM images or golden templates with a baked-in key).
- An agent restarted or changed IP frequently, so the manager treats it as a new connection.
- An agent was re-installed and re-enrolled while its old registration still exists.

## Prevention

- Give every agent a **unique hostname** (or set a unique `<agent_name>` explicitly).
- Never bake `client.keys` into machine images - enroll on first boot instead.
- Prefer stable naming over stable IPs; Wazuh identifies agents primarily by name, not by IP.

## Enable force re-enrollment on the manager

If agents legitimately change IPs or hit key mismatches, configure the manager to overwrite the existing (disconnected) registration when an agent with the same name re-enrolls.

**Step 1** - Open the manager configuration from the dashboard: **☰ → Server Management → Settings → Edit Configuration** (or edit `/var/ossec/etc/ossec.conf` directly).

**Step 2** - Add the following inside the `<auth>` section:

```xml
<auth>
  <force>
    <enabled>yes</enabled>
    <disconnected_time enabled="yes">0h</disconnected_time>
    <after_registration_time>0h</after_registration_time>
    <key_mismatch>yes</key_mismatch>
  </force>
</auth>
```

**Step 3** - Save and restart the manager:

```bash
systemctl restart wazuh-manager
```

> Note: `0h` replaces conflicting registrations immediately. In stricter environments, raise `disconnected_time` (e.g. `1h`) so an actively connected agent can never be displaced by an impostor with the same name.

Reference: [`auth` force options](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/auth.html)

## Roaming devices: laptops and VPN clients

Wazuh determines the agent name from the agent's `ossec.conf`: if `<agent_name>` is set it is used, otherwise the device hostname. Changing IPs (office Wi-Fi, home network, VPN) is **not** a problem by itself - the manager keys off the name.

For laptop fleets:

- Let agents enroll with their hostname, and ensure hostnames are unique across the fleet; or set an explicit, unique `<agent_name>` per device via your deployment tooling.
- Combine with the force re-enrollment configuration above so that a device returning from a different network can always re-attach to its own registration.

References:

- [Agent name configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/client.html#agent-name)
- [`use_source_ip` option](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/auth.html#use-source-ip)

## Related guides

- [Disconnections](disconnections.md) - key conflicts and disconnections usually appear together; fix connectivity first
- [Flooding](flooding.md) - a key-mismatch loop can contribute to reconnection storms
