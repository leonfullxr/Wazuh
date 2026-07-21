# Enrollment and Key Conflicts

Runbook for `agent key already in use` / duplicate-name warnings during enrollment, and for fleets of roaming devices (laptops, VPN clients) whose IP addresses change constantly.

## Table of Contents

- [Why it happens](#why-it-happens)
- [Decoding authd enrollment rejections](#decoding-authd-enrollment-rejections)
- [Prevention](#prevention)
- [Enable force re-enrollment on the manager](#enable-force-re-enrollment-on-the-manager)
- [Enrollment loops and the duplicate-name storm](#enrollment-loops-and-the-duplicate-name-storm)
- [Roaming devices: laptops and VPN clients](#roaming-devices-laptops-and-vpn-clients)
- [Related guides](#related-guides)

## Why it happens

The manager logs this warning when more than one agent tries to connect using the same agent ID, or when an agent presents a key that no longer matches the one stored on the manager. Typical triggers:

- Two hosts enrolled with the same name (e.g. cloned VM images or golden templates with a baked-in key).
- An agent restarted or changed IP frequently, so the manager treats it as a new connection.
- An agent was re-installed and re-enrolled while its old registration still exists.

## Decoding authd enrollment rejections

When enrollment fails, `wazuh-authd` logs a specific reason. The three "duplicate name" variants are **not** the same problem - each is governed by a different `<auth><force>` setting:

| Manager log (`wazuh-authd`) | What it means | Governed by | Fix |
|---|---|---|---|
| `Duplicate name '<name>', rejecting enrollment. Agent '<id>' doesn't comply with the registration time to be removed.` | An agent with that name exists and was registered **too recently** to be auto-replaced. | `<force><after_registration_time>` | Lower `after_registration_time`, or stop the agent re-enrolling ([enrollment loops](#enrollment-loops-and-the-duplicate-name-storm)). |
| `Duplicate name '<name>' ... can't be replaced since it is not disconnected` | An agent with that name is **still connected**, so authd will not displace it. | `<force><disconnected_time>` (+ `<enabled>`) | Confirm it is genuinely the same host; if the record is stale, wait `disconnected_time` or delete the agent. |
| `Duplicate name '<name>', rejecting enrollment` (no further clause) | The name is taken and **force-replace is disabled**. | `<force><enabled>` | Enable `<force>` ([below](#enable-force-re-enrollment-on-the-manager)), or give the host a unique name. |
| `Invalid password provided by <ip>. Closing connection.` | The enrollment password/token is wrong or missing. | `<use_password>` + `authd.pass` | Fix `/var/ossec/etc/authd.pass` (or your deployment's enrollment secret) on the agent. |
| `Too many connections. Rejecting.` | `authd` hit its concurrent-connection limit - almost always an enrollment storm. | - | Stop the retry loop at the source ([enrollment loops](#enrollment-loops-and-the-duplicate-name-storm)). |

The first three are all controlled by the [force re-enrollment settings](#enable-force-re-enrollment-on-the-manager) - the defaults deliberately stop a new host from silently stealing an active agent's identity, so a rejection is often correct behaviour reacting to a *client* that should not be re-enrolling at all.

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

## Enrollment loops and the duplicate-name storm

A flood of duplicate-name rejections for names that **are** already registered (often still active) usually is not many hosts fighting over a name - it is a **few agents stuck retrying enrollment**, each retry re-hitting `authd`. Two symptoms confirm it:

- The same name reappears every ~1-2 minutes, seemingly from different source IPs (those are usually infrastructure hops, not real agents - see [reading source IPs](#reading-source-ips-in-enrollment-logs)).
- The agent side loops on this sequence, with a consistent **~60-second gap** before the error:

    ```
    wazuh-agentd: INFO: Requesting a key from server: <MANAGER>
    wazuh-agentd: INFO: Using agent name as: <AGENT_NAME>
    wazuh-agentd: INFO: Waiting for server reply
    wazuh-agentd: ERROR: SSL read (unable to receive message)
    wazuh-agentd: ERROR: If Agent verification is enabled, agent key and certificates may be incorrect!
    ```

That ~60-second wait is the tell. It is a **read timeout waiting for the server's reply**, not a certificate/key mismatch (which fails within a second). `authd` may even log `Agent key generated` successfully - but if that reply never reaches the agent, the agent gives up and re-requests a key, producing the storm. The problem is the **manager → agent return path**, not the agent's credentials.

Work through the return path, cheapest first:

1. **Wrong endpoint / split-DNS.** The agent resolves the manager name to an internal or corporate IP instead of the real manager. Confirm the configured address and what it resolves to *from the affected host*:

    ```bash
    grep -A2 "<server>" /var/ossec/etc/ossec.conf   # confirm <address>
    nslookup <MANAGER_ADDRESS>
    echo | openssl s_client -connect <MANAGER_ADDRESS>:1515 2>/dev/null | openssl x509 -noout -subject -dates
    ```

2. **A security control holding or dropping the TLS reply** - firewall, proxy, **SSL/TLS inspection (e.g. Zscaler)**, IDS/IPS, asymmetric routing, or an idle timeout that fires before the reply. The decisive test is to **enroll from a known-good network**: if enrollment succeeds from another segment but times out from the affected host, the path is the cause, not Wazuh. Probe and time the 1515 handshake from both locations with the [TLS test on 1515](../../certificates/troubleshooting.md#agent-connectivity-on-15141515). Disabling one inspection product does not clear established sessions - retest on a fresh connection.

3. **A path-MTU black hole** produces the same stall (small packets pass, the larger TLS reply is silently dropped) - see [MTU / path-MTU black hole](disconnections.md#agent-connects-but-forwards-no-logs-mtu--path-mtu-black-hole).

4. **A very old agent against a modern manager** (e.g. a 4.2.x agent) can fail the enrollment TLS exchange - align the agent's major version with the manager before deeper network analysis.

While you fix the path, damp the storm: enable [`<key_mismatch>`](#enable-force-re-enrollment-on-the-manager) so already-registered agents stop renewing keys unnecessarily, and make the agent prefer reconnection over re-registration (`force_reconnect_interval` / `time-reconnect`, see [disconnections](disconnections.md#agents-stuck-in-a-re-registration-loop)).

### Reading source IPs in enrollment logs

The `from: <ip>` that `authd` logs is the **last hop that delivered the request**, not necessarily the agent. Behind a load balancer, NAT, reverse proxy, or a Kubernetes service, that address is the balancer's or the cluster node's internal IP - so a single agent legitimately appears to enroll "from" many different internal addresses (e.g. many `10.x.x.x`), and the agent's real public IP cannot be recovered from the manager log at all. Do not chase those IPs as if they were distinct rogue agents; correlate by **agent name** plus agent-side logs and packet captures instead.

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
- [Certificate troubleshooting](../../certificates/troubleshooting.md#agent-connectivity-on-15141515) - the `unexpected eof while reading` (server-side) and `SSL read` (agent-side) handshake signatures on 1515
- [Flooding](flooding.md) - a key-mismatch loop can contribute to reconnection storms
