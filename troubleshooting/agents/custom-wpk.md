# WPK Certificates and Remote Upgrade Failures

Runbook for remote agent upgrades (WPK packages) that fail with certificate errors, and for `Send lock restart error` / `Send open file error` during the upgrade process.

## Table of Contents

- [Background](#background)
- [Install the renewed WPK root CA on agents](#install-the-renewed-wpk-root-ca-on-agents)
  - [Linux](#linux)
  - [macOS](#macos)
  - [Windows](#windows)
  - [Keep the old CA alongside the new one](#keep-the-old-ca-alongside-the-new-one)
- [Send lock restart / Send open file errors](#send-lock-restart--send-open-file-errors)
- [Related guides](#related-guides)

## Background

Remote upgrades deliver a signed WPK package to the agent, which verifies the signature against a root CA stored locally (`wpk_root.pem`, referenced by `<ca_store>` in the agent's `ossec.conf`). Older agents (<= 4.3.7) shipped a root CA that has since been rotated; those agents reject current WPK packages with certificate verification errors until the new CA is installed.

The CA cannot be pushed centrally from the dashboard - it must be placed on each agent, so use your systems-management tooling (GPO, Ansible, Intune, etc.) to run the commands below at scale.

The current `wpk_root.pem` is published in the Wazuh repository: <https://github.com/wazuh/wazuh/blob/master/etc/wpk_root.pem>. See the [custom WPK documentation](https://documentation.wazuh.com/current/user-manual/agent/agent-management/remote-upgrading/custom-wpk-packages.html) when building WPKs signed by your own CA.

## Install the renewed WPK root CA on agents

The pattern is the same on every OS: download the new CA under a **new file name**, point `<ca_store>` at it, and restart the agent.

### Linux

```bash
curl -o /var/ossec/etc/wpk_root_new.pem https://raw.githubusercontent.com/wazuh/wazuh/master/etc/wpk_root.pem
sed -i 's| <ca_store>etc/wpk_root.pem| <ca_store>etc/wpk_root_new.pem|1' /var/ossec/etc/ossec.conf
chown $(ls -l /var/ossec/etc/wpk_root.pem | awk '{print $3":"$4}') /var/ossec/etc/wpk_root_new.pem
systemctl restart wazuh-agent
```

### macOS

```bash
curl -o /Library/Ossec/etc/wpk_root_new.pem https://raw.githubusercontent.com/wazuh/wazuh/master/etc/wpk_root.pem
sed -i -- 's| <ca_store>etc/wpk_root.pem| <ca_store>etc/wpk_root_new.pem|1' /Library/Ossec/etc/ossec.conf
/Library/Ossec/bin/wazuh-control restart
```

### Windows

```powershell
Move-Item "${env:ProgramFiles(x86)}\ossec-agent\wpk_root.pem" "${env:ProgramFiles(x86)}\ossec-agent\wpk_root.pem.old"
Invoke-WebRequest -Uri https://raw.githubusercontent.com/wazuh/wazuh/master/etc/wpk_root.pem -OutFile "${env:ProgramFiles(x86)}\ossec-agent\wpk_root.pem"
Restart-Service WazuhSvc
```

### Keep the old CA alongside the new one

`<ca_store>` can be declared multiple times, so during a fleet-wide rollout you can trust both CAs simultaneously:

```xml
<ossec_config>
  <active-response>
    <disabled>no</disabled>
    <ca_store>etc/wpk_root.pem</ca_store>
    <ca_store>etc/wpk_root_new.pem</ca_store>
    <ca_verification>yes</ca_verification>
  </active-response>
</ossec_config>
```

Restart the agent afterwards (`systemctl restart wazuh-agent` on Linux, `net stop wazuh && net start wazuh` on Windows). Once the valid CA is in place, upgrade agents remotely as described in the [agent upgrade guide](https://documentation.wazuh.com/current/upgrade-guide/wazuh-agent/index.html).

If agents are already above 4.3.7 and still fail, collect the agent's `ossec.log` and version before assuming a CA problem:

- Linux: `/var/ossec/logs/ossec.log`
- Windows: `C:\Program Files (x86)\ossec-agent\ossec.log`

## Send lock restart / Send open file errors

`Send lock restart error` and `Send open file error` mean the agent never acknowledged the *lock restart* or *open file* commands the manager sends as part of the upgrade sequence, so the upgrade is cancelled. This is characteristic of **network congestion** - packet loss or connection resets between agent and manager - not of a corrupt package.

Recovery procedure:

1. As a diagnostic workaround, disable CA verification on the affected agent (`ossec.conf`), then restart the agent:

   ```xml
   <agent-upgrade>
     <ca_verification>
       <enabled>no</enabled>
     </ca_verification>
   </agent-upgrade>
   ```

   > Re-enable verification after testing - leaving it off removes package-authenticity checks.

2. Confirm agent <-> manager connectivity is stable (see [disconnections.md](disconnections.md)).
3. Retry the upgrade **one agent at a time**, pinning the target version. From the manager:

   ```bash
   /var/ossec/bin/agent_upgrade -v v4.7.4 -a <AGENT_ID>
   ```

   Expected output:

   ```
   Upgrading...
   Upgraded agents:
        Agent <AGENT_ID> upgraded: Wazuh v4.7.1 -> v4.7.4
   ```

## Related guides

- [disconnections.md](disconnections.md) - verify stable connectivity before retrying upgrades
- [Upgrading agents](../../upgrading/upgrading-agents.md) - general centralized upgrade procedures
- [WPK upgrade CA](../../certificates/component-certificates.md#wpk-upgrade-ca-on-agents) - rotate and distribute the trusted package-signing CA
