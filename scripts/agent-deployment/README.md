# Automated mass deployment of Wazuh agents

Battle-tested approaches for rolling out 100+ Wazuh agents automatically and
managing them centrally. This is a guidance document; the tools referenced are
the official ones.

## Deployment methods by platform

**Windows endpoints**

- **Active Directory GPO (MSI + MST transform):** add MSI properties
  (manager, group, etc.) via an MST and push by GPO.
  [Official guide](https://wazuh.com/blog/deploying-wazuh-agent-using-windows-gpo/)
  - see [GPO deployment walkthrough](#gpo-deployment-walkthrough) below.
- **PDQ Deploy:** [official guide](https://wazuh.com/blog/deploying-wazuh-agents-to-windows-endpoints-with-pdq-deploy/)
- **ManageEngine Endpoint Central:** [official guide](https://wazuh.com/blog/deploying-wazuh-agents-using-manageengine/)
- **Intune / SCCM:** these are plain MSI deployments using the same MSI
  properties as the GPO method.

**Linux/macOS endpoints**

- **Ansible (official roles):** first-party playbooks/roles to install and
  enroll agents at scale, with variables for manager(s), enrollment, and
  groups. [Documentation](https://documentation.wazuh.com/current/deployment-options/deploying-with-ansible/guide/install-wazuh-agent.html)
- **Puppet (official module):** [documentation](https://documentation.wazuh.com/current/deployment-options/index.html)

## Deployment variables (hands-off installs)

Everything the agent needs can be passed at install time: manager address,
enrollment password, group, agent name, protocol/port.

Linux (one-liner per package manager, see the
[full variable list](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/deployment-variables/deployment-variables-linux.html)):

```bash
WAZUH_MANAGER="10.0.0.2" \
WAZUH_REGISTRATION_PASSWORD="<enrollment-password>" \
WAZUH_AGENT_GROUP="my-group" \
apt-get install wazuh-agent   # or yum/dnf/zypper
```

Windows (quiet MSI install; agent name, group, and registration password are
also available as [MSI properties](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html)):

```powershell
.\wazuh-agent-<version>.msi /q WAZUH_MANAGER="10.0.0.2"
```

## GPO deployment walkthrough

The condensed version of the
[official guide](https://wazuh.com/blog/deploying-wazuh-agent-using-windows-gpo/)
plus the gotchas that come up in practice.

### 1. Prepare the manager for password enrollment

```bash
# /var/ossec/etc/ossec.conf, inside <auth>:  <use_password>yes</use_password>
echo "<enrollment-password>" > /var/ossec/etc/authd.pass
chmod 640 /var/ossec/etc/authd.pass
chown root:wazuh /var/ossec/etc/authd.pass
systemctl restart wazuh-manager
```

### 2. Build the MST transform with Orca

Orca ships in the Windows SDK ("Windows SDK Components for Windows Installer
Developers"); the installer `Orca-x86_en-us.msi` lands under
`C:\Program Files (x86)\Windows Kits\10\bin\<sdk-version>\x86`. With Orca:

1. Open the Wazuh agent MSI, go to the Property table.
2. **Transform > New Transform**, then add rows for the
   [Windows deployment variables](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/deployment-variables/deployment-variables-windows.html):
   - `ADDRESS` = manager IP/FQDN
   - `AUTHD_SERVER` = manager IP/FQDN
   - `PROTOCOL` = `TCP`
   - `PASSWORD` = the enrollment password from step 1
3. **Transform > Generate Transform**, save as `custom.mst`.

Managed-cloud environments: `ADDRESS`/`AUTHD_SERVER` is the tenant URL (e.g.
`<tenant-id>.cloud.wazuh.com`), and password enrollment is typically already
enforced: grab `WAZUH_REGISTRATION_PASSWORD` from the dashboard's
Deploy new agent form (step 4 of the generated command).

### 3. Share the installer

Put the MSI + `custom.mst` in a network share readable by the machines, not
just the admins: grant Domain Computers (or Authenticated Users)
Read/Execute on both the share and NTFS ACLs. A common failure mode is a GPO
error along the lines of "cannot read from the domain controller file": the
computer account cannot read the UNC path. Re-check share/NTFS permissions
and that the UNC path (`\\server\share\wazuh-agent-<version>.msi`) resolves
from a workstation (`Win+R` > path).

### 4. Two GPOs: install, then activate

**Install GPO:** Computer Configuration > Policies > Software Settings >
Software installation > New > Package. Point at the UNC path of the MSI,
choose Advanced deployment (not Assigned): the Modifications tab,
where you attach `custom.mst`, is only available at package-creation time.

**Activate GPO** (starts the service fleet-wide): Computer Configuration >
Preferences > Control Panel Settings > Services > New > Service, with
Service name `WazuhSvc`, Startup `Automatic`, Service action `Start service`,
and all three Recovery options set to `Restart the Service`.

Apply on endpoints with `gpupdate /force` (or `echo N | gpupdate /force` for
non-interactive use). Software-installation policies only take effect after
a reboot/logon: the warning "changes must be processed before system
startup or user logon" is expected, not an error. If the install still fails
after a reboot, re-verify share permissions before anything else.

### Targeting without reorganizing AD

You do not need a dedicated "Wazuh" OU, and computers cannot live in more
than one OU anyway:

- Link the *same* GPO to each existing OU that contains target machines
  (right-click OU > Link an Existing GPO).
- Use security filtering on the GPO to scope it to a computer group when
  you do not want every machine in the linked OUs.
- **WMI filters** can target by OS version/hostname if group membership is
  not practical.

### Alternative: GPO startup script (no Orca)

A startup PowerShell script is the recommended path when you want to pass
MSI properties directly and add logic (skip if already installed, random
delay):

```powershell
Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum 60)  # spread enrollment
msiexec.exe /i "\\<server>\<share>\wazuh-agent-<version>.msi" /qn `
  WAZUH_MANAGER="<manager-ip-or-fqdn>" `
  WAZUH_REGISTRATION_SERVER="<manager-ip-or-fqdn>" `
  WAZUH_REGISTRATION_PASSWORD="<enrollment-password>" `
  WAZUH_AGENT_GROUP="<group-name>" `
  /L*v "C:\Windows\Temp\wazuh-agent-install.log"
Start-Service WazuhSvc
```

Notes from the field:

- The agent name defaults to the endpoint hostname when not set, usually
  what you want for GPO fleets.
- Any `WAZUH_AGENT_GROUP` must exist on the manager before enrollment or
  registration errors out / falls back to `default`.
- The enrollment password ends up readable in SYSVOL with this method;
  restrict the share, rotate the password after rollout, and/or limit
  1515/TCP to internal ranges.
- A few dozen simultaneous enrollments is negligible load for a manager; no
  batching needed at that scale (the random sleep is belt-and-braces).

### Validate the rollout

- Manager CLI: `/var/ossec/bin/agent_control -l` (agents show `Active`).
- Dashboard **Agents** tab.
- On an endpoint: `C:\Program Files (x86)\ossec-agent\ossec.log` should show
  "Connected to the server".

## Enrollment and security

- **Password-based enrollment** (simple and scalable): set an enrollment
  password on the manager (`/var/ossec/etc/authd.pass`) and pass it at
  install time. Works across GPO/PDQ/Ansible.
  [Documentation](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/security-options/using-password-authentication.html)
- **API-based enrollment** (tighter control): pre-request an agent key via the
  Wazuh API and import it on the endpoint. Useful for locked-down flows or
  offline bootstraps.
  [Documentation](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/enrollment-methods/via-manager-API/index.html)
- **Open the right ports:** 1514/TCP (agent-manager), 1515/TCP (enrollment),
  55000/TCP (Wazuh API).

## Grouping and centralized configuration

Put agents into groups (e.g. `servers`, `workstations`, `linux`, `windows`)
and manage policy centrally with per-group `agent.conf` instead of per-host
edits. Groups can be created and agents assigned programmatically via the
Wazuh API (`POST /groups`, `PUT /agents/group`): see
[`../agent-management`](../agent-management) for a ready-made script.
**Tip:** groups must exist before assignment.

- [Grouping agents](https://documentation.wazuh.com/current/user-manual/agent/agent-management/grouping-agents.html)
- [Centralized configuration (agent.conf)](https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html)

## Ongoing fleet care

Upgrade agents centrally via the manager/Wazuh API using signed WPK packages,
avoiding per-endpoint work:
[Remote upgrading](https://documentation.wazuh.com/current/user-manual/agent/agent-management/remote-upgrading/index.html)

## A simple, repeatable plan for 100+ agents

1. **Decide the enrollment method** (password is easiest) and set
   `/var/ossec/etc/authd.pass` on the manager(s).
2. **Pre-create groups** that map to your policies (OS, environment,
   criticality).
3. **Windows:** roll out the MSI by GPO/PDQ/Intune, passing `WAZUH_MANAGER`
   and (optionally) group/password properties via MST or command line.
4. **Linux/macOS:** run the Ansible `wazuh-agent` role (or your config
   manager of choice), setting managers, enrollment options, and default
   group.
5. **Centralize policy** with `agent.conf` per group rather than per-host
   edits.
6. **Keep doors open:** ensure 1514/1515/55000 are reachable.
7. **Maintain:** use remote upgrades to keep versions aligned.

## Related

- [`../agent-management`](../agent-management) - group management script.
- [`../../ansible`](../../ansible) - Ansible playbooks in this repo.
