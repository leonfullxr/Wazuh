# Automated mass deployment of Wazuh agents

Battle-tested approaches for rolling out 100+ Wazuh agents automatically and
managing them centrally. This is a guidance document; the tools referenced are
the official ones.

## Deployment methods by platform

**Windows endpoints**

- **Active Directory GPO (MSI + MST transform):** add MSI properties
  (manager, group, etc.) via an MST and push by GPO.
  [Official guide](https://wazuh.com/blog/deploying-wazuh-agent-using-windows-gpo/)
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

Linux (one-liner per package manager -
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
Wazuh API (`POST /groups`, `PUT /agents/group`) - see
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
