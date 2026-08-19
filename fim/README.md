# File Integrity Monitoring

File Integrity Monitoring answers two questions: what changed on disk, and who changed it. The answer depends far more on the scale and the platform than on the Wazuh configuration. Start by choosing the approach, not by writing a `<syscheck>` block.

## Table of Contents

- [Guides](#guides)
- [Choosing an approach](#choosing-an-approach)
- [Costs to plan for](#costs-to-plan-for)
- [Related](#related)

## Guides

| Guide | Description |
|---|---|
| [FIM on a large Windows file server](windows-file-servers.md) | `syscheck` with whodata, the scale at which its inventory stalls, and the move to native Windows object access auditing: audit policy, SACLs, event 4663, access masks, and the dashboard |
| [FIM in containerized environments](containers.md) | What FIM can and cannot do per agent deployment model, volumes against bind mounts, and centralized syscheck configuration |

## Choosing an approach

| Scope | Approach |
|---|---|
| A defined set of files, such as configuration, binaries, or web roots | `syscheck`, with `whodata` where user attribution matters |
| A Windows share above roughly 1 million files | Native Windows object access auditing. See [Windows file servers](windows-file-servers.md#approach-2-windows-object-access-auditing) |
| Files inside a container | Usually not FIM. See [containers](containers.md) |
| The Windows registry | [Registry monitoring](../troubleshooting/agents/windows-registry.md) |

The number that decides it is the count of files **in scope after exclusions**, not the size of the volume. `syscheck` builds and maintains its own inventory of every monitored file, so its cost scales with file count. Native auditing keeps no inventory, so it does not.

## Costs to plan for

Three settings cost far more than the rest. Decide each one deliberately:

- **`whodata`** adds the user and process behind each change. It depends on the Windows audit subsystem or the Linux audit daemon, so it needs an audit policy in place before it reports anything.
- **`report_changes`** copies every monitored file into a private directory to compute content differences. Use it on small text and configuration files only. On a large share it fills the disk.
- **The baseline scan** hashes every file in scope. It is the heaviest moment of any deployment, and exclusions do not avoid it, because the agent still walks the tree.

Roll out in phases, lowest-volume directory first. Before you add the next directory, watch agent CPU and RAM, the agent `ossec.log` for queue-full warnings, and event volume against indexer capacity.

## Related

- [Agent flooding and noisy alerts](../troubleshooting/agents/flooding.md) - reducing event volume after a rollout
- [Analysisd, EPS, and dropped events](../troubleshooting/server/analysisd.md) - when the manager cannot absorb the volume
- [Custom rules](../rules/README.md) - frequency-based rules for mass modification and deletion
- [Syscheck email notifications](../scripts/syscheck-email-notifications/) - alerting on FIM events by email
- [Official FIM documentation](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity-monitoring/index.html)
