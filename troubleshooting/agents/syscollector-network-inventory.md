# Syscollector network inventory: `key 'name' not found`

Runbook for an agent whose syscollector scan stops with a JSON range exception and records no network interfaces.

> **Applies to:** Wazuh agent 4.x, observed on 4.14.x, on a Linux host that carries
> a virtual IP with a non-standard address label. The usual example is a
> keepalived-managed API or Ingress VIP on an OpenShift/OKD node. The trigger
> itself is not specific to Kubernetes.

## Table of Contents

- [The symptom](#the-symptom)
- [Step 1: Confirm the network section is the trigger](#step-1-confirm-the-network-section-is-the-trigger)
- [Step 2: Compare the interfaces with a correct host](#step-2-compare-the-interfaces-with-a-correct-host)
- [Root cause: an address label that is not an interface name](#root-cause-an-address-label-that-is-not-an-interface-name)
- [Fix: change the VIP label](#fix-change-the-vip-label)
- [Workaround: disable network inventory](#workaround-disable-network-inventory)
- [Why this is not the 4.4 tunnel-adapter bug](#why-this-is-not-the-44-tunnel-adapter-bug)
- [Related](#related)

## The symptom

Each syscollector cycle logs the same exception and records no interfaces:

```text
wazuh-modulesd:syscollector: INFO: Starting evaluation.
wazuh-modulesd:syscollector: ERROR: [json.exception.out_of_range.403] key 'name' not found
wazuh-modulesd:syscollector: INFO: Evaluation finished.
```

The agent collects the rest of the inventory correctly. Packages, OS, hardware, processes, and ports all appear. Only **Network interfaces** stays empty in the dashboard and in `GET /syscollector/<AGENT_ID>/netiface`.

The main characteristic is that the fault affects a subset of otherwise identical hosts. In the investigated case, 2 of 6 nodes failed. One node was a control plane and one node was a worker. All six nodes ran the same agent build, the same binary hashes, the same DaemonSet, and the same node hardware profile.

## Step 1: Confirm the network section is the trigger

Set `<network>no</network>` inside the syscollector wodle. Then restart the agent.

```xml
<wodle name="syscollector">
  <network>no</network>
</wodle>
```

If the error stops on the next scan, the fault is in network interface collection. Continue with the next step. If the error continues, this runbook does not apply.

## Step 2: Compare the interfaces with a correct host

Collect the full interface data from an affected host and from a correct host. Then compare the two results. Run these commands on the **host**, not inside the agent container. A minimal agent image usually has no `ip` binary.

```bash
ip -json addr show
ip -details link show
ls -l /sys/class/net
cat /proc/net/dev
```

Do not compare interface types or interface counts. The important difference is one address entry. Its `label` value is neither the parent interface name nor the conventional `<ifname>:<N>` alias form:

```json
{
  "family": "inet",
  "local": "192.0.2.10",
  "prefixlen": 32,
  "scope": "global",
  "label": "vip"
}
```

In this example, the label `vip` belongs to a secondary address on `br-ex`. On the correct nodes that address is absent, because a different node holds the VIP.

Find the owner of the address:

```bash
ip -o addr show br-ex
grep -A10 "virtual_ipaddress" /etc/keepalived/keepalived.conf
```

An OpenShift IPI installation uses keepalived to move the API and Ingress VIP between nodes. This explains the count, because only the nodes that currently hold a VIP fail. It also explains the intermittency, because the set of affected nodes changes after a failover.

## Root cause: an address label that is not an interface name

The agent enumerates interfaces through `getifaddrs()`. This function reports an IP-aliased address under the **address label**, not under the real name of the parent interface.

- The conventional label `br-ex:0` keeps the real interface name as its prefix. The lookup that follows therefore succeeds.
- An arbitrary label such as `vip` produces a pseudo-interface named `vip`. This name has no matching row in `/proc/net/dev` and no link-layer object behind it.

The network data provider reads per-interface statistics and the interface type from `/proc/net/dev` for every name that it enumerated. For the pseudo-interface, that lookup finds nothing. The interface object therefore keeps no `name` field, and the JSON serialization raises `out_of_range.403`. The exception stops the complete network section. This is why the agent reports no interfaces instead of all interfaces except one.

## Fix: change the VIP label

Give the virtual address a label that follows the `<ifname>:<N>` alias convention. The label then still resolves to a real interface.

```conf
vrrp_instance <NAME> {
    virtual_ipaddress {
        192.0.2.10/32 dev br-ex label br-ex:0
    }
}
```

1. Reload keepalived.
2. Confirm the new label with `ip -o addr show br-ex`. Expect `br-ex:0`, not a custom label.
3. Read the log after the next syscollector cycle with `grep -i syscollector /var/ossec/logs/ossec.log | tail -20`.

> This change modifies the VIP failover configuration. Test it in a staging cluster
> that uses the same keepalived setup before you change production. Confirm that the
> VIP still moves correctly during a failover.

## Workaround: disable network inventory

If you cannot change the VIP label, keep `<network>no</network>`. The cost is small and exact. You lose the network interface inventory, and nothing else. The agent still collects package and OS inventory, so [Vulnerability Detection](../server/vulnerability-detection.md) keeps full CVE coverage.

## Why this is not the 4.4 tunnel-adapter bug

The exception text is identical to a defect that Wazuh corrected in agent 4.4 ([wazuh/wazuh#11822](https://github.com/wazuh/wazuh/issues/11822)). Engineers therefore diagnose this condition as a regression. The two code paths are different:

| | 4.4 tunnel bug | This case |
|---|---|---|
| Trigger | `IFF_POINTOPOINT` interfaces (tun/tap) | An IP alias with a label that is not `ifname:N` |
| Mechanism | `getifaddrs()` returns `ifa_addr = NULL`, so `sa_family` is unreadable | `ifa_addr` and `sa_family` are valid throughout |
| Failure | Interface identification fails | A label-derived pseudo-interface has no `/proc/net/dev` counterpart |

The 4.4 fix moved interface identification to `getifaddrs()` and read the statistics from `/proc/net/dev`. This case breaks the assumption behind that fix. Not every name that `getifaddrs()` enumerates maps to a real `/proc/net/dev` entry. This signature on 4.14.x is therefore a different condition, not a return of the old defect. Look for POINTOPOINT interfaces before you decide otherwise:

```bash
ip -details link show | grep -i pointopoint
```

## Related

- [Vulnerability Detection](../server/vulnerability-detection.md) - what depends on the syscollector inventory, and what does not
- [Wazuh on Red Hat OpenShift / OKD](../../containerization/kubernetes/openshift.md) - how to deploy the agent and the manager components on OCP
- [Containerized agent - custom image](../../containerization/kubernetes/agent-daemonset.md) - the agent DaemonSet deployment model
- [Syscollector configuration reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-syscollector.html)
