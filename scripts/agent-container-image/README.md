# Wazuh agent container image

A minimal Wazuh agent image on a base you control, for when the official
[`wazuh/wazuh-agent`](https://hub.docker.com/r/wazuh/wazuh-agent) image is ruled
out (base-image policy, internal registry, extra tooling). The guide that uses it
is [Containerized agent - custom image](../../containerization/kubernetes/agent-daemonset.md).

| File | Purpose |
|---|---|
| `Dockerfile` | Debian 12 slim plus the `wazuh-agent` package from the signed Wazuh repository, pinned with `WAZUH_VERSION` |
| `entrypoint.sh` | Writes a connection-only `ossec.conf`, starts the agent, stops it cleanly on `SIGTERM` |

## Build

```bash
docker build --build-arg WAZUH_VERSION=4.14.9-1 -t <REGISTRY>/wazuh-agent:4.14.9 .
docker push <REGISTRY>/wazuh-agent:4.14.9
```

Keep the agent at or below the manager version.

## Runtime settings

| Variable | Default | Meaning |
|---|---|---|
| `WAZUH_MANAGER` | required | Address for events (1514), usually the worker Service or load balancer |
| `WAZUH_MANAGER_PORT` | `1514` | Events port |
| `WAZUH_REGISTRATION_SERVER` | `WAZUH_MANAGER` | Address for enrollment (1515), usually the master |
| `WAZUH_REGISTRATION_PORT` | `1515` | Enrollment port |
| `WAZUH_AGENT_NAME` | container hostname | Set it to the node name on a DaemonSet |
| `WAZUH_AGENT_GROUP` | none | Group(s) requested at enrollment, comma separated |
| `WAZUH_AUTHD_PASS_FILE` | `/run/secrets/wazuh/authd.pass` | Enrollment password, mounted from a Secret |

The rendered `ossec.conf` only connects and enrolls. Syscollector, SCA and
rootcheck are off because inside a container they describe the container, not
the host. Collection (`<localfile>`, `<syscheck>` directories) comes from the
group `agent.conf` on the manager, which can also turn those modules back on.

Deliberately left out: Java, OpenSCAP and CIS-CAT content, VirusTotal settings
(integrations run on the manager), and any Wazuh API credentials on the agent.
