# Agent management via the Wazuh API

| File | Purpose |
|---|---|
| `wazuh_group_manager.py` | Interactive agent group management |
| `stale-agent-cleanup.yaml` | CronJob that removes agents left behind by replaced Kubernetes nodes. See [Stale agent cleanup](#stale-agent-cleanup-for-replaced-nodes) |

`wazuh_group_manager.py` is an interactive menu-driven script for managing
Wazuh agent groups through the REST API. It lets you:

- **Create new agent groups**
- **Delete existing agent groups** (individually or all at once, with
  confirmation)
- **Add agents to groups**
- **Remove agents from groups**

## Requirements

- Python 3 with the `requests` library
- Network access to the Wazuh API (port 55000/TCP by default)
- An API user with permissions on the `/groups` and `/agents/group` endpoints

## Usage

Configure the API endpoint and credentials via environment variables (defaults
shown):

```bash
export WAZUH_API_URL="https://<manager-ip>:55000"
export WAZUH_API_USER="wazuh-wui"
export WAZUH_API_PASSWORD="<password>"

./wazuh_group_manager.py
```

The script authenticates once (JWT), then presents a menu. Select the number
of the action you want and follow the prompts. Group names are validated
against the Wazuh naming rules (alphanumeric plus `_-.`; max 128 characters).

Operations are logged to `/tmp/wazuh_group_manager.log`.

Note: TLS verification is disabled (`verify=False`) to work with the default
self-signed certificates. If your API uses a trusted certificate, consider
enabling verification.

## Stale agent cleanup for replaced nodes

`stale-agent-cleanup.yaml` is a Kubernetes CronJob that deletes agents of one
group once they have been `disconnected` or `never_connected` for longer than
`OLDER_THAN`. It exists for DaemonSet agents on autoscaled or replaced nodes:
every new node enrolls under a new name, and Wazuh 4.x has no setting that
removes the old entries. The `<auth><force>` options only replace an agent that
re-enrolls with the same name or IP.

The job is two `curl` calls, authenticate and then:

```text
DELETE /agents?agents_list=all&status=disconnected,never_connected&older_than=2d&group=k8s-nodes&purge=true
```

For `never_connected` agents, `older_than` compares the registration date
instead of the last keepalive.

### Least-privilege API user

Give the job its own API user whose only permission is `agent:delete` on the
group. Even a request without the `group` filter then deletes nothing outside
it. Run once with an administrator token:

```bash
API=https://<MANAGER_FQDN>:55000
TOKEN=$(curl -fsS -k -u '<ADMIN_USER>:<ADMIN_PASSWORD>' -X POST "$API/security/user/authenticate?raw=true")
AUTH=(-fsS -k -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json')

curl "${AUTH[@]}" -X POST "$API/security/policies" -d '{"name":"k8s_nodes_agent_cleanup",
  "policy":{"actions":["agent:delete"],"resources":["agent:group:k8s-nodes"],"effect":"allow"}}'
curl "${AUTH[@]}" -X POST "$API/security/roles" -d '{"name":"k8s_nodes_agent_cleanup"}'
curl "${AUTH[@]}" -X POST "$API/security/users" -d '{"username":"agent-cleanup","password":"<PASSWORD>"}'

# Use the IDs the three calls returned:
curl "${AUTH[@]}" -X POST "$API/security/roles/<ROLE_ID>/policies?policy_ids=<POLICY_ID>"
curl "${AUTH[@]}" -X POST "$API/security/users/<USER_ID>/roles?role_ids=<ROLE_ID>"
```

API passwords need 8 to 64 characters with upper and lower case, a digit and a
symbol.

### TLS to the API

The certificate the manager generates for the API is self-signed for
`CN=wazuh.com` with `DNS:localhost` as its only SAN, so `--cacert` fails against
a Service name or FQDN. Either replace it with a certificate your CA signs for
the name the job uses (see [certificates/](../../certificates/)), or pin its
public key and set `CURL_TLS` to `-k --pinnedpubkey sha256//<HASH>`:

```bash
echo | openssl s_client -connect <MANAGER_FQDN>:55000 2>/dev/null | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
```

With a pin, curl refuses any other key even though `-k` skips name checks. The
pin changes if the API certificate is regenerated, for example on a manager pod
without persistent `/var/ossec/api/configuration`.

### Choosing `OLDER_THAN`

Pick a value longer than the longest planned node outage. A node that comes
back after its entry was removed enrolls again as a new agent, provided the
enrollment password is still mounted.

## Related

- [Containerized agent - custom image](../../containerization/kubernetes/agent-daemonset.md) - where the stale entries come from
- API reference: [Wazuh API - Groups](https://documentation.wazuh.com/current/user-manual/api/reference.html)
- [Grouping agents](https://documentation.wazuh.com/current/user-manual/agent/agent-management/grouping-agents.html)
- [`../../scripts/agent-email-summary`](../agent-email-summary) - reports
  agent status via the same API.
