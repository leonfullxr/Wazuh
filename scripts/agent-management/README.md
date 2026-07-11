# Agent group management via the Wazuh API

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

## Related

- API reference: [Wazuh API - Groups](https://documentation.wazuh.com/current/user-manual/api/reference.html)
- [Grouping agents](https://documentation.wazuh.com/current/user-manual/agent/agent-management/grouping-agents.html)
- [`../../scripts/agent-email-summary`](../agent-email-summary) - reports
  agent status via the same API.
