# HTML agent status email summary

`agent_status_report.sh` queries the Wazuh API for agents in `disconnected`,
`pending`, or `never_connected` state and sends an HTML-formatted email report
with a color-coded table (agent name, IP, registration date, last keepalive,
status).

## Requirements

- `curl` and `jq`
- A working `sendmail` on the host (typically provided by Postfix)
- A Wazuh API user with read access to the `/agents` endpoint

## Configuration

Set these variables at the top of the script or export them in the
environment:

| Variable | Purpose | Default |
|---|---|---|
| `WAZUH_BASE_URL` | Wazuh API endpoint | `https://<MANAGER_IP>:55000` |
| `WAZUH_API_USER` / `WAZUH_API_PASSWORD` | API credentials | `wazuh-wui` |
| `FROM_EMAIL` / `TO_EMAIL` | Sender and recipient addresses | example.com placeholders |

## Usage

```bash
chmod +x agent_status_report.sh
./agent_status_report.sh
```

Schedule a daily report via cron:

```
0 8 * * * /path/to/agent_status_report.sh >/dev/null 2>&1
```

## How it works

1. Authenticates against `POST /security/user/authenticate` to obtain a JWT.
2. Calls `GET /agents?status=disconnected,pending,never_connected` selecting
   `ip,id,name,dateAdd,lastKeepAlive,status`.
3. Builds an inline-styled HTML table, converting UTC timestamps to local
   time; each row is color-coded by status.
4. Pipes the message to `sendmail -t`.

## Related

- [`../agent-management`](../agent-management) - group management via the same
  API.
- [`../service-monitoring`](../service-monitoring) - email alerts when Wazuh
  services go down.
