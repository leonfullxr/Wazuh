# GitHub Enterprise Audit Logs (GHE.com and Enterprise-Level)

The built-in Wazuh GitHub module only reads organization audit logs from
`api.github.com`. It cannot collect from GitHub Enterprise Cloud with data
residency (GHE.com, API at `api.<subdomain>.ghe.com`), and it cannot read the
enterprise-level audit log at all. This guide covers the supported workaround:
a small collector on a host running a Wazuh agent that pulls the audit log and
hands each event to the agent in the same shape the native module uses, so
the stock GitHub ruleset applies unchanged.

> Applies to Wazuh 4.x up to at least 4.14, self-hosted or Wazuh Cloud (the
> collector runs on an agent, so the manager side needs no changes). Verified
> pattern in production on a GHE.com enterprise with Enterprise Managed Users.

## Table of Contents

- [Why the native module cannot do it](#why-the-native-module-cannot-do-it)
- [How the workaround works](#how-the-workaround-works)
- [Prerequisites](#prerequisites)
- [Deploy the collector](#deploy-the-collector)
- [Verify](#verify)
- [Troubleshooting](#troubleshooting)
- [Design notes](#design-notes)
- [Related](#related)

## Why the native module cannot do it

Reading `src/wazuh_modules/wm_github.h` (v4.14.x and main) shows three hard
limits:

| Limit | Effect |
|---|---|
| API host is a compile-time constant (`api.github.com`) | No `<api_url>` option, so GHE.com tenants are unreachable |
| Only `/orgs/{org}/audit-log` is queried | The enterprise endpoint `/enterprises/{enterprise}/audit-log` is never used, even on github.com |
| main branch rejects pagination links to any other host (`wm_url_is_allowed`) | Patching the host alone would still break on page 2 |

There is no configuration change that works around this. Treat a request for
GHE.com or enterprise-level collection as a feature request and use the
collector below in the meantime.

## How the workaround works

Rule 91100, the parent of the whole GitHub ruleset, matches any JSON event
with `integration` equal to `github`, regardless of how it arrived. Children
key on `github.action` (`org.*`, `repo.*`, `git.*`, `protected_branch.*`, ...),
and rule 91449 catches unknown actions. Wrapping the raw audit event as
`{"integration":"github","github":{<event>}}` is therefore enough for every
stock rule to fire, and custom rules can be layered on top with
`<if_sid>91100</if_sid>` or a specific child.

Two delivery options produce the same alerts:

| Option | How | Trade-off |
|---|---|---|
| Queue socket (used here) | Write `1:github:<json>` to `/var/ossec/queue/sockets/queue` | Events get `location: github` like the native module; no file to rotate |
| NDJSON file | Append one wrapped object per line, read with `<localfile>` + `<log_format>json</log_format>` | Easiest to inspect; you must rotate the file |

## Prerequisites

- A Linux host with a running Wazuh agent and Python 3.6+.
- Outbound HTTPS from that host to the API host
  (`api.<subdomain>.ghe.com` or `api.github.com`).
- A classic personal access token with scope `read:audit_log`, created by an
  enterprise owner (for the enterprise endpoint) or an org owner (for an org).
  With Enterprise Managed Users the token must belong to a managed owner
  account (or the setup user).
- The enterprise slug (from `https://<subdomain>.ghe.com/enterprises/<slug>`)
  or the organization name.

Audit events contain user names, IPs, token hashes, and repository names.
Restrict who can read the alerts.

## Deploy the collector

1. Install the script and the token (root-only, it is a credential):

   ```bash
   sudo install -d -o root -g root -m 700 /var/ossec/wodles/github-audit
   sudo install -o root -g root -m 700 github_audit_wodle.py \
     /var/ossec/wodles/github-audit/github_audit_wodle.py
   sudo sh -c 'umask 077; cat > /var/ossec/wodles/github-audit/token'   # paste token, Ctrl-D
   ```

2. Set `api_url` and exactly one of `enterprise` / `org` in the `CONFIG`
   block at the top of the script (every key is also a command-line option).

3. Test without sending anything to Wazuh. This prints the events it would
   send and uses a throwaway state file:

   ```bash
   sudo python3 /var/ossec/wodles/github-audit/github_audit_wodle.py \
     --dry-run --initial-lookback 60 --log-stderr --state-file /tmp/gh-test.json
   ```

4. Schedule it from the agent `ossec.conf` (or a centralized agent group):

   ```xml
   <wodle name="command">
     <disabled>no</disabled>
     <tag>github-audit</tag>
     <command>/usr/bin/python3 /var/ossec/wodles/github-audit/github_audit_wodle.py</command>
     <interval>5m</interval>
     <run_on_start>yes</run_on_start>
     <timeout>300</timeout>
     <ignore_output>yes</ignore_output>
   </wodle>
   ```

   Keep `max_runtime` (default 240 s) below the wodle `<timeout>`. A centrally
   pushed command wodle also needs `wazuh_command.remote_commands=1` in the
   agent `local_internal_options.conf`.

5. Restart the agent: `systemctl restart wazuh-agent`.

The first scheduled run only sets a bookmark (`initial_lookback` is 0), so
nothing is backfilled unless you ask for it.

## Verify

```bash
tail -f /var/ossec/logs/github_audit_wodle.log
# ... collecting 2026-10-07T10:00:00Z..2026-10-07T10:04:00Z
# ... done: 12 new events sent, 3 duplicates skipped, 1 page(s), bookmark ...
```

In the dashboard, filter `rule.groups: github` or `location: github`. Each
alert carries the original audit fields under `data.github.*`.

The script's own logic can be checked offline (fake API on localhost):

```bash
python3 github_audit_wodle.py --selftest
```

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `HTTP 404` on the enterprise endpoint | Wrong slug, or the token owner is not an enterprise owner | Check the slug in the enterprise URL; recreate the token as an owner |
| `HTTP 401` / `HTTP 403` without rate-limit headers | Token expired, missing `read:audit_log`, or a fine-grained PAT | Use a classic PAT with `read:audit_log`; with EMU, a managed owner account |
| `HTTP 404` against `api.github.com` for a GHE.com tenant | Data-residency tenants are only served from their own API host | Set `api_url` to `https://api.<subdomain>.ghe.com` |
| `cannot connect to Wazuh queue` | Agent stopped, or the script is not running as root | Start the agent; run from the wodle (runs as root) |
| `refusing pagination link to another host` | API returned a `Link` header for a different host | Check `api_url` matches the host GitHub actually serves |
| Rule 91448 "GitHub module internal event" | The collector failed 3 runs in a row (same alert as the native module) | Read `github_audit_wodle.log` for the error |
| Events present in the log but no alerts | Agent `client_buffer` dropping bursts | Lower `max_eps` or raise the agent `events_per_second` |
| `include=all` floods the manager | Git events (`git.clone`, `git.push`, ...) are very high volume | Use `include=web` unless Git events are needed; measure EPS first |

## Design notes

- Windowing: each run queries `phrase=created:<start>..<end>`, `order=asc`,
  `per_page=100`, and follows `Link: rel="next"` pages. The window ends
  `delay` (60 s) behind now to allow for audit log indexing lag, and starts
  `overlap` (600 s) before the previous bookmark so late-indexed events are
  not missed.
- De-duplication: overlap re-reads are filtered by `_document_id` kept in the
  state file and pruned past the overlap.
- Budgets: a run stops at `max_runtime` or `max_events` and saves the
  bookmark at the newest event sent; the next run continues from there.
- Rate limits: `Retry-After` and `X-RateLimit-Reset` are honored; a plain 403
  is treated as a permission error and not retried.
- Oversized events (over 60000 bytes, close to the 65535-byte message limit)
  are sent with an essential-field subset and `wazuh_truncated: true` rather
  than dropped.
- Audit log streaming (to S3, Azure Blob, Splunk, and others) is an
  alternative for very high volumes; it is not covered here.

## Related

- [Jira audit collection](../alerts/jira/README.md) - same pull, normalize, ingest pattern
- [Confluence audit collection](../alerts/confluence/README.md)
- [Custom rules](../../rules/README.md)
- [Wazuh GitHub module documentation](https://documentation.wazuh.com/current/cloud-security/github/index.html)
