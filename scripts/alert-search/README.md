# Search alerts by rule ID and time window

`search_alerts.py` scans the manager's `/var/ossec/logs/alerts/alerts.json`
for alerts matching a rule ID within a recent time window and prints each
match as a JSON block. Useful for quick triage on the manager without going
through the indexer, and for confirming what a retention/deletion query would
hit before running it (see [`../policy-deletion`](../policy-deletion)).

It deliberately stays simple, and uses the Python interpreter bundled with the
Wazuh manager (`/var/ossec/framework/python/bin/python3`) so it has no OS
Python dependency.

## Usage

1. Edit the constants at the top of the script:

   - `TARGET_RULE_ID` - the rule ID to search for (e.g. `"5501"`)
   - `LOOKBACK_SECONDS` - how far back from now to search
   - `LOG_FILE` - normally the default `alerts.json`

2. Run it on the manager:

   ```bash
   chmod +x search_alerts.py
   ./search_alerts.py
   ```

## Sample output

```
Searching /var/ossec/logs/alerts/alerts.json for rule.id '5501' within the last 60 seconds...
----------------------------------------
{"timestamp": "2025-03-31T11:32:25.842-0300", "rule": {"level": 3, "description": "PAM: Login session opened.", "id": "5501", ...}, "agent": {"id": "000", "name": "manager01"}, ...}
----------------------------------------
Search complete.
```

Timestamps are parsed with milliseconds and timezone offset (Wazuh's
`%Y-%m-%dT%H:%M:%S.%f%z` format, with a fallback for timestamps without
milliseconds) and compared in UTC.

## Related

- [`../policy-deletion`](../policy-deletion) - delete alerts by rule ID and
  time range once you have confirmed the matches.
