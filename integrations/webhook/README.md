# Forwarding Wazuh Alerts to a Webhook

Use a custom Wazuh Integrator script to POST selected alerts to an HTTPS
webhook such as an incident-management platform, SOAR, or internal gateway.
The manager invokes the script once per matching alert and passes a temporary
JSON file, API key, and hook URL.

This direct pattern is appropriate for low-to-moderate alert volume and an
endpoint with predictable latency. For high volume or strict delivery
guarantees, put a durable queue or message broker between Wazuh and the
destination; a synchronous script can otherwise delay or lose deliveries
during prolonged outages.

## Prerequisites

- Wazuh manager shell access.
- An HTTPS endpoint and its CA chain trusted by the manager.
- A narrowly defined rule ID, group, or minimum level.
- The destination's authentication and payload requirements.

Do not put the webhook token in the script or log it. Wazuh passes `<api_key>`
as a process argument, so restrict access to the manager and its process/log
data.

## Procedure

1. Create `/var/ossec/integrations/custom-webhook`:

   ```python
   #!/var/ossec/framework/python/bin/python3
   import json
   import ssl
   import sys
   import urllib.error
   import urllib.request
   from urllib.parse import urlparse


   def fail(message: str) -> int:
       print(f"custom-webhook: {message}", file=sys.stderr)
       return 1


   def main() -> int:
       if len(sys.argv) < 4:
           return fail("expected alert file, API key, and hook URL")

       alert_path, api_key, hook_url = sys.argv[1:4]
       parsed_url = urlparse(hook_url)
       if parsed_url.scheme != "https" or not parsed_url.netloc:
           return fail("hook_url must be a valid HTTPS URL")

       try:
           with open(alert_path, encoding="utf-8") as alert_file:
               alert = json.load(alert_file)
       except (OSError, json.JSONDecodeError) as error:
           return fail(f"cannot read alert JSON: {error}")

       # Adapt this object if the destination requires a vendor-specific schema.
       payload = json.dumps({"event": alert}).encode("utf-8")
       headers = {
           "Content-Type": "application/json",
           "User-Agent": "wazuh-custom-webhook/1.0",
       }
       if api_key:
           headers["Authorization"] = f"Bearer {api_key}"

       request = urllib.request.Request(
           hook_url,
           data=payload,
           headers=headers,
           method="POST",
       )

       try:
           with urllib.request.urlopen(
               request,
               timeout=10,
               context=ssl.create_default_context(),
           ) as response:
               if 200 <= response.status < 300:
                   return 0
               return fail(f"unexpected HTTP status {response.status}")
       except urllib.error.HTTPError as error:
           return fail(f"destination returned HTTP {error.code}")
       except urllib.error.URLError as error:
           return fail(f"request failed: {error.reason}")


   if __name__ == "__main__":
       raise SystemExit(main())
   ```

2. Set ownership and permissions:

   ```bash
   sudo chown root:wazuh /var/ossec/integrations/custom-webhook
   sudo chmod 750 /var/ossec/integrations/custom-webhook
   ```

3. Register the integration inside `/var/ossec/etc/ossec.conf`. Filter it so
   only actionable alerts invoke the endpoint:

   ```xml
   <integration>
     <name>custom-webhook</name>
     <hook_url>https://hooks.example.com/wazuh</hook_url>
     <api_key>REPLACE_WITH_DESTINATION_TOKEN</api_key>
     <rule_id>100100,100101</rule_id>
     <alert_format>json</alert_format>
   </integration>
   ```

   Use one of `rule_id`, `group`, `event_location`, or `level` based on the
   destination. Avoid forwarding every alert by default.

4. Validate and restart:

   ```bash
   sudo /var/ossec/bin/wazuh-integratord -t
   sudo systemctl restart wazuh-manager
   sudo journalctl -u wazuh-manager --since "5 minutes ago" --no-pager
   ```

## Verification

Test the script independently before relying on a live rule:

```bash
sudo tail -n 1 /var/ossec/logs/alerts/alerts.json > /tmp/webhook-alert.json
read -rsp "Webhook token: " WEBHOOK_TOKEN; echo
sudo -u wazuh /var/ossec/integrations/custom-webhook \
  /tmp/webhook-alert.json \
  "$WEBHOOK_TOKEN" \
  "https://hooks.example.com/wazuh"
unset WEBHOOK_TOKEN
```

The command selects one valid alert object rather than the entire
newline-delimited alerts file. Then trigger one test rule and verify:

- The destination receives exactly one event.
- `rule.id`, `agent.id`, `agent.name`, `timestamp`, and `full_log` have the
  expected shape.
- The manager logs contain no timeout, TLS, or HTTP errors.
- The script never prints the token or full webhook URL.

## Production hardening

- Keep TLS verification enabled and install the private CA in the manager's
  trust store if necessary. Do not add an insecure `CERT_NONE` workaround.
- Transform the payload to the destination's documented schema and cap fields
  that may contain large raw logs.
- Redact credentials and personal data before sending alerts to a third party.
- Define retry and deduplication behavior. The minimal script exits non-zero
  on failure but does not persist a queue.
- Monitor destination latency and rate limits; use a queue-backed worker when
  retries must survive manager restarts.
- Deploy the script and configuration consistently across manager nodes that
  process alerts.

## See also

- [Wazuh external API integration](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html)
- [Wazuh `<integration>` reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/integration.html)
- [Splunk SOAR integration](../splunk/README.md)
