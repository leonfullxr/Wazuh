# Splunk Integrations

This section covers two distinct data paths. Choose by destination and
delivery model; they are not interchangeable.

| Task | Guide |
|---|---|
| Send selected Wazuh alerts to Splunk SOAR as containers | This README |
| Copy indexed Wazuh alerts into Splunk Enterprise or Cloud | [Logstash forwarding](logstash-forwarding.md) |

## Splunk SOAR alert hook

The bundled `custom-splunk` wrapper and `custom-splunk.py` script transform a
Wazuh alert into a Splunk SOAR container and POST it to `/rest/container`.
Failed requests are stored in a local newline-delimited queue and retried when
the next alert invokes the script.

This queue is best-effort and opportunistic. It has no independent worker,
size limit, or exactly-once guarantee. Use a durable external queue for
high-volume or compliance-critical delivery.

### Prerequisites

- Splunk SOAR on-premises with an automation user and API token.
- HTTPS connectivity from every Wazuh manager that can invoke integrations.
- The Splunk SOAR CA trusted by the manager.
- `urllib3` installed in the Wazuh Python runtime.
- A narrow Wazuh rule, group, or level filter.

### Procedure

1. Copy the wrapper and Python file to `/var/ossec/integrations/`, then create
   the runtime directory:

   ```bash
   sudo install -o root -g wazuh -m 750 custom-splunk \
     /var/ossec/integrations/custom-splunk
   sudo install -o root -g wazuh -m 750 custom-splunk.py \
     /var/ossec/integrations/custom-splunk.py
   sudo install -d -o wazuh -g wazuh -m 750 /var/log/custom-splunk
   ```

2. If Splunk SOAR uses a private CA, install its PEM bundle and expose the path
   to the manager service as `SPLUNK_SOAR_CA_FILE`. For example, create a
   root-owned systemd drop-in:

   ```ini
   [Service]
   Environment="SPLUNK_SOAR_CA_FILE=/etc/pki/ca-trust/source/anchors/splunk-soar-ca.pem"
   ```

   Then reload systemd. The script verifies TLS and accepts HTTPS URLs only.

3. Add a filtered integration block to
   `/var/ossec/etc/ossec.conf`:

   ```xml
   <integration>
     <name>custom-splunk</name>
     <hook_url>https://soar.example.com/rest/container</hook_url>
     <api_key>Splunk:REPLACE_WITH_PH_AUTH_TOKEN</api_key>
     <rule_id>100100,100101</rule_id>
     <alert_format>json</alert_format>
   </integration>
   ```

   The `Splunk:` prefix is required by the script and removed before sending
   the `ph-auth-token` header. Replace the example rule IDs with approved
   alerts; do not forward the entire alert stream by default.

4. Validate and restart:

   ```bash
   sudo systemctl daemon-reload
   sudo /var/ossec/bin/wazuh-integratord -t
   sudo systemctl restart wazuh-manager
   sudo journalctl -u wazuh-manager --since "5 minutes ago" --no-pager
   ```

### Verification

Trigger one test alert and confirm:

1. Splunk SOAR creates one container with the Wazuh rule description.
2. The container artifact contains the original alert fields.
3. `/var/log/custom-splunk/custom-splunk.log` records HTTP success without
   printing the token or webhook URL.
4. `/var/log/custom-splunk/splunk_queue.json` is absent or empty after
   successful delivery.

Test failure recovery in a maintenance window by making the endpoint
temporarily unreachable, generating one test alert, restoring connectivity,
and generating another alert. The first payload should be replayed before the
second is sent.

### Operations

- Monitor queue file size and age; no alert means no automatic retry attempt.
- The log rotates at 10 MiB with five backups.
- A response outside HTTP 2xx is treated as failure and queued.
- Rotate the SOAR token in `ossec.conf`, restart the manager, and perform a
  test alert.
- Preserve CA verification. Do not reintroduce `CERT_NONE` or `curl -k`.
- Review payload size because the full Wazuh alert is included in both the
  SOAR description and artifact.

## References

- [Wazuh external API integration](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html)
- [Splunk SOAR REST API](https://docs.splunk.com/Documentation/SOARonprem/latest/PlatformAPI/Using)
