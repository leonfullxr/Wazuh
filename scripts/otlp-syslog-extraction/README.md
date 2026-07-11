# Realtime syslog extraction from OpenTelemetry JSON logs

Some log pipelines (e.g. an OpenTelemetry collector writing OTLP JSON) wrap
the original syslog line inside a JSON structure, which Wazuh cannot decode as
syslog. `otlp_syslog_follow.sh` follows the JSON log in realtime, extracts the
embedded syslog line from every `stringValue` field, and appends the clean
line to a second file that the Wazuh agent monitors with `log_format: syslog`.

## Input / output example

Input JSON line (as received, e.g. from a firewall via an OTLP collector):

```json
{"resourceLogs": {"resource": {},"scopeLogs": {"scope": {},"logRecords": {"observedTimeUnixNano": "1755685223624760239","body": {"stringValue": "<188>date=2025-08-20 time=10:20:23 devname=\"fw01\" type=\"event\" subtype=\"wireless\" level=\"warning\" msg=\"AP sent 1/4 message of 4-way handshake to client\""},"traceId": "","spanId": ""}}}}
```

Extracted output line (the `<188>` PRI prefix and escaping backslashes are
stripped so fields are clean for decoders):

```text
date=2025-08-20 time=10:20:23 devname="fw01" type="event" subtype="wireless" level="warning" msg="AP sent 1/4 message of 4-way handshake to client"
```

## Requirements

`tail`, `jq`, and `stdbuf` (coreutils):

```bash
command -v tail; command -v jq; command -v stdbuf
```

## Installation

1. Install the script (paths are the defaults; both can be overridden as
   arguments):

   ```bash
   cp otlp_syslog_follow.sh /usr/local/bin/
   chmod +x /usr/local/bin/otlp_syslog_follow.sh
   ```

   Note: if your log directory is mounted `noexec`, keep the script in
   `/usr/local/bin` (as here) or invoke it via `/bin/bash`.

2. Install and start the systemd unit (edit the input/output paths in
   `ExecStart` to match your environment):

   ```bash
   cp extract_syslog_realtime.service /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable --now extract_syslog_realtime.service
   systemctl status extract_syslog_realtime.service
   ```

   The script follows the source with `tail -F`, so it survives log rotation;
   `Restart=always` covers everything else.

3. Point the Wazuh agent at the **extracted** file in
   `/var/ossec/etc/ossec.conf`:

   ```xml
   <localfile>
     <location>/var/log/otlp/syslog_extracted.log</location>
     <log_format>syslog</log_format>
   </localfile>
   ```

   ```bash
   systemctl restart wazuh-agent
   ```

## Quick test

Append a sample JSON line to the source log and confirm the extracted line
appears:

```bash
echo '{"resourceLogs":{"resource":{},"scopeLogs":{"scope":{},"logRecords":{"body":{"stringValue":"<188>date=2025-08-20 time=10:20:23 devname=\"123\" msg=\"hi\""}}}}}' >> /var/log/otlp/syslog.log
sleep 1
tail -n1 /var/log/otlp/syslog_extracted.log
# Should show:
# date=2025-08-20 time=10:20:23 devname="123" msg="hi"
```

## Related

- [`../eventchannel-extraction`](../eventchannel-extraction) - same
  "unwrap the embedded payload" idea for Windows eventchannel messages.
- [`../../decoders/fortigate`](../../decoders/fortigate) - decoders for the
  key=value firewall format shown in the example.
