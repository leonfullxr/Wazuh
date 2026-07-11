# Postfix / Email Delivery Failures

Diagnosing Wazuh email alert delivery failures when Postfix relays through an external SMTP service (Office 365 or similar). Wazuh's email alerting and scheduled report scripts rely on a working local MTA, so a broken relay silently kills all email notifications.

## Table of Contents

- [Symptom](#symptom)
- [Capture the SMTP session with tcpdump](#capture-the-smtp-session-with-tcpdump)
- [Interpreting the capture](#interpreting-the-capture)
- [Checklist](#checklist)

## Symptom

Email alerts stop arriving; Postfix logs show connection failures to the smart host (e.g. `smtp.office365.com:587`) with no SMTP-level error — the connection dies before any SMTP banner is exchanged.

## Capture the SMTP session with tcpdump

Capture the traffic while reproducing the failure:

```bash
# Terminal 1: capture traffic to the smart host
sudo tcpdump -i any host smtp.office365.com and port 587 -w /tmp/587.pcap

# Terminal 2: trigger the failure manually
telnet smtp.office365.com 587

# Stop tcpdump (Ctrl-C) and inspect
tcpdump -nn -r /tmp/587.pcap -A
```

## Interpreting the capture

A common failure mode: the three-way TCP handshake (SYN, SYN-ACK, ACK) completes, and then the remote side immediately sends a **TCP RST** and tears the connection down before any SMTP dialogue.

That pattern means something in the network path — typically a next-generation firewall (Palo Alto, Fortinet, etc.) doing application inspection — is actively resetting the session. It is **not** a Postfix configuration problem: Postfix never got to speak SMTP.

Resolution: have the firewall team fully open outbound TCP 587 (including any SMTP/TLS application-layer inspection profiles) from the Wazuh server to the mail relay, then retest with the same `telnet`/`tcpdump` procedure.

If instead you see the SMTP banner (`220 ...`) followed by an SMTP error code, the problem is at the mail-service level (authentication, sender restrictions, TLS requirements) — fix it in Postfix's relay configuration, not the network.

## Checklist

1. `telnet <SMTP_HOST> 587` — does a banner appear?
2. No banner + RST in tcpdump → firewall/network path. Engage the network team.
3. Banner + SMTP 4xx/5xx → Postfix relay settings: credentials (`sasl_passwd`), TLS (`smtp_use_tls`), allowed sender addresses on the mail service side.
4. Once `telnet` reaches a banner and authentication works, restart Postfix and send a test message:

   ```bash
   systemctl restart postfix
   echo "Test body" | mail -s "Wazuh mail test" you@example.com
   tail -f /var/log/maillog   # or /var/log/mail.log on Debian/Ubuntu
   ```

Reference: [Configuring email alerts via authenticated SMTP](https://documentation.wazuh.com/current/user-manual/manager/manual-email-report/smtp-authentication.html)
