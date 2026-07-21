# Ingesting Palo Alto / Prisma Cloud logs into Wazuh

Palo Alto's **Strata Logging Service** (formerly Cortex Data Lake) is the log backend behind Prisma Access, Prisma Cloud, and PAN-OS NGFW. It forwards logs to external SIEMs **push-only**, over **Syslog** or **HTTPS** - there is no pull/API-poll option, so Wazuh must be configured to receive.

Wazuh has **no HTTPS event-collector listener**, so the supported path is **syslog over TLS (TCP/6514)**. (HTTPS forwarding would require an intermediate proxy to receive, decompress, and relay to Wazuh - extra moving parts and failure points; avoid it unless you already run such a collector.)

## Table of Contents

- [Architecture](#architecture)
- [Certificate requirements (the main blocker)](#certificate-requirements-the-main-blocker)
- [Receiver setup (rsyslog TLS on 6514)](#receiver-setup-rsyslog-tls-on-6514)
- [Parsing the logs (decoder and rules)](#parsing-the-logs-decoder-and-rules)
- [Verify](#verify)
- [Volume planning](#volume-planning)
- [See also](#see-also)

## Architecture

```
Strata Logging Service ──TLS syslog (TCP/6514)──▶  rsyslog TLS collector  ──▶  Wazuh manager
 (Syslog Forwarding Profile)                        (terminates TLS)            (decoder + rules)
```

Configure a **Syslog Forwarding Profile** in Strata (not the HTTPS profile) pointing at your receiver FQDN on `6514`, protocol TCP, TLS enabled. The receiver terminates TLS and relays the decrypted stream to the Wazuh manager (or writes per-source files a local agent reads).

## Certificate requirements (the main blocker)

This is where most Prisma/Strata integrations stall. **Strata enforces mandatory OCSP/CRL revocation checks on the receiver's server certificate, and the sender cannot disable them.** A plain self-signed certificate carries no revocation information and is rejected at the TLS handshake:

```
TLS handshake with server failed: Certificate does not specify OCSP responder
```

The receiver's certificate must carry valid **AIA OCSP** or **CRL Distribution Point** information, and those endpoints must be publicly reachable by the sender. Options, best first:

1. **Public-CA certificate for the receiver's FQDN.** Public CAs embed OCSP/CRL URLs automatically and are publicly reachable, so this satisfies the check outright. Simplest option.
2. **Your-own-domain FQDN + CNAME.** When you cannot obtain a certificate for the receiver's own hostname (e.g. the endpoint lives on a provider domain you don't control), create a **CNAME** for a domain **you** own pointing at the receiver endpoint, issue a certificate for that owned FQDN (public CA, or an internal PKI **only if** it publishes reachable OCSP/CRL responders), load it on the receiver, and configure Strata to connect to your FQDN.
3. **Do not fake it.** Hand-adding `authorityInfoAccess = OCSP;URI:http://...` to a private certificate passes only if that OCSP responder actually exists and is reachable from the sender. A placeholder URL will fail the revocation check.

> Importing the receiver's CA into the sender's trust store is **not** sufficient here. Trust and revocation are separate checks - the certificate itself must advertise OCSP/CRL, regardless of whether the CA is trusted.

Inspect a candidate certificate's revocation pointers before deploying it:

```bash
openssl x509 -in server.crt -noout -text \
  | grep -A4 -E "Authority Information Access|CRL Distribution Points"
# Expect an "OCSP - URI:http://..." and/or a CRL "URI:http://..." entry.
```

## Receiver setup (rsyslog TLS on 6514)

Terminate TLS with an rsyslog collector and forward to Wazuh - the full recipe (the `imtcp` + `ossl` stream driver, cert file layout, validation) is in [syslog over TLS (6514)](../syslog/README.md#receiving-syslog-over-tls-6514). Server-authentication only (`StreamDriver.AuthMode="anon"`) is normal: the sender validates your certificate; you do not require a client certificate from Strata.

If rsyslog refuses to open `6514` after loading the certificate, validate the cert/key/chain first - malformed PEM is a common cause and shows up as OpenSSL ASN.1 errors, not a mismatch: see [validating a server cert, key, and chain](../../certificates/troubleshooting.md#validating-a-server-cert-key-and-chain).

## Parsing the logs (decoder and rules)

Strata sends newline-delimited syslog with a **JSON** body. On the wire a record looks like this (fields trimmed; values are placeholders):

```
<14>Mar 30 08:53:11 log-forwarder-abc123 logforwarder {"TimeReceived":"2026-03-30T08:46:57.000000Z","LogType":"TRAFFIC","Subtype":"end","SourceAddress":"198.51.100.20","DestinationAddress":"203.0.113.40","Rule":"allow-internal","SourceUser":"user@example.com","Application":"web-browsing","Protocol":"tcp","Action":"allow","SourcePort":51375,"DestinationPort":80,"Bytes":2386,"SessionEndReason":"tcp-rst-from-server","URLCategory":"business-and-economy"}
```

Wazuh's predecoder strips the `<PRI>` (`<14>`) and parses the syslog timestamp and hostname; the program field is `logforwarder` and the remainder is JSON. A minimal decoder keys off `logforwarder ` and hands the body to the built-in JSON decoder:

```xml
<decoder name="paloalto-strata">
  <prematch>logforwarder </prematch>
  <plugin_decoder offset="after_prematch">JSON_Decoder</plugin_decoder>
</decoder>
```

A base (decoder-anchor) rule plus an example child that only alerts on blocked sessions - so you are not alerting on every allowed-traffic log:

```xml
<group name="paloalto,prisma,">
  <!-- Base rule: anchors the decoder, level 0 = not an alert by itself -->
  <rule id="100100" level="0">
    <decoded_as>paloalto-strata</decoded_as>
    <description>Palo Alto / Prisma log (Strata Logging Service)</description>
  </rule>

  <!-- Alert only on denied/dropped/reset sessions -->
  <rule id="100101" level="5">
    <if_sid>100100</if_sid>
    <field name="Action">deny|drop|reset</field>
    <description>Palo Alto: $(Action) session for $(Application) from $(SourceAddress)</description>
  </rule>
</group>
```

Extend with child rules (`<if_sid>100100</if_sid>`) matching the JSON fields you care about - `LogType`, `Action`, `SourceAddress`, `DestinationAddress`, `Application`, `URLCategory`, `SourceUser`, `SessionEndReason`, etc. The `<field>` names are the JSON keys verbatim.

> Use custom rule IDs in the `100000+` range so they never collide with the bundled ruleset.

## Verify

```bash
# 1. Packets arriving on the TLS port
sudo tcpdump -ni any 'tcp port 6514'

# 2. TLS handshake + delivery from a test host (should complete and land in the receiver)
echo '<14>Mar 30 08:53:11 test logforwarder {"LogType":"TRAFFIC","Action":"deny","SourceAddress":"198.51.100.20"}' \
  | openssl s_client -connect <RECEIVER_FQDN>:6514 -quiet
```

- **Decoding:** paste a sample line into `/var/ossec/bin/wazuh-logtest` - phase 2 must show decoder `paloalto-strata`, phase 3 your rule.
- **Dashboard:** filter on the rule ID or `decoder.name: paloalto-strata`.

## Volume planning

Strata traffic logs are high-volume - a firewall can emit thousands of EPS. Plan for it before turning the firehose on:

- Filter unneeded log types **at the Strata forwarding profile** (send only TRAFFIC/THREAT/URL as needed) - the cheapest event is the one never sent.
- Size and distribute the receiving side: [per-node EPS limits](../../troubleshooting/server/analysisd.md#the-eps-limit-limitseps-throttles-bursts) and [load balancing syslog across cluster workers](../syslog/README.md#load-balancing-syslog-across-cluster-workers).

## See also

- [Receiving syslog over TLS (6514)](../syslog/README.md#receiving-syslog-over-tls-6514) - the rsyslog collector recipe
- [Validating a server cert, key, and chain](../../certificates/troubleshooting.md#validating-a-server-cert-key-and-chain) - when rsyslog won't start after a cert change
- [Manager dropped events, EPS, and scaling](../../troubleshooting/server/analysisd.md) - capacity for high-volume ingestion
- [Custom decoders](../../decoders/README.md) / [Custom rules](../../rules/README.md)
- [Palo Alto: Forward logs to a syslog server](https://docs.paloaltonetworks.com/strata-logging-service/administration/forward-logs/forward-logs-to-syslog-server) (vendor docs)
