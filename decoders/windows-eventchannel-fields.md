# Extracting fields buried in a Windows eventchannel message (ADFS example)

Some Windows events carry the value you actually want (a user, a source IP) inside `data.win.system.message` as free text or escaped XML, not as a first-class field. You cannot write a clean rule or dashboard on it until it is its own field. ADFS audit events are the canonical case: the `UserId` and `IpAddress` live inside an XML blob in the message. This guide explains why a normal decoder cannot reach them and the supported ways to extract them.

## Table of Contents

- [Why a custom decoder does not work here](#why-a-custom-decoder-does-not-work-here)
- [The data: XML inside the message](#the-data-xml-inside-the-message)
- [Options and their limits](#options-and-their-limits)
- [Recommended: an integration script that extracts and re-injects](#recommended-an-integration-script-that-extracts-and-re-injects)
- [Parsing gotchas](#parsing-gotchas)
- [Scale caveat](#scale-caveat)
- [Related](#related)

## Why a custom decoder does not work here

Windows eventchannel logs (`<log_format>eventchannel</log_format>`) are parsed by Wazuh's built-in `windows_eventchannel` decoder. Two consequences trip people up:

- A custom `<decoder>` you write for the same events is overridden by the internal decoder, so you cannot re-decode eventchannel with your own decoder the way you would for a syslog source ([decoder syntax](syntax.md)).
- `<out_format>` in the `<localfile>` block is ignored for eventchannel (the JSON is produced by internal logic), so you cannot reshape the event at collection time either.

So the normal decoder route does not apply to eventchannel message bodies. Use one of the options below.

## The data: XML inside the message

A genericized ADFS "failed credential" event (`win.system.eventID` 1203; extranet lockout is 1210). The useful values are XML elements inside the message:

```xml
<UserId>user@example.com</UserId>
<IpAddress>203.0.113.10,198.51.100.20</IpAddress>
```

Three things to know before parsing:

- **Two possible sources.** `data.win.system.message` is usually clean XML; `data.win.eventdata.data` carries the same content HTML-escaped (`&lt;...&gt;`) and is sometimes truncated. Prefer `system.message`, fall back to `eventdata.data`.
- `<IpAddress>` can be a comma-separated list: client IP plus a forwarded/proxy IP (`203.0.113.10,198.51.100.20`). Split it downstream if you need the true client IP.
- **ADFS audit EventIDs worth alerting on:** `1203` (failed credential validation) and `1210` (extranet lockout).

## Options and their limits

| Approach | What it does | Limit |
|---|---|---|
| Rule `<match>` / `<field>` on the raw message | Alert on a literal value inside `data.win.system.message`; several values can be OR-ed in one regex | Brittle - you must enumerate the values; it never turns `UserId`/`IpAddress` into reusable fields |
| Indexer Painless script (runtime field) | Extract a value from the message at query time | One field at a time; indexer-side only, not on the alert, and unusable in rule logic |
| Fix at the source | Have ADFS emit a cleaner/structured format | Not always possible |
| **Integration script (recommended)** | A rule triggers a script that parses the XML and re-injects the fields as a JSON alert | Extra queue load - see [scale caveat](#scale-caveat) |

## Recommended: an integration script that extracts and re-injects

The pattern: a rule fires the extractor, then the script parses the tags out of the message, then it re-injects the event as JSON to the analysis queue, then a second rule alerts on the now-first-class fields. The ready-made, enhanced script lives in [scripts/eventchannel-extraction](../scripts/eventchannel-extraction/) as `custom-windows-xml` (its `custom-windows` sibling handles `key: value` messages). For JSON logs the analogous tool is [scripts/custom-json](../scripts/custom-json/README.md) (a different input format and a different script, not this one).

**1. Trigger rule**: fire the extractor on the ADFS EventIDs (as a child of the bundled ADFS/eventchannel rule for these events):

```xml
<group name="adfs,custom-windows,">
  <rule id="100100" level="10">
    <if_sid><BUNDLED_ADFS_RULE_ID></if_sid>
    <field name="win.system.eventID">1203|1210</field>
    <description>ADFS audit event - run field extractor</description>
  </rule>
</group>
```

**2. Extractor script**: install [`custom-windows-xml`](../scripts/eventchannel-extraction/) into `/var/ossec/integrations/` (`chmod 750`, `chown root:wazuh`, on every manager node). Its core is unescape, then XML parse, then regex fallback, then re-inject; the extraction itself is just:

```python
def extract_tags(message, tags={"UserId": "UserId", "IpAddress": "IpAddress"}):
    result = {out: None for out in tags.values()}
    text = html.unescape(message or "")
    try:                                  # 1) well-formed XML (namespace-tolerant)
        for elem in ET.fromstring(text).iter():
            local = elem.tag.rsplit("}", 1)[-1]
            if local in tags and elem.text and result[tags[local]] is None:
                result[tags[local]] = elem.text.strip()
    except ET.ParseError:
        pass                              # 2) escaped/truncated XML -> regex fallback
    for tag, out in tags.items():
        if result[out] is None:
            m = re.search(rf"<{tag}>(.*?)</{tag}>", text, re.I | re.S)
            if m:
                result[out] = m.group(1).strip()
    return result
```

The full script - with logging, error handling, a configurable `TAGS` map, and a `--selftest` - is in [scripts/eventchannel-extraction](../scripts/eventchannel-extraction/), alongside `custom-windows` for `key: value` messages.

**3. Wire it up** in `/var/ossec/etc/ossec.conf` and add the second rule that fires on the re-injected JSON:

```xml
<integration>
  <name>custom-windows-xml</name>
  <rule_id>100100</rule_id>
  <alert_format>json</alert_format>
</integration>
```

```xml
<rule id="100110" level="10">
  <decoded_as>json</decoded_as>
  <field name="integration">^custom-windows-xml$</field>
  <description>ADFS: user $(win.system.parsed_fields.UserId) from $(win.system.parsed_fields.IpAddress)</description>
</rule>
```

Restart the manager (every node) and debug with `integrator.debug=2` in `internal_options.conf`, watching `ossec.log`. The parsed values now arrive as real fields (`data.win.system.parsed_fields.UserId` / `.IpAddress`) you can alert and pivot on.

## Parsing gotchas

- **Escaped / malformed XML.** `win.eventdata.data` is HTML-escaped and can be truncated, which makes a strict parser fail (`Failed XML parse: unclosed token`). Always `html.unescape()` first and keep the regex fallback: that is why the script tries `ElementTree`, then regex.
- **Comma-separated IPs.** `<IpAddress>` may be `client,forwarded`; keep the whole string, or split on `,` and take the first for the true client.
- **Pick the right source.** Prefer `win.system.message` (clean); only fall back to `win.eventdata.data` when the message is empty.

## Scale caveat

The extractor **runs on every matching alert and re-injects a second event**, so it roughly **doubles the queue load for those events**. On a busy ADFS feed (high EPS), especially alongside another heavy source such as a syslog forwarder, this can saturate the analysisd queue and produce **dropped, delayed, or empty alerts** (empty = the script ran but its output was discarded before indexing). That is a capacity symptom, not a script bug: measure EPS and `events_dropped`, and size the manager (add a worker, or reduce the input) before blaming the extraction. See [analysisd, EPS, and dropped events](../troubleshooting/server/analysisd.md).

The same pattern works for any eventchannel message with an embedded structured payload (key:value AV logs, other XML) - only the parsing in `extract_*` changes.

## Related

- [scripts/eventchannel-extraction](../scripts/eventchannel-extraction/) - the ready-made `custom-windows-xml` (XML) and `custom-windows` (`key: value`) integratord scripts
- [scripts/custom-json](../scripts/custom-json/README.md) - the equivalent enrichment for **JSON** logs (a different input format, not the same script)
- [Decoder syntax and examples](syntax.md) - standard decoders, for non-eventchannel sources
- [Custom rules](../rules/) - rule chaining with `if_sid` / `decoded_as`
- [analysisd, EPS, and dropped events](../troubleshooting/server/analysisd.md) - the capacity side of the scale caveat
