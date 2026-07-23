# Decoder Syntax and Examples

Reference for writing custom Wazuh decoders. For vendor-specific suites see [FortiGate](fortigate/README.md), [Vectra](vectra/README.md), and [NetIQ](netIQ/README.md).

Official docs: [Decoders syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/decoders.html), [Dynamic fields](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/dynamic-fields.html#traditional-decoders)

## Overview

Wazuh decoders extract fields from log lines using its own regex dialect (`OS_Regex`, not PCRE). Two common patterns:

1. **Sibling decoders**: a parent matches the log source; child decoders each extract one field independently. Tolerates optional or reordered key/value pairs.
2. **Static vs dynamic fields**: thirteen predefined static fields (`user`, `srcip`, `dstip`, ...) cannot be renamed; any other name in `<order>` becomes a dynamic field usable in rules.

Test decoders with `/var/ossec/bin/wazuh-logtest` or Server management to Log test in the Wazuh Dashboard.

## Regex (OS_Regex) syntax

### Expressions

| Operator | Matches |
|---|---|
| `\S` | anything but whitespace |
| `\S+` | one or more non-whitespace characters |
| `\s` | spaces |
| `\t` | tabs |
| `\p` | punctuation: `()*+,-.:;<=>?[]!"'#$%&\|{}` |
| `\.` | anything, including whitespace |
| `\.+` | one or more of anything |
| `\d` | digits `0-9` |
| `\w` | word characters: `A-Z`, `a-z`, `0-9`, `-`, `@`, `_` |
| `\W` | anything not `\w` |

### Modifiers

| Modifier | Meaning |
|---|---|
| `+` | match one or more times |
| `*` | match zero or more times |

### Special characters

| Char | Meaning |
|---|---|
| `^` | beginning of the text |
| `$` | end of the text |
| `\|` | logical OR between patterns |

## Static vs dynamic fields

Predefined static fields: `user`, `srcip`, `dstip`, `srcport`, `dstport`, `protocol`, `action`, `id`, `url`, `data`, `extra_data`, `status`, `system_name`.

Any other name in `<order>` is a dynamic field: reference in rules as `field name="..."` and in descriptions as `$(field.name)`.

## Example - sibling decoders

Sample logs (fields in varying order):

```
2019/01/02 13:16:35 securityapp: INFO: srcuser="Bob" action="called" dstusr="Alice"
Apr 01 19:21:24 hostname2 securityapp: INFO: action="logged on" srcuser="Bob"
```

```xml
<decoder name="securityapp">
  <program_name>securityapp</program_name>
</decoder>

<decoder name="securityapp">
  <parent>securityapp</parent>
  <regex>^(\w+):</regex>
  <order>type</order>
</decoder>

<decoder name="securityapp">
  <parent>securityapp</parent>
  <regex>srcuser="(\.+)"</regex>
  <order>srcuser</order>
</decoder>

<decoder name="securityapp">
  <parent>securityapp</parent>
  <regex>action="(\.+)"</regex>
  <order>action</order>
</decoder>

<decoder name="securityapp">
  <parent>securityapp</parent>
  <regex>dstusr="(\.+)"</regex>
  <order>dstuser</order>
</decoder>
```

## Notes

- Place custom decoders in `/var/ossec/etc/decoders/local_decoder.xml` and restart the manager.
- CEF logs (Vectra, NetIQ) and key=value firewalls (FortiGate) benefit from sibling decoders when field order varies.
- For nested JSON, see [custom JSON extraction](../scripts/custom-json/README.md).
- For values trapped in a Windows eventchannel message that a custom decoder cannot reach (e.g. ADFS `UserId`/`IpAddress` inside XML), see [Windows eventchannel field extraction](windows-eventchannel-fields.md).

## See also

- [FortiGate decoders](fortigate/README.md)
- [Vectra decoders](vectra/README.md)
- [NetIQ decoders](netIQ/README.md)
- [FortiGate rules](../rules/fortigate/)
