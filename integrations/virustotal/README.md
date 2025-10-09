# Wazuh × VirusTotal IP Reputation Integration (v3)

A lightweight integration that enriches Wazuh alerts with **VirusTotal IP reputation** and returns a clear verdict: **malicious**, **suspicious**, or **unknown**. It’s built on Wazuh’s Integrator framework and the VirusTotal **v3** API.

## What this integration does

* Extracts the **source IP** from matching Wazuh alerts.
* Queries VirusTotal’s **IP object** (`/api/v3/ip_addresses/{ip}`) and (optionally) pivots to **communicating files** for borderline cases.
* Computes a verdict using **engine consensus, freshness, community reputation, risk tags**, and **light engine-weighting**.
* Emits an enriched JSON block under `virustotal_ip` and a flat `verdict_line` string for easy rule matching.

**Verdicts:**

* **malicious** – strong, fresh multi-source evidence of abuse.
* **suspicious** – weak/partial signal; monitor or rate-limit.
* **unknown** – no evidence either way (default-conservative).

## Files & placement

* Script path (recommended): **`/var/ossec/integrations/custom-virustotal-ip`**
  *(You can keep a `.py` development copy if you prefer; for Integrator, the executable file without extension is customary.)*

Permissions:

```bash
sudo chmod 750 /var/ossec/integrations/custom-virustotal-ip
sudo chown root:ossec /var/ossec/integrations/custom-virustotal-ip
```

## Wazuh configuration

Add an `<integration>` block to the **Manager** `ossec.conf`:

```xml
<integration>
  <name>custom-virustotal-ip</name>
  <api_key>YOUR_VT_KEY</api_key>
  <group>authentication_failures</group> <!-- adjust groups to your use case -->
  <alert_format>json</alert_format>
  <timeout>15</timeout>     <!-- optional -->
  <retries>1</retries>      <!-- optional -->
</integration>
```

**Notes**

* `group` controls which alerts trigger the integration (e.g., `sshd`, `authentication_failures`, `vt_test`, etc.).
* `alert_format` **must** be `json` for this script.

Restart Wazuh Manager after changes:

```bash
sudo systemctl restart wazuh-manager
```

## Heuristic (how the verdict is decided)

The script combines several signals from VirusTotal:

1. **Engine consensus** – `last_analysis_stats` counts how many sources label the IP `malicious` or `suspicious`.
2. **Per-engine weighting** – `last_analysis_results` adds a small score: `malicious=+1.0`, `suspicious=+0.5`.
3. **Community reputation** – `reputation` (negative is worse). Used as a tie‑breaker when there’s at least one hit.
4. **Freshness** – `last_analysis_date` → older weak hits get discounted.
5. **Risk tags** – `tags` like `tor`, `vpn`, `proxy` don’t convict alone, but keep weakly-bad IPs at least *suspicious*.
6. **Borderline pivot** – optional second call to `/communicating_files` to look for **strongly malicious files** that contacted the IP.

### Default thresholds (constants at top of script)

These are easy to tune later without changing logic:

```python
# Primary threshold: malicious if >= this many engines say malicious
MAL_STRONG_MIN = 3

# If at least 1 malicious AND reputation < this (0 → negative): malicious
REP_BAD_LT = 0

# Lightweight engine weighting (mal=1.0, sus=0.5)
WEIGHT_MAL_STRONG = 3.0   # malicious if weighted >= 3.0
WEIGHT_MAL_SUS    = 1.5   # unknown -> suspicious if weighted >= 1.5

# Discount stale weak hits
STALE_WEAK_DAYS = 90

# Risk tags that prevent downgrading below suspicious when any hit exists
RISK_TAGS = {"tor", "vpn", "proxy", "anonymizer", "anonymous"}

# Borderline pivot to communicating files
PIVOT_ENABLED = True
PIVOT_LIMIT = 10
PIVOT_STRONG_FILE_MIN = 5      # a file is "strong" if >=5 engines flag it
PIVOT_UPGRADE_1 = 1            # >=1 strong file: unknown -> suspicious
PIVOT_UPGRADE_2 = 3            # >=3 strong files: suspicious -> malicious
```

### Decision flow

1. **Start with engine counts**

   * `malicious >= 3` → **malicious**
   * `malicious >= 1` and `reputation < 0` → **malicious**
   * `(malicious + suspicious) >= 1` → **suspicious** (unless stale weak, below)
   * else → **unknown**

2. **Freshness discount**
   If `age_days > 90`, `malicious <= 1`, and `reputation >= 0` → **unknown** (stale weak)

3. **Lightweight engine weighting**
   Score `>= 3.0` → **malicious**; score `>= 1.5` (when unknown) → **suspicious**

4. **Risk tags guardrail**
   If any hit exists and tag in `RISK_TAGS`, ensure at least **suspicious**

5. **Borderline pivot (optional)**
   If verdict is unknown/suspicious with few hits (<=1), fetch up to 10 **communicating files**.
   If strong files `>= 3` → upgrade one level; if `>=1` and verdict was unknown → suspicious.

## Testing & simulation

**Direct (unit) test** — mirrors how Integrator calls the script:

```bash
cat >/tmp/test-alert.json <<'JSON'
{
  "id": "999999",
  "rule": {"id": 100500, "description": "VT test"},
  "agent": {"id":"000","name":"wazuh-manager"},
  "data": {"srcip": "45.159.112.120"}
}
JSON

sudo -u ossec /var/ossec/framework/python/bin/python3 \
  /var/ossec/integrations/custom-virustotal-ip \
  /tmp/test-alert.json \
  "api_key:$VT_API_KEY"
```

**End-to-end pipeline test** — with a dummy log source & rule:

```xml
<!-- /var/ossec/etc/rules/local_rules.xml -->
<group name="local,vt_test">
  <rule id="100500" level="6">
    <if_matched_regex>VTTEST</if_matched_regex>
    <description>VT test log</description>
    <group>vt_test</group>
  </rule>
</group>
```

```bash
sudo touch /var/log/wzvt_test.log
# Add a collector in ossec.conf (localfile … /var/log/wzvt_test.log), restart manager

echo "Oct  9 12:00:00 host app[123]: VTTEST SRC=45.159.112.120" | sudo tee -a /var/log/wzvt_test.log

tail -f /var/ossec/logs/integrations.log
```

Enable Integrator debug while testing:

```bash
echo "integrator.debug=2" | sudo tee -a /var/ossec/etc/local_internal_options.conf
sudo systemctl restart wazuh-manager
```

---

## Output schema (example)

The script emits a **manager-to-dashboard** message with a JSON body like:

```json
{
  "virustotal_ip": {
    "found": 1,
    "verdict": "malicious",
    "source": {"alert_id": "1753101678.8211", "rule": "100003", "ip": "64.62.197.132"},
    "counts": {"malicious": 10, "suspicious": 1},
    "engine_counts": {"malicious": 10, "suspicious": 1},
    "weighted_malicious": 10.5,
    "reputation": -3,
    "tags": [],
    "age_days": 0.8,
    "last_analysis_date": "2025-10-08T15:22:00+00:00",
    "country": "US",
    "as_owner": "HURRICANE",
    "network": "64.62.197.0/24",
    "permalink": "https://www.virustotal.com/gui/ip-address/64.62.197.132",
    "pivot": {"used": false},
    "verdict_line": "vt_ip verdict=malicious ip=64.62.197.132 mal=10 sus=1 wmal=10.5 rep=-3 age_days=0.8 tags=- as_owner=\"HURRICANE\""
  },
  "integration": "virustotal_ip"
}
```

**Tip:** `verdict_line` is intentionally flat text so you can match it easily with rules.

## Escalation rules (optional)

Raise alert levels automatically based on the verdict.

```xml
<!-- /var/ossec/etc/rules/local_rules.xml -->
<group name="local,virustotal,vt_ip">
  <!-- Malicious -> level 12 -->
  <rule id="199901" level="12">
    <if_group>authentication_failures|sshd|vt_test</if_group>
    <field name="virustotal_ip.verdict_line">vt_ip verdict=malicious</field>
    <description>Source IP flagged malicious by VirusTotal</description>
    <options>no_full_log</options>
  </rule>

  <!-- Suspicious -> level 7 -->
  <rule id="199902" level="7">
    <if_group>authentication_failures|sshd|vt_test</if_group>
    <field name="virustotal_ip.verdict_line">vt_ip verdict=suspicious</field>
    <description>Source IP suspicious per VirusTotal</description>
    <options>no_full_log</options>
  </rule>
</group>
```