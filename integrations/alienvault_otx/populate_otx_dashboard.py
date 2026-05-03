#!/usr/bin/env python3
"""
populate_otx_dashboard.py

Generate a varied set of synthetic Wazuh alerts and run each through the
custom-alienvault integration. Designed to populate every panel of the
AlienVault OTX dashboard with realistic data variety.

The 20 scenarios below intentionally vary:
  * Wazuh agent (8 distinct hostnames/IDs)
  * Original rule ID (10+ distinct values across SSH, web, FIM, Suricata,
    Sysmon, MS Graph, AWS CloudTrail, firewall sources)
  * IOC type (src_ip, dst_ip, domain, file_hash; many in combination)
  * Verdict outcome (mix of malicious and clean)
  * Field-path coverage (exercises the SUPPORTED_FIELD_PATHS registry
    across registered log sources)

Indicators used:
  * 45.153.34.132   - malicious (Komari malware family)
  * 176.65.139.134  - malicious (Mirai/DDoS botnet, adversary: Tadashi)
  * 1.1.1.1         - clean (Cloudflare DNS, 0 OTX pulses)
  * 149.72.157.191  - clean (SendGrid IP, 0 OTX pulses)
  * 8.8.8.8         - clean (Google DNS, 0 OTX pulses)
  * www.cloudflare.com / api.github.com / wazuh.com - clean domains
  * EICAR SHA-256   - malicious (40+ pulses, EICAR malware family)

OTX content rotates; if any indicator above stops returning pulses,
swap it for a current OTX-known indicator from your subscribed pulses:
    curl -s -H "X-OTX-API-KEY: $OTX_KEY" \\
      "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20" \\
      | jq -r '.results[].indicators[]? | select(.type=="IPv4") | .indicator'

Usage:
    OTX_KEY=<your-otx-key> python3 populate_otx_dashboard.py
    OTX_KEY=<your-otx-key> python3 populate_otx_dashboard.py --dry-run
    OTX_KEY=<your-otx-key> python3 populate_otx_dashboard.py --sleep 2.0
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

INTEGRATION_SCRIPT = "/var/ossec/integrations/custom-alienvault.py"
OTX_HOOK = "https://otx.alienvault.com"
DEFAULT_SLEEP = 1.5  # seconds between OTX queries

# ---------------------------------------------------------------------------
# Indicators
# ---------------------------------------------------------------------------

MAL_IP_KOMARI = "45.153.34.132"
MAL_IP_MIRAI = "176.65.139.134"
CLEAN_IP_CLOUDFLARE = "1.1.1.1"
CLEAN_IP_SENDGRID = "149.72.157.191"
CLEAN_IP_GOOGLE = "8.8.8.8"

CLEAN_DOMAIN_CF = "www.cloudflare.com"
CLEAN_DOMAIN_GH = "api.github.com"
CLEAN_DOMAIN_WAZUH = "wazuh.com"

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"
EICAR_SHA1 = "3395856ce81f2b7382dee72602f798b642f14140"

# ---------------------------------------------------------------------------
# Agent profiles
# ---------------------------------------------------------------------------

AGENTS = {
    "web1":      {"id": "001", "name": "web-server-01",        "ip": "192.168.10.10"},
    "fw1":       {"id": "002", "name": "fw-edge-01",           "ip": "10.0.5.1"},
    "ids1":      {"id": "003", "name": "ids-sensor-01",        "ip": "10.0.0.99"},
    "mail1":     {"id": "004", "name": "mail-gateway-01",      "ip": "10.0.6.10"},
    "fin1":      {"id": "005", "name": "endpoint-finance-12",  "ip": "10.0.8.42"},
    "hr1":       {"id": "006", "name": "endpoint-hr-07",       "ip": "10.0.8.55"},
    "dns1":      {"id": "007", "name": "dns-resolver-02",      "ip": "10.0.0.30"},
    "dc1":       {"id": "008", "name": "domain-controller-01", "ip": "10.0.0.10"},
}

def now_iso(offset_min=0):
    return (datetime.now(timezone.utc) + timedelta(minutes=offset_min)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

# ---------------------------------------------------------------------------
# Alert builders -- each returns a Wazuh-style alert dict
# ---------------------------------------------------------------------------

def ssh_brute_force(agent_key, src_ip, alert_id, t):
    return {
        "agent": AGENTS[agent_key],
        "manager": {"name": "wazuh-server"},
        "data": {"srcip": src_ip, "srcuser": "root", "dstuser": "admin"},
        "rule": {
            "id": "5712", "level": 10,
            "description": "sshd: brute force trying to get access to the system",
            "groups": ["syslog", "sshd", "authentication_failures"],
        },
        "decoder": {"name": "sshd"},
        "location": "/var/log/secure",
        "id": alert_id, "timestamp": t,
    }

def ssh_login_success(agent_key, src_ip, alert_id, t):
    return {
        "agent": AGENTS[agent_key],
        "manager": {"name": "wazuh-server"},
        "data": {"srcip": src_ip, "dstuser": "ubuntu"},
        "rule": {
            "id": "5715", "level": 3,
            "description": "sshd: authentication success",
            "groups": ["syslog", "sshd", "authentication_success"],
        },
        "decoder": {"name": "sshd"},
        "location": "/var/log/secure",
        "id": alert_id, "timestamp": t,
    }

def web_scanner(agent_key, src_ip, alert_id, t):
    return {
        "agent": AGENTS[agent_key],
        "manager": {"name": "wazuh-server"},
        "data": {
            "srcip": src_ip, "id": "404",
            "url": "/admin/.env", "protocol": "GET",
        },
        "rule": {
            "id": "31151", "level": 6,
            "description": "Multiple web server 400 error codes from same source IP",
            "groups": ["web", "accesslog", "web_scan"],
        },
        "decoder": {"name": "web-accesslog"},
        "location": "/var/log/apache2/access.log",
        "id": alert_id, "timestamp": t,
    }

def firewall_outbound(agent_key, src_priv_ip, dst_ip, alert_id, t):
    return {
        "agent": AGENTS[agent_key],
        "manager": {"name": "wazuh-server"},
        "data": {
            "srcip": src_priv_ip, "dstip": dst_ip,
            "action": "allowed", "protocol": "tcp", "dst_port": "443",
        },
        "rule": {
            "id": "100200", "level": 5,
            "description": "Firewall: outbound HTTPS connection",
            "groups": ["firewall"],
        },
        "decoder": {"name": "json"},
        "location": "firewall", "id": alert_id, "timestamp": t,
    }

def sysmon_dns_query(agent_key, query_name, alert_id, t):
    return {
        "agent": AGENTS[agent_key],
        "manager": {"name": "wazuh-server"},
        "data": {
            "win": {
                "system": {
                    "providerName": "Microsoft-Windows-Sysmon",
                    "eventID": "22",
                    "computer": AGENTS[agent_key]["name"],
                },
                "eventdata": {
                    "queryName": query_name,
                    "image": "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
                    "processId": "4488",
                },
            }
        },
        "rule": {
            "id": "61606", "level": 5,
            "description": "Sysmon - Event 22: DNSEvent (DNS query)",
            "groups": ["sysmon", "sysmon_event_22"],
        },
        "decoder": {"name": "windows_eventchannel"},
        "location": "EventChannel", "id": alert_id, "timestamp": t,
    }

def sysmon_process_create_eicar(agent_key, alert_id, t):
    return {
        "agent": AGENTS[agent_key],
        "manager": {"name": "wazuh-server"},
        "data": {
            "win": {
                "system": {
                    "providerName": "Microsoft-Windows-Sysmon",
                    "eventID": "1",
                    "computer": AGENTS[agent_key]["name"],
                },
                "eventdata": {
                    "image": "C:\\Users\\test\\Downloads\\eicar.com",
                    "parentImage": "C:\\Windows\\explorer.exe",
                    "processId": "5012",
                    "parentProcessId": "1832",
                    "currentDirectory": "C:\\Users\\test\\Downloads\\",
                    "hashes": (f"MD5={EICAR_MD5},SHA256={EICAR_SHA256},"
                               f"IMPHASH=0000000000000000"),
                },
            }
        },
        "rule": {
            "id": "61603", "level": 7,
            "description": "Sysmon - Event 1: Process creation",
            "groups": ["sysmon", "sysmon_event_1"],
        },
        "decoder": {"name": "windows_eventchannel"},
        "location": "EventChannel", "id": alert_id, "timestamp": t,
    }

def fim_eicar(agent_key, alert_id, t):
    return {
        "agent": AGENTS[agent_key],
        "manager": {"name": "wazuh-server"},
        "syscheck": {
            "path": "/tmp/eicar.com", "mode": "scheduled",
            "size_after": "68", "perm_after": "rw-r--r--",
            "uid_after": "0", "gid_after": "0",
            "md5_after": EICAR_MD5,
            "sha1_after": EICAR_SHA1,
            "sha256_after": EICAR_SHA256,
            "event": "added",
        },
        "rule": {
            "id": "554", "level": 7,
            "description": "FIM: file added to monitored directory",
            "groups": ["ossec", "syscheck"],
        },
        "decoder": {"name": "syscheck_new_entry"},
        "location": "syscheck", "id": alert_id, "timestamp": t,
    }

def suricata_alert(agent_key, src_ip, dst_ip, alert_id, t):
    return {
        "agent": AGENTS[agent_key],
        "manager": {"name": "wazuh-server"},
        "data": {
            "suricata": {
                "src_ip": src_ip, "dest_ip": dst_ip,
                "src_port": "55512", "dest_port": "443", "proto": "TCP",
                "alert": {
                    "signature": "ET MALWARE Possible C2 Beacon",
                    "category": "Malware Command and Control Activity Detected",
                    "severity": "1",
                },
            }
        },
        "rule": {
            "id": "86601", "level": 9,
            "description": "Suricata: malware C2 detected",
            "groups": ["ids", "suricata"],
        },
        "decoder": {"name": "json"},
        "location": "suricata", "id": alert_id, "timestamp": t,
    }

def msgraph_mail(agent_key, sender_ip, alert_id, t, malicious=True):
    return {
        "agent": AGENTS[agent_key],
        "manager": {"name": "wazuh-server"},
        "data": {
            "integration": "ms-graph",
            "ms-graph": {
                "id": alert_id,
                "title": ("Suspicious mail" if malicious
                          else "Mail filter informational"),
                "severity": "medium" if malicious else "informational",
                "createdDateTime": t,
                "evidence": [{
                    "@odata.type":
                        "#microsoft.graph.security.analyzedMessageEvidence",
                    "senderIp": sender_ip,
                    "recipientEmailAddress": "user@wazuh.com",
                    "verdict": "suspicious" if malicious else "informational",
                    "p2Sender": {
                        "emailAddress":
                            ("attacker@badsender.example" if malicious
                             else "newsletter@trusted-vendor.example"),
                        "domainName":
                            ("badsender.example" if malicious
                             else "trusted-vendor.example"),
                    },
                }],
            },
        },
        "rule": {
            "id": "300126", "level": 5 if malicious else 3,
            "description": "MS Defender: mail evidence",
            "groups": ["ms-graph"],
        },
        "decoder": {"name": "json-msgraph"},
        "location": "ms-graph", "id": alert_id, "timestamp": t,
    }

def aws_cloudtrail(agent_key, src_ip, alert_id, t):
    return {
        "agent": AGENTS[agent_key],
        "manager": {"name": "wazuh-server"},
        "data": {
            "integration": "aws",
            "aws": {
                "source": "cloudtrail",
                "eventSource": "iam.amazonaws.com",
                "eventName": "CreateAccessKey",
                "sourceIPAddress": src_ip,
                "userIdentity": {"userName": "admin"},
            },
        },
        "rule": {
            "id": "80100", "level": 6,
            "description": "AWS CloudTrail: IAM access key created",
            "groups": ["amazon", "aws"],
        },
        "decoder": {"name": "json"},
        "location": "aws", "id": alert_id, "timestamp": t,
    }

# ---------------------------------------------------------------------------
# 20 scenarios -- distinct names, varied agents/rules/IOCs
# ---------------------------------------------------------------------------

SCENARIOS = [
    # SSH brute force from malicious IPs
    ("ssh-brute-force-komari-1",       ssh_brute_force,        ("web1",  MAL_IP_KOMARI)),
    ("ssh-brute-force-mirai-1",        ssh_brute_force,        ("web1",  MAL_IP_MIRAI)),
    ("ssh-brute-force-komari-2",       ssh_brute_force,        ("dc1",   MAL_IP_KOMARI)),

    # SSH success (lower-severity, exercises rule 5715)
    ("ssh-login-success-clean",        ssh_login_success,      ("web1",  CLEAN_IP_CLOUDFLARE)),
    ("ssh-login-success-malicious-ip", ssh_login_success,      ("web1",  MAL_IP_KOMARI)),

    # Web scanner activity
    ("web-scanner-mirai",              web_scanner,            ("web1",  MAL_IP_MIRAI)),
    ("web-scanner-komari",             web_scanner,            ("web1",  MAL_IP_KOMARI)),

    # Firewall outbound -- exercises dst_ip path
    ("firewall-outbound-c2-komari",    firewall_outbound,      ("fw1",   "10.0.5.50",  MAL_IP_KOMARI)),
    ("firewall-outbound-c2-mirai",     firewall_outbound,      ("fw1",   "10.0.5.51",  MAL_IP_MIRAI)),
    ("firewall-outbound-clean-cf",     firewall_outbound,      ("fw1",   "10.0.5.52",  CLEAN_IP_CLOUDFLARE)),

    # Sysmon DNS queries
    ("sysmon-dns-cloudflare",          sysmon_dns_query,       ("fin1",  CLEAN_DOMAIN_CF)),
    ("sysmon-dns-github",              sysmon_dns_query,       ("hr1",   CLEAN_DOMAIN_GH)),
    ("sysmon-dns-wazuh",               sysmon_dns_query,       ("dns1",  CLEAN_DOMAIN_WAZUH)),

    # File hash / FIM
    ("fim-eicar-finance",              fim_eicar,              ("fin1",)),
    ("fim-eicar-hr",                   fim_eicar,              ("hr1",)),
    ("sysmon-process-eicar",           sysmon_process_create_eicar, ("fin1",)),

    # Suricata C2 -- multi-IOC alert
    ("suricata-c2-multi-ioc",          suricata_alert,         ("ids1",  MAL_IP_MIRAI, MAL_IP_KOMARI)),
    ("suricata-clean-traffic",         suricata_alert,         ("ids1",  CLEAN_IP_GOOGLE, CLEAN_IP_CLOUDFLARE)),

    # MS Graph mail evidence
    ("msgraph-mail-malicious-sender",  msgraph_mail,           ("mail1", MAL_IP_KOMARI, True)),
    ("msgraph-mail-clean-sender",      msgraph_mail,           ("mail1", CLEAN_IP_SENDGRID, False)),

    # AWS CloudTrail
    ("aws-cloudtrail-malicious-src",   aws_cloudtrail,         ("dc1",   MAL_IP_MIRAI)),
]

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_alert(scenario_name, builder, args, idx):
    alert_id = f"populate.{scenario_name}.{idx:03d}"
    t = now_iso(offset_min=-(len(SCENARIOS) - idx))   # spread over time
    if "msgraph_mail" in builder.__name__:
        agent_key, ip, mal = args
        return builder(agent_key, ip, alert_id, t, malicious=mal)
    full = list(args) + [alert_id, t]
    return builder(*full)

def run_one(alert_dict, otx_key, sleep_for, dry_run=False):
    payload = json.dumps(alert_dict, indent=2)
    if dry_run:
        print(payload)
        print("---")
        return True
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, dir="/tmp"
    ) as fh:
        fh.write(payload)
        path = fh.name
    try:
        result = subprocess.run(
            [INTEGRATION_SCRIPT, path, otx_key, OTX_HOOK, "debug"],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            sys.stderr.write(f"  integration exited {result.returncode}\n")
            if result.stderr:
                sys.stderr.write(f"  stderr: {result.stderr.strip()}\n")
            return False
        return True
    except subprocess.TimeoutExpired:
        sys.stderr.write("  integration timed out\n")
        return False
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
        time.sleep(sleep_for)

def main():
    parser = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true",
                        help="Print each alert JSON instead of running it")
    parser.add_argument("--sleep", type=float, default=DEFAULT_SLEEP,
                        help=f"Seconds between OTX queries (default {DEFAULT_SLEEP})")
    parser.add_argument("--filter", default=None,
                        help="Only run scenarios whose name contains this substring")
    args = parser.parse_args()

    otx_key = os.environ.get("OTX_KEY")
    if not args.dry_run and not otx_key:
        sys.stderr.write("ERROR: set OTX_KEY env var (or use --dry-run)\n")
        return 2

    if not args.dry_run and not os.access(INTEGRATION_SCRIPT, os.X_OK):
        sys.stderr.write(f"ERROR: {INTEGRATION_SCRIPT} not found or not executable\n")
        return 2

    selected = [(n, b, a) for (n, b, a) in SCENARIOS
                if (args.filter is None or args.filter in n)]
    print(f"Running {len(selected)} scenario(s)" + (
        " (dry run)" if args.dry_run else f" (OTX hook: {OTX_HOOK})"))
    print()

    succ = 0
    fail = 0
    for idx, (name, builder, builder_args) in enumerate(selected, 1):
        print(f"[{idx:2d}/{len(selected)}] {name}")
        alert = build_alert(name, builder, builder_args, idx)
        ok = run_one(alert, otx_key, args.sleep, dry_run=args.dry_run)
        if ok:
            succ += 1
        else:
            fail += 1

    print()
    print(f"Done. {succ} succeeded, {fail} failed.")
    if not args.dry_run:
        print()
        print("Verify enriched events on the manager:")
        print("  tail -n 50 /var/ossec/logs/archives/archives.json | "
              "grep alienvault_otx | jq .")
        print()
        print("Then refresh the AlienVault OTX dashboard. Allow ~10 seconds for")
        print("OpenSearch to index the new events before they appear.")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())