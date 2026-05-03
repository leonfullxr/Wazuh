#!/var/ossec/framework/python/bin/python3
"""
Wazuh integration: AlienVault OTX threat intelligence enrichment.

For each Wazuh alert that crosses the configured level threshold, this
script extracts indicators of compromise (source/destination IPs,
domains, and SHA-256 file hashes), queries the AlienVault OTX
``/api/v1/indicators/.../general`` endpoint for each one, and emits an
enriched event back to the Wazuh queue with a per-indicator verdict
(``malicious`` / ``clean`` / ``unknown``) plus an overall summary
verdict for the alert.

Reliability:

  * Enriched events that fail to reach the Wazuh manager queue socket
    are saved to a local queue file and re-sent on the next invocation.
  * Alerts whose enrichment fails because OTX is unreachable are saved
    to a per-alert holding directory. On the next invocation, an OTX
    health check is performed; if successful, all queued alerts are
    re-enriched and emitted.

Invocation (Wazuh manager):
    custom-alienvault.py <alert_path> <api_key> <hook_url> [debug]

Where:
    alert_path  Path to the alert JSON written by Wazuh.
    api_key     OTX API key (X-OTX-API-KEY header value).
    hook_url    OTX base URL, typically https://otx.alienvault.com
    debug       Optional literal "debug" to enable DEBUG-level logging.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from socket import socket, AF_UNIX, SOCK_DGRAM
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Service identification
SERVICE_NAME = "wazuh-alienvault-integration"
INTEGRATION_TAG = "alienvault_otx"

# Filesystem layout
LOG_DIR = Path("/var/log/wazuh-alienvault")
LOG_FILE = LOG_DIR / "custom-alienvault.log"
SOCKET_ADDR = "/var/ossec/queue/sockets/queue"

# Queue locations
QUEUE_FILE_DIR = LOG_DIR / "wazuh-retry-queue"
QUEUE_FILE = QUEUE_FILE_DIR / "alienvault_queue.json"
QUEUE_TMP = QUEUE_FILE.with_suffix(".inprocess")
FAILED_OTX_ALERTS_DIR = LOG_DIR / "otx-failed-enrichment"

# Exit codes
ERR_OTX_UNREACHABLE = 10
ERR_SOCKET_OPERATION = 11
ERR_INVALID_JSON = 12
ERR_BAD_ARGUMENTS = 13

# OTX query parameters
OTX_TIMEOUT_SECONDS = 15
OTX_HEALTHCHECK_TIMEOUT_SECONDS = 5
USER_AGENT = "Wazuh-AlienVault-OTX-Integration/2.1"

# Confidence tiers based on OTX pulse_info.count
HIGH_CONFIDENCE_PULSES = 5
MEDIUM_CONFIDENCE_PULSES = 2

# Cap details so the enriched alert payload stays compact
MAX_PULSE_DETAIL_ITEMS = 5

# Patterns
SHA256_HEX_PATTERN = re.compile(r"^[A-Fa-f0-9]{64}$")
SHA256_IN_HASHES_STRING = re.compile(r"SHA256=([A-Fa-f0-9]{64})")


# ---------------------------------------------------------------------------
# IOC field registry
# ---------------------------------------------------------------------------

SUPPORTED_FIELD_PATHS: Dict[str, List[str]] = {
    "src_ip": [
        "srcip",
        "data.srcip",
        "data.nat_source_ip",
        "data.aws.ClientIP",
        "data.aws.source_ip_address",
        "data.aws.sourceIPAddress",
        "data.win.eventdata.ipAddress",
        "data.office365.ClientIPAddress",
        "data.office365.ClientIP",
        "data.office365.SenderIp",
        "data.gcp.jsonPayload.sourceIP",
        "data.azure.properties.ipAddress",
        "data.suricata.src_ip",
        "data.zeek.id_orig_h",
    ],
    "dst_ip": [
        "dstip",
        "data.dstip",
        "data.aws.destinationIPAddress",
        "data.win.eventdata.destinationIp",
        "data.suricata.dest_ip",
        "data.zeek.id_resp_h",
    ],
    "domain": [
        "domain",
        "data.domain",
        "data.fqdn",
        "data.hostname",
        "data.win.eventdata.queryName",
        "data.win.eventdata.destinationHostname",
        "data.dns.query",
        "data.suricata.dns.rrname",
    ],
    "file_hash": [
        "syscheck.sha256_after",
        "data.osquery.columns.sha256",
        "data.virustotal.source.sha256",
    ],
}


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(SERVICE_NAME)


def setup_logging(debug: bool = False) -> None:
    """Configure rotating-file logging to /var/log/wazuh-alienvault/."""
    level = logging.DEBUG if debug else logging.INFO
    logger.setLevel(level)

    # Idempotent: don't add duplicate handlers on re-import / repeat calls.
    if logger.handlers:
        return

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        # Fall back to stderr-only logging if we can't create the dir.
        sys.stderr.write(f"WARN: cannot create {LOG_DIR}: {e}\n")
    else:
        # 10MB per file, 5 backups -- ~60MB total before old logs are dropped.
        try:
            file_handler = RotatingFileHandler(
                LOG_FILE, maxBytes=10_000_000, backupCount=5, encoding="utf-8"
            )
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except OSError as e:
            sys.stderr.write(f"WARN: cannot open log file {LOG_FILE}: {e}\n")

    # Stream handler so stderr captures any output if Wazuh runs the script
    # interactively (e.g. for testing).
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    logger.propagate = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_nested(obj: Any, dotted_path: str) -> Any:
    """Walk a dotted path through nested dicts. Returns None if any segment is missing."""
    cur = obj
    for part in dotted_path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
        if cur is None:
            return None
    return cur


def first_match(alert: Dict[str, Any], paths: Iterable[str]) -> Optional[Any]:
    """Return the first non-empty value found at any of the given dotted paths."""
    for path in paths:
        val = get_nested(alert, path)
        if val not in (None, "", [], {}):
            return val
    return None


def is_public_ip(value: Any) -> bool:
    """True only for globally-routable IPs."""
    if not value:
        return False
    try:
        return ipaddress.ip_address(str(value)).is_global
    except ValueError:
        return False


def is_valid_domain(value: Any) -> bool:
    """Reject values that are clearly not queryable as a domain."""
    if not isinstance(value, str):
        return False
    v = value.strip()
    if not v or len(v) < 4 or " " in v or "\t" in v or "." not in v:
        return False
    try:
        ipaddress.ip_address(v)
        return False
    except ValueError:
        return True


def clean_domain(value: Optional[str]) -> Optional[str]:
    """Strip scheme/path/port/query so OTX gets a bare hostname."""
    if not value:
        return None
    v = str(value).strip().lower()
    for scheme in ("http://", "https://", "ftp://"):
        if v.startswith(scheme):
            v = v[len(scheme):]
            break
    for sep in ("/", "?", "#"):
        if sep in v:
            v = v.split(sep, 1)[0]
    if ":" in v and not v.startswith("["):
        v = v.split(":", 1)[0]
    return v or None


# ---------------------------------------------------------------------------
# Indicator extraction
# ---------------------------------------------------------------------------

def iter_msgraph_evidence(alert: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    evidence = get_nested(alert, "data.ms-graph.evidence")
    if isinstance(evidence, list):
        for item in evidence:
            if isinstance(item, dict):
                yield item
    elif isinstance(evidence, dict):
        yield evidence


def extract_src_ip(alert: Dict[str, Any]) -> Optional[str]:
    ip = first_match(alert, SUPPORTED_FIELD_PATHS["src_ip"])
    if ip:
        return str(ip)
    for ev in iter_msgraph_evidence(alert):
        ip = ev.get("ipAddress") or ev.get("senderIp")
        if ip:
            return str(ip)
    return None


def extract_dst_ip(alert: Dict[str, Any]) -> Optional[str]:
    ip = first_match(alert, SUPPORTED_FIELD_PATHS["dst_ip"])
    return str(ip) if ip else None


def extract_domain(alert: Dict[str, Any]) -> Optional[str]:
    domain = first_match(alert, SUPPORTED_FIELD_PATHS["domain"])
    if domain:
        return str(domain)

    for ev in iter_msgraph_evidence(alert):
        for url_key in ("url", "urls"):
            value = ev.get(url_key)
            if isinstance(value, str) and value:
                return value
            if isinstance(value, list) and value:
                first = value[0]
                if isinstance(first, str) and first:
                    return first
                if isinstance(first, dict) and first.get("url"):
                    return first["url"]
        for sender_key in ("p1Sender", "p2Sender", "sender"):
            sender = ev.get(sender_key)
            if isinstance(sender, dict):
                if sender.get("domainName"):
                    return sender["domainName"]
                email = sender.get("emailAddress")
                if email and "@" in email:
                    return email.split("@", 1)[1]
    return None


def extract_sha256_hash(alert: Dict[str, Any]) -> Optional[str]:
    eventdata = get_nested(alert, "data.win.eventdata") or {}
    hashes_str = eventdata.get("hashes") or eventdata.get("Hashes") or ""
    if hashes_str:
        match = SHA256_IN_HASHES_STRING.search(hashes_str)
        if match:
            logger.debug("Found SHA-256 in data.win.eventdata.hashes")
            return match.group(1)

    val = first_match(alert, SUPPORTED_FIELD_PATHS["file_hash"])
    if isinstance(val, str) and SHA256_HEX_PATTERN.match(val):
        return val

    for ev in iter_msgraph_evidence(alert):
        details = ev.get("fileDetails")
        if isinstance(details, dict):
            sha256 = details.get("sha256") or details.get("sha256Ac")
            if sha256:
                logger.debug("Found SHA-256 in MS Graph fileEvidence")
                return sha256
    return None


def extract_file_path(alert: Dict[str, Any]) -> Optional[str]:
    return (
        get_nested(alert, "data.win.eventdata.Image")
        or get_nested(alert, "data.win.eventdata.image")
        or get_nested(alert, "syscheck.path")
    )


def extract_windows_event_fields(alert: Dict[str, Any]) -> Dict[str, Any]:
    eventdata = get_nested(alert, "data.win.eventdata") or {}
    field_aliases = {
        "image": ("image", "Image"),
        "parentImage": ("parentImage", "ParentImage"),
        "parentProcessId": ("parentProcessId", "ParentProcessId"),
        "processId": ("processId", "ProcessId"),
        "currentDirectory": ("currentDirectory", "CurrentDirectory"),
    }

    extracted = {}
    for output_key, candidate_keys in field_aliases.items():
        for candidate_key in candidate_keys:
            if eventdata.get(candidate_key) is not None:
                extracted[output_key] = eventdata[candidate_key]
                break
    return extracted


# ---------------------------------------------------------------------------
# OTX queries
# ---------------------------------------------------------------------------

def _otx_request(
    url: str, api_key: str, timeout: float = OTX_TIMEOUT_SECONDS
) -> Tuple[Optional[Dict[str, Any]], bool]:
    """Issue a GET to OTX. Returns (data_or_none, is_recoverable_failure).

    is_recoverable_failure=True signals that the alert should be queued for
    later retry. False means either a successful response (data set) or a
    permanent failure that retrying won't fix (auth, malformed JSON, 404).
    """
    headers = {"X-OTX-API-KEY": api_key, "User-Agent": USER_AGENT}
    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
        logger.warning(f"OTX network failure for {url}: {e}")
        return None, True
    except requests.exceptions.RequestException as e:
        logger.warning(f"OTX request failed for {url}: {e}")
        return None, True

    if resp.status_code == 401:
        logger.error("OTX returned 401 Unauthorized -- check the api_key.")
        return None, False
    if resp.status_code == 429:
        logger.warning("OTX rate limit hit (429). Will retry later.")
        return None, True
    if resp.status_code == 404:
        logger.debug(f"OTX 404 for {url} (indicator not in OTX).")
        return None, False
    if resp.status_code >= 500:
        logger.warning(f"OTX server error {resp.status_code} for {url}.")
        return None, True
    if not resp.ok:
        logger.warning(f"OTX returned HTTP {resp.status_code} for {url}.")
        return None, False

    try:
        return resp.json(), False
    except ValueError:
        logger.warning(f"OTX returned non-JSON response for {url}.")
        return None, False


def query_otx(
    indicator_type: str, value: str, api_key: str, hook_url: str
) -> Tuple[Optional[Dict[str, Any]], bool]:
    """Query OTX /general for IPv4, domain, or file (SHA-256).

    Returns (data, is_recoverable_failure) -- see _otx_request.
    """
    base = hook_url.rstrip("/")
    if indicator_type in ("src_ip", "dst_ip"):
        url = f"{base}/api/v1/indicators/IPv4/{value}/general"
    elif indicator_type == "domain":
        url = f"{base}/api/v1/indicators/domain/{value}/general"
    elif indicator_type == "file_hash":
        url = f"{base}/api/v1/indicators/file/{value}/general"
    else:
        return None, False

    data, is_failure = _otx_request(url, api_key)
    if data and "pulse_info" in data:
        return data, False
    return None, is_failure


def otx_is_reachable(api_key: str, hook_url: str) -> bool:
    """Quick health check using /api/v1/user/me."""
    url = f"{hook_url.rstrip('/')}/api/v1/user/me"
    try:
        resp = requests.get(
            url,
            headers={"X-OTX-API-KEY": api_key, "User-Agent": USER_AGENT},
            timeout=OTX_HEALTHCHECK_TIMEOUT_SECONDS,
        )
        return resp.status_code == 200
    except requests.exceptions.RequestException as e:
        logger.warning(f"OTX healthcheck failed: {e}")
        return False


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

def evaluate_verdict(otx_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:

    if not otx_data:
        return {
            "malicious": False,
            "verdict": "unknown",
            "confidence": "unknown",
            "reason": "no_otx_response_or_query_failed",
        }

    pulse_info = otx_data.get("pulse_info") or {}
    pulse_count = int(pulse_info.get("count", 0) or 0)
    pulses = pulse_info.get("pulses") or []

    pulse_names: List[str] = []
    adversaries: List[str] = []
    malware_families: List[str] = []

    for p in pulses:
        if len(pulse_names) < MAX_PULSE_DETAIL_ITEMS and p.get("name"):
            pulse_names.append(p["name"])
        adv = p.get("adversary")
        if adv and adv not in adversaries and len(adversaries) < MAX_PULSE_DETAIL_ITEMS:
            adversaries.append(adv)
        for fam in (p.get("malware_families") or []):
            name = fam.get("display_name") if isinstance(fam, dict) else fam
            if name and name not in malware_families and len(malware_families) < MAX_PULSE_DETAIL_ITEMS:
                malware_families.append(name)

    if pulse_count <= 0:
        return {
            "malicious": False,
            "verdict": "clean",
            "confidence": "high",
            "pulse_count": 0,
            "reason": "no_otx_pulses",
        }

    if pulse_count >= HIGH_CONFIDENCE_PULSES:
        confidence = "high"
    elif pulse_count >= MEDIUM_CONFIDENCE_PULSES:
        confidence = "medium"
    else:
        confidence = "low"

    return {
        "malicious": True,
        "verdict": "malicious",
        "confidence": confidence,
        "pulse_count": pulse_count,
        "pulse_names": pulse_names,
        "adversaries": adversaries,
        "malware_families": malware_families,
    }


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def is_public_ipv4(value: str) -> bool:
    try:
        parsed_ip = ipaddress.ip_address(value)
    except ValueError:
        return False

    return parsed_ip.version == 4 and parsed_ip.is_global


def collect_indicators(alert: Dict[str, Any]) -> Dict[str, str]:
    indicators: Dict[str, str] = {}

    src_ip = extract_src_ip(alert)
    if src_ip and is_public_ipv4(src_ip):
        indicators["src_ip"] = src_ip
    elif src_ip:
        logger.debug(f"Skipping non-public or non-IPv4 src_ip: {src_ip}")

    dst_ip = extract_dst_ip(alert)
    if dst_ip and is_public_ipv4(dst_ip):
        indicators["dst_ip"] = dst_ip
    elif dst_ip:
        logger.debug(f"Skipping non-public or non-IPv4 dst_ip: {dst_ip}")

    domain = extract_domain(alert)
    if domain:
        cleaned = clean_domain(domain)
        if cleaned and is_valid_domain(cleaned):
            indicators["domain"] = cleaned
        else:
            logger.debug(f"Skipping invalid/IP-like domain: {domain!r}")

    file_hash = extract_sha256_hash(alert)
    if file_hash:
        indicators["file_hash"] = file_hash

    return indicators


def enrich_alert(
    alert: Dict[str, Any], api_key: str, hook_url: str
) -> Tuple[Optional[Dict[str, Any]], bool]:
    """Enrich one alert with OTX data.

    Returns (enriched_event, all_otx_unreachable):

      * (event, False) -- normal case, emit the event.
      * (None,  True ) -- every OTX query for this alert was a recoverable
                          failure. Caller should queue the alert.
      * (event, False) for partial failures: emit what we have.
    """
    indicators = collect_indicators(alert)
    if not indicators:
        logger.info("No queryable indicators found in alert.")
        minimal_event: Dict[str, Any] = {
            "integration": INTEGRATION_TAG,
            "original_rule": get_nested(alert, "rule.id"),
            "input_alert": alert.get("id"),
            "overall_malicious": False,
            "overall_verdict": "no_indicators",
            "reason": "no_indicators",
        }

        win_fields = extract_windows_event_fields(alert)
        if win_fields:
            minimal_event["windows_event_data"] = win_fields
        else:
            file_path = extract_file_path(alert)
            if file_path:
                minimal_event["file_path"] = file_path

        return ({k: v for k, v in minimal_event.items() if v not in (None, [], {})}, False)

    enriched_indicators: Dict[str, Dict[str, Any]] = {}
    recoverable_failures = 0

    for ioc_type, value in indicators.items():
        otx_data, is_failure = query_otx(ioc_type, value, api_key, hook_url)
        if is_failure:
            recoverable_failures += 1
        verdict = evaluate_verdict(otx_data)
        block = {
            "value": value,
            "malicious": verdict["malicious"],
            "verdict": verdict["verdict"],
            "confidence": verdict["confidence"],
            "pulse_count": verdict.get("pulse_count"),
            "pulse_names": verdict.get("pulse_names"),
            "adversaries": verdict.get("adversaries"),
            "malware_families": verdict.get("malware_families"),
            "reason": verdict.get("reason"),
        }
        enriched_indicators[ioc_type] = {
            k: v for k, v in block.items() if v not in (None, [], {})
        }

    # If every single query had a recoverable failure, queue rather than emit.
    if recoverable_failures == len(indicators) and len(indicators) > 0:
        logger.warning(
            f"All {len(indicators)} OTX queries failed for alert "
            f"{alert.get('id', '?')}. Queuing for retry."
        )
        return None, True

    any_malicious = any(v.get("malicious") for v in enriched_indicators.values())
    all_clean = all(v.get("verdict") == "clean" for v in enriched_indicators.values())
    overall = "malicious" if any_malicious else ("clean" if all_clean else "partial_unknown")

    enriched: Dict[str, Any] = {
        "integration": INTEGRATION_TAG,
        "original_rule": get_nested(alert, "rule.id"),
        "input_alert": alert.get("id"),
        "overall_malicious": any_malicious,
        "overall_verdict": overall,
        "indicators": enriched_indicators,
    }

    win_fields = extract_windows_event_fields(alert)
    if win_fields:
        enriched["windows_event_data"] = win_fields
    else:
        file_path = extract_file_path(alert)
        if file_path:
            enriched["file_path"] = file_path

    return ({k: v for k, v in enriched.items() if v not in (None, [], {})}, False)


# ---------------------------------------------------------------------------
# Send event with socket-failure queue
# ---------------------------------------------------------------------------

def _build_socket_line(msg: Dict[str, Any], agent: Optional[Dict[str, Any]]) -> str:
    if not agent:
        return f"1:{INTEGRATION_TAG}:{json.dumps(msg, separators=(',', ':'))}"

    agent_id = agent.get("id")
    if not agent_id or agent_id == "000":
        return f"1:{INTEGRATION_TAG}:{json.dumps(msg, separators=(',', ':'))}"

    agent_str = f"[{agent_id}] ({agent.get('name', '?')}) {agent.get('ip', 'any')}"
    return f"1:{agent_str}->{INTEGRATION_TAG}:{json.dumps(msg, separators=(',', ':'))}"


def _send_to_socket(line: str) -> bool:
    """Try to send a single pre-formatted line to the Wazuh queue socket."""
    try:
        with socket(AF_UNIX, SOCK_DGRAM) as sock:
            sock.connect(SOCKET_ADDR)
            sock.send(line.encode())
        return True
    except FileNotFoundError:
        logger.error(f"Wazuh queue socket not found at {SOCKET_ADDR}")
        return False
    except OSError as e:
        logger.error(f"Failed to send to Wazuh queue socket: {e}")
        return False


def send_event(msg: Dict[str, Any], agent: Optional[Dict[str, Any]] = None) -> None:
    line = _build_socket_line(msg, agent)
    logger.debug(f"Sending event to queue ({len(line)} bytes)")
    if not _send_to_socket(line):
        logger.warning("Could not deliver event to socket; queuing for retry.")
        save_to_queue(line)


# ---------------------------------------------------------------------------
# Socket-retry queue (events that failed to reach the Wazuh queue socket)
# ---------------------------------------------------------------------------

def save_to_queue(socket_line: str) -> None:
    try:
        QUEUE_FILE_DIR.mkdir(parents=True, exist_ok=True)
        with open(QUEUE_FILE, "a", encoding="utf-8") as f:
            f.write(socket_line + "\n")
        logger.info("Event saved to socket-retry queue.")
    except OSError as e:
        logger.error(f"Failed to write event to retry queue: {e}")


def process_queue() -> None:
    """Re-send any socket-queue events from previous runs."""
    # Recover any leftover QUEUE_TMP left behind by a previously interrupted run.
    if QUEUE_TMP.exists():
        if QUEUE_FILE.exists():
            # Both files exist: merge the leftover temp entries into the main queue
            # file so they are processed together, then remove the temp file.
            try:
                with open(QUEUE_TMP, "r", encoding="utf-8") as tmp_f:
                    leftover = tmp_f.read()
                with open(QUEUE_FILE, "a", encoding="utf-8") as q_f:
                    q_f.write(leftover)
                QUEUE_TMP.unlink()
            except OSError as e:
                logger.error(f"Failed to merge leftover temp queue file: {e}")
                return
        else:
            # Only QUEUE_TMP exists: rename it back so the normal path processes it.
            try:
                QUEUE_TMP.rename(QUEUE_FILE)
            except OSError as e:
                logger.error(f"Failed to rename temp queue file for reprocessing: {e}")
                return

    if not QUEUE_FILE.exists():
        return

    try:
        QUEUE_FILE.rename(QUEUE_TMP)
    except OSError as e:
        logger.error(f"Failed to rotate socket queue file: {e}")
        return

    failed: List[str] = []
    try:
        with open(QUEUE_TMP, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.rstrip("\n")
                if not line:
                    continue
                if _send_to_socket(line):
                    logger.info("Re-sent queued event successfully.")
                else:
                    failed.append(line)
    except OSError as e:
        logger.error(f"Failed to read socket queue: {e}")
        # Rename QUEUE_TMP back to QUEUE_FILE so data is not lost on the next run.
        try:
            QUEUE_TMP.rename(QUEUE_FILE)
        except OSError as rename_err:
            logger.error(f"Failed to recover queue after read error: {rename_err}")
        return

    if failed:
        try:
            with open(QUEUE_FILE, "w", encoding="utf-8") as f:
                f.write("\n".join(failed) + "\n")
            logger.warning(f"{len(failed)} event(s) still queued after retry.")
        except OSError as e:
            logger.error(f"Failed to restore failed events to queue: {e}")

    # Always clean up QUEUE_TMP once processing is complete (success or partial failure).
    try:
        if QUEUE_TMP.exists():
            QUEUE_TMP.unlink()
    except OSError as e:
        logger.error(f"Failed to remove temp queue file: {e}")


# ---------------------------------------------------------------------------
# Failed-enrichment queue (alerts that couldn't reach OTX at all)
# ---------------------------------------------------------------------------

def save_failed_otx_alert(alert: Dict[str, Any]) -> None:
    try:
        FAILED_OTX_ALERTS_DIR.mkdir(parents=True, exist_ok=True)
        alert_id = str(alert.get("id", "unknown")).replace("/", "_").replace(".", "_")
        target = FAILED_OTX_ALERTS_DIR / f"alert_{alert_id}.json"
        with open(target, "w", encoding="utf-8") as f:
            json.dump(alert, f, separators=(",", ":"))
        logger.warning(
            f"Alert {alert.get('id', '?')} stored at {target} for later "
            f"OTX enrichment retry."
        )
    except OSError as e:
        logger.error(f"Failed to store unenriched alert for retry: {e}")


def process_failed_otx_alerts(api_key: str, hook_url: str) -> None:
    """Re-enrich every alert in the failed-enrichment dir if OTX is back."""
    if not FAILED_OTX_ALERTS_DIR.exists():
        return

    pending = list(FAILED_OTX_ALERTS_DIR.glob("alert_*.json"))
    if not pending:
        return

    if not otx_is_reachable(api_key, hook_url):
        logger.info(
            f"OTX still unreachable; leaving {len(pending)} alert(s) in "
            f"the failed-enrichment queue."
        )
        return

    logger.info(f"OTX is reachable. Retrying {len(pending)} queued alert(s).")

    for alert_file in pending:
        try:
            with open(alert_file, "r", encoding="utf-8") as f:
                alert = json.load(f)
        except (OSError, ValueError) as e:
            logger.error(f"Could not read {alert_file}: {e}")
            continue

        enriched, all_failed = enrich_alert(alert, api_key, hook_url)
        if all_failed:
            # OTX went down again mid-batch. Leave this and remaining files
            # in place for the next run.
            logger.warning(
                "OTX queries failed during retry; aborting remaining batch."
            )
            return
        if enriched is not None:
            send_event(enriched, alert.get("agent"))

        try:
            alert_file.unlink()
            logger.info(f"Successfully reprocessed {alert_file.name}.")
        except OSError as e:
            logger.error(f"Failed to remove processed alert {alert_file}: {e}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: List[str]) -> int:
    if len(argv) < 4:
        sys.stderr.write(
            f"Usage: {argv[0]} <alert_path> <api_key> <hook_url> [debug]\n"
        )
        return ERR_BAD_ARGUMENTS

    alert_path, api_key, hook_url = argv[1], argv[2], argv[3]
    debug = len(argv) > 4 and argv[4] == "debug"
    setup_logging(debug=debug)

    logger.info(f"Starting; alert={alert_path} hook_url={hook_url}")

    # Drain any pending socket-retry events first. These are independent of
    # OTX availability -- they just need the local Wazuh socket to be up.
    process_queue()

    # Then, if there are any alerts whose previous enrichment failed because
    # OTX was unreachable, retry them now (an OTX healthcheck gates this).
    process_failed_otx_alerts(api_key, hook_url)

    # Process the current alert.
    try:
        with open(alert_path, "r", encoding="utf-8") as f:
            alert = json.load(f)
    except (OSError, ValueError) as e:
        logger.error(f"Failed to read or parse alert file {alert_path}: {e}")
        return ERR_INVALID_JSON

    # Convenience for ad-hoc testing: unwrap raw Elasticsearch documents.
    if isinstance(alert.get("_source"), dict) and "data" not in alert:
        logger.debug("Unwrapping Elasticsearch _source envelope.")
        alert = alert["_source"]

    enriched, all_failed = enrich_alert(alert, api_key, hook_url)
    if all_failed:
        save_failed_otx_alert(alert)
        return ERR_OTX_UNREACHABLE

    if enriched is not None:
        send_event(enriched, alert.get("agent"))

    logger.info("Done.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Exception as e:
        logging.getLogger(SERVICE_NAME).exception(f"Unhandled exception: {e}")
        sys.exit(1)