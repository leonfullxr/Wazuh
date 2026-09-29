#!/usr/bin/env python3
"""Active LAN availability poller for Wazuh.

Polls a CSV list of hosts with ICMP ping and TCP connect checks, keeps the
current state in a JSON file, and sends one JSON event per check on every
round straight to the local Wazuh queue socket.

The event carries ``reachability_event`` so the rules can tell a fresh
transition from a repeat of the current state:

  {"reachability_monitor": "availability", "reachability_check": "ping",
   "reachability_server": "app-server-01", "reachability_target": "10.0.0.22",
   "reachability_timestamp": "2026-01-01 08:45:14 +0000",
   "reachability_status": "success", "reachability_reason": "reachable",
   "reachability_event": "up"}

  {"reachability_monitor": "availability", "reachability_check": "port",
   "reachability_server": "app-server-01", "reachability_target": "10.0.0.22",
   "reachability_timestamp": "2026-01-01 08:45:14 +0000",
   "reachability_port": 22, "reachability_status": "failure",
   "reachability_reason": "connection refused",
   "reachability_event": "down"}

Only the transitions (down / recovered) match alerting rules, so one outage
produces one alert and one recovery alert, while every round is still recorded.

See README.md in this directory for configuration, rules, and notification
wiring.
"""

import concurrent.futures
import csv
import errno
import json
import logging
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration: edit here, or override through environment variables
# ---------------------------------------------------------------------------
TARGETS_FILE = Path(
    os.environ.get("AVAILABILITY_TARGETS_FILE", "/etc/availability_monitor/targets.csv")
)
STATE_FILE = Path(
    os.environ.get(
        "AVAILABILITY_STATE_FILE",
        "/var/ossec/logs/availability_monitor_state.json",
    )
)

# How often a full round (ping plus port checks for every target) runs.
CHECK_INTERVAL = int(os.environ.get("AVAILABILITY_INTERVAL_SECONDS", "60"))
PING_TIMEOUT = 1        # seconds to wait for a single ICMP reply
PING_COUNT = 1          # ICMP echo requests per host per round
TCP_TIMEOUT = 2         # seconds to wait for a TCP connect on a port
MAX_WORKERS = 30        # parallel checks, so ~100 hosts x a few ports don't serialize

# --- Wazuh direct-queue settings -------------------------------------------
WAZUH_SOCKET = os.environ.get(
    "AVAILABILITY_WAZUH_SOCKET", "/var/ossec/queue/sockets/queue"
)
APP_NAME = "availability-monitor"

# Set DEBUG=1 in the environment (or run with --debug) for verbose output
# showing every socket send attempt and its outcome.
DEBUG = os.environ.get("DEBUG") == "1" or "--debug" in sys.argv

# Default level is WARNING (not INFO) so normal runs produce no stdout output
# at all. This matters because a `command` localfile pointing at this script's
# stdout would ingest every check a second time, in addition to the JSON event
# sent directly to the queue socket. Use --debug or DEBUG=1 for
# troubleshooting; that prints everything.
logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(APP_NAME)


# ---------------------------------------------------------------------------
def load_targets(path):
    """Parse the CSV target file into a list of dicts:
    {"name": "app-server-01", "target": "10.0.0.22", "ports": [22, 80, 443]}

    "target" may be an IP address or a hostname. Blank lines and lines
    starting with # are skipped. Malformed rows are skipped with a warning,
    not a crash.
    """
    targets = []
    if not path.exists():
        print(f"[availability_monitor] WARNING: targets file not found: {path}")
        return targets
    with open(path, newline="") as f:
        reader = csv.reader(f)
        for lineno, row in enumerate(reader, start=1):
            if not row or not row[0].strip() or row[0].strip().startswith("#"):
                continue
            row = [c.strip() for c in row]
            if len(row) < 2:
                print(
                    f"[availability_monitor] WARNING: skipping malformed line "
                    f"{lineno}: {row}"
                )
                continue
            name, target = row[0], row[1]
            ports = []
            for p in row[2:]:
                if not p:
                    continue
                try:
                    ports.append(int(p))
                except ValueError:
                    print(
                        f"[availability_monitor] WARNING: bad port '{p}' on "
                        f"line {lineno}, skipping it"
                    )
            targets.append({"name": name, "target": target, "ports": ports})
    return targets


def ping_host(target):
    """Return (is_up: bool, reason: str). reason is always populated."""
    try:
        result = subprocess.run(
            ["ping", "-c", str(PING_COUNT), "-W", str(PING_TIMEOUT), target],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        output = result.stdout or ""
        if result.returncode == 0:
            return True, "reachable"
        if re.search(
            r"unknown host|Name or service not known|"
            r"Temporary failure in name resolution",
            output,
            re.I,
        ):
            return False, "DNS resolution failed"
        if "Destination Host Unreachable" in output or "Destination Net Unreachable" in output:
            return False, "host unreachable (ICMP)"
        if "100% packet loss" in output:
            return False, "no reply (timeout)"
        return False, "no reply"
    except Exception as e:  # noqa: BLE001 - one bad check must not kill the round
        return False, f"ping error: {e}"


def check_port(target, port):
    """Return (is_up: bool, reason: str) for a TCP connect to target:port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(TCP_TIMEOUT)
            result = sock.connect_ex((target, port))
            if result == 0:
                return True, "connected"
            if result == errno.ECONNREFUSED:
                return False, "connection refused"
            if result == errno.ETIMEDOUT:
                return False, "connection timed out"
            reason = errno.errorcode.get(result, str(result))
            return False, f"connect failed ({reason})"
    except socket.gaierror:
        return False, "DNS resolution failed"
    except socket.timeout:
        return False, "connection timed out"
    except Exception as e:  # noqa: BLE001 - one bad check must not kill the round
        return False, f"port check error: {e}"


def load_state():
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))


def now_iso():
    return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %z")


def format_duration(seconds):
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    parts = []
    if h:
        parts.append(f"{h}h")
    if m or h:
        parts.append(f"{m}m")
    parts.append(f"{s}s")
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Wazuh queue sender
# ---------------------------------------------------------------------------
def send_wazuh_event(payload):
    """Send a JSON event straight to the local Wazuh queue socket.

    Never raises: logs on failure so one bad send cannot kill the run.
    Same wire format Wazuh's own modules use, "1:{program_name}:{json}",
    over a Unix datagram socket.
    """
    message = f"1:{APP_NAME}:{json.dumps(payload)}"
    log.debug("Preparing to send event: %s", message)
    if not os.path.exists(WAZUH_SOCKET):
        log.error(
            "Wazuh socket %s does not exist. Is the Wazuh agent/manager "
            "running? Event NOT sent: server=%s check=%s event=%s",
            WAZUH_SOCKET,
            payload.get("reachability_server"),
            payload.get("reachability_check"),
            payload.get("reachability_event"),
        )
        return
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        sent_bytes = sock.sendto(message.encode(), WAZUH_SOCKET)
        log.debug(
            "Sent %d bytes to %s for server=%s check=%s event=%s",
            sent_bytes,
            WAZUH_SOCKET,
            payload.get("reachability_server"),
            payload.get("reachability_check"),
            payload.get("reachability_event"),
        )
    except OSError as e:
        log.error("Failed to send event to wazuh queue (%s): %s", WAZUH_SOCKET, e)
    finally:
        sock.close()


# ---------------------------------------------------------------------------
def build_jobs(targets):
    jobs = []
    for t in targets:
        jobs.append(
            {
                "check": "ping",
                "name": t["name"],
                "target": t["target"],
                "key": f'{t["name"]}:ping',
            }
        )
        for port in t["ports"]:
            jobs.append(
                {
                    "check": "port",
                    "name": t["name"],
                    "target": t["target"],
                    "port": port,
                    "key": f'{t["name"]}:port:{port}',
                }
            )
    return jobs


def run_job(job):
    if job["check"] == "ping":
        is_up, reason = ping_host(job["target"])
    else:
        is_up, reason = check_port(job["target"], job["port"])
    return job["key"], is_up, reason


def run_once(targets, state):
    """One polling round.

    Sends exactly one event per check, every round, always, directly to the
    Wazuh queue socket, so current status is never silent. reachability_event
    says whether this is a fresh transition or a repeat of the current state,
    which lets the rules stay quiet on "up" and "still_down" while every check
    is still recorded.
    """
    jobs = build_jobs(targets)
    jobs_by_key = {j["key"]: j for j in jobs}
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = [pool.submit(run_job, j) for j in jobs]
        for future in concurrent.futures.as_completed(futures):
            key, is_up, reason = future.result()
            results[key] = (is_up, reason)

    timestamp = now_iso()
    changed = False
    for key, (is_up, reason) in results.items():
        job = jobs_by_key[key]
        prev = state.get(key, {"status": "unknown"})
        prev_status = prev.get("status")
        entry = {
            "reachability_monitor": "availability",
            "reachability_check": job["check"],
            "reachability_server": job["name"],
            "reachability_target": job["target"],
            "reachability_timestamp": timestamp,
            "reachability_status": "success" if is_up else "failure",
            "reachability_reason": reason,
        }
        if job["check"] == "port":
            entry["reachability_port"] = job["port"]

        if is_up:
            if prev_status == "failure":
                down_since = prev.get("down_since")
                downtime_seconds = (
                    time.time() - down_since if down_since else None
                )
                entry["reachability_event"] = "recovered"
                entry["reachability_downtime_seconds"] = (
                    round(downtime_seconds) if downtime_seconds else None
                )
                entry["reachability_downtime_human"] = (
                    format_duration(downtime_seconds) if downtime_seconds else None
                )
            else:
                entry["reachability_event"] = "up"
            new_state = {"status": "success"}
        else:
            if prev_status == "failure":
                entry["reachability_event"] = "still_down"
            else:
                entry["reachability_event"] = "down"
            new_state = {
                "status": "failure",
                "down_since": prev.get("down_since") or time.time(),
            }

        send_wazuh_event(entry)
        if new_state.get("status") != prev_status:
            changed = True
        state[key] = new_state

    if changed:
        save_state(state)
    return state


def main():
    state = load_state()
    print(
        f"[availability_monitor] starting, targets_file={TARGETS_FILE}, "
        f"interval={CHECK_INTERVAL}s, wazuh_socket={WAZUH_SOCKET}"
    )
    while True:
        start = time.time()
        # Re-read every cycle: edit the CSV, no restart needed
        targets = load_targets(TARGETS_FILE)
        if targets:
            state = run_once(targets, state)
        else:
            print("[availability_monitor] WARNING: no targets loaded this cycle")
        elapsed = time.time() - start
        time.sleep(max(0, CHECK_INTERVAL - elapsed))


if __name__ == "__main__":
    main()
