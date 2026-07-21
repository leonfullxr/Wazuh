#!/usr/bin/env python3
"""
cdb-blocklist-integration.py

Wazuh <integration> script that maintains a CDB blocklist of attacker IPs.

On each matching alert, integratord runs this script with the alert JSON file
as sys.argv[1]. The script extracts the source IP (from `data.srcip`, falling
back to parsing `srcip=` out of `full_log`) and atomically appends an entry
`<ip>:` to the CDB source list if it is not already present. A companion rule
(see README) then raises a high-severity alert whenever a new event arrives
from an IP already on the list.

Why an integration and not an <active-response> command: appending to a shared
list from the AR execution context is unreliable across versions; the
integration hook runs the script cleanly on every matching alert instead.

Install (on every manager):
  cp cdb-blocklist-integration.py /var/ossec/integrations/
  chown root:wazuh /var/ossec/integrations/cdb-blocklist-integration.py
  chmod 750       /var/ossec/integrations/cdb-blocklist-integration.py
Then wire it up in ossec.conf with an <integration> block (see README).

Note: integratord invokes scripts by exact filename. If you rename this file,
keep the <name> in ossec.conf in sync.
"""
import sys
import json
import os
import logging
from logging.handlers import TimedRotatingFileHandler

# Configuration paths - adjust to taste.
TXT_LIST = '/var/ossec/etc/lists/blacklist-custom'
LOG_DIR = '/var/log/cdb-blocklist'
LOG_FILE = os.path.join(LOG_DIR, 'cdb-blocklist.log')

os.makedirs(LOG_DIR, exist_ok=True)


def setup_logger():
    logger = logging.getLogger('cdb-blocklist')
    logger.setLevel(logging.DEBUG)
    handler = TimedRotatingFileHandler(LOG_FILE, when='midnight', backupCount=7)
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    logger.addHandler(handler)
    return logger


logger = setup_logger()


def error_exit(message, code=1):
    """Log an error, print it, and exit non-zero."""
    logger.error(message)
    print(f"ERROR: {message}")
    sys.exit(code)


def extract_srcip(alert):
    """Return the source IP from the alert, or exit if none is found.

    Tries the structured `data.srcip` field first, then falls back to
    parsing a `srcip=<ip>` token out of the raw `full_log`.
    """
    ip = None
    try:
        ip = alert.get('data', {}).get('srcip')
    except Exception:
        ip = None

    if not ip:
        raw = alert.get('full_log', '')
        if isinstance(raw, str):
            for token in raw.split():
                if token.startswith('srcip='):
                    ip = token.split('=', 1)[1]
                    break

    if not ip:
        error_exit("No 'srcip' field found in JSON alert or 'full_log'")
    return ip


def append_entry(ip):
    """Append `<ip>:` to the CDB source list if it is not already present."""
    entry = f"{ip}:"
    try:
        existing = set()
        if os.path.exists(TXT_LIST):
            with open(TXT_LIST, 'r') as f:
                for line in f:
                    ln = line.strip()
                    if ln:
                        existing.add(ln)
        if entry in existing:
            logger.info(f"Entry already present: {entry}")
        else:
            with open(TXT_LIST, 'a') as f:
                f.write(entry + '\n')
            logger.info(f"Appended entry: {entry}")
    except Exception as e:
        error_exit(f"Failed updating '{TXT_LIST}': {e}")


def main():
    if len(sys.argv) < 2:
        error_exit("Integration invocation requires the alert JSON file path as sys.argv[1]")
    alert_file = sys.argv[1]
    logger.debug(f"Alert file path: {alert_file}")

    if not os.path.isfile(alert_file):
        error_exit(f"Alert JSON file does not exist: {alert_file}")
    try:
        with open(alert_file, 'r') as f:
            alert = json.load(f)
        logger.debug("Loaded alert JSON successfully")
    except Exception as e:
        error_exit(f"Failed to parse alert JSON '{alert_file}': {e}")

    ip = extract_srcip(alert)
    append_entry(ip)

    logger.info("cdb-blocklist completed successfully")
    sys.exit(0)


if __name__ == '__main__':
    main()
