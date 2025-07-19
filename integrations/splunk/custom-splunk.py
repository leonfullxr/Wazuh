#!/var/ossec/framework/python/bin/python3

import sys
import os
import json
import logging
import time
from argparse import ArgumentParser
from pathlib import Path
from urllib.parse import urlparse

# === Constants ===
CONTENT_TYPE = "application/json"
TIMEOUT_CONNECT = 5.0
TIMEOUT_READ = 30.0
DEBUG = False

ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS     = 2
ERR_FILE_NOT_FOUND    = 6
ERR_INVALID_JSON      = 7

# ### Constants ###############################################################
CONTENT_TYPE = "application/json"
TIMEOUT_CONNECT = 5.0  # seconds
TIMEOUT_READ = 30.0    # seconds
TOKEN_PREFIX = "Splunk:"
DEBUG = False # Set to true for debugging 

# ### HTTP library ###############################################################
try:
    import urllib3
    from urllib3.exceptions import InsecureRequestWarning
except ImportError:
    print("Error: urllib3 library is required but not installed.", file=sys.stderr)
    sys.exit(ERR_NO_REQUEST_MODULE)
import warnings
warnings.filterwarnings('ignore', category=InsecureRequestWarning)

# ### Configuration ###############################################################
LOG_DIR      = Path("/var/log/custom-splunk")
LOG_FILE     = LOG_DIR / "custom-splunk.log"
QUEUE_FILE = LOG_DIR / "splunk_queue.json"
QUEUE_TMP = LOG_DIR / "splunk_queue.json.inprocess"

# ### Logging Setup ###############################################################
def setup_logging() -> logging.Logger:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    
    logger = logging.getLogger("splunk_soar")
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    handler = logging.FileHandler(str(LOG_FILE), encoding="utf-8")
    handler.setFormatter(fmt)
    logger.addHandler(handler)
    return logger

# ### Helpers ###############################################################
def validate_token(raw: str, logger: logging.Logger) -> str:
    if not raw.startswith(TOKEN_PREFIX):
        logger.error("API token must start with '%s'.", TOKEN_PREFIX)
        sys.exit(ERR_BAD_ARGUMENTS)
    token = raw.split(":", 1)[1]
    if not token:
        logger.error("API token missing value after '%s'.", TOKEN_PREFIX)
        sys.exit(ERR_BAD_ARGUMENTS)
    return token

def validate_url(url: str, logger: logging.Logger):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        logger.error("Invalid hook URL: '%s'", url)
        sys.exit(ERR_BAD_ARGUMENTS)

def load_event(path: Path, logger: logging.Logger) -> dict:
    if not path.is_file():
        logger.error("Event file not found: '%s'", path)
        sys.exit(ERR_FILE_NOT_FOUND)
    try:
        with path.open(encoding="latin-1") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        logger.error("Malformed JSON in '%s': %s", path, e)
        sys.exit(ERR_INVALID_JSON)
    except Exception as e:
        logger.error("Cannot read event file '%s': %s", path, e)
        sys.exit(ERR_FILE_NOT_FOUND)

def build_container_payload(event: dict) -> dict:
    """
    Construct the SOAR container JSON payload from a Wazuh event.
    """
    level = event.get("rule", {}).get("level", 0)
    severity = "high" if level >= 15 else "medium"
    return {
        "name": f"Custom Wazuh alert - {event.get('rule', {}).get('description', 'wazuh_event')}",
        "description": json.dumps(event),
        "severity": severity,
        "artifacts": [
            {
                "label": "event",
                "name": "wazuh",
                "cef": event,
                "type": "custom_wazuh"
            }
        ]
    }

def send_payload(hook_url: str, token: str, container: dict, logger) -> None:
    """
    Send the JSON payload to Splunk SOAR and handle errors.
    Exits on failure with relevant sys.exit code.
    """
    http = urllib3.PoolManager(cert_reqs="CERT_NONE")
    headers = {
        "Content-Type": CONTENT_TYPE,
        "ph-auth-token": token
    }
    timeout = urllib3.Timeout(connect=TIMEOUT_CONNECT, read=TIMEOUT_READ)

    try:
        resp = http.request("POST", hook_url, headers=headers,
                            body=json.dumps(container), timeout=timeout)
    except Exception as e:
        logger.error("HTTP request failed: %s", e)
        sys.exit(ERR_BAD_ARGUMENTS)

    body = resp.data.decode("utf-8", errors="ignore")
    if resp.status >= 400:
        logger.error("Webhook POST error %s: %s", resp.status, body)
        sys.exit(resp.status)

    logger.info("Webhook POST succeeded: %s", body)

def queue_event(container: dict):
    try:
        with open(QUEUE_FILE, "a") as f:
            f.write(json.dumps(container) + "\n")
        logging.warning("Event queued due to webhook failure.")
    except Exception as e:
        logging.error(f"Failed to queue event: {e}")

def process_queue(hook_url: str, token: str):
    if not QUEUE_FILE.exists():
        return

    try:
        os.rename(QUEUE_FILE, QUEUE_TMP)
    except Exception as e:
        logging.error(f"Could not rotate queue file: {e}")
        return

    failed = []
    with open(QUEUE_TMP, "r") as f:
        for line in f:
            try:
                container = json.loads(line)
                if not send_payload(hook_url, token, container):
                    failed.append(line)
            except Exception as e:
                logging.error(f"Queue replay failed: {e}")
                failed.append(line)

    if failed:
        try:
            with open(QUEUE_FILE, "a") as f:
                f.writelines(failed)
        except Exception as e:
            logging.error(f"Could not restore failed events: {e}")

    try:
        os.remove(QUEUE_TMP)
    except Exception as e:
        logging.error(f"Failed to remove temp queue: {e}")

# === Main ===
def main():
    # 1) Set up logging first
    logger = setup_logging()

    # 2) Declare our ArgumentParser and grab only the first three positional args + debug flag
    p = ArgumentParser(
        description="Send a Wazuh alert to Splunk SOAR via HTTP webhook."
    )
    p.add_argument("event_file", type=Path,
                   help="Path to the Wazuh event JSON file.")
    p.add_argument("api_token",
                   help=f"API token prefixed with '{TOKEN_PREFIX}'.")
    p.add_argument("hook_url",
                   help="Full URL to the Splunk SOAR webhook endpoint.")
    p.add_argument("-d", "--debug", action="store_true",
                   help="Enable debug-level logging.")

    args, extras = p.parse_known_args()


    # 3) Bump to DEBUG if requested
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")

    # 4) Log everything we got
    if DEBUG:
        logger.info("RAW ARGV: %r", sys.argv)
        if extras:
            logger.info("Ignoring extra args: %r", extras)

    # 5) Validate inputs
    token = validate_token(args.api_token, logger)
    validate_url(args.hook_url, logger)
    event = load_event(args.event_file, logger)
  
    # Retry previously failed events first
    process_queue(args.hook_url, token)

    # Build payload for this alert
    container = build_container_payload(event)

    # Send or queue if it fails
    if not send_payload(args.hook_url, token, container, logger):
        queue_event(container)

if __name__ == "__main__":
    sys.exit(main())
