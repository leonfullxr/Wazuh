#! /var/ossec/framework/python/bin/python3

import datetime
import json
import sys
import time
import logging
from logging.handlers import TimedRotatingFileHandler
import urllib3
import warnings

warnings.filterwarnings("ignore")

def main():
    if len(sys.argv) < 5:
        logger.error(f'Error: Expected 5 arguments, received {len(sys.argv)}.')
        sys.exit(1)

    logger.info("Starting splunk_integration script execution.")

    splunk = {}

    with open(sys.argv[1], encoding='latin-1') as f:
        splunk["event"] = json.loads(f.read())

    splunk["sourcetype"] = "_json"

    splunk["source"] = "wazuh-manager"
    if "manager" in splunk["event"]:
        if "name" in splunk["event"]["manager"]:
            splunk["source"] = splunk["event"]["manager"]["name"]

    splunk["time"] = int(time.time())
    if "timestamp" in splunk["event"]:
        dt = datetime.datetime.strptime(splunk["event"]["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z")
        splunk["time"] = int(
            (dt - datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)).total_seconds()
        )

    if "agent" in splunk["event"]:
        if "name" in splunk["event"]["agent"]:
            splunk["host"] = splunk["event"]["agent"]["name"]

    http = urllib3.PoolManager(cert_reqs="CERT_NONE")

    hec_token = sys.argv[2].split(":")
    str_token = hec_token[0] + " " + hec_token[1]

    r = http.request(
        "POST",
        sys.argv[3],
        headers={"Authorization": str_token, "Content-Type": "application/json"},
        body=json.dumps(splunk),
    )

    logger.info("API request sent. Response: %s", r.data)

    return 0


if __name__ == "__main__":

    log_file = "/var/ossec/logs/splunk_integration.log"
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    handler = TimedRotatingFileHandler(log_file, when="midnight", backupCount=1)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    main()
