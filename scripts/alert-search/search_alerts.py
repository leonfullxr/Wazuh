#!/var/ossec/framework/python/bin/python3
"""search_alerts.py - Find alerts in alerts.json by rule ID within a recent
time window.

Uses the Python bundled with the Wazuh manager package (shebang above) to
avoid depending on the OS Python. Run on the manager:

    /var/ossec/framework/python/bin/python3 search_alerts.py

Edit TARGET_RULE_ID and LOOKBACK_SECONDS below to fit your search.
"""

import json
import datetime
import os
import sys

LOG_FILE = "/var/ossec/logs/alerts/alerts.json"
TARGET_RULE_ID = "5501"  # Rule ID to search for
LOOKBACK_SECONDS = 60    # How far back to search
SEPARATOR = "-" * 40

def parse_wazuh_timestamp(timestamp_str):
    """Parse Wazuh's timestamp with milliseconds and timezone (-0300 format)"""
    try:
        # Parse timestamp with milliseconds and timezone
        dt = datetime.datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f%z")
        return dt.astimezone(datetime.timezone.utc).timestamp()
    except ValueError:
        try:
            # Fallback for timestamps without milliseconds
            dt = datetime.datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S%z")
            return dt.astimezone(datetime.timezone.utc).timestamp()
        except ValueError as e:
            print(f"Invalid timestamp format: {timestamp_str} - {str(e)}", file=sys.stderr)
            return None

def main():
    current_time = datetime.datetime.now(datetime.timezone.utc).timestamp()
    time_threshold = current_time - LOOKBACK_SECONDS
    alerts_found = False

    if not os.path.exists(LOG_FILE):
        print(f"Error: Log file not found at {LOG_FILE}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(LOG_FILE, 'r') as f:
            print(f"Searching {LOG_FILE} for rule.id '{TARGET_RULE_ID}' within the last {LOOKBACK_SECONDS} seconds...")

            for line in f:
                line = line.strip()
                if not line:
                    continue

                try:
                    alert = json.loads(line)
                except json.JSONDecodeError:
                    print(f"Error decoding JSON: {line}", file=sys.stderr)
                    continue

                # Check rule ID match
                if str(alert.get('rule', {}).get('id')) != TARGET_RULE_ID:
                    continue

                # Parse and validate timestamp
                timestamp_str = alert.get('timestamp', '')
                if not timestamp_str:
                    continue

                log_time = parse_wazuh_timestamp(timestamp_str)
                if log_time is None:
                    continue

                # Check if within time window
                if log_time >= time_threshold:
                    print(SEPARATOR)
                    print(json.dumps(alert, ensure_ascii=False))
                    alerts_found = True

            # Add final separator if any alerts were found
            if alerts_found:
                print(SEPARATOR)

            print("Search complete.")

    except Exception as e:
        print(f"Error processing log file: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
