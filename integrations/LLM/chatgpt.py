#!/var/ossec/framework/python/bin/python3
# ChatGPT Integration template for PowerShell command enrichment.

import json
import sys
import time
import os
from socket import socket, AF_UNIX, SOCK_DGRAM

try:
    import requests
except ImportError:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)

# Global variables
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

now = time.strftime("%a %b %d %H:%M:%S %Z %Y")
log_file = f"{pwd}/logs/integrations.log"
socket_addr = f"{pwd}/queue/sockets/queue"

def debug(msg):
    """Log debug messages to file and print if enabled."""
    if debug_enabled:
        msg = f"{now}: {msg}\n"
        print(msg)
    with open(log_file, "a") as f:
        f.write(msg)

def main(args):
    """Main function to process the alert and call ChatGPT."""
    debug("# Starting")
    if len(args) < 3:
        debug("# Exiting: Insufficient arguments.")
        sys.exit(1)

    alert_file_location = args[1]
    apikey = args[2]
    debug(f"# API Key: {apikey}")
    debug(f"# File location: {alert_file_location}")

    # Load alert file
    try:
        with open(alert_file_location) as alert_file:
            raw_data = alert_file.read()
            debug(f"# Raw alert data: {raw_data}")
            json_alert = json.loads(raw_data)
    except Exception as e:
        debug(f"# Error loading alert file: {e}")
        sys.exit(1)


    # Process the alert and query ChatGPT
    msg = process_alert(json_alert, apikey)
    if msg:
        send_event(msg)

def process_alert(alert, apikey):
    """Extract PowerShell command and query ChatGPT."""
    # Extract scriptBlockText
    ps_command = alert.get("data", {}).get("win", {}).get("eventdata", {}).get("scriptBlockText")
    if not ps_command:
        debug("# No PowerShell command found in eventdata. Skipping alert.")
        return None

    # Log the command
    debug(f"# Extracted PowerShell command: {ps_command}")

    # Query ChatGPT for insights
    chatgpt_response = query_chatgpt(ps_command, apikey)
    if not chatgpt_response:
        debug("# No response from ChatGPT.")
        return None

    # Prepare enriched alert
    enriched_alert = {
        "chatgpt": {
            "found": 1,
            "powerShellCommand": ps_command,
            "chatgptAnalysis": chatgpt_response
        },
        "integration": "powershell-chatgpt-enrichment",
        "source": {
            "alert_id": alert.get("id", ""),
            "rule": alert.get("rule", {}).get("id", ""),
            "description": alert.get("rule", {}).get("description", ""),
            "full_log": alert.get("full_log", "")
        }
    }

    debug(f"# Enriched alert: {json.dumps(enriched_alert, indent=4)}")
    return enriched_alert

def query_chatgpt(ps_command, apikey):
    """Query ChatGPT API with the PowerShell command."""
    headers = {
        'Authorization': f'Bearer {apikey}',
        'Content-Type': 'application/json',
     }

    payload = {
        'model': 'gpt-3.5-turbo',
        'messages': [
            {
                'role': 'user',
                'content': (
                    f"Analyze this PowerShell command and provide insights, determine if it is malicious or benign, "
                    f"and suggest well-formatted recommendations for mitigation or next steps: {ps_command}"
             )
           }
         ]
       }


    debug(f"# ChatGPT payload: {json.dumps(payload, indent=4)}")

    try:
        response = requests.post('https://api.openai.com/v1/chat/completions', headers=headers, json=payload)
        if response.status_code == 200:
            debug("# ChatGPT API response received successfully.")

            return response.json()["choices"][0]["message"]["content"]
        else:
            debug(f"# ChatGPT API error: {response.status_code}, {response.text}")
            return None
    except Exception as e:
        debug(f"# Error querying ChatGPT API: {e}")
        return None

def send_event(msg):
    """Send the enriched alert to Wazuh."""
    string = f'1:chatgpt:{json.dumps(msg)}'

    debug(f"# Sending enriched alert: {string}")

    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(socket_addr)
        sock.send(string.encode())
        sock.close()
    except Exception as e:
        debug(f"# Error sending enriched alert: {e}")

if __name__ == "__main__":
    try:
        debug_enabled = len(sys.argv) > 3 and sys.argv[3] == 'debug'
        main(sys.argv)
    except Exception as e:
        debug(f"# Exception in main: {e}")
        raise
        