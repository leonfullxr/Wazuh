#!/usr/bin/env python3

import sys
import json
import os
from socket import socket, AF_UNIX, SOCK_DGRAM
from datetime import datetime
import logging


"""
Config to add to the manager:

  <integration>
      <name>custom-swift_log_extractor.py</name>
      <rule_id>159633</rule_id>
      <alert_format>json</alert_format>
      <options>JSON</options>
  </integration>

"""

"""
Value I want to extract
{"InitiatedBy":"{\"user\":{\"id\":\"3456654-4356-4097-5665-345634564356433456\",\"displayName\":null,\"userPrincipalName\":\"whdsfhbdf@erahetrherth.onmicrosoft.com\",\"ipAddress\":\"345.345.33.355\",\"roles\":[]}}"}
"""

#configuration

logging.basicConfig(filename='/var/ossec/logs/swift_extractor.log',
                    filemode='a',
                    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                    datefmt='%Y-%m-%dT%H:%M:%S',
                    level=logging.DEBUG)

pwd             = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
SOCKET_ADDR     = f'{pwd}/queue/sockets/queue'

try:
    # Reading configuration parameters
    alert_file = open(sys.argv[1])

except Exception as e:
    logging.error("Failed to read config parameters: %s", str(e))

try:
    # Read the alert file
    alert_json = json.loads(alert_file.read())
    alert_file.close()
except Exception as e:
    logging.error("Failed to read the alert file: %s", str(e)) 

try:
    initiated_by = alert_json["data"].get("InitiatedBy", "")
except Exception as e:
    logging.error("Failed extracting the issue fields: %s", str(e))
    logging.debug("Alert JSON content: %s", json.dumps(alert_json))

# Extract the 'user' object.
try:
    user_obj = initiated_by['user']
except Exception as e:
    logging.error("Error accessing 'user' within 'InitiatedBy':", e)

# Extract the desired fields.
try:
    user_principal = user_obj.get('userPrincipalName', '')
    ip_address     = user_obj.get('ipAddress', '')
    display_name   = user_obj.get('displayName', None)  # Allow None for displayName.
    # Use 'Id' if available, else fallback to 'id'
    user_id        = user_obj.get('Id', user_obj.get('id', ''))
    roles          = user_obj.get('roles', [])
except Exception as e:
    logging.error("Error extracting required fields:", e)
    user_id = ''  # Set a default value to avoid NameError
    roles   = []

# Construct the output dictionary.
output_dict = {
    "InitiatedBy": initiated_by
}

# Convert the output dictionary to a JSON string.
output_json = json.dumps(output_dict)

# Sending SWIFT log to the Analysis daemon queue
try:
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(SOCKET_ADDR)
    message = "\"\"SWIFT:" + output_json
    sock.send(message.encode())

    sock.close()
    logging.info("SWIFT log has been sent to the analysis queue.")
    logging.debug("Prepared SWIFT message: %s", message)
except Exception as error:
    print("An exception occurred", error);

sys.exit(0)