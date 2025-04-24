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
      <name>extracting_fields_from_json.py</name>
      <rule_id>159633</rule_id> <-- Rule ID to trigger the script, arbitrary in this case -->
      <alert_format>json</alert_format>
      <options>JSON</options>
  </integration>
"""

"""
Full JSON event example:
{"TenantId":"00000000-0000-0000-0000-000000000000","SourceSystem":"TestSystem","TimeGenerated":"2025-03-27T14:49:42.9293064Z","ResourceId":"/tenants/00000000-0000-0000-0000-000000000000/providers/Microsoft.TestProvider","OperationName":"Test Operation","OperationVersion":"1.0","Category":"TestCategory","ResultType":"Success","ResultSignature":"TestSignature","ResultDescription":"Test operation completed successfully","DurationMs":123,"CorrelationId":"11111111-1111-1111-1111-111111111111","Resource":"TestResource","ResourceGroup":"TestResourceGroup","ResourceProvider":"TestProvider","Identity":"TestIdentity","Level":"4","Location":"TestLocation","AdditionalDetails":"[{\"key\":\"User-Agent\",\"value\":\"TestAgent/1.0\"}]","Id":"TestDirectory_11111111-1111-1111-1111-111111111111_TestInstance_12345678","InitiatedBy":"{\"user\":{\"id\":\"00000000-0000-0000-0000-000000000000\",\"displayName\":\"Test User\",\"userPrincipalName\":\"testuser@example.com\",\"ipAddress\":\"0.0.0.0\",\"roles\":[]}}","LoggedByService":"TestService","Result":"success","ResultReason":"TestReason","TargetResources":"[{\"id\":\"11111111-1111-1111-1111-111111111111\",\"displayName\":\"Test Target User\",\"type\":\"User\",\"userPrincipalName\":\"targetuser@example.test\",\"modifiedProperties\":[{\"displayName\":\"Group.ObjectID\",\"oldValue\":null,\"newValue\":\"\\\"00000000-0000-0000-0000-000000000000\\\"\"},{\"displayName\":\"Group.DisplayName\",\"oldValue\":null,\"newValue\":\"\\\"test-group\\\"\"},{\"displayName\":\"Group.WellKnownObjectName\",\"oldValue\":null,\"newValue\":null}],\"administrativeUnits\":[]},{\"id\":\"22222222-2222-2222-2222-222222222222\",\"displayName\":\"Test Group\",\"type\":\"Group\",\"modifiedProperties\":[],\"administrativeUnits\":[],\"groupType\":\"TestGroupType\"}]","AADTenantId":"00000000-0000-0000-0000-000000000000","ActivityDisplayName":"Test Activity","ActivityDateTime":"2025-04-02T15:32:32.9293064Z","AADOperationType":"TestOperationType","Type":"TestLogType","azure_tag":"test-tag","log_analytics_tag":"Test-Log-Analytics","InitiatedBy_user_id":"00000000-0000-0000-0000-000000000000","InitiatedBy_user_displayName":"Test User","InitiatedBy_user_userPrincipalName":"testadmin@example.com","InitiatedBy_user_ipAddress":"0.0.0.0"}
"""

"""
Value I want to extract from InitiatedBy:
{"InitiatedBy":"{\"user\":{\"id\":\"00000000-0000-0000-0000-000000000000\",\"displayName\":\"Test User\",\"userPrincipalName\":\"testuser@example.com\",\"ipAddress\":\"0.0.0.0\",\"roles\":[]}}"}

And also from TargetResources, extract:
- userPrincipalName (e.g., "targetuser@example.test")
- The newValue of the "Group.DisplayName" property (e.g., "\"test-group\"")
"""

# configuration for logging
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
    sys.exit(1)

try:
    # Read the alert file
    alert_json = json.loads(alert_file.read())
    alert_file.close()
except Exception as e:
    logging.error("Failed to read the alert file: %s", str(e))
    sys.exit(1)

# We assume alert_json has a key "data" which holds our alert info.
alert_data = alert_json["data"]

# ---- Extraction from InitiatedBy ----
# Extract the InitiatedBy field (as a string) and then parse it.
initiated_by_str = alert_data.get("InitiatedBy", "")
if initiated_by_str:
    try:
        initiated_by = json.loads(initiated_by_str)
    except Exception as e:
        logging.error("Failed parsing InitiatedBy: %s", str(e))
        initiated_by = {}
else:
    initiated_by = {}

# If the parsed InitiatedBy contains a 'user' object, extract its fields:
if isinstance(initiated_by, dict) and "user" in initiated_by:
    user_obj = initiated_by["user"]
    alert_data["InitiatedBy_user_PrincipalName"] = user_obj.get("userPrincipalName", "")
    alert_data["InitiatedBy_user_ipAddress"] = user_obj.get("ipAddress", "")
else:
    logging.error("InitiatedBy does not contain a user object.")

# (Optional) Preserve the original InitiatedBy string if needed:
# alert_data["InitiatedBy_original"] = initiated_by_str

target_resources_field = alert_data.get("TargetResources", "")

# Determine if we need to parse or use it directly.
if isinstance(target_resources_field, list):
    target_resources = target_resources_field
elif isinstance(target_resources_field, str):
    try:
        # Convert the string representation of the list into a Python list.
        target_resources = json.loads(target_resources_field)
    except Exception as e:
        logging.error("Failed parsing TargetResources: %s", str(e))
        target_resources = []
else:
    logging.error("Unexpected data type for TargetResources: %s", type(target_resources_field))
    target_resources = []

if target_resources:
    # For this example, extract data from the first target resource
    first_target = target_resources[0]
    
    # Extract the userPrincipalName from the target resource
    alert_data["TargetResources_userPrincipalName"] = first_target.get("userPrincipalName", "")
    
    # Now, loop through modifiedProperties to get the "Group.DisplayName" value.
    group_display_name = ""
    modified_properties = first_target.get("modifiedProperties", [])
    for prop in modified_properties:
        if prop.get("displayName") == "Group.DisplayName":
            group_display_name = prop.get("newValue", "")
            break
    alert_data["TargetResources_GroupDisplayName"] = group_display_name
else:
    logging.error("TargetResources field is empty or not a valid list.")


# Convert the modified alert data back to a JSON string.
output_json = json.dumps(alert_data)

# ---- Sending SWIFT log to the Analysis daemon queue ----
try:
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(SOCKET_ADDR)
    message = "SWIFT:" + output_json
    sock.send(message.encode())
    sock.close()
    logging.info("SWIFT log has been sent to the analysis queue.")
    logging.debug("Prepared SWIFT message: %s", message)
except Exception as error:
    logging.error("Error sending message: %s", str(error))
    print("An exception occurred", error)

sys.exit(0)
