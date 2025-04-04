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
Value I want to extract
{"InitiatedBy":"{\"user\":{\"id\":\"00000000-0000-0000-0000-000000000000\",\"displayName\":\"Test User\",\"userPrincipalName\":\"testuser@example.com\",\"ipAddress\":\"0.0.0.0\",\"roles\":[]}}"}
"""

"""
Output from the script:
2025-04-04T10:26:58,900 root INFO SWIFT log has been sent to the analysis queue.
2025-04-04T10:26:58,900 root DEBUG Prepared SWIFT message: SWIFT:{"TenantId": "5ac64f95-784a-4cb8-a5d3-ac30ad3aaf7f", "SourceSystem": "Azure AD", "TimeGenerated": "2025-03-27T14:49:42.9293064Z", "ResourceId": "/tenants/4f95594c-a630-4b9d-b5c1-cc628e2b07e5/providers/Microsoft.aadiam", "OperationName": "Add member to group", "OperationVersion": "1.0", "Category": "GroupManagement", "ResultSignature": "None", "DurationMs": "0", "CorrelationId": "dbcb74c9-7b30-4cc2-8202-c98f3bfdf469", "Resource": "Microsoft.aadiam", "ResourceGroup": "Microsoft.aadiam", "Level": "4", "AdditionalDetails": [{"key": "User-Agent", "value": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"}], "Id": "Directory_dbcb74c9-7b30-4cc2-8202-c98f3bfdf469_PSDW5_66032801", "InitiatedBy": "{\"user\":{\"id\":\"0f0b85e6-fe8a-4097-bc16-1c1f6fd1e615\",\"displayName\":null,\"userPrincipalName\":\"argrdgrdg@agregaerga.onmicrosoft.com\",\"ipAddress\":\"186.144.92.225\",\"roles\":[]}}", "LoggedByService": "Core Directory", "Result": "success", "TargetResources": [{"id": "0960048c-4887-42d6-aefd-d5559295f11b", "displayName": null, "type": "User", "userPrincipalName": "aqergerg@aregerg.test.com", "modifiedProperties": [{"displayName": "Group.ObjectID", "oldValue": null, "newValue": "\"23453245-2345-2345-2345-234523454352\""}, {"displayName": "Group.DisplayName", "oldValue": null, "newValue": "\"sase-jwproject-prd\""}, {"displayName": "Group.WellKnownObjectName", "oldValue": null, "newValue": null}], "administrativeUnits": []}, {"id": "234524-9d48-23454235-23454-234523452345", "displayName": null, "type": "Group", "modifiedProperties": [], "administrativeUnits": [], "groupType": "unknownFutureValue"}], "AADTenantId": "4f95594c-a630-4b9d-b5c1-cc628e2b07e5", "ActivityDisplayName": "Add member to group", "ActivityDateTime": "2025-04-02T15:32:32.9293064Z", "AADOperationType": "Assign", "Type": "AuditLogs", "azure_tag": "azure-log-analytics", "log_analytics_tag": "AZ-Audit-Logss", "InitiatedBy_user_id": "0f0b85e6-fe8a-4097-bc16-1c1f6fd1e615", "InitiatedBy_user_displayName": null, "InitiatedBy_user_userPrincipalName": "argrdgrdg@agregaerga.onmicrosoft.com", "InitiatedBy_user_ipAddress": "186.144.92.225"}
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

# Assume alert_json is already parsed and we’re working with alert_json["data"]
alert_data = alert_json["data"]

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
    alert_data["InitiatedBy_user_id"] = user_obj.get("id", "")
    alert_data["InitiatedBy_user_displayName"] = user_obj.get("displayName", "")
    alert_data["InitiatedBy_user_PrincipalName"] = user_obj.get("userPrincipalName", "")
    alert_data["InitiatedBy_user_ipAddress"] = user_obj.get("ipAddress", "")
else:
    logging.error("InitiatedBy does not contain a user object.")

# (Optional) If you want to preserve the original InitiatedBy as a string:
# alert_data["InitiatedBy_original"] = initiated_by_str

# Convert the modified alert data back to a JSON string.
output_json = json.dumps(alert_data)

# Sending SWIFT log to the Analysis daemon queue
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
