# json converted - Jira Audit logs

Convert the embedded json log to various properly formatted json logs.

The one line initial log has the following format:

{"offset":0,"limit":1000,"total":5141,"records":[{json_log},{json_log},{json_log},...]

And this needs to be broken down into:

{json_log}
{json_log}
{json_log}
....
{json_log}

Initial log:

```json
{"offset":0,"limit":1000,"total":5141,"records":[
  {"id":94231,"summary":"Project initialized","authorKey":"123456:abcd1234-abcd-1234-abcd-1234abcd5678","authorAccountId":"123456:abcd1234-abcd-1234-abcd-1234abcd5678","created":"2025-05-07T10:23:45.789+0000","category":"projects","eventSource":"","objectItem":{"id":"50234","name":"ORION - BETA","typeName":"PROJECT"},"changedValues":[{"fieldName":"Name","changedTo":"ORION - BETA"},{"fieldName":"Key","changedTo":"ORIONBETA"},{"fieldName":"Description","changedTo":"Beta release prep"},{"fieldName":"Project lead","changedTo":"123456:abcd1234-abcd-1234-abcd-1234abcd5679"},{"fieldName":"Default Assignee","changedTo":"Project lead"}],"associatedItems":[{"id":"123456:abcd1234-abcd-1234-abcd-1234abcd5680","name":"123456:abcd1234-abcd-1234-abcd-1234abcd5681","typeName":"USER","parentId":"10000","parentName":"Development Team"}]},
  {"id":94230,"summary":"Workflow generated","authorKey":"223456:bcde2345-bcde-2345-bcde-2345bcde6789","authorAccountId":"223456:bcde2345-bcde-2345-bcde-2345bcde6789","created":"2025-05-07T10:23:44.500+0000","category":"workflows","eventSource":"","objectItem":{"id":"50234:50235 design workflow","name":"50234:50235 design workflow","typeName":"WORKFLOW"},"changedValues":[{"fieldName":"Name","changedTo":"50234:50235 design workflow"},{"fieldName":"Description","changedTo":"Defines design stage"}]},
  {"id":94229,"summary":"Issue type defined","authorKey":"323456:cdef3456-cdef-3456-cdef-3456cdef7890","authorAccountId":"323456:cdef3456-cdef-3456-cdef-3456cdef7890","created":"2025-05-07T10:23:43.321+0000","category":"issue types","eventSource":"","objectItem":{"id":"50236","name":"Bug","typeName":"ISSUE_TYPE"}},
  {"id":94228,"summary":"Issue type defined","authorKey":"323456:cdef3456-cdef-3456-cdef-3456cdef7890","authorAccountId":"323456:cdef3456-cdef-3456-cdef-3456cdef7890","created":"2025-05-07T10:23:43.200+0000","category":"issue types","eventSource":"","objectItem":{"id":"50237","name":"Task","typeName":"ISSUE_TYPE"}},
  {"id":94227,"summary":"Field configuration scheme modified","authorKey":"423456:def45678-def4-5678-def4-5678def45678","authorAccountId":"423456:def45678-def4-5678-def4-5678def45678","created":"2025-05-07T10:23:43.100+0000","category":"fields","eventSource":"","objectItem":{"id":"50300","name":"Field Configuration Scheme for Project ORIONBETA","typeName":"SCHEME"},"changedValues":[{"fieldName":"Issue Type","changedFrom":"","changedTo":"Bug"},{"fieldName":"Field Configuration","changedFrom":"","changedTo":"ORIONBETA-50236"}]},
  {"id":94226,"summary":"Field configuration scheme modified","authorKey":"423456:def45678-def4-5678-def4-5678def45678","authorAccountId":"423456:def45678-def4-5678-def4-5678def45678","created":"2025-05-07T10:23:43.000+0000","category":"fields","eventSource":"","objectItem":{"id":"50300","name":"Field Configuration Scheme for Project ORIONBETA","typeName":"SCHEME"},"changedValues":[{"fieldName":"Issue Type","changedFrom":"","changedTo":"Task"},{"fieldName":"Field Configuration","changedFrom":"","changedTo":"ORIONBETA-50237"}]},
  {"id":94225,"summary":"Project roles updated","remoteAddress":"192.168.100.10","authorKey":"523456:ef567890-ef56-7890-ef56-7890ef567890","authorAccountId":"523456:ef567890-ef56-7890-ef56-7890ef567890","created":"2025-05-07T08:00:00.000+0000","category":"projects","eventSource":"","objectItem":{"id":"10010","name":"Developers","typeName":"PROJECT_ROLE"},"changedValues":[{"fieldName":"Users","changedTo":"523456:ef567890-ef56-7890-ef56-7890ef567891"}],"associatedItems":[{"id":"50301","name":"ORION - BETA","typeName":"PROJECT"}]},
  {"id":94224,"summary":"User assigned to group","created":"2025-05-07T07:50:30.400+0000","category":"group management","eventSource":"","objectItem":{"name":"beta-admins","typeName":"GROUP","parentId":"10000","parentName":"com.atlassian.crowd.directory.RemoteDirectory"},"associatedItems":[{"id":"523456:ef567890-ef56-7890-ef56-7890ef567891","name":"523456:ef567890-ef56-7890-ef56-7890ef567891","typeName":"USER","parentId":"10000","parentName":"com.atlassian.crowd.directory.RemoteDirectory"}]},
  {"id":94223,"summary":"User removed from group","created":"2025-05-07T07:30:21.200+0000","category":"group management","eventSource":"","objectItem":{"name":"beta-developers","typeName":"GROUP","parentId":"10000","parentName":"com.atlassian.crowd.directory.RemoteDirectory"},"associatedItems":[{"id":"addon_com.example.plugin","name":"addon_com.example.plugin","typeName":"USER","parentId":"10000","parentName":"com.atlassian.crowd.directory.RemoteDirectory"}]},
  {"id":94222,"summary":"Group membership changed","created":"2025-05-07T07:29:55.100+0000","category":"group management","eventSource":"","objectItem":{"name":"beta-viewers","typeName":"GROUP","parentId":"10000","parentName":"com.atlassian.crowd.directory.RemoteDirectory"},"associatedItems":[{"id":"addon_com.example.plugin","name":"addon_com.example.plugin","typeName":"USER","parentId":"10000","parentName":"com.atlassian.crowd.directory.RemoteDirectory"}]}
]}

```

Formated json log:
```json
{"id":43210,"summary":"Project created","authorKey":"812345:abcdef01-2345-6789-ab","authorAccountId":"812345:abcdef01-2345-6789-ab","created":"2025-05-14T14:23:45.123+0000","category":"projects","eventSource":"","objectItem":{"id":"20001","name":"ZEUS - ALPHA","typeName":"PROJECT"},"changedValues":[{"fieldName":"Name","changedTo":"ZEUS - ALPHA"},{"fieldName":"Key","changedTo":"ZEUSALPHA"},{"fieldName":"Description","changedTo":"Initial project setup"},{"fieldName":"Project lead","changedTo":"812345:abcdef01-2345-6789-ac"},{"fieldName":"Default Assignee","changedTo":"Group lead"}],"associatedItems":[{"id":"812345:abcdef01-2345-6789-ad","name":"812345:abcdef01-2345-6789-ae","typeName":"USER","parentId":"10000","parentName":"Engineering Team"}]}

{"id":43209,"summary":"Workflow created","authorKey":"812345:abcdef01-2345-6789-ad","authorAccountId":"812345:abcdef01-2345-6789-ae","created":"2025-05-14T14:23:44.000+0000","category":"workflows","eventSource":"","objectItem":{"id":"20001:20002 initial workflow","name":"20001:20002 initial workflow","typeName":"WORKFLOW"},"changedValues":[{"fieldName":"Name","changedTo":"20001:20002 initial workflow"},{"fieldName":"Description","changedTo":"Handles ticket creation"}]}

{"id":43208,"summary":"Issue type created","authorKey":"812345:abcdef01-2345-6789-ad","authorAccountId":"812345:abcdef01-2345-6789-ae","created":"2025-05-14T14:23:43.890+0000","category":"issue types","eventSource":"","objectItem":{"id":"20003","name":"Bug","typeName":"ISSUE_TYPE"}}

{"id":43207,"summary":"Issue type created","authorKey":"812345:abcdef01-2345-6789-ad","authorAccountId":"812345:abcdef01-2345-6789-ae","created":"2025-05-14T14:23:43.800+0000","category":"issue types","eventSource":"","objectItem":{"id":"20004","name":"Improvement","typeName":"ISSUE_TYPE"}}

{"id":43206,"summary":"Field configuration scheme updated","authorKey":"812345:abcdef01-2345-6789-bf","authorAccountId":"812345:abcdef01-2345-6789-bf","created":"2025-05-14T14:23:43.700+0000","category":"fields","eventSource":"","objectItem":{"id":"20300","name":"Field Configuration Scheme for Project ZEUSALPHA","typeName":"SCHEME"},"changedValues":[{"fieldName":"Issue Type","changedFrom":"","changedTo":"Bug"},{"fieldName":"Field Configuration","changedFrom":"","changedTo":"ZEUSALPHA-20003"}]}

{"id":43205,"summary":"Field configuration scheme updated","authorKey":"812345:abcdef01-2345-6789-bf","authorAccountId":"812345:abcdef01-2345-6789-bf","created":"2025-05-14T14:23:43.600+0000","category":"fields","eventSource":"","objectItem":{"id":"20300","name":"Field Configuration Scheme for Project ZEUSALPHA","typeName":"SCHEME"},"changedValues":[{"fieldName":"Issue Type","changedFrom":"","changedTo":"Improvement"},{"fieldName":"Field Configuration","changedFrom":"","changedTo":"ZEUSALPHA-20004"}]}

{"id":43204,"summary":"Project roles changed","remoteAddress":"192.168.1.100","authorKey":"923456:bcdef234-5678-9012","authorAccountId":"923456:bcdef234-5678-9012","created":"2025-05-14T10:00:00.000+0000","category":"projects","eventSource":"","objectItem":{"id":"10010","name":"Developers","typeName":"PROJECT_ROLE"},"changedValues":[{"fieldName":"Users","changedTo":"923456:bcdef234-5678-9013"}],"associatedItems":[{"id":"20301","name":"ZEUS - ALPHA","typeName":"PROJECT"}]}

{"id":43203,"summary":"User added to group","created":"2025-05-14T09:55:30.000+0000","category":"group management","eventSource":"","objectItem":{"name":"alpha-admins","typeName":"GROUP","parentId":"10000","parentName":"com.atlassian.crowd.directory.RemoteDirectory"},"associatedItems":[{"id":"923456:bcdef234-5678-9013","name":"923456:bcdef234-5678-9013","typeName":"USER","parentId":"10000","parentName":"com.atlassian.crowd.directory.RemoteDirectory"}]}

{"id":43202,"summary":"User added to group","created":"2025-05-14T09:50:00.000+0000","category":"group management","eventSource":"","objectItem":{"name":"alpha-developers","typeName":"GROUP","parentId":"10000","parentName":"com.atlassian.crowd.directory.RemoteDirectory"},"associatedItems":[{"id":"addon_com.example.plugin","name":"addon_com.example.plugin","typeName":"USER","parentId":"10000","parentName":"com.atlassian.crowd.directory.RemoteDirectory"}]}

{"id":43201,"summary":"User added to group","created":"2025-05-14T09:49:00.000+0000","category":"group management","eventSource":"","objectItem":{"name":"alpha-viewers","typeName":"GROUP","parentId":"10000","parentName":"com.atlassian.crowd.directory.RemoteDirectory"},"associatedItems":[{"id":"addon_com.example.plugin","name":"addon_com.example.plugin","typeName":"USER","parentId":"10000","parentName":"com.atlassian.crowd.directory.RemoteDirectory"}]}

```

# Alerts
To replicate this in lab, I have done the following to generate the alerts and what the process should look like:

In the `ossec.conf` file, I have added the following:
```xml
  <localfile>
    <log_format>json</log_format>
    <location>/tmp/jira_json/converted_jira-audit-log_*T*.json</location>
  </localfile>
```


# Usage

```bash
./extract_records.sh [input_file]
```
or
```bash
cat input_file | ./extract_records.sh
```