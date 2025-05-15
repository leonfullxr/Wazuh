# json converted - Confluence Audit logs
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
{"results":[
  {
    "author": {
      "type": "user",
      "displayName": "System",
      "operations": null,
      "isExternalCollaborator": false,
      "accountType": "",
      "publicName": "Unknown user",
      "externalCollaborator": false
    },
    "remoteAddress": "",
    "creationDate": 1746601154321,
    "summary": "User removed from group",
    "description": "",
    "category": "Users and groups",
    "sysAdmin": false,
    "superAdmin": false,
    "affectedObject": {
      "name": "alpha-admins:1a2b3c4d",
      "objectType": "Group"
    },
    "changedValues": [],
    "associatedObjects": [
      {
        "name": "Jane Doe",
        "objectType": "User"
      }
    ]
  },
  {
    "author": {
      "type": "user",
      "displayName": "Alice Johnson",
      "operations": null,
      "isExternalCollaborator": false,
      "username": "a1b2c3d4",
      "userKey": "key1234abcd",
      "accountId": "a1b2c3d4e5f6",
      "accountType": "",
      "publicName": "Alice J.",
      "externalCollaborator": false
    },
    "remoteAddress": "203.0.113.5",
    "creationDate": 1746601098765,
    "summary": "Permission revoked",
    "description": "",
    "category": "Permissions",
    "sysAdmin": false,
    "superAdmin": false,
    "affectedObject": {
      "name": "finance-team:55e6f7g8-9h10-11i12-13j14",
      "objectType": "Group"
    },
    "changedValues": [
      {
        "name": "Permission",
        "oldValue": "Edit",
        "newValue": "View",
        "hiddenOldValue": "",
        "hiddenNewValue": ""
      }
    ],
    "associatedObjects": [
      {
        "name": "Budget Report",
        "objectType": "Page"
      },
      {
        "name": "Finance Space",
        "objectType": "Space"
      }
    ]
  },
  {
    "author": {
      "type": "user",
      "displayName": "Bob Smith",
      "operations": null,
      "isExternalCollaborator": false,
      "username": "b2c3d4e5",
      "userKey": "key5678efgh",
      "accountId": "b2c3d4e5f6g7",
      "accountType": "",
      "publicName": "Bob S.",
      "externalCollaborator": false
    },
    "remoteAddress": "198.51.100.23",
    "creationDate": 1746601032100,
    "summary": "Content restriction removed",
    "description": "",
    "category": "Permissions",
    "sysAdmin": false,
    "superAdmin": false,
    "affectedObject": {
      "name": "Project Plan:9a8b7c6d-5e4f-3g2h-1i0j",
      "objectType": "Page"
    },
    "changedValues": [
      {
        "name": "Restriction",
        "oldValue": "Read",
        "newValue": "None",
        "hiddenOldValue": "",
        "hiddenNewValue": ""
      }
    ],
    "associatedObjects": [
      {
        "name": "Operations Manual",
        "objectType": "Page"
      }
    ]
  },
  {
    "author": {
      "type": "user",
      "displayName": "Charlie Lee",
      "operations": null,
      "isExternalCollaborator": false,
      "username": "c3d4e5f6",
      "userKey": "key9012ijkl",
      "accountId": "c3d4e5f6g7h8",
      "accountType": "",
      "publicName": "Charlie L.",
      "externalCollaborator": false
    },
    "remoteAddress": "",
    "creationDate": 1746600987654,
    "summary": "Page moved",
    "description": "",
    "category": "Content management",
    "sysAdmin": false,
    "superAdmin": false,
    "affectedObject": {
      "name": "Team Roadmap",
      "objectType": "Page"
    },
    "changedValues": [
      {
        "name": "Old Space",
        "oldValue": "Development",
        "newValue": "Management",
        "hiddenOldValue": "",
        "hiddenNewValue": ""
      },
      {
        "name": "New Space",
        "oldValue": "",
        "newValue": "Management",
        "hiddenOldValue": "",
        "hiddenNewValue": ""
      }
    ],
    "associatedObjects": [
      {
        "name": "Team Roadmap",
        "objectType": "Page"
      }
    ]
  }
],
"start":0,
"limit":1000,
"size":4,
"_links":{
  "base":"https://acmecorp.atlassian.net/wiki",
  "context":"/wiki",
  "self":"https://acmecorp.atlassian.net/wiki/rest/api/audit?endDate=2025-05-07T11:45:32.100Z&startDate=2025-05-07T06:45:32.100Z"
}}

```

Formated json log:
```json
{"author":{"type":"user","displayName":"System","operations":null,"isExternalCollaborator":false,"accountType":"","publicName":"Unknown user","externalCollaborator":false},"remoteAddress":"203.0.113.1","creationDate":1746600954321,"summary":"User removed from group","description":"","category":"Users and groups","sysAdmin":false,"superAdmin":false,"affectedObject":{"name":"alpha-admins:1a2b3c4d","objectType":"Group"},"changedValues":[],"associatedObjects":[{"name":"Jane Doe","objectType":"User"}]}

{"author":{"type":"user","displayName":"Emily Clark","operations":null,"isExternalCollaborator":false,"username":"e1f2a3b4c5d6","userKey":"f1e2d3c4b5a6","accountId":"e1f2a3b4c5d6f7","accountType":"","publicName":"Emily C.","externalCollaborator":false},"remoteAddress":"198.51.100.42","creationDate":1746600906789,"summary":"Content restriction removed","description":"","category":"Permissions","sysAdmin":false,"superAdmin":false,"affectedObject":{"name":"team-admins:d4e5f678-1234-5678-9ab0-cdef12345678","objectType":"Group"},"changedValues":[{"name":"Restriction","oldValue":"Read","newValue":"None","hiddenOldValue":"","hiddenNewValue":""}],"associatedObjects":[{"name":"Project Overview","objectType":"Page"},{"name":"Engineering Docs","objectType":"Space"}]}

{"author":{"type":"user","displayName":"Michael Brown","operations":null,"isExternalCollaborator":false,"username":"f7e6d5c4b3a2","userKey":"a1b2c3d4e5f6","accountId":"f7e6d5c4b3a2f1","accountType":"","publicName":"Michael B.","externalCollaborator":false},"remoteAddress":"","creationDate":1746600851234,"summary":"Content restriction added","description":"","category":"Permissions","sysAdmin":false,"superAdmin":false,"affectedObject":{"name":"John Doe","objectType":"User"},"changedValues":[{"name":"Type","oldValue":"","newValue":"Edit","hiddenOldValue":"","hiddenNewValue":""},{"name":"User","oldValue":"","newValue":"John Doe","hiddenOldValue":"","hiddenNewValue":""}],"associatedObjects":[{"name":"Team Playbook","objectType":"Page"},{"name":"HR Space","objectType":"Space"}]}

{"author":{"type":"user","displayName":"Sarah Johnson","operations":null,"isExternalCollaborator":false,"username":"c3b2a1d4e5f6","userKey":"b1c2d3e4f5g6","accountId":"c3b2a1d4e5f6g7","accountType":"","publicName":"Sarah J.","externalCollaborator":false},"remoteAddress":"203.0.113.88","creationDate":1746600807890,"summary":"Permission updated","description":"","category":"Permissions","sysAdmin":false,"superAdmin":false,"affectedObject":{"name":"Project Plan:9a8b7c6d-5e4f-3g2h-1i0j","objectType":"Page"},"changedValues":[{"name":"Permission","oldValue":"View","newValue":"Edit","hiddenOldValue":"","hiddenNewValue":""}],"associatedObjects":[{"name":"Budget Tracker","objectType":"Page"}]}

```

# Alerts
I have added this to the manager's `ossec.conf` file to monitor the converted logs. The `log_format` is set to `json` to parse the logs correctly.

```xml
<localfile>
    <log_format>json</log_format>
    <location>/tmp/confluence_json/converted_confluence-audit-log_*T*.json</loc$
</localfile>
```