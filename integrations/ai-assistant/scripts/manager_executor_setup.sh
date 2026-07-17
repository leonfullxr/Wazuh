#!/usr/bin/env bash
# Least-privilege Wazuh API users for the action executors (R6.10/D35).
#
# The manager and active-response tiers must NOT run as wazuh-wui/admin. This
# creates two scoped RBAC users the gateway's env registry points at:
#   wazuh_ai_manager_op  -> agent:restart,
#                          agent:modify_group + group:modify_assignments,
#                          rules:update + rules:delete,
#                          manager:read + manager:restart (analysisd reload)
#   wazuh_ai_ar_exec     -> active-response:command only
# Each proven mutually exclusive: the restart user cannot fire AR and vice
# versa. Idempotent: re-running reconciles instead of failing on "exists".
#
# Blast radius (F3/F4):
# - rules:update/delete can replace any custom rules file via
#   PUT /rules/files/{filename} (scoped as narrowly as the API allows).
# - manager:restart is required by PUT /manager/analysisd/reload in 4.14
#   (alongside manager:read); it also permits a full manager restart.
#
# Usage: WAZUH_API_URL=https://localhost:55000 WAZUH_ADMIN=wazuh-wui:<pass> \
#        bash scripts/manager_executor_setup.sh
set -euo pipefail

API="${WAZUH_API_URL:-https://localhost:55000}"
ADMIN="${WAZUH_ADMIN:-wazuh-wui:wazuh-wui}"
MGR_PASS="${WAI_MANAGER_OP_PASSWORD:-MgrOpLab1!}"
AR_PASS="${WAI_AR_EXEC_PASSWORD:-ArExecLab1!}"

tok() { curl -sk -u "$ADMIN" "$API/security/user/authenticate?raw=true"; }
T="$(tok)"
api() { curl -sk -H "Authorization: Bearer $T" -H "Content-Type: application/json" "$@"; }

# Resolve an object id by name from a security collection, or empty.
id_of() {  # $1=collection (users|roles|policies) $2=name-field $3=name
  api "$API/security/$1?limit=500" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(next((str(o['id']) for o in d['data']['affected_items'] if o.get('$2')=='$3'), ''))"
}

ensure_user() {  # $1=username $2=password -> id (stdout, last line)
  local uid; uid="$(id_of users username "$1")"
  if [[ -z "$uid" ]]; then
    api -X POST "$API/security/users" -d "{\"username\":\"$1\",\"password\":\"$2\"}" >/dev/null
    uid="$(id_of users username "$1")"
    echo "created user $1 ($uid)" >&2
  else
    api -X PUT "$API/security/users/$uid" -d "{\"password\":\"$2\"}" >/dev/null
    echo "user $1 exists ($uid), password reconciled" >&2
  fi
  echo "$uid"
}

ensure_role() {  # $1=name -> id
  local rid; rid="$(id_of roles name "$1")"
  if [[ -z "$rid" ]]; then
    api -X POST "$API/security/roles" -d "{\"name\":\"$1\"}" >/dev/null
    rid="$(id_of roles name "$1")"
  fi
  echo "$rid"
}

# $1=name $2=JSON-array-of-actions $3=JSON-array-of-resources
# Recreates the policy body when the name already exists (PUT). If create fails
# because an identical policy body already exists (Wazuh error 4009 — e.g. stock
# rules_all_resourceless), resolve that existing policy id and reuse it.
ensure_policy() {
  local name="$1" actions="$2" resources="$3"
  local body="{\"name\":\"$name\",\"policy\":{\"actions\":$actions,\"resources\":$resources,\"effect\":\"allow\"}}"
  local pid; pid="$(id_of policies name "$name")"
  if [[ -z "$pid" ]]; then
    local create_out
    create_out="$(api -X POST "$API/security/policies" -d "$body")"
    pid="$(id_of policies name "$name")"
    if [[ -z "$pid" ]]; then
      # Identical body may already exist under another name (stock policies).
      pid="$(api "$API/security/policies?limit=500" | ACTIONS="$actions" RESOURCES="$resources" python3 -c "
import sys,json,os
d=json.load(sys.stdin)
want_a=json.loads(os.environ['ACTIONS'])
want_r=json.loads(os.environ['RESOURCES'])
for o in d['data']['affected_items']:
  pol=o.get('policy') or {}
  if pol.get('actions')==want_a and pol.get('resources')==want_r and pol.get('effect')=='allow':
    print(o['id']); break
")"
    fi
    if [[ -z "$pid" ]]; then
      echo "failed to ensure policy $name: $create_out" >&2
      return 1
    fi
  else
    api -X PUT "$API/security/policies/$pid" -d "$body" >/dev/null || true
  fi
  echo "$pid"
}

MGR_UID="$(ensure_user wazuh_ai_manager_op "$MGR_PASS")"
AR_UID="$(ensure_user wazuh_ai_ar_exec "$AR_PASS")"
MGR_RID="$(ensure_role wazuh_ai_restart_role)"
AR_RID="$(ensure_role wazuh_ai_ar_role)"

MGR_PID_RESTART="$(ensure_policy wazuh_ai_restart_policy '["agent:restart"]' '["agent:id:*"]')"
# agent:modify_group resources are agent:id + agent:group (not group:id).
MGR_PID_AGENT_GROUP="$(ensure_policy wazuh_ai_modify_group_policy '["agent:modify_group"]' '["agent:id:*","agent:group:*"]')"
# Assign endpoint also requires group:modify_assignments on group:id.
MGR_PID_GROUP_ASSIGN="$(ensure_policy wazuh_ai_group_assign_policy '["group:modify_assignments"]' '["group:id:*"]')"
# Custom rules via PUT /rules/files/{filename} (not /manager/files).
MGR_PID_RULES_UPD="$(ensure_policy wazuh_ai_rules_update_policy '["rules:update"]' '["*:*:*"]')"
MGR_PID_RULES_DEL="$(ensure_policy wazuh_ai_rules_delete_policy '["rules:delete"]' '["rule:file:*"]')"
# analysisd reload is gated by manager:read + manager:restart in 4.14.
MGR_PID_MGR_READ="$(ensure_policy wazuh_ai_manager_read_policy '["manager:read"]' '["*:*:*"]')"
MGR_PID_MGR_RESTART="$(ensure_policy wazuh_ai_manager_restart_policy '["manager:restart"]' '["*:*:*"]')"
AR_PID="$(ensure_policy wazuh_ai_ar_policy '["active-response:command"]' '["agent:id:*"]')"

for pid in \
  "$MGR_PID_RESTART" \
  "$MGR_PID_AGENT_GROUP" \
  "$MGR_PID_GROUP_ASSIGN" \
  "$MGR_PID_RULES_UPD" \
  "$MGR_PID_RULES_DEL" \
  "$MGR_PID_MGR_READ" \
  "$MGR_PID_MGR_RESTART"
do
  api -X POST "$API/security/roles/$MGR_RID/policies?policy_ids=$pid" >/dev/null
done
api -X POST "$API/security/users/$MGR_UID/roles?role_ids=$MGR_RID" >/dev/null
api -X POST "$API/security/roles/$AR_RID/policies?policy_ids=$AR_PID" >/dev/null
api -X POST "$API/security/users/$AR_UID/roles?role_ids=$AR_RID" >/dev/null

echo "manager executor: wazuh_ai_manager_op"
echo "  actions: agent:restart, agent:modify_group, group:modify_assignments,"
echo "           rules:update, rules:delete, manager:read, manager:restart"
echo "AR executor:      wazuh_ai_ar_exec (active-response:command)"
echo "point the env registry at these:"
echo "  WAI_ENV_LAB_MANAGER_EXECUTOR=wazuh_ai_manager_op:$MGR_PASS"
echo "  WAI_ENV_LAB_AR_EXECUTOR=wazuh_ai_ar_exec:$AR_PASS"
