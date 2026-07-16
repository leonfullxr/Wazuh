#!/usr/bin/env bash
# Least-privilege Wazuh API users for the action executors (R6.10/D35).
#
# The manager and active-response tiers must NOT run as wazuh-wui/admin. This
# creates two scoped RBAC users the gateway's env registry points at:
#   wazuh_ai_manager_op  -> agent:restart only
#   wazuh_ai_ar_exec     -> active-response:command only
# Each proven mutually exclusive: the restart user cannot fire AR and vice
# versa. Idempotent: re-running reconciles instead of failing on "exists".
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

ensure_policy() {  # $1=name $2=action -> id
  local pid; pid="$(id_of policies name "$1")"
  if [[ -z "$pid" ]]; then
    api -X POST "$API/security/policies" \
      -d "{\"name\":\"$1\",\"policy\":{\"actions\":[\"$2\"],\"resources\":[\"agent:id:*\"],\"effect\":\"allow\"}}" >/dev/null
    pid="$(id_of policies name "$1")"
  fi
  echo "$pid"
}

MGR_UID="$(ensure_user wazuh_ai_manager_op "$MGR_PASS")"
AR_UID="$(ensure_user wazuh_ai_ar_exec "$AR_PASS")"
MGR_RID="$(ensure_role wazuh_ai_restart_role)"
AR_RID="$(ensure_role wazuh_ai_ar_role)"
MGR_PID="$(ensure_policy wazuh_ai_restart_policy agent:restart)"
AR_PID="$(ensure_policy wazuh_ai_ar_policy active-response:command)"

# Link (idempotent: the API ignores already-linked ids).
api -X POST "$API/security/roles/$MGR_RID/policies?policy_ids=$MGR_PID" >/dev/null
api -X POST "$API/security/users/$MGR_UID/roles?role_ids=$MGR_RID" >/dev/null
api -X POST "$API/security/roles/$AR_RID/policies?policy_ids=$AR_PID" >/dev/null
api -X POST "$API/security/users/$AR_UID/roles?role_ids=$AR_RID" >/dev/null

echo "manager executor: wazuh_ai_manager_op (agent:restart)"
echo "AR executor:      wazuh_ai_ar_exec (active-response:command)"
echo "point the env registry at these:"
echo "  WAI_ENV_LAB_MANAGER_EXECUTOR=wazuh_ai_manager_op:$MGR_PASS"
echo "  WAI_ENV_LAB_AR_EXECUTOR=wazuh_ai_ar_exec:$AR_PASS"
