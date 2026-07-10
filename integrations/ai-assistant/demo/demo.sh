#!/usr/bin/env bash
# One-take demo of the ai-assistant harness. Assumes the stack is up and seeded:
#   make keys wazuh securityconfig poc seed
# Record it with either:
#   vhs demo/demo.tape                          (GIF, deterministic)
#   asciinema rec -c ./demo/demo.sh demo.cast   (cast, then: agg demo.cast demo.gif)
set -euo pipefail

say() { printf '\n\033[1;36m# %s\033[0m\n' "$*"; sleep 1; }

need_token() { # fail fast with the raw response instead of carrying "null" forward
  if [ -z "$2" ] || [ "$2" = "null" ]; then
    printf '\033[1;31m%s failed - raw response:\033[0m\n%s\n' "$1" "$3" >&2
    exit 1
  fi
}

say "1. Log in as analyst1 (OIDC password grant against Keycloak)"
OIDC_RAW=$(curl -s http://localhost:8085/realms/wazuh-poc/protocol/openid-connect/token \
  -d grant_type=password -d client_id=wazuh-ai \
  -d username=analyst1 -d password=analyst1)
OIDC=$(jq -r .access_token <<<"$OIDC_RAW")
need_token "OIDC login" "$OIDC" "$OIDC_RAW"
echo "OIDC token: ${OIDC:0:24}..."

say "2. Exchange it at the auth shim for a turn JWT (<=10 min, tenant from config)"
TURN_RAW=$(curl -s -X POST http://localhost:8081/v1/token/exchange \
  -H "Authorization: Bearer $OIDC")
TURN=$(jq -r .access_token <<<"$TURN_RAW")
need_token "token exchange" "$TURN" "$TURN_RAW"
echo "turn JWT:   ${TURN:0:24}..."

say "3. The ceiling, with no AI involved: reads allowed, writes denied (403)"
curl -sk -H "Authorization: Bearer $TURN" \
  "https://localhost:9200/wazuh-alerts-*/_count" | jq '{alerts_readable: .count}'
curl -sk -X DELETE -H "Authorization: Bearer $TURN" \
  -o /dev/null -w 'DELETE wazuh-alerts-* -> HTTP %{http_code}\n' \
  "https://localhost:9200/wazuh-alerts-4.x-2026.07.08"

say "4. Ask a real question - the answer carries its own verifiability label"
curl -s -X POST http://localhost:8080/v1/chat/sync \
  -H "Authorization: Bearer $TURN" -H "Content-Type: application/json" \
  -d '{"text": "How many authentication failures in the last 24 hours, and which users are targeted?"}' \
  | jq '{answer, verifiability, tools: .tools_called, usage}'

say "5. Zero-hit honesty: a question about an agent that does not exist"
curl -s -X POST http://localhost:8080/v1/chat/sync \
  -H "Authorization: Bearer $TURN" -H "Content-Type: application/json" \
  -d '{"text": "Show me alerts from agent db-99 today"}' \
  | jq '{answer, verifiability}'

say "Done - every number came from the datastore, every claim is cited, nothing was trusted"
