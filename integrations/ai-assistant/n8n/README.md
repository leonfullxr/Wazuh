# n8n as the edge (D28)

n8n is the front door and nothing more: chat channel in, relay to the tool
service, answer out. The brain lives in the tool service. These are manual
build steps because a hand-written workflow JSON tends to break across n8n
versions. Once you build it, export it and commit the JSON here.

Open n8n at http://localhost:5678, create an owner account, then build a
five-node workflow:

1. **Chat Trigger** node. This gives you the hosted chat UI.

2. **HTTP Request** node, name it `Get OIDC token`.
   - Method POST, URL `http://keycloak:8080/realms/wazuh-poc/protocol/openid-connect/token`
   - Body type: form urlencoded, with fields
     `grant_type=password`, `client_id=wazuh-ai`,
     `username=analyst1`, `password=analyst1`
   - This is the lab stand-in for the customer SSO login. In a customer PoC
     the analyst authenticates at the OIDC proxy in front of n8n instead, and
     this node disappears. Move the credentials into an n8n credential
     entry rather than the node body if you keep it beyond a demo.

3. **HTTP Request** node, name it `Exchange for turn JWT`.
   - Method POST, URL `http://auth-shim:8081/v1/token/exchange`
   - Header `Authorization` = `Bearer {{ $json.access_token }}`

4. **HTTP Request** node, name it `Ask wazuh-ai`.
   - Method POST, URL `http://tool-service:8080/v1/chat/sync`
   - Header `Authorization` = `Bearer {{ $json.access_token }}`
   - JSON body: `{ "text": "{{ $('When chat message received').item.json.chatInput }}" }`
   - Timeout: raise to 180000 ms, investigations take time.
   - The body takes two optional fields. `conversation_id` keeps multi-turn
     context: every response returns one, echo it back on the next request
     and the service replays the recent turns to the model (window bounded
     by `WAI_CONVERSATION_TTL`). `alert_id` is the deep-link entry point
     (D34): the service prefixes the turn with
     `Explain the alert with id <alert_id>` so a dashboard link can open a
     pre-seeded investigation.

5. Wire the chat response to
   `{{ $json.answer }}\n\n_{{ $json.verifiability }}_`
   so every answer displays its verifiability label (D23). That label line is
   the product thesis in one string, keep it visible.

Two useful variants once the basic flow works. Point a workflow at
`POST /v1/tools/top_rules` (with the same Authorization header and a JSON
params body) to see the HTTP tool surface that replaces raw community-node
arms in a typical community-node chat workflow. And add a webhook workflow that takes an `alert_id`
query parameter and passes it straight through as the `alert_id` JSON body
field to prototype the explain-this-alert deep link (D34).
