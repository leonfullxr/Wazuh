"""Static assets for the in-browser action confirm UI (V3.5c)."""

INJECT_JS = r"""
(function () {
  if (window.__wazuhAiActionsInjected) return;
  window.__wazuhAiActionsInjected = true;

  var CFG = window.WAZUH_AI_ACTIONS_CONFIG || {
    toolServiceUrl: "http://localhost:8080",
    shimUrl: "http://localhost:8081",
    kcUrl: "http://localhost:8085",
    kcRealm: "wazuh-poc",
    kcClient: "wazuh-ai",
  };

  var MARKER_RE = /<!--WAZUH_AI_ACTIONS([A-Za-z0-9_-]*)WAZUH_AI_ACTIONS_END-->/g;
  var JWT_KEY = "wazuh_ai_turn_jwt";

  function b64ToJson(token) {
    var pad = "=".repeat((4 - (token.length % 4)) % 4);
    var raw = atob(token.replace(/-/g, "+").replace(/_/g, "/") + pad);
    return JSON.parse(raw);
  }

  function jwt() {
    return sessionStorage.getItem(JWT_KEY) || "";
  }

  function setJwt(tok) {
    sessionStorage.setItem(JWT_KEY, tok);
  }

  async function login(username, password) {
    var body = new URLSearchParams({
      grant_type: "password",
      client_id: CFG.kcClient,
      username: username,
      password: password,
    });
    var oidc = await fetch(
      CFG.kcUrl + "/realms/" + CFG.kcRealm + "/protocol/openid-connect/token",
      { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: body }
    );
    if (!oidc.ok) throw new Error("Keycloak login failed (" + oidc.status + ")");
    var access = (await oidc.json()).access_token;
    var exchanged = await fetch(CFG.shimUrl + "/v1/token/exchange", {
      method: "POST",
      headers: { Authorization: "Bearer " + access },
    });
    if (!exchanged.ok) throw new Error("token exchange failed (" + exchanged.status + ")");
    var turn = (await exchanged.json()).access_token;
    setJwt(turn);
    return turn;
  }

  async function api(path, opts) {
    opts = opts || {};
    var headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
    if (jwt()) headers.Authorization = "Bearer " + jwt();
    var res = await fetch(CFG.toolServiceUrl + path, Object.assign({}, opts, { headers: headers }));
    return res;
  }

  function cardEl(action) {
    var wrap = document.createElement("div");
    wrap.className = "wazuh-ai-action-card";
    wrap.dataset.proposalId = action.proposal_id;
    wrap.innerHTML =
      '<div class="wazuh-ai-action-card__head">Action proposed · not executed</div>' +
      '<div class="wazuh-ai-action-card__preview"></div>' +
      '<div class="wazuh-ai-action-card__meta"></div>' +
      '<div class="wazuh-ai-action-card__login" hidden>' +
      '<input class="wazuh-ai-action-card__user" placeholder="Operator username" />' +
      '<input class="wazuh-ai-action-card__pass" type="password" placeholder="Password" />' +
      '<button type="button" class="wazuh-ai-action-card__login-btn">Sign in</button>' +
      "</div>" +
      '<div class="wazuh-ai-action-card__actions">' +
      '<button type="button" class="wazuh-ai-action-card__confirm">Confirm</button>' +
      '<button type="button" class="wazuh-ai-action-card__reject">Reject</button>' +
      "</div>" +
      '<div class="wazuh-ai-action-card__status"></div>";
    wrap.querySelector(".wazuh-ai-action-card__preview").textContent = action.preview || "";
    wrap.querySelector(".wazuh-ai-action-card__meta").textContent =
      "Risk: " + (action.risk || "?") + " · Tier: " + (action.tier || "?");
    return wrap;
  }

  function ensureLoginUI(card) {
    if (jwt()) return Promise.resolve(jwt());
    var login = card.querySelector(".wazuh-ai-action-card__login");
    login.hidden = false;
    return new Promise(function (resolve, reject) {
      card.querySelector(".wazuh-ai-action-card__login-btn").onclick = async function () {
        try {
          var user = card.querySelector(".wazuh-ai-action-card__user").value;
          var pass = card.querySelector(".wazuh-ai-action-card__pass").value;
          resolve(await login(user, pass));
          login.hidden = true;
        } catch (err) {
          reject(err);
        }
      };
    });
  }

  function wireCard(card, action) {
    var status = card.querySelector(".wazuh-ai-action-card__status");
    card.querySelector(".wazuh-ai-action-card__confirm").onclick = async function () {
      status.textContent = "Confirming…";
      try {
        await ensureLoginUI(card);
        var key = "ui-" + action.proposal_id + "-" + Date.now();
        var res = await api(action.confirm_path || ("/v1/actions/" + action.proposal_id + "/confirm"), {
          method: "POST",
          body: JSON.stringify({ idempotency_key: key }),
        });
        var body = await res.json();
        if (!res.ok) throw new Error(body.detail || res.statusText);
        status.textContent = body.result && body.result.ok
          ? "Confirmed: " + (body.result.message || "ok")
          : "Failed: " + (body.result && body.result.message);
        card.classList.add("wazuh-ai-action-card--done");
      } catch (err) {
        status.textContent = String(err.message || err);
      }
    };
    card.querySelector(".wazuh-ai-action-card__reject").onclick = async function () {
      status.textContent = "Rejecting…";
      try {
        await ensureLoginUI(card);
        var res = await api("/v1/actions/" + action.proposal_id + "/reject", { method: "POST" });
        if (!res.ok) {
          var body = await res.json();
          throw new Error(body.detail || res.statusText);
        }
        status.textContent = "Proposal rejected.";
        card.classList.add("wazuh-ai-action-card--done");
      } catch (err) {
        status.textContent = String(err.message || err);
      }
    };
  }

  function injectCards(root) {
    if (!root || root.dataset.wazuhAiActionsProcessed === "1") return;
    var html = root.innerHTML || root.textContent || "";
    var match;
  var found = false;
    MARKER_RE.lastIndex = 0;
    while ((match = MARKER_RE.exec(html)) !== null) found = true;
    if (!found) return;
    root.dataset.wazuhAiActionsProcessed = "1";
    html = html.replace(MARKER_RE, function (_all, payload) {
      var data;
      try {
        data = b64ToJson(payload);
      } catch (_e) {
        return "";
      }
      var host = document.createElement("div");
      host.className = "wazuh-ai-action-cards";
      (data.actions || []).forEach(function (action) {
        var card = cardEl(action);
        wireCard(card, action);
        host.appendChild(card);
      });
      root.appendChild(host);
      return "";
    });
    root.innerHTML = html;
  }

  function scan() {
    var nodes = document.querySelectorAll(
      '[class*="assistant"], [data-test-subj*="assistant"], .euiMarkdownFormat, .assistantChat'
    );
    nodes.forEach(injectCards);
  }

  var style = document.createElement("style");
  style.textContent =
    ".wazuh-ai-action-card{border:1px solid #d3dae6;border-radius:6px;padding:12px;margin:10px 0;background:#f5f7fa}" +
    ".wazuh-ai-action-card__head{font-weight:600;margin-bottom:6px}" +
    ".wazuh-ai-action-card__preview{white-space:pre-wrap;margin-bottom:8px}" +
    ".wazuh-ai-action-card__meta{font-size:12px;color:#5a6b86;margin-bottom:8px}" +
    ".wazuh-ai-action-card__actions button{margin-right:8px}" +
    ".wazuh-ai-action-card--done{opacity:.85}";
  document.head.appendChild(style);

  var obs = new MutationObserver(scan);
  obs.observe(document.body, { childList: true, subtree: true });
  scan();
})();
"""

UI_PAGE_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>wazuh-ai · confirm action</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body { font-family: system-ui, sans-serif; margin: 2rem; max-width: 42rem; }
    .card { border: 1px solid #d3dae6; border-radius: 8px; padding: 1rem 1.25rem; }
    .meta { color: #5a6b86; font-size: 0.9rem; }
    pre { white-space: pre-wrap; background: #f5f7fa; padding: 0.75rem; border-radius: 6px; }
    button { margin-right: 0.5rem; margin-top: 0.75rem; padding: 0.4rem 0.9rem; }
    #status { margin-top: 1rem; }
    .login { margin-top: 1rem; display: grid; gap: 0.5rem; max-width: 20rem; }
  </style>
</head>
<body>
  <h1>Confirm proposed action</h1>
  <div class="card">
    <div class="meta" id="meta"></div>
    <pre id="preview"></pre>
    <div class="login" id="login">
      <label>Operator sign-in (Keycloak)</label>
      <input id="user" placeholder="username" autocomplete="username" />
      <input id="pass" type="password" placeholder="password" autocomplete="current-password" />
      <button type="button" id="signin">Sign in</button>
    </div>
    <button type="button" id="confirm">Confirm</button>
    <button type="button" id="reject">Reject</button>
    <div id="status"></div>
  </div>
  <script>
    window.WAZUH_AI_ACTIONS_CONFIG = __CONFIG_JSON__;
    const CFG = window.WAZUH_AI_ACTIONS_CONFIG;
    const PROPOSAL_ID = __PROPOSAL_ID_JSON__;
    const JWT_KEY = "wazuh_ai_turn_jwt";
    const status = document.getElementById("status");
    const jwt = () => sessionStorage.getItem(JWT_KEY) || "";
    const setJwt = (t) => sessionStorage.setItem(JWT_KEY, t);

    async function login() {
      const body = new URLSearchParams({
        grant_type: "password",
        client_id: CFG.kcClient,
        username: document.getElementById("user").value,
        password: document.getElementById("pass").value,
      });
      const oidc = await fetch(`${CFG.kcUrl}/realms/${CFG.kcRealm}/protocol/openid-connect/token`, {
        method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body,
      });
      if (!oidc.ok) throw new Error(`Keycloak login failed (${oidc.status})`);
      const access = (await oidc.json()).access_token;
      const exchanged = await fetch(`${CFG.shimUrl}/v1/token/exchange`, {
        method: "POST", headers: { Authorization: `Bearer ${access}` },
      });
      if (!exchanged.ok) throw new Error(`token exchange failed (${exchanged.status})`);
      setJwt((await exchanged.json()).access_token);
      document.getElementById("login").style.display = "none";
    }

    async function api(path, opts = {}) {
      const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
      if (jwt()) headers.Authorization = `Bearer ${jwt()}`;
      return fetch(`${CFG.toolServiceUrl}${path}`, { ...opts, headers });
    }

    async function load() {
      const res = await api(`/v1/actions/${PROPOSAL_ID}`);
      const prop = await res.json();
      if (!res.ok) throw new Error(prop.detail || res.statusText);
      document.getElementById("meta").textContent =
        `${prop.action_name} · ${prop.risk} risk · ${prop.status}`;
      document.getElementById("preview").textContent = prop.preview || "";
      if (jwt()) document.getElementById("login").style.display = "none";
    }

    document.getElementById("signin").onclick = () => login().catch(e => status.textContent = e.message);
    document.getElementById("confirm").onclick = async () => {
      status.textContent = "Confirming…";
      try {
        if (!jwt()) await login();
        const key = `ui-page-${PROPOSAL_ID}-${Date.now()}`;
        const res = await api(`/v1/actions/${PROPOSAL_ID}/confirm`, {
          method: "POST", body: JSON.stringify({ idempotency_key: key }),
        });
        const body = await res.json();
        if (!res.ok) throw new Error(body.detail || res.statusText);
        status.textContent = body.result.ok
          ? `Confirmed: ${body.result.message}`
          : `Failed: ${body.result.message}`;
      } catch (e) { status.textContent = e.message; }
    };
    document.getElementById("reject").onclick = async () => {
      status.textContent = "Rejecting…";
      try {
        if (!jwt()) await login();
        const res = await api(`/v1/actions/${PROPOSAL_ID}/reject`, { method: "POST" });
        const body = await res.json();
        if (!res.ok) throw new Error(body.detail || res.statusText);
        status.textContent = "Proposal rejected.";
      } catch (e) { status.textContent = e.message; }
    };
    load().catch(e => status.textContent = e.message);
  </script>
</body>
</html>
"""
