"""Packaged, network-isolated MCP Apps investigation viewer."""

import base64
import hashlib

from wazuh_mcp.ui_theme import css as _ui_css

URI = "ui://wazuh/agent-timeline.html"
MIME = "text/html;profile=mcp-app"

_LAYOUT = r'''
.facts dd { overflow-wrap: anywhere; }
.split {
  display: grid;
  grid-template-columns: minmax(220px, 1fr) minmax(280px, 1.3fr);
  gap: 28px;
  margin-top: 8px;
}
#events { list-style: none; padding: 0; margin: 8px 0 0; border-top: 1px solid var(--line); }
#events button {
  display: block;
  width: 100%;
  min-height: 44px;
  margin: 0;
  padding: 8px 8px 8px 12px;
  text-align: left;
  border: 0;
  border-radius: 0;
  background: transparent;
  font-weight: 400;
}
#events button[aria-pressed="true"] { box-shadow: inset 2px 0 0 var(--focus); }
.time {
  display: block;
  margin-top: 2px;
  color: var(--muted);
  font-size: 12px;
  font-variant-numeric: tabular-nums;
}
pre {
  margin: 0;
  padding: 12px;
  background: var(--field);
  border: 1px solid var(--line);
  border-radius: 8px;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  font: 13px/1.5 ui-monospace, ui-monospace, monospace;
}
#status { min-height: 1.5em; color: var(--muted); }
#sources { white-space: pre-line; }
@media (max-width: 640px) {
  .split { grid-template-columns: 1fr; }
}
'''


SCRIPT = r'''
(() => {
  "use strict";
  const host = window.parent;
  const $ = (id) => document.getElementById(id);
  let ready = false,
    nextId = 2,
    pending = new Map(),
    current = null;
  const put = (id, value) => {
    $(id).textContent = value == null ? "Unavailable" : String(value);
  };
  const send = (message) =>
    host.postMessage({ jsonrpc: "2.0", ...message }, "*");
  function draw(data) {
    if (
      !data ||
      !Array.isArray(data.events) ||
      typeof data.cluster !== "string"
    ) {
      put("status", "Timeline data is unavailable.");
      return;
    }
    current = data;
    put("agent", data.agent_id);
    put("cluster", data.cluster);
    put(
      "window",
      `${data.window?.from ?? "Unavailable"} → ${data.window?.to ?? "Unavailable"}`,
    );
    put("collected", data.collected_at);
    const alerts = data.sources?.alerts || {},
      agent = data.sources?.agent_status || {};
    put(
      "sources",
      `Alerts: ${alerts.status ?? "unavailable"} · ${alerts.returned ?? 0} returned · matched: ${alerts.matched ?? "unknown"} · truncated: ${alerts.truncated === true ? "yes" : "no"}\nAgent status: ${agent.status ?? "unavailable"} · observed: ${agent.observed_at ?? "unavailable"} · ${agent.observation?.status ?? "unavailable"}`,
    );
    const list = $("events");
    list.replaceChildren();
    put(
      "status",
      data.events.length
        ? `${data.events.length} events, oldest first. Select an event to retrieve current evidence.`
        : "No events returned. Check source coverage before drawing conclusions.",
    );
    for (const item of data.events) {
      if (!item || typeof item.evidence_ref !== "string") continue;
      const li = document.createElement("li"),
        button = document.createElement("button"),
        time = document.createElement("span");
      button.type = "button";
      button.textContent = `Rule ${item.rule_id ?? "unavailable"}`;
      time.className = "time";
      time.textContent = item.at ?? "Time unavailable";
      button.append(time);
      button.addEventListener("click", () => {
        for (const other of list.querySelectorAll("button"))
          other.setAttribute("aria-pressed", "false");
        button.setAttribute("aria-pressed", "true");
        put("detail", "Retrieving evidence…");
        const id = nextId++;
        pending.clear();
        pending.set(id, true);
        send({
          id,
          method: "tools/call",
          params: {
            name: "get_investigation_evidence",
            arguments: {
              evidence_ref: item.evidence_ref,
              cluster_id: current.cluster,
            },
          },
        });
      });
      li.append(button);
      list.append(li);
    }
  }
  window.addEventListener("message", (event) => {
    const msg = event.data;
    if (event.source !== host || !msg || msg.jsonrpc !== "2.0") return;
    if (
      !ready &&
      msg.id === 1 &&
      msg.result?.protocolVersion === "2026-01-26"
    ) {
      ready = true;
      send({ method: "ui/notifications/initialized" });
      return;
    }
    if (!ready) return;
    if (msg.method === "ui/notifications/tool-result") {
      let data = msg.params?.structuredContent;
      if (!data) {
        try {
          data = JSON.parse(
            msg.params?.content?.find(
              (part) => part.type === "text" && part.text?.startsWith("{"),
            )?.text,
          );
        } catch (_) {}
      }
      draw(data);
      return;
    }
    if (pending.has(msg.id)) {
      pending.delete(msg.id);
      const result = msg.result?.structuredContent;
      if (
        msg.error ||
        msg.result?.isError ||
        !result ||
        result.status !== "available"
      )
        put("detail", "Evidence unavailable or access has changed.");
      else put("detail", JSON.stringify(result.event, null, 2));
    }
    if (msg.method === "ui/resource-teardown" && msg.id != null)
      send({ id: msg.id, result: {} });
  });
  send({
    id: 1,
    method: "ui/initialize",
    params: {
      appInfo: { name: "Wazuh investigation timeline", version: "1.0.0" },
      appCapabilities: {},
      protocolVersion: "2026-01-26",
    },
  });
})();
'''

# Hashes authorize only these bundled blocks, including in hosts that enforce CSP.
def _hash(value: str) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(value.encode()).digest()).decode()


def html() -> str:
    style = _ui_css() + _LAYOUT
    csp = (
        "default-src 'none'; script-src '" + _hash(SCRIPT) + "'; style-src '" + _hash(style)
        + "'; font-src data:; connect-src 'none'; img-src 'none'; base-uri 'none'; form-action 'none'"
    )
    return f'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <meta http-equiv="Content-Security-Policy" content="{csp}">
  <title>Investigation timeline</title>
  <style>{style}</style>
</head>
<body>
  <a class="skip" href="#main">Skip to content</a>
  <header class="bar"><strong>Wazuh MCP</strong><span>Investigation</span></header>
  <main id="main" class="sheet">
    <h1>Agent timeline</h1>
    <dl class="facts">
      <div><dt>Agent</dt><dd id="agent">Waiting for timeline</dd></div>
      <div><dt>Cluster</dt><dd id="cluster">Unavailable</dd></div>
      <div><dt>Window</dt><dd id="window">Unavailable</dd></div>
      <div><dt>Collected</dt><dd id="collected">Unavailable</dd></div>
    </dl>
    <h2>Source coverage</h2>
    <p id="sources" class="lead">Waiting for timeline data.</p>
    <p id="status" role="status">Connecting to host…</p>
    <div class="split">
      <section><h2>Events</h2><ul id="events"></ul></section>
      <section><h2>Evidence</h2><pre id="detail">Select an event to view its record.</pre></section>
    </div>
  </main>
  <script>{SCRIPT}</script>
</body>
</html>'''
