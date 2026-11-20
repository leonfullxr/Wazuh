"""Packaged, network-isolated MCP Apps investigation viewer."""

import base64
import hashlib

URI = "ui://wazuh/agent-timeline.html"
MIME = "text/html;profile=mcp-app"

STYLE = r'''
:root {
  color-scheme: light dark;
  font-family: system-ui, sans-serif;
  background: #f5f6f4;
  color: #17241e;
}
* {
  box-sizing: border-box;
}
body {
  margin: 0;
  padding: 24px;
  max-width: 1100px;
  margin-inline: auto;
}
header {
  border-bottom: 1px solid #cbd5cd;
  padding-bottom: 18px;
  margin-bottom: 20px;
}
.eyebrow {
  font-size: 0.72rem;
  letter-spacing: 0.13em;
  text-transform: uppercase;
  color: #48745b;
  font-weight: 700;
}
h1 {
  font-size: 1.65rem;
  margin: 0.35rem 0;
}
h2 {
  font-size: 1rem;
  margin: 0 0 12px;
}
.muted {
  color: #5a6a60;
}
.summary {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px;
  margin-bottom: 22px;
}
.metric,
.panel {
  background: #fff;
  border: 1px solid #d9e2db;
  border-radius: 9px;
  padding: 16px;
  min-width: 0;
}
.metric span {
  display: block;
  overflow-wrap: anywhere;
}
.label {
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: #62746a;
  margin-bottom: 6px;
}
.layout {
  display: grid;
  grid-template-columns: minmax(220px, 1fr) minmax(260px, 1.4fr);
  gap: 16px;
}
ul {
  list-style: none;
  padding: 0;
  margin: 0;
}
li + li {
  border-top: 1px solid #e2e8e3;
}
button {
  font: inherit;
  text-align: left;
  width: 100%;
  padding: 13px 8px;
  background: transparent;
  color: inherit;
  border: 0;
  cursor: pointer;
  overflow-wrap: anywhere;
}
button:hover,
button[aria-pressed="true"] {
  background: #eaf3ec;
}
button:focus-visible {
  outline: 3px solid #36794e;
  outline-offset: -3px;
}
.time {
  display: block;
  font-size: 0.78rem;
  color: #617268;
  margin-top: 4px;
}
pre {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  font:
    0.82rem/1.5 ui-monospace,
    monospace;
  margin: 0;
}
#status {
  min-height: 1.5em;
}
.sources {
  white-space: pre-line;
  font-size: 0.87rem;
  line-height: 1.55;
  overflow-wrap: anywhere;
}
@media (max-width: 640px) {
  body {
    padding: 16px;
  }
  .layout {
    grid-template-columns: 1fr;
  }
}
@media (prefers-color-scheme: dark) {
  :root {
    background: #111b16;
    color: #e6eee8;
  }
  .metric,
  .panel {
    background: #1a2820;
    border-color: #34463a;
  }
  .muted,
  .label,
  .time {
    color: #aec1b3;
  }
  .eyebrow {
    color: #9acba9;
  }
  header,
  li + li {
    border-color: #34463a;
  }
  button:hover,
  button[aria-pressed="true"] {
    background: #304a37;
  }
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
    csp = ("default-src 'none'; script-src '" + _hash(SCRIPT) + "'; style-src '" + _hash(STYLE)
           + "'; connect-src 'none'; img-src 'none'; base-uri 'none'; form-action 'none'")
    return f'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="{csp}">
  <title>Investigation timeline</title>
  <style>{STYLE}</style>
</head>
<body>
  <header>
    <div class="eyebrow">Wazuh · investigation</div>
    <h1>Agent timeline</h1>
    <div class="muted">Evidence and source coverage</div>
  </header>
  <main>
    <div class="summary">
      <div class="metric"><span class="label">Agent</span><span id="agent">Waiting for timeline</span></div>
      <div class="metric"><span class="label">Cluster</span><span id="cluster">—</span></div>
      <div class="metric"><span class="label">Selected window</span><span id="window">—</span></div>
      <div class="metric"><span class="label">Collected at</span><span id="collected">—</span></div>
    </div>
    <section class="panel">
      <h2>Source coverage</h2>
      <div id="sources" class="sources">Waiting for timeline data.</div>
    </section>
    <p id="status" class="muted" role="status">Connecting to host…</p>
    <div class="layout">
      <section class="panel"><h2>Events</h2><ul id="events"></ul></section>
      <section class="panel"><h2>Evidence</h2><pre id="detail">Select an event to view its record.</pre></section>
    </div>
  </main>
  <script>{SCRIPT}</script>
</body>
</html>'''
