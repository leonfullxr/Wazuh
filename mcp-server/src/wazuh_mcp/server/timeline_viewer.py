"""Packaged, network-isolated MCP Apps investigation viewer."""

import base64
import hashlib

from wazuh_mcp.ui_theme import bar as _bar
from wazuh_mcp.ui_theme import css as _ui_css

URI = "ui://wazuh/agent-timeline.html"
MIME = "text/html;profile=mcp-app"

_LAYOUT = r'''
.timeline-head { max-width: 68rem; margin: 0 auto; padding: 28px 28px 8px; }
.timeline-head .facts { display: grid; grid-template-columns: repeat(auto-fit, minmax(16rem, 1fr)); gap: 16px 28px; border-top: 0; }
.timeline-head .facts div { display: block; border-bottom: 0; padding: 0; }
time { display: inline; }
.workspace {
  display: grid;
  grid-template-columns: minmax(18rem, 24rem) minmax(0, 1fr);
  min-height: calc(100vh - 64px);
  border-top: 1px solid var(--line);
}
.events-pane { border-right: 1px solid var(--line); padding: 16px 0 32px; min-width: 0; }
.evidence-pane { padding: 16px 28px 40px; min-width: 0; }
.events-pane h2, .evidence-pane h2 { margin: 0 20px 8px; }
#events { list-style: none; padding: 0; margin: 0; border-top: 1px solid var(--line); }
#events button {
  display: block;
  width: 100%;
  min-height: 48px;
  margin: 0;
  padding: 8px 20px;
  text-align: left;
  border: 0;
  border-radius: 0;
  background: transparent;
  font-weight: 600;
  font-size: 16px;
}
#events button[aria-selected="true"] { box-shadow: inset 3px 0 0 var(--focus); background: var(--field); }
#events time { display: block; margin-top: 2px; }
pre {
  margin: 0;
  padding: 16px;
  background: var(--field);
  border: 1px solid var(--line);
  border-radius: 2px;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  font: 15px/1.55 "Source Code Pro", ui-monospace, monospace;
  font-variant-numeric: tabular-nums;
}
#status { min-height: 1.5em; }
#sources { white-space: pre-line; max-width: 70ch; }
@media (max-width: 800px) {
  .timeline-head { padding: 20px 16px 8px; }
  .timeline-head .facts { grid-template-columns: 1fr; gap: 12px 0; }
  .workspace { grid-template-columns: 1fr; }
  .events-pane { border-right: 0; border-bottom: 1px solid var(--line); }
  .evidence-pane { padding: 16px; }
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
  const stamp = (iso) => {
    const node = document.createElement("time");
    if (iso == null || iso === "") {
      node.textContent = "Unavailable";
      return node;
    }
    const date = new Date(iso);
    const raw = String(iso);
    if (Number.isNaN(date.getTime())) {
      node.textContent = raw;
      node.dateTime = raw;
      node.title = raw;
      return node;
    }
    const exact = date.toISOString();
    node.dateTime = exact;
    node.title = exact;
    node.textContent = new Intl.DateTimeFormat(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    }).format(date);
    return node;
  };
  const localText = (iso) => {
    const date = new Date(iso);
    if (iso == null || iso === "" || Number.isNaN(date.getTime())) return iso == null || iso === "" ? "unavailable" : String(iso);
    return new Intl.DateTimeFormat(undefined, {
      year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
    }).format(date);
  };
  const fillTime = (id, iso) => $(id).replaceChildren(stamp(iso));
  const fillSpan = (id, start, end) => {
    const node = $(id);
    node.replaceChildren(stamp(start), document.createTextNode(" to "), stamp(end));
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
    fillSpan("window", data.window?.from, data.window?.to);
    fillTime("collected", data.collected_at);
    const alerts = data.sources?.alerts || {},
      agent = data.sources?.agent_status || {};
    put(
      "sources",
      `Alerts: ${alerts.status ?? "unavailable"} · ${alerts.returned ?? 0} returned · matched: ${alerts.matched ?? "unknown"} · truncated: ${alerts.truncated === true ? "yes" : "no"}\nAgent status: ${agent.status ?? "unavailable"} · observed: ${localText(agent.observed_at)} · ${agent.observation?.status ?? "unavailable"}`,
    );
    const list = $("events");
    list.replaceChildren();
    put(
      "status",
      data.events.length
        ? `${data.events.length} events, oldest first. Select an event to retrieve current evidence.`
        : "No events returned. Check source coverage before drawing conclusions.",
    );
    const choose = (button) => {
      for (const other of list.querySelectorAll("button")) {
        other.setAttribute("aria-selected", "false");
        other.tabIndex = -1;
      }
      button.setAttribute("aria-selected", "true");
      button.tabIndex = 0;
      button.focus();
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
            evidence_ref: button.dataset.ref,
            cluster_id: current.cluster,
          },
        },
      });
    };
    let first = true;
    for (const item of data.events) {
      if (!item || typeof item.evidence_ref !== "string") continue;
      const li = document.createElement("li"),
        button = document.createElement("button"),
        rule = document.createElement("span");
      button.type = "button";
      button.setAttribute("role", "option");
      button.setAttribute("aria-selected", "false");
      button.tabIndex = first ? 0 : -1;
      first = false;
      button.dataset.ref = item.evidence_ref;
      rule.textContent = `Rule ${item.rule_id ?? "unavailable"}`;
      button.append(rule, stamp(item.at));
      button.addEventListener("click", () => choose(button));
      li.append(button);
      list.append(li);
    }
    list.onkeydown = (event) => {
      const buttons = [...list.querySelectorAll("button")];
      if (!buttons.length) return;
      const focused = buttons.indexOf(document.activeElement);
      const selected = buttons.findIndex((button) => button.getAttribute("aria-selected") === "true");
      const from = focused >= 0 ? focused : Math.max(selected, 0);
      let next = from;
      if (event.key === "ArrowDown") next = selected < 0 ? from : Math.min(buttons.length - 1, from + 1);
      else if (event.key === "ArrowUp") next = selected < 0 ? from : Math.max(0, from - 1);
      else if (event.key === "Home") next = 0;
      else if (event.key === "End") next = buttons.length - 1;
      else return;
      event.preventDefault();
      choose(buttons[next]);
    };
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
  {_bar("Investigation")}
  <main id="main">
    <div class="timeline-head">
      <h1>Agent timeline</h1>
      <dl class="facts">
        <div><dt>Agent</dt><dd id="agent">Waiting for timeline</dd></div>
        <div><dt>Cluster</dt><dd id="cluster">Unavailable</dd></div>
        <div><dt>Window</dt><dd id="window">Unavailable</dd></div>
        <div><dt>Collected</dt><dd id="collected">Unavailable</dd></div>
      </dl>
      <h2>Source coverage</h2>
      <p id="sources">Waiting for timeline data.</p>
      <p id="status" role="status">Connecting to host…</p>
    </div>
    <div class="workspace">
      <section class="events-pane" aria-labelledby="events-heading">
        <h2 id="events-heading">Events</h2>
        <ul id="events" role="listbox" aria-label="Timeline events"></ul>
      </section>
      <section class="evidence-pane" aria-labelledby="evidence-heading">
        <h2 id="evidence-heading">Evidence</h2>
        <pre id="detail">Select an event to view its record.</pre>
      </section>
    </div>
  </main>
  <script>{SCRIPT}</script>
</body>
</html>'''
